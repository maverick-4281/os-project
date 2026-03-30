import json
import os
from datetime import datetime
from pathlib import Path

from cryptography.fernet import Fernet, InvalidToken


BASE_DIR = Path(__file__).resolve().parent.parent
USERS_DIR = BASE_DIR / "data" / "users"
FILES_DIR = BASE_DIR / "data" / "files"
LOGS_DIR = BASE_DIR / "data" / "logs"


# os.path.getsize() and os.path.getmtime() are wrappers for the stat() system call.
# AES-256 Fernet encryption mirrors filesystem-level encryption like LUKS on Linux.
def _user_json_path(username):
    return USERS_DIR / f"{username.strip()}.json"


def _user_log_path(username):
    return LOGS_DIR / f"{username.strip()}.log"


def _user_files_dir(username):
    return FILES_DIR / username.strip()


def _load_user(username):
    user_path = _user_json_path(username)
    if not user_path.exists():
        return None
    with user_path.open("r", encoding="utf-8") as file:
        return json.load(file)


def _save_user(username, user_data):
    user_path = _user_json_path(username)
    with user_path.open("w", encoding="utf-8") as file:
        json.dump(user_data, file, indent=2)


def _log_action(username, action):
    LOGS_DIR.mkdir(parents=True, exist_ok=True)
    timestamp = datetime.now().isoformat(timespec="seconds")
    with _user_log_path(username).open("a", encoding="utf-8") as log_file:
        log_file.write(f"[{timestamp}] {action}\n")


def _find_metadata_entry(user_data, filename):
    for entry in user_data.get("files", []):
        if entry.get("filename") == filename:
            return entry
    return None


def _has_shared_access(username, filename):
    for user_file in USERS_DIR.glob("*.json"):
        with user_file.open("r", encoding="utf-8") as file:
            owner_data = json.load(file)
        for entry in owner_data.get("files", []):
            if entry.get("filename") == filename and username in entry.get("shared_with", []):
                return owner_data.get("username"), entry
    return None, None


def write_file(username, filename, content):
    user_data = _load_user(username)
    if not user_data:
        return False, "User not found."

    user_folder = _user_files_dir(username)
    user_folder.mkdir(parents=True, exist_ok=True)
    file_path = user_folder / filename

    with file_path.open("w", encoding="utf-8") as file:
        file.write(content)

    metadata = _find_metadata_entry(user_data, filename)
    now = datetime.now().isoformat(timespec="seconds")
    if metadata:
        metadata["modified_at"] = now
        metadata["is_encrypted"] = False
    else:
        user_data.setdefault("files", []).append(
            {
                "filename": filename,
                "owner": username,
                "shared_with": [],
                "is_encrypted": False,
                "created_at": now,
                "modified_at": now,
            }
        )
    _save_user(username, user_data)
    _log_action(username, f"WRITE file={filename}")
    return True, "File saved successfully."


def read_file(username, filename):
    owner = username
    file_path = _user_files_dir(owner) / filename
    has_access = file_path.exists()

    if not has_access:
        shared_owner, _ = _has_shared_access(username, filename)
        if shared_owner:
            owner = shared_owner
            file_path = _user_files_dir(owner) / filename
            has_access = file_path.exists()

    if not has_access:
        return None, "File not found or access denied."

    try:
        with file_path.open("r", encoding="utf-8") as file:
            content = file.read()
    except UnicodeDecodeError:
        return None, "File appears encrypted. Use decrypt to view content."

    _log_action(username, f"READ file={filename} owner={owner}")
    return content, None


def get_file_metadata(username, filename):
    owner = username
    user_data = _load_user(username)
    entry = _find_metadata_entry(user_data, filename) if user_data else None

    if not entry:
        shared_owner, shared_entry = _has_shared_access(username, filename)
        if shared_owner and shared_entry:
            owner = shared_owner
            entry = shared_entry

    file_path = _user_files_dir(owner) / filename
    if not file_path.exists():
        return None

    stat_size = os.path.getsize(file_path)
    stat_mtime = os.path.getmtime(file_path)
    stat_ctime = os.path.getctime(file_path)
    return {
        "filename": filename,
        "size": stat_size,
        "created_at": datetime.fromtimestamp(stat_ctime).isoformat(timespec="seconds"),
        "modified_at": datetime.fromtimestamp(stat_mtime).isoformat(timespec="seconds"),
        "owner": owner,
        "is_encrypted": bool(entry.get("is_encrypted", False)) if entry else False,
        "shared_with": entry.get("shared_with", []) if entry else [],
    }


def generate_encryption_key(username):
    USERS_DIR.mkdir(parents=True, exist_ok=True)
    key = Fernet.generate_key()
    key_path = USERS_DIR / f"{username.strip()}.key"
    with key_path.open("wb") as key_file:
        key_file.write(key)
    return key


def get_encryption_key(username):
    key_path = USERS_DIR / f"{username.strip()}.key"
    if not key_path.exists():
        return generate_encryption_key(username)
    with key_path.open("rb") as key_file:
        return key_file.read()


def encrypt_file(username, filename):
    user_data = _load_user(username)
    if not user_data:
        return False, "User not found."

    metadata = _find_metadata_entry(user_data, filename)
    if not metadata:
        return False, "File metadata not found."

    file_path = _user_files_dir(username) / filename
    if not file_path.exists():
        return False, "File not found."

    key = get_encryption_key(username)
    cipher = Fernet(key)

    with file_path.open("rb") as file:
        plaintext_bytes = file.read()
    ciphertext = cipher.encrypt(plaintext_bytes)
    with file_path.open("wb") as file:
        file.write(ciphertext)

    metadata["is_encrypted"] = True
    metadata["modified_at"] = datetime.now().isoformat(timespec="seconds")
    _save_user(username, user_data)
    _log_action(username, f"ENCRYPT file={filename}")
    return True, "File encrypted successfully."


def decrypt_file(username, filename):
    user_data = _load_user(username)
    if not user_data:
        return None, "User not found."

    metadata = _find_metadata_entry(user_data, filename)
    if not metadata:
        return None, "File metadata not found."

    file_path = _user_files_dir(username) / filename
    if not file_path.exists():
        return None, "File not found."

    key = get_encryption_key(username)
    cipher = Fernet(key)

    with file_path.open("rb") as file:
        encrypted_bytes = file.read()
    try:
        plaintext = cipher.decrypt(encrypted_bytes).decode("utf-8")
    except (InvalidToken, UnicodeDecodeError):
        return None, "Unable to decrypt file. Invalid key or file format."

    _log_action(username, f"DECRYPT file={filename}")
    return plaintext, None
