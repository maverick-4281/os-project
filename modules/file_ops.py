"""
Module 2: File Operations & Encryption
OS Concepts: os.path.getsize() and os.path.getmtime() are wrappers for the stat() system call.
AES-256 Fernet encryption mirrors filesystem-level encryption like LUKS on Linux.
"""

import json
import os
import stat
from datetime import datetime
from pathlib import Path

from cryptography.fernet import Fernet

BASE_DIR = Path(__file__).resolve().parent.parent
USERS_DIR = BASE_DIR / "data" / "users"
FILES_DIR = BASE_DIR / "data" / "files"
LOGS_DIR = BASE_DIR / "data" / "logs"


def _log(username: str, action: str) -> None:
    LOGS_DIR.mkdir(parents=True, exist_ok=True)
    log_file = LOGS_DIR / f"{username}.log"
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with open(log_file, "a") as f:
        f.write(f"[{timestamp}] {action}\n")


def _load_user(username: str) -> dict:
    user_file = USERS_DIR / f"{username}.json"
    if not user_file.exists():
        return {}
    with open(user_file) as f:
        return json.load(f)


def _save_user(username: str, data: dict) -> None:
    with open(USERS_DIR / f"{username}.json", "w") as f:
        json.dump(data, f, indent=2)


def generate_encryption_key(username: str) -> bytes:
    key = Fernet.generate_key()
    key_path = USERS_DIR / f"{username}.key"
    with open(key_path, "wb") as f:
        f.write(key)
    return key


def get_encryption_key(username: str):
    key_path = USERS_DIR / f"{username}.key"
    if not key_path.exists():
        return generate_encryption_key(username)
    with open(key_path, "rb") as f:
        return f.read()


def write_file(username: str, filename: str, content: str):
    user_folder = FILES_DIR / username
    user_folder.mkdir(parents=True, exist_ok=True)
    file_path = user_folder / filename
    with open(file_path, "w") as f:
        f.write(content)
    user_data = _load_user(username)
    files_list = user_data.get("files", [])
    files_list = [f for f in files_list if f.get("filename") != filename]
    files_list.append({
        "filename": filename,
        "created_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "is_encrypted": False,
        "shared_with": [],
        "permissions": {"owner": "rw", "shared": "r"}
    })
    user_data["files"] = files_list
    _save_user(username, user_data)
    _log(username, f"WRITE file={filename}")
    return True, "File saved successfully."


def read_file(username: str, filename: str):
    user_folder = FILES_DIR / username
    file_path = user_folder / filename
    if not file_path.exists():
        return None, "File not found."
    user_data = _load_user(username)
    owned = any(f.get("filename") == filename for f in user_data.get("files", []))
    shared = any(
        f.get("filename") == filename
        for f in user_data.get("shared_files", [])
    )
    if not owned and not shared:
        return None, "Access denied."
    file_meta = next((f for f in user_data.get("files", []) if f.get("filename") == filename), {})
    if file_meta.get("is_encrypted"):
        return None, "File is encrypted. Use decrypt to view."
    with open(file_path, "r") as f:
        content = f.read()
    _log(username, f"READ file={filename}")
    return content, None


def get_file_metadata(username: str, filename: str):
    user_folder = FILES_DIR / username
    file_path = user_folder / filename
    if not file_path.exists():
        return None
    user_data = _load_user(username)
    file_meta = next((f for f in user_data.get("files", []) if f.get("filename") == filename), {})
    stat_info = os.stat(file_path)
    return {
        "filename": filename,
        "size": os.path.getsize(file_path),
        "created_at": file_meta.get("created_at", "N/A"),
        "modified_at": datetime.fromtimestamp(os.path.getmtime(file_path)).strftime("%Y-%m-%d %H:%M:%S"),
        "owner": username,
        "is_encrypted": file_meta.get("is_encrypted", False),
        "shared_with": file_meta.get("shared_with", []),
        "permissions": file_meta.get("permissions", {"owner": "rw", "shared": "r"}),
        "mode": oct(stat_info.st_mode)
    }


def encrypt_file(username: str, filename: str):
    user_folder = FILES_DIR / username
    file_path = user_folder / filename
    if not file_path.exists():
        return False, "File not found."
    user_data = _load_user(username)
    file_meta = next((f for f in user_data.get("files", []) if f.get("filename") == filename), {})
    if file_meta.get("is_encrypted"):
        return False, "File is already encrypted."
    key = get_encryption_key(username)
    fernet = Fernet(key)
    with open(file_path, "rb") as f:
        data = f.read()
    encrypted = fernet.encrypt(data)
    with open(file_path, "wb") as f:
        f.write(encrypted)
    for f in user_data.get("files", []):
        if f.get("filename") == filename:
            f["is_encrypted"] = True
    _save_user(username, user_data)
    os.chmod(file_path, stat.S_IRUSR | stat.S_IWUSR)
    _log(username, f"ENCRYPT file={filename}")
    return True, "File encrypted successfully."


def decrypt_file(username: str, filename: str):
    user_folder = FILES_DIR / username
    file_path = user_folder / filename
    if not file_path.exists():
        return None, "File not found."
    user_data = _load_user(username)
    file_meta = next((f for f in user_data.get("files", []) if f.get("filename") == filename), {})
    if not file_meta.get("is_encrypted"):
        return None, "File is not encrypted."
    key = get_encryption_key(username)
    fernet = Fernet(key)
    with open(file_path, "rb") as f:
        data = f.read()
    try:
        decrypted = fernet.decrypt(data)
        _log(username, f"DECRYPT file={filename}")
        return decrypted.decode("utf-8"), None
    except Exception:
        return None, "Decryption failed. Invalid key or corrupted file."


def share_file(owner_username: str, filename: str, target_username: str):
    target_file = USERS_DIR / f"{target_username}.json"
    if not target_file.exists():
        return False, "Target user does not exist."
    owner_data = _load_user(owner_username)
    file_meta = next((f for f in owner_data.get("files", []) if f.get("filename") == filename), None)
    if not file_meta:
        return False, "File not found."
    if target_username not in file_meta.get("shared_with", []):
        file_meta.setdefault("shared_with", []).append(target_username)
    _save_user(owner_username, owner_data)
    target_data = _load_user(target_username)
    shared = target_data.setdefault("shared_files", [])
    if not any(f.get("filename") == filename for f in shared):
        shared.append({"filename": filename, "owner": owner_username})
    _save_user(target_username, target_data)
    _log(owner_username, f"SHARE file={filename} with={target_username}")
    return True, f"File shared with {target_username}."


def revoke_access(owner_username: str, filename: str, target_username: str):
    owner_data = _load_user(owner_username)
    for f in owner_data.get("files", []):
        if f.get("filename") == filename:
            f["shared_with"] = [u for u in f.get("shared_with", []) if u != target_username]
    _save_user(owner_username, owner_data)
    target_data = _load_user(target_username)
    target_data["shared_files"] = [
        f for f in target_data.get("shared_files", [])
        if not (f.get("filename") == filename and f.get("owner") == owner_username)
    ]
    _save_user(target_username, target_data)
    _log(owner_username, f"REVOKE file={filename} from={target_username}")
    return True, "Access revoked."


def set_file_permissions(username: str, filename: str, permission: str):
    user_folder = FILES_DIR / username
    file_path = user_folder / filename
    if not file_path.exists():
        return False, "File not found."
    if permission == "rw":
        os.chmod(file_path, stat.S_IRUSR | stat.S_IWUSR)
    elif permission == "r":
        os.chmod(file_path, stat.S_IRUSR)
    elif permission == "none":
        os.chmod(file_path, 0o000)
    _log(username, f"CHMOD file={filename} permission={permission}")
    return True, f"Permissions set to {permission}."


def get_access_log(username: str) -> str:
    log_file = LOGS_DIR / f"{username}.log"
    if not log_file.exists():
        return "No activity logs found."
    with open(log_file, "r") as f:
        return f.read()


def list_shared_files(username: str) -> list:
    user_data = _load_user(username)
    return user_data.get("shared_files", [])