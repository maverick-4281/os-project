import json
from datetime import datetime, timezone
from pathlib import Path

import bcrypt


BASE_DIR = Path(__file__).resolve().parent.parent
USERS_DIR = BASE_DIR / "data" / "users"


# Password hashing simulates OS-level credential storage, similar to /etc/shadow in Linux where passwords are stored as salted hashes.
def register_user(username, password, email):
    """Register a new user and persist credentials securely."""
    sanitized_username = username.strip()
    sanitized_email = email.strip().lower()

    if user_exists(sanitized_username):
        return False, "Username already exists."

    USERS_DIR.mkdir(parents=True, exist_ok=True)
    password_hash = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")
    user_payload = {
        "username": sanitized_username,
        "email": sanitized_email,
        "password_hash": password_hash,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "totp_secret": "",
        "files": [],
        "role": "user",
    }

    user_file = USERS_DIR / f"{sanitized_username}.json"
    with user_file.open("w", encoding="utf-8") as file:
        json.dump(user_payload, file, indent=2)

    return True, user_payload


def login_user(username, password):
    """Validate credentials against stored hashed password."""
    user_data = get_user(username.strip())
    if not user_data:
        return False, "User not found."

    password_hash = user_data.get("password_hash", "")
    if not password_hash:
        return False, "User record is invalid."

    is_valid = bcrypt.checkpw(password.encode("utf-8"), password_hash.encode("utf-8"))
    if not is_valid:
        return False, "Invalid username or password."

    return True, user_data


def user_exists(username):
    """Check whether a user's JSON record already exists."""
    user_file = USERS_DIR / f"{username.strip()}.json"
    return user_file.exists()


def get_user(username):
    """Load and return the user dictionary if present."""
    user_file = USERS_DIR / f"{username.strip()}.json"
    if not user_file.exists():
        return None

    with user_file.open("r", encoding="utf-8") as file:
        return json.load(file)
