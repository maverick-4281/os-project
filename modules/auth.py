import json
from datetime import datetime, timezone
from pathlib import Path

import bcrypt
import pyotp
import qrcode


BASE_DIR = Path(__file__).resolve().parent.parent
USERS_DIR = BASE_DIR / "data" / "users"
QRCODES_DIR = BASE_DIR / "static" / "qrcodes"


# 2FA mimics multi-factor OS authentication (PAM modules in Linux).
# TOTP uses HMAC-SHA1 to generate time-based codes — similar to
# challenge-response mechanisms in OS security frameworks.


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


def _save_user(username, user_data):
    """Persist updated user data to disk."""
    user_file = USERS_DIR / f"{username.strip()}.json"
    with user_file.open("w", encoding="utf-8") as file:
        json.dump(user_data, file, indent=2)


def generate_totp_secret(username):
    """Generate and persist a TOTP secret for a user."""
    user_data = get_user(username.strip())
    if not user_data:
        return None

    secret = pyotp.random_base32()
    user_data["totp_secret"] = secret
    _save_user(username, user_data)
    return secret


def get_totp_uri(username, secret):
    """Build a provisioning URI for authenticator apps."""
    return pyotp.totp.TOTP(secret).provisioning_uri(name=username, issuer_name="SecureVault")


def generate_qr_code(username):
    """Generate and save QR code for the user's TOTP setup."""
    user_data = get_user(username.strip())
    if not user_data:
        return None

    secret = user_data.get("totp_secret", "")
    if not secret:
        secret = generate_totp_secret(username)
        if not secret:
            return None

    totp_uri = get_totp_uri(username, secret)
    QRCODES_DIR.mkdir(parents=True, exist_ok=True)
    qr_path = QRCODES_DIR / f"{username.strip()}_qr.png"

    qr_img = qrcode.make(totp_uri)
    qr_img.save(qr_path)
    return str(qr_path)


def verify_otp(username, otp_code):
    """Verify a TOTP code for the specified user."""
    user_data = get_user(username.strip())
    if not user_data:
        return False

    secret = user_data.get("totp_secret", "")
    if not secret:
        return False

    return pyotp.TOTP(secret).verify(otp_code)


def setup_2fa(username):
    """Initialize a user's 2FA secret and QR code."""
    secret = generate_totp_secret(username)
    if not secret:
        return None, None

    qr_path = generate_qr_code(username)
    return secret, qr_path
