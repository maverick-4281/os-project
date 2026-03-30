"""
SecureVault - Secure File Management System
CSE-316 Operating Systems | CA2 Project
"""

import json
from datetime import datetime
from functools import wraps
from pathlib import Path

from flask import Flask, flash, redirect, render_template, request, session, url_for

from modules.auth import get_user, login_user, register_user, setup_2fa, verify_otp
from modules.file_ops import (
    decrypt_file, encrypt_file, get_access_log,
    get_encryption_key, get_file_metadata, list_shared_files,
    read_file, revoke_access, set_file_permissions,
    share_file, write_file,
)
from modules.threat_detection import (
    analyze_input_safety, get_threat_level,
    log_threat, scan_content_for_malware, scan_file_for_malware,
)

app = Flask(__name__)
app.secret_key = "securevault-secret-key-cse316"

BASE_DIR = Path(__file__).resolve().parent
USERS_DIR = BASE_DIR / "data" / "users"
FILES_DIR = BASE_DIR / "data" / "files"
LOGS_DIR = BASE_DIR / "data" / "logs"


def create_required_folders():
    for folder in ["data/users", "data/files", "data/logs", "static/qrcodes"]:
        (BASE_DIR / folder).mkdir(parents=True, exist_ok=True)


create_required_folders()


def login_required(view_func):
    @wraps(view_func)
    def wrapped_view(*args, **kwargs):
        if not session.get("authenticated") or not session.get("otp_verified"):
            flash("Please complete login and OTP verification.", "error")
            return redirect(url_for("login"))
        return view_func(*args, **kwargs)
    return wrapped_view


# ─── AUTH ROUTES ─────────────────────────────────────────────────────────────

@app.route("/")
def home():
    if session.get("authenticated") and session.get("otp_verified"):
        return redirect(url_for("dashboard"))
    if session.get("username") and not session.get("otp_verified"):
        return redirect(url_for("otp_verify"))
    return redirect(url_for("login"))


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        if not username or not password:
            flash("Username and password are required.", "error")
            return render_template("login.html")
        is_valid, result = login_user(username, password)
        if not is_valid:
            flash(result, "error")
            return render_template("login.html")
        session["username"] = result["username"]
        session["authenticated"] = False
        session["otp_verified"] = False
        flash("Password verified. Complete OTP verification.", "success")
        return redirect(url_for("otp_verify"))
    return render_template("login.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        email = request.form.get("email", "").strip()
        password = request.form.get("password", "")
        if not username or not email or not password:
            flash("All fields are required.", "error")
            return render_template("register.html")
        is_registered, result = register_user(username, password, email)
        if not is_registered:
            flash(result, "error")
            return render_template("register.html")
        flash("Registration successful. Please log in.", "success")
        return redirect(url_for("login"))
    return render_template("register.html")


@app.route("/setup-2fa")
def setup_2fa_route():
    username = session.get("username")
    if not username:
        flash("Please log in first.", "error")
        return redirect(url_for("login"))
    user_data = get_user(username)
    if not user_data:
        flash("User not found.", "error")
        return redirect(url_for("login"))
    if not user_data.get("totp_secret"):
        secret, qr_path = setup_2fa(username)
        if not secret or not qr_path:
            flash("Failed to set up 2FA.", "error")
            return redirect(url_for("login"))
    qr_file = f"qrcodes/{username}_qr.png"
    return render_template("otp.html", qr_code_url=url_for("static", filename=qr_file), first_time_setup=True)


@app.route("/otp-verify", methods=["GET", "POST"])
def otp_verify():
    username = session.get("username")
    if not username:
        flash("Please log in first.", "error")
        return redirect(url_for("login"))
    user_data = get_user(username)
    if not user_data:
        flash("User not found.", "error")
        return redirect(url_for("login"))
    if not user_data.get("totp_secret"):
        return redirect(url_for("setup_2fa_route"))
    if request.method == "POST":
        otp_code = request.form.get("otp_code", "").strip()
        if not otp_code:
            flash("Please enter the 6-digit OTP code.", "error")
            return render_template("otp.html", qr_code_url=None, first_time_setup=False)
        if not verify_otp(username, otp_code):
            flash("Invalid OTP code. Try again.", "error")
            return render_template("otp.html", qr_code_url=None, first_time_setup=False)
        session["authenticated"] = True
        session["otp_verified"] = True
        flash("2FA verification successful. Welcome!", "success")
        return redirect(url_for("dashboard"))
    return render_template("otp.html", qr_code_url=None, first_time_setup=False)


@app.route("/logout")
def logout():
    session.clear()
    flash("You have been logged out.", "success")
    return redirect(url_for("login"))


# ─── DASHBOARD ───────────────────────────────────────────────────────────────

@app.route("/dashboard")
@login_required
def dashboard():
    username = session.get("username")
    user_data = get_user(username) or {}
    files = user_data.get("files", [])
    shared = list_shared_files(username)
    encrypted = [f for f in files if f.get("is_encrypted")]

    threat_log = LOGS_DIR / "threats.log"
    threat_count = 0
    if threat_log.exists():
        with open(threat_log) as f:
            threat_count = sum(1 for line in f if line.strip())

    stats = {
        "total_files": len(files),
        "shared_files": len(shared),
        "encrypted_files": len(encrypted),
        "threats_detected": threat_count,
    }

    log_content = get_access_log(username)
    recent_logs = log_content.strip().split("\n")[-5:] if log_content.strip() else []

    return render_template("dashboard.html", stats=stats, recent_logs=recent_logs, username=username)


# ─── FILE ROUTES ─────────────────────────────────────────────────────────────

@app.route("/files")
@login_required
def files():
    username = session.get("username")
    user_data = get_user(username) or {}
    files_metadata = []
    for entry in user_data.get("files", []):
        metadata = get_file_metadata(username, entry.get("filename", ""))
        if metadata:
            files_metadata.append(metadata)
    shared = list_shared_files(username)
    return render_template("files.html", files=files_metadata, shared=shared,
                           file_content=None, active_file=None, view_mode=None)


@app.route("/files/upload", methods=["POST"])
@login_required
def upload_file():
    username = session.get("username")
    filename = request.form.get("filename", "").strip()
    content = request.form.get("content", "")
    if not filename:
        flash("Filename is required.", "error")
        return redirect(url_for("files"))
    status, message = write_file(username, filename, content)
    flash(message, "success" if status else "error")
    return redirect(url_for("files"))


@app.route("/files/read/<filename>")
@login_required
def read_user_file(filename):
    username = session.get("username")
    content, error = read_file(username, filename)
    user_data = get_user(username) or {}
    files_metadata = []
    for entry in user_data.get("files", []):
        metadata = get_file_metadata(username, entry.get("filename", ""))
        if metadata:
            files_metadata.append(metadata)
    shared = list_shared_files(username)
    if error:
        flash(error, "error")
        return render_template("files.html", files=files_metadata, shared=shared,
                               file_content=None, active_file=None, view_mode=None)
    return render_template("files.html", files=files_metadata, shared=shared,
                           file_content=content, active_file=filename, view_mode="read")


@app.route("/files/encrypt/<filename>", methods=["POST"])
@login_required
def encrypt_user_file(filename):
    username = session.get("username")
    status, message = encrypt_file(username, filename)
    flash(message, "success" if status else "error")
    return redirect(url_for("files"))


@app.route("/files/decrypt/<filename>")
@login_required
def decrypt_user_file(filename):
    username = session.get("username")
    plaintext, error = decrypt_file(username, filename)
    user_data = get_user(username) or {}
    files_metadata = []
    for entry in user_data.get("files", []):
        metadata = get_file_metadata(username, entry.get("filename", ""))
        if metadata:
            files_metadata.append(metadata)
    shared = list_shared_files(username)
    if error:
        flash(error, "error")
        return render_template("files.html", files=files_metadata, shared=shared,
                               file_content=None, active_file=None, view_mode=None)
    return render_template("files.html", files=files_metadata, shared=shared,
                           file_content=plaintext, active_file=filename, view_mode="decrypt")


@app.route("/files/share/<filename>", methods=["POST"])
@login_required
def share_user_file(filename):
    username = session.get("username")
    target = request.form.get("target_username", "").strip()
    if not target:
        flash("Target username is required.", "error")
        return redirect(url_for("files"))
    status, message = share_file(username, filename, target)
    flash(message, "success" if status else "error")
    return redirect(url_for("files"))


@app.route("/files/revoke/<filename>", methods=["POST"])
@login_required
def revoke_user_file(filename):
    username = session.get("username")
    target = request.form.get("target_username", "").strip()
    status, message = revoke_access(username, filename, target)
    flash(message, "success" if status else "error")
    return redirect(url_for("files"))


@app.route("/files/permissions/<filename>", methods=["POST"])
@login_required
def set_permissions(filename):
    username = session.get("username")
    permission = request.form.get("permission", "rw")
    status, message = set_file_permissions(username, filename, permission)
    flash(message, "success" if status else "error")
    return redirect(url_for("files"))


@app.route("/files/logs")
@login_required
def file_logs():
    username = session.get("username")
    log_content = get_access_log(username)
    logs = log_content.strip().split("\n") if log_content.strip() else []
    return render_template("logs.html", logs=logs, username=username)


@app.route("/files/metadata/<filename>")
@login_required
def file_metadata(filename):
    username = session.get("username")
    metadata = get_file_metadata(username, filename)
    if not metadata:
        flash("File not found.", "error")
        return redirect(url_for("files"))
    return render_template("metadata.html", metadata=metadata, filename=filename)


# ─── THREAT ROUTES ───────────────────────────────────────────────────────────

@app.route("/threats")
@login_required
def threats():
    username = session.get("username")
    user_data = get_user(username) or {}
    user_files = [f.get("filename") for f in user_data.get("files", [])]

    threat_log = LOGS_DIR / "threats.log"
    threat_logs = []
    if threat_log.exists():
        with open(threat_log) as f:
            for line in f:
                line = line.strip()
                if line:
                    try:
                        threat_logs.append(json.loads(line))
                    except Exception:
                        pass

    return render_template("threats.html", user_files=user_files,
                           threat_logs=threat_logs, scan_result=None, input_result=None)


@app.route("/threats/scan-input", methods=["POST"])
@login_required
def scan_input():
    username = session.get("username")
    user_input = request.form.get("user_input", "")
    input_result = analyze_input_safety(user_input)
    malware_result = scan_content_for_malware(user_input)
    input_result["malware"] = malware_result
    if input_result["threat_level"] != "CLEAN":
        log_threat(username, {"source": "input_scan", "result": input_result})

    user_data = get_user(username) or {}
    user_files = [f.get("filename") for f in user_data.get("files", [])]
    threat_log = LOGS_DIR / "threats.log"
    threat_logs = []
    if threat_log.exists():
        with open(threat_log) as f:
            for line in f:
                line = line.strip()
                if line:
                    try:
                        threat_logs.append(json.loads(line))
                    except Exception:
                        pass

    return render_template("threats.html", user_files=user_files,
                           threat_logs=threat_logs, scan_result=None,
                           input_result=input_result)


@app.route("/threats/scan-file/<filename>", methods=["POST"])
@login_required
def scan_file(filename):
    username = session.get("username")
    file_path = FILES_DIR / username / filename
    scan_result = scan_file_for_malware(str(file_path))
    scan_result["threat_level"] = get_threat_level(scan_result)
    log_threat(username, {"source": f"file_scan:{filename}", "result": scan_result})

    user_data = get_user(username) or {}
    user_files = [f.get("filename") for f in user_data.get("files", [])]
    threat_log = LOGS_DIR / "threats.log"
    threat_logs = []
    if threat_log.exists():
        with open(threat_log) as f:
            for line in f:
                line = line.strip()
                if line:
                    try:
                        threat_logs.append(json.loads(line))
                    except Exception:
                        pass

    return render_template("threats.html", user_files=user_files,
                           threat_logs=threat_logs, scan_result=scan_result,
                           input_result=None)


# ─── API ─────────────────────────────────────────────────────────────────────

@app.route("/api/stats")
@login_required
def api_stats():
    total_users = len(list(USERS_DIR.glob("*.json")))
    total_files = sum(1 for _ in FILES_DIR.rglob("*") if _.is_file())
    threat_log = LOGS_DIR / "threats.log"
    total_threats = 0
    if threat_log.exists():
        with open(threat_log) as f:
            total_threats = sum(1 for line in f if line.strip())
    return {"total_users": total_users, "total_files": total_files, "total_threats": total_threats}


@app.route("/health")
def health():
    return {"status": "ok", "modules": ["auth", "file_ops", "threat_detection"]}


if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=5000)