from pathlib import Path
from functools import wraps

from flask import Flask, flash, redirect, render_template, request, session, url_for

from modules.auth import get_user, login_user, register_user, setup_2fa, verify_otp


app = Flask(__name__)
app.secret_key = "change-this-secret-key"


def create_required_folders() -> None:
    """Create runtime data directories if they do not exist."""
    base_dir = Path(__file__).resolve().parent
    for folder in ["data/users", "data/files", "data/logs", "static/qrcodes"]:
        (base_dir / folder).mkdir(parents=True, exist_ok=True)


create_required_folders()


def login_required(view_func):
    """Protect routes that require an authenticated session."""

    @wraps(view_func)
    def wrapped_view(*args, **kwargs):
        if not session.get("authenticated") or not session.get("otp_verified"):
            flash("Please complete login and OTP verification.", "error")
            return redirect(url_for("login"))
        return view_func(*args, **kwargs)

    return wrapped_view


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
            flash("Username, email, and password are required.", "error")
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
    else:
        qr_path = str(Path(__file__).resolve().parent / "static" / "qrcodes" / f"{username}_qr.png")
        if not Path(qr_path).exists():
            _, qr_path = setup_2fa(username)

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
        flash("2FA verification successful.", "success")
        return redirect(url_for("dashboard"))

    return render_template("otp.html", qr_code_url=None, first_time_setup=False)


@app.route("/dashboard")
@login_required
def dashboard():
    return render_template("dashboard.html")


@app.route("/files")
@login_required
def files():
    return render_template("files.html")


@app.route("/threats")
@login_required
def threats():
    return render_template("threats.html")


@app.route("/logout")
def logout():
    session.clear()
    flash("You have been logged out.", "success")
    return redirect(url_for("login"))


if __name__ == "__main__":
    app.run(debug=True)
