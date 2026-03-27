from pathlib import Path
from functools import wraps

from flask import Flask, flash, redirect, render_template, request, session, url_for

from modules.auth import login_user, register_user


app = Flask(__name__)
app.secret_key = "change-this-secret-key"


def create_required_folders() -> None:
    """Create runtime data directories if they do not exist."""
    base_dir = Path(__file__).resolve().parent
    for folder in ["data/users", "data/files", "data/logs"]:
        (base_dir / folder).mkdir(parents=True, exist_ok=True)


create_required_folders()


def login_required(view_func):
    """Protect routes that require an authenticated session."""

    @wraps(view_func)
    def wrapped_view(*args, **kwargs):
        if not session.get("authenticated"):
            flash("Please log in to continue.", "error")
            return redirect(url_for("login"))
        return view_func(*args, **kwargs)

    return wrapped_view


@app.route("/")
def home():
    if session.get("authenticated"):
        return redirect(url_for("dashboard"))
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
        session["authenticated"] = True
        session["otp_verified"] = False
        flash("Login successful.", "success")
        return redirect(url_for("dashboard"))

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
