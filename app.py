from pathlib import Path

from flask import Flask, render_template


app = Flask(__name__)
app.secret_key = "change-this-secret-key"


def create_required_folders() -> None:
    """Create runtime data directories if they do not exist."""
    base_dir = Path(__file__).resolve().parent
    for folder in ["data/users", "data/files", "data/logs"]:
        (base_dir / folder).mkdir(parents=True, exist_ok=True)


create_required_folders()


@app.route("/")
def home():
    return render_template("login.html")


@app.route("/login")
def login():
    return render_template("login.html")


@app.route("/register")
def register():
    return render_template("register.html")


@app.route("/dashboard")
def dashboard():
    return render_template("dashboard.html")


@app.route("/files")
def files():
    return render_template("files.html")


@app.route("/threats")
def threats():
    return render_template("threats.html")


if __name__ == "__main__":
    app.run(debug=True)
