from urllib import response

from flask import Flask
from config import Config
from database import db
from models.user import User
from flask import Flask, render_template, request
from extensions import bcrypt
from flask import session, redirect, url_for
import os
from werkzeug.utils import secure_filename
from utils.encryption import encrypt_file
from models.file import File
from utils.encryption import (
    encrypt_file,
    decrypt_file
)
from flask import send_file
import io
from models.audit import AuditLog
from flask import (
    Flask,
    render_template,
    request,
    redirect,
    url_for,
    session,
    flash
)
from sqlalchemy import func
from datetime import datetime
import requests
from cryptography.fernet import Fernet


VAULT_TOKEN = os.getenv("ghostvault_super_secret_2026")

app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY")
app.config.from_object(Config)

db.init_app(app)

bcrypt.init_app(app)

with app.app_context():
    db.create_all()

@app.route('/')
def home():
    return render_template("index.html")

@app.route("/register", methods=["GET", "POST"])
def register():

    if request.method == "POST":

        username = request.form.get("username")
        email = request.form.get("email")
        password = request.form.get("password")

        # Check if user already exists
        existing_user = User.query.filter(
            (User.email == email) |
            (User.username == username)
        ).first()

        if existing_user:
            flash("User already exists!", "danger")
            return redirect(url_for("register"))

        # Hash password
        hashed_password = bcrypt.generate_password_hash(
            password
        ).decode("utf-8")

        # Create new user
        new_user = User(
            username=username,
            email=email,
            password=hashed_password
        )

        db.session.add(new_user)
        db.session.commit()

        flash("Registration successful! Please login.", "success")
        flash("Welcome back!", "success")
        return redirect(url_for("login"))

    return render_template("register.html")

@app.route("/login", methods=["GET", "POST"])
def login():

    if request.method == "POST":

        email = request.form.get("email")
        password = request.form.get("password")

        user = User.query.filter_by(
            email=email
        ).first()

        if user and bcrypt.check_password_hash(
            user.password,
            password
        ):

            session["user_id"] = user.id
            session["username"] = user.username

            return redirect(url_for("dashboard"))

        flash("Invalid email or password!", "danger")
        return redirect(url_for("login"))

    return render_template("login.html")

@app.route("/profile")
def profile():

    if "user_id" not in session:
        return redirect(url_for("login"))

    user_files = File.query.filter_by(user_id=session["user_id"]).count()
    logs = AuditLog.query.filter_by(user_id=session["user_id"]).count()

    return render_template(
        "profile.html",
        user_files=user_files,
        logs=logs
    )

@app.route("/dashboard")
def dashboard():

    if "user_id" not in session:
        return redirect(url_for("login"))

    files = File.query.filter_by(
        user_id=session["user_id"]
    ).all()

    recent_logs = AuditLog.query.filter_by(
        user_id=session["user_id"]
    ).order_by(
        AuditLog.timestamp.desc()
    ).limit(5).all()

    return render_template(
        "dashboard.html",
        files=files,
        recent_logs=recent_logs
    )

@app.route("/upload", methods=["POST"])
def upload():

    if "user_id" not in session:
        return redirect(url_for("login"))

    uploaded_file = request.files.get("file")

    if not uploaded_file:
        flash("No file selected", "danger")
        return redirect(url_for("dashboard"))

    # Generate unique file ID
    filename = secure_filename(uploaded_file.filename)

    # Generate unique encryption key
    file_key = Fernet.generate_key()

    # Store key in Key Vault
    requests.post(
        "http://localhost:5001/store_key",

        headers={
            "Authorization":
            f"Bearer {VAULT_TOKEN}"
        },

        json={
            "file_id": filename,
            "encryption_key": file_key.decode()
        }
    )

    # Encrypt file
    cipher = Fernet(file_key)

    data = uploaded_file.read()

    encrypted_data = cipher.encrypt(data)

    # Create storage folder
    os.makedirs("storage", exist_ok=True)

    encrypted_path = os.path.join(
        "storage",
        filename + ".enc"
    )

    # Save encrypted file
    with open(encrypted_path, "wb") as f:
        f.write(encrypted_data)

    # Save file info in database
    new_file = File(
        filename=filename,
        encrypted_path=encrypted_path,
        key_path="Stored in Key Vault",
        user_id=session["user_id"]
    )

    db.session.add(new_file)
    db.session.commit()

    # Audit log
    log = AuditLog(
        action=f"Uploaded {filename}",
        user_id=session["user_id"]
    )

    db.session.add(log)
    db.session.commit()

    flash("File encrypted and stored successfully 🔐", "success")

    return redirect(url_for("dashboard"))

@app.route("/download/<int:file_id>")
def download(file_id):

    if "user_id" not in session:
        return redirect(url_for("login"))

    file = File.query.get_or_404(file_id)

    if file.user_id != session["user_id"]:
        return "Unauthorized"
    
    response = requests.get(
        f"http://localhost:5001/get_key/{file.filename}",

        headers={
            "Authorization":
            f"Bearer {VAULT_TOKEN}"
        }
    )

    # Get key from Key Vault
    response = requests.get(
        f"http://localhost:5001/get_key/{file.filename}",
        headers={
            "Authorization": f"Bearer {VAULT_TOKEN}"
        }
    )

    if response.status_code != 200:
        return "Failed to retrieve decryption key"

    file_key = response.json()["encryption_key"].encode()

    cipher = Fernet(file_key)

    # Read encrypted file
    with open(file.encrypted_path, "rb") as f:
        encrypted_data = f.read()

    # Decrypt file
    decrypted_data = cipher.decrypt(encrypted_data)

    original_name = file.filename

    log = AuditLog(
        action=f"Downloaded {file.filename}",
        user_id=session["user_id"]
    )

    db.session.add(log)
    db.session.commit()

    return send_file(
        io.BytesIO(decrypted_data),
        as_attachment=True,
        download_name=original_name
    )

@app.route("/delete/<int:file_id>")
def delete_file(file_id):

    if "user_id" not in session:
        flash("File deleted permanently.", "warning")
        return redirect(url_for("login"))

    file = File.query.get_or_404(file_id)

    # Prevent unauthorized deletion
    if file.user_id != session["user_id"]:
        return "Unauthorized"

    # Delete encrypted file
    if os.path.exists(file.encrypted_path):
        os.remove(file.encrypted_path)

    # Delete key file
    if os.path.exists(file.key_path):
        os.remove(file.key_path)

    log = AuditLog(
        action=f"Deleted {file.filename}",
        user_id=session["user_id"]
    )

    db.session.add(log)
    db.session.commit()

    # Delete DB record
    db.session.delete(file)
    db.session.commit()

    return redirect(url_for("dashboard"))

@app.route("/audit")
def audit():

    if "user_id" not in session:
        return redirect(url_for("login"))

    logs = AuditLog.query.filter_by(
        user_id=session["user_id"]
    ).order_by(
        AuditLog.timestamp.desc()
    ).all()

    return render_template(
        "audit.html",
        logs=logs
    )

@app.route("/search", methods=["GET"])
def search():

    if "user_id" not in session:
        return redirect(url_for("login"))

    query = request.args.get("q")

    files = File.query.filter(
        File.user_id == session["user_id"],
        File.filename.contains(query)
    ).all()

    recent_logs = AuditLog.query.filter_by(
        user_id=session["user_id"]
    ).order_by(
        AuditLog.timestamp.desc()
    ).limit(5).all()

    return render_template(
        "dashboard.html",
        files=files,
        recent_logs=recent_logs
    )

@app.route("/analytics")
def analytics():

    if "user_id" not in session:
        return redirect(url_for("login"))

    file_count = File.query.filter_by(
        user_id=session["user_id"]
    ).count()

    upload_count = AuditLog.query.filter_by(
        user_id=session["user_id"],
        action="upload"
    ).count()

    delete_count = AuditLog.query.filter_by(
        user_id=session["user_id"],
        action="delete"
    ).count()

    return render_template(
        "analytics.html",
        file_count=file_count,
        upload_count=upload_count,
        delete_count=delete_count
    )

@app.route("/heatmap")
def heatmap():

    if "user_id" not in session:
        return redirect(url_for("login"))

    logs = db.session.query(
        func.date(AuditLog.timestamp),
        func.count(AuditLog.id)
    ).filter_by(
        user_id=session["user_id"]
    ).group_by(
        func.date(AuditLog.timestamp)
    ).all()

    data = [
        {"date": str(d), "count": c}
        for d, c in logs
    ]

    print(data)
    return render_template("heatmap.html", data=data)

@app.route("/insights")
def insights():

    if "user_id" not in session:
        return redirect(url_for("login"))

    logs = AuditLog.query.filter_by(
        user_id=session["user_id"]
    ).all()

    upload_count = sum("Uploaded" in l.action for l in logs)
    delete_count = sum("Deleted" in l.action for l in logs)

    risk_level = "Low"

    if delete_count > upload_count:
        risk_level = "Medium"
    if delete_count > upload_count * 2:
        risk_level = "High"

    return render_template(
        "insights.html",
        upload_count=upload_count,
        delete_count=delete_count,
        risk_level=risk_level
    )

@app.route("/logout")
def logout():

    session.clear()

    return redirect(url_for("login"))

if __name__ == "__main__":
    app.run(debug=True)