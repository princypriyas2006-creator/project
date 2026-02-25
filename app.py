import os
import random
import string
from datetime import datetime, timedelta, timezone
from functools import wraps

import jwt
from flask import Flask, request, jsonify, send_from_directory, redirect, make_response
from flask_cors import CORS
from flask_mail import Mail, Message
from werkzeug.security import generate_password_hash, check_password_hash

from models import SessionLocal, User, OTP, init_db

# ─────────────────────────── CONFIG ──────────────────────────────────────────
app = Flask(__name__, static_folder=".", static_url_path="")
app.config["SECRET_KEY"] = "stylesense-secret-key-change-in-production"

# Gmail SMTP
app.config["MAIL_SERVER"] = "smtp.gmail.com"
app.config["MAIL_PORT"] = 587
app.config["MAIL_USE_TLS"] = True
app.config["MAIL_USERNAME"] = "gpremkumar0911@gmail.com"
app.config["MAIL_PASSWORD"] = "zwhh fttc xeff ecwk"
app.config["MAIL_DEFAULT_SENDER"] = ("StyleSense", "gpremkumar0911@gmail.com")

CORS(app)
mail = Mail(app)

JWT_SECRET = app.config["SECRET_KEY"]
JWT_ALGORITHM = "HS256"
JWT_EXPIRY_HOURS = 24


# ─────────────────────────── HELPERS ─────────────────────────────────────────
def generate_otp(length=6):
    return "".join(random.choices(string.digits, k=length))


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def db_session():
    return SessionLocal()


def create_jwt(user):
    payload = {
        "user_id": user.id,
        "email": user.email,
        "name": user.name,
        "exp": datetime.now(timezone.utc) + timedelta(hours=JWT_EXPIRY_HOURS),
        "iat": datetime.now(timezone.utc),
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)


def decode_jwt(token):
    try:
        return jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
    except jwt.ExpiredSignatureError:
        return None
    except jwt.InvalidTokenError:
        return None


def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        # Check Authorization header
        auth_header = request.headers.get("Authorization", "")
        if auth_header.startswith("Bearer "):
            token = auth_header.split(" ")[1]
        # Check cookie
        if not token:
            token = request.cookies.get("token")
        if not token:
            return jsonify({"error": "Authentication required"}), 401
        payload = decode_jwt(token)
        if not payload:
            return jsonify({"error": "Invalid or expired token"}), 401
        request.user_payload = payload
        return f(*args, **kwargs)
    return decorated


def send_otp_email(email, otp_code, name="there"):
    html_body = f"""
    <div style="font-family:'Inter',Arial,sans-serif; max-width:480px; margin:0 auto; padding:40px 30px; background:#FAF7F4; border-radius:16px;">
        <div style="text-align:center; margin-bottom:30px;">
            <span style="font-size:28px; font-weight:700; font-family:'Georgia',serif; color:#1A1A1A;">Style<span style="color:#D4787B;">Sense</span></span>
        </div>
        <h2 style="color:#1A1A1A; font-size:22px; margin:0 0 8px; text-align:center;">Verify Your Email</h2>
        <p style="color:#666; font-size:14px; text-align:center; margin:0 0 30px;">Hi {name}, use the code below to complete your registration.</p>
        <div style="background:linear-gradient(135deg,#1A1A1A,#2D2D2D); border-radius:12px; padding:24px; text-align:center; margin-bottom:24px;">
            <span style="font-size:36px; font-weight:700; letter-spacing:8px; color:#F4C2C2;">{otp_code}</span>
        </div>
        <p style="color:#999; font-size:12px; text-align:center;">This code expires in <strong>10 minutes</strong>. If you didn't request this, please ignore this email.</p>
        <hr style="border:none; border-top:1px solid #EDE5DB; margin:24px 0;" />
        <p style="color:#BBB; font-size:11px; text-align:center;">© 2026 StyleSense. All rights reserved.</p>
    </div>
    """
    msg = Message(
        subject="Your StyleSense Verification Code",
        recipients=[email],
        html=html_body,
    )
    mail.send(msg)


# ─────────────────────────── ROUTES ─────────────────────────────────────────

# --- Pages ---
@app.route("/")
def index():
    return send_from_directory(".", "index.html")


@app.route("/dashboard")
def dashboard_page():
    token = request.cookies.get("token")
    if not token or not decode_jwt(token):
        return redirect("/")
    return send_from_directory(".", "dashboard.html")


# --- Auth API ---
@app.route("/api/signup", methods=["POST"])
def signup():
    data = request.get_json()
    name = data.get("name", "").strip()
    email = data.get("email", "").strip().lower()

    if not name or not email:
        return jsonify({"error": "Name and email are required"}), 400

    db = db_session()
    try:
        existing = db.query(User).filter(User.email == email).first()
        if existing and existing.verified:
            return jsonify({"error": "An account with this email already exists"}), 409

        # Create or update unverified user
        if existing and not existing.verified:
            existing.name = name
            user = existing
        else:
            user = User(name=name, email=email, verified=False)
            db.add(user)

        # Invalidate old OTPs
        db.query(OTP).filter(OTP.email == email, OTP.used == False).update({"used": True})

        # Generate new OTP
        otp_code = generate_otp()
        otp = OTP(
            email=email,
            otp_code=otp_code,
            purpose="signup",
            expires_at=datetime.utcnow() + timedelta(minutes=10),
        )
        db.add(otp)
        db.commit()

        # Send OTP email
        try:
            send_otp_email(email, otp_code, name)
        except Exception as e:
            db.rollback()
            return jsonify({"error": f"Failed to send OTP email: {str(e)}"}), 500

        return jsonify({"message": "OTP sent to your email", "email": email}), 200

    except Exception as e:
        db.rollback()
        return jsonify({"error": str(e)}), 500
    finally:
        db.close()


@app.route("/api/verify-otp", methods=["POST"])
def verify_otp():
    data = request.get_json()
    email = data.get("email", "").strip().lower()
    otp_code = data.get("otp", "").strip()
    password = data.get("password", "")

    if not email or not otp_code or not password:
        return jsonify({"error": "Email, OTP, and password are required"}), 400

    if len(password) < 6:
        return jsonify({"error": "Password must be at least 6 characters"}), 400

    db = db_session()
    try:
        otp = (
            db.query(OTP)
            .filter(
                OTP.email == email,
                OTP.otp_code == otp_code,
                OTP.purpose == "signup",
                OTP.used == False,
            )
            .order_by(OTP.created_at.desc())
            .first()
        )

        if not otp:
            return jsonify({"error": "Invalid OTP code"}), 400

        if datetime.utcnow() > otp.expires_at:
            otp.used = True
            db.commit()
            return jsonify({"error": "OTP has expired. Please request a new one"}), 400

        # Mark OTP as used
        otp.used = True

        # Update user
        user = db.query(User).filter(User.email == email).first()
        if not user:
            return jsonify({"error": "User not found"}), 404

        user.password_hash = generate_password_hash(password)
        user.verified = True
        db.commit()

        # Generate JWT
        token = create_jwt(user)
        resp = jsonify({"message": "Account verified successfully", "token": token, "user": user.to_dict()})
        resp.set_cookie("token", token, httponly=False, samesite="Lax", max_age=JWT_EXPIRY_HOURS * 3600)
        return resp, 200

    except Exception as e:
        db.rollback()
        return jsonify({"error": str(e)}), 500
    finally:
        db.close()


@app.route("/api/login", methods=["POST"])
def login():
    data = request.get_json()
    email = data.get("email", "").strip().lower()
    password = data.get("password", "")

    if not email or not password:
        return jsonify({"error": "Email and password are required"}), 400

    db = db_session()
    try:
        user = db.query(User).filter(User.email == email).first()

        if not user:
            return jsonify({"error": "No account found with this email"}), 404

        if not user.verified:
            return jsonify({"error": "Account not verified. Please sign up again"}), 403

        if not user.password_hash or not check_password_hash(user.password_hash, password):
            return jsonify({"error": "Incorrect password"}), 401

        token = create_jwt(user)
        resp = jsonify({"message": "Login successful", "token": token, "user": user.to_dict()})
        resp.set_cookie("token", token, httponly=False, samesite="Lax", max_age=JWT_EXPIRY_HOURS * 3600)
        return resp, 200

    except Exception as e:
        return jsonify({"error": str(e)}), 500
    finally:
        db.close()


@app.route("/api/me", methods=["GET"])
@token_required
def get_me():
    db = db_session()
    try:
        user = db.query(User).filter(User.id == request.user_payload["user_id"]).first()
        if not user:
            return jsonify({"error": "User not found"}), 404
        return jsonify({"user": user.to_dict()}), 200
    finally:
        db.close()


@app.route("/api/logout", methods=["POST"])
def logout():
    resp = jsonify({"message": "Logged out successfully"})
    resp.delete_cookie("token")
    return resp, 200


@app.route("/api/resend-otp", methods=["POST"])
def resend_otp():
    data = request.get_json()
    email = data.get("email", "").strip().lower()

    if not email:
        return jsonify({"error": "Email is required"}), 400

    db = db_session()
    try:
        user = db.query(User).filter(User.email == email).first()
        if not user:
            return jsonify({"error": "No signup found for this email"}), 404

        if user.verified:
            return jsonify({"error": "Account already verified. Please login"}), 409

        # Invalidate old OTPs
        db.query(OTP).filter(OTP.email == email, OTP.used == False).update({"used": True})

        otp_code = generate_otp()
        otp = OTP(
            email=email,
            otp_code=otp_code,
            purpose="signup",
            expires_at=datetime.utcnow() + timedelta(minutes=10),
        )
        db.add(otp)
        db.commit()

        try:
            send_otp_email(email, otp_code, user.name)
        except Exception as e:
            db.rollback()
            return jsonify({"error": f"Failed to send OTP: {str(e)}"}), 500

        return jsonify({"message": "New OTP sent to your email"}), 200

    except Exception as e:
        db.rollback()
        return jsonify({"error": str(e)}), 500
    finally:
        db.close()


# ─────────────────────────── MAIN ────────────────────────────────────────────
if __name__ == "__main__":
    init_db()
    print("\n  StyleSense server running at http://localhost:5000\n")
    app.run(debug=True, host="0.0.0.0", port=5000)
