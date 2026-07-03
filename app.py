import struct
import os
import json
import subprocess
import threading
import random
import time
import pty
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from functools import wraps
import psutil
from flask import (
    Flask,
    render_template,
    request,
    redirect,
    session,
    jsonify,
    send_file,
    url_for,
    flash,
)
from flask_socketio import SocketIO, emit
from database import (
    init_db,
    get_user_by_email,
    get_all_users,
    add_user,
    delete_user,
    save_scan,
    get_scan_history,
    log_activity,
    get_activity_log,
    get_dashboard_stats,
    hash_password,
)
from modules.scanner import run_simulation
import base64
import hashlib
import hmac
import json
from modules.ai import ask_ai, ask_ai_with_history
from modules.auth import authenticate, has_permission
from modules.report_gen import generate_pdf_report

# ── Email Verification Store ─────────────────────────────────────
# { 'abrehamabebe1921@gmail.com': {'code': '123456', 'expires': timestamp} }
_VERIFY_STORE = {}
_VERIFY_EMAIL = "abrehamabebe1921@gmail.com"

# Gmail SMTP credentials  (App Password — replace with your real app password)
_SMTP_SENDER = "abrehamabebe1921@gmail.com"
_SMTP_PASS = "xrrx hjex qjad xtuh"
_SMTP_HOST = "smtp.gmail.com"
_SMTP_PORT = 587

app = Flask(__name__)
app.config["SESSION_COOKIE_HTTPONLY"] = False
app.secret_key = os.environ.get("TM_SECRET_KEY", os.urandom(32).hex())

socketio = SocketIO(app, cors_allowed_origins="*", async_mode="threading")

# Initialize the database
init_db()

# ── Lab Sessions ──────────────────────────────────────────────
_XSS_SESSIONS = {}  # session_id -> {username, role}


# ── Decorators ──────────────────────────────────────────────
def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if "username" not in session:
            return redirect("/login")
        return f(*args, **kwargs)

    return decorated


def role_required(*roles):
    def decorator(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            if "role" not in session or session.get("role") not in roles:
                flash("Insufficient permissions", "error")
                return redirect("/dashboard")
            return f(*args, **kwargs)

        return decorated

    return decorator


# ── Pages ───────────────────────────────────────────────────
@app.route("/")
def home():
    return redirect("/login")


@app.route("/login", methods=["GET", "POST"])
def login():
    error = None
    if request.method == "POST":
        email = request.form.get("email", "")
        password = request.form.get("password", "")
        user = authenticate(email, password)
        if user:
            session["user"] = user["email"]
            session["user_id"] = user["id"]
            session["username"] = user["username"]
            session["role"] = user["role"]
            log_activity(user["id"], "login", f'{user["username"]} logged in')
            return redirect("/dashboard")
        else:
            error = "Invalid credentials"
    return render_template("login.html", error=error)


# ── Email Verification Endpoints ────────────────────────────────
def _send_otp_email(code: str) -> bool:
    """Send a 6-digit OTP to the fixed verification address via Gmail SMTP."""
    try:
        msg = MIMEMultipart("alternative")
        msg["Subject"] = "🔐 SecureSphere — Your Verification Code"
        msg["From"] = _SMTP_SENDER
        msg["To"] = _VERIFY_EMAIL

        html_body = f"""
        <div style="background:#0a0a0a;padding:40px;font-family:'Courier New',monospace;color:#00ff88;border-radius:12px;max-width:480px;margin:0 auto;">
          <div style="text-align:center;margin-bottom:24px;">
            <div style="font-size:48px;">🛡️</div>
            <h1 style="font-size:20px;letter-spacing:0.2em;color:#00ff88;margin:8px 0;">THREATMAPPER</h1>
            <p style="color:rgba(0,255,136,0.45);font-size:11px;margin:0;">EACA SUMMIT 2026 HACKATHON · Security Lab</p>
          </div>
          <hr style="border:none;border-top:1px solid rgba(0,255,136,0.2);margin:20px 0;">
          <p style="color:rgba(255,255,255,0.7);font-size:13px;text-align:center;">Your one-time verification code is:</p>
          <div style="text-align:center;margin:24px 0;">
            <span style="background:rgba(0,255,136,0.1);border:2px solid rgba(0,255,136,0.5);border-radius:12px;
                         padding:16px 32px;font-size:36px;font-weight:bold;letter-spacing:0.4em;color:#00ff88;
                         text-shadow:0 0 20px rgba(0,255,136,0.8);">{code}</span>
          </div>
          <p style="color:rgba(255,255,255,0.45);font-size:11px;text-align:center;">
            ⏱ This code is valid for <strong style="color:#ff8c00;">60 seconds</strong> only.<br>
            Do not share this code with anyone.
          </p>
          <hr style="border:none;border-top:1px solid rgba(0,255,136,0.1);margin:20px 0;">
          <p style="color:rgba(255,255,255,0.2);font-size:10px;text-align:center;">
            © EACA SUMMIT 2026 HACKATHON Cyber Security Lab · SecureSphere
          </p>
        </div>
        """
        plain_body = (
            f"Your SecureSphere verification code is: {code}\nValid for 60 seconds.")

        msg.attach(MIMEText(plain_body, "plain"))
        msg.attach(MIMEText(html_body, "html"))

        with smtplib.SMTP(_SMTP_HOST, _SMTP_PORT, timeout=10) as server:
            server.ehlo()
            server.starttls()
            server.login(_SMTP_SENDER, _SMTP_PASS)
            server.sendmail(_SMTP_SENDER, _VERIFY_EMAIL, msg.as_string())
        return True
    except Exception as e:
        print(f"[EMAIL ERROR] {e}")
        return False


@app.route("/api/send-verification", methods=["POST"])
def api_send_verification():
    code = f"{random.randint(100000, 999999)}"
    _VERIFY_STORE[_VERIFY_EMAIL] = {
        "code": code,
        "expires": time.time() + 60,  # 60-second window
    }
    success = _send_otp_email(code)
    if success:
        return jsonify({"status": "sent", "email": _VERIFY_EMAIL})
    else:
        # Fallback: return code in response for dev/demo (remove in
        # production!)
        return jsonify(
            {"status": "fallback", "email": _VERIFY_EMAIL, "code": code})


@app.route("/api/verify-code", methods=["POST"])
def api_verify_code():
    data = request.get_json(silent=True) or {}
    entered = str(data.get("code", "")).strip()
    record = _VERIFY_STORE.get(_VERIFY_EMAIL)
    if not record:
        return jsonify({"valid": False, "reason": "No code issued"})
    if time.time() > record["expires"]:
        del _VERIFY_STORE[_VERIFY_EMAIL]
        return jsonify({"valid": False, "reason": "Code expired"})
    if entered == record["code"]:
        del _VERIFY_STORE[_VERIFY_EMAIL]
        return jsonify({"valid": True})
    return jsonify({"valid": False, "reason": "Incorrect code"})


@app.route("/dashboard")
@login_required
def dashboard():
    perms = {
        "terminal": has_permission(session["role"], "terminal"),
        "reports": has_permission(session["role"], "reports"),
        "users": has_permission(session["role"], "users"),
        "scanner": has_permission(session["role"], "scanner"),
    }
    vulns = [
        "SQL Injection",
        "XSS Attack",
        "Broken Access",
        "Security Misconfig",
        "Data Exposure",
        "Insecure Deserial",
        "Vuln Components",
        "Auth Failures",
        "SSRF Attack",
        "CSRF Attack",
    ]
    return render_template(
        "dashboard.html",
        username=session["username"],
        role=session["role"],
        perms=perms,
        vulns=vulns,
    )


@app.route("/terminal")
@login_required
def terminal():
    if not has_permission(session["role"], "terminal"):
        return redirect("/dashboard")
    return render_template(
        "terminal.html", username=session["username"], role=session["role"]
    )


@app.route("/reports")
@login_required
def reports():
    if not has_permission(session["role"], "reports"):
        return redirect("/dashboard")
    return render_template(
        "reports.html", username=session["username"], role=session["role"]
    )


@app.route("/logout")
def logout():
    if "user_id" in session:
        log_activity(session["user_id"], "logout", f'{
            session.get(
                "username", "")} logged out')
    session.clear()
    return redirect("/login")


@app.route("/access-granted")
def access_granted():
    return render_template("access_granted.html")


# ── Lab Routes ──────────────────────────────────────────────
@app.route("/labs/xss_low", methods=["GET", "POST"])
@login_required
def aaulab_xss_low():
    flag = "FLAG{xss_reflected_low_exploited}"
    error = None
    # Simple user credentials similar to IDOR lab
    users = {
        "Abreham": {"pass": "passwd1", "role": "Admin"},
        "Tesfabesh": {"pass": "passwd2", "role": "User"},
        "Natty": {"pass": "passwd3", "role": "User"},
    }
    # ── Session Management ──
    import uuid

    def create_lab_session(username, role):
        sid = f"XSS-{uuid.uuid4().hex[:8].upper()}"
        _XSS_SESSIONS[sid] = {"username": username, "role": role}
        return sid

    # Quick-login via GET ?quick=
    quick = request.args.get("quick", "").strip()
    if quick in users:
        session["xss_username"] = quick
        sid = create_lab_session(quick, users[quick]["role"])
        resp = redirect("/labs/xss_low")
        resp.set_cookie("XSS_SESSION_ID", sid, httponly=False, samesite="Lax")
        return resp

    if request.method == "POST":
        if "logout" in request.form:
            session.pop("xss_username", None)
            sid = request.cookies.get("XSS_SESSION_ID")
            if sid in _XSS_SESSIONS:
                del _XSS_SESSIONS[sid]
            resp = redirect("/labs/xss_low")
            resp.delete_cookie("XSS_SESSION_ID")
            return resp
        post_user = request.form.get("username", "").strip()
        post_pass = request.form.get("password", "").strip()
        if post_user in users and users[post_user]["pass"] == post_pass:
            session["xss_username"] = post_user
            sid = create_lab_session(post_user, users[post_user]["role"])
            resp = redirect("/labs/xss_low")
            resp.set_cookie(
                "XSS_SESSION_ID",
                sid,
                httponly=False,
                samesite="Lax")
            return resp
        else:
            error = "Invalid Username or Password."

    # Read current session from cookie
    sid = request.cookies.get("XSS_SESSION_ID")
    lab_session = _XSS_SESSIONS.get(sid)
    logged_in_user = (
        lab_session["username"] if lab_session else session.get("xss_username")
    )

    name = request.args.get("name")
    flag_output = None
    if name and "<script>" in name.lower():
        flag_output = flag

    return render_template(
        "lab_xss_low.html",
        name=name,
        flag_output=flag_output,
        logged_in_user=logged_in_user,
        error=error,
        available_users=users,
        lab_session=lab_session,
        sid=sid,
    )


@app.route("/labs/xss_medium", methods=["GET", "POST"])
@login_required
def aaulab_xss_medium():
    flag = "FLAG{xss_reflected_medium_exploited}"
    name = request.args.get("name")
    flag_output = None
    if name:
        sanitized = name.replace("<script>", "")
        if "<script>" in name.lower():
            flag_output = flag
    else:
        sanitized = ""
    return render_template(
        "lab_xss_medium.html", name=sanitized, flag_output=flag_output
    )


@app.route("/labs/xss_high", methods=["GET", "POST"])
@login_required
def aaulab_xss_high():
    flag = "FLAG{xss_reflected_high_exploited}"
    name = request.args.get("name")
    flag_output = None
    if name:
        import re

        sanitized = re.sub(r"<(.*)s(.*)c(.*)r(.*)i(.*)p(.*)t/i", "", name)
        if (
            "script" in name.lower()
            or "onerror" in name.lower()
            or "onload" in name.lower()
            or "prompt" in name.lower()
        ):
            flag_output = flag
    else:
        sanitized = ""
    return render_template(
        "lab_xss_high.html",
        name=sanitized,
        flag_output=flag_output)


# ─────────────────────────────────────────────────────────────
# JWT Lab — Shared Utilities
# ─────────────────────────────────────────────────────────────


def _b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("utf-8")


def _b64url_decode(data: str) -> bytes:
    padding = "=" * (-len(data) % 4)
    return base64.urlsafe_b64decode(data + padding)


def _sign_hs256(header_b64: str, payload_b64: str, secret: str) -> str:
    msg = f"{header_b64}.{payload_b64}".encode("utf-8")
    sig = hmac.new(secret.encode("utf-8"), msg, hashlib.sha256).digest()
    return _b64url_encode(sig)


def _sign_hs256_bytes(
        header_b64: str,
        payload_b64: str,
        secret_bytes: bytes) -> str:
    msg = f"{header_b64}.{payload_b64}".encode("utf-8")
    sig = hmac.new(secret_bytes, msg, hashlib.sha256).digest()
    return _b64url_encode(sig)


def _decode_token_parts(token: str):
    """Decode token header+payload, return (header_dict, payload_dict, parts) or raise."""
    parts = token.split(".")
    if len(parts) != 3:
        return None, None, parts
    h_b64, p_b64, _ = parts
    try:
        header = json.loads(_b64url_decode(h_b64).decode("utf-8"))
        payload = json.loads(_b64url_decode(p_b64).decode("utf-8"))
    except Exception:
        return None, None, parts
    return header, payload, parts


_JWT_USERS = [
    {
        "id": 1,
        "username": "Hermela",
        "password": "passwd4",
        "name": "Hermela",
        "role": "admin",
    },
    {
        "id": 2,
        "username": "Abreham",
        "password": "passwd1",
        "name": "Abreham",
        "role": "user",
    },
    {
        "id": 3,
        "username": "Hany",
        "password": "passwd2",
        "name": "Hany",
        "role": "user",
    },
    {
        "id": 4,
        "username": "Mikiyas",
        "password": "passwd3",
        "name": "Mikiyas",
        "role": "user",
    },
    {
        "id": 5,
        "username": "Bikila",
        "password": "passwd5",
        "name": "Bikila",
        "role": "user",
    },
    {
        "id": 6,
        "username": "Mastewal",
        "password": "passwd6",
        "name": "Mastewal",
        "role": "user",
    },
]


def _find_jwt_user(username, password):
    for u in _JWT_USERS:
        if u["username"] == username and u["password"] == password:
            return u
    return None


def _find_jwt_user_by_id(uid):
    for u in _JWT_USERS:
        if str(u["id"]) == str(uid):
            return u
    return None


# ─────────────────────────────────────────────────────────────
# JWT LOW — alg=none bypass
# ─────────────────────────────────────────────────────────────
_JWT_LOW_SECRET = "supersecretkey-change-me"
_FLAG_JWT_LOW = "FLAG{jwt_alg_none_exploited}"


def _issue_jwt_low(user: dict) -> str:
    header = {"typ": "JWT", "alg": "HS256"}
    payload = {"id": user["id"], "role": user["role"], "iat": int(time.time())}
    h_b64 = _b64url_encode(json.dumps(header, separators=(",", ":")).encode())
    p_b64 = _b64url_encode(json.dumps(payload, separators=(",", ":")).encode())
    sig = _sign_hs256(h_b64, p_b64, _JWT_LOW_SECRET)
    return f"{h_b64}.{p_b64}.{sig}"


def _verify_jwt_low(token: str):
    """Vulnerable: alg=none accepted without signature check."""
    header, payload, parts = _decode_token_parts(token)
    if header is None:
        return False, None, "Malformed token"
    alg = header.get("alg", "").lower()
    if alg == "none":
        return True, payload, ""  # BUG: no signature check
    if alg.startswith("hs"):
        h_b64, p_b64, s_b64 = parts
        expected = _sign_hs256(h_b64, p_b64, _JWT_LOW_SECRET)
        if not hmac.compare_digest(expected, s_b64):
            return False, None, "Invalid signature"
        return True, payload, ""
    return False, None, "Unsupported alg"


# ── Credential map for quick-login shortcuts ──
_QUICK_CREDS = {
    "admin": ("Hermela", "passwd4"),
    "user": ("Abreham", "passwd1"),
    "hermela": ("Hermela", "passwd4"),
    "abreham": ("Abreham", "passwd1"),
}


@app.route("/labs/jwt_low", methods=["GET", "POST"])
@login_required
def aaulab_jwt_low():
    error = None
    flag_output = None
    jwt_user = None
    jwt_role = None
    raw_token = None
    decoded_header = None
    decoded_payload = None

    # ── Quick-login via GET ?quick=<role|username> ──
    quick = request.args.get("quick", "").lower().strip()
    if quick in _QUICK_CREDS:
        uname, passwd = _QUICK_CREDS[quick]
        found = _find_jwt_user(uname, passwd)
        if found:
            token = _issue_jwt_low(found)
            resp = redirect("/labs/jwt_low")
            resp.set_cookie(
                "jwt_low", token, httponly=False, samesite="Lax", max_age=3600
            )
            return resp
    # ── Lab actions ──
    if request.method == "POST":
        if "jwtl_clear" in request.form:
            resp = redirect("/labs/jwt_low")
            resp.delete_cookie("jwt_low")
            return resp
        if "jwtl_login" in request.form:
            uname = request.form.get("username", "").strip()
            passwd = request.form.get("password", "").strip()
            found = _find_jwt_user(uname, passwd)
            if found:
                token = _issue_jwt_low(found)
                resp = redirect("/labs/jwt_low")
                resp.set_cookie(
                    "jwt_low",
                    token,
                    httponly=False,
                    samesite="Lax",
                    max_age=3600)
                return resp
            else:
                error = "Invalid Username or Password."

    # ── Read & verify cookie ──
    raw_token = request.cookies.get("jwt_low")
    if raw_token:
        ok, payload, err = _verify_jwt_low(raw_token)
        if ok and payload:
            jwt_role = payload.get("role", "unknown")
            jwt_user = {
                "id": payload.get("id", "0"),
                "name": payload.get("name", payload.get("user", "Guest")),
                "role": jwt_role,
            }
            if jwt_role == "admin":
                flag_output = _FLAG_JWT_LOW
            parts = raw_token.split(".")
            if len(parts) == 3:
                try:
                    decoded_header = json.dumps(
                        json.loads(_b64url_decode(parts[0]).decode()), indent=2
                    )
                except BaseException:
                    decoded_header = "(decode error)"
                try:
                    decoded_payload = json.dumps(
                        json.loads(_b64url_decode(parts[1]).decode()), indent=2
                    )
                except BaseException:
                    decoded_payload = "(decode error)"
        else:
            flash(f"JWT error: {err}", "error")

    return render_template(
        "lab_jwt_low.html",
        error=error,
        flag_output=flag_output,
        jwt_role=jwt_role,
        jwt_user=jwt_user,
        raw_token=raw_token,
        decoded_header=decoded_header,
        decoded_payload=decoded_payload,
        available_users=_JWT_USERS,
    )


# ─────────────────────────────────────────────────────────────
# JWT MEDIUM — Secure HS256 (alg enforced, temporal claims)
# ─────────────────────────────────────────────────────────────
_JWT_MED_SECRET = "S3cur3-L0ng-Rand0m-Pr0d-S3cret!"
_FLAG_JWT_MEDIUM = "FLAG{jwt_secure_hs256_reference}"
_TOKEN_TTL = 3600
_SKEW = 60


def _issue_jwt_medium(user: dict) -> str:
    now = int(time.time())
    header = {"typ": "JWT", "alg": "HS256"}
    payload = {
        "sub": str(user["id"]),
        "id": user["id"],
        "role": user["role"],
        "iat": now,
        "nbf": now - 10,
        "exp": now + _TOKEN_TTL,
        "iss": "jwt-lab",
        "aud": "jwt-lab-users",
    }
    h_b64 = _b64url_encode(json.dumps(header, separators=(",", ":")).encode())
    p_b64 = _b64url_encode(json.dumps(payload, separators=(",", ":")).encode())
    sig = _sign_hs256(h_b64, p_b64, _JWT_MED_SECRET)
    return f"{h_b64}.{p_b64}.{sig}"


def _verify_jwt_medium(token: str):
    """Strict: only HS256, constant-time compare, temporal claims."""
    header, payload, parts = _decode_token_parts(token)
    if header is None:
        return False, None, "Malformed token"
    h_b64, p_b64, s_b64 = parts
    if not s_b64:
        return False, None, "Missing signature"
    alg = header.get("alg", "").upper()
    if alg != "HS256":
        return False, None, f"Disallowed alg: {alg}"
    expected = _sign_hs256(h_b64, p_b64, _JWT_MED_SECRET)
    if not hmac.compare_digest(expected, s_b64):
        return False, None, "Invalid signature"
    now = int(time.time())
    if payload and "exp" in payload and payload["exp"] < now - _SKEW:
        return False, None, "Token expired"
    if payload and "nbf" in payload and payload["nbf"] > now + _SKEW:
        return False, None, "Token not yet valid"
    if payload and "iat" in payload and payload["iat"] > now + _SKEW:
        return False, None, "Issued in the future"
    return True, payload, ""


@app.route("/labs/jwt_medium", methods=["GET", "POST"])
@login_required
def aaulab_jwt_medium():
    error = None
    flag_output = None
    jwt_user = None
    jwt_role = None
    raw_token = None
    decoded_header = None
    decoded_payload = None

    # ── Quick-login via GET ?quick=<role|username> ──
    quick = request.args.get("quick", "").lower().strip()
    if quick in _QUICK_CREDS:
        uname, passwd = _QUICK_CREDS[quick]
        found = _find_jwt_user(uname, passwd)
        if found:
            token = _issue_jwt_medium(found)
            resp = redirect("/labs/jwt_medium")
            resp.set_cookie(
                "jwt_medium",
                token,
                httponly=False,
                samesite="Lax",
                max_age=3600)
            return resp

    # ── Lab actions ──
    if request.method == "POST":
        if "jwtm_clear" in request.form:
            resp = redirect("/labs/jwt_medium")
            resp.delete_cookie("jwt_medium")
            return resp
        if "jwtm_login" in request.form:
            uname = request.form.get("username", "").strip()
            passwd = request.form.get("password", "").strip()
            found = _find_jwt_user(uname, passwd)
            if found:
                token = _issue_jwt_medium(found)
                resp = redirect("/labs/jwt_medium")
                resp.set_cookie(
                    "jwt_medium",
                    token,
                    httponly=False,
                    samesite="Lax",
                    max_age=3600)
                return resp
            else:
                error = "Invalid Username or Password."

    raw_token = request.cookies.get("jwt_medium")
    if raw_token:
        ok, payload, err = _verify_jwt_medium(raw_token)
        if ok and payload:
            jwt_role = payload.get("role", "unknown")
            jwt_user = {
                "id": payload.get("id", "0"),
                "name": payload.get("name", payload.get("user", "Guest")),
                "role": jwt_role,
            }
            if jwt_role == "admin":
                flag_output = _FLAG_JWT_MEDIUM
            parts = raw_token.split(".")
            if len(parts) == 3:
                try:
                    decoded_header = json.dumps(
                        json.loads(_b64url_decode(parts[0]).decode()), indent=2
                    )
                except BaseException:
                    decoded_header = "(decode error)"
                try:
                    decoded_payload = json.dumps(
                        json.loads(_b64url_decode(parts[1]).decode()), indent=2
                    )
                except BaseException:
                    decoded_payload = "(decode error)"
        else:
            flash(f"JWT error: {err}", "error")

    return render_template(
        "lab_jwt_medium.html",
        error=error,
        flag_output=flag_output,
        jwt_role=jwt_role,
        jwt_user=jwt_user,
        raw_token=raw_token,
        decoded_header=decoded_header,
        decoded_payload=decoded_payload,
        available_users=_JWT_USERS,
    )


# ─────────────────────────────────────────────────────────────
# JWT HIGH — RS256 → HS256 Algorithm Confusion
# ─────────────────────────────────────────────────────────────
try:
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa, padding
    from cryptography.hazmat.backends import default_backend

    _CRYPTO_OK = True
except ImportError:
    _CRYPTO_OK = False

_FLAG_JWT_HIGH = "FLAG{jwt_rs256_hs256_confusion_exploited}"
_HIGH_KEY_DIR = os.path.join(os.path.dirname(__file__), "jwt_high_keys")
_HIGH_PRIV_PEM = os.path.join(_HIGH_KEY_DIR, "private.pem")
_HIGH_PUB_PEM = os.path.join(_HIGH_KEY_DIR, "public.pem")
_HIGH_JWKS = os.path.join(_HIGH_KEY_DIR, "jwks.json")


def _b64url_encode_bytes(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def _ensure_rsa_keys():
    """Generate RSA 2048-bit keys + JWKS on first call."""
    if (
        os.path.exists(_HIGH_PRIV_PEM)
        and os.path.exists(_HIGH_PUB_PEM)
        and os.path.exists(_HIGH_JWKS)
    ):
        return True
    if not _CRYPTO_OK:
        return False
    os.makedirs(_HIGH_KEY_DIR, exist_ok=True)
    private_key = rsa.generate_private_key(
        public_exponent=65537, key_size=2048, backend=default_backend()
    )
    # Save private
    with open(_HIGH_PRIV_PEM, "wb") as f:
        f.write(
            private_key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.TraditionalOpenSSL,
                serialization.NoEncryption(),
            )
        )
    # Save public
    pub = private_key.public_key()
    pub_pem = pub.public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo)
    with open(_HIGH_PUB_PEM, "wb") as f:
        f.write(pub_pem)
    # Build JWKS
    pub_nums = pub.public_numbers()
    n_int = pub_nums.n
    e_int = pub_nums.e

    def int_to_bytes_b64url(i):
        length = (i.bit_length() + 7) // 8
        b = i.to_bytes(length, "big")
        return _b64url_encode_bytes(b)

    kid = base64.urlsafe_b64encode(os.urandom(8)).rstrip(b"=").decode()
    jwks = {
        "keys": [
            {
                "kty": "RSA",
                "use": "sig",
                "alg": "RS256",
                "kid": kid,
                "n": int_to_bytes_b64url(n_int),
                "e": int_to_bytes_b64url(e_int),
            }
        ]
    }
    with open(_HIGH_JWKS, "w") as f:
        json.dump(jwks, f, indent=2)
    return True


_ensure_rsa_keys()


def _load_high_keys():
    """Returns (kid, pub_pem_str, jwks_dict, priv_pem_str). None on error."""
    if not (
        os.path.exists(_HIGH_PRIV_PEM)
        and os.path.exists(_HIGH_PUB_PEM)
        and os.path.exists(_HIGH_JWKS)
    ):
        return None, None, None, None
    with open(_HIGH_PUB_PEM, "rb") as f:
        pub_pem = f.read().decode()
    with open(_HIGH_PRIV_PEM, "rb") as f:
        priv_pem = f.read().decode()
    with open(_HIGH_JWKS, "r") as f:
        jwks = json.load(f)
    kid = jwks.get("keys", [{}])[0].get("kid")
    return kid, pub_pem, jwks, priv_pem


def _issue_jwt_high(user: dict, kid: str, priv_pem: str) -> str:
    now = int(time.time())
    header = {"typ": "JWT", "alg": "RS256", "kid": kid}
    payload = {
        "sub": str(user["id"]),
        "id": user["id"],
        "role": user["role"],
        "iat": now,
        "iss": "jwt-confusion-lab",
        "aud": "jwt-confusion-users",
    }
    h_b64 = _b64url_encode(json.dumps(header, separators=(",", ":")).encode())
    p_b64 = _b64url_encode(json.dumps(payload, separators=(",", ":")).encode())
    if not _CRYPTO_OK:
        return f"{h_b64}.{p_b64}.NOSIG"
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import padding
    from cryptography.hazmat.backends import default_backend

    pk = serialization.load_pem_private_key(
        priv_pem.encode(), password=None, backend=default_backend()
    )
    sig_bytes = pk.sign(
        f"{h_b64}.{p_b64}".encode(), padding.PKCS1v15(), hashes.SHA256()
    )
    return f"{h_b64}.{p_b64}.{_b64url_encode(sig_bytes)}"


def _verify_jwt_high(token: str, pub_pem: str, expected_kid: str = None):
    """
    VULNERABLE verifier:
     - RS256 -> correct RSA verify
     - HS256 -> uses RSA public key PEM as HMAC secret (BUG), and does NOT check result
    """
    header, payload, parts = _decode_token_parts(token)
    if header is None:
        return False, None, "Malformed token"
    h_b64, p_b64, s_b64 = parts
    alg = header.get("alg", "").upper()
    kid = header.get("kid")
    if expected_kid and kid and kid != expected_kid:
        return False, None, "Unknown kid"

    if alg == "RS256":
        if not _CRYPTO_OK:
            return False, None, "RSA library unavailable"
        try:
            from cryptography.hazmat.primitives import hashes, serialization
            from cryptography.hazmat.primitives.asymmetric import padding
            from cryptography.hazmat.backends import default_backend

            pub = serialization.load_pem_public_key(
                pub_pem.encode(), backend=default_backend()
            )
            pub.verify(
                _b64url_decode(s_b64),
                f"{h_b64}.{p_b64}".encode(),
                padding.PKCS1v15(),
                hashes.SHA256(),
            )
            return True, payload, ""
        except Exception as ex:
            return False, None, f"Invalid RS256 signature: {ex}"

    if alg == "HS256":
        # ---- INTENTIONAL VULNERABILITY ----
        # Use public key PEM as HMAC secret, and never verify the result
        _secret_bytes = pub_pem.encode("utf-8")  # BUG: public key as secret
        _expected_sig = _sign_hs256_bytes(h_b64, p_b64, _secret_bytes)
        # Missing hash_equals check → always accept HS256!
        return True, payload, ""

    return False, None, "Unsupported alg"


@app.route("/labs/jwt_high", methods=["GET", "POST"])
@login_required
def aaulab_jwt_high():
    error = None
    flag_output = None
    jwt_user = None
    jwt_role = None
    raw_token = None
    decoded_header = None
    decoded_payload = None
    current_alg = None
    kid = None
    jwks_data = None
    pub_pem = None

    _kid, _pub_pem, _jwks, _priv_pem = _load_high_keys()

    # ── Quick-login via GET ?quick=<role|username> ──
    quick = request.args.get("quick", "").lower().strip()
    if quick in _QUICK_CREDS and _priv_pem and _kid:
        uname, passwd = _QUICK_CREDS[quick]
        found = _find_jwt_user(uname, passwd)
        if found:
            token = _issue_jwt_high(found, _kid, _priv_pem)
            resp = redirect("/labs/jwt_high")
            resp.set_cookie(
                "jwt_high", token, httponly=False, samesite="Lax", max_age=3600
            )
            return resp

    if request.method == "POST":
        if "jwth_clear" in request.form:
            resp = redirect("/labs/jwt_high")
            resp.delete_cookie("jwt_high")
            return resp
        if "jwth_login" in request.form:
            uname = request.form.get("username", "").strip()
            passwd = request.form.get("password", "").strip()
            found = _find_jwt_user(uname, passwd)
            if found and _priv_pem and _kid:
                token = _issue_jwt_high(found, _kid, _priv_pem)
                resp = redirect("/labs/jwt_high")
                resp.set_cookie(
                    "jwt_high",
                    token,
                    httponly=False,
                    samesite="Lax",
                    max_age=3600)
                return resp
            else:
                error = "Invalid Username or Password."

    raw_token = request.cookies.get("jwt_high")
    if raw_token and _pub_pem:
        ok, payload, err = _verify_jwt_high(raw_token, _pub_pem, _kid)
        if ok and payload:
            jwt_role = payload.get("role", "unknown")
            jwt_user = {
                "id": payload.get("id", "0"),
                "name": payload.get("name", payload.get("user", "Guest")),
                "role": jwt_role,
            }
            current_alg = ""
            parts = raw_token.split(".")
            if len(parts) == 3:
                try:
                    hdr = json.loads(_b64url_decode(parts[0]).decode())
                    current_alg = hdr.get("alg", "")
                    kid = hdr.get("kid", "")
                    decoded_header = json.dumps(hdr, indent=2)
                except BaseException:
                    decoded_header = "(decode error)"
                try:
                    decoded_payload = json.dumps(
                        json.loads(_b64url_decode(parts[1]).decode()), indent=2
                    )
                except BaseException:
                    decoded_payload = "(decode error)"
            if jwt_role == "admin":
                flag_output = _FLAG_JWT_HIGH
        else:
            flash(f"JWT error: {err}", "error")

    # Expose JWKS + PEM when user is logged in
    if jwt_user and _jwks:
        jwks_data = json.dumps(_jwks, indent=2)
        pub_pem = _pub_pem

    return render_template(
        "lab_jwt_high.html",
        error=error,
        flag_output=flag_output,
        jwt_role=jwt_role,
        jwt_user=jwt_user,
        raw_token=raw_token,
        decoded_header=decoded_header,
        decoded_payload=decoded_payload,
        kid=kid,
        available_users=_JWT_USERS,
    )


@app.route("/labs/jwt_high/jwks")
def jwt_high_jwks():
    """Public JWKS endpoint — exposes RSA public key for the high lab."""
    _, _, jwks, _ = _load_high_keys()
    if jwks:
        return jsonify(jwks)
    return jsonify({"error": "JWKS not initialized"}), 500


# New route to display private user info after login
@app.route("/private_info")
@login_required
def private_info():
    # Mock private data based on username
    user = session.get("username")
    # In a real app, this would query a database for private details
    private_data = {
        "abebe": {
            "id": "001",
            "username": "abebe",
            "gender": "Male",
            "bank_account": "ET1234567890",
            "password": "1234",
        },
        "kebede": {
            "id": "002",
            "username": "kebede",
            "gender": "Female",
            "bank_account": "ET0987654321",
            "password": "1234",
        },
    }
    info = private_data.get(user.lower(), {})
    return render_template("private_info.html", info=info)


@app.route("/labs/bruteforce/low", methods=["GET", "POST"])
@login_required
def aaulab_bruteforce_low():
    flag = "FLAG{bruteforce_low_exploited}"
    error = None
    flag_output = None
    if "Login" in request.args:
        username = request.args.get("username", "")
        password = request.args.get("password", "")
        if username == "ATE/5788/16" and password == "7854":
            flag_output = flag
        else:
            error = "Username and/or password incorrect."
    return render_template(
        "lab_bruteforce_low.html",
        username=session.get("username"),
        role=session.get("role"),
        error=error,
        flag_output=flag_output,
    )


@app.route("/labs/bruteforce/medium",
           methods=["GET", "POST"])
@login_required
def aaulab_bruteforce_medium():
    flag = "FLAG{bruteforce_medium_exploited}"
    error = None
    flag_output = None
    if "Login" in request.args:
        username = request.args.get("username", "")
        password = request.args.get("password", "")
        if username == "ATE/5788/16" and password == "7854":
            flag_output = flag
        else:
            import time

            time.sleep(2)
            error = "Username and/or password incorrect."
    return render_template(
        "lab_bruteforce_medium.html",
        username=session.get("username"),
        role=session.get("role"),
        error=error,
        flag_output=flag_output,
    )


@app.route("/labs/bruteforce/high", methods=["GET", "POST"])
@login_required
def aaulab_bruteforce_high():
    flag = "FLAG{bruteforce_high_exploited}"
    error = None
    flag_output = None
    import uuid

    if "Login" in request.args:
        username = request.args.get("username", "")
        password = request.args.get("password", "")
        user_token = request.args.get("user_token", "")
        expected_token = session.get("bf_csrf_token", "")
        if not expected_token or user_token != expected_token:
            error = "CSRF token is missing or incorrect. Request rejected."
        else:
            if username == "ATE/5788/16" and password == "7854":
                flag_output = flag
            else:
                import time
                import random

                time.sleep(random.randint(0, 3))
                error = "Username and/or password incorrect."
    new_token = str(uuid.uuid4())
    session["bf_csrf_token"] = new_token
    return render_template(
        "lab_bruteforce_high.html",
        username=session.get("username"),
        role=session.get("role"),
        error=error,
        flag_output=flag_output,
        user_token=new_token,
    )


# ─────────────────────────────────────────────────────────────
# SSTI Lab Routes
# ─────────────────────────────────────────────────────────────

@app.route("/labs/ssti/low", methods=["GET", "POST"])
@login_required
def aaulab_ssti_low():
    flag = "FLAG{ssti_low_jinja2_template_injection}"
    result = None
    if request.method == "POST":
        template_input = request.form.get("template", "")
        # Low: no sanitization — raw Jinja2 render (simulated, safe demo)
        if "{{" in template_input and "}}" in template_input:
            result = "RENDERED: " + template_input
            flag_output = flag
        else:
            result = "RENDERED: " + template_input
            flag_output = None
        return render_template(
            "lab_ssti_low.html",
            result=result,
            flag_output=flag_output if "{{" in template_input else None,
            username=session.get("username"),
            role=session.get("role"),
        )
    return render_template(
        "lab_ssti_low.html",
        result=None,
        flag_output=None,
        username=session.get("username"),
        role=session.get("role"),
    )


@app.route("/labs/ssti/medium", methods=["GET", "POST"])
@login_required
def aaulab_ssti_medium():
    flag = "FLAG{ssti_medium_bypassed_blocklist}"
    result = None
    flag_output = None
    if request.method == "POST":
        template_input = request.form.get("template", "")
        # Medium: blocks simple {{ but not clever bypasses
        blocked = ["__class__", "__mro__", "__subclasses__", "config"]
        if any(b in template_input for b in blocked):
            result = "Error: Potentially dangerous keyword detected."
        elif "{{" in template_input:
            result = "RENDERED: " + template_input
            flag_output = flag
        else:
            result = "RENDERED: " + template_input
    return render_template(
        "lab_ssti_medium.html",
        result=result,
        flag_output=flag_output,
        username=session.get("username"),
        role=session.get("role"),
    )


@app.route("/labs/ssti/high", methods=["GET", "POST"])
@login_required
def aaulab_ssti_high():
    flag = "FLAG{ssti_high_escaped_filter_bypass}"
    result = None
    flag_output = None
    if request.method == "POST":
        import re
        template_input = request.form.get("template", "")
        # High: strips {{ and }} but bypass possible with encoding tricks
        cleaned = re.sub(r"\{\{.*?\}\}", "[FILTERED]", template_input)
        if "[FILTERED]" not in cleaned and ("{{" in template_input or "}}" in template_input):
            flag_output = flag
        result = "RENDERED: " + cleaned
    return render_template(
        "lab_ssti_high.html",
        result=result,
        flag_output=flag_output,
        username=session.get("username"),
        role=session.get("role"),
    )


@app.route("/labs/ssti/impossible", methods=["GET", "POST"])
@login_required
def aaulab_ssti_impossible():
    result = None
    if request.method == "POST":
        import html
        template_input = request.form.get("template", "")
        # Impossible: HTML-escape everything; no injection possible
        result = "RENDERED: " + html.escape(template_input)
    return render_template(
        "lab_ssti_impossible.html",
        result=result,
        flag_output=None,
        username=session.get("username"),
        role=session.get("role"),
    )


# ─────────────────────────────────────────────────────────────
# SQL Injection Lab Routes (simulated in-memory, no real DB)
# ─────────────────────────────────────────────────────────────

_SQL_USERS = [
    {"id": 1, "username": "admin", "password": "supersecret123", "role": "admin"},
    {"id": 2, "username": "alice",  "password": "alice2024",       "role": "user"},
    {"id": 3, "username": "bob",    "password": "b0bPass!",         "role": "user"},
]


@app.route("/labs/sqli/low", methods=["GET", "POST"])
@login_required
def aaulab_sqli_low():
    flag = "FLAG{sql_injection_low_classic_bypass}"
    results = []
    flag_output = None
    query_display = ""
    if request.method == "POST":
        username = request.form.get("username", "")
        query_display = f"SELECT * FROM users WHERE username = '{username}'"
        # Low: no sanitization; detect ' OR-style injection
        if "'" in username or "or" in username.lower() or "1=1" in username:
            results = _SQL_USERS
            flag_output = flag
        else:
            results = [u for u in _SQL_USERS if u["username"] == username]
    return render_template(
        "lab_sqli_low.html",
        results=results,
        flag_output=flag_output,
        query_display=query_display,
        username=session.get("username"),
        role=session.get("role"),
    )


@app.route("/labs/sqli/medium", methods=["GET", "POST"])
@login_required
def aaulab_sqli_medium():
    flag = "FLAG{sql_injection_medium_bypass_filter}"
    results = []
    flag_output = None
    query_display = ""
    if request.method == "POST":
        username = request.form.get("username", "").replace("'", "\\'")
        query_display = f"SELECT * FROM users WHERE username = '{username}'"
        # Medium: single-quotes escaped but UNION still works via numeric id
        user_id = request.form.get("user_id", "")
        if user_id and not user_id.isdigit():
            flag_output = flag
            results = _SQL_USERS
        elif user_id:
            results = [u for u in _SQL_USERS if str(u["id"]) == user_id]
        else:
            results = [u for u in _SQL_USERS if u["username"] == username.replace("\\'", "'")]
    return render_template(
        "lab_sqli_medium.html",
        results=results,
        flag_output=flag_output,
        query_display=query_display,
        username=session.get("username"),
        role=session.get("role"),
    )


@app.route("/labs/sqli/high", methods=["GET", "POST"])
@login_required
def aaulab_sqli_high():
    flag = "FLAG{sql_injection_high_second_order}"
    results = []
    flag_output = None
    query_display = ""
    # High: simulates second-order injection via stored username
    stored = session.get("sqli_stored_username", "")
    if request.method == "POST":
        action = request.form.get("action", "")
        if action == "store":
            stored = request.form.get("username", "")
            session["sqli_stored_username"] = stored
            query_display = f"INSERT INTO users (username) VALUES ('{stored}')"
        elif action == "search":
            # The stored value is now used unsanitized in a second query
            query_display = f"SELECT * FROM users WHERE username = '{stored}'"
            if "'" in stored or "or" in stored.lower():
                results = _SQL_USERS
                flag_output = flag
            else:
                results = [u for u in _SQL_USERS if u["username"] == stored]
    return render_template(
        "lab_sqli_high.html",
        results=results,
        flag_output=flag_output,
        query_display=query_display,
        stored_username=stored,
        username=session.get("username"),
        role=session.get("role"),
    )


@app.route("/labs/sqli/impossible", methods=["GET", "POST"])
@login_required
def aaulab_sqli_impossible():
    results = []
    query_display = ""
    if request.method == "POST":
        username = request.form.get("username", "")
        # Impossible: parameterized query simulation — exact match only
        query_display = "SELECT * FROM users WHERE username = ? (parameterized)"
        results = [u for u in _SQL_USERS if u["username"] == username]
    return render_template(
        "lab_sqli_impossible.html",
        results=results,
        flag_output=None,
        query_display=query_display,
        username=session.get("username"),
        role=session.get("role"),
    )


# ─────────────────────────────────────────────────────────────
# JWT Attack Lab — bridge existing routes + add Impossible
# ─────────────────────────────────────────────────────────────

@app.route("/labs/jwt/low")
@login_required
def aaulab_jwt_low_redirect():
    return redirect("/labs/jwt_low")


@app.route("/labs/jwt/medium")
@login_required
def aaulab_jwt_medium_redirect():
    return redirect("/labs/jwt_medium")


@app.route("/labs/jwt/high")
@login_required
def aaulab_jwt_high_redirect():
    return redirect("/labs/jwt_high")


@app.route("/labs/jwt/impossible", methods=["GET", "POST"])
@login_required
def aaulab_jwt_impossible():
    return render_template(
        "lab_jwt_impossible.html",
        username=session.get("username"),
        role=session.get("role"),
    )


# ─────────────────────────────────────────────────────────────
# IDOR Lab Routes
# ─────────────────────────────────────────────────────────────

_IDOR_USERS = {
    "1": {"name": "Admin User",   "email": "admin@lab.local",  "role": "admin",  "bank": "ET1234567890", "flag": "FLAG{idor_low_direct_object_reference}"},
    "2": {"name": "Alice Johnson","email": "alice@lab.local",  "role": "user",   "bank": "ET2345678901", "flag": None},
    "3": {"name": "Bob Smith",    "email": "bob@lab.local",    "role": "user",   "bank": "ET3456789012", "flag": None},
    "4": {"name": "Carol White",  "email": "carol@lab.local",  "role": "analyst","bank": "ET4567890123", "flag": None},
}


@app.route("/labs/idor/low", methods=["GET"])
@login_required
def aaulab_idor_low():
    user_id = request.args.get("id", "2")  # Default: logged-in user (id=2)
    # Low: No access control; any user_id works
    profile = _IDOR_USERS.get(user_id)
    flag_output = profile.get("flag") if profile else None
    return render_template(
        "lab_idor_low.html",
        profile=profile,
        user_id=user_id,
        current_id="2",
        flag_output=flag_output,
        username=session.get("username"),
        role=session.get("role"),
    )


@app.route("/labs/idor/medium", methods=["GET"])
@login_required
def aaulab_idor_medium():
    flag = "FLAG{idor_medium_indirect_reference}"
    # Medium: Uses hashed IDs — MD5 of numeric id
    import hashlib
    hashed_id = request.args.get("id", hashlib.md5(b"2").hexdigest())
    # Reverse lookup
    profile = None
    found_id = None
    for real_id, data in _IDOR_USERS.items():
        if hashlib.md5(real_id.encode()).hexdigest() == hashed_id:
            profile = data
            found_id = real_id
            break
    flag_output = flag if found_id == "1" else None
    # Provide the current user's hash
    current_hash = hashlib.md5(b"2").hexdigest()
    return render_template(
        "lab_idor_medium.html",
        profile=profile,
        hashed_id=hashed_id,
        current_hash=current_hash,
        flag_output=flag_output,
        username=session.get("username"),
        role=session.get("role"),
    )


@app.route("/labs/idor/high", methods=["GET"])
@login_required
def aaulab_idor_high():
    flag = "FLAG{idor_high_predictable_token}"
    # High: Token-based but still predictable (base64 of id)
    token = request.args.get("token", base64.b64encode(b"2").decode())
    try:
        real_id = base64.b64decode(token).decode()
    except Exception:
        real_id = "2"
    profile = _IDOR_USERS.get(real_id)
    flag_output = flag if real_id == "1" else None
    current_token = base64.b64encode(b"2").decode()
    return render_template(
        "lab_idor_high.html",
        profile=profile,
        token=token,
        current_token=current_token,
        flag_output=flag_output,
        username=session.get("username"),
        role=session.get("role"),
    )


@app.route("/labs/idor/impossible", methods=["GET"])
@login_required
def aaulab_idor_impossible():
    # Impossible: Can only view own profile; no parameter accepted
    profile = _IDOR_USERS.get("2")  # Always serves fixed user
    return render_template(
        "lab_idor_impossible.html",
        profile=profile,
        flag_output=None,
        username=session.get("username"),
        role=session.get("role"),
    )


# ─────────────────────────────────────────────────────────────
# BOLA Lab Routes (API-style broken object-level authorization)
# ─────────────────────────────────────────────────────────────

_BOLA_ORDERS = {
    "101": {"owner_id": "2", "item": "iPhone 15 Pro",    "total": "$999",  "status": "shipped", "flag": None},
    "102": {"owner_id": "1", "item": "Admin License Key","total": "$4999", "status": "pending", "flag": "FLAG{bola_low_unauthorized_api_access}"},
    "103": {"owner_id": "3", "item": "MacBook Pro M3",   "total": "$2499", "status": "shipped", "flag": None},
    "104": {"owner_id": "4", "item": "Security Report",  "total": "$599",  "status": "draft",   "flag": None},
}


@app.route("/labs/bola/low", methods=["GET"])
@login_required
def aaulab_bola_low():
    order_id = request.args.get("order_id", "101")
    # Low: No ownership check; any order ID accessible
    order = _BOLA_ORDERS.get(order_id)
    flag_output = order.get("flag") if order else None
    return render_template(
        "lab_bola_low.html",
        order=order,
        order_id=order_id,
        flag_output=flag_output,
        username=session.get("username"),
        role=session.get("role"),
    )


@app.route("/labs/bola/medium", methods=["GET"])
@login_required
def aaulab_bola_medium():
    flag = "FLAG{bola_medium_weak_role_check}"
    order_id = request.args.get("order_id", "101")
    # Medium: checks role in header but header can be spoofed (mocked via GET arg for demo)
    role_header = request.args.get("role_header") or request.headers.get("X-User-Role", "user")
    order = _BOLA_ORDERS.get(order_id)
    flag_output = None
    if order:
        if role_header == "admin" or order.get("owner_id") == "2":
            flag_output = flag if order_id == "102" else None
    return render_template(
        "lab_bola_medium.html",
        order=order,
        order_id=order_id,
        flag_output=flag_output,
        role_header=role_header,
        username=session.get("username"),
        role=session.get("role"),
    )


@app.route("/labs/bola/high", methods=["GET"])
@login_required
def aaulab_bola_high():
    flag = "FLAG{bola_high_uuid_still_insecure}"
    # High: Uses UUIDs but still no server-side auth check
    uuid_map = {
        "a1b2c3d4-0001": "101",
        "e5f6a7b8-0002": "102",
        "c9d0e1f2-0003": "103",
        "a3b4c5d6-0004": "104",
    }
    order_uuid = request.args.get("order_uuid", "a1b2c3d4-0001")
    order_id = uuid_map.get(order_uuid)
    order = _BOLA_ORDERS.get(order_id) if order_id else None
    flag_output = flag if order_uuid == "e5f6a7b8-0002" else None
    return render_template(
        "lab_bola_high.html",
        order=order,
        order_uuid=order_uuid,
        flag_output=flag_output,
        username=session.get("username"),
        role=session.get("role"),
    )


@app.route("/labs/bola/impossible", methods=["GET"])
@login_required
def aaulab_bola_impossible():
    # Impossible: Server strictly checks ownership — only own orders shown
    my_orders = {oid: o for oid, o in _BOLA_ORDERS.items() if o["owner_id"] == "2"}
    return render_template(
        "lab_bola_impossible.html",
        orders=my_orders,
        flag_output=None,
        username=session.get("username"),
        role=session.get("role"),
    )


# ─────────────────────────────────────────────────────────────
# Brute Force Impossible (Low/Medium/High already exist above)
# ─────────────────────────────────────────────────────────────

@app.route("/labs/bruteforce/impossible", methods=["GET", "POST"])
@login_required
def aaulab_bruteforce_impossible():
    import time
    error = None
    flag_output = None
    locked_until = session.get("bf_locked_until", 0)
    attempts = session.get("bf_attempts", 0)

    now = time.time()
    if now < locked_until:
        remaining = int(locked_until - now)
        error = f"Account locked. Try again in {remaining} seconds."
        return render_template(
            "lab_bruteforce_impossible.html",
            username=session.get("username"),
            role=session.get("role"),
            error=error,
            flag_output=None,
        )

    if "Login" in request.args:
        uname = request.args.get("username", "")
        pwd   = request.args.get("password", "")
        if uname == "ATE/5788/16" and pwd == "7854":
            flag_output = "FLAG{bruteforce_impossible_captcha_lockout}"
            session["bf_attempts"] = 0
        else:
            attempts += 1
            session["bf_attempts"] = attempts
            if attempts >= 3:
                session["bf_locked_until"] = now + 60
                session["bf_attempts"] = 0
                error = "Too many failed attempts. Account locked for 60 seconds."
            else:
                error = f"Invalid credentials. ({attempts}/3 attempts)"

    return render_template(
        "lab_bruteforce_impossible.html",
        username=session.get("username"),
        role=session.get("role"),
        error=error,
        flag_output=flag_output,
    )


# ── API Routes ──────────────────────────────────────────────



@app.route("/api/scan", methods=["POST"])
@login_required
def api_scan():
    target = request.json.get("target", "demo")
    subdomains = request.json.get("subdomains", None)
    scan_type = request.json.get("type", "full")

    risk_level = request.json.get("risk_level", "Medium")

    result = run_simulation(
        target,
        subdomains=subdomains,
        risk_level=risk_level)

    # Save to DB
    summary = result.get("summary", {})
    save_scan(
        session["user_id"],
        target,
        scan_type,
        summary.get("total", 0),
        summary.get("critical", 0),
        summary.get("high", 0),
        summary.get("medium", 0),
        summary.get("low", 0),
        summary.get("info", 0),
        json.dumps(result["findings"]),
    )
    log_activity(session["user_id"], "scan", f"Scan on {target} ({scan_type})")

    return jsonify(result)


@app.route("/api/ai", methods=["POST"])
@login_required
def api_ai():
    q = request.json.get("question", "")
    answer = ask_ai(q)
    log_activity(session["user_id"], "ai_query", q[:100])
    return jsonify({"answer": answer})


# ── ChatGPT-style multi-turn chat ───────────────────────────────
CHAT_HISTORIES = {}  # session_key -> list of {role, content}


@app.route("/api/chat", methods=["POST"])
@login_required
def api_chat():
    """Send a message and get a response, maintaining full conversation history."""
    data = request.json or {}
    user_message = data.get("message", "").strip()
    conversation_id = data.get("conversation_id", "default")

    if not user_message:
        return jsonify({"error": "Empty message"}), 400

    # Build session-scoped key
    session_key = f"{session['user_id']}:{conversation_id}"

    # Initialize history if new conversation
    if session_key not in CHAT_HISTORIES:
        CHAT_HISTORIES[session_key] = []

    # Append user message
    CHAT_HISTORIES[session_key].append(
        {"role": "user", "content": user_message})

    # Get AI response with full history
    answer = ask_ai_with_history(CHAT_HISTORIES[session_key])

    # Append assistant response
    CHAT_HISTORIES[session_key].append(
        {"role": "assistant", "content": answer})

    # Keep last 40 messages (20 turns) to control memory
    if len(CHAT_HISTORIES[session_key]) > 40:
        CHAT_HISTORIES[session_key] = CHAT_HISTORIES[session_key][-40:]

    log_activity(session["user_id"], "ai_chat", user_message[:100])

    return jsonify(
        {
            "answer": answer,
            "conversation_id": conversation_id,
            "turn": len(
                [m for m in CHAT_HISTORIES[session_key] if m["role"] == "user"]
            ),
        }
    )


@app.route("/api/chat/reset", methods=["POST"])
@login_required
def api_chat_reset():
    """Start a new conversation (clears history for given conversation_id)."""
    data = request.json or {}
    conversation_id = data.get("conversation_id", "default")
    session_key = f"{session['user_id']}:{conversation_id}"
    CHAT_HISTORIES.pop(session_key, None)
    return jsonify({"success": True, "conversation_id": conversation_id})


@app.route("/api/chat/history", methods=["GET"])
@login_required
def api_chat_history():
    """Get the full history for a conversation."""
    conversation_id = request.args.get("conversation_id", "default")
    session_key = f"{session['user_id']}:{conversation_id}"
    history = CHAT_HISTORIES.get(session_key, [])
    return jsonify({"history": history, "conversation_id": conversation_id})


@app.route("/api/stats")
@login_required
def api_stats():
    return jsonify(get_dashboard_stats())


@app.route("/api/scan-history")
@login_required
def api_scan_history():
    return jsonify(get_scan_history())


@app.route("/api/activity")
@login_required
def api_activity():
    return jsonify(get_activity_log())


# ── User Management (Admin only) ───────────────────────────
@app.route("/api/users")
@login_required
@role_required("admin")
def api_users():
    return jsonify(get_all_users())


@app.route("/api/users/add", methods=["POST"])
@login_required
@role_required("admin")
def api_add_user():
    data = request.json
    ok = add_user(
        data["username"],
        data["email"],
        data["password"],
        data["role"])
    if ok:
        log_activity(session["user_id"], "user_add", f'Added user {
            data["email"]}')
        return jsonify({"success": True})
    return jsonify({"success": False, "error": "User already exists"}), 400


@app.route("/api/users/delete", methods=["POST"])
@login_required
@role_required("admin")
def api_delete_user():
    user_id = request.json.get("id")
    if user_id == session["user_id"]:
        return jsonify({"error": "Cannot delete yourself"}), 400
    delete_user(user_id)
    log_activity(
        session["user_id"],
        "user_delete",
        f"Deleted user ID {user_id}")
    return jsonify({"success": True})


# ── PDF Export ──────────────────────────────────────────────
@app.route("/api/export-pdf", methods=["POST"])
@login_required
def api_export_pdf():
    findings = request.json.get("findings", [])
    if not findings:
        return jsonify({"error": "No findings to export"}), 400
    filepath = generate_pdf_report(findings)
    log_activity(session["user_id"], "export_pdf", f"Exported {
        len(findings)} findings")
    return send_file(
        filepath, as_attachment=True, download_name=os.path.basename(filepath)
    )


# ── WebSocket Terminal ──────────────────────────────────────
PTY_SESSIONS = {}


@socketio.on("terminal_start")
def start_pty():
    sid = request.sid
    if sid in PTY_SESSIONS:
        return

    pid, fd = pty.fork()

    if pid == 0:  # Child process
        env = os.environ.copy()
        env["TERM"] = "xterm-256color"

        # Dedicated tools sandbox
        base_dir = os.path.abspath(os.path.dirname(__file__))
        lab_tools = os.path.join(base_dir, "lab_tools")
        lab_bin = os.path.join(lab_tools, "bin")

        env["PATH"] = f"{lab_bin}:{env.get('PATH', '')}"
        os.chdir(lab_tools)

        os.execvpe("bash", ["bash"], env)

    # Parent process
    PTY_SESSIONS[sid] = {"fd": fd, "pid": pid}

    def read_output(master_fd, socket_id):
        while True:
            try:
                data = os.read(master_fd, 4096)
                if not data:
                    break
                socketio.emit(
                    "terminal_output",
                    {"data": data.decode("utf-8", "replace")},
                    to=socket_id,
                )
            except OSError:
                break

    threading.Thread(target=read_output, args=(fd, sid), daemon=True).start()
    emit(
        "terminal_output", {
            "data": f"\r\n[Connected to interactive lab shell]\r\n"})


@socketio.on("terminal_input")
def terminal_input(data):
    sid = request.sid
    if sid in PTY_SESSIONS:
        fd = PTY_SESSIONS[sid]["fd"]
        cmd = data.get("input", "")
        try:
            os.write(fd, cmd.encode("utf-8"))
        except OSError:
            pass


@socketio.on("disconnect")
def on_disconnect():
    sid = request.sid
    if sid in PTY_SESSIONS:
        fd = PTY_SESSIONS[sid]["fd"]
        pid = PTY_SESSIONS[sid]["pid"]
        try:
            os.close(fd)
        except BaseException:
            pass
        try:
            import signal

            os.kill(pid, signal.SIGKILL)
        except OSError:
            pass
        del PTY_SESSIONS[sid]


# ── WebSocket Live Scan ─────────────────────────────────────
@socketio.on("start_scan")
def handle_scan(data):
    target = data.get("target", "demo")
    scan_type = data.get("type", "full")
    speed = float(data.get("speed", 10))
    subdomains = data.get("subdomains", None)
    source_code = data.get("source_code", None)
    risk_level = data.get("risk_level", "Medium")

    def callback(msg):
        socketio.emit("scan_output", {"data": msg + "\n"}, namespace="/")

    def progress_callback(pct):
        socketio.emit("scan_progress", {"pct": pct}, namespace="/")

    def run():
        result = run_simulation(
            target=target,
            subdomains=subdomains,
            source_code=source_code,
            callback=callback,
            progress_callback=progress_callback,
            speed=speed,
            risk_level=risk_level,
        )
        socketio.emit("scan_complete", result, namespace="/")

    thread = threading.Thread(target=run)
    thread.daemon = True
    thread.start()


# ── SOC Real-time Stats v3 ─────────────────────────────────────
@app.route("/api/system")
@login_required
def api_system():
    return jsonify(
        {
            "cpu": psutil.cpu_percent(interval=None),
            "memory": psutil.virtual_memory().percent,
            "disk": psutil.disk_usage("/").percent,
        }
    )


@app.route("/api/network")
@login_required
def api_network():
    net = psutil.net_io_counters()
    return jsonify({"sent": net.bytes_sent, "recv": net.bytes_recv})


@app.route("/api/threats")
@login_required
def api_threats():
    threat_types = [
        "Port Scan Detected",
        "Suspicious Login Attempt",
        "Brute Force Pattern",
        "Malware Signature Match",
        "SQL Injection Pattern (blocked)",
        "XSS Attempt (blocked)",
        "Anomalous Traffic Spike",
    ]
    severity = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]

    event = {
        "type": random.choice(threat_types),
        "severity": random.choice(severity),
        "score": random.randint(10, 99),
        "timestamp": time.strftime("%H:%M:%S"),
    }
    return jsonify(event)



import os, uuid
from werkzeug.utils import secure_filename

@app.route("/labs/image_xss_low", methods=["GET", "POST"])
@login_required
def lab_image_xss_low():
    upload_dir = os.path.join(app.root_path, 'static', 'uploads', 'svg')
    os.makedirs(upload_dir, exist_ok=True)
    
    message = ""
    color = "red"
    if request.method == "POST" and "file" in request.files:
        file = request.files["file"]
        if file.filename:
            ext = file.filename.rsplit('.', 1)[-1].lower()
            if ext != 'svg':
                message = "❌ Only SVG files are allowed."
            else:
                filename = f"file_{uuid.uuid4().hex}.svg"
                target = os.path.join(upload_dir, filename)
                file.save(target)
                view_url = f"/static/uploads/svg/{filename}"
                color = "green"
                message = f"✅ File uploaded!<br><iframe src='{view_url}' style='width:100%; height:500px; border:none;'></iframe>"

    return render_template("lab_image_xss_low.html",
        message=message, msg_color=color,
        username=session.get('username'), role=session.get('role'))

@app.route("/labs/file_upload_low", methods=["GET", "POST"])
@login_required
def lab_file_upload_low():
    upload_dir = os.path.join(app.root_path, 'static', 'uploads', 'hackable')
    os.makedirs(upload_dir, exist_ok=True)
    
    message = ""
    uploaded_url = None
    if request.method == "POST" and "uploaded" in request.files:
        file = request.files["uploaded"]
        if file.filename:
            filename = file.filename
            target = os.path.join(upload_dir, filename)
            try:
                file.save(target)
                uploaded_url = f"/static/uploads/hackable/{filename}"
                message = f"{filename} successfully uploaded!"
            except Exception as e:
                message = f"Upload failed: {e}"

    return render_template("lab_file_upload_low.html", message=message,
        uploaded_url=uploaded_url,
        username=session.get('username'), role=session.get('role'))

@app.route("/labs/otp_bypass_low", methods=["GET", "POST"])
@login_required
def lab_otp_bypass_low():
    # Regenerate OTP on each fresh GET visit
    if request.method == "GET":
        session["lab_otp"] = str(random.randint(1000, 9999))
    otp = session.get("lab_otp", "0000")
    return render_template("lab_otp_bypass_low.html", otp=otp,
        username=session.get('username'), role=session.get('role'))

if __name__ == "__main__":
    socketio.run(app, debug=False, host="0.0.0.0", port=5000, allow_unsafe_werkzeug=True)
