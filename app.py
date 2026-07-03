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
def lab_xss_low():
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
def lab_xss_medium():
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
def lab_xss_high():
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



}




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




