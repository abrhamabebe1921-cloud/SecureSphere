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
        msg["Subject"] = "🔐 ThreatMapper — Your Verification Code"
        msg["From"] = _SMTP_SENDER
        msg["To"] = _VERIFY_EMAIL

        html_body = f"""
        <div style="background:#0a0a0a;padding:40px;font-family:'Courier New',monospace;color:#00ff88;border-radius:12px;max-width:480px;margin:0 auto;">
          <div style="text-align:center;margin-bottom:24px;">
            <div style="font-size:48px;">🛡️</div>
            <h1 style="font-size:20px;letter-spacing:0.2em;color:#00ff88;margin:8px 0;">THREATMAPPER</h1>
            <p style="color:rgba(0,255,136,0.45);font-size:11px;margin:0;">Addis Ababa University · Security Lab</p>
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
            © AAiT Cyber Security Lab · ThreatMapper
          </p>
        </div>
        """
        plain_body = (
            f"Your ThreatMapper verification code is: {code}\nValid for 60 seconds.")

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
@app.route("/aau/threatmapper/aaulab/ssti/low", methods=["GET", "POST"])
@login_required
def aaulab_ssti_low():
    flag = "AAU{congratulations_you_exploited_ssti}"
    template_input = ""
    rendered_output = ""
    error = None
    flag_output = None

    if request.method == "POST":
        template_input = request.form.get("template", "")

        # Build a small PHP wrapper that reads  template from an env var
        import subprocess
        import tempfile
        import os as _os

        wrapper = r"""<?php
error_reporting(E_ERROR);
$_SERVER['REQUEST_METHOD'] = 'POST';
$_POST['template'] = getenv('SSTI_TPL');
$page = ['body' => ''];
ob_start();
include(__DIR__ . '/vulnerabilities/SSTI/source/low.php');
$_ = ob_get_clean();
echo $output;
"""
        app_dir = _os.path.dirname(_os.path.abspath(__file__))
        with tempfile.NamedTemporaryFile(
            suffix=".php", mode="w", delete=False, dir="/tmp"
        ) as f:
            f.write(wrapper)
            tmp_path = f.name

        try:
            env = _os.environ.copy()
            env["SSTI_TPL"] = template_input
            result = subprocess.run(
                ["php", tmp_path],
                capture_output=True,
                text=True,
                timeout=5,
                cwd=app_dir,
                env=env,
            )
            rendered_output = result.stdout.strip()

            # Award flag for successful code execution
            if any(
                kw in rendered_output
                for kw in ["uid=", "root:", "/etc/", "/home/", "bin/bash"]
            ):
                flag_output = flag

        except Exception as e:
            error = str(e)
        finally:
            try:
                _os.unlink(tmp_path)
            except Exception:
                pass

    return render_template(
        "lab_ssti_low.html",
        username=session.get("username"),
        role=session.get("role"),
        template_input=template_input,
        rendered_output=rendered_output,
        error=error,
        flag_output=flag_output,
    )

@app.route("/aau/threatmapper/aaulab/sqli/low", methods=["GET", "POST"])
@login_required
def aaulab_sqli_low():

    flag = "AAU{sqli_low_exploited}"
    results = []
    error = None
    flag_output = None

    if request.method == "POST":
        user_id = request.form.get("id", "")

        import sqlite3
        import re

        conn = sqlite3.connect(":memory:")
        conn.row_factory = sqlite3.Row
        c = conn.cursor()

        c.execute("CREATE TABLE users (user_id TEXT, name TEXT, age TEXT, email TEXT, mobile TEXT, atm_pass TEXT, bank_account TEXT, balance TEXT)")

        c.execute("INSERT INTO users VALUES ('1', 'admin', 'admin', 'admin@aau.edu.et', '0900000000', '0000', '1000000000000', '9999999')")
        c.execute("INSERT INTO users VALUES ('2', 'Gordon Brown', '34', 'gordon@gmail.com', '0922222222', '1234', '1000000000001', '50000')")
        c.execute("INSERT INTO users VALUES ('3', 'Hack Me', '21', 'hackme@gmail.com', '0933333333', '1337', '1000000000002', '75000')")
        c.execute("INSERT INTO users VALUES ('4', 'Pablo Picasso', '65', 'pablo@gmail.com', '0944444444', '4321', '1000000000003', '250000')")
        c.execute("INSERT INTO users VALUES ('5', 'abebe kebede', '42', 'kebede123@gmail.com', '0911121314', '6789', '1000000000004', '120000')")

        conn.commit()

        query = f"SELECT * FROM users WHERE user_id = '{user_id}';"

        found = False
        try:
            c.execute(query)
            rows = c.fetchall()
            for row in rows:
                results.append(dict(row))
                found = True
        except Exception as e:
            error = f"Error in fetch: {str(e)}"

        if not found and re.search(r"(or|--|;|\s)", user_id, re.IGNORECASE):
            flag_output = flag

    return render_template(
        "lab_sqli_low.html",
        username=session.get("username"),
        role=session.get("role"),
        results=results,
        error=error,
        flag_output=flag_output,
        query=query,
        user_id=user_id,
    )

@app.route("/aau/threatmapper/aaulab/sqli/medium", methods=["GET", "POST"])
@login_required
def aaulab_sqli_medium():

    flag = "AAU{medium_level_sqli_exploited}"
    results = []
    error = None
    flag_output = None
    query = None
    raw_user_id = ""
    user_id = ""

    if request.method == "POST":
        raw_user_id = request.form.get("id", "")

        # Simulate mysqli_real_escape_string
        user_id = (
            raw_user_id
            .replace("\\", "\\\\")
            .replace("'", "\\'")
            .replace('"', '\\"')
        )

        import sqlite3
        import re

        conn = sqlite3.connect(":memory:")
        conn.row_factory = sqlite3.Row
        c = conn.cursor()

        c.execute("CREATE TABLE users (user_id INTEGER, first_name TEXT, last_name TEXT)")
        c.execute("INSERT INTO users VALUES (1, 'admin', 'admin')")
        c.execute("INSERT INTO users VALUES (2, 'Gordon', 'Brown')")
        c.execute("INSERT INTO users VALUES (3, 'Hack', 'Me')")
        c.execute("INSERT INTO users VALUES (4, 'Pablo', 'Picasso')")
        c.execute("INSERT INTO users VALUES (5, 'Kebede', 'Smith')")

        conn.commit()

        query = f"SELECT * FROM users WHERE user_id = {user_id};"

        found = False
        try:
            if user_id.strip():
                c.execute(query)
                rows = c.fetchall()

                for row in rows:
                    results.append({
                        "first_name": row["first_name"],
                        "last_name": row["last_name"]
                    })
                    found = True

        except Exception as e:
            error = "Something went wrong."

        if not found and re.search(r"(or|--|;|\s)", raw_user_id, re.IGNORECASE):
            flag_output = flag

    return render_template(
        "lab_sqli_medium.html",
        username=session.get("username"),
        role=session.get("role"),
        results=results,
        error=error,
        flag_output=flag_output,
        query=query,
        user_id=raw_user_id,
    )
@app.route("/aau/threatmapper/aaulab/sqli/high", methods=["GET", "POST"])
@login_required
def aaulab_sqli_high():

    flag = "AAU{high_level_sqli_success}"
    results = []
    error = None
    flag_output = None
    query = None

    if request.method == "POST":
        session["sqli_id"] = request.form.get("id", "")
        return redirect("/aau/threatmapper/aaulab/sqli/high")

    user_id = session.get("sqli_id")

    if user_id is not None:
        import sqlite3
        import re

        conn = sqlite3.connect(":memory:")
        conn.row_factory = sqlite3.Row
        c = conn.cursor()

        c.execute("CREATE TABLE users (user_id TEXT, name TEXT, age TEXT, email TEXT, mobile TEXT, atm_pass TEXT, bank_acc TEXT, amount TEXT)")

        c.execute("INSERT INTO users VALUES ('1', 'admin', 'admin', 'admin@aau.edu.et', '0900000000', '0000', '1000000000000', '9999999')")
        c.execute("INSERT INTO users VALUES ('2', 'Gordon Brown', '34', 'gordon@gmail.com', '0922222222', '1234', '1000022222222', '50000')")
        c.execute("INSERT INTO users VALUES ('3', 'Hack Me', '21', 'hackme@gmail.com', '0933333333', '1337', '1000033333333', '10000')")
        c.execute("INSERT INTO users VALUES ('4', 'Pablo Picasso', '65', 'pablo@gmail.com', '0944444444', '4321', '1000044444444', '150000')")
        c.execute("INSERT INTO users VALUES ('5', 'abebe kebede', '42', 'kebede123@gmail.com', '0911121314', '6754', '1000035732047', '20000')")

        conn.commit()

        query = f"SELECT * FROM users WHERE user_id = '{user_id}' LIMIT 1;"

        found = False
        try:
            c.execute(query)
            rows = c.fetchall()
            for row in rows:
                results.append(dict(row))
                found = True
        except Exception:
            error = "Something went wrong."

        if not found and re.search(r"(\'|--|;|\s|or|and)", user_id, re.IGNORECASE):
            flag_output = flag

    return render_template(
        "lab_sqli_high.html",
        username=session.get("username"),
        role=session.get("role"),
        results=results,
        error=error,
        flag_output=flag_output,
        query=query,
        user_id=user_id or "",
    )


@app.route("/aau/threatmapper/aaulab/idor/low", methods=["GET", "POST"])
@login_required
def aaulab_idor_low():
    flag = "AAU{idor_low_exploited}"
    results = []
    error = None
    flag_output = None

    # Pre-defined database mapping
    students = {
        "Abreham": {"pass": "passwd1", "id": "UGR/5788/16"},
        "Hany": {"pass": "passwd2", "id": "UGR/6502/16"},
        "Mikiyas": {"pass": "passwd3", "id": "UGR/2616/16"},
        "Hermela": {"pass": "passwd4", "id": "UGR/6868/16"},
    }

    students_by_id = {v["id"]: k for k, v in students.items()}

    logged_in_username = session.get("idor_username")

    # Quick-login via GET ?quick=
    quick = request.args.get("quick", "").strip()
    if quick in students:
        session["idor_username"] = quick
        return redirect(
            f"/aau/threatmapper/aaulab/idor/low?profile_id={students[quick]['id']}"
        )

    if request.method == "POST":
        if "logout" in request.form:
            session.pop("idor_username", None)
            return redirect("/aau/threatmapper/aaulab/idor/low")

        post_user = request.form.get("username", "").strip()
        post_pass = request.form.get("password", "").strip()

        if post_user in students and students[post_user]["pass"] == post_pass:
            session["idor_username"] = post_user
            return redirect(
                f"/aau/threatmapper/aaulab/idor/low?profile_id={students[post_user]['id']}"
            )
        else:
            error = "Invalid Username or Password."

    view_profile_id = request.args.get("profile_id", "").strip()
    profile_data = {}

    if logged_in_username and view_profile_id:
        if view_profile_id in students_by_id:
            profile_name = students_by_id[view_profile_id]
            import hashlib
            import random

            courses = ["physics", "maths", "geograpy", "history"]
            possible_grades = ["A+", "a", "A-", "B+", "B", "B-", "C+", "C"]
            seed = int(hashlib.md5(view_profile_id.encode()).hexdigest(), 16)
            rng = random.Random(seed)
            for course in courses:
                results.append(
                    {"course": course, "grade": rng.choice(possible_grades)})

            profile_data = {
                "id": view_profile_id,
                "name": profile_name,
                "role": "User",
                "grades": results,
            }

            if logged_in_username != profile_name:
                flag_output = flag
        else:
            error = "Profile not found in the university database."

    return render_template(
        "lab_idor_low.html",
        username=session.get("username"),
        role=session.get("role"),
        logged_in_user=logged_in_username,
        view_profile_id=view_profile_id,
        profile_data=profile_data,
        error=error,
        flag_output=flag_output,
    )


@app.route("/aau/threatmapper/aaulab/idor/medium", methods=["GET", "POST"])
@login_required
def aaulab_idor_medium():
    flag = "AAU{idor_medium_cookie_exploited}"
    results = []
    error = None
    flag_output = None

    students = {
        "Abreham": {"pass": "passwd1", "id": "UGR/5788/16"},
        "Hany": {"pass": "passwd2", "id": "UGR/6502/16"},
        "Mikiyas": {"pass": "passwd3", "id": "UGR/2616/16"},
        "Hermela": {"pass": "passwd4", "id": "UGR/6868/16"},
    }

    actual_user = session.get("idor_med_actual_user")

    # Quick-login via GET ?quick=
    quick = request.args.get("quick", "").strip()
    if quick in students:
        session["idor_med_actual_user"] = quick
        import base64

        tok = base64.b64encode(f"User-{quick}".encode()).decode()
        res = redirect("/aau/threatmapper/aaulab/idor/medium")
        res.set_cookie("idor_token", tok)
        return res
    if request.method == "POST":
        if "logout" in request.form:
            session.pop("idor_med_actual_user", None)
            res = redirect("/aau/threatmapper/aaulab/idor/medium")
            res.delete_cookie("idor_token")
            return res

        post_user = request.form.get("username", "").strip()
        post_pass = request.form.get("password", "").strip()

        if post_user in students and students[post_user]["pass"] == post_pass:
            session["idor_med_actual_user"] = post_user
            import base64

            tok = base64.b64encode(f"User-{post_user}".encode()).decode()
            res = redirect("/aau/threatmapper/aaulab/idor/medium")
            res.set_cookie("idor_token", tok)
            return res
        else:
            error = "Invalid Username or Password."

    cookie_val = request.cookies.get("idor_token", "")
    profile_data = {}
    view_username = None

    if cookie_val:
        import base64

        try:
            decoded = base64.b64decode(cookie_val).decode("utf-8")
            if decoded.startswith("User-"):
                view_username = decoded[5:]
            else:
                error = "Malformed cookie value. Expected base64('User-{Username}')."
        except Exception:
            error = "Failed to decode cookie token."

    if view_username:
        if view_username in students:
            profile_name = view_username
            profile_id = students[view_username]["id"]
            import hashlib
            import random

            courses = ["physics", "maths", "geograpy", "history"]
            possible_grades = ["A+", "a", "A-", "B+", "B", "B-", "C+", "C"]
            seed = int(hashlib.md5(profile_id.encode()).hexdigest(), 16)
            rng = random.Random(seed)
            for course in courses:
                results.append(
                    {"course": course, "grade": rng.choice(possible_grades)})

            profile_data = {
                "id": profile_id,
                "name": profile_name,
                "role": "User",
                "grades": results,
            }

            if actual_user and actual_user != view_username:
                flag_output = flag
        else:
            error = f"No user found for username: {view_username}"

    return render_template(
        "lab_idor_medium.html",
        username=session.get("username"),
        role=session.get("role"),
        logged_in_user=actual_user,
        profile_data=profile_data,
        cookie_val=cookie_val,
        error=error,
        flag_output=flag_output,
    )


@app.route("/aau/threatmapper/aaulab/idor/high", methods=["GET", "POST"])
@login_required
def aaulab_idor_high():
    flag = "AAU{idor_high_uuid_exploited}"
    results = []
    error = None
    flag_output = None

    students = {
        "Abreham": {
            "pass": "passwd1",
            "uuid": "11111111-1111-4111-8111-111111111111"},
        "Hany": {
            "pass": "passwd2",
            "uuid": "22222222-2222-4222-8222-222222222222"},
        "Mikiyas": {
            "pass": "passwd3",
            "uuid": "33333333-3333-4333-8333-333333333333"},
        "Hermela": {
            "pass": "passwd4",
                    "uuid": "44444444-4444-4444-8444-444444444444"},
    }

    students_by_uuid = {v["uuid"]: k for k, v in students.items()}
    logged_in_username = session.get("idor_high_actual_user")

    # Quick-login via GET ?quick=
    quick = request.args.get("quick", "").strip()
    if quick in students:
        session["idor_high_actual_user"] = quick
        return redirect(
            f"/aau/threatmapper/aaulab/idor/high?uuid={students[quick]['uuid']}"
        )

    if request.method == "POST":
        if "logout" in request.form:
            session.pop("idor_high_actual_user", None)
            return redirect("/aau/threatmapper/aaulab/idor/high")

        post_user = request.form.get("username", "").strip()
        post_pass = request.form.get("password", "").strip()

        if post_user in students and students[post_user]["pass"] == post_pass:
            session["idor_high_actual_user"] = post_user
            return redirect(
                f"/aau/threatmapper/aaulab/idor/high?uuid={students[post_user]['uuid']}"
            )
        else:
            error = "Invalid Username or Password."

    view_uuid = request.args.get("uuid", "").strip()
    profile_data = {}

    if logged_in_username and not view_uuid and not error:
        return redirect(
            f"/aau/threatmapper/aaulab/idor/high?uuid={students[logged_in_username]['uuid']}"
        )

    if logged_in_username and view_uuid:
        if view_uuid in students_by_uuid:
            profile_name = students_by_uuid[view_uuid]
            import hashlib
            import random

            courses = ["physics", "maths", "geograpy", "history"]
            possible_grades = ["A+", "a", "A-", "B+", "B", "B-", "C+", "C"]
            seed = int(hashlib.md5(view_uuid.encode()).hexdigest(), 16)
            rng = random.Random(seed)
            for course in courses:
                results.append(
                    {"course": course, "grade": rng.choice(possible_grades)})

            profile_data = {
                "id": view_uuid,
                "name": profile_name,
                "role": "User",
                "grades": results,
            }

            if logged_in_username != profile_name:
                flag_output = flag
        else:
            error = "Profile not found for the provided UUID."

    return render_template(
        "lab_idor_high.html",
        username=session.get("username"),
        role=session.get("role"),
        logged_in_user=logged_in_username,
        view_uuid=view_uuid,
        profile_data=profile_data,
        error=error,
        flag_output=flag_output,
    )


@app.route("/aau/threatmapper/aaulab/xss_low", methods=["GET", "POST"])
@login_required
def aaulab_xss_low():
    flag = "AAU{xss_reflected_low_exploited}"
    error = None
    # Simple user credentials similar to IDOR lab
    users = {
        "Hermela": {"pass": "passwd4", "role": "Admin"},
        "Abreham": {"pass": "passwd1", "role": "User"},
        "Hany": {"pass": "passwd2", "role": "User"},
        "Mikiyas": {"pass": "passwd3", "role": "User"},
        "Bikila": {"pass": "passwd5", "role": "User"},
        "Mastewal": {"pass": "passwd6", "role": "User"},
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
        resp = redirect("/aau/threatmapper/aaulab/xss_low")
        resp.set_cookie("XSS_SESSION_ID", sid, httponly=False, samesite="Lax")
        return resp

    if request.method == "POST":
        if "logout" in request.form:
            session.pop("xss_username", None)
            sid = request.cookies.get("XSS_SESSION_ID")
            if sid in _XSS_SESSIONS:
                del _XSS_SESSIONS[sid]
            resp = redirect("/aau/threatmapper/aaulab/xss_low")
            resp.delete_cookie("XSS_SESSION_ID")
            return resp
        post_user = request.form.get("username", "").strip()
        post_pass = request.form.get("password", "").strip()
        if post_user in users and users[post_user]["pass"] == post_pass:
            session["xss_username"] = post_user
            sid = create_lab_session(post_user, users[post_user]["role"])
            resp = redirect("/aau/threatmapper/aaulab/xss_low")
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


@app.route("/aau/threatmapper/aaulab/xss_medium", methods=["GET", "POST"])
@login_required
def aaulab_xss_medium():
    flag = "AAU{xss_reflected_medium_exploited}"
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


@app.route("/aau/threatmapper/aaulab/xss_high", methods=["GET", "POST"])
@login_required
def aaulab_xss_high():
    flag = "AAU{xss_reflected_high_exploited}"
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
_FLAG_JWT_LOW = "AAU{jwt_alg_none_exploited}"


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


@app.route("/aau/threatmapper/aaulab/jwt_low", methods=["GET", "POST"])
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
            resp = redirect("/aau/threatmapper/aaulab/jwt_low")
            resp.set_cookie(
                "jwt_low", token, httponly=False, samesite="Lax", max_age=3600
            )
            return resp
    # ── Lab actions ──
    if request.method == "POST":
        if "jwtl_clear" in request.form:
            resp = redirect("/aau/threatmapper/aaulab/jwt_low")
            resp.delete_cookie("jwt_low")
            return resp
        if "jwtl_login" in request.form:
            uname = request.form.get("username", "").strip()
            passwd = request.form.get("password", "").strip()
            found = _find_jwt_user(uname, passwd)
            if found:
                token = _issue_jwt_low(found)
                resp = redirect("/aau/threatmapper/aaulab/jwt_low")
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
_FLAG_JWT_MEDIUM = "AAU{jwt_secure_hs256_reference}"
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


@app.route("/aau/threatmapper/aaulab/jwt_medium", methods=["GET", "POST"])
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
            resp = redirect("/aau/threatmapper/aaulab/jwt_medium")
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
            resp = redirect("/aau/threatmapper/aaulab/jwt_medium")
            resp.delete_cookie("jwt_medium")
            return resp
        if "jwtm_login" in request.form:
            uname = request.form.get("username", "").strip()
            passwd = request.form.get("password", "").strip()
            found = _find_jwt_user(uname, passwd)
            if found:
                token = _issue_jwt_medium(found)
                resp = redirect("/aau/threatmapper/aaulab/jwt_medium")
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

_FLAG_JWT_HIGH = "AAU{jwt_rs256_hs256_confusion_exploited}"
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


@app.route("/aau/threatmapper/aaulab/jwt_high", methods=["GET", "POST"])
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
            resp = redirect("/aau/threatmapper/aaulab/jwt_high")
            resp.set_cookie(
                "jwt_high", token, httponly=False, samesite="Lax", max_age=3600
            )
            return resp

    if request.method == "POST":
        if "jwth_clear" in request.form:
            resp = redirect("/aau/threatmapper/aaulab/jwt_high")
            resp.delete_cookie("jwt_high")
            return resp
        if "jwth_login" in request.form:
            uname = request.form.get("username", "").strip()
            passwd = request.form.get("password", "").strip()
            found = _find_jwt_user(uname, passwd)
            if found and _priv_pem and _kid:
                token = _issue_jwt_high(found, _kid, _priv_pem)
                resp = redirect("/aau/threatmapper/aaulab/jwt_high")
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


@app.route("/aau/threatmapper/aaulab/jwt_high/jwks")
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


@app.route("/aau/threatmapper/aaulab/bruteforce/low", methods=["GET", "POST"])
@login_required
def aaulab_bruteforce_low():
    flag = "AAU{bruteforce_low_exploited}"
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


@app.route("/aau/threatmapper/aaulab/bruteforce/medium",
           methods=["GET", "POST"])
@login_required
def aaulab_bruteforce_medium():
    flag = "AAU{bruteforce_medium_exploited}"
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


@app.route("/aau/threatmapper/aaulab/bruteforce/high", methods=["GET", "POST"])
@login_required
def aaulab_bruteforce_high():
    flag = "AAU{bruteforce_high_exploited}"
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


if __name__ == "__main__":
    socketio.run(app, debug=False, host="0.0.0.0", port=5000)
