import os
import json
import subprocess
import threading
import random
import time
import pty
from functools import wraps
import psutil
from flask import Flask, render_template, request, redirect, session, jsonify, send_file, url_for, flash
from flask_socketio import SocketIO, emit
from database import init_db, get_user_by_email, get_all_users, add_user, delete_user, \
    save_scan, get_scan_history, log_activity, get_activity_log, get_dashboard_stats, hash_password
from modules.scanner import run_simulation
import base64
import hashlib
import hmac
import json
from modules.ai import ask_ai, ask_ai_with_history
from modules.auth import authenticate, has_permission
from modules.report_gen import generate_pdf_report

app = Flask(__name__)
app.config['SESSION_COOKIE_HTTPONLY'] = False
app.secret_key = 'threatmapper-secret-2026'

socketio = SocketIO(
    app,
    cors_allowed_origins='*',
    async_mode='threading'
)

# Initialize the database
init_db()


# ── Decorators ──────────────────────────────────────────────
def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        # The login route stores the username under the key 'username'.
        # If that key is missing the user is not authenticated.
        if 'username' not in session:
            return redirect('/login')
        return f(*args, **kwargs)
    return decorated


def role_required(*roles):
    def decorator(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            # Ensure the user has one of the required roles.
            # The role is stored in the session as 'role'.
            if 'role' not in session or session.get('role') not in roles:
                flash('Insufficient permissions', 'error')
                return redirect('/dashboard')
            if 'role' not in session or session['role'] not in roles:
                return jsonify({'error': 'Access denied'}), 403
            return f(*args, **kwargs)
        return decorated
    return decorator


# ── Pages ───────────────────────────────────────────────────
@app.route('/')
def home():
    return redirect('/login')


@app.route('/login', methods=['GET', 'POST'])
def login():
    error = None
    if request.method == 'POST':
        email = request.form.get('email', '')
        password = request.form.get('password', '')
        user = authenticate(email, password)
        if user:
            session['user'] = user['email']
            session['user_id'] = user['id']
            session['username'] = user['username']
            session['role'] = user['role']
            log_activity(user['id'], 'login', f'{user["username"]} logged in')
            return redirect('/dashboard')
        else:
            error = 'Invalid credentials'
    return render_template('login.html', error=error)


@app.route('/dashboard')
@login_required
def dashboard():
    perms = {
        'terminal': has_permission(session['role'], 'terminal'),
        'reports': has_permission(session['role'], 'reports'),
        'users': has_permission(session['role'], 'users'),
        'scanner': has_permission(session['role'], 'scanner'),
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
        "CSRF Attack"
    ]
    return render_template('dashboard.html',
                           username=session['username'],
                           role=session['role'],
                           perms=perms,
                           vulns=vulns)


@app.route('/terminal')
@login_required
def terminal():
    if not has_permission(session['role'], 'terminal'):
        return redirect('/dashboard')
    return render_template('terminal.html',
                           username=session['username'],
                           role=session['role'])


@app.route('/reports')
@login_required
def reports():
    if not has_permission(session['role'], 'reports'):
        return redirect('/dashboard')
    return render_template('reports.html',
                           username=session['username'],
                           role=session['role'])


@app.route('/logout')
def logout():
    if 'user_id' in session:
        log_activity(session['user_id'], 'logout', f'{session.get("username", "")} logged out')
    session.clear()
    return redirect('/login')


# ── Lab Routes ──────────────────────────────────────────────
@app.route('/aau/threatmapper/aaulab/ssti/low', methods=['GET', 'POST'])
@login_required
def aaulab_ssti_low():
    flag = 'gtwss{congratulations_you_exploited_ssti}'
    template_input = ''
    rendered_output = ''
    error = None
    flag_output = None
    
    if request.method == 'POST':
        template_input = request.form.get('template', '')
        
        # Build a small PHP wrapper that reads  template from an env var
        import subprocess, tempfile, os as _os
        
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
        with tempfile.NamedTemporaryFile(suffix='.php', mode='w', delete=False, dir='/tmp') as f:
            f.write(wrapper)
            tmp_path = f.name
        
        try:
            env = _os.environ.copy()
            env['SSTI_TPL'] = template_input
            result = subprocess.run(
                ['php', tmp_path],
                capture_output=True, text=True, timeout=5,
                cwd=app_dir, env=env
            )
            rendered_output = result.stdout.strip()
            
            # Award flag for successful code execution
            if any(kw in rendered_output for kw in ['uid=', 'root:', '/etc/', '/home/', 'bin/bash']):
                flag_output = flag
                
        except Exception as e:
            error = str(e)
        finally:
            try:
                _os.unlink(tmp_path)
            except Exception:
                pass
            
    return render_template('lab_ssti_low.html',
                           username=session.get('username'),
                           role=session.get('role'),
                           template_input=template_input,
                           rendered_output=rendered_output,
                           error=error,
                           flag_output=flag_output)

@app.route('/aau/threatmapper/aaulab/sqli/low', methods=['GET', 'POST'])
@login_required
def aaulab_sqli_low():
    flag = 'gtwss{congratulations_you_exploited_sqli}'
    results = []
    error = None
    flag_output = None
    query = None
    user_id = ''
    
    if request.method == 'POST':
        user_id = request.form.get('id', '')
        
        import sqlite3
        import re
        conn = sqlite3.connect(':memory:')
        conn.row_factory = sqlite3.Row
        c = conn.cursor()
        c.execute("CREATE TABLE users (user_id TEXT, first_name TEXT, last_name TEXT)")
        c.execute("INSERT INTO users VALUES ('1', 'admin', 'admin')")
        c.execute("INSERT INTO users VALUES ('2', 'Gordon', 'Brown')")
        c.execute("INSERT INTO users VALUES ('3', 'Hack', 'Me')")
        c.execute("INSERT INTO users VALUES ('4', 'Pablo', 'Picasso')")
        c.execute("INSERT INTO users VALUES ('5', 'Bob', 'Smith')")
        conn.commit()
        
        query = f"SELECT first_name, last_name FROM users WHERE user_id = '{user_id}';"
        
        found = False
        try:
            c.execute(query)
            rows = c.fetchall()
            for row in rows:
                results.append({
                    'first_name': row['first_name'],
                    'last_name': row['last_name']
                })
                found = True
        except Exception as e:
            error = f"Error in fetch: {str(e)}"
            
        if not found and re.search(r'(or|--|;|\s)', user_id, re.IGNORECASE):
            flag_output = flag
            
    return render_template('lab_sqli_low.html',
                           username=session.get('username'),
                           role=session.get('role'),
                           results=results,
                           error=error,
                           flag_output=flag_output,
                           query=query,
                           user_id=user_id)


@app.route('/aau/threatmapper/aaulab/sqli/medium', methods=['GET', 'POST'])
@login_required
def aaulab_sqli_medium():
    flag = 'gtwss{medium_level_sqli_exploited}'
    results = []
    error = None
    flag_output = None
    query = None
    raw_user_id = ''
    
    if request.method == 'POST':
        raw_user_id = request.form.get('id', '')
        
        # Simulate mysqli_real_escape_string
        user_id = raw_user_id.replace('\\', '\\\\').replace("'", "\\'").replace('"', '\\"')
        
        import sqlite3
        import re
        conn = sqlite3.connect(':memory:')
        conn.row_factory = sqlite3.Row
        c = conn.cursor()
        c.execute("CREATE TABLE users (user_id INTEGER, first_name TEXT, last_name TEXT)")
        c.execute("INSERT INTO users VALUES (1, 'admin', 'admin')")
        c.execute("INSERT INTO users VALUES (2, 'Gordon', 'Brown')")
        c.execute("INSERT INTO users VALUES (3, 'Hack', 'Me')")
        c.execute("INSERT INTO users VALUES (4, 'Pablo', 'Picasso')")
        c.execute("INSERT INTO users VALUES (5, 'Bob', 'Smith')")
        conn.commit()
        
        query = f"SELECT first_name, last_name FROM users WHERE user_id = {user_id};"
        
        found = False
        try:
            if user_id.strip():
                c.execute(query)
                rows = c.fetchall()
                for row in rows:
                    results.append({
                        'first_name': row['first_name'],
                        'last_name': row['last_name']
                    })
                    found = True
        except Exception as e:
            error = f"Error in fetch: {str(e)}"
            
        if not found and re.search(r'(or|--|;|\s)', raw_user_id, re.IGNORECASE):
            flag_output = flag
            
    return render_template('lab_sqli_medium.html',
                           username=session.get('username'),
                           role=session.get('role'),
                           results=results,
                           error=error,
                           flag_output=flag_output,
                           query=query,
                           user_id=raw_user_id)


@app.route('/aau/threatmapper/aaulab/sqli/high', methods=['GET', 'POST'])
@login_required
def aaulab_sqli_high():
    flag = 'gtwss{high_level_sqli_success}'
    results = []
    error = None
    flag_output = None
    query = None
    
    if request.method == 'POST':
        # Simulate storing ID in a separate session/window process
        session['sqli_id'] = request.form.get('id', '')
        return redirect('/aau/threatmapper/aaulab/sqli/high')

    user_id = session.get('sqli_id')
    
    if user_id is not None:
        import sqlite3
        import re
        conn = sqlite3.connect(':memory:')
        conn.row_factory = sqlite3.Row
        c = conn.cursor()
        c.execute("CREATE TABLE users (user_id TEXT, first_name TEXT, last_name TEXT)")
        c.execute("INSERT INTO users VALUES ('1', 'admin', 'admin')")
        c.execute("INSERT INTO users VALUES ('2', 'Gordon', 'Brown')")
        c.execute("INSERT INTO users VALUES ('3', 'Hack', 'Me')")
        c.execute("INSERT INTO users VALUES ('4', 'Pablo', 'Picasso')")
        c.execute("INSERT INTO users VALUES ('5', 'Bob', 'Smith')")
        conn.commit()
        
        query = f"SELECT first_name, last_name FROM users WHERE user_id = '{user_id}' LIMIT 1;"
        
        found = False
        try:
            c.execute(query)
            rows = c.fetchall()
            for row in rows:
                results.append({
                    'first_name': row['first_name'],
                    'last_name': row['last_name']
                })
                found = True
        except Exception as e:
            # High level obfuscates exact SQL error messages
            error = "Something went wrong."
            
        if not found and re.search(r'(\'|--|;|\s|or|and)', user_id, re.IGNORECASE):
            flag_output = flag
            
    return render_template('lab_sqli_high.html',
                           username=session.get('username'),
                           role=session.get('role'),
                           results=results,
                           error=error,
                           flag_output=flag_output,
                           query=query,
                           user_id=user_id or '')


@app.route('/aau/threatmapper/aaulab/idor/low', methods=['GET', 'POST'])
@login_required
def aaulab_idor_low():
    flag = 'gtwss{idor_low_exploited}'
    results = []
    error = None
    flag_output = None
    
    # Pre-defined database mapping
    students = {
        'Abreham': {'pass': 'passwd1', 'id': 'UGR/5788/16'},
        'Hany':    {'pass': 'passwd2', 'id': 'UGR/6502/16'},
        'Mikiyas': {'pass': 'passwd3', 'id': 'UGR/2616/16'},
        'Hermela': {'pass': 'passwd4', 'id': 'UGR/6868/16'}
    }
    
    students_by_id = {v['id']: k for k, v in students.items()}
    
    logged_in_username = session.get('idor_username')
    
    if request.method == 'POST':
        if 'logout' in request.form:
            session.pop('idor_username', None)
            return redirect('/aau/threatmapper/aaulab/idor/low')
            
        post_user = request.form.get('username', '').strip()
        post_pass = request.form.get('password', '').strip()
        
        if post_user in students and students[post_user]['pass'] == post_pass:
            session['idor_username'] = post_user
            return redirect(f"/aau/threatmapper/aaulab/idor/low?profile_id={students[post_user]['id']}")
        else:
            error = "Invalid Username or Password."

    view_profile_id = request.args.get('profile_id', '').strip()
    profile_data = {}
    
    if logged_in_username and view_profile_id:
        if view_profile_id in students_by_id:
            profile_name = students_by_id[view_profile_id]
            import hashlib, random
            courses = ['physics', 'maths', 'geograpy', 'history']
            possible_grades = ['A+', 'a', 'A-', 'B+', 'B', 'B-', 'C+', 'C']
            seed = int(hashlib.md5(view_profile_id.encode()).hexdigest(), 16)
            rng = random.Random(seed)
            for course in courses:
                results.append({'course': course, 'grade': rng.choice(possible_grades)})
                
            profile_data = {
                'id': view_profile_id,
                'name': profile_name,
                'role': 'User',
                'grades': results
            }
                
            if logged_in_username != profile_name:
                flag_output = flag
        else:
            error = "Profile not found in the university database."

    return render_template('lab_idor_low.html',
                           username=session.get('username'),
                           role=session.get('role'),
                           logged_in_user=logged_in_username,
                           view_profile_id=view_profile_id,
                           profile_data=profile_data,
                           error=error,
                           flag_output=flag_output)



@app.route('/aau/threatmapper/aaulab/idor/medium', methods=['GET', 'POST'])
@login_required
def aaulab_idor_medium():
    flag = 'gtwss{idor_medium_cookie_exploited}'
    results = []
    error = None
    flag_output = None
    
    students = {
        'Abreham': {'pass': 'passwd1', 'id': 'UGR/5788/16'},
        'Hany':    {'pass': 'passwd2', 'id': 'UGR/6502/16'},
        'Mikiyas': {'pass': 'passwd3', 'id': 'UGR/2616/16'},
        'Hermela': {'pass': 'passwd4', 'id': 'UGR/6868/16'}
    }
    
    actual_user = session.get('idor_med_actual_user')
    
    if request.method == 'POST':
        if 'logout' in request.form:
            session.pop('idor_med_actual_user', None)
            res = redirect('/aau/threatmapper/aaulab/idor/medium')
            res.delete_cookie('idor_token')
            return res
            
        post_user = request.form.get('username', '').strip()
        post_pass = request.form.get('password', '').strip()
        
        if post_user in students and students[post_user]['pass'] == post_pass:
            session['idor_med_actual_user'] = post_user
            import base64
            tok = base64.b64encode(f"User-{post_user}".encode()).decode()
            res = redirect('/aau/threatmapper/aaulab/idor/medium')
            res.set_cookie('idor_token', tok)
            return res
        else:
            error = "Invalid Username or Password."
            
    cookie_val = request.cookies.get('idor_token', '')
    profile_data = {}
    view_username = None
    
    if cookie_val:
        import base64
        try:
            decoded = base64.b64decode(cookie_val).decode('utf-8')
            if decoded.startswith('User-'):
                view_username = decoded[5:]
            else:
                error = "Malformed cookie value. Expected base64('User-{Username}')."
        except Exception:
            error = "Failed to decode cookie token."
            
    if view_username:
        if view_username in students:
            profile_name = view_username
            profile_id = students[view_username]['id']
            import hashlib, random
            courses = ['physics', 'maths', 'geograpy', 'history']
            possible_grades = ['A+', 'a', 'A-', 'B+', 'B', 'B-', 'C+', 'C']
            seed = int(hashlib.md5(profile_id.encode()).hexdigest(), 16)
            rng = random.Random(seed)
            for course in courses:
                results.append({'course': course, 'grade': rng.choice(possible_grades)})
            
            profile_data = {
                'id': profile_id,
                'name': profile_name,
                'role': 'User',
                'grades': results
            }
            
            if actual_user and actual_user != view_username:
                flag_output = flag
        else:
            error = f"No user found for username: {view_username}"
            
    return render_template('lab_idor_medium.html',
                           username=session.get('username'),
                           role=session.get('role'),
                           logged_in_user=actual_user,
                           profile_data=profile_data,
                           cookie_val=cookie_val,
                           error=error,
                           flag_output=flag_output)

@app.route('/aau/threatmapper/aaulab/idor/high', methods=['GET', 'POST'])
@login_required
def aaulab_idor_high():
    flag = 'gtwss{idor_high_uuid_exploited}'
    results = []
    error = None
    flag_output = None
    
    students = {
        'Abreham': {'pass': 'passwd1', 'uuid': '11111111-1111-4111-8111-111111111111'},
        'Hany':    {'pass': 'passwd2', 'uuid': '22222222-2222-4222-8222-222222222222'},
        'Mikiyas': {'pass': 'passwd3', 'uuid': '33333333-3333-4333-8333-333333333333'},
        'Hermela': {'pass': 'passwd4', 'uuid': '44444444-4444-4444-8444-444444444444'}
    }
    
    students_by_uuid = {v['uuid']: k for k, v in students.items()}
    logged_in_username = session.get('idor_high_actual_user')
    
    if request.method == 'POST':
        if 'logout' in request.form:
            session.pop('idor_high_actual_user', None)
            return redirect('/aau/threatmapper/aaulab/idor/high')
            
        post_user = request.form.get('username', '').strip()
        post_pass = request.form.get('password', '').strip()
        
        if post_user in students and students[post_user]['pass'] == post_pass:
            session['idor_high_actual_user'] = post_user
            return redirect(f"/aau/threatmapper/aaulab/idor/high?uuid={students[post_user]['uuid']}")
        else:
            error = "Invalid Username or Password."
            
    view_uuid = request.args.get('uuid', '').strip()
    profile_data = {}
    
    if logged_in_username and not view_uuid and not error:
        return redirect(f"/aau/threatmapper/aaulab/idor/high?uuid={students[logged_in_username]['uuid']}")

    if logged_in_username and view_uuid:
        if view_uuid in students_by_uuid:
            profile_name = students_by_uuid[view_uuid]
            import hashlib, random
            courses = ['physics', 'maths', 'geograpy', 'history']
            possible_grades = ['A+', 'a', 'A-', 'B+', 'B', 'B-', 'C+', 'C']
            seed = int(hashlib.md5(view_uuid.encode()).hexdigest(), 16)
            rng = random.Random(seed)
            for course in courses:
                results.append({'course': course, 'grade': rng.choice(possible_grades)})
            
            profile_data = {
                'id': view_uuid,
                'name': profile_name,
                'role': 'User',
                'grades': results
            }
            
            if logged_in_username != profile_name:
                flag_output = flag
        else:
            error = "Profile not found for the provided UUID."
            
    return render_template('lab_idor_high.html',
                           username=session.get('username'),
                           role=session.get('role'),
                           logged_in_user=logged_in_username,
                           view_uuid=view_uuid,
                           profile_data=profile_data,
                           error=error,
                           flag_output=flag_output)

@app.route('/aau/threatmapper/aaulab/xss_low', methods=['GET', 'POST'])
@login_required
def aaulab_xss_low():
    flag = 'gtwss{xss_reflected_low_exploited}'
    error = None
    # Simple user credentials similar to IDOR lab
    users = {
        'Hermela': {'pass': 'passwd4', 'role': 'Admin'},
        'Abreham': {'pass': 'passwd1', 'role': 'User'},
        'Hany': {'pass': 'passwd2', 'role': 'User'},
        'Mikiyas': {'pass': 'passwd3', 'role': 'User'},
        'Bikila': {'pass': 'passwd5', 'role': 'User'},
        'Mastewal': {'pass': 'passwd6', 'role': 'User'}
    }
    if request.method == 'POST':
        if 'logout' in request.form:
            session.pop('xss_username', None)
            return redirect('/aau/threatmapper/aaulab/xss_low')
        post_user = request.form.get('username', '').strip()
        post_pass = request.form.get('password', '').strip()
        if post_user in users and users[post_user]['pass'] == post_pass:
            session['xss_username'] = post_user
            return redirect('/aau/threatmapper/aaulab/xss_low')
        else:
            error = 'Invalid Username or Password.'
    logged_in_user = session.get('xss_username')
    name = request.args.get('name')
    flag_output = None
    if name and '<script>' in name.lower():
        flag_output = flag
    return render_template('lab_xss_low.html', name=name, flag_output=flag_output,
                           logged_in_user=logged_in_user, error=error, available_users=users)

@app.route('/aau/threatmapper/aaulab/xss_medium', methods=['GET', 'POST'])
@login_required
def aaulab_xss_medium():
    flag = 'gtwss{xss_reflected_medium_exploited}'
    name = request.args.get('name')
    flag_output = None
    if name:
        sanitized = name.replace('<script>', '')
        if '<script>' in name.lower():
            flag_output = flag
    else:
        sanitized = ''
    return render_template('lab_xss_medium.html', name=sanitized, flag_output=flag_output)

# JWT Low Level Lab – vulnerable alg=none implementation
JWT_SECRET = 'supersecretkey-change-me'
FLAG_JWT = 'gtwss{jwt_alg_none_exploited}'

def _b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b'=').decode('utf-8')

def _b64url_decode(data: str) -> bytes:
    padding = '=' * (-len(data) % 4)
    return base64.urlsafe_b64decode(data + padding)

def _sign_hs256(header_b64: str, payload_b64: str, secret: str) -> str:
    msg = f"{header_b64}.{payload_b64}".encode('utf-8')
    sig = hmac.new(secret.encode('utf-8'), msg, hashlib.sha256).digest()
    return _b64url_encode(sig)

def verify_jwt_vulnerable(token: str):
    parts = token.split('.')
    if len(parts) != 3:
        return False, None, 'Malformed token'
    h_b64, p_b64, s_b64 = parts
    try:
        header = json.loads(_b64url_decode(h_b64).decode('utf-8'))
        payload = json.loads(_b64url_decode(p_b64).decode('utf-8'))
    except Exception:
        return False, None, 'Invalid encoding'
    alg = header.get('alg', '').lower()
    if alg == 'none':
        return True, payload, ''
    if alg.startswith('hs'):
        expected = _sign_hs256(h_b64, p_b64, JWT_SECRET)
        if not hmac.compare_digest(expected, s_b64):
            return False, None, 'Invalid signature'
        return True, payload, ''
    return False, None, 'Unsupported alg'

@app.route('/aau/threatmapper/aaulab/jwt_low', methods=['GET', 'POST'])
@login_required
def aaulab_jwt_low():
    token = request.cookies.get('jwt')
    payload = None
    flag_output = None
    if token:
        ok, payload, err = verify_jwt_vulnerable(token)
        if not ok:
            flash(f'JWT verification failed: {err}', 'error')
        else:
            # payload is a dict
            if payload.get('role') == 'admin':
                flag_output = FLAG_JWT
    return render_template('lab_jwt_low.html', token=token, payload=payload, flag_output=flag_output)




# New route to display private user info after login
@app.route('/private_info')
@login_required
def private_info():
    # Mock private data based on username
    user = session.get('username')
    # In a real app, this would query a database for private details
    private_data = {
        'abebe': {
            'id': '001',
            'username': 'abebe',
            'gender': 'Male',
            'bank_account': 'ET1234567890',
            'password': '1234'
        },
        'kebede': {
            'id': '002',
            'username': 'kebede',
            'gender': 'Female',
            'bank_account': 'ET0987654321',
            'password': '1234'
        }
    }
    info = private_data.get(user.lower(), {})
    return render_template('private_info.html', info=info)


@app.route('/aau/threatmapper/aaulab/bruteforce/low', methods=['GET', 'POST'])
@login_required
def aaulab_bruteforce_low():
    flag = 'gtwss{bruteforce_low_exploited}'
    error = None
    flag_output = None
    if 'Login' in request.args:
        username = request.args.get('username', '')
        password = request.args.get('password', '')
        if username == 'admin' and password == 'password':
            flag_output = flag
        else:
            error = "Username and/or password incorrect."
    return render_template('lab_bruteforce_low.html', username=session.get('username'), role=session.get('role'), error=error, flag_output=flag_output)

@app.route('/aau/threatmapper/aaulab/bruteforce/medium', methods=['GET', 'POST'])
@login_required
def aaulab_bruteforce_medium():
    flag = 'gtwss{bruteforce_medium_exploited}'
    error = None
    flag_output = None
    if 'Login' in request.args:
        username = request.args.get('username', '')
        password = request.args.get('password', '')
        if username == 'admin' and password == 'password':
            flag_output = flag
        else:
            import time
            time.sleep(2)
            error = "Username and/or password incorrect."
    return render_template('lab_bruteforce_medium.html', username=session.get('username'), role=session.get('role'), error=error, flag_output=flag_output)

@app.route('/aau/threatmapper/aaulab/bruteforce/high', methods=['GET', 'POST'])
@login_required
def aaulab_bruteforce_high():
    flag = 'gtwss{bruteforce_high_exploited}'
    error = None
    flag_output = None
    import uuid
    if 'Login' in request.args:
        username = request.args.get('username', '')
        password = request.args.get('password', '')
        user_token = request.args.get('user_token', '')
        expected_token = session.get('bf_csrf_token', '')
        if not expected_token or user_token != expected_token:
            error = "CSRF token is missing or incorrect. Request rejected."
        else:
            if username == 'admin' and password == 'password':
                flag_output = flag
            else:
                import time, random
                time.sleep(random.randint(0, 3))
                error = "Username and/or password incorrect."
    new_token = str(uuid.uuid4())
    session['bf_csrf_token'] = new_token
    return render_template('lab_bruteforce_high.html', username=session.get('username'), role=session.get('role'), error=error, flag_output=flag_output, user_token=new_token)
# ── API Routes ──────────────────────────────────────────────
@app.route('/api/scan', methods=['POST'])
@login_required
def api_scan():
    target = request.json.get('target', 'demo')
    subdomains = request.json.get('subdomains', None)
    scan_type = request.json.get('type', 'full')

    risk_level = request.json.get('risk_level', 'Medium')
    
    result = run_simulation(target, subdomains=subdomains, risk_level=risk_level)

    # Save to DB
    summary = result.get('summary', {})
    save_scan(
        session['user_id'], target, scan_type,
        summary.get('total', 0),
        summary.get('critical', 0),
        summary.get('high', 0),
        summary.get('medium', 0),
        summary.get('low', 0),
        summary.get('info', 0),
        json.dumps(result['findings'])
    )
    log_activity(session['user_id'], 'scan', f'Scan on {target} ({scan_type})')

    return jsonify(result)


@app.route('/api/ai', methods=['POST'])
@login_required
def api_ai():
    q = request.json.get('question', '')
    answer = ask_ai(q)
    log_activity(session['user_id'], 'ai_query', q[:100])
    return jsonify({'answer': answer})


# ── ChatGPT-style multi-turn chat ───────────────────────────────
CHAT_HISTORIES = {}  # session_key -> list of {role, content}


@app.route('/api/chat', methods=['POST'])
@login_required
def api_chat():
    """Send a message and get a response, maintaining full conversation history."""
    data = request.json or {}
    user_message = data.get('message', '').strip()
    conversation_id = data.get('conversation_id', 'default')

    if not user_message:
        return jsonify({'error': 'Empty message'}), 400

    # Build session-scoped key
    session_key = f"{session['user_id']}:{conversation_id}"

    # Initialize history if new conversation
    if session_key not in CHAT_HISTORIES:
        CHAT_HISTORIES[session_key] = []

    # Append user message
    CHAT_HISTORIES[session_key].append({
        'role': 'user',
        'content': user_message
    })

    # Get AI response with full history
    answer = ask_ai_with_history(CHAT_HISTORIES[session_key])

    # Append assistant response
    CHAT_HISTORIES[session_key].append({
        'role': 'assistant',
        'content': answer
    })

    # Keep last 40 messages (20 turns) to control memory
    if len(CHAT_HISTORIES[session_key]) > 40:
        CHAT_HISTORIES[session_key] = CHAT_HISTORIES[session_key][-40:]

    log_activity(session['user_id'], 'ai_chat', user_message[:100])

    return jsonify({
        'answer': answer,
        'conversation_id': conversation_id,
        'turn': len([m for m in CHAT_HISTORIES[session_key] if m['role'] == 'user'])
    })


@app.route('/api/chat/reset', methods=['POST'])
@login_required
def api_chat_reset():
    """Start a new conversation (clears history for given conversation_id)."""
    data = request.json or {}
    conversation_id = data.get('conversation_id', 'default')
    session_key = f"{session['user_id']}:{conversation_id}"
    CHAT_HISTORIES.pop(session_key, None)
    return jsonify({'success': True, 'conversation_id': conversation_id})


@app.route('/api/chat/history', methods=['GET'])
@login_required
def api_chat_history():
    """Get the full history for a conversation."""
    conversation_id = request.args.get('conversation_id', 'default')
    session_key = f"{session['user_id']}:{conversation_id}"
    history = CHAT_HISTORIES.get(session_key, [])
    return jsonify({'history': history, 'conversation_id': conversation_id})


@app.route('/api/stats')
@login_required
def api_stats():
    return jsonify(get_dashboard_stats())


@app.route('/api/scan-history')
@login_required
def api_scan_history():
    return jsonify(get_scan_history())


@app.route('/api/activity')
@login_required
def api_activity():
    return jsonify(get_activity_log())


# ── User Management (Admin only) ───────────────────────────
@app.route('/api/users')
@login_required
@role_required('admin')
def api_users():
    return jsonify(get_all_users())


@app.route('/api/users/add', methods=['POST'])
@login_required
@role_required('admin')
def api_add_user():
    data = request.json
    ok = add_user(data['username'], data['email'], data['password'], data['role'])
    if ok:
        log_activity(session['user_id'], 'user_add', f'Added user {data["email"]}')
        return jsonify({'success': True})
    return jsonify({'success': False, 'error': 'User already exists'}), 400


@app.route('/api/users/delete', methods=['POST'])
@login_required
@role_required('admin')
def api_delete_user():
    user_id = request.json.get('id')
    if user_id == session['user_id']:
        return jsonify({'error': 'Cannot delete yourself'}), 400
    delete_user(user_id)
    log_activity(session['user_id'], 'user_delete', f'Deleted user ID {user_id}')
    return jsonify({'success': True})


# ── PDF Export ──────────────────────────────────────────────
@app.route('/api/export-pdf', methods=['POST'])
@login_required
def api_export_pdf():
    findings = request.json.get('findings', [])
    if not findings:
        return jsonify({'error': 'No findings to export'}), 400
    filepath = generate_pdf_report(findings)
    log_activity(session['user_id'], 'export_pdf', f'Exported {len(findings)} findings')
    return send_file(filepath, as_attachment=True, download_name=os.path.basename(filepath))


# ── WebSocket Terminal ──────────────────────────────────────
PTY_SESSIONS = {}

@socketio.on('terminal_start')
def start_pty():
    sid = request.sid
    if sid in PTY_SESSIONS:
        return
    
    pid, fd = pty.fork()
    
    if pid == 0: # Child process
        env = os.environ.copy()
        env['TERM'] = 'xterm-256color'
        
        # Dedicated tools sandbox
        base_dir = os.path.abspath(os.path.dirname(__file__))
        lab_tools = os.path.join(base_dir, 'lab_tools')
        lab_bin = os.path.join(lab_tools, 'bin')
        
        env['PATH'] = f"{lab_bin}:{env.get('PATH', '')}"
        os.chdir(lab_tools)
        
        os.execvpe('bash', ['bash'], env)
    
    # Parent process
    PTY_SESSIONS[sid] = {'fd': fd, 'pid': pid}

    def read_output(master_fd, socket_id):
        while True:
            try:
                data = os.read(master_fd, 4096)
                if not data:
                    break
                socketio.emit('terminal_output', {'data': data.decode('utf-8', 'replace')}, to=socket_id)
            except OSError:
                break

    threading.Thread(target=read_output, args=(fd, sid), daemon=True).start()
    emit('terminal_output', {'data': f'\r\n[Connected to interactive lab shell]\r\n'})

@socketio.on('terminal_input')
def terminal_input(data):
    sid = request.sid
    if sid in PTY_SESSIONS:
        fd = PTY_SESSIONS[sid]['fd']
        cmd = data.get('input', '')
        try:
            os.write(fd, cmd.encode('utf-8'))
        except OSError:
            pass

@socketio.on('disconnect')
def on_disconnect():
    sid = request.sid
    if sid in PTY_SESSIONS:
        fd = PTY_SESSIONS[sid]['fd']
        pid = PTY_SESSIONS[sid]['pid']
        try:
            os.close(fd)
        except:
            pass
        try:
            import signal
            os.kill(pid, signal.SIGKILL)
        except OSError:
            pass
        del PTY_SESSIONS[sid]


# ── WebSocket Live Scan ─────────────────────────────────────
@socketio.on('start_scan')
def handle_scan(data):
    target = data.get('target', 'demo')
    scan_type = data.get('type', 'full')
    speed = float(data.get('speed', 10))
    subdomains = data.get('subdomains', None)
    source_code = data.get('source_code', None)
    risk_level = data.get('risk_level', 'Medium')

    def callback(msg):
        socketio.emit('scan_output', {'data': msg + '\n'}, namespace='/')
        
    def progress_callback(pct):
        socketio.emit('scan_progress', {'pct': pct}, namespace='/')

    def run():
        result = run_simulation(
            target=target, 
            subdomains=subdomains, 
            source_code=source_code, 
            callback=callback, 
            progress_callback=progress_callback,
            speed=speed, 
            risk_level=risk_level
        )
        socketio.emit('scan_complete', result, namespace='/')

    thread = threading.Thread(target=run)
    thread.daemon = True
    thread.start()


# ── SOC Real-time Stats v3 ─────────────────────────────────────
@app.route('/api/system')
@login_required
def api_system():
    return jsonify({
        "cpu": psutil.cpu_percent(interval=None),
        "memory": psutil.virtual_memory().percent,
        "disk": psutil.disk_usage('/').percent
    })

@app.route('/api/network')
@login_required
def api_network():
    net = psutil.net_io_counters()
    return jsonify({
        "sent": net.bytes_sent,
        "recv": net.bytes_recv
    })

@app.route('/api/threats')
@login_required
def api_threats():
    threat_types = [
        "Port Scan Detected",
        "Suspicious Login Attempt",
        "Brute Force Pattern",
        "Malware Signature Match",
        "SQL Injection Pattern (blocked)",
        "XSS Attempt (blocked)",
        "Anomalous Traffic Spike"
    ]
    severity = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]

    event = {
        "type": random.choice(threat_types),
        "severity": random.choice(severity),
        "score": random.randint(10, 99),
        "timestamp": time.strftime("%H:%M:%S")
    }
    return jsonify(event)

if __name__ == '__main__':
    socketio.run(app, debug=True, host='0.0.0.0', port=5000)

@app.route("/")
    return "ThreatMapper Backend Running Successfully"

