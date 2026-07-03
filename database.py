import sqlite3
import hashlib
import os

DB_PATH = os.path.join(os.path.dirname(__file__), 'threatmapper.db')

def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

def init_db():
    conn = get_db()
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        email TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        role TEXT NOT NULL DEFAULT 'analyst',
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )''')
    c.execute('''CREATE TABLE IF NOT EXISTS scan_history (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        target TEXT,
        scan_type TEXT,
        findings_count INTEGER DEFAULT 0,
        critical INTEGER DEFAULT 0,
        high INTEGER DEFAULT 0,
        medium INTEGER DEFAULT 0,
        low INTEGER DEFAULT 0,
        info INTEGER DEFAULT 0,
        results TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY(user_id) REFERENCES users(id)
    )''')
    c.execute('''CREATE TABLE IF NOT EXISTS activity_log (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        action TEXT,
        detail TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY(user_id) REFERENCES users(id)
    )''')
    conn.commit()

    # Seed default users if none exist
    existing = c.execute('SELECT COUNT(*) FROM users').fetchone()[0]
    if existing == 0:
        users = [
            ('admin', 'abc@gmail.com', hash_password('1234'), 'admin'),
            ('analyst', 'analyst@eacasummit.com', hash_password('1234'), 'analyst'),
            ('developer', 'dev@eacasummit.com', hash_password('1234'), 'developer'),
            ('user', 'user@eacasummit.com', hash_password('1234'), 'user'),
            ('abebe', 'abebe@eacasummit.com', hash_password('1234'), 'admin'),
            ('kebede', 'kebede@eacasummit.com', hash_password('1234'), 'user'),
        ]
        c.executemany('INSERT INTO users (username, email, password, role) VALUES (?,?,?,?)', users)
        conn.commit()
    conn.close()

def get_user_by_email(email):
    conn = get_db()
    user = conn.execute('SELECT * FROM users WHERE email = ?', (email,)).fetchone()
    conn.close()
    return user

def get_all_users():
    conn = get_db()
    users = conn.execute('SELECT id, username, email, role, created_at FROM users').fetchall()
    conn.close()
    return [dict(u) for u in users]

def add_user(username, email, password, role):
    conn = get_db()
    try:
        conn.execute('INSERT INTO users (username, email, password, role) VALUES (?,?,?,?)',
                      (username, email, hash_password(password), role))
        conn.commit()
        return True
    except sqlite3.IntegrityError:
        return False
    finally:
        conn.close()

def delete_user(user_id):
    conn = get_db()
    conn.execute('DELETE FROM users WHERE id = ?', (user_id,))
    conn.commit()
    conn.close()

def save_scan(user_id, target, scan_type, findings_count, critical, high, medium, low, info, results):
    conn = get_db()
    conn.execute('''INSERT INTO scan_history
        (user_id, target, scan_type, findings_count, critical, high, medium, low, info, results)
        VALUES (?,?,?,?,?,?,?,?,?,?)''',
        (user_id, target, scan_type, findings_count, critical, high, medium, low, info, results))
    conn.commit()
    conn.close()

def get_scan_history(limit=50):
    conn = get_db()
    rows = conn.execute('''SELECT s.*, u.username FROM scan_history s
        LEFT JOIN users u ON s.user_id = u.id
        ORDER BY s.created_at DESC LIMIT ?''', (limit,)).fetchall()
    conn.close()
    return [dict(r) for r in rows]

def log_activity(user_id, action, detail=''):
    conn = get_db()
    conn.execute('INSERT INTO activity_log (user_id, action, detail) VALUES (?,?,?)',
                 (user_id, action, detail))
    conn.commit()
    conn.close()

def get_activity_log(limit=100):
    conn = get_db()
    rows = conn.execute('''SELECT a.*, u.username FROM activity_log a
        LEFT JOIN users u ON a.user_id = u.id
        ORDER BY a.created_at DESC LIMIT ?''', (limit,)).fetchall()
    conn.close()
    return [dict(r) for r in rows]

def get_dashboard_stats():
    conn = get_db()
    total_scans = conn.execute('SELECT COUNT(*) FROM scan_history').fetchone()[0]
    total_findings = conn.execute('SELECT COALESCE(SUM(findings_count),0) FROM scan_history').fetchone()[0]
    severity = conn.execute('''SELECT
        COALESCE(SUM(critical),0) as critical,
        COALESCE(SUM(high),0) as high,
        COALESCE(SUM(medium),0) as medium,
        COALESCE(SUM(low),0) as low,
        COALESCE(SUM(info),0) as info
        FROM scan_history''').fetchone()
    total_users = conn.execute('SELECT COUNT(*) FROM users').fetchone()[0]
    conn.close()
    return {
        'total_scans': total_scans,
        'total_findings': total_findings,
        'total_users': total_users,
        'severity': {
            'critical': severity['critical'],
            'high': severity['high'],
            'medium': severity['medium'],
            'low': severity['low'],
            'info': severity['info'],
        }
    }
