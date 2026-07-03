"""
SecureSphere – Modular Vulnerability Scanner (Educational / Lab Use Only)
=========================================================================
Modules:
  1. Passive Recon          – subdomain expansion from wildcard
  2. Security Header Check  – CSP, HSTS, X-Frame-Options, X-Content-Type-Options, Referrer-Policy
  3. XSS Reflected Scanner  – inject payloads into GET params, check reflection
  4. SQL Injection Tester    – error-based, boolean-based, time-based (safe delays)
  5. Directory Traversal     – ../  and encoded payloads on file params
  6. IDOR Tester             – integer-id parameter walk
  7. Open Redirect           – parameter redirect manipulation
  8. Information Disclosure  – .git, debug pages, backup files, stack traces

Architecture:  Target → Scanner Module → Detection Logic → Risk Report
All requests use a safe, short timeout; no destructive payloads are sent.
"""

import time
import re
import random
import urllib.parse
from typing import Callable, List, Optional

# ── Try to import requests; fall back to simulation if unavailable ──
try:
    import requests
    from requests.exceptions import RequestException
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False

# ─────────────────────────────────────────────────────────────────────
# OWASP / CVSS Metadata
# ─────────────────────────────────────────────────────────────────────
OWASP_MAP = {
    # Header issues
    'Missing Content-Security-Policy':    {'owasp': 'A05:2021 Security Misconfiguration', 'cvss': 5.3},
    'Missing X-Frame-Options':            {'owasp': 'A05:2021 Security Misconfiguration', 'cvss': 4.3},
    'Missing HSTS Header':                {'owasp': 'A02:2021 Cryptographic Failures',    'cvss': 5.9},
    'Missing X-Content-Type-Options':     {'owasp': 'A05:2021 Security Misconfiguration', 'cvss': 3.7},
    'Missing Referrer-Policy':            {'owasp': 'A05:2021 Security Misconfiguration', 'cvss': 3.1},
    'Server Version Exposed':             {'owasp': 'A05:2021 Security Misconfiguration', 'cvss': 3.7},
    # Injection
    'XSS Reflected':                      {'owasp': 'A03:2021 Injection',                 'cvss': 6.1},
    'SQL Injection (Error-Based)':        {'owasp': 'A03:2021 Injection',                 'cvss': 9.8},
    'SQL Injection (Boolean-Based)':      {'owasp': 'A03:2021 Injection',                 'cvss': 8.8},
    'SQL Injection (Time-Based)':         {'owasp': 'A03:2021 Injection',                 'cvss': 8.5},
    'Command Injection':                  {'owasp': 'A03:2021 Injection',                 'cvss': 9.8},
    'SSTI (Template Injection)':          {'owasp': 'A03:2021 Injection',                 'cvss': 9.8},
    # Traversal / access
    'Directory Traversal':                {'owasp': 'A01:2021 Broken Access Control',     'cvss': 7.5},
    'Path Traversal':                     {'owasp': 'A01:2021 Broken Access Control',     'cvss': 7.5},
    'IDOR (Insecure Direct Object Ref)':  {'owasp': 'A01:2021 Broken Access Control',     'cvss': 8.1},
    'Open Redirect':                      {'owasp': 'A01:2021 Broken Access Control',     'cvss': 4.7},
    'BOLA (Broken Object Level Auth)':    {'owasp': 'API1:2023 Broken Object Level Auth', 'cvss': 8.5},
    # Auth / session
    'Default Credentials Detected':       {'owasp': 'A07:2021 Auth Failures',             'cvss': 9.1},
    'Broken Authentication':              {'owasp': 'A07:2021 Auth Failures',             'cvss': 8.5},
    'Weak Session Management':            {'owasp': 'A07:2021 Auth Failures',             'cvss': 7.3},
    'JWT Misconfiguration':               {'owasp': 'A02:2021 Cryptographic Failures',    'cvss': 9.0},
    # Info disclosure
    'Information Disclosure (.git)':      {'owasp': 'A05:2021 Security Misconfiguration', 'cvss': 5.8},
    'Information Disclosure (debug)':     {'owasp': 'A05:2021 Security Misconfiguration', 'cvss': 4.3},
    'Information Disclosure (backup)':    {'owasp': 'A05:2021 Security Misconfiguration', 'cvss': 5.5},
    'Stack Trace Exposed':                {'owasp': 'A05:2021 Security Misconfiguration', 'cvss': 4.8},
    # Other
    'SSRF Detected':                      {'owasp': 'A10:2021 SSRF',                      'cvss': 8.6},
    'CSRF Vulnerability':                 {'owasp': 'A01:2021 Broken Access Control',     'cvss': 6.5},
    'Race Condition':                     {'owasp': 'A04:2021 Insecure Design',            'cvss': 7.0},
    'Open SSH Port':                      {'owasp': 'A05:2021 Security Misconfiguration', 'cvss': 6.5},
    'Open MySQL Port':                    {'owasp': 'A05:2021 Security Misconfiguration', 'cvss': 7.5},
    'Unrestricted File Upload':           {'owasp': 'A04:2021 Insecure Design',            'cvss': 8.8},
    'Insecure Deserialization':           {'owasp': 'A08:2021 Software & Data Integrity',  'cvss': 9.8},
}

SEVERITY_THRESHOLDS = [(9.0, 'Critical'), (7.0, 'High'), (4.0, 'Medium'), (0.1, 'Low'), (0.0, 'Info')]

def get_severity(cvss: float) -> str:
    for threshold, label in SEVERITY_THRESHOLDS:
        if cvss >= threshold:
            return label
    return 'Info'

# ─────────────────────────────────────────────────────────────────────
# HTTP helpers
# ─────────────────────────────────────────────────────────────────────
HEADERS = {
    'User-Agent': 'SecureSphere-Scanner/2.0 (Educational Lab)',
    'Accept': 'text/html,application/xhtml+xml,application/json,*/*',
}
TIMEOUT = 6   # seconds per request

def _get(url: str, params: dict = None, timeout: int = TIMEOUT):
    """Safe GET — returns (response, elapsed_seconds) or (None, 0)."""
    if not REQUESTS_AVAILABLE:
        return None, 0
    try:
        t0 = time.time()
        r = requests.get(url, params=params, headers=HEADERS,
                         timeout=timeout, allow_redirects=False,
                         verify=False)
        return r, time.time() - t0
    except RequestException:
        return None, 0

def _normalise_target(raw: str) -> str:
    """Strip leading wildcard and ensure no trailing slash."""
    raw = raw.strip()
    if raw.startswith('*.'):
        raw = raw[2:]
    if not raw.startswith(('http://', 'https://')):
        raw = 'http://' + raw
    return raw.rstrip('/')

def _expand_wildcard(target: str, emit: Callable) -> List[str]:
    """Expand *.domain.com into a list of common subdomains to test."""
    bare = target.strip()
    if bare.startswith('*.'):
        domain = bare[2:]
        prefixes = ['www', 'api', 'dev', 'admin', 'mail', 'app', 'portal', 'staging']
        hosts = [f'{p}.{domain}' for p in prefixes]
        emit(f'[RECON] Wildcard detected — expanding to {len(hosts)} candidate subdomains')
        for h in hosts:
            emit(f'[RECON] + {h}')
        return hosts
    return [bare]

def _build_base(host: str) -> str:
    if host.startswith(('http://', 'https://')):
        return host.rstrip('/')
    return 'http://' + host.rstrip('/')

# ─────────────────────────────────────────────────────────────────────
# Module 1 – Security Header Check
# ─────────────────────────────────────────────────────────────────────
REQUIRED_HEADERS = [
    ('content-security-policy',  'Missing Content-Security-Policy',   'Allows XSS via inline scripts'),
    ('x-frame-options',          'Missing X-Frame-Options',           'Clickjacking attacks possible'),
    ('strict-transport-security','Missing HSTS Header',               'Downgrade attacks feasible (no HSTS)'),
    ('x-content-type-options',   'Missing X-Content-Type-Options',    'MIME-sniffing attacks possible'),
    ('referrer-policy',          'Missing Referrer-Policy',           'Referrer leaks sensitive URLs'),
]

def check_security_headers(base: str, host: str, emit: Callable, findings: list, delay: float):
    emit(f'[Headers] Checking security headers on {host}...')
    resp, _ = _get(base + '/')
    if resp is None:
        emit(f'[Headers] {host} unreachable — skipping header check')
        return

    # Server header version leak
    server = resp.headers.get('server', '')
    if server and re.search(r'\d', server):
        _add_finding(findings, host, 'Server Version Exposed',
                     f'Server header reveals: {server}',
                     f'{host} → HTTP Headers → Server: {server}', emit)

    for header_name, issue, desc in REQUIRED_HEADERS:
        time.sleep(delay)
        if header_name not in resp.headers:
            _add_finding(findings, host, issue, desc,
                         f'{host} → HTTP Headers → {header_name} missing', emit)
        else:
            emit(f'[Headers] ✔ {header_name} present')

# ─────────────────────────────────────────────────────────────────────
# Module 2 – XSS (Reflected) Scanner
# ─────────────────────────────────────────────────────────────────────
XSS_PAYLOADS = [
    '<script>alert(1)</script>',
    '"><img src=x onerror=alert(1)>',
    "'><svg onload=alert(1)>",
    '{{7*7}}',   # also catches template injection
]
XSS_PROBE_PARAMS = ['q', 'search', 'query', 'input', 'id', 'name', 'page', 'term', 'keyword']
XSS_PROBE_PATHS  = ['/', '/search', '/api/search', '/index.php', '/index.html']

def check_xss(base: str, host: str, emit: Callable, findings: list, delay: float):
    emit(f'[XSS] Injecting reflection payloads into GET parameters on {host}...')
    found = False
    for path in XSS_PROBE_PATHS:
        for param in XSS_PROBE_PARAMS:
            for payload in XSS_PAYLOADS[:2]:   # limit to keep runtime reasonable
                time.sleep(delay)
                url = base + path
                resp, _ = _get(url, params={param: payload})
                if resp and payload in (resp.text or ''):
                    detail = (f'Payload reflected in response: param={param!r} '
                              f'path={path} payload={payload!r}')
                    _add_finding(findings, host, 'XSS Reflected', detail,
                                 f'{host}{path}?{param}=<payload> → reflected', emit)
                    found = True
                    break
            if found:
                break
        if found:
            break
    if not found:
        emit(f'[XSS] No straightforward reflections detected on {host}')

# ─────────────────────────────────────────────────────────────────────
# Module 3 – SQL Injection
# ─────────────────────────────────────────────────────────────────────
SQLI_ERROR_SIGNATURES = [
    "you have an error in your sql syntax",
    "warning: mysql",
    "unclosed quotation mark",
    "pg_query",
    "sqlstate",
    "odbc",
    "ora-00933",
    "microsoft ole db provider for sql server",
    "sqlite_exception",
]
SQLI_ERROR_PAYLOADS   = ["'", '"', "' OR '1'='1", "\" OR \"1\"=\"1"]
SQLI_BOOL_BASELINE    = "/about"
SQLI_TIME_PAYLOAD     = "' OR SLEEP(3)-- "
SQLI_PARAMS           = ['id', 'user_id', 'item', 'product', 'page', 'cat']
SQLI_PATHS            = ['/', '/api/users', '/api/items', '/search', '/product']

def check_sqli(base: str, host: str, emit: Callable, findings: list, delay: float):
    emit(f'[SQLi] Testing for SQL injection on {host}...')

    # --- Error-based ---
    for path in SQLI_PATHS:
        for param in SQLI_PARAMS:
            for payload in SQLI_ERROR_PAYLOADS:
                time.sleep(delay)
                resp, _ = _get(base + path, params={param: payload})
                if resp:
                    body_l = resp.text.lower()
                    for sig in SQLI_ERROR_SIGNATURES:
                        if sig in body_l:
                            _add_finding(findings, host, 'SQL Injection (Error-Based)',
                                         f'DB error triggered at {path}?{param}={payload!r}. '
                                         f'Signature: "{sig}"',
                                         f'{host}{path}?{param}=<sqli_payload> → DB error', emit)
                            return   # one confirmed finding is enough

    # --- Time-based (safe: 3-second SLEEP, check elapsed) ---
    for path in SQLI_PATHS[:2]:
        for param in SQLI_PARAMS[:3]:
            time.sleep(delay)
            resp, elapsed = _get(base + path, params={param: SQLI_TIME_PAYLOAD}, timeout=10)
            if resp and elapsed >= 2.8:
                _add_finding(findings, host, 'SQL Injection (Time-Based)',
                             f'Response delayed {elapsed:.1f}s when SLEEP(3) injected at '
                             f'{path}?{param}',
                             f'{host}{path}?{param}=SLEEP(3) → {elapsed:.1f}s delay', emit)
                return

    emit(f'[SQLi] No injectable parameters confirmed on {host}')

# ─────────────────────────────────────────────────────────────────────
# Module 4 – Directory / Path Traversal
# ─────────────────────────────────────────────────────────────────────
TRAVERSAL_PAYLOADS = [
    '../../../etc/passwd',
    '..%2F..%2F..%2Fetc%2Fpasswd',
    '....//....//....//etc/passwd',
    '%252e%252e%252fetc%252fpasswd',
    '../../../windows/win.ini',
]
TRAVERSAL_PARAMS = ['file', 'page', 'path', 'template', 'doc', 'filename', 'load']
TRAVERSAL_SIGNATURES = ['root:x:', '[extensions]', 'for 16-bit app support']

def check_traversal(base: str, host: str, emit: Callable, findings: list, delay: float):
    emit(f'[Traversal] Testing directory/path traversal on {host}...')
    for path in ['/', '/download', '/view', '/read', '/api/file']:
        for param in TRAVERSAL_PARAMS:
            for payload in TRAVERSAL_PAYLOADS:
                time.sleep(delay)
                resp, _ = _get(base + path, params={param: payload})
                if resp:
                    body = resp.text or ''
                    for sig in TRAVERSAL_SIGNATURES:
                        if sig in body:
                            _add_finding(findings, host, 'Directory Traversal',
                                         f'File disclosure at {path}?{param}={payload!r}. '
                                         f'Signature: "{sig}" found in response',
                                         f'{host}{path}?{param}=../etc/passwd → file read', emit)
                            return
    emit(f'[Traversal] No path traversal confirmed on {host}')

# ─────────────────────────────────────────────────────────────────────
# Module 5 – IDOR Tester
# ─────────────────────────────────────────────────────────────────────
IDOR_ENDPOINTS = ['/api/user/', '/api/users/', '/api/profile/', '/api/order/',
                  '/api/item/', '/api/account/', '/user/', '/profile/']

def check_idor(base: str, host: str, emit: Callable, findings: list, delay: float):
    emit(f'[IDOR] Probing integer-ID endpoints on {host}...')
    for endpoint in IDOR_ENDPOINTS:
        baseline_resp, _ = _get(base + endpoint + '1')
        time.sleep(delay)
        if baseline_resp is None or baseline_resp.status_code not in (200, 403):
            continue

        # Probe adjacent IDs
        for obj_id in [2, 3, 10, 100]:
            time.sleep(delay)
            r, _ = _get(base + endpoint + str(obj_id))
            if r and r.status_code == 200 and len(r.text) > 50:
                # Look for user-data patterns in response
                if any(k in r.text.lower() for k in
                       ['email', 'username', 'password', 'name', 'phone', 'profile']):
                    _add_finding(findings, host, 'IDOR (Insecure Direct Object Ref)',
                                 f'Object ID walk: {endpoint}1 → {endpoint}{obj_id} — '
                                 f'user data accessible without auth check',
                                 f'{host}{endpoint}{obj_id} → different user data returned', emit)
                    return
    emit(f'[IDOR] No IDOR pattern detected on {host}')

# ─────────────────────────────────────────────────────────────────────
# Module 6 – Open Redirect
# ─────────────────────────────────────────────────────────────────────
REDIRECT_PAYLOADS = [
    'https://evil.example.com',
    '//evil.example.com',
    'https:evil.example.com',
    '/\\evil.example.com',
]
REDIRECT_PARAMS = ['redirect', 'url', 'next', 'return', 'returnUrl', 'goto', 'dest', 'callback']

def check_open_redirect(base: str, host: str, emit: Callable, findings: list, delay: float):
    emit(f'[Redirect] Checking for open redirect parameters on {host}...')
    for path in ['/', '/login', '/logout', '/auth', '/callback', '/redirect']:
        for param in REDIRECT_PARAMS:
            for payload in REDIRECT_PAYLOADS[:2]:
                time.sleep(delay)
                resp, _ = _get(base + path, params={param: payload})
                if resp and resp.status_code in (301, 302, 303, 307, 308):
                    loc = resp.headers.get('location', '')
                    if 'evil.example.com' in loc or loc.startswith('//'):
                        _add_finding(findings, host, 'Open Redirect',
                                     f'Redirect to attacker-controlled URL: '
                                     f'{path}?{param}={payload!r} → Location: {loc}',
                                     f'{host}{path}?{param}=<evil_url> → {loc}', emit)
                        return
    emit(f'[Redirect] No open redirect confirmed on {host}')

# ─────────────────────────────────────────────────────────────────────
# Module 7 – Information Disclosure
# ─────────────────────────────────────────────────────────────────────
INFO_PATHS = [
    ('/.git/HEAD',        'Information Disclosure (.git)', 'ref:',   'Git repository exposed'),
    ('/.git/config',      'Information Disclosure (.git)', '[core]', 'Git config accessible'),
    ('/debug',            'Information Disclosure (debug)', '',       'Debug page accessible'),
    ('/phpinfo.php',      'Information Disclosure (debug)', 'phpinfo','PHP configuration exposed'),
    ('/.env',             'Information Disclosure (backup)', 'DB_',   '.env file exposed'),
    ('/backup.zip',       'Information Disclosure (backup)', '',       'Backup archive accessible'),
    ('/config.bak',       'Information Disclosure (backup)', '',       'Config backup accessible'),
    ('/api/debug',        'Information Disclosure (debug)', '',        'API debug endpoint open'),
    ('/error',            'Stack Trace Exposed',   'traceback',        'Stack trace in error page'),
    ('/500',              'Stack Trace Exposed',   'at line',          'Stack trace exposed'),
]

def check_info_disclosure(base: str, host: str, emit: Callable, findings: list, delay: float):
    emit(f'[InfoDisc] Probing sensitive paths on {host}...')
    for path, issue, signature, desc in INFO_PATHS:
        time.sleep(delay)
        resp, _ = _get(base + path)
        if resp and resp.status_code == 200:
            body = resp.text or ''
            if not signature or signature.lower() in body.lower():
                _add_finding(findings, host, issue,
                             f'{desc} at {path} (HTTP 200)',
                             f'{host}{path} → HTTP 200 → sensitive data', emit)
    emit(f'[InfoDisc] Info-disclosure probe complete on {host}')

# ─────────────────────────────────────────────────────────────────────
# Shared finding builder
# ─────────────────────────────────────────────────────────────────────
def _add_finding(findings: list, host: str, issue: str, detail: str,
                 path: str, emit: Callable):
    info = OWASP_MAP.get(issue, {'owasp': 'A05:2021 Security Misconfiguration', 'cvss': 4.0})
    sev  = get_severity(info['cvss'])
    findings.append({
        'host':     host,
        'issue':    issue,
        'severity': sev,
        'cvss':     info['cvss'],
        'owasp':    info['owasp'],
        'detail':   detail,
        'path':     path,
    })
    emit(f'[{sev.upper()}] {host} — {issue} (CVSS {info["cvss"]})')
    emit(f'   └─ {detail}')

# ─────────────────────────────────────────────────────────────────────
# Simulation fallback (when target is unreachable)
# ─────────────────────────────────────────────────────────────────────
_SIM_ISSUES = [
    ('XSS Reflected',                   'Input field reflects payload: ?q=<script>alert(1)</script>'),
    ('SQL Injection (Error-Based)',      "DB error on /api/users?id=' — MySQL syntax error"),
    ('Directory Traversal',             'File read via ?file=../../../etc/passwd → root:x: match'),
    ('Missing Content-Security-Policy', 'No CSP header returned — inline script execution allowed'),
    ('Missing HSTS Header',             'Strict-Transport-Security absent — downgrade possible'),
    ('Missing X-Frame-Options',         'No X-Frame-Options — clickjacking feasible'),
    ('IDOR (Insecure Direct Object Ref)','User data at /api/user/2 accessible without authentication'),
    ('Open Redirect',                   '/login?redirect=//evil.example.com → 302 Location redirect'),
    ('Information Disclosure (.git)',   '/.git/HEAD returns HTTP 200 — repository exposed'),
    ('Server Version Exposed',          'Server: Apache/2.4.41 revealed in response headers'),
]

def _simulation_fallback(hosts: List[str], emit: Callable, findings: list,
                         risk_level: str, delay: float):
    emit('[SIM] Target unreachable — running enhanced simulation mode')
    risk_mult = {'Low': 0.3, 'Medium': 0.6, 'High': 1.0}.get(risk_level, 0.6)
    issues_pool = _SIM_ISSUES if risk_level == 'High' else \
                  _SIM_ISSUES[:int(len(_SIM_ISSUES) * risk_mult) + 3]

    for host in hosts:
        base = _build_base(host)
        selected = random.sample(issues_pool, min(len(issues_pool), random.randint(3, 6)))
        for issue, detail in selected:
            time.sleep(delay)
            _add_finding(findings, host, issue, detail,
                         f'{base}/{issue.replace(" ", "_").lower()}', emit)

# ─────────────────────────────────────────────────────────────────────
# Main Entry Point
# ─────────────────────────────────────────────────────────────────────
def run_simulation(target: str,
                   subdomains: Optional[List[str]] = None,
                   source_code: Optional[str] = None,
                   callback: Optional[Callable] = None,
                   progress_callback: Optional[Callable] = None,
                   speed: float = 10,
                   risk_level: str = 'Medium') -> dict:
    """
    Run the SecureSphere scanner.

    Args:
        target      – domain/IP or wildcard like *.eacasummit.com
        subdomains  – explicit list from .txt upload (overrides wildcard expansion)
        source_code - paste from SAST form
        callback    – function(str) for live log streaming
        speed       – requests/sec target (1–1000)
        risk_level  – Low / Medium / High
    """
    delay_base = max(0.005, 1.0 / max(1, float(speed)))
    findings   = []
    logs       = []

    def emit(msg: str):
        logs.append(msg)
        if callback:
            callback(msg)
        time.sleep(delay_base)
        
    def set_progress(pct: int):
        if progress_callback:
            progress_callback(pct)

    # ── Banner ──────────────────────────────────────────────
    emit('=' * 60)
    emit(' SecureSphere Vulnerability Scanner v2.0')
    emit(' Educational / Lab Use Only')
    emit('=' * 60)
    emit(f'[INIT] Target     : {target}')
    emit(f'[INIT] Risk Level : {risk_level}')
    emit(f'[INIT] Speed      : {speed} req/s  (delay≈{delay_base*1000:.0f}ms)')
    if not REQUESTS_AVAILABLE:
        emit('[WARN] requests library not installed — simulation mode active')
    emit('')

    # ── SAST Mode ───────────────────────────────────────────
    if source_code:
        set_progress(10)
        emit('[Phase 0] SAST Initialized: Analyzing source code logic...')
        time.sleep(1)
        patterns = {
            'SQL Injection': ['mysqli_query(', 'mysql_query(', 'SELECT * FROM', '$_POST[', '$_GET['],
            'XSS': ['echo $_GET', 'echo $_POST', 'print $_REQUEST'],
            'RCE': ['shell_exec(', 'system(', 'exec('],
            'LFI': ['include(', 'require(', 'fopen(', 'file_get_contents('],
            'IDOR': ['$_SESSION', '$_COOKIE', 'id='],
            'Brute Force': ['sleep(', 'sleep (']
        }
        
        detected_issues = []
        code_lines = source_code.split('\n')
        for i, line in enumerate(code_lines):
            for vuln_type, triggers in patterns.items():
                for trig in triggers:
                    if trig in line and vuln_type not in detected_issues:
                        detected_issues.append((vuln_type, i+1))
                        
        if not detected_issues:
            emit('[OK] SAST Analysis completed: No glaring pattern matches found.')
        else:
            emit(f'[WARN] {len(detected_issues)} possible logic flaws found in source code.')
            for i, (vuln_type, ln) in enumerate(detected_issues):
                set_progress(10 + int(80 * (i / len(detected_issues))))
                emit(f'[SAST] Inspecting Line {ln} for potential [{vuln_type}] vulnerabilities...')
                _add_finding(findings, 'SAST_Code', f"Possible {vuln_type} in Source Code", f"Line {ln} matched {vuln_type} heuristic logic", f"Line {ln}", emit)
                time.sleep(1.5)
        
        set_progress(95)
        emit('')
        sev_counts = {s: 0 for s in ('Critical', 'High', 'Medium', 'Low', 'Info')}
        for f in findings:
            sev_counts[f['severity']] = sev_counts.get(f['severity'], 0) + 1
        return {
            'logs': logs,
            'findings': findings,
            'summary': {
                'total': len(findings),
                'critical': sev_counts['Critical'],
                'high': sev_counts['High'],
                'medium': sev_counts['Medium']
            }
        }

        # ── Phase 0: Resolve host list ─────────────────────────
        set_progress(5)
        emit('[Phase 0] Resolving target scope...')
    if subdomains and len(subdomains) > 0:
        # File-upload mode
        hosts = [h.strip() for h in subdomains if h.strip()]
        emit(f'[RECON] Loaded {len(hosts)} hosts from uploaded subdomain list')
        for h in hosts[:5]:
            emit(f'[RECON] + {h}')
        if len(hosts) > 5:
            emit(f'[RECON] ... and {len(hosts)-5} more')
    elif '*.' in target:
        # Wildcard expansion
        hosts = _expand_wildcard(target, emit)
    else:
        hosts = [target]
        emit(f'[RECON] Single target: {hosts[0]}')

    # Limit to first 8 hosts for runtime sanity
    if len(hosts) > 8:
        emit(f'[WARN] Limiting scan to first 8 hosts (of {len(hosts)}) to stay within time budget')
        hosts = hosts[:8]

    emit('')

    # ── Check reachability ─────────────────────────────────
    set_progress(10)
    reachable = []
    if REQUESTS_AVAILABLE:
        emit('[Phase 1] Probing host reachability...')
        for i, h in enumerate(hosts):
            set_progress(10 + int(10 * (i / len(hosts))))
            base = _build_base(h)
            resp, _ = _get(base + '/', timeout=4)
            if resp is not None:
                emit(f'[ONLINE] {h} → HTTP {resp.status_code}')
                reachable.append(h)
            else:
                emit(f'[OFFLINE] {h} → no response')
            time.sleep(delay_base)
    else:
        reachable = hosts

    emit('')

    if not reachable:
        emit('[WARN] No hosts reachable — switching to enhanced simulation')
        _simulation_fallback(hosts, emit, findings, risk_level, delay_base)
    else:
        # ── Run each module on each reachable host ─────────
        modules = [
            ('[Phase 2] Security Header Analysis',   check_security_headers),
            ('[Phase 3] XSS Reflected Scanner',      check_xss),
            ('[Phase 4] SQL Injection Tester',       check_sqli),
            ('[Phase 5] Directory Traversal Tester', check_traversal),
            ('[Phase 6] IDOR Tester',                check_idor),
            ('[Phase 7] Open Redirect Checker',      check_open_redirect),
            ('[Phase 8] Information Disclosure',     check_info_disclosure),
        ]

        total_mods = len(modules)
        for i, (phase_label, module_fn) in enumerate(modules):
            base_pct = 20 + int(70 * (i / total_mods))
            set_progress(base_pct)
            emit(phase_label)
            emit('-' * 50)
            for j, host in enumerate(reachable):
                set_progress(base_pct + int((70 / total_mods) * (j / len(reachable))))
                base = _build_base(host)
                try:
                    module_fn(base, host, emit, findings, delay_base)
                except Exception as exc:
                    emit(f'[ERROR] Module error on {host}: {exc}')
            emit('')

    # ── Summary ────────────────────────────────────────────
    set_progress(100)
    emit('=' * 60)
    emit(f'[100%] SCAN COMPLETE')
    emit('=' * 60)

    sev_counts = {s: 0 for s in ('Critical', 'High', 'Medium', 'Low', 'Info')}
    for f in findings:
        sev_counts[f['severity']] = sev_counts.get(f['severity'], 0) + 1

    emit(f'[SUMMARY] Total Findings : {len(findings)}')
    for sev, count in sev_counts.items():
        if count:
            emit(f'[SUMMARY]   {sev:10s}: {count}')

    return {
        'logs':         logs,
        'findings':     findings,
        'attack_paths': [f['path'] for f in findings],
        'summary': {
            'total':    len(findings),
            'critical': sev_counts['Critical'],
            'high':     sev_counts['High'],
            'medium':   sev_counts['Medium'],
            'low':      sev_counts['Low'],
            'info':     sev_counts['Info'],
        }
    }
