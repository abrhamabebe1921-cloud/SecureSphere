# 🛡️ SecureSphere — EACA SUMMIT 2026 HACKATHON
### Cyber Security Education & Training Platform
**Version:** 2.0 | **Event:** EACA SUMMIT 2026 HACKATHON | **Stack:** Python · Flask · SQLite · HTML5 · JavaScript

---

## 📌 Overview

**SecureSphere** is a fully interactive, browser-based cybersecurity training platform purpose-built for the **EACA SUMMIT 2026 Hackathon**. It provides a realistic, controlled environment where participants practice identifying and exploiting common web application vulnerabilities across multiple difficulty levels. The platform features a cinematic hacker-themed UI, an AI assistant, a live vulnerability scanner, and a phishing-blocking browser extension.

---

## 🚀 Getting Started

### Prerequisites
- Python 3.10+
- pip (with virtualenv recommended)

### Launch
```bash
cd threatmapper
source venv/bin/activate       # activate virtual environment
python3 app.py                 # start the Flask server
```

Open your browser and navigate to:
```
http://127.0.0.1:5000
```

### Admin Login Credentials
| Field    | Value           |
|----------|-----------------|
| Email    | abc@gmail.com   |
| Password | 1234            |

---

## 🎯 Platform Features

### 1. 🔐 Secure Authentication System
- Email + password login with session management
- Email verification modal (OTP gate) before portal access
- Session-based authentication across all lab modules
- Admin vs User role distinction

### 2. 💻 Boot Sequence & Landing Page
- **Animated CMatrix rain** (Japanese katakana + Latin + digits) runs as the background on opening
- **EACA SUMMIT 2026 Logo** displayed prominently in medium size on boot
- **Progress bar** animates from 0% → 100% below the logo with live "Loading… X%" counter
- Boot sequence auto-completes and fades into the login portal
- Entire boot sequence is slowpaced for dramatic effect

### 3. 🧪 Security Lab Modules

| Lab | Difficulty | Vulnerability | Path |
|-----|-----------|---------------|------|
| Reflected XSS | Low | Cross-Site Scripting via `name` parameter | `/labs/xss_low` |
| Reflected XSS | Medium | XSS with basic sanitization | `/labs/xss_medium` |
| Reflected XSS | High | XSS with strict filtering | `/labs/xss_high` |
| OTP Bypass | Low | Authentication bypass via OTP manipulation | `/labs/otp_bypass_low` |
| File Upload | Low | Unrestricted file upload RCE | `/labs/file_upload_low` |
| Image XSS | Low | XSS via image metadata/filename | `/labs/image_xss_low` |
| JWT Attack | Low | Weak secret / none alg bypass | `/labs/jwt_low` |
| JWT Attack | Medium | RS256 → HS256 confusion | `/labs/jwt_medium` |
| JWT Attack | High | JWKS spoofing / kid injection | `/labs/jwt_high` |
| Brute Force | Low/Med/High | Credential brute-force attacks | `/labs/bruteforce/low` |
| SQL Injection | Low | Classic UNION-based SQLi | `/labs/sqli` |
| SSTI | Low | Server-Side Template Injection | `/labs/ssti` |

#### XSS Lab Users (Low Level)
| Username   | Password | Role  |
|------------|----------|-------|
| Abreham    | passwd1  | Admin |
| Tesfabesh  | passwd2  | User  |
| Natty      | passwd3  | User  |

### 4. 🤖 AI Security Assistant
- Built-in AI assistant accessible from the dashboard
- Knows the full XSS payload library (hundreds of HTML5 event-handler payloads across all tag types)
- Provides hints, payload suggestions, and exploitation guidance for all lab modules
- Ask it: *"Give me XSS payloads"* → it will supply crafted vectors from the trained payload knowledge base

### 5. 🔍 Vulnerability Scanner
- Target URL input with real-time scan engine
- Detects: XSS, SQLi, IDOR, CSRF, Open Redirect, CSP misconfigurations, Command Injection, Blind XSS, JWT weaknesses
- Circular animated progress indicator
- PDF-downloadable scan report

### 6. 🛡️ Phishing Detection Browser Extension

**SecureSphere Phishing Shield** is a Manifest V3 Chrome/Chromium extension that:

- **Warns** on the 1st visit to a suspected phishing URL (banner overlay injected into page)
- **Blocks** entirely on the 2nd visit (redirects to `blocked.html` warning page)
- Detects phishing via:
  - Keyword matching (obfuscated brand names: `payrna1`, `g00gle`, `arnazon`, etc.)
  - Regex patterns (suspicious TLDs, IP-based login pages, homograph attacks)
  - Heuristics (excessive hyphens, deep subdomains, suspicious query params)
- **Badge** on toolbar icon: `!` in red (HIGH) or orange (MEDIUM) for flagged tabs
- Popup shows blocked URL log history

#### How to Install the Extension
1. Open Chrome/Chromium → go to `chrome://extensions/`
2. Enable **Developer Mode** (top-right toggle)
3. Click **"Load unpacked"** → select the `browser_extension/` folder
   _OR_ drag-and-drop `SecureSphere_Phishing_Shield.zip`
4. The 🛡️ shield icon appears in the toolbar — active immediately

**Extension location:** `browser_extension/SecureSphere_Phishing_Shield.zip`

---

## 🗂️ Project Structure

```
project2/
├── browser_extension/              # Phishing Shield Chrome Extension
│   ├── manifest.json               # Extension config (Manifest V3)
│   ├── background.js               # Service worker — detection engine
│   ├── content.js                  # Page overlay injector (warning banner)
│   ├── blocked.html                # Full-block warning redirect page
│   ├── popup.html                  # Extension popup UI + log viewer
│   ├── icons/                      # Extension icons (16/48/128px)
│   └── SecureSphere_Phishing_Shield.zip  ← Load this in Chrome
│
├── threatmapper/                   # Main Flask Application
│   ├── app.py                      # All routes & backend lab logic
│   ├── database.py                 # DB init, schema, user seeding
│   ├── sqli_helper.py              # SQLi lab database helper
│   ├── xss_payloads.txt            # AI payload knowledge base (500+ vectors)
│   ├── templates/                  # All HTML pages
│   │   ├── login.html              # Boot screen + login portal
│   │   ├── dashboard.html          # Main dashboard (scanner + AI + labs)
│   │   ├── lab_xss_low.html        # XSS Lab UI
│   │   ├── lab_otp_bypass_low.html # OTP Bypass Lab UI
│   │   ├── lab_file_upload_low.html# File Upload Lab UI
│   │   └── ...                     # Other lab templates
│   ├── static/                     # CSS, JS, images
│   ├── modules/                    # Modular lab helpers
│   ├── venv/                       # Python virtual environment
│   └── threatmapper.db             # SQLite database
│
└── vulnerabilities/                # Reference vulnerability scripts
    ├── xss_r/                      # XSS reference payloads
    └── jwt-attacks/                # JWT attack scripts
```

---

## 🔑 XSS Payload Knowledge Base

The AI assistant is trained on a comprehensive library of **HTML5 event-handler XSS payloads** covering:
- All standard HTML tags (`<a>`, `<audio>`, `<button>`, `<canvas>`, `<body>`, etc.)
- Exotic/deprecated tags (`<blink>`, `<marquee>`, `<applet>`, `<acronym>`)
- SVG & animation tags (`<animate>`, `<animatemotion>`, `<animatetransform>`)
- All event handlers: `onfocus`, `onmouseover`, `ondrag`, `onpointerdown`, `onwebkitmouseforce*`, `onbeforetoggle`, `oncontentvisibilityautostatechange`, and many more

**Quick examples:**
```html
<a autofocus onfocus=alert(1) href></a>
<img src=x onerror=alert(1)>
<body onload=alert(1)>
<svg/onload=alert(1)>
<button popovertarget=x>Click<div id=x onbeforetoggle=alert(1) popover>XSS</div>
```

---

## 🏆 EACA SUMMIT 2026 HACKATHON

**Event:** EACA SUMMIT 2026 | Cyber Security Hackathon Track  
**Platform:** SecureSphere v2.0  
**Purpose:** Hands-on offensive security training & CTF-style lab challenges  
**Participants:** Practice real-world attacks in a safe, isolated environment  

Good luck to all participants! 🔐
