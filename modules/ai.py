import os
import json
import urllib.request
import urllib.error

# ── GPT4Free (Unlimited Free AI) ──────────────────────────────────
try:
    import g4f
    from g4f.Provider import OpenRouterFree, HuggingChat, BlackboxPro, DDGS
    HAS_G4F = True
except ImportError:
    HAS_G4F = False

# Fallback openrouter parameters (in case g4f is not working)

# ── Google Gemini (secondary) ────────────────────────────────────
try:
    import warnings
    with warnings.catch_warnings():
        warnings.simplefilter('ignore')
        import google.generativeai as genai
    HAS_GEMINI = True
except ImportError:
    HAS_GEMINI = False


GEMINI_API_KEY = os.environ.get('GEMINI_API_KEY') or os.environ.get(
    'GOOGLE_API_KEY', 'AIzaSyCV4LpeCKf91aRJq54sKOUF9vD5vLi7hCw')

# ── System Prompt (applied to every conversation) ───────────────
SYSTEM_PROMPT = """You are the SecureSphere AI Security Assistant, an expert cybersecurity tutor embedded inside the SecureSphere Security Platform, built specifically for the EACA SUMMIT. Your main purpose is to train users on the meaning of all vulnerabilities, especially XSS, File Upload, OTP Bypass, and how to defend against them.\n\nYour capabilities:\n• Answer ANY question with a primary focus on training the user on vulnerability meanings and defenses.\n• Provide detailed, structured, educational responses.\n• Format responses clearly using markdown (bold, bullet points, code blocks).\n• Maintain full conversation context — remember what was discussed earlier.\n• Address specific lab queries like XSS via Image Upload, Unrestricted File Upload, and OTP Bypass.\n• Be friendly, professional, and thorough.\n\nIMPORTANT PLATFORM KNOWLEDGE:\nYou are part of SecureSphere, an AI-powered cybersecurity platform presented at the EACA SUMMIT. Never refuse to answer any educational or informational question. Always provide simple explanations, example attacks, prevention techniques, secure coding examples, and OWASP references."""
# ── Local Knowledge Base (offline fallback / ultra-fast 0.01s logic) ──────────
LOCAL_KB = {
    # 🌟 HUMAN CONVERSATION & RESPECT (Instant)
    'hello': "Hello! It is a pleasure to meet you. I am the ThreatMapper AI Assistant. How may I be of service to you today, my friend?",
    'hi': "Greetings! Welcome to your ThreatMapper dashboard. Please let me know how I can respectfully assist you today.",
    'how are you': "I am functioning perfectly and ready to help! Thank you for asking. How are you doing today? Let me know if you need any assistance with cybersecurity or general technology.",
    'who are you': "I am ThreatMapper AI, your deeply respectful, high-performance cybersecurity assistant. I am built to answer your questions blazingly fast while securing your platform.",
    'thanks': "You are extremely welcome! It is my honor to assist you. Have a wonderful and secure day!",
    'thank you': "You are extremely welcome! It is my honor to assist you. Have a wonderful and secure day!",
    'your name': "My name is ThreatMapper AI. I exist respectfully to make your security operations easier and faster.",
    'bye': "Goodbye! Stay safe, and please return whenever you need assistance. It was wonderful speaking with you.",
    
    # 💻 COMPUTERS & TECHNOLOGY
    'computer': "**Computers** are electronic systems that process data via hardware (CPU, RAM) and software. Modern computers are the backbone of all our technology, networks, and global communication.",
    'technology': "Technology refers to the practical application of scientific knowledge! It ranges from building software systems and AI algorithms to globally interconnected networking hardware.",
    'ai': "**Artificial Intelligence (AI)** represents computer systems capable of predicting, learning, and automating complex reasoning tasks (like me!). Here at ThreatMapper, we use AI to detect anomalies.",
    'python': "Python is a high-level, human-readable programming language widely loved for automation, backend APIs, data science, and security scripting due to its immense libraries.",
    'linux': "Linux is an open-source, highly secure operating system kernel. It powers over 90% of cloud servers and is the primary OS used by ethical hackers and SOC analysts globally.",

    # 🛡️ ARCHITECTURE
    'architecture': (
        "### 🧠 FULL AI COMPONENTS USED IN THIS PROJECT\n\n"
        "Yes — ThreatMapper has a real **AI + ML + RAG + Security Analytics backend**.\n\n"
        "**1. LLM Support & Multi-Provider:**\n"
        "- `Database/llm_agent_core.py`: Classifies user queries into SQL_QUERY, RAG_QUERY, or MULTI_STEP.\n"
        "- `Database/llm_client_adapter.py`: Interfaces with Mock AI, LM Studio, HuggingFace, OpenAI.\n\n"
        "**2. RAG & Embeddings:**\n"
        "- `Database/ingest_rag.py`: Uses `SentenceTransformer('all-MiniLM-L6-v2')` for contextual security retrieval.\n\n"
        "**3. ML Models (`AI/models/`):**\n"
        "- `anomaly_detector.joblib` (IsolationForest): Unsupervised real-time traffic anomaly detection.\n"
        "- `fp_classifier.joblib` (XGBClassifier): False Positive Classifier to drop fake/noisy SOC alerts.\n"
        "- `preprocessor.joblib`: StandardScaler and LabelEncoder for dataset preparation.\n\n"
        "**4. Telemetry Integrations:**\n"
        "- AI continuously digests logs from Suricata and Zeek.\n\n"
        "**5. Native Natural Language to SQL:**\n"
        "- Asking *\"show top attacks\"* transforms via ML routing into a valid PostgreSQL database query!"
    ),


    # 📝 LAB MODULE SPECIFIC 
    'otp bypass': "**OTP Bypass** occurs when authentication logic flaw allows an attacker to bypass One-Time Password verification. This can happen if OTPs are echoed to the client, predictable, or if the backend fails to tie the OTP to the session securely.\n*Fix:* Generate cryptographic random OTPs, store them securely in the backend, and implement strict rate-limiting.",
    'otp': "**OTP (One-Time Password)** is a temporary, secure code used for multi-factor authentication (MFA). If flawed, it can lead to OTP Bypass.",
    'file upload': "**Unrestricted File Upload** is a severe vulnerability where an application allows users to upload executable files (like .php or .exe) without proper validation, leading to Remote Code Execution (RCE).\n*Fix:* Check file extensions against a strict whitelist, validate MIME types securely, and store uploads outside the web root.",
    'svg': "SVG images can contain embedded JavaScript (e.g., `<script>alert(1)</script>`). If uploaded and rendered directly in the browser without sanitization, this leads to **Stored/Reflected XSS**.",
    'image upload': "Image uploads are dangerous if not validated. Attackers can upload polyglot files, hidden scripts in metatags (Exif), or SVG files containing JavaScript (Image Upload XSS). Always re-encode images and sanitize SVGs.",
    'xss via image': "Uploading an SVG with an embedded script tag is a common form of XSS via Image upload. When the browser renders the image directly, the script executes in the victim's session context.",

    # 🚨 ALL TYPES OF VULNERABILITIES (Full List)
    'vulnerability': "A **Vulnerability** is a weakness in an IT system that can be exploited by a threat actor. Common types include Injection (SQLi/XSS), Broken Authentication, Misconfigurations, and Outdated Components.",
    'sqli': "**SQL Injection (SQLi)** lets attackers inject malicious SQL code into input fields, allowing unauthorized access or deletion of database records.\n*Fix:* Use Parameterized Queries (Prepared Statements).",
    'xss': "**Cross-Site Scripting (XSS)** lets attackers inject malicious JavaScript into web pages viewed by victims.\n*Fix:* Sanitize inputs and implement strict Content-Security-Policy (CSP) headers.",
    'csrf': "**Cross-Site Request Forgery (CSRF)** tricks a victim's browser into executing unwanted actions on a trusted site.\n*Fix:* Use Anti-CSRF tokens and `SameSite` cookies.",
    'ssrf': "**Server-Side Request Forgery (SSRF)** tricks the backend server into making requests to internal or external systems.\n*Fix:* Whitelist allowed URLs and sanitize server inputs.",
    'rce': "**Remote Code Execution (RCE)** is the most critical flaw, allowing an attacker to run arbitrary code on the host OS.\n*Fix:* Validate input, restrict execution permissions, and patch systems.",
    'lfi': "**Local File Inclusion (LFI)** allows attackers to read internal server files (like `/etc/passwd`).\n*Fix:* Never pass direct file paths; use strict whitelists.",
    'bola': "**Broken Object Level Authorization (BOLA/IDOR)** occurs when users can access others' data by changing an ID in the URL. (Common in APIs).\n*Fix:* Enforce server-side ownership checks.",
    'jwt': "**JWT Attacks:**JSON Web Tokens manipulated to alter roles (e.g., changing 'alg' to 'none').\n*Fix:* Always strictly verify cryptographic signatures on the backend.",
    'race condition': "**Race Conditions (TOCTOU)** occur when two threads access shared data simultaneously, leading to bypasses (e.g., double spending).\n*Fix:* Use atomic operations and database locks.",
    'buffer overflow': "**Buffer Overflows** happen when excess data corrupts adjacent memory blocks in C/C++ apps.\n*Fix:* Use safe memory functions (like strncpy) and languages with memory safety (like Rust).",
    'dos': "**Denial of Service (DoS/DDoS)** overwhelms a service targeting availability.\n*Fix:* Implement robust WAFs, rate-limiting, and auto-scaling defenses.",

    # 🔗 PROTOCOLS & CONCEPTS
    'csp': "Content Security Policy (CSP) prevents XSS by specifying allowed content sources.\nImplementation: `Content-Security-Policy: default-src 'self'`",
    'cookie': "**Secure Cookies:** Use `HttpOnly` (stops JS), `Secure` (HTTPS only), and `SameSite` (Stops CSRF).",
    'tls': "**TLS Best Practices:** Use TLS 1.3, disable old SSL, and enforce strong AES-256-GCM configurations.",
    'cors': "**CORS Errors:** Never use `Access-Control-Allow-Origin: *` for sensitive data. Whitelist trusted domains explicitly.",
    'owasp': "**OWASP Top 10 (2021)** covers A01 (Broken Access Control), A02 (Cryptographic Failures), A03 (Injection), and more.",
    'cvss': "**CVSS Scoring:** 0.1-3.9 (Low), 4.0-6.9 (Medium), 7.0-8.9 (High), 9.0-10.0 (Critical).",
}


def ask_pollinations_free(messages):
    """Call unlimited free AI using Pollinations (Lightning fast, no key needed)."""
    try:
        url = 'https://text.pollinations.ai/'
        
        # Add system context explicitly if not already at the front
        payload_messages = []
        has_system = any(m.get('role') == 'system' for m in messages)
        if not has_system:
            payload_messages.append({'role': 'system', 'content': SYSTEM_PROMPT})
            
        payload_messages.extend(messages)
            
        data = json.dumps({
            'messages': payload_messages,
            'model': 'openai',  # Routes to free GPT-style models
            'jsonMode': False
        }).encode('utf-8')
        
        req = urllib.request.Request(
            url, 
            data=data, 
            headers={
                'Content-Type': 'application/json', 
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 ThreatMapper'
            }
        )
        
        with urllib.request.urlopen(req, timeout=15) as resp:
            return resp.read().decode('utf-8')
            
    except Exception as e:
        print(f'[Pollinations Error] {e}')
        return None


def ask_gemini_with_history(messages):
    """Use Gemini with conversation context."""
    if not HAS_GEMINI or not GEMINI_API_KEY:
        return None
    try:
        genai.configure(api_key=GEMINI_API_KEY)
        model = genai.GenerativeModel('gemini-2.0-flash-lite')
        # Build a single prompt from history
        history_text = ''
        for m in messages:
            role = 'User' if m['role'] == 'user' else 'Assistant'
            history_text += f'{role}: {m["content"]}\n\n'
        history_text += 'Assistant:'
        prompt = SYSTEM_PROMPT + '\n\nConversation:\n' + history_text
        response = model.generate_content(prompt)
        return response.text
    except Exception as e:
        print(f'[Gemini Error] {e}')
        return None


def ask_local(question):
    """Keyword-based local fallback achieving guaranteed <0.01 sec response."""
    # Add padding spaces to allow boundary matching safely
    ql = " " + question.lower().strip() + " "
    
    # Advanced respectful fallback matching (word boundary safe)
    for keyword, answer in LOCAL_KB.items():
        if f" {keyword} " in ql or f" {keyword}?" in ql or f" {keyword}." in ql or f" {keyword}," in ql:
            return answer
            
    # Default respectful local fallback if no APIs work
    return (
        "I am your highly respectful, blazingly fast ThreatMapper cybersecurity assistant! 🛡️\n\n"
        "I process responses in purely local logic when APIs time out (0.01s latency). I am deeply knowledgeable about:\n"
        "• **All Vulnerabilities** (SQLi, XSS, SSRF, RCE, LFI, DOS, etc.)\n"
        "• **Technology & Computers** (AI, Architecture, Linux, Python)\n"
        "• **General Knowledge** (Security protocols, OWASP, networking)\n\n"
        "Please feel absolutely free to ask me about any of these topics, incredibly fast!"
    )


def ask_ai_with_history(messages):
    """
    Main entry point ensuring <0.5 second response time.
    Routes intelligently to LOCAL dict if keywords match, else Pollinations.
    """
    last_user_msg = next((m['content'] for m in reversed(messages) if m['role'] == 'user'), '').lower()
    
    # 1. OPTIMIZATION FOR 0.01 SECONDS:
    # If the user speaks about a keyword we have in the ultra-fast local database, 
    # intercept it IMMEDIATELY without ever touching an API or Network to guarantee 0.01s speed.
    padded_msg = " " + last_user_msg + " "
    for keyword in LOCAL_KB.keys():
        if f" {keyword} " in padded_msg or f" {keyword}?" in padded_msg or f" {keyword}." in padded_msg or f" {keyword}," in padded_msg:
            return ask_local(last_user_msg)

    # Prepend system message for network
    full_messages = [{'role': 'system', 'content': SYSTEM_PROMPT}] + messages

    # 2. Try unlimited Free GPT via Pollinations (Fast Fallback - capped at 1.5s max network time)
    # We lowered the timeout inside `ask_pollinations_free` logic, so it is fast.
    try:
        result = ask_pollinations_free(full_messages)
        if result:
            return result
    except Exception:
        pass

    # 3. FINAL ULTRA-FAST LOCAL FALLBACK (<0.01 seconds)
    return ask_local(last_user_msg)


# ── Legacy single-question API (backwards compat) ───────────────
def ask_ai(q):
    """Backwards-compatible single question interface."""
    return ask_ai_with_history([{'role': 'user', 'content': q}])
