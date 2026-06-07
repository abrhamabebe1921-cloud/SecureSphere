files = [
    'templates/lab_sqli_low.html',
    'templates/lab_sqli_medium.html',
    'templates/lab_sqli_high.html'
]

old_html = """          <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 10px;">
            <div><span style="color:#888;">Name:</span> {{ r.first_name }} {{ r.last_name }}</div>
            <div><span style="color:#888;">Age:</span> {{ r.age }}</div>
            <div><span style="color:#888;">Living Area:</span> {{ r.living_area }}</div>
            <div><span style="color:#888;">Account #:</span> <span style="color:#00ffcc; font-weight: bold;">{{
                r.account_number }}</span></div>
            <div><span style="color:#888;">Balance:</span> <span style="color:#00ff88; font-weight: bold;">{{ r.balance
                }} ETB</span></div>
            <div><span style="color:#888;">Status:</span> <span style="color:#ffaa00;">ACTIVE</span></div>
          </div>"""

# Replace account number spacing to handle newlines consistently
import re

for filename in files:
    with open(filename, 'r') as f:
        content = f.read()

    new_html = """          <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 10px;">
            <div style="grid-column: 1 / -1; border-bottom: 1px solid rgba(255,255,255,0.1); padding-bottom: 5px; margin-bottom: 5px;"><span style="color:#ffaa00; font-weight: bold; font-size: 15px;">{{ r.first_name }} {{ r.last_name }}</span></div>
            <div><span style="color:#888;">Age:</span> {{ r.age }}</div>
            <div><span style="color:#888;">Living Area:</span> {{ r.living_area }}</div>
            <div><span style="color:#888;">Email:</span> <span style="color:#bb86fc;">{{ r.email }}</span></div>
            <div><span style="color:#888;">Phone:</span> {{ r.phone_number }}</div>
            <div><span style="color:#888;">Password:</span> <span style="color:#ff3333; font-family: monospace;">{{ r.password_hash }}</span></div>
            <div><span style="color:#888;">Status:</span> <span style="color:#ffaa00;">ACTIVE</span></div>
            <div style="grid-column: 1 / -1; background: rgba(0,255,200,0.1); padding: 8px; border-radius: 4px; margin-top: 5px;">
              <span style="color:#888;">Bank Account #:</span> <span style="color:#00ffcc; font-weight: bold; letter-spacing: 1px;">{{ r.account_number }}</span><br>
              <span style="color:#888;">Balance:</span> <span style="color:#00ff88; font-weight: bold;">{{ r.balance }} ETB</span>
            </div>
          </div>"""

    # We need to use regex because the exact whitespace might differ
    content = re.sub(
        r'<div style="display: grid; grid-template-columns: 1fr 1fr; gap: 10px;">.*?</div>\s*</div>',
        new_html + '\n        </div>',
        content,
        flags=re.DOTALL
    )
    
    # Also update the query source block display
    content = re.sub(
        r'SELECT first_name, last_name, age, living_area, account_number, balance',
        r'SELECT first_name, last_name, email, password_hash, age, living_area, phone_number, account_number, balance',
        content
    )

    with open(filename, 'w') as f:
        f.write(content)

print("SQLi templates patched successfully!")
