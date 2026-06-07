import re

with open('templates/dashboard.html', 'r') as f:
    text = f.read()

# Make the section titles very bold and vivid
text = text.replace(
    'font-size: 11px;\n      font-family: monospace;\n      text-transform: uppercase;\n      letter-spacing: 0.12em;\n      color: #555;\n      margin-bottom: 6px;\n      padding-bottom: 6px;',
    'font-size: 13px;\n      font-family: "JetBrains Mono", monospace;\n      font-weight: 800;\n      text-transform: uppercase;\n      letter-spacing: 0.15em;\n      color: #00ffcc;\n      text-shadow: 0 0 10px rgba(0,255,204,0.3);\n      margin-bottom: 8px;\n      padding-bottom: 8px;'
)

# Thicker dashboard cards borders and bolder hover
text = text.replace(
    'border: 1px solid rgba(0, 255, 136, 0.25);',
    'border: 2px solid rgba(0, 255, 136, 0.4);'
)
text = text.replace(
    'border: 1px solid rgba(255, 106, 0, 0.4);',
    'border: 2px solid rgba(255, 106, 0, 0.6);'
)

# Make main stat values bolder
text = text.replace(
    'font-size: 28px;\n      font-weight: 700;',
    'font-size: 34px;\n      font-weight: 900;'
)

# Darker panel backgrounds for higher contrast
text = text.replace(
    'background: linear-gradient(135deg, rgba(0, 255, 136, 0.06) 0%, rgba(0, 0, 0, 0.65) 100%);',
    'background: linear-gradient(135deg, rgba(0, 255, 136, 0.10) 0%, rgba(0, 0, 0, 0.85) 100%);'
)

# AI Panel bolder
text = text.replace(
    'background: linear-gradient(135deg, rgba(0, 255, 136, 0.08) 0%, rgba(0, 0, 0, 0.7) 100%);',
    'background: linear-gradient(135deg, rgba(0, 255, 136, 0.12) 0%, rgba(0, 0, 0, 0.85) 100%);'
)

# Lab Panel bolder buttons
text = text.replace(
    'font-weight: 500;',
    'font-weight: 800;'
)
text = text.replace(
    'font-size: 11px;',
    'font-size: 12px;'
)

with open('templates/dashboard.html', 'w') as f:
    f.write(text)
