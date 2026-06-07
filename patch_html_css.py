import re

files = [
    'templates/lab_sqli_low.html',
    'templates/lab_sqli_medium.html',
    'templates/lab_sqli_high.html',
    'templates/lab_ssti_low.html'
]

for filename in files:
    with open(filename, 'r') as f:
        html = f.read()

    # Find the .flag-output class and modify it
    # We'll use regex to overwrite text-align: center; with text-align: left;
    # and add white-space: pre-wrap;
    html = re.sub(
        r'text-align:\s*center;',
        'text-align: left;\n      white-space: pre-wrap;\n      font-family: monospace;\n      font-size: 14px;',
        html
    )

    with open(filename, 'w') as f:
        f.write(html)

print("HTML templates modified successfully for pre-wrap.")
