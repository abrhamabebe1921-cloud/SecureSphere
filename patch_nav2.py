import glob

html_files = glob.glob("templates/lab_*.html")
for f in html_files:
    with open(f, 'r') as file:
        content = file.read()
    content = content.replace('<a href="/dashboard">🔍 Scan Engine</a>', '<a href="/dashboard#scanPanel">🔍 Scan Engine</a>')
    with open(f, 'w') as file:
        file.write(content)
