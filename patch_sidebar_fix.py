import glob
for f in glob.glob("templates/lab_*.html") + ['templates/admin_logs.html', 'templates/private_info.html']:
    with open(f, 'r') as file:
        content = file.read()
    
    content = content.replace("body {\n      padding-left: 250px !important; \n    }", "body {\n      padding-left: 250px !important; \n      box-sizing: border-box !important;\n      width: 100vw !important;\n      overflow-x: hidden;\n    }")
    
    with open(f, 'w') as file:
        file.write(content)
