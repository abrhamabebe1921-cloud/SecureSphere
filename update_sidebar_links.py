import glob

html_files = glob.glob("templates/lab_*.html") + ['templates/admin_logs.html', 'templates/private_info.html']
for f in html_files:
    with open(f, 'r') as file:
        content = file.read()
    
    # Replace the generic /dashboard link for those two menus
    content = content.replace('<a href="/dashboard"><span>👥</span> User Management</a>', '<a href="/dashboard#usersPanel"><span>👥</span> User Management</a>')
    content = content.replace('<a href="/dashboard"><span>🔒</span> Lab Modules</a>', '<a href="/dashboard#trainingPanel"><span>🔒</span> Lab Modules</a>')
    
    with open(f, 'w') as file:
        file.write(content)
