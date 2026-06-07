import re

new_nav = """<nav class="sidebar-nav">
                <div class="nav-section">
                    <div class="nav-section-title">Navigation</div>
                    <a href="/dashboard" class="nav-item">
                        <span class="icon">📊</span> Dashboard
                    </a>
                    <a href="/dashboard#scanPanel" class="nav-item">
                        <span class="icon">🔍</span> Scan Engine
                    </a>
                    <a href="/reports" class="nav-item">
                        <span class="icon">📋</span> Reports
                    </a>
                    <a href="/terminal" class="nav-item">
                        <span class="icon">💻</span> Terminal
                    </a>
                </div>
                <div class="nav-section">
                    <div class="nav-section-title">Administration</div>
                    <a href="/dashboard#usersPanel" class="nav-item">
                        <span class="icon">👥</span> User Management
                    </a>
                    <a href="/admin/logs" class="nav-item">
                        <span class="icon">📜</span> Security Event Log
                    </a>
                </div>
                <div class="nav-section">
                    <div class="nav-section-title">Training</div>
                    <a href="/dashboard#trainingPanel" class="nav-item">
                        <span class="icon">🔒</span> Lab Modules
                    </a>
                </div>
            </nav>"""

def patch_file(f, active_keyword):
    with open(f, 'r') as file:
        content = file.read()
    
    # Replace the existing sidebar-nav
    content = re.sub(r'<nav class="sidebar-nav">.*?</nav>', new_nav, content, flags=re.DOTALL)
    
    # Make the corresponding item active
    content = content.replace(f'<a href="/{active_keyword}" class="nav-item">', f'<a href="/{active_keyword}" class="nav-item active">')
    
    with open(f, 'w') as file:
        file.write(content)

patch_file('templates/reports.html', 'reports')
patch_file('templates/terminal.html', 'terminal')
print("Patched reports.html and terminal.html")
