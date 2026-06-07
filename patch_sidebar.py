import glob
import re

css = """
  <!-- THE NEW SIDEBAR CSS -->
  <style>
    .lab-sidebar {
      position: fixed;
      left: 0;
      top: 0;
      bottom: 0;
      width: 250px;
      background: rgba(5, 5, 16, 0.95);
      backdrop-filter: blur(10px);
      border-right: 1px solid rgba(0,255,136,0.2);
      display: flex;
      flex-direction: column;
      padding: 20px 0;
      z-index: 9999;
      font-family: 'Inter', sans-serif;
    }
    .lab-sidebar .brand {
      font-size: 20px;
      font-weight: 800;
      color: #00ffcc;
      text-align: left;
      margin-bottom: 30px;
      padding: 0 24px;
      text-shadow: 0 0 10px rgba(0,255,136,0.3);
    }
    .lab-sidebar a {
      display: flex;
      align-items: center;
      gap: 12px;
      padding: 12px 24px;
      color: #bbb;
      text-decoration: none;
      font-size: 14px;
      font-weight: 500;
      transition: all 0.3s;
      box-sizing: border-box;
    }
    .lab-sidebar a:hover {
      background: rgba(0,255,136,0.1);
      color: #00ffcc;
      border-right: 3px solid #00ffcc;
    }
    .lab-sidebar .nav-section {
      margin-bottom: 24px;
    }
    .lab-sidebar .section-title {
      font-size: 11px;
      text-transform: uppercase;
      color: #666;
      padding: 0 24px;
      margin-bottom: 10px;
      letter-spacing: 1px;
    }
    /* Shift main content */
    body {
      padding-left: 250px !important; 
    }
    /* Hide the top nav from previous patch */
    body > nav { display: none !important; }
  </style>
"""

sidebar_html = """
  <div class="lab-sidebar">
    <div class="brand">THREATMAPPER</div>
    
    <div class="nav-section">
      <div class="section-title">Navigation</div>
      <a href="/dashboard"><span>📊</span> Dashboard</a>
      <a href="/dashboard#scanPanel"><span>🔍</span> Scan Engine</a>
      <a href="/reports"><span>📋</span> Reports</a>
      <a href="/terminal"><span>💻</span> Terminal</a>
    </div>
    
    <div class="nav-section">
      <div class="section-title">Administration</div>
      <a href="/dashboard"><span>👥</span> User Management</a>
      <a href="/admin/logs"><span>📜</span> Security Event Log</a>
    </div>
    
    <div class="nav-section">
      <div class="section-title">Training</div>
      <a href="/dashboard"><span>🔒</span> Lab Modules</a>
    </div>
  </div>
"""

count = 0
for f in glob.glob("templates/lab_*.html"):
    with open(f, 'r') as file:
        content = file.read()
    
    if 'class="lab-sidebar"' in content:
        continue
        
    content = content.replace("</head>", css + "\n</head>")
    content = content.replace("<body>", "<body>\n" + sidebar_html)
    
    with open(f, 'w') as file:
        file.write(content)
    count += 1
print(f"Patched {count} lab HTML files with sidebar.")
