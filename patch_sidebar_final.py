import glob
import re

css = """
  <!-- FINAL SIDEBAR CSS -->
  <style>
    /* Toggle Icon */
    #sidebarToggleBtn {
      position: fixed;
      top: 15px;
      left: 15px;
      z-index: 10001;
      background: rgba(0, 0, 0, 0.7);
      border: 1px solid rgba(0,255,136,0.3);
      color: #00ffcc;
      font-size: 24px;
      width: 40px;
      height: 40px;
      border-radius: 8px;
      cursor: pointer;
      display: flex;
      align-items: center;
      justify-content: center;
      box-shadow: 0 0 10px rgba(0,255,136,0.2);
    }
    #sidebarToggleBtn:hover {
      background: rgba(0,255,136,0.2);
    }

    .lab-sidebar {
      position: fixed;
      left: 0;
      top: 0;
      bottom: 0;
      width: 250px;
      background: rgba(5, 5, 16, 0.98);
      backdrop-filter: blur(14px);
      border-right: 1px solid rgba(0,255,136,0.2);
      display: flex;
      flex-direction: column;
      padding: 0; /* Changed to allow header spacing */
      z-index: 9999;
      font-family: 'Inter', sans-serif;
      transition: transform 0.3s ease-in-out;
      transform: translateX(0); /* Opened by default */
      overflow-y: auto;
    }
    .lab-sidebar.collapsed {
      transform: translateX(-100%);
    }

    .lab-sidebar .brand {
      font-size: 20px;
      font-weight: 800;
      color: #00ffcc;
      text-align: left;
      margin: 25px 0 30px 0;
      padding: 0 24px 0 70px;
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
    
    /* Footer for user profile */
    .lab-sidebar-footer {
      margin-top: auto;
      padding: 15px;
      border-top: 1px solid rgba(255,255,255,0.1);
    }
    .user-info {
      display: flex;
      align-items: center;
      gap: 12px;
      padding: 10px;
      border-radius: 8px;
      background: rgba(255,255,255,0.05);
      margin-bottom: 10px;
    }
    .user-avatar {
      width: 36px;
      height: 36px;
      border-radius: 50%;
      background: linear-gradient(135deg, #00ff88, #00ccff);
      display: flex;
      align-items: center;
      justify-content: center;
      color: #000;
      font-weight: bold;
      font-size: 16px;
    }
    .user-details {
      display: flex;
      flex-direction: column;
    }
    .user-details .name {
      color: #fff;
      font-weight: bold;
      font-size: 13px;
    }
    .user-details .role {
      color: #00ffcc;
      font-size: 11px;
      text-transform: uppercase;
      letter-spacing: 1px;
      margin-top: 2px;
    }

    /* Shift main content dynamically */
    body {
      transition: padding-left 0.3s ease-in-out;
      padding-left: 250px !important; 
    }
    body.sidebar-collapsed {
      padding-left: 0 !important;
    }
  </style>
"""

js_code = """
  <script>
    function toggleLabSidebar() {
      const sidebar = document.querySelector('.lab-sidebar');
      const body = document.body;
      sidebar.classList.toggle('collapsed');
      body.classList.toggle('sidebar-collapsed');
    }
  </script>
"""

sidebar_html = """
  <button id="sidebarToggleBtn" onclick="toggleLabSidebar()">☰</button>
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
      <a href="/dashboard#usersPanel"><span>👥</span> User Management</a>
      <a href="/admin/logs"><span>📜</span> Security Event Log</a>
    </div>
    
    <div class="nav-section">
      <div class="section-title">Training</div>
      <a href="/dashboard#trainingPanel"><span>🔒</span> Lab Modules</a>
    </div>

    <!-- User Profile Footer -->
    <div class="lab-sidebar-footer">
      <div class="user-info">
        <div class="user-avatar">{{ username[0]|upper if username else '?' }}</div>
        <div class="user-details">
          <div class="name">{{ username if username else 'Unknown' }}</div>
          <div class="role">{{ role if role else 'Guest' }}</div>
        </div>
      </div>
      <a href="/logout" style="width:100%; text-align:center; display:block; padding:8px; background:rgba(255,255,255,0.1); border-radius:6px; font-weight:bold; color:#ff3b3b; justify-content:center;">🚪 Logout</a>
    </div>
  </div>
"""

html_files = glob.glob("templates/lab_*.html") + ['templates/admin_logs.html', 'templates/private_info.html']

for f in html_files:
    with open(f, 'r') as file:
        content = file.read()
    
    # Clean previous injected lab-sidebar css and html
    content = re.sub(r'<!-- THE NEW SIDEBAR CSS -->.*?</style>', '', content, flags=re.DOTALL)
    content = re.sub(r'<div class="lab-sidebar">.*?</div>\s*</div>\s*</div>\s*</div>', '', content, flags=re.DOTALL) # weak regex, let's just use strict replace
    # Actually wait, let's just do a clean replace using simpler boundaries
