import glob
import re

css = """
    .nav-links {
      display: flex;
      gap: 24px;
      align-items: center;
    }
    .dropdown {
      position: relative;
      display: inline-block;
      height: 100%;
    }
    .dropdown-content {
      display: none;
      position: absolute;
      right: 0;
      top: 100%;
      background-color: rgba(5, 5, 16, 0.98);
      backdrop-filter: blur(10px);
      min-width: 180px;
      box-shadow: 0px 8px 32px rgba(0,0,0,0.8);
      border: 1px solid rgba(0,255,136,0.3);
      border-radius: 8px;
      z-index: 1000;
      overflow: hidden;
      margin-top: 10px;
    }
    .dropdown::after {
      /* invisible area to bridge gap */
      content: '';
      position: absolute;
      top: 100%;
      left: 0;
      width: 100%;
      height: 10px;
    }
    .dropdown-content a {
      color: #eee !important;
      padding: 14px 18px !important;
      text-decoration: none !important;
      display: block !important;
      font-size: 14px !important;
      border-bottom: 1px solid rgba(255,255,255,0.05);
      transition: all 0.3s !important;
    }
    .dropdown-content a:hover {
      background-color: rgba(0,255,136,0.15) !important;
      color: #00ffcc !important;
      padding-left: 24px !important;
    }
    .dropdown:hover .dropdown-content {
      display: block;
    }
"""

nav_html = """
  <nav>
    <div class="brand">ThreatMapper Labs</div>
    <div class="nav-links">
      <a href="/dashboard">📊 Dashboard</a>
      <a href="/reports">📋 Reports</a>
      <a href="/dashboard">🔍 Scan Engine</a>
      <div class="dropdown">
        <a href="javascript:void(0)" class="dropdown-toggle" style="cursor:default;">🔒 Lab Modules ▾</a>
        <div class="dropdown-content">
          <a href="/aau/threatmapper/aaulab/xss_low">Reflected XSS</a>
          <a href="/aau/threatmapper/aaulab/sqli/low">SQL Injection</a>
          <a href="/aau/threatmapper/aaulab/ssti/low">SSTI</a>
          <a href="/aau/threatmapper/aaulab/idor/low">IDOR</a>
          <a href="/aau/threatmapper/aaulab/jwt_low">JWT Attacks</a>
          <a href="/aau/threatmapper/aaulab/bruteforce/low">Brute Force</a>
        </div>
      </div>
    </div>
  </nav>
"""

count = 0
for f in glob.glob("templates/lab_*.html"):
    with open(f, 'r') as file:
        content = file.read()
    
    if 'class="nav-links"' in content:
        continue
        
    content = content.replace("</head>", css + "\n</head>")
    content = re.sub(r'<nav>.*?</nav>', nav_html.strip(), content, flags=re.DOTALL)
    
    with open(f, 'w') as file:
        file.write(content)
    count += 1
print(f"Patched {count} lab HTML files with navigation bar.")
