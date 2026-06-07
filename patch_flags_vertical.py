with open('app.py', 'r') as f:
    app_code = f.read()

# The vertical SQLi data
vertical_sqli_data = """\n[+] DATABASE DUMP SUCCESSFUL
==============================
First Name     : Abebe
Last Name      : Kebede
Email          : abebe.k@aau.edu.et
Password Hash  : passwd_abebe_99
Age            : 45
Living Area    : Addis Ababa (Bole)
Phone Number   : +251911234567
Bank Account # : 1000112233445
Balance        : 125500.75 ETB
=============================="""

# 1. Update SQLi flags in Python code (replace previous flag)
app_code = app_code.replace(
    "flag = 'AAU{sqli_exploited} | DATA EXTRACTED: First=Abebe, Last=Kebede, Email=abebe.k@aau.edu.et, Pass=passwd_abebe_99, Age=45, Area=Addis Ababa (Bole), Phone=+251911234567, Account=1000112233445, Balance=125500.75 ETB'",
    f"flag = 'AAU{{sqli_exploited}}' + '''{vertical_sqli_data}'''"
)

app_code = app_code.replace(
    "flag = 'AAU{sqli_medium_exploited} | DATA EXTRACTED: First=Abebe, Last=Kebede, Email=abebe.k@aau.edu.et, Pass=passwd_abebe_99, Age=45, Area=Addis Ababa (Bole), Phone=+251911234567, Account=1000112233445, Balance=125500.75 ETB'",
    f"flag = 'AAU{{sqli_medium_exploited}}' + '''{vertical_sqli_data}'''"
)

app_code = app_code.replace(
    "flag = 'AAU{sqli_high_success} | DATA EXTRACTED: First=Abebe, Last=Kebede, Email=abebe.k@aau.edu.et, Pass=passwd_abebe_99, Age=45, Area=Addis Ababa (Bole), Phone=+251911234567, Account=1000112233445, Balance=125500.75 ETB'",
    f"flag = 'AAU{{sqli_high_success}}' + '''{vertical_sqli_data}'''"
)

# 2. Update SSTI flag to contain real-world server data
vertical_ssti_data = """\n[+] SERVER SECRETS EXTRACTED
==============================
/etc/passwd:
root:x:0:0:root:/root:/bin/bash
threatmapper:x:1001:1001::/home/threatmapper:/bin/bash

# aau_database_creds.txt
DB_HOST=127.0.0.1
DB_PORT=5432
DB_USER=aau_admin_root
DB_PASS=Sup3rS3cr3t_Ethi0pia_2026!
DB_NAME=aau_student_records_db

# AAU_OVERRIDE_AUTH
TOKEN=AAU_OVERRIDE_TOKEN_9901X_ETH_2026
=============================="""

app_code = app_code.replace(
    "flag = 'AAU{congratulations_you_exploited_ssti}'",
    f"flag = 'AAU{{congratulations_you_exploited_ssti}}' + '''{vertical_ssti_data}'''"
)

with open('app.py', 'w') as f:
    f.write(app_code)

print("Updated app.py with vertical dumps successfully.")
