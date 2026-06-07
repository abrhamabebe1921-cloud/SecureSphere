with open('app.py', 'r') as f:
    app_code = f.read()

app_code = app_code.replace(
    "flag = 'AAU{congratulations_you_exploited_sqli}'",
    "flag = 'AAU{sqli_exploited} | DATA EXTRACTED: First=Abebe, Last=Kebede, Email=abebe.k@aau.edu.et, Pass=passwd_abebe_99, Age=45, Area=Addis Ababa (Bole), Phone=+251911234567, Account=1000112233445, Balance=125500.75 ETB'"
)

app_code = app_code.replace(
    "flag = 'AAU{medium_level_sqli_exploited}'",
    "flag = 'AAU{sqli_medium_exploited} | DATA EXTRACTED: First=Abebe, Last=Kebede, Email=abebe.k@aau.edu.et, Pass=passwd_abebe_99, Age=45, Area=Addis Ababa (Bole), Phone=+251911234567, Account=1000112233445, Balance=125500.75 ETB'"
)

app_code = app_code.replace(
    "flag = 'AAU{high_level_sqli_success}'",
    "flag = 'AAU{sqli_high_success} | DATA EXTRACTED: First=Abebe, Last=Kebede, Email=abebe.k@aau.edu.et, Pass=passwd_abebe_99, Age=45, Area=Addis Ababa (Bole), Phone=+251911234567, Account=1000112233445, Balance=125500.75 ETB'"
)

app_code = app_code.replace(
    "if not found and re.search(r'(or|--|;|\\s)', user_id, re.IGNORECASE):",
    "if len(results) > 1 or (not found and re.search(r'(or|--|;|\\s)', user_id, re.IGNORECASE)):"
)

app_code = app_code.replace(
    "if not found and re.search(r'(or|--|;|\\s)', raw_user_id, re.IGNORECASE):",
    "if len(results) > 1 or (not found and re.search(r'(or|--|;|\\s)', raw_user_id, re.IGNORECASE)):"
)

app_code = app_code.replace(
    "if not found and re.search(r'(\\'|--|;|\\s|or|and)', user_id, re.IGNORECASE):",
    "if len(results) > 1 or (not found and re.search(r'(\\'|--|;|\\s|or|and)', user_id, re.IGNORECASE)):"
)

with open('app.py', 'w') as f:
    f.write(app_code)

