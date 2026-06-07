import re

with open('app.py', 'r') as f:
    content = f.read()

# Replacement 1: The Table Schema
old_schema = """            CREATE TABLE users (
                id TEXT, 
                first_name TEXT, 
                last_name TEXT, 
                age INTEGER, 
                living_area TEXT, 
                account_number TEXT, 
                pin TEXT, 
                balance REAL
            )"""

new_schema = """            CREATE TABLE users (
                id TEXT, 
                first_name TEXT, 
                last_name TEXT, 
                email TEXT,
                password_hash TEXT,
                age INTEGER, 
                living_area TEXT,
                phone_number TEXT,
                account_number TEXT, 
                pin TEXT, 
                balance REAL
            )"""

content = content.replace(old_schema, new_schema)

old_schema_medium = old_schema.replace("id TEXT", "id INTEGER")
new_schema_medium = new_schema.replace("id TEXT", "id INTEGER")
content = content.replace(old_schema_medium, new_schema_medium)


# Replacement 2: The User Data
old_data = """        bank_users = [
            ('1', 'Abebe', 'Kebede', 45, 'Addis Ababa (Bole)', '1000112233445', '1234', 125500.75),
            ('2', 'Hermela', 'Tadesse', 28, 'Bahir Dar (Poly)', '1000556677889', '4455', 4520.00),
            ('3', 'Bikila', 'Desta', 34, 'Adama (Lugo)', '1000990011223', '0000', 890.30),
            ('4', 'Mastewal', 'Girma', 22, 'Gondar (Piassa)', '1000334455667', '7788', 23400.00),
            ('5', 'Dawit', 'Haile', 50, 'Hawassa (Tabor)', '1000778899001', '9901', 1050600.50),
            ('6', 'Selamawit', 'Berhe', 26, 'Mekelle (Kedamay)', '1000223344556', '2211', 1200.00),
            ('7', 'Tewodros', 'Kassa', 38, 'Dire Dawa (Kezira)', '1000889900112', '1921', 15700.45)
        ]
        c.executemany("INSERT INTO users VALUES (?,?,?,?,?,?,?,?)", bank_users)"""

new_data = """        bank_users = [
            ('1', 'Abebe', 'Kebede', 'abebe.k@aau.edu.et', 'passwd_abebe_99', 45, 'Addis Ababa (Bole)', '+251911234567', '1000112233445', '1234', 125500.75),
            ('2', 'Hermela', 'Tadesse', 'hermela.t@aau.edu.et', 'hermi_secure!2026', 28, 'Bahir Dar (Poly)', '+251912345678', '1000556677889', '4455', 4520.00),
            ('3', 'Bikila', 'Desta', 'bikila.d@aau.edu.et', 'run_bikila_run', 34, 'Adama (Lugo)', '+251913456789', '1000990011223', '0000', 890.30),
            ('4', 'Mastewal', 'Girma', 'masti.g@aau.edu.et', 'masti@admin_22', 22, 'Gondar (Piassa)', '+251914567890', '1000334455667', '7788', 23400.00),
            ('5', 'Dawit', 'Haile', 'dawit.h@aau.edu.et', 'boss_dawit_50', 50, 'Hawassa (Tabor)', '+251915678901', '1000778899001', '9901', 1050600.50),
            ('6', 'Selamawit', 'Berhe', 'selam.b@aau.edu.et', 'selam_peace_11', 26, 'Mekelle (Kedamay)', '+251916789012', '1000223344556', '2211', 1200.00),
            ('7', 'Tewodros', 'Kassa', 'teddy.k@aau.edu.et', 'teddy_bear_38', 38, 'Dire Dawa (Kezira)', '+251917890123', '1000889900112', '1921', 15700.45)
        ]
        c.executemany("INSERT INTO users VALUES (?,?,?,?,?,?,?,?,?,?,?)", bank_users)"""

content = content.replace(old_data, new_data)

old_data_medium = old_data.replace("'1'", "1").replace("'2'", "2").replace("'3'", "3").replace("'4'", "4").replace("'5'", "5").replace("'6'", "6").replace("'7'", "7")
new_data_medium = new_data.replace("'1'", "1").replace("'2'", "2").replace("'3'", "3").replace("'4'", "4").replace("'5'", "5").replace("'6'", "6").replace("'7'", "7")
content = content.replace(old_data_medium, new_data_medium)


# Replacement 3: The SELECT queries
content = content.replace(
    "SELECT first_name, last_name, age, living_area, account_number, balance FROM users WHERE id =",
    "SELECT first_name, last_name, email, password_hash, age, living_area, phone_number, account_number, balance FROM users WHERE id ="
)

with open('app.py', 'w') as f:
    f.write(content)

print("SQLi lab data patched successfully.")
