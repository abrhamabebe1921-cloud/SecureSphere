import re

with open('app.py', 'r') as f:
    text = f.read()

# Make the database creation general for SQLi 
DB_CREATE = """
        c.execute("CREATE TABLE users (user_id TEXT, name TEXT, age TEXT, email TEXT, mobile TEXT, atm_pass TEXT, bank_acc TEXT, amount TEXT)")
        c.execute("INSERT INTO users VALUES ('1', 'admin', 'admin', 'admin@aau.edu.et', '0900000000', '0000', '1000000000000', '9999999')")
        c.execute("INSERT INTO users VALUES ('2', 'Gordon Brown', '34', 'gordon@gmail.com', '0922222222', '1234', '1000022222222', '500')")
        c.execute("INSERT INTO users VALUES ('3', 'Hack Me', '21', 'hackme@gmail.com', '0933333333', '1337', '1000033333333', '10')")
        c.execute("INSERT INTO users VALUES ('4', 'Pablo Picasso', '65', 'pablo@gmail.com', '0944444444', '4321', '1000044444444', '100000')")
        c.execute("INSERT INTO users VALUES ('5', 'abebe kebede', '42', 'kebede123@gmail.com', '0911121314', '6754', '1000035732047', '115000')")
"""

OLD_CREATE = """        c.execute("CREATE TABLE users (user_id TEXT, first_name TEXT, last_name TEXT)")
        c.execute("INSERT INTO users VALUES ('1', 'admin', 'admin')")
        c.execute("INSERT INTO users VALUES ('2', 'Gordon', 'Brown')")
        c.execute("INSERT INTO users VALUES ('3', 'Hack', 'Me')")
        c.execute("INSERT INTO users VALUES ('4', 'Pablo', 'Picasso')")
        c.execute("INSERT INTO users VALUES ('5', 'Kebede', 'Smith')")"""

text = text.replace(OLD_CREATE, DB_CREATE.strip())

# Replace "SELECT first_name, last_name" with "SELECT *"
text = text.replace("SELECT first_name, last_name FROM users", "SELECT * FROM users")

# Replace the row append logic dynamically
OLD_APPEND = """                results.append({
                    'first_name': row['first_name'],
                    'last_name': row['last_name']
                })"""

NEW_APPEND = """                results.append(dict(row))"""
text = text.replace(OLD_APPEND, NEW_APPEND)

with open('app.py', 'w') as f:
    f.write(text)

