import sys

with open('app.py', 'r') as f:
    text = f.read()

new_route = """    return render_template('lab_sqli_low.html',
                           username=session.get('username'),
                           role=session.get('role'),
                           results=results,
                           error=error,
                           flag_output=flag_output,
                           query=query,
                           user_id=user_id)


@app.route('/aau/threatmapper/aaulab/sqli/medium', methods=['GET', 'POST'])
@login_required
def aaulab_sqli_medium():
    flag = 'AAU{medium_level_sqli_exploited}'
    results = []
    error = None
    flag_output = None
    query = None
    raw_user_id = ''
    
    if request.method == 'POST':
        raw_user_id = request.form.get('id', '')
        
        # Simulate mysqli_real_escape_string
        user_id = raw_user_id.replace('\\\\', '\\\\\\\\').replace("'", "\\\\'").replace('"', '\\\\"')
        
        import sqlite3
        import re
        conn = sqlite3.connect(':memory:')
        conn.row_factory = sqlite3.Row
        c = conn.cursor()
        c.execute("CREATE TABLE users (user_id INTEGER, first_name TEXT, last_name TEXT)")
        c.execute("INSERT INTO users VALUES (1, 'admin', 'admin')")
        c.execute("INSERT INTO users VALUES (2, 'Gordon', 'Brown')")
        c.execute("INSERT INTO users VALUES (3, 'Hack', 'Me')")
        c.execute("INSERT INTO users VALUES (4, 'Pablo', 'Picasso')")
        c.execute("INSERT INTO users VALUES (5, 'Bob', 'Smith')")
        conn.commit()
        
        query = f"SELECT first_name, last_name FROM users WHERE user_id = {user_id};"
        
        found = False
        try:
            if user_id.strip():
                c.execute(query)
                rows = c.fetchall()
                for row in rows:
                    results.append({
                        'first_name': row['first_name'],
                        'last_name': row['last_name']
                    })
                    found = True
        except Exception as e:
            error = f"Error in fetch: {str(e)}"
            
        if not found and re.search(r'(or|--|;|\\s)', raw_user_id, re.IGNORECASE):
            flag_output = flag
            
    return render_template('lab_sqli_medium.html',
                           username=session.get('username'),
                           role=session.get('role'),
                           results=results,
                           error=error,
                           flag_output=flag_output,
                           query=query,
                           user_id=raw_user_id)"""

target = """    return render_template('lab_sqli_low.html',
                           username=session.get('username'),
                           role=session.get('role'),
                           results=results,
                           error=error,
                           flag_output=flag_output,
                           query=query,
                           user_id=user_id)"""

if target in text:
    text = text.replace(target, new_route)
    with open('app.py', 'w') as f:
        f.write(text)
    print("app.py patched successfully.")
else:
    print("Could not find patch target.")
