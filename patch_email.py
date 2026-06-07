with open('app.py', 'r') as f:
    app_code = f.read()

app_code = app_code.replace("abebe.k@aau.edu.et", "kebede@gmail.com")

with open('app.py', 'w') as f:
    f.write(app_code)

print("Email replaced.")
