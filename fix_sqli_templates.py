import glob

for filename in glob.glob('templates/lab_sqli_*.html'):
    with open(filename, 'r') as f:
        text = f.read()

    OLD_RESULT = """          ID: {{ user_id }}<br />
          First name: {{ r.first_name }}<br />
          Surname: {{ r.last_name }}"""
          
    NEW_RESULT = """          {% if r.name %}
          <b>Name:</b> {{ r.name }}<br>
          <b>Age:</b> {{ r.age }}<br>
          <b>Email:</b> {{ r.email }}<br>
          <b>Mobile Number:</b> {{ r.mobile }}<br>
          <b>ATM Passwd:</b> {{ r.atm_pass }}<br>
          <b>Bank Account:</b> {{ r.bank_acc }}<br>
          <b>Amount in Bank:</b> {{ r.amount }}<br>
          {% else %}
          {% for k, v in r.items() %}
             <b>{{ k }}:</b> {{ v }}<br>
          {% endfor %}
          {% endif %}"""
    
    text = text.replace(OLD_RESULT, NEW_RESULT)
    
    # Update the query shown in the source block to match app.py (SELECT *)
    text = text.replace("SELECT first_name, last_name", "SELECT *")

    with open(filename, 'w') as f:
        f.write(text)

