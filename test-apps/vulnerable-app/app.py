"""
INTENTIONALLY VULNERABLE APPLICATION
DO NOT USE IN PRODUCTION!
This is for learning purposes only.
"""

import os
import sqlite3
from flask import Flask, request, render_template_string

app = Flask(__name__)

# ════════════════════════════════════════════════════════════════════
# ⚠️  WARNING: INTENTIONALLY INSECURE CODE BELOW ⚠️
# This is FAKE test data for security scanner demonstration
# DO NOT use any of these patterns in production!
# See test-apps/secure-example/ for proper secret management
# ════════════════════════════════════════════════════════════════════

# VULNERABILITY 1: Hardcoded credentials
DATABASE_PASSWORD = "admin123"
API_KEY = "sk_live_51H8xK2L3m4N5o6P7q8R9s0T"
SECRET_KEY = "super_secret_key_12345"

# VULNERABILITY 2: SQL Injection
@app.route('/search')
def search():
    query = request.args.get('q', '')
    
    # BAD: Direct string concatenation in SQL
    sql = f"SELECT * FROM users WHERE name = '{query}'"
    
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    cursor.execute(sql)  # SQL Injection vulnerability!
    results = cursor.fetchall()
    conn.close()
    
    return str(results)

# VULNERABILITY 3: Command Injection
@app.route('/ping')
def ping():
    host = request.args.get('host', 'localhost')
    
    # BAD: Using user input directly in system command
    result = os.system(f'ping -c 1 {host}')  # Command injection!
    
    return f"Ping result: {result}"

# VULNERABILITY 4: Cross-Site Scripting (XSS)
@app.route('/hello')
def hello():
    name = request.args.get('name', 'Guest')
    
    # BAD: Rendering user input without sanitization
    template = f"<h1>Hello {name}!</h1>"
    return render_template_string(template)  # XSS vulnerability!

# VULNERABILITY 5: Path Traversal
@app.route('/read')
def read_file():
    filename = request.args.get('file', 'readme.txt')
    
    # BAD: No validation on file path
    with open(filename, 'r') as f:  # Path traversal!
        content = f.read()
    
    return content

# VULNERABILITY 6: Eval of user input
@app.route('/calc')
def calculate():
    expression = request.args.get('expr', '1+1')
    
    # BAD: eval() with user input
    result = eval(expression)  # Code injection!
    
    return f"Result: {result}"

# VULNERABILITY 7: Weak cryptography
@app.route('/hash')
def hash_password():
    import hashlib
    password = request.args.get('password', '')
    
    # BAD: MD5 is broken
    hashed = hashlib.md5(password.encode()).hexdigest()
    
    return f"Hash: {hashed}"

# VULNERABILITY 8: Debug mode enabled
if __name__ == '__main__':
    # BAD: Debug mode in production
    app.run(debug=True, host='0.0.0.0')
