#!/usr/bin/env python3
"""
Vulnerable Test Server for Dominator Scanner Testing

This server intentionally contains various security vulnerabilities
for testing the scanner's detection capabilities.

WARNING: DO NOT DEPLOY IN PRODUCTION!
This server is for testing purposes only.

Run: python tests/vulnerable_server.py
Access: http://localhost:5000
"""

from flask import Flask, request, render_template_string, redirect, make_response, jsonify
import sqlite3
import os
import subprocess
import xml.etree.ElementTree as ET

app = Flask(__name__)
app.secret_key = 'super_secret_key_12345'  # Hardcoded secret (vulnerability)

# Database setup (SQLite in memory for testing)
def get_db():
    db = sqlite3.connect(':memory:')
    db.execute('CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, username TEXT, password TEXT, email TEXT)')
    db.execute('CREATE TABLE IF NOT EXISTS products (id INTEGER PRIMARY KEY, name TEXT, price REAL)')
    db.execute("INSERT OR IGNORE INTO users VALUES (1, 'admin', 'admin123', 'admin@test.com')")
    db.execute("INSERT OR IGNORE INTO users VALUES (2, 'user', 'password', 'user@test.com')")
    db.execute("INSERT OR IGNORE INTO products VALUES (1, 'Product A', 99.99)")
    db.execute("INSERT OR IGNORE INTO products VALUES (2, 'Product B', 149.99)")
    db.commit()
    return db

# ============== VULNERABLE ENDPOINTS ==============

# ---------- XSS Vulnerabilities ----------
@app.route('/')
def index():
    """Homepage with reflected XSS"""
    name = request.args.get('name', 'Guest')
    # VULNERABLE: No escaping - Reflected XSS
    html = f'''
    <!DOCTYPE html>
    <html>
    <head><title>Vulnerable Test App</title></head>
    <body>
        <h1>Welcome, {name}!</h1>
        <p>This is a vulnerable test server for Dominator scanner testing.</p>
        <h2>Test Endpoints:</h2>
        <ul>
            <li><a href="/search?q=test">Search (XSS)</a></li>
            <li><a href="/user?id=1">User Profile (SQLi)</a></li>
            <li><a href="/login">Login Form (SQLi, CSRF)</a></li>
            <li><a href="/admin">Admin Panel (IDOR)</a></li>
            <li><a href="/file?name=test.txt">File Reader (LFI)</a></li>
            <li><a href="/fetch?url=http://example.com">URL Fetcher (SSRF)</a></li>
            <li><a href="/api/users">API Endpoint (Info Disclosure)</a></li>
            <li><a href="/comment">Comment Form (Stored XSS)</a></li>
            <li><a href="/redirect?url=http://evil.com">Open Redirect</a></li>
            <li><a href="/xml">XML Parser (XXE)</a></li>
            <li><a href="/template?name=test">Template (SSTI)</a></li>
            <li><a href="/cmd?input=whoami">Command (RCE)</a></li>
            <li><a href="/headers">Security Headers Check</a></li>
            <li><a href="/robots.txt">Robots.txt</a></li>
            <li><a href="/.git/config">Git Config Exposed</a></li>
            <li><a href="/backup.sql">Backup File</a></li>
            <li><a href="/phpinfo.php">PHP Info</a></li>
            <li><a href="/api/v1/swagger.json">API Spec</a></li>
        </ul>
    </body>
    </html>
    '''
    response = make_response(html)
    # Missing security headers (vulnerability)
    return response

@app.route('/search')
def search():
    """Search with reflected XSS"""
    query = request.args.get('q', '')
    # VULNERABLE: Reflected XSS
    return f'''
    <html>
    <head><title>Search Results</title></head>
    <body>
        <h1>Search Results for: {query}</h1>
        <p>No results found for your query.</p>
        <form method="GET">
            <input type="text" name="q" value="{query}">
            <button type="submit">Search</button>
        </form>
    </body>
    </html>
    '''

@app.route('/comment', methods=['GET', 'POST'])
def comment():
    """Comment form with stored XSS"""
    comments = []
    if request.method == 'POST':
        comment_text = request.form.get('comment', '')
        # VULNERABLE: Stored XSS - comment stored without sanitization
        comments.append(comment_text)

    # VULNERABLE: No CSRF token
    return f'''
    <html>
    <head><title>Comments</title></head>
    <body>
        <h1>Leave a Comment</h1>
        <form method="POST">
            <textarea name="comment"></textarea>
            <button type="submit">Submit</button>
        </form>
        <h2>Comments:</h2>
        <div>{'<br>'.join(comments)}</div>
    </body>
    </html>
    '''

# ---------- SQL Injection ----------
@app.route('/user')
def user_profile():
    """User profile with SQLi"""
    user_id = request.args.get('id', '1')
    db = get_db()
    # VULNERABLE: SQL Injection
    try:
        cursor = db.execute(f"SELECT * FROM users WHERE id = {user_id}")
        user = cursor.fetchone()
        if user:
            return f'''
            <html>
            <body>
                <h1>User Profile</h1>
                <p>ID: {user[0]}</p>
                <p>Username: {user[1]}</p>
                <p>Email: {user[3]}</p>
            </body>
            </html>
            '''
        return "User not found", 404
    except Exception as e:
        # VULNERABLE: Error disclosure
        return f"Database error: {str(e)}", 500

@app.route('/login', methods=['GET', 'POST'])
def login():
    """Login form with SQLi"""
    error = ''
    if request.method == 'POST':
        username = request.form.get('username', '')
        password = request.form.get('password', '')
        db = get_db()
        # VULNERABLE: SQL Injection in login
        try:
            query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"
            cursor = db.execute(query)
            user = cursor.fetchone()
            if user:
                return f"Welcome, {user[1]}!"
            error = "Invalid credentials"
        except Exception as e:
            error = f"Error: {str(e)}"

    # VULNERABLE: No CSRF protection
    return f'''
    <html>
    <head><title>Login</title></head>
    <body>
        <h1>Login</h1>
        <p style="color:red">{error}</p>
        <form method="POST">
            <input type="text" name="username" placeholder="Username"><br>
            <input type="password" name="password" placeholder="Password"><br>
            <button type="submit">Login</button>
        </form>
    </body>
    </html>
    '''

# ---------- IDOR ----------
@app.route('/admin')
def admin():
    """Admin panel with IDOR"""
    # VULNERABLE: No authentication check, relies on user_id parameter
    user_id = request.args.get('user_id', '2')
    db = get_db()
    cursor = db.execute(f"SELECT * FROM users WHERE id = {user_id}")
    user = cursor.fetchone()

    return f'''
    <html>
    <body>
        <h1>Admin Panel</h1>
        <p>Viewing data for user ID: {user_id}</p>
        <p>Username: {user[1] if user else 'N/A'}</p>
        <p>Password: {user[2] if user else 'N/A'}</p>
        <p>Email: {user[3] if user else 'N/A'}</p>
        <p><a href="/admin?user_id=1">View Admin (ID: 1)</a></p>
        <p><a href="/admin?user_id=2">View User (ID: 2)</a></p>
    </body>
    </html>
    '''

# ---------- LFI / Path Traversal ----------
@app.route('/file')
def read_file():
    """File reader with LFI"""
    filename = request.args.get('name', 'test.txt')
    # VULNERABLE: Path traversal / LFI
    try:
        filepath = f"./files/{filename}"
        with open(filepath, 'r') as f:
            content = f.read()
        return f"<pre>{content}</pre>"
    except Exception as e:
        return f"Error reading file: {str(e)}", 404

@app.route('/download')
def download():
    """Download with path traversal"""
    file_path = request.args.get('path', '')
    # VULNERABLE: Arbitrary file download
    try:
        with open(file_path, 'rb') as f:
            content = f.read()
        response = make_response(content)
        response.headers['Content-Disposition'] = f'attachment; filename={os.path.basename(file_path)}'
        return response
    except:
        return "File not found", 404

# ---------- SSRF ----------
@app.route('/fetch')
def fetch_url():
    """URL fetcher with SSRF"""
    url = request.args.get('url', '')
    if url:
        # VULNERABLE: SSRF - no URL validation
        import urllib.request
        try:
            response = urllib.request.urlopen(url, timeout=5)
            return f"<pre>{response.read().decode('utf-8', errors='ignore')[:5000]}</pre>"
        except Exception as e:
            return f"Error fetching URL: {str(e)}", 500
    return '''
    <html>
    <body>
        <h1>URL Fetcher</h1>
        <form method="GET">
            <input type="text" name="url" placeholder="Enter URL">
            <button type="submit">Fetch</button>
        </form>
    </body>
    </html>
    '''

# ---------- XXE ----------
@app.route('/xml', methods=['GET', 'POST'])
def xml_parser():
    """XML parser with XXE"""
    if request.method == 'POST':
        xml_data = request.data.decode('utf-8')
        # VULNERABLE: XXE - XML parser with external entities enabled
        try:
            root = ET.fromstring(xml_data)
            return f"Parsed XML: {ET.tostring(root).decode()}"
        except Exception as e:
            return f"XML Error: {str(e)}", 400

    return '''
    <html>
    <body>
        <h1>XML Parser</h1>
        <p>POST XML data to this endpoint</p>
        <pre>
Example:
&lt;?xml version="1.0"?&gt;
&lt;data&gt;test&lt;/data&gt;
        </pre>
    </body>
    </html>
    '''

# ---------- SSTI ----------
@app.route('/template')
def template():
    """Template with SSTI"""
    name = request.args.get('name', 'World')
    # VULNERABLE: Server-Side Template Injection
    template_string = f"Hello, {name}!"
    return render_template_string(template_string)

@app.route('/greet')
def greet():
    """Another SSTI endpoint"""
    user_input = request.args.get('input', '')
    # VULNERABLE: SSTI
    template = f"<h1>Welcome</h1><p>Your input: {user_input}</p>"
    return render_template_string(template)

# ---------- Command Injection ----------
@app.route('/cmd')
def command():
    """Command execution with RCE"""
    user_input = request.args.get('input', '')
    if user_input:
        # VULNERABLE: Command injection
        try:
            result = subprocess.check_output(f"echo {user_input}", shell=True, stderr=subprocess.STDOUT)
            return f"<pre>{result.decode()}</pre>"
        except Exception as e:
            return f"Error: {str(e)}", 500
    return '''
    <html>
    <body>
        <h1>Command Runner</h1>
        <form method="GET">
            <input type="text" name="input" placeholder="Enter text">
            <button type="submit">Run</button>
        </form>
    </body>
    </html>
    '''

@app.route('/ping')
def ping():
    """Ping with command injection"""
    host = request.args.get('host', '')
    if host:
        # VULNERABLE: Command injection
        try:
            result = subprocess.check_output(f"ping -c 1 {host}", shell=True, stderr=subprocess.STDOUT, timeout=5)
            return f"<pre>{result.decode()}</pre>"
        except:
            return "Ping failed", 500
    return "Provide host parameter"

# ---------- Open Redirect ----------
@app.route('/redirect')
def open_redirect():
    """Open redirect vulnerability"""
    url = request.args.get('url', '/')
    # VULNERABLE: Open redirect - no validation
    return redirect(url)

@app.route('/goto')
def goto():
    """Another open redirect"""
    next_url = request.args.get('next', '/')
    # VULNERABLE: Open redirect
    return redirect(next_url)

# ---------- Information Disclosure ----------
@app.route('/api/users')
def api_users():
    """API endpoint with info disclosure"""
    db = get_db()
    cursor = db.execute("SELECT * FROM users")
    users = cursor.fetchall()
    # VULNERABLE: Sensitive data exposure
    return jsonify([{
        'id': u[0],
        'username': u[1],
        'password': u[2],  # Exposing passwords!
        'email': u[3]
    } for u in users])

@app.route('/api/v1/swagger.json')
def swagger():
    """Exposed API documentation"""
    return jsonify({
        "swagger": "2.0",
        "info": {"title": "Vulnerable API", "version": "1.0"},
        "paths": {
            "/api/users": {"get": {"summary": "Get all users"}},
            "/api/admin": {"get": {"summary": "Admin endpoint"}},
            "/api/internal/debug": {"get": {"summary": "Debug endpoint"}}
        }
    })

@app.route('/debug')
def debug():
    """Debug endpoint with info disclosure"""
    # VULNERABLE: Debug info exposure
    return jsonify({
        'server': 'Flask',
        'python_version': '3.x',
        'debug_mode': True,
        'secret_key': app.secret_key,
        'database': 'sqlite:memory',
        'environment': 'development'
    })

# ---------- Security Headers (Missing) ----------
@app.route('/headers')
def headers():
    """Endpoint to test missing security headers"""
    response = make_response('''
    <html>
    <body>
        <h1>Security Headers Test</h1>
        <p>Check the response headers - many security headers are missing!</p>
    </body>
    </html>
    ''')
    # VULNERABLE: Missing all security headers
    # No X-Frame-Options
    # No X-Content-Type-Options
    # No Content-Security-Policy
    # No X-XSS-Protection
    # No Strict-Transport-Security
    return response

# ---------- Sensitive Files ----------
@app.route('/robots.txt')
def robots():
    """Robots.txt with sensitive paths"""
    return '''User-agent: *
Disallow: /admin/
Disallow: /backup/
Disallow: /config/
Disallow: /database/
Disallow: /.git/
Disallow: /api/internal/
'''

@app.route('/.git/config')
def git_config():
    """Exposed git config"""
    # VULNERABLE: Git config exposure
    return '''[core]
    repositoryformatversion = 0
    filemode = true
    bare = false
[remote "origin"]
    url = https://github.com/company/private-repo.git
    fetch = +refs/heads/*:refs/remotes/origin/*
[user]
    email = developer@company.com
'''

@app.route('/backup.sql')
def backup():
    """Exposed database backup"""
    # VULNERABLE: Backup file exposure
    return '''-- MySQL dump
-- Database: vulnerable_app
CREATE TABLE users (id INT, username VARCHAR(50), password VARCHAR(50));
INSERT INTO users VALUES (1, 'admin', 'supersecretpassword123');
INSERT INTO users VALUES (2, 'user', 'userpassword456');
'''

@app.route('/.env')
def env_file():
    """Exposed .env file"""
    # VULNERABLE: Environment file exposure
    return '''DATABASE_URL=mysql://root:rootpassword@localhost/app
SECRET_KEY=super_secret_key_12345
AWS_ACCESS_KEY=AKIAIOSFODNN7EXAMPLE
AWS_SECRET_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
STRIPE_API_KEY=sk_live_abcdefghijklmnopqrstuvwxyz
'''

@app.route('/config.php')
def config_php():
    """Exposed PHP config"""
    return '''<?php
$db_host = "localhost";
$db_user = "root";
$db_pass = "password123";
$db_name = "vulnerable_app";
$secret_key = "my_secret_key";
?>'''

@app.route('/phpinfo.php')
def phpinfo():
    """Simulated phpinfo"""
    return '''<html>
<head><title>PHP Info</title></head>
<body>
<h1>PHP Version 7.4.3</h1>
<table>
<tr><td>System</td><td>Linux server 5.4.0</td></tr>
<tr><td>Document Root</td><td>/var/www/html</td></tr>
<tr><td>Server Admin</td><td>admin@localhost</td></tr>
<tr><td>DOCUMENT_ROOT</td><td>/var/www/html</td></tr>
<tr><td>MySQL Support</td><td>enabled</td></tr>
</table>
</body>
</html>'''

@app.route('/server-status')
def server_status():
    """Apache server status"""
    return '''Apache Server Status
Server Version: Apache/2.4.41 (Ubuntu)
Current Time: 2024-01-01 12:00:00
Restart Time: 2024-01-01 00:00:00
Server uptime: 12 hours
Total accesses: 10000
CPU Usage: 50%
'''

# ---------- CORS Misconfiguration ----------
@app.route('/api/cors')
def cors_api():
    """API with CORS misconfiguration"""
    response = jsonify({'data': 'sensitive_info', 'user': 'admin'})
    # VULNERABLE: Permissive CORS
    response.headers['Access-Control-Allow-Origin'] = '*'
    response.headers['Access-Control-Allow-Credentials'] = 'true'
    return response

# ---------- Directory Listing ----------
@app.route('/files/')
def directory_listing():
    """Directory listing enabled"""
    # VULNERABLE: Directory listing
    return '''<html>
<head><title>Index of /files/</title></head>
<body>
<h1>Index of /files/</h1>
<ul>
<li><a href="../">../</a></li>
<li><a href="config.txt">config.txt</a></li>
<li><a href="passwords.txt">passwords.txt</a></li>
<li><a href="database.sql">database.sql</a></li>
<li><a href="private_key.pem">private_key.pem</a></li>
</ul>
</body>
</html>'''

# ---------- JWT Issues ----------
@app.route('/api/token')
def get_token():
    """Weak JWT generation"""
    # VULNERABLE: Weak JWT (none algorithm, weak secret)
    import base64
    header = base64.b64encode(b'{"alg":"none","typ":"JWT"}').decode()
    payload = base64.b64encode(b'{"user":"admin","role":"admin"}').decode()
    return jsonify({
        'token': f'{header}.{payload}.',
        'note': 'Use this token for authentication'
    })

# ---------- Rate Limiting (None) ----------
@app.route('/api/login', methods=['POST'])
def api_login():
    """API login without rate limiting"""
    # VULNERABLE: No rate limiting - brute force possible
    username = request.json.get('username', '')
    password = request.json.get('password', '')

    if username == 'admin' and password == 'admin123':
        return jsonify({'success': True, 'message': 'Login successful'})
    return jsonify({'success': False, 'message': 'Invalid credentials'}), 401

# ---------- Error Handling ----------
@app.errorhandler(500)
def internal_error(error):
    # VULNERABLE: Verbose error messages
    import traceback
    return f'''
    <html>
    <body>
        <h1>500 Internal Server Error</h1>
        <pre>{traceback.format_exc()}</pre>
        <p>Server: Flask Development Server</p>
        <p>Debug Mode: True</p>
    </body>
    </html>
    ''', 500

# Create files directory
os.makedirs('files', exist_ok=True)
with open('files/test.txt', 'w') as f:
    f.write('This is a test file.')

if __name__ == '__main__':
    print("=" * 60)
    print("VULNERABLE TEST SERVER FOR DOMINATOR SCANNER")
    print("=" * 60)
    print("WARNING: This server contains intentional vulnerabilities!")
    print("DO NOT expose to the internet!")
    print("")
    print("Starting server at http://localhost:5000")
    print("=" * 60)

    # Run in debug mode (also a vulnerability!)
    app.run(host='127.0.0.1', port=5000, debug=True)
