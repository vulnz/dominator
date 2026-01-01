"""
HTTP Form Bruteforce Tab
Provides form field detection, auth type detection, CSRF handling,
and credential bruteforce capabilities with proxy support
"""

import re
import os
import base64
import requests
from pathlib import Path
from urllib.parse import urlparse, urljoin, parse_qs
from PyQt5.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QGridLayout, QGroupBox,
    QLabel, QLineEdit, QPushButton, QTextEdit, QTableWidget,
    QTableWidgetItem, QHeaderView, QComboBox, QSpinBox, QCheckBox,
    QProgressBar, QFrame, QMessageBox, QFileDialog, QSplitter,
    QAbstractItemView, QSizePolicy, QTabWidget, QScrollArea,
    QDialog, QDialogButtonBox, QRadioButton, QButtonGroup
)
from PyQt5.QtCore import Qt, QThread, pyqtSignal
from PyQt5.QtGui import QFont, QColor, QBrush

# Auth type constants
AUTH_TYPE_FORM = "form"
AUTH_TYPE_BASIC = "basic"
AUTH_TYPE_DIGEST = "digest"
AUTH_TYPE_NTLM = "ntlm"
AUTH_TYPE_BEARER = "bearer"
AUTH_TYPE_API_KEY = "api_key"

# CSRF token patterns
CSRF_PATTERNS = [
    r'name=["\']?csrf[_-]?token["\']?\s+value=["\']([^"\']+)["\']',
    r'name=["\']?_?csrf["\']?\s+value=["\']([^"\']+)["\']',
    r'name=["\']?authenticity_token["\']?\s+value=["\']([^"\']+)["\']',
    r'name=["\']?__RequestVerificationToken["\']?\s+value=["\']([^"\']+)["\']',
    r'name=["\']?csrfmiddlewaretoken["\']?\s+value=["\']([^"\']+)["\']',
    r'name=["\']?_token["\']?\s+value=["\']([^"\']+)["\']',
    r'name=["\']?nonce["\']?\s+value=["\']([^"\']+)["\']',
    r'name=["\']?state["\']?\s+value=["\']([^"\']+)["\']',
]

# Default wordlists
DEFAULT_USERNAMES = """admin
root
administrator
user
test
guest
info
support
mysql
postgres
ftp
www
web
webmaster
demo
backup
service
system
manager
operator"""

DEFAULT_PASSWORDS = """123456
password
12345678
qwerty
123456789
12345
1234
111111
1234567
dragon
123123
baseball
iloveyou
trustno1
sunshine
master
welcome
shadow
ashley
football
jesus
michael
ninja
mustang
password1
123456a
a123456
000000
letmein
abc123
admin
login
monkey
starwars
passw0rd
princess
qwerty123
solo
admin123
root
toor
pass
test
guest
changeme
654321
superman
qazwsx
michael
jordan
harley
ranger
buster
thomas
robert
soccer
hockey
killer
george
andrew
charlie
martin
dallas
jessica
liverpool
james
pepper
daniel
cherry
william
matrix
yankees
maggie
austin
secret
summer
phoenix
hammer
sparky
ginger
silver
asdfgh
zxcvbn
1q2w3e
q1w2e3
1qaz2wsx
zaq12wsx
1234qwer
qwer1234
asdf1234
password123
admin1234
root123
test123
user123
hello123
welcome1
letmein1
passw0rd!
P@ssw0rd"""

# Default emails (common patterns)
DEFAULT_EMAILS = """admin@example.com
admin@test.com
admin@localhost
administrator@example.com
root@example.com
test@example.com
user@example.com
info@example.com
support@example.com
contact@example.com
webmaster@example.com
postmaster@example.com
sales@example.com
demo@example.com
guest@example.com
admin@admin.com
test@test.com
user@user.com"""

# Known/Common Bearer tokens and API keys that might grant admin access
# These are commonly found in CTFs, misconfigured apps, default installations
DEFAULT_BEARER_TOKENS = """
# JWT tokens with weak/known secrets
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6ImFkbWluIiwiaWF0IjoxNTE2MjM5MDIyLCJyb2xlIjoiYWRtaW4ifQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyIjoiYWRtaW4iLCJyb2xlIjoiYWRtaW5pc3RyYXRvciJ9.4PZsK6P8Z8Q8Q8Q8Q8Q8Q8Q8Q8Q8Q8Q8Q8Q8Q8Q8Q8Q
eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJ1c2VyIjoiYWRtaW4iLCJyb2xlIjoiYWRtaW4ifQ.
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6MSwidXNlcm5hbWUiOiJhZG1pbiIsInJvbGUiOiJhZG1pbiJ9.
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJhZG1pbiIsImFkbWluIjp0cnVlfQ.
# Common weak secrets: secret, password, 123456, key, admin
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJyb2xlIjoiYWRtaW4ifQ.BqHOuHsW8l4mfk3P2NPNpFm-6Pv1kK5qZa9Q8Q8c9Uc
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VybmFtZSI6ImFkbWluIiwiYWRtaW4iOnRydWV9.
# API Keys - Common patterns
admin
administrator
root
superuser
master
default
test
demo
development
dev
staging
production
prod
secret
supersecret
api_key
apikey
api-key
API_KEY
APIKEY
access_token
token
auth_token
bearer
Bearer
admin_token
master_key
masterkey
master-key
secret_key
secretkey
private_key
privatekey
public
private
internal
system
service
app
application
mobile
web
client
server
backend
frontend
key
key123
key1234
123456
1234567890
abcdef
abc123
password
pass123
admin123
root123
test123
qwerty
letmein
changeme
default123
# UUID-like tokens often used
00000000-0000-0000-0000-000000000000
11111111-1111-1111-1111-111111111111
aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa
12345678-1234-1234-1234-123456789012
deadbeef-dead-beef-dead-beefdeadbeef
# Hex tokens
0000000000000000
1111111111111111
aaaaaaaaaaaaaaaa
0123456789abcdef
deadbeefdeadbeef
cafebabecafebabe
# Base64 encoded common values
YWRtaW4=
YWRtaW5pc3RyYXRvcg==
cm9vdA==
dGVzdA==
dXNlcg==
cGFzc3dvcmQ=
c2VjcmV0
# Common service account tokens
sa-token
service-account
svc-account
robot-token
ci-token
cd-token
deploy-token
build-token
pipeline-token
jenkins
travis
circleci
github
gitlab
bitbucket
azure
aws
gcp
google
amazon
microsoft
# Framework defaults
laravel_token
django_token
flask_token
express_token
spring_token
rails_token
# Common test/dev tokens
test_token
dev_token
debug_token
local_token
localhost_token
sandbox_token
staging_token
qa_token
uat_token
# Null/empty variations
null
NULL
none
None
NONE
undefined
empty
blank
void
# Common hardcoded tokens found in code
x-api-key
X-API-KEY
x-auth-token
X-Auth-Token
x-access-token
X-Access-Token
authorization
Authorization
AUTHORIZATION
# Firebase/Google defaults
AIzaSyDemoKeyForTesting123456789
AIzaSyABCDEFGHIJKLMNOPQRSTUVWXYZ123456
# AWS-like keys
AKIAIOSFODNN7EXAMPLE
wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
# Stripe test keys
sk_test_4eC39HqLyjWDarjtT1zdp7dc
pk_test_TYooMQauvdEDq54NiTphI7jx
rk_test_51234567890abcdefghijklmnop
# Twilio test
ACtest1234567890abcdef1234567890ab
# SendGrid test
SG.test1234567890abcdef1234567890abcdef
# Slack test tokens
xoxb-test-token-placeholder
xoxp-test-token-placeholder
xoxa-test-token-placeholder
# GitHub test tokens
ghp_test1234567890abcdefghijklmnopqrstuv
gho_test1234567890abcdefghijklmnopqrstuv
# GitLab tokens
glpat-test1234567890abcdef
# NPM tokens
npm_test1234567890abcdefghijklmnopqrstuvwx
# PyPI tokens
pypi-test1234567890abcdefghijklmnopqrstuvwxyz
# Docker tokens
dckr_pat_test1234567890abcdefghij
# Heroku
test-api-key-heroku-placeholder
# DigitalOcean
dop_v1_test1234567890abcdefghijklmnopqrstuvwxyz
# Mailchimp
test1234567890abcdef1234567890ab-us1
# Common short tokens
admin_key
root_key
super_key
god_mode
backdoor
bypass
override
master_override
emergency_access
debug_mode
maintenance
"""


class AuthTypeDetector(QThread):
    """Thread to detect authentication type from a URL"""
    auth_detected = pyqtSignal(str, dict)  # (auth_type, details)
    error_signal = pyqtSignal(str)

    def __init__(self, url, proxy=None):
        super().__init__()
        self.url = url
        self.proxy = proxy

    def run(self):
        try:
            headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
            }

            proxies = None
            if self.proxy:
                proxies = {'http': self.proxy, 'https': self.proxy}

            # First, make a request without credentials to check auth type
            response = requests.get(self.url, headers=headers, timeout=15,
                                   verify=False, allow_redirects=False, proxies=proxies)

            auth_type = AUTH_TYPE_FORM
            details = {'status_code': response.status_code, 'headers': dict(response.headers)}

            # Check for Basic/Digest/NTLM auth via WWW-Authenticate header
            www_auth = response.headers.get('WWW-Authenticate', '').lower()

            if response.status_code == 401:
                if 'basic' in www_auth:
                    auth_type = AUTH_TYPE_BASIC
                    details['realm'] = self._extract_realm(response.headers.get('WWW-Authenticate', ''))
                    details['message'] = "HTTP Basic Authentication detected"
                elif 'digest' in www_auth:
                    auth_type = AUTH_TYPE_DIGEST
                    details['realm'] = self._extract_realm(response.headers.get('WWW-Authenticate', ''))
                    details['message'] = "HTTP Digest Authentication detected"
                elif 'ntlm' in www_auth or 'negotiate' in www_auth:
                    auth_type = AUTH_TYPE_NTLM
                    details['message'] = "NTLM/Windows Authentication detected"
                elif 'bearer' in www_auth:
                    auth_type = AUTH_TYPE_BEARER
                    details['message'] = "Bearer Token Authentication detected"
                else:
                    auth_type = AUTH_TYPE_BASIC  # Default to basic for 401
                    details['message'] = "HTTP Authentication detected (assuming Basic)"
            elif response.status_code == 403:
                # Could be API key or other auth
                if 'x-api-key' in str(response.headers).lower():
                    auth_type = AUTH_TYPE_API_KEY
                    details['message'] = "API Key Authentication detected"
            else:
                # Check for form-based auth
                details['message'] = "Form-based Authentication detected"

            self.auth_detected.emit(auth_type, details)

        except Exception as e:
            self.error_signal.emit(f"Error detecting auth type: {str(e)}")

    def _extract_realm(self, www_auth):
        """Extract realm from WWW-Authenticate header"""
        match = re.search(r'realm=["\']?([^"\']+)["\']?', www_auth, re.IGNORECASE)
        return match.group(1) if match else "Unknown"


class FormFieldDetector(QThread):
    """Thread to detect form fields, CSRF tokens, and auth type from a URL"""
    fields_detected = pyqtSignal(list, str, str, str, dict)  # (fields, action_url, method, auth_type, csrf_info)
    error_signal = pyqtSignal(str)

    def __init__(self, url, proxy=None):
        super().__init__()
        self.url = url
        self.proxy = proxy

    def run(self):
        try:
            from bs4 import BeautifulSoup

            # More realistic browser headers to bypass WAFs like Cloudflare
            headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8',
                'Accept-Language': 'en-US,en;q=0.9',
                'Accept-Encoding': 'gzip, deflate, br',
                'Connection': 'keep-alive',
                'Upgrade-Insecure-Requests': '1',
                'Sec-Fetch-Dest': 'document',
                'Sec-Fetch-Mode': 'navigate',
                'Sec-Fetch-Site': 'none',
                'Sec-Fetch-User': '?1',
                'Cache-Control': 'max-age=0',
            }

            proxies = None
            if self.proxy:
                proxies = {'http': self.proxy, 'https': self.proxy}

            # Create session for cookie handling
            session = requests.Session()

            # First check for HTTP auth
            auth_response = session.get(self.url, headers=headers, timeout=20,
                                        verify=False, allow_redirects=False, proxies=proxies)

            auth_type = AUTH_TYPE_FORM
            csrf_info = {'found': False, 'name': '', 'value': '', 'type': 'none'}

            # Check for Cloudflare/WAF challenge
            if auth_response.status_code == 403:
                # Check for Cloudflare challenge page
                if 'cloudflare' in auth_response.text.lower() or 'cf-ray' in str(auth_response.headers).lower():
                    self.error_signal.emit("Cloudflare protection detected. Try using a proxy or manual field entry.")
                    return
                else:
                    self.error_signal.emit(f"Access denied (403). Site may have WAF protection.")
                    return

            if auth_response.status_code == 503:
                if 'cloudflare' in auth_response.text.lower():
                    self.error_signal.emit("Cloudflare challenge page. Site is protected. Use manual field entry.")
                    return

            # Check for Basic/Digest auth
            if auth_response.status_code == 401:
                www_auth = auth_response.headers.get('WWW-Authenticate', '').lower()
                if 'basic' in www_auth:
                    auth_type = AUTH_TYPE_BASIC
                elif 'digest' in www_auth:
                    auth_type = AUTH_TYPE_DIGEST
                elif 'ntlm' in www_auth or 'negotiate' in www_auth:
                    auth_type = AUTH_TYPE_NTLM

                # For HTTP auth, return minimal info
                self.fields_detected.emit([], self.url, 'GET', auth_type, csrf_info)
                return

            # For form-based auth, continue with full detection
            response = session.get(self.url, headers=headers, timeout=20,
                                   verify=False, allow_redirects=True, proxies=proxies)

            # Check for challenge pages after redirect
            if 'cloudflare' in response.text.lower() and 'challenge' in response.text.lower():
                self.error_signal.emit("Cloudflare JS challenge detected. Manual field entry required.")
                return

            soup = BeautifulSoup(response.text, 'html.parser')

            # Detect CSRF tokens
            csrf_info = self._detect_csrf(response.text, soup)

            # Find forms - prioritize login forms
            forms = soup.find_all('form')

            if not forms:
                # Check if this is a WordPress login page without detected forms
                # This can happen with Cloudflare or JS-rendered pages
                if 'wp-login' in self.url.lower() or 'wordpress' in response.text.lower():
                    # Return default WordPress login fields
                    wp_fields = [
                        {'name': 'log', 'type': 'text', 'id': 'user_login', 'value': '',
                         'placeholder': 'Username or Email', 'is_username': True, 'is_password': False, 'is_csrf': False},
                        {'name': 'pwd', 'type': 'password', 'id': 'user_pass', 'value': '',
                         'placeholder': 'Password', 'is_username': False, 'is_password': True, 'is_csrf': False},
                        {'name': 'wp-submit', 'type': 'hidden', 'id': '', 'value': 'Log In',
                         'placeholder': '', 'is_username': False, 'is_password': False, 'is_csrf': False},
                        {'name': 'testcookie', 'type': 'hidden', 'id': '', 'value': '1',
                         'placeholder': '', 'is_username': False, 'is_password': False, 'is_csrf': False},
                    ]
                    self.fields_detected.emit(wp_fields, self.url, 'POST', AUTH_TYPE_FORM, csrf_info)
                    return
                else:
                    self.error_signal.emit("No forms found on this page. Try adding fields manually.")
                    return

            # Find the best login form
            form = None
            # First try to find form with login-related attributes
            for f in forms:
                form_id = f.get('id', '').lower()
                form_name = f.get('name', '').lower()
                form_class = ' '.join(f.get('class', [])).lower() if f.get('class') else ''
                form_action = f.get('action', '').lower()

                if any(kw in form_id + form_name + form_class + form_action
                       for kw in ['login', 'signin', 'auth', 'loginform', 'wp-login']):
                    form = f
                    break

            # If no login form found, use first form
            if form is None:
                form = forms[0]

            # Get form action and method
            action = form.get('action', '')
            if action:
                action = urljoin(self.url, action)
            else:
                action = self.url

            method = form.get('method', 'POST').upper()

            # Find all input fields
            fields = []

            # Text inputs
            for inp in form.find_all('input'):
                field_type = inp.get('type', 'text').lower()
                field_name = inp.get('name', '')
                field_id = inp.get('id', '')
                field_value = inp.get('value', '')
                placeholder = inp.get('placeholder', '')

                if field_name and field_type not in ['submit', 'button', 'image', 'reset']:
                    is_csrf = self._is_csrf_field(field_name, field_id)
                    field_data = {
                        'name': field_name,
                        'type': field_type,
                        'id': field_id,
                        'value': field_value,
                        'placeholder': placeholder,
                        'is_username': self._is_username_field(field_name, field_id, placeholder),
                        'is_password': field_type == 'password',
                        'is_csrf': is_csrf
                    }
                    fields.append(field_data)

                    # Update CSRF info if found
                    if is_csrf and field_value:
                        csrf_info = {'found': True, 'name': field_name, 'value': field_value, 'type': 'hidden_field'}

            # Textareas
            for ta in form.find_all('textarea'):
                field_name = ta.get('name', '')
                if field_name:
                    fields.append({
                        'name': field_name,
                        'type': 'textarea',
                        'id': ta.get('id', ''),
                        'value': ta.text,
                        'placeholder': ta.get('placeholder', ''),
                        'is_username': False,
                        'is_password': False,
                        'is_csrf': False
                    })

            # Select dropdowns
            for sel in form.find_all('select'):
                field_name = sel.get('name', '')
                if field_name:
                    options = [opt.get('value', opt.text) for opt in sel.find_all('option')]
                    fields.append({
                        'name': field_name,
                        'type': 'select',
                        'id': sel.get('id', ''),
                        'value': options[0] if options else '',
                        'placeholder': '',
                        'options': options,
                        'is_username': False,
                        'is_password': False,
                        'is_csrf': False
                    })

            self.fields_detected.emit(fields, action, method, auth_type, csrf_info)

        except Exception as e:
            self.error_signal.emit(f"Error: {str(e)}")

    def _detect_csrf(self, html_text, soup):
        """Detect CSRF tokens in the page"""
        csrf_info = {'found': False, 'name': '', 'value': '', 'type': 'none'}

        # Check meta tags for CSRF
        csrf_meta = soup.find('meta', attrs={'name': re.compile(r'csrf', re.I)})
        if csrf_meta:
            csrf_info = {
                'found': True,
                'name': csrf_meta.get('name', 'csrf-token'),
                'value': csrf_meta.get('content', ''),
                'type': 'meta_tag'
            }
            return csrf_info

        # Check for common CSRF patterns in HTML
        for pattern in CSRF_PATTERNS:
            match = re.search(pattern, html_text, re.IGNORECASE)
            if match:
                csrf_info = {
                    'found': True,
                    'name': 'csrf_token',
                    'value': match.group(1),
                    'type': 'hidden_field'
                }
                return csrf_info

        # Check cookies for CSRF tokens
        # This would need session cookies to be passed through

        return csrf_info

    def _is_csrf_field(self, name, field_id):
        """Check if this looks like a CSRF token field"""
        csrf_keywords = ['csrf', 'token', 'authenticity', 'verification', 'nonce', '_token', 'xsrf']
        text = f"{name} {field_id}".lower()
        return any(kw in text for kw in csrf_keywords)

    def _is_username_field(self, name, field_id, placeholder):
        """Check if this looks like a username/email field"""
        # WordPress uses 'log' for username field
        if name.lower() == 'log' or field_id.lower() == 'user_login':
            return True
        patterns = ['user', 'login', 'email', 'username', 'account', 'uname', 'uid']
        text = f"{name} {field_id} {placeholder}".lower()
        # Exclude password-related fields
        if 'pass' in text or 'pwd' in text:
            return False
        return any(p in text for p in patterns)


class BruteforceWorker(QThread):
    """Worker thread for bruteforce attack with multi-auth support and smart success detection"""
    progress_signal = pyqtSignal(int, int, str)  # (current, total, status)
    found_signal = pyqtSignal(str, str, dict)  # (username, password, response_info)
    response_signal = pyqtSignal(str, str, int, str, int, bool, str)  # (user, pass, status, title, size, is_success, reason)
    finished_signal = pyqtSignal(bool, str)  # (success, message)
    baseline_signal = pyqtSignal(int, str, int, int)  # (status, title, size, cookie_count)

    def __init__(self, url, method, fields, usernames, passwords, success_indicators, failure_indicators,
                 auth_type=AUTH_TYPE_FORM, csrf_info=None, proxy=None, refresh_csrf=False, threads=1,
                 stop_on_found=False, bearer_tokens=None, api_key_header="Authorization"):
        super().__init__()
        self.url = url
        self.method = method
        self.fields = fields
        self.usernames = usernames
        self.passwords = passwords
        self.success_indicators = success_indicators
        self.failure_indicators = failure_indicators
        self.auth_type = auth_type
        self.csrf_info = csrf_info or {'found': False}
        self.proxy = proxy
        self.refresh_csrf = refresh_csrf
        self.threads = threads
        self.running = True
        self.session = None
        self.stop_on_found = stop_on_found
        self.bearer_tokens = bearer_tokens or []
        self.api_key_header = api_key_header
        self.found_credentials = []  # Track all found credentials

        # Baseline for comparison
        self.baseline_status = None
        self.baseline_title = None
        self.baseline_size = None
        self.baseline_cookies = set()
        self.baseline_redirect_url = None
        self.baseline_content_hash = None

    def stop(self):
        self.running = False

    def _get_session(self):
        """Get or create a requests session"""
        if self.session is None:
            self.session = requests.Session()
            if self.proxy:
                self.session.proxies = {'http': self.proxy, 'https': self.proxy}
        return self.session

    def _reset_session(self):
        """Reset session to clear cookies between attempts"""
        self.session = requests.Session()
        if self.proxy:
            self.session.proxies = {'http': self.proxy, 'https': self.proxy}
        return self.session

    def _refresh_csrf_token(self):
        """Refresh CSRF token by fetching the page again"""
        if not self.csrf_info.get('found') or not self.refresh_csrf:
            return

        try:
            session = self._get_session()
            response = session.get(self.url, timeout=10, verify=False)

            # Find CSRF token in response
            for pattern in CSRF_PATTERNS:
                match = re.search(pattern, response.text, re.IGNORECASE)
                if match:
                    self.csrf_info['value'] = match.group(1)
                    # Update field value
                    for field in self.fields:
                        if field.get('is_csrf'):
                            field['value'] = match.group(1)
                    break
        except:
            pass

    def _extract_title(self, html):
        """Extract page title from HTML"""
        match = re.search(r'<title[^>]*>([^<]+)</title>', html, re.IGNORECASE)
        return match.group(1).strip()[:50] if match else "N/A"

    def _establish_baseline(self, session, headers):
        """Establish baseline with known-bad credentials to compare against"""
        import hashlib
        try:
            # Use obviously wrong credentials to establish baseline
            baseline_user = "definitely_not_a_real_user_12345"
            baseline_pass = "definitely_not_a_real_password_67890"

            if self.auth_type == AUTH_TYPE_BASIC:
                from requests.auth import HTTPBasicAuth
                response = session.get(self.url, auth=HTTPBasicAuth(baseline_user, baseline_pass),
                                      headers=headers, timeout=10, verify=False, allow_redirects=True)
            elif self.auth_type == AUTH_TYPE_DIGEST:
                from requests.auth import HTTPDigestAuth
                response = session.get(self.url, auth=HTTPDigestAuth(baseline_user, baseline_pass),
                                      headers=headers, timeout=10, verify=False, allow_redirects=True)
            elif self.auth_type == AUTH_TYPE_BEARER:
                # For bearer auth, test with invalid token
                test_headers = headers.copy()
                test_headers[self.api_key_header] = f"Bearer {baseline_pass}"
                response = session.get(self.url, headers=test_headers, timeout=10,
                                      verify=False, allow_redirects=True)
            elif self.auth_type == AUTH_TYPE_API_KEY:
                # For API key auth, test with invalid key
                test_headers = headers.copy()
                test_headers[self.api_key_header] = baseline_pass
                response = session.get(self.url, headers=test_headers, timeout=10,
                                      verify=False, allow_redirects=True)
            else:
                # Form-based
                data = {}
                for field in self.fields:
                    if field.get('is_username') or field.get('is_email'):
                        data[field['name']] = baseline_user
                    elif field.get('is_password'):
                        data[field['name']] = baseline_pass
                    elif field.get('is_csrf'):
                        data[field['name']] = self.csrf_info.get('value', field.get('value', ''))
                    elif field.get('value'):
                        data[field['name']] = field['value']

                if self.method == 'POST':
                    response = session.post(self.url, data=data, headers=headers,
                                           timeout=10, verify=False, allow_redirects=True)
                else:
                    response = session.get(self.url, params=data, headers=headers,
                                          timeout=10, verify=False, allow_redirects=True)

            self.baseline_status = response.status_code
            self.baseline_title = self._extract_title(response.text)
            self.baseline_size = len(response.content)
            self.baseline_cookies = set(session.cookies.keys())
            self.baseline_redirect_url = response.url
            # Hash content for comparison (excluding dynamic elements)
            clean_content = re.sub(r'(csrf|token|nonce)[^"\']*["\'][^"\']+["\']', '', response.text, flags=re.IGNORECASE)
            self.baseline_content_hash = hashlib.md5(clean_content.encode()).hexdigest()

            self.baseline_signal.emit(self.baseline_status, self.baseline_title,
                                      self.baseline_size, len(self.baseline_cookies))

        except Exception as e:
            # Use defaults
            self.baseline_status = 200
            self.baseline_title = ""
            self.baseline_size = 0
            self.baseline_cookies = set()
            self.baseline_content_hash = None

    def _detect_success(self, response, session, response_text):
        """
        Smart success detection using multiple indicators:
        1. New session cookies set
        2. Page content significantly different
        3. Redirect to different page
        4. Success indicators present
        5. Failure indicators absent (weighted, not absolute)
        6. Content hash comparison
        7. Response headers analysis
        """
        import hashlib
        reasons = []
        success_score = 0
        failure_score = 0

        status_code = response.status_code
        page_title = self._extract_title(response.text)
        page_size = len(response.content)
        current_cookies = set(session.cookies.keys())

        # For HTTP auth, 200 = success, 401 = failure (clear cut)
        if self.auth_type in [AUTH_TYPE_BASIC, AUTH_TYPE_DIGEST, AUTH_TYPE_NTLM]:
            if status_code == 200:
                return True, "HTTP 200 OK (Auth success)"
            elif status_code == 401:
                return False, "HTTP 401 Unauthorized"
            else:
                return False, f"HTTP {status_code}"

        # For Bearer/API key auth - check for 200 vs 401/403
        if self.auth_type in [AUTH_TYPE_BEARER, AUTH_TYPE_API_KEY]:
            if status_code == 200:
                # Additional check: content should be different from baseline
                if self.baseline_status in [401, 403] and status_code == 200:
                    return True, "HTTP 200 OK (Token valid)"
                success_score += 3
                reasons.append("HTTP 200 OK")
            elif status_code in [401, 403]:
                return False, f"HTTP {status_code} (Token rejected)"

        # Check for failure indicators (weighted, not absolute deal-breaker)
        failure_indicators_found = [ind for ind in self.failure_indicators if ind and ind.lower() in response_text]
        if failure_indicators_found:
            failure_score += 2
            reasons.append(f"Failure indicator: {failure_indicators_found[0][:20]}")

        # Check for success indicators
        success_indicators_found = [ind for ind in self.success_indicators if ind and ind.lower() in response_text]
        if success_indicators_found:
            success_score += 3
            reasons.append(f"Success indicator: {success_indicators_found[0][:20]}")

        # Check for new cookies (session/auth cookies often set on login)
        new_cookies = current_cookies - self.baseline_cookies
        auth_cookie_keywords = ['session', 'auth', 'token', 'jwt', 'user', 'login', 'logged', 'sid', 'ssid', 'phpsessid', 'aspnet']
        if new_cookies:
            for cookie in new_cookies:
                if any(kw in cookie.lower() for kw in auth_cookie_keywords):
                    success_score += 4
                    reasons.append(f"New auth cookie: {cookie}")
                    break
            else:
                success_score += 2
                reasons.append(f"New cookies: {', '.join(list(new_cookies)[:3])}")

        # Check if page title changed (often changes after login)
        if self.baseline_title and page_title and page_title != self.baseline_title:
            # Title no longer contains login-related words = likely logged in
            login_title_keywords = ['login', 'sign in', 'signin', 'log in', 'authenticate', 'authorization']
            baseline_is_login = any(kw in self.baseline_title.lower() for kw in login_title_keywords)
            current_is_login = any(kw in page_title.lower() for kw in login_title_keywords)

            # Check if title suggests logged-in state
            logged_in_title_keywords = ['dashboard', 'welcome', 'home', 'profile', 'account', 'panel', 'admin',
                                        'user', 'settings', 'my ', 'member', 'portal', 'console', 'inbox', 'overview']
            current_is_logged_in = any(kw in page_title.lower() for kw in logged_in_title_keywords)

            if current_is_logged_in:
                success_score += 4
                reasons.append(f"Title indicates logged in: {page_title}")
            elif baseline_is_login and not current_is_login:
                # Was on login page, now on different page
                success_score += 3
                reasons.append(f"Left login page: {page_title}")
            elif page_title != self.baseline_title:
                success_score += 2
                reasons.append(f"Title changed: {self.baseline_title} -> {page_title}")

        # Check for significant page size change (login pages often much different from dashboard)
        if self.baseline_size > 0:
            size_diff = abs(page_size - self.baseline_size)
            size_ratio = size_diff / self.baseline_size if self.baseline_size else 0

            # Larger page often means more content (dashboard vs login)
            if page_size > self.baseline_size and size_ratio > 0.10:
                success_score += 2
                reasons.append(f"Page larger by {size_ratio*100:.0f}%")
            elif size_ratio > 0.30:
                success_score += 1
                reasons.append(f"Page size changed by {size_ratio*100:.0f}%")

        # Check content hash - different content = likely different page
        if self.baseline_content_hash:
            clean_content = re.sub(r'(csrf|token|nonce)[^"\']*["\'][^"\']+["\']', '', response.text, flags=re.IGNORECASE)
            current_hash = hashlib.md5(clean_content.encode()).hexdigest()
            if current_hash != self.baseline_content_hash:
                success_score += 2
                reasons.append("Page content changed")

        # Check for redirect to different URL - ENHANCED
        if response.url != self.url:
            parsed_response = urlparse(response.url)
            parsed_original = urlparse(self.url)

            # Check if redirected to a different path
            if parsed_response.path != parsed_original.path:
                # Identify success redirect paths
                success_paths = ['dashboard', 'home', 'admin', 'panel', 'account', 'profile',
                                'welcome', 'main', 'portal', 'member', 'user', 'console', 'app']
                login_paths = ['login', 'signin', 'auth', 'authenticate', 'logon']

                current_path_lower = parsed_response.path.lower()

                # Check if redirected to success-indicating path
                if any(sp in current_path_lower for sp in success_paths):
                    success_score += 4
                    reasons.append(f"Redirected to success path: {parsed_response.path}")
                # Check if NOT redirected back to login (good sign)
                elif not any(lp in current_path_lower for lp in login_paths):
                    if self.baseline_redirect_url and response.url != self.baseline_redirect_url:
                        success_score += 3
                        reasons.append(f"Unique redirect: {response.url[:50]}")
                    else:
                        success_score += 2
                        reasons.append(f"Redirected to: {parsed_response.path}")

        # Check response history for 302 redirects - more detailed
        if response.history:
            redirect_count = len(response.history)
            redirect_codes = [r.status_code for r in response.history]

            # Multiple redirects often indicate successful login flow
            if redirect_count >= 2:
                success_score += 2
                reasons.append(f"Redirect chain: {redirect_count} hops {redirect_codes}")
            elif redirect_count == 1:
                success_score += 1
                reasons.append(f"Single redirect ({redirect_codes[0]})")

        # Check for Set-Cookie headers in response (new session establishment)
        set_cookie_headers = response.headers.get('Set-Cookie', '')
        if set_cookie_headers:
            if any(kw in set_cookie_headers.lower() for kw in auth_cookie_keywords):
                success_score += 2
                reasons.append("Auth cookie in response headers")

        # Check for authentication-related headers
        if 'X-Auth-Token' in response.headers or 'Authorization' in response.headers:
            success_score += 2
            reasons.append("Auth header in response")

        # Calculate final score: success signals minus failure signals
        final_score = success_score - failure_score

        # Determine if successful based on final score
        # Score threshold: 3+ points indicates likely success
        # Strong success signals can override failure indicators
        is_success = final_score >= 3

        if reasons:
            reason_str = "; ".join(reasons)
        else:
            reason_str = "No success indicators"

        return is_success, reason_str

    def run(self):
        try:
            # Calculate total based on auth type
            if self.auth_type in [AUTH_TYPE_BEARER, AUTH_TYPE_API_KEY]:
                # For bearer/API key, we test tokens directly
                total = len(self.bearer_tokens) if self.bearer_tokens else len(self.passwords)
                tokens_to_test = self.bearer_tokens if self.bearer_tokens else self.passwords
            else:
                total = len(self.usernames) * len(self.passwords)
                tokens_to_test = None

            current = 0
            found = False

            headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
                'Content-Type': 'application/x-www-form-urlencoded'
            }

            # Establish baseline with wrong credentials
            session = self._reset_session()
            self._establish_baseline(session, headers)

            # Bearer/API Key token testing mode
            if self.auth_type in [AUTH_TYPE_BEARER, AUTH_TYPE_API_KEY]:
                for token in tokens_to_test:
                    if not self.running:
                        break

                    current += 1
                    token = token.strip()

                    # Skip empty lines and comments
                    if not token or token.startswith('#'):
                        continue

                    try:
                        session = self._reset_session()
                        test_headers = headers.copy()

                        if self.auth_type == AUTH_TYPE_BEARER:
                            # Try with and without Bearer prefix
                            if not token.lower().startswith('bearer '):
                                test_headers[self.api_key_header] = f"Bearer {token}"
                            else:
                                test_headers[self.api_key_header] = token
                        else:
                            test_headers[self.api_key_header] = token

                        response = session.get(self.url, headers=test_headers, timeout=10,
                                              verify=False, allow_redirects=True)

                        if response:
                            status_code = response.status_code
                            page_title = self._extract_title(response.text)
                            page_size = len(response.content)
                            response_text = response.text.lower()

                            is_success, reason = self._detect_success(response, session, response_text)

                            # Emit response (use "TOKEN" as username for display)
                            self.response_signal.emit("TOKEN", token[:30], status_code,
                                                     page_title, page_size, is_success, reason)

                            if is_success:
                                response_info = {
                                    'status_code': status_code,
                                    'title': page_title,
                                    'size': page_size,
                                    'url': response.url,
                                    'cookies': list(session.cookies.keys()),
                                    'reason': reason
                                }
                                self.found_signal.emit("VALID_TOKEN", token, response_info)
                                self.found_credentials.append(("TOKEN", token))
                                found = True

                                if self.stop_on_found:
                                    self.running = False
                                    break

                    except Exception as e:
                        self.response_signal.emit("TOKEN", token[:30], 0, f"Error: {str(e)[:30]}", 0, False, "Request error")

                    self.progress_signal.emit(current, total, f"Testing token: {token[:20]}...")

            else:
                # Standard username:password bruteforce
                for username in self.usernames:
                    if not self.running:
                        break

                    for password in self.passwords:
                        if not self.running:
                            break

                        current += 1
                        username = username.strip()
                        password = password.strip()

                        if not username or not password:
                            continue

                        try:
                            # Reset session for each attempt to get clean cookie state
                            session = self._reset_session()

                            # Refresh CSRF token if needed
                            if self.refresh_csrf:
                                self._refresh_csrf_token()

                            response = None

                            if self.auth_type == AUTH_TYPE_BASIC:
                                from requests.auth import HTTPBasicAuth
                                response = session.get(self.url, auth=HTTPBasicAuth(username, password),
                                                      headers=headers, timeout=10, verify=False,
                                                      allow_redirects=True)

                            elif self.auth_type == AUTH_TYPE_DIGEST:
                                from requests.auth import HTTPDigestAuth
                                response = session.get(self.url, auth=HTTPDigestAuth(username, password),
                                                      headers=headers, timeout=10, verify=False,
                                                      allow_redirects=True)

                            elif self.auth_type == AUTH_TYPE_NTLM:
                                try:
                                    from requests_ntlm import HttpNtlmAuth
                                    response = session.get(self.url, auth=HttpNtlmAuth(username, password),
                                                          headers=headers, timeout=10, verify=False,
                                                          allow_redirects=True)
                                except ImportError:
                                    auth_header = base64.b64encode(f"{username}:{password}".encode()).decode()
                                    headers['Authorization'] = f'NTLM {auth_header}'
                                    response = session.get(self.url, headers=headers, timeout=10,
                                                          verify=False, allow_redirects=True)

                            else:
                                # Form-based authentication
                                data = {}
                                for field in self.fields:
                                    if field.get('is_username') or field.get('is_email'):
                                        data[field['name']] = username
                                    elif field.get('is_password'):
                                        data[field['name']] = password
                                    elif field.get('is_csrf'):
                                        data[field['name']] = self.csrf_info.get('value', field.get('value', ''))
                                    elif field.get('value'):
                                        data[field['name']] = field['value']

                                if self.method == 'POST':
                                    response = session.post(self.url, data=data, headers=headers,
                                                           timeout=10, verify=False, allow_redirects=True)
                                else:
                                    response = session.get(self.url, params=data, headers=headers,
                                                          timeout=10, verify=False, allow_redirects=True)

                            if response:
                                status_code = response.status_code
                                page_title = self._extract_title(response.text)
                                page_size = len(response.content)
                                response_text = response.text.lower()

                                # Smart success detection
                                is_success, reason = self._detect_success(response, session, response_text)

                                # Emit response details for table
                                self.response_signal.emit(username, password, status_code,
                                                         page_title, page_size, is_success, reason)

                                if is_success:
                                    response_info = {
                                        'status_code': status_code,
                                        'title': page_title,
                                        'size': page_size,
                                        'url': response.url,
                                        'cookies': list(session.cookies.keys()),
                                        'reason': reason
                                    }
                                    self.found_signal.emit(username, password, response_info)
                                    self.found_credentials.append((username, password))
                                    found = True

                                    # Stop if configured to stop on first match
                                    if self.stop_on_found:
                                        self.running = False
                                        break

                        except Exception as e:
                            self.response_signal.emit(username, password, 0, f"Error: {str(e)[:30]}", 0, False, "Request error")

                        self.progress_signal.emit(current, total, f"Testing: {username}:{password[:8]}...")

            # Final result
            if found:
                count = len(self.found_credentials)
                self.finished_signal.emit(True, f"Found {count} valid credential(s)!")
            else:
                self.finished_signal.emit(False, "No valid credentials found")

        except Exception as e:
            self.finished_signal.emit(False, f"Error: {str(e)}")


class BruteforceTabBuilder:
    """Builder class for creating the HTTP Form Bruteforce tab"""

    def __init__(self, gui, collapsible_box_class):
        self.gui = gui
        self.CollapsibleBox = collapsible_box_class
        self.detector_thread = None
        self.bruteforce_thread = None
        self.detected_fields = []
        self.action_url = ""
        self.form_method = "POST"
        self.auth_type = AUTH_TYPE_FORM
        self.csrf_info = {'found': False, 'name': '', 'value': '', 'type': 'none'}

    def build(self):
        """Create and return the bruteforce tab widget"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(15, 15, 15, 15)
        layout.setSpacing(12)

        # Header
        header = QLabel("HTTP Form Bruteforce")
        header.setFont(QFont("Segoe UI", 16, QFont.Bold))
        header.setStyleSheet("color: #1e293b;")
        layout.addWidget(header)

        desc = QLabel("Detect login form fields and perform credential bruteforce attacks")
        desc.setStyleSheet("color: #64748b; margin-bottom: 10px;")
        layout.addWidget(desc)

        # Main splitter
        splitter = QSplitter(Qt.Horizontal)

        # Left side - Configuration
        left_widget = QWidget()
        left_layout = QVBoxLayout(left_widget)
        left_layout.setContentsMargins(0, 0, 10, 0)

        # URL Input section
        url_group = QGroupBox("Target URL & Options")
        url_group.setStyleSheet(self._get_group_style())
        url_layout = QVBoxLayout(url_group)

        url_row = QHBoxLayout()
        self.gui.brute_url_input = QLineEdit()
        self.gui.brute_url_input.setPlaceholderText("https://example.com/login")
        self.gui.brute_url_input.setMinimumHeight(36)
        self.gui.brute_url_input.setStyleSheet(self._get_input_style())
        url_row.addWidget(self.gui.brute_url_input)

        detect_btn = QPushButton("Detect Fields")
        detect_btn.setMinimumHeight(36)
        detect_btn.setStyleSheet(self._get_primary_button_style())
        detect_btn.clicked.connect(self._detect_fields)
        url_row.addWidget(detect_btn)

        url_layout.addLayout(url_row)

        # Auth type and Proxy row
        options_row = QHBoxLayout()

        # Auth type display/selection
        options_row.addWidget(QLabel("Auth Type:"))
        self.gui.brute_auth_type = QComboBox()
        self.gui.brute_auth_type.addItems([
            "Form-based", "HTTP Basic", "HTTP Digest", "NTLM", "Bearer Token", "API Key"
        ])
        self.gui.brute_auth_type.setStyleSheet(self._get_combo_style())
        self.gui.brute_auth_type.setMinimumWidth(120)
        options_row.addWidget(self.gui.brute_auth_type)

        options_row.addSpacing(20)

        # Proxy input
        options_row.addWidget(QLabel("Proxy:"))
        self.gui.brute_proxy = QLineEdit()
        self.gui.brute_proxy.setPlaceholderText("http://127.0.0.1:8080")
        self.gui.brute_proxy.setStyleSheet(self._get_input_style())
        self.gui.brute_proxy.setMinimumWidth(150)
        options_row.addWidget(self.gui.brute_proxy)

        options_row.addStretch()
        url_layout.addLayout(options_row)

        # CSRF and Auth info display
        info_row = QHBoxLayout()

        # Auth status badge
        self.gui.brute_auth_badge = QLabel("No auth detected")
        self.gui.brute_auth_badge.setStyleSheet("""
            QLabel {
                background-color: #e2e8f0;
                color: #475569;
                padding: 4px 10px;
                border-radius: 10px;
                font-size: 11px;
            }
        """)
        info_row.addWidget(self.gui.brute_auth_badge)

        # CSRF status badge
        self.gui.brute_csrf_badge = QLabel("No CSRF token")
        self.gui.brute_csrf_badge.setStyleSheet("""
            QLabel {
                background-color: #fef3c7;
                color: #92400e;
                padding: 4px 10px;
                border-radius: 10px;
                font-size: 11px;
            }
        """)
        info_row.addWidget(self.gui.brute_csrf_badge)

        # Refresh CSRF checkbox
        self.gui.brute_refresh_csrf = QCheckBox("Refresh CSRF token")
        self.gui.brute_refresh_csrf.setToolTip("Refresh CSRF token for each attempt (slower but more reliable)")
        info_row.addWidget(self.gui.brute_refresh_csrf)

        info_row.addStretch()
        url_layout.addLayout(info_row)

        left_layout.addWidget(url_group)

        # Detected Fields section
        fields_group = QGroupBox("Form Fields")
        fields_group.setStyleSheet(self._get_group_style())
        fields_layout = QVBoxLayout(fields_group)

        # Form info row
        form_info = QHBoxLayout()
        form_info.addWidget(QLabel("Action URL:"))
        self.gui.brute_action_url = QLineEdit()
        self.gui.brute_action_url.setStyleSheet(self._get_input_style())
        form_info.addWidget(self.gui.brute_action_url, 1)

        form_info.addWidget(QLabel("Method:"))
        self.gui.brute_method = QComboBox()
        self.gui.brute_method.addItems(["POST", "GET"])
        self.gui.brute_method.setStyleSheet(self._get_combo_style())
        form_info.addWidget(self.gui.brute_method)

        fields_layout.addLayout(form_info)

        # Fields table - now with Email column
        self.gui.brute_fields_table = QTableWidget()
        self.gui.brute_fields_table.setColumnCount(6)
        self.gui.brute_fields_table.setHorizontalHeaderLabels([
            "Field Name", "Type", "Value", "Username?", "Email?", "Password?"
        ])
        self.gui.brute_fields_table.setMinimumHeight(150)
        self.gui.brute_fields_table.setStyleSheet(self._get_table_style())
        self.gui.brute_fields_table.setAlternatingRowColors(True)

        tbl_header = self.gui.brute_fields_table.horizontalHeader()
        tbl_header.setSectionResizeMode(0, QHeaderView.Stretch)
        tbl_header.setSectionResizeMode(1, QHeaderView.Interactive)
        tbl_header.setSectionResizeMode(2, QHeaderView.Stretch)
        tbl_header.setSectionResizeMode(3, QHeaderView.Interactive)
        tbl_header.setSectionResizeMode(4, QHeaderView.Interactive)
        tbl_header.setSectionResizeMode(5, QHeaderView.Interactive)
        tbl_header.setStretchLastSection(False)
        self.gui.brute_fields_table.setColumnWidth(1, 80)
        self.gui.brute_fields_table.setColumnWidth(3, 80)
        self.gui.brute_fields_table.setColumnWidth(4, 70)
        self.gui.brute_fields_table.setColumnWidth(5, 80)

        fields_layout.addWidget(self.gui.brute_fields_table)

        # Add/remove field buttons
        field_btns = QHBoxLayout()
        add_field_btn = QPushButton("+ Add Field")
        add_field_btn.setStyleSheet(self._get_secondary_button_style())
        add_field_btn.clicked.connect(self._add_field)
        field_btns.addWidget(add_field_btn)

        remove_field_btn = QPushButton("- Remove Field")
        remove_field_btn.setStyleSheet(self._get_secondary_button_style())
        remove_field_btn.clicked.connect(self._remove_field)
        field_btns.addWidget(remove_field_btn)
        field_btns.addStretch()

        fields_layout.addLayout(field_btns)
        left_layout.addWidget(fields_group)

        # Success/Failure indicators
        indicators_group = QGroupBox("Detection Indicators")
        indicators_group.setStyleSheet(self._get_group_style())
        indicators_layout = QGridLayout(indicators_group)

        indicators_layout.addWidget(QLabel("Success indicators:"), 0, 0)
        self.gui.brute_success_indicators = QLineEdit()
        self.gui.brute_success_indicators.setPlaceholderText("dashboard, welcome, logout, my account")
        self.gui.brute_success_indicators.setStyleSheet(self._get_input_style())
        indicators_layout.addWidget(self.gui.brute_success_indicators, 0, 1)

        indicators_layout.addWidget(QLabel("Failure indicators:"), 1, 0)
        self.gui.brute_failure_indicators = QLineEdit()
        self.gui.brute_failure_indicators.setText("invalid, incorrect, failed, error, wrong password")
        self.gui.brute_failure_indicators.setStyleSheet(self._get_input_style())
        indicators_layout.addWidget(self.gui.brute_failure_indicators, 1, 1)

        left_layout.addWidget(indicators_group)
        left_layout.addStretch()

        splitter.addWidget(left_widget)

        # Right side - Wordlists and Results with tabs
        right_widget = QWidget()
        right_layout = QVBoxLayout(right_widget)
        right_layout.setContentsMargins(10, 0, 0, 0)

        # Create tabs for wordlists
        wordlist_tabs = QTabWidget()
        wordlist_tabs.setStyleSheet("""
            QTabWidget::pane { border: 1px solid #e2e8f0; border-radius: 6px; background: white; }
            QTabBar::tab { padding: 8px 16px; background: #f1f5f9; border: 1px solid #e2e8f0; border-bottom: none; }
            QTabBar::tab:selected { background: white; border-bottom: 2px solid #3b82f6; }
        """)

        # Tab 1: Wordlists
        wordlist_tab = QWidget()
        wordlist_layout = QVBoxLayout(wordlist_tab)
        wordlist_layout.setContentsMargins(10, 10, 10, 10)

        # Usernames section
        user_label = QLabel("Usernames (Top 20 default):")
        user_label.setStyleSheet("font-weight: bold; color: #475569;")
        wordlist_layout.addWidget(user_label)

        user_row = QHBoxLayout()
        self.gui.brute_usernames = QTextEdit()
        self.gui.brute_usernames.setText(DEFAULT_USERNAMES)
        self.gui.brute_usernames.setMaximumHeight(100)
        self.gui.brute_usernames.setStyleSheet(self._get_textedit_style())
        user_row.addWidget(self.gui.brute_usernames, 1)

        user_btns = QVBoxLayout()
        load_users_btn = QPushButton("Load File")
        load_users_btn.setStyleSheet(self._get_secondary_button_style())
        load_users_btn.clicked.connect(lambda: self._load_wordlist('usernames'))
        user_btns.addWidget(load_users_btn)

        clear_users_btn = QPushButton("Clear")
        clear_users_btn.setStyleSheet(self._get_secondary_button_style())
        clear_users_btn.clicked.connect(lambda: self.gui.brute_usernames.clear())
        user_btns.addWidget(clear_users_btn)
        user_btns.addStretch()
        user_row.addLayout(user_btns)

        wordlist_layout.addLayout(user_row)

        # Passwords section
        pass_label = QLabel("Passwords (Top 100 default):")
        pass_label.setStyleSheet("font-weight: bold; color: #475569;")
        wordlist_layout.addWidget(pass_label)

        pass_row = QHBoxLayout()
        self.gui.brute_passwords = QTextEdit()
        self.gui.brute_passwords.setText(DEFAULT_PASSWORDS)
        self.gui.brute_passwords.setMaximumHeight(100)
        self.gui.brute_passwords.setStyleSheet(self._get_textedit_style())
        pass_row.addWidget(self.gui.brute_passwords, 1)

        pass_btns = QVBoxLayout()
        load_pass_btn = QPushButton("Load File")
        load_pass_btn.setStyleSheet(self._get_secondary_button_style())
        load_pass_btn.clicked.connect(lambda: self._load_wordlist('passwords'))
        pass_btns.addWidget(load_pass_btn)

        clear_pass_btn = QPushButton("Clear")
        clear_pass_btn.setStyleSheet(self._get_secondary_button_style())
        clear_pass_btn.clicked.connect(lambda: self.gui.brute_passwords.clear())
        pass_btns.addWidget(clear_pass_btn)
        pass_btns.addStretch()
        pass_row.addLayout(pass_btns)

        wordlist_layout.addLayout(pass_row)

        # Quick load buttons
        quick_load = QHBoxLayout()
        quick_load.addWidget(QLabel("Quick Load:"))

        load_short_btn = QPushButton("Short (4-6 chars)")
        load_short_btn.setStyleSheet(self._get_secondary_button_style())
        load_short_btn.clicked.connect(lambda: self._load_builtin_wordlist('short'))
        quick_load.addWidget(load_short_btn)

        load_numeric_btn = QPushButton("Numeric Only")
        load_numeric_btn.setStyleSheet(self._get_secondary_button_style())
        load_numeric_btn.clicked.connect(lambda: self._load_builtin_wordlist('numeric'))
        quick_load.addWidget(load_numeric_btn)

        load_top100_btn = QPushButton("Top 100")
        load_top100_btn.setStyleSheet(self._get_secondary_button_style())
        load_top100_btn.clicked.connect(lambda: self._load_builtin_wordlist('top100'))
        quick_load.addWidget(load_top100_btn)

        quick_load.addStretch()
        wordlist_layout.addLayout(quick_load)

        wordlist_tabs.addTab(wordlist_tab, "Wordlists")

        # Tab 2: Filters
        filter_tab = QWidget()
        filter_layout = QVBoxLayout(filter_tab)
        filter_layout.setContentsMargins(10, 10, 10, 10)

        filter_label = QLabel("Password Length Filter:")
        filter_label.setStyleSheet("font-weight: bold; color: #475569;")
        filter_layout.addWidget(filter_label)

        len_row = QHBoxLayout()
        len_row.addWidget(QLabel("Min length:"))
        self.gui.brute_min_len = QSpinBox()
        self.gui.brute_min_len.setRange(0, 100)
        self.gui.brute_min_len.setValue(0)
        self.gui.brute_min_len.setStyleSheet(self._get_input_style())
        len_row.addWidget(self.gui.brute_min_len)

        len_row.addWidget(QLabel("Max length:"))
        self.gui.brute_max_len = QSpinBox()
        self.gui.brute_max_len.setRange(0, 100)
        self.gui.brute_max_len.setValue(0)
        self.gui.brute_max_len.setStyleSheet(self._get_input_style())
        len_row.addWidget(self.gui.brute_max_len)

        apply_filter_btn = QPushButton("Apply Filter")
        apply_filter_btn.setStyleSheet(self._get_primary_button_style())
        apply_filter_btn.clicked.connect(self._apply_password_filter)
        len_row.addWidget(apply_filter_btn)

        len_row.addStretch()
        filter_layout.addLayout(len_row)

        # Character type filters
        char_label = QLabel("Character Type Filter:")
        char_label.setStyleSheet("font-weight: bold; color: #475569; margin-top: 10px;")
        filter_layout.addWidget(char_label)

        char_row = QHBoxLayout()
        self.gui.brute_filter_numeric = QCheckBox("Numeric only")
        self.gui.brute_filter_alpha = QCheckBox("Letters only")
        self.gui.brute_filter_alphanum = QCheckBox("Alphanumeric")
        char_row.addWidget(self.gui.brute_filter_numeric)
        char_row.addWidget(self.gui.brute_filter_alpha)
        char_row.addWidget(self.gui.brute_filter_alphanum)
        char_row.addStretch()
        filter_layout.addLayout(char_row)

        filter_layout.addStretch()
        wordlist_tabs.addTab(filter_tab, "Filters")

        # Tab 3: Generator
        gen_tab = QWidget()
        gen_layout = QVBoxLayout(gen_tab)
        gen_layout.setContentsMargins(10, 10, 10, 10)

        gen_label = QLabel("Password Generator Tools")
        gen_label.setStyleSheet("font-weight: bold; color: #1e293b; font-size: 13px; margin-bottom: 5px;")
        gen_layout.addWidget(gen_label)

        # Number range generator - using QGroupBox for proper styling
        num_group = QGroupBox("Number Range Generator")
        num_group.setStyleSheet("""
            QGroupBox {
                font-weight: bold;
                font-size: 12px;
                color: #1e293b;
                border: 1px solid #e2e8f0;
                border-radius: 6px;
                margin-top: 10px;
                padding-top: 10px;
                background: #f8fafc;
            }
            QGroupBox::title {
                subcontrol-origin: margin;
                left: 10px;
                padding: 0 5px;
            }
            QLabel { font-size: 11px; color: #475569; font-weight: normal; }
        """)
        num_layout = QVBoxLayout(num_group)
        num_layout.setContentsMargins(10, 15, 10, 10)
        num_layout.setSpacing(8)

        num_row = QHBoxLayout()
        from_label = QLabel("From:")
        num_row.addWidget(from_label)
        self.gui.brute_gen_from = QSpinBox()
        self.gui.brute_gen_from.setRange(0, 999999)
        self.gui.brute_gen_from.setValue(1)
        self.gui.brute_gen_from.setMinimumWidth(80)
        num_row.addWidget(self.gui.brute_gen_from)

        to_label = QLabel("To:")
        num_row.addWidget(to_label)
        self.gui.brute_gen_to = QSpinBox()
        self.gui.brute_gen_to.setRange(0, 999999)
        self.gui.brute_gen_to.setValue(2000)
        self.gui.brute_gen_to.setMinimumWidth(80)
        num_row.addWidget(self.gui.brute_gen_to)

        gen_num_btn = QPushButton("Generate Numbers")
        gen_num_btn.setStyleSheet(self._get_primary_button_style())
        gen_num_btn.clicked.connect(self._generate_numbers)
        num_row.addWidget(gen_num_btn)

        num_row.addStretch()
        num_layout.addLayout(num_row)

        gen_layout.addWidget(num_group)

        # Pattern generator - using QGroupBox for proper styling
        pattern_group = QGroupBox("Pattern Generator")
        pattern_group.setStyleSheet("""
            QGroupBox {
                font-weight: bold;
                font-size: 12px;
                color: #1e293b;
                border: 1px solid #e2e8f0;
                border-radius: 6px;
                margin-top: 10px;
                padding-top: 10px;
                background: #f8fafc;
            }
            QGroupBox::title {
                subcontrol-origin: margin;
                left: 10px;
                padding: 0 5px;
            }
            QLabel { font-size: 11px; color: #475569; font-weight: normal; }
        """)
        pattern_layout = QVBoxLayout(pattern_group)
        pattern_layout.setContentsMargins(10, 15, 10, 10)
        pattern_layout.setSpacing(8)

        pattern_row = QHBoxLayout()
        base_label = QLabel("Base word:")
        pattern_row.addWidget(base_label)
        self.gui.brute_gen_base = QLineEdit()
        self.gui.brute_gen_base.setPlaceholderText("e.g., password, admin")
        self.gui.brute_gen_base.setMinimumHeight(32)
        pattern_row.addWidget(self.gui.brute_gen_base, 1)

        gen_pattern_btn = QPushButton("Generate Variants")
        gen_pattern_btn.setStyleSheet(self._get_primary_button_style())
        gen_pattern_btn.clicked.connect(self._generate_variants)
        pattern_row.addWidget(gen_pattern_btn)

        pattern_layout.addLayout(pattern_row)

        pattern_help = QLabel("Generates: base, Base, BASE, base123, base1, base!, base@123, etc.")
        pattern_layout.addWidget(pattern_help)

        gen_layout.addWidget(pattern_group)

        # Year generator - using QGroupBox for proper styling
        year_group = QGroupBox("Year-based Generator")
        year_group.setStyleSheet("""
            QGroupBox {
                font-weight: bold;
                font-size: 12px;
                color: #1e293b;
                border: 1px solid #e2e8f0;
                border-radius: 6px;
                margin-top: 10px;
                padding-top: 10px;
                background: #f8fafc;
            }
            QGroupBox::title {
                subcontrol-origin: margin;
                left: 10px;
                padding: 0 5px;
            }
        """)
        year_layout = QVBoxLayout(year_group)
        year_layout.setContentsMargins(10, 15, 10, 10)
        year_layout.setSpacing(8)

        year_row = QHBoxLayout()
        gen_years_btn = QPushButton("Generate Years (1990-2025)")
        gen_years_btn.setStyleSheet(self._get_secondary_button_style())
        gen_years_btn.clicked.connect(self._generate_years)
        year_row.addWidget(gen_years_btn)

        gen_dates_btn = QPushButton("Generate Common Dates")
        gen_dates_btn.setStyleSheet(self._get_secondary_button_style())
        gen_dates_btn.clicked.connect(self._generate_dates)
        year_row.addWidget(gen_dates_btn)

        year_row.addStretch()
        year_layout.addLayout(year_row)

        gen_layout.addWidget(year_group)

        gen_layout.addStretch()
        wordlist_tabs.addTab(gen_tab, "Generator")

        # Tab 4: Bearer Tokens / API Keys
        token_tab = QWidget()
        token_layout = QVBoxLayout(token_tab)
        token_layout.setContentsMargins(10, 10, 10, 10)

        token_label = QLabel("Bearer Tokens / API Keys:")
        token_label.setStyleSheet("font-weight: bold; color: #475569;")
        token_layout.addWidget(token_label)

        token_desc = QLabel("Used when Auth Type is 'Bearer Token' or 'API Key'. Includes 200+ known default/weak tokens.")
        token_desc.setStyleSheet("color: #64748b; font-size: 11px; margin-bottom: 5px;")
        token_desc.setWordWrap(True)
        token_layout.addWidget(token_desc)

        token_row = QHBoxLayout()
        self.gui.brute_bearer_tokens = QTextEdit()
        self.gui.brute_bearer_tokens.setPlaceholderText("Enter tokens one per line, or load default tokens...")
        self.gui.brute_bearer_tokens.setStyleSheet(self._get_textedit_style())
        token_row.addWidget(self.gui.brute_bearer_tokens, 1)

        token_btns = QVBoxLayout()
        load_default_tokens_btn = QPushButton("Load Default")
        load_default_tokens_btn.setStyleSheet(self._get_primary_button_style())
        load_default_tokens_btn.setToolTip("Load 200+ known weak/default tokens")
        load_default_tokens_btn.clicked.connect(self._load_default_bearer_tokens)
        token_btns.addWidget(load_default_tokens_btn)

        load_tokens_file_btn = QPushButton("Load File")
        load_tokens_file_btn.setStyleSheet(self._get_secondary_button_style())
        load_tokens_file_btn.clicked.connect(lambda: self._load_wordlist('tokens'))
        token_btns.addWidget(load_tokens_file_btn)

        clear_tokens_btn = QPushButton("Clear")
        clear_tokens_btn.setStyleSheet(self._get_secondary_button_style())
        clear_tokens_btn.clicked.connect(lambda: self.gui.brute_bearer_tokens.clear())
        token_btns.addWidget(clear_tokens_btn)
        token_btns.addStretch()
        token_row.addLayout(token_btns)

        token_layout.addLayout(token_row)

        # API Key header configuration
        header_row = QHBoxLayout()
        header_row.addWidget(QLabel("Header Name:"))
        self.gui.brute_api_header = QLineEdit()
        self.gui.brute_api_header.setText("Authorization")
        self.gui.brute_api_header.setPlaceholderText("Authorization, X-API-Key, etc.")
        self.gui.brute_api_header.setStyleSheet(self._get_input_style())
        self.gui.brute_api_header.setMinimumWidth(200)
        header_row.addWidget(self.gui.brute_api_header)
        header_row.addStretch()
        token_layout.addLayout(header_row)

        token_layout.addStretch()
        wordlist_tabs.addTab(token_tab, "Tokens/API")

        # Tab 5: Emails
        email_tab = QWidget()
        email_layout = QVBoxLayout(email_tab)
        email_layout.setContentsMargins(10, 10, 10, 10)

        email_label = QLabel("Email Addresses:")
        email_label.setStyleSheet("font-weight: bold; color: #475569;")
        email_layout.addWidget(email_label)

        email_desc = QLabel("Used for login forms that use email as username. Mark the field as 'Email?' in Form Fields.")
        email_desc.setStyleSheet("color: #64748b; font-size: 11px; margin-bottom: 5px;")
        email_desc.setWordWrap(True)
        email_layout.addWidget(email_desc)

        email_row = QHBoxLayout()
        self.gui.brute_emails = QTextEdit()
        self.gui.brute_emails.setText(DEFAULT_EMAILS)
        self.gui.brute_emails.setStyleSheet(self._get_textedit_style())
        email_row.addWidget(self.gui.brute_emails, 1)

        email_btns = QVBoxLayout()
        load_emails_btn = QPushButton("Load File")
        load_emails_btn.setStyleSheet(self._get_secondary_button_style())
        load_emails_btn.clicked.connect(lambda: self._load_wordlist('emails'))
        email_btns.addWidget(load_emails_btn)

        clear_emails_btn = QPushButton("Clear")
        clear_emails_btn.setStyleSheet(self._get_secondary_button_style())
        clear_emails_btn.clicked.connect(lambda: self.gui.brute_emails.clear())
        email_btns.addWidget(clear_emails_btn)

        gen_emails_btn = QPushButton("Generate")
        gen_emails_btn.setStyleSheet(self._get_secondary_button_style())
        gen_emails_btn.setToolTip("Generate email variants from usernames")
        gen_emails_btn.clicked.connect(self._generate_emails)
        email_btns.addWidget(gen_emails_btn)

        email_btns.addStretch()
        email_row.addLayout(email_btns)

        email_layout.addLayout(email_row)

        # Domain input for email generation
        domain_row = QHBoxLayout()
        domain_row.addWidget(QLabel("Domain for generation:"))
        self.gui.brute_email_domain = QLineEdit()
        self.gui.brute_email_domain.setText("example.com")
        self.gui.brute_email_domain.setPlaceholderText("example.com")
        self.gui.brute_email_domain.setStyleSheet(self._get_input_style())
        self.gui.brute_email_domain.setMinimumWidth(200)
        domain_row.addWidget(self.gui.brute_email_domain)
        domain_row.addStretch()
        email_layout.addLayout(domain_row)

        email_layout.addStretch()
        wordlist_tabs.addTab(email_tab, "Emails")

        right_layout.addWidget(wordlist_tabs)

        # Results section
        results_group = QGroupBox("Results")
        results_group.setStyleSheet(self._get_group_style())
        results_layout = QVBoxLayout(results_group)

        # Progress bar
        self.gui.brute_progress = QProgressBar()
        self.gui.brute_progress.setMinimumHeight(24)
        self.gui.brute_progress.setStyleSheet("""
            QProgressBar {
                border: 1px solid #e2e8f0;
                border-radius: 4px;
                text-align: center;
                background-color: #f1f5f9;
            }
            QProgressBar::chunk {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
                    stop:0 #3b82f6, stop:1 #2563eb);
                border-radius: 3px;
            }
        """)
        results_layout.addWidget(self.gui.brute_progress)

        # Status and baseline info
        status_row = QHBoxLayout()
        self.gui.brute_status = QLabel("Ready")
        self.gui.brute_status.setStyleSheet("color: #64748b;")
        status_row.addWidget(self.gui.brute_status)

        self.gui.brute_baseline_info = QLabel("")
        self.gui.brute_baseline_info.setStyleSheet("color: #94a3b8; font-size: 11px;")
        status_row.addWidget(self.gui.brute_baseline_info)
        status_row.addStretch()
        results_layout.addLayout(status_row)

        # Found credentials (success) table
        found_label = QLabel("Valid Credentials Found:")
        found_label.setStyleSheet("font-weight: bold; color: #22c55e; margin-top: 5px;")
        results_layout.addWidget(found_label)

        self.gui.brute_results_table = QTableWidget()
        self.gui.brute_results_table.setColumnCount(4)
        self.gui.brute_results_table.setHorizontalHeaderLabels(["Username", "Password", "Reason", "URL"])
        self.gui.brute_results_table.setStyleSheet(self._get_table_style())
        self.gui.brute_results_table.setSortingEnabled(True)
        self.gui.brute_results_table.setAlternatingRowColors(True)
        header = self.gui.brute_results_table.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.Interactive)
        header.setSectionResizeMode(1, QHeaderView.Interactive)
        header.setSectionResizeMode(2, QHeaderView.Stretch)
        header.setSectionResizeMode(3, QHeaderView.Stretch)
        header.setStretchLastSection(True)
        self.gui.brute_results_table.setMinimumHeight(100)
        self.gui.brute_results_table.setMaximumHeight(200)
        results_layout.addWidget(self.gui.brute_results_table)

        # Response details table header with clear button
        response_header = QHBoxLayout()
        response_label = QLabel("Response Details (all attempts):")
        response_label.setStyleSheet("font-weight: bold; color: #475569; margin-top: 5px;")
        response_header.addWidget(response_label)
        response_header.addStretch()

        clear_resp_btn = QPushButton("Clear Log")
        clear_resp_btn.setFixedWidth(80)
        clear_resp_btn.setStyleSheet("""
            QPushButton {
                background-color: #ef4444;
                color: white;
                border: none;
                border-radius: 4px;
                padding: 4px 8px;
                font-size: 11px;
            }
            QPushButton:hover {
                background-color: #dc2626;
            }
        """)
        clear_resp_btn.clicked.connect(lambda: self.gui.brute_response_table.setRowCount(0))
        response_header.addWidget(clear_resp_btn)
        results_layout.addLayout(response_header)

        self.gui.brute_response_table = QTableWidget()
        self.gui.brute_response_table.setColumnCount(7)
        self.gui.brute_response_table.setHorizontalHeaderLabels([
            "Username", "Password", "Status", "Title", "Size", "Success", "Reason"
        ])
        self.gui.brute_response_table.setStyleSheet(self._get_table_style())
        self.gui.brute_response_table.setSortingEnabled(True)
        self.gui.brute_response_table.setAlternatingRowColors(True)
        resp_header = self.gui.brute_response_table.horizontalHeader()
        resp_header.setSectionResizeMode(0, QHeaderView.Interactive)
        resp_header.setSectionResizeMode(1, QHeaderView.Interactive)
        resp_header.setSectionResizeMode(2, QHeaderView.Interactive)
        resp_header.setSectionResizeMode(3, QHeaderView.Stretch)
        resp_header.setSectionResizeMode(4, QHeaderView.Interactive)
        resp_header.setSectionResizeMode(5, QHeaderView.Interactive)
        resp_header.setSectionResizeMode(6, QHeaderView.Stretch)
        resp_header.setStretchLastSection(True)
        self.gui.brute_response_table.setColumnWidth(2, 60)
        self.gui.brute_response_table.setColumnWidth(4, 70)
        self.gui.brute_response_table.setColumnWidth(5, 60)
        self.gui.brute_response_table.setMinimumHeight(200)
        results_layout.addWidget(self.gui.brute_response_table)

        right_layout.addWidget(results_group)

        # Control options row
        options_control = QHBoxLayout()

        # Stop on first match checkbox
        self.gui.brute_stop_on_found = QCheckBox("Stop on first match")
        self.gui.brute_stop_on_found.setChecked(True)
        self.gui.brute_stop_on_found.setToolTip("Stop bruteforce when first valid credential is found")
        self.gui.brute_stop_on_found.setStyleSheet("color: #475569; font-weight: bold;")
        options_control.addWidget(self.gui.brute_stop_on_found)

        # Use emails checkbox
        self.gui.brute_use_emails = QCheckBox("Use emails as usernames")
        self.gui.brute_use_emails.setToolTip("Also try email addresses from the Emails tab")
        self.gui.brute_use_emails.setStyleSheet("color: #475569;")
        options_control.addWidget(self.gui.brute_use_emails)

        options_control.addStretch()
        right_layout.addLayout(options_control)

        # Control buttons
        controls = QHBoxLayout()

        self.gui.brute_start_btn = QPushButton("Start Bruteforce")
        self.gui.brute_start_btn.setMinimumHeight(40)
        self.gui.brute_start_btn.setStyleSheet("""
            QPushButton {
                background-color: #22c55e;
                color: white;
                border: none;
                border-radius: 6px;
                font-weight: bold;
                font-size: 13px;
            }
            QPushButton:hover { background-color: #16a34a; }
            QPushButton:disabled { background-color: #94a3b8; }
        """)
        self.gui.brute_start_btn.clicked.connect(self._start_bruteforce)
        controls.addWidget(self.gui.brute_start_btn)

        self.gui.brute_stop_btn = QPushButton("Stop")
        self.gui.brute_stop_btn.setMinimumHeight(40)
        self.gui.brute_stop_btn.setEnabled(False)
        self.gui.brute_stop_btn.setStyleSheet("""
            QPushButton {
                background-color: #ef4444;
                color: white;
                border: none;
                border-radius: 6px;
                font-weight: bold;
                font-size: 13px;
            }
            QPushButton:hover { background-color: #dc2626; }
            QPushButton:disabled { background-color: #94a3b8; }
        """)
        self.gui.brute_stop_btn.clicked.connect(self._stop_bruteforce)
        controls.addWidget(self.gui.brute_stop_btn)

        right_layout.addLayout(controls)

        splitter.addWidget(right_widget)
        splitter.setSizes([450, 550])

        layout.addWidget(splitter)

        return widget

    def _detect_fields(self):
        """Detect form fields from URL"""
        url = self.gui.brute_url_input.text().strip()
        if not url:
            QMessageBox.warning(self.gui, "Error", "Please enter a URL")
            return

        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url
            self.gui.brute_url_input.setText(url)

        self.gui.brute_status.setText("Detecting auth type and form fields...")

        # Get proxy if set
        proxy = self.gui.brute_proxy.text().strip() or None

        self.detector_thread = FormFieldDetector(url, proxy)
        self.detector_thread.fields_detected.connect(self._on_fields_detected)
        self.detector_thread.error_signal.connect(self._on_detection_error)
        self.detector_thread.start()

    def _on_fields_detected(self, fields, action_url, method, auth_type, csrf_info):
        """Handle detected fields, auth type, and CSRF info"""
        self.detected_fields = fields
        self.action_url = action_url
        self.form_method = method
        self.auth_type = auth_type
        self.csrf_info = csrf_info

        self.gui.brute_action_url.setText(action_url)
        self.gui.brute_method.setCurrentText(method)

        # Update auth type dropdown and badge
        auth_type_map = {
            AUTH_TYPE_FORM: ("Form-based", "Form-based Auth", "#22c55e"),
            AUTH_TYPE_BASIC: ("HTTP Basic", "HTTP Basic Auth", "#3b82f6"),
            AUTH_TYPE_DIGEST: ("HTTP Digest", "HTTP Digest Auth", "#8b5cf6"),
            AUTH_TYPE_NTLM: ("NTLM", "NTLM/Windows Auth", "#f97316"),
            AUTH_TYPE_BEARER: ("Bearer Token", "Bearer Token Auth", "#ec4899"),
            AUTH_TYPE_API_KEY: ("API Key", "API Key Auth", "#14b8a6"),
        }

        auth_display, auth_badge_text, auth_color = auth_type_map.get(auth_type, ("Form-based", "Unknown Auth", "#94a3b8"))
        self.gui.brute_auth_type.setCurrentText(auth_display)
        self.gui.brute_auth_badge.setText(auth_badge_text)
        self.gui.brute_auth_badge.setStyleSheet(f"""
            QLabel {{
                background-color: {auth_color};
                color: white;
                padding: 4px 10px;
                border-radius: 10px;
                font-size: 11px;
                font-weight: bold;
            }}
        """)

        # Update CSRF badge
        if csrf_info.get('found'):
            self.gui.brute_csrf_badge.setText(f"CSRF: {csrf_info.get('name', 'token')[:15]}")
            self.gui.brute_csrf_badge.setStyleSheet("""
                QLabel {
                    background-color: #22c55e;
                    color: white;
                    padding: 4px 10px;
                    border-radius: 10px;
                    font-size: 11px;
                    font-weight: bold;
                }
            """)
            self.gui.brute_refresh_csrf.setChecked(True)
        else:
            self.gui.brute_csrf_badge.setText("No CSRF token")
            self.gui.brute_csrf_badge.setStyleSheet("""
                QLabel {
                    background-color: #fef3c7;
                    color: #92400e;
                    padding: 4px 10px;
                    border-radius: 10px;
                    font-size: 11px;
                }
            """)

        # Populate table
        self.gui.brute_fields_table.setRowCount(len(fields))

        for i, field in enumerate(fields):
            # Name
            name_item = QTableWidgetItem(field['name'])
            # Highlight CSRF fields
            if field.get('is_csrf'):
                name_item.setBackground(QBrush(QColor("#fef3c7")))
            self.gui.brute_fields_table.setItem(i, 0, name_item)

            # Type
            type_item = QTableWidgetItem(field['type'])
            self.gui.brute_fields_table.setItem(i, 1, type_item)

            # Value
            value_item = QTableWidgetItem(field.get('value', ''))
            self.gui.brute_fields_table.setItem(i, 2, value_item)

            # Username checkbox
            user_check = QCheckBox()
            user_check.setChecked(field.get('is_username', False))
            user_widget = QWidget()
            user_layout = QHBoxLayout(user_widget)
            user_layout.addWidget(user_check)
            user_layout.setAlignment(Qt.AlignCenter)
            user_layout.setContentsMargins(0, 0, 0, 0)
            self.gui.brute_fields_table.setCellWidget(i, 3, user_widget)

            # Email checkbox - detect if field looks like email
            email_check = QCheckBox()
            is_email = self._is_email_field(field['name'], field.get('id', ''), field.get('placeholder', ''))
            email_check.setChecked(is_email)
            email_widget = QWidget()
            email_layout = QHBoxLayout(email_widget)
            email_layout.addWidget(email_check)
            email_layout.setAlignment(Qt.AlignCenter)
            email_layout.setContentsMargins(0, 0, 0, 0)
            self.gui.brute_fields_table.setCellWidget(i, 4, email_widget)

            # Password checkbox
            pass_check = QCheckBox()
            pass_check.setChecked(field.get('is_password', False))
            pass_widget = QWidget()
            pass_layout = QHBoxLayout(pass_widget)
            pass_layout.addWidget(pass_check)
            pass_layout.setAlignment(Qt.AlignCenter)
            pass_layout.setContentsMargins(0, 0, 0, 0)
            self.gui.brute_fields_table.setCellWidget(i, 5, pass_widget)

        if auth_type in [AUTH_TYPE_BASIC, AUTH_TYPE_DIGEST, AUTH_TYPE_NTLM]:
            self.gui.brute_status.setText(f"Detected {auth_badge_text} - no form fields needed")
        else:
            self.gui.brute_status.setText(f"Detected {len(fields)} form fields" + (f" with CSRF token" if csrf_info.get('found') else ""))

    def _on_detection_error(self, error):
        """Handle detection error"""
        self.gui.brute_status.setText(f"Error: {error}")

        # Provide more helpful message for Cloudflare/WAF issues
        if 'cloudflare' in error.lower() or 'waf' in error.lower():
            detailed_msg = f"{error}\n\n"
            detailed_msg += "The target appears to be behind WAF protection.\n\n"
            detailed_msg += "Options:\n"
            detailed_msg += "1. Add form fields manually using '+ Add Field' button\n"
            detailed_msg += "2. Use a proxy/VPN that can bypass Cloudflare\n"
            detailed_msg += "3. For WordPress: Common fields are 'log' (username) and 'pwd' (password)\n"
            detailed_msg += "4. Check if the site has an API endpoint without WAF\n"
            QMessageBox.warning(self.gui, "WAF Protection Detected", detailed_msg)
        else:
            QMessageBox.warning(self.gui, "Detection Error", error)

    def _is_email_field(self, name, field_id, placeholder):
        """Check if this looks like an email field"""
        email_patterns = ['email', 'e-mail', 'mail', 'correo']
        text = f"{name} {field_id} {placeholder}".lower()
        return any(p in text for p in email_patterns)

    def _add_field(self):
        """Add a new field row"""
        row = self.gui.brute_fields_table.rowCount()
        self.gui.brute_fields_table.insertRow(row)

        self.gui.brute_fields_table.setItem(row, 0, QTableWidgetItem(""))
        self.gui.brute_fields_table.setItem(row, 1, QTableWidgetItem("text"))
        self.gui.brute_fields_table.setItem(row, 2, QTableWidgetItem(""))

        # Add checkboxes for Username?, Email?, Password?
        for col in [3, 4, 5]:
            check = QCheckBox()
            widget = QWidget()
            layout = QHBoxLayout(widget)
            layout.addWidget(check)
            layout.setAlignment(Qt.AlignCenter)
            layout.setContentsMargins(0, 0, 0, 0)
            self.gui.brute_fields_table.setCellWidget(row, col, widget)

    def _remove_field(self):
        """Remove selected field row"""
        row = self.gui.brute_fields_table.currentRow()
        if row >= 0:
            self.gui.brute_fields_table.removeRow(row)

    def _load_wordlist(self, target):
        """Load wordlist from file"""
        filename, _ = QFileDialog.getOpenFileName(
            self.gui, f"Load {target.title()} Wordlist",
            "", "Text Files (*.txt);;All Files (*.*)"
        )
        if filename:
            try:
                with open(filename, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()
                if target == 'usernames':
                    self.gui.brute_usernames.setText(content)
                elif target == 'passwords':
                    self.gui.brute_passwords.setText(content)
                elif target == 'emails':
                    self.gui.brute_emails.setText(content)
                elif target == 'tokens':
                    self.gui.brute_bearer_tokens.setText(content)
            except Exception as e:
                QMessageBox.warning(self.gui, "Error", f"Failed to load file: {e}")

    def _load_default_bearer_tokens(self):
        """Load default bearer tokens and API keys"""
        # Filter out comments and empty lines
        tokens = [t.strip() for t in DEFAULT_BEARER_TOKENS.split('\n')
                  if t.strip() and not t.strip().startswith('#')]
        self.gui.brute_bearer_tokens.setText('\n'.join(tokens))
        self.gui.brute_status.setText(f"Loaded {len(tokens)} default tokens")

    def _generate_emails(self):
        """Generate email addresses from usernames"""
        domain = self.gui.brute_email_domain.text().strip() or "example.com"
        usernames = [u.strip() for u in self.gui.brute_usernames.toPlainText().split('\n') if u.strip()]

        emails = set()
        for username in usernames:
            # Basic email
            emails.add(f"{username}@{domain}")
            # Common variations
            emails.add(f"{username.lower()}@{domain}")
            if '.' not in username and len(username) > 3:
                # first.last variations
                emails.add(f"{username[0]}.{username[1:]}@{domain}")

        # Append to current emails
        current = self.gui.brute_emails.toPlainText().strip()
        if current:
            current += '\n'

        self.gui.brute_emails.setText(current + '\n'.join(sorted(emails)))
        self.gui.brute_status.setText(f"Generated {len(emails)} emails from usernames")

    def _start_bruteforce(self):
        """Start bruteforce attack with auth type and CSRF support"""
        # Get auth type from dropdown
        auth_type_map = {
            "Form-based": AUTH_TYPE_FORM,
            "HTTP Basic": AUTH_TYPE_BASIC,
            "HTTP Digest": AUTH_TYPE_DIGEST,
            "NTLM": AUTH_TYPE_NTLM,
            "Bearer Token": AUTH_TYPE_BEARER,
            "API Key": AUTH_TYPE_API_KEY,
        }
        selected_auth = self.gui.brute_auth_type.currentText()
        auth_type = auth_type_map.get(selected_auth, self.auth_type)

        # Get fields from table (only needed for form-based auth)
        fields = []
        for row in range(self.gui.brute_fields_table.rowCount()):
            name_item = self.gui.brute_fields_table.item(row, 0)
            value_item = self.gui.brute_fields_table.item(row, 2)

            user_widget = self.gui.brute_fields_table.cellWidget(row, 3)
            email_widget = self.gui.brute_fields_table.cellWidget(row, 4)
            pass_widget = self.gui.brute_fields_table.cellWidget(row, 5)

            is_user = user_widget.findChild(QCheckBox).isChecked() if user_widget else False
            is_email = email_widget.findChild(QCheckBox).isChecked() if email_widget else False
            is_pass = pass_widget.findChild(QCheckBox).isChecked() if pass_widget else False

            # Check if it's a CSRF field by name
            field_name = name_item.text() if name_item else ''
            is_csrf = any(kw in field_name.lower() for kw in ['csrf', 'token', 'authenticity', 'nonce', 'xsrf'])

            fields.append({
                'name': field_name,
                'value': value_item.text() if value_item else '',
                'is_username': is_user,
                'is_email': is_email,
                'is_password': is_pass,
                'is_csrf': is_csrf
            })

        # For Bearer/API Key auth, fields are not required
        if auth_type not in [AUTH_TYPE_BASIC, AUTH_TYPE_DIGEST, AUTH_TYPE_NTLM, AUTH_TYPE_BEARER, AUTH_TYPE_API_KEY] and not fields:
            QMessageBox.warning(self.gui, "Error", "No form fields defined")
            return

        # Get wordlists
        usernames = [u for u in self.gui.brute_usernames.toPlainText().split('\n') if u.strip()]
        passwords = [p for p in self.gui.brute_passwords.toPlainText().split('\n') if p.strip()]

        # Add emails to usernames if option is checked
        if self.gui.brute_use_emails.isChecked():
            emails = [e for e in self.gui.brute_emails.toPlainText().split('\n') if e.strip()]
            usernames.extend(emails)
            usernames = list(set(usernames))  # Remove duplicates

        # Get bearer tokens (for Bearer/API Key auth)
        bearer_tokens = [t for t in self.gui.brute_bearer_tokens.toPlainText().split('\n')
                        if t.strip() and not t.strip().startswith('#')]

        # Validate input based on auth type
        if auth_type in [AUTH_TYPE_BEARER, AUTH_TYPE_API_KEY]:
            if not bearer_tokens and not passwords:
                QMessageBox.warning(self.gui, "Error", "No tokens provided. Load default tokens or add your own.")
                return
        else:
            if not usernames:
                QMessageBox.warning(self.gui, "Error", "No usernames provided")
                return
            if not passwords:
                QMessageBox.warning(self.gui, "Error", "No passwords provided")
                return

        # Get indicators
        success_ind = [s.strip() for s in self.gui.brute_success_indicators.text().split(',') if s.strip()]
        failure_ind = [s.strip() for s in self.gui.brute_failure_indicators.text().split(',') if s.strip()]

        # Get URL and method
        url = self.gui.brute_action_url.text().strip() or self.gui.brute_url_input.text().strip()
        method = self.gui.brute_method.currentText()

        # Get proxy
        proxy = self.gui.brute_proxy.text().strip() or None

        # Get CSRF refresh setting
        refresh_csrf = self.gui.brute_refresh_csrf.isChecked()

        # Get stop on found setting
        stop_on_found = self.gui.brute_stop_on_found.isChecked()

        # Get API header name
        api_key_header = self.gui.brute_api_header.text().strip() or "Authorization"

        # Clear results
        self.gui.brute_results_table.setRowCount(0)
        self.gui.brute_response_table.setRowCount(0)
        self.gui.brute_progress.setValue(0)
        self.gui.brute_baseline_info.setText("Establishing baseline...")

        # Update UI
        self.gui.brute_start_btn.setEnabled(False)
        self.gui.brute_stop_btn.setEnabled(True)

        # Start worker with all parameters
        self.bruteforce_thread = BruteforceWorker(
            url=url,
            method=method,
            fields=fields,
            usernames=usernames,
            passwords=passwords,
            success_indicators=success_ind,
            failure_indicators=failure_ind,
            auth_type=auth_type,
            csrf_info=self.csrf_info,
            proxy=proxy,
            refresh_csrf=refresh_csrf,
            stop_on_found=stop_on_found,
            bearer_tokens=bearer_tokens,
            api_key_header=api_key_header
        )
        self.bruteforce_thread.progress_signal.connect(self._on_progress)
        self.bruteforce_thread.found_signal.connect(self._on_found)
        self.bruteforce_thread.response_signal.connect(self._on_response)
        self.bruteforce_thread.baseline_signal.connect(self._on_baseline)
        self.bruteforce_thread.finished_signal.connect(self._on_finished)
        self.bruteforce_thread.start()

    def _stop_bruteforce(self):
        """Stop bruteforce attack"""
        if self.bruteforce_thread:
            self.bruteforce_thread.stop()

    def _on_progress(self, current, total, status):
        """Update progress"""
        progress = int((current / total) * 100) if total > 0 else 0
        self.gui.brute_progress.setValue(progress)
        self.gui.brute_status.setText(f"{status} ({current}/{total})")

    def _on_baseline(self, status, title, size, cookie_count):
        """Handle baseline info"""
        self.gui.brute_baseline_info.setText(
            f"Baseline: Status={status}, Title='{title[:20]}...', Size={size}, Cookies={cookie_count}"
        )

    def _on_response(self, username, password, status_code, title, size, is_success, reason):
        """Handle response details - add to response table"""
        row = self.gui.brute_response_table.rowCount()
        self.gui.brute_response_table.insertRow(row)

        # Username
        user_item = QTableWidgetItem(username)
        self.gui.brute_response_table.setItem(row, 0, user_item)

        # Password
        pass_item = QTableWidgetItem(password)
        self.gui.brute_response_table.setItem(row, 1, pass_item)

        # Status code with color
        status_item = QTableWidgetItem(str(status_code))
        if status_code == 200:
            status_item.setBackground(QBrush(QColor("#dcfce7")))
        elif status_code == 401 or status_code == 403:
            status_item.setBackground(QBrush(QColor("#fee2e2")))
        elif status_code >= 500:
            status_item.setBackground(QBrush(QColor("#fef3c7")))
        self.gui.brute_response_table.setItem(row, 2, status_item)

        # Title
        title_item = QTableWidgetItem(title[:40])
        self.gui.brute_response_table.setItem(row, 3, title_item)

        # Size
        size_str = f"{size}" if size < 1024 else f"{size/1024:.1f}KB"
        size_item = QTableWidgetItem(size_str)
        self.gui.brute_response_table.setItem(row, 4, size_item)

        # Success indicator
        success_item = QTableWidgetItem("YES" if is_success else "NO")
        if is_success:
            success_item.setBackground(QBrush(QColor("#22c55e")))
            success_item.setForeground(QBrush(QColor("white")))
            success_item.setFont(QFont("Segoe UI", 9, QFont.Bold))
        else:
            success_item.setForeground(QBrush(QColor("#94a3b8")))
        self.gui.brute_response_table.setItem(row, 5, success_item)

        # Reason
        reason_item = QTableWidgetItem(reason[:60])
        if is_success:
            reason_item.setForeground(QBrush(QColor("#22c55e")))
        self.gui.brute_response_table.setItem(row, 6, reason_item)

        # Scroll to bottom
        self.gui.brute_response_table.scrollToBottom()

        # Limit to last 500 rows to prevent memory issues
        if self.gui.brute_response_table.rowCount() > 500:
            self.gui.brute_response_table.removeRow(0)

    def _on_found(self, username, password, response_info):
        """Handle found credentials"""
        row = self.gui.brute_results_table.rowCount()
        self.gui.brute_results_table.insertRow(row)

        user_item = QTableWidgetItem(username)
        user_item.setForeground(QBrush(QColor('#22c55e')))
        user_item.setFont(QFont("Consolas", 10, QFont.Bold))
        self.gui.brute_results_table.setItem(row, 0, user_item)

        pass_item = QTableWidgetItem(password)
        pass_item.setForeground(QBrush(QColor('#22c55e')))
        pass_item.setFont(QFont("Consolas", 10, QFont.Bold))
        self.gui.brute_results_table.setItem(row, 1, pass_item)

        reason_item = QTableWidgetItem(response_info.get('reason', 'N/A'))
        reason_item.setForeground(QBrush(QColor('#16a34a')))
        self.gui.brute_results_table.setItem(row, 2, reason_item)

        url_item = QTableWidgetItem(response_info.get('url', 'N/A'))
        url_item.setForeground(QBrush(QColor('#3b82f6')))
        self.gui.brute_results_table.setItem(row, 3, url_item)

    def _on_finished(self, success, message):
        """Handle bruteforce completion"""
        self.gui.brute_start_btn.setEnabled(True)
        self.gui.brute_stop_btn.setEnabled(False)
        self.gui.brute_progress.setValue(100)
        self.gui.brute_status.setText(message)

        if success:
            QMessageBox.information(self.gui, "Success", message)

    def _get_group_style(self):
        return """
            QGroupBox {
                font-weight: bold;
                font-size: 12px;
                color: #1e293b;
                border: 1px solid #e2e8f0;
                border-radius: 8px;
                margin-top: 12px;
                padding-top: 12px;
                background-color: #ffffff;
            }
            QGroupBox::title {
                subcontrol-origin: margin;
                left: 12px;
                padding: 0 8px;
                background-color: #ffffff;
            }
        """

    def _get_input_style(self):
        return """
            QLineEdit {
                background-color: #ffffff;
                border: 1px solid #e2e8f0;
                border-radius: 6px;
                padding: 8px 12px;
                font-size: 12px;
            }
            QLineEdit:focus {
                border-color: #3b82f6;
            }
        """

    def _get_textedit_style(self):
        return """
            QTextEdit {
                background-color: #ffffff;
                border: 1px solid #e2e8f0;
                border-radius: 6px;
                padding: 8px;
                font-family: Consolas, monospace;
                font-size: 11px;
            }
            QTextEdit:focus {
                border-color: #3b82f6;
            }
        """

    def _get_primary_button_style(self):
        return """
            QPushButton {
                background-color: #3b82f6;
                color: white;
                border: none;
                border-radius: 6px;
                padding: 8px 16px;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: #2563eb;
            }
        """

    def _get_secondary_button_style(self):
        return """
            QPushButton {
                background-color: #f1f5f9;
                color: #475569;
                border: 1px solid #e2e8f0;
                border-radius: 6px;
                padding: 6px 12px;
            }
            QPushButton:hover {
                background-color: #e2e8f0;
            }
        """

    def _get_combo_style(self):
        return """
            QComboBox {
                background-color: #ffffff;
                border: 1px solid #e2e8f0;
                border-radius: 6px;
                padding: 6px 12px;
                min-width: 80px;
            }
            QComboBox:hover {
                border-color: #3b82f6;
            }
        """

    def _get_table_style(self):
        return """
            QTableWidget {
                background-color: #ffffff;
                border: 1px solid #e2e8f0;
                border-radius: 6px;
                gridline-color: #f1f5f9;
            }
            QHeaderView::section {
                background-color: #f8fafc;
                color: #475569;
                padding: 8px;
                border: none;
                border-bottom: 2px solid #3b82f6;
                font-weight: bold;
                font-size: 11px;
            }
            QTableWidget::item {
                padding: 6px;
            }
            QTableWidget::item:selected {
                background-color: #dbeafe;
                color: #1e40af;
            }
        """

    def _load_builtin_wordlist(self, wordlist_type):
        """Load a builtin wordlist from the wordlists directory"""
        wordlist_dir = Path(__file__).parent.parent.parent / 'wordlists'

        wordlist_files = {
            'short': 'passwords_short.txt',
            'numeric': 'passwords_numeric.txt',
            'top100': 'passwords_top100.txt'
        }

        filename = wordlist_files.get(wordlist_type)
        if not filename:
            return

        filepath = wordlist_dir / filename

        if filepath.exists():
            try:
                with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()
                self.gui.brute_passwords.setText(content)
                self.gui.brute_status.setText(f"Loaded {wordlist_type} wordlist ({len(content.splitlines())} passwords)")
            except Exception as e:
                QMessageBox.warning(self.gui, "Error", f"Failed to load wordlist: {e}")
        else:
            # Fall back to built-in defaults
            if wordlist_type == 'short':
                passwords = "123\n1234\n12345\npass\nroot\ntest\nadmin\nuser\nqwer\nasdf"
            elif wordlist_type == 'numeric':
                passwords = "\n".join(str(i) for i in [0, 1, 12, 123, 1234, 12345, 123456,
                                                       1234567, 12345678, 123456789, 1234567890,
                                                       0000, 1111, 2222, 3333, 4444, 5555,
                                                       6666, 7777, 8888, 9999])
            else:  # top100
                passwords = DEFAULT_PASSWORDS

            self.gui.brute_passwords.setText(passwords)
            self.gui.brute_status.setText(f"Loaded built-in {wordlist_type} wordlist")

    def _apply_password_filter(self):
        """Apply filters to the current password list"""
        current_passwords = self.gui.brute_passwords.toPlainText().split('\n')
        filtered = []

        min_len = self.gui.brute_min_len.value()
        max_len = self.gui.brute_max_len.value()

        numeric_only = self.gui.brute_filter_numeric.isChecked()
        alpha_only = self.gui.brute_filter_alpha.isChecked()
        alphanum_only = self.gui.brute_filter_alphanum.isChecked()

        for password in current_passwords:
            password = password.strip()
            if not password:
                continue

            # Length filter
            if min_len > 0 and len(password) < min_len:
                continue
            if max_len > 0 and len(password) > max_len:
                continue

            # Character type filters
            if numeric_only and not password.isdigit():
                continue
            if alpha_only and not password.isalpha():
                continue
            if alphanum_only and not password.isalnum():
                continue

            filtered.append(password)

        self.gui.brute_passwords.setText('\n'.join(filtered))
        self.gui.brute_status.setText(f"Filtered to {len(filtered)} passwords")

    def _generate_numbers(self):
        """Generate number range passwords"""
        from_num = self.gui.brute_gen_from.value()
        to_num = self.gui.brute_gen_to.value()

        if from_num > to_num:
            from_num, to_num = to_num, from_num

        # Limit to reasonable range to avoid memory issues
        if to_num - from_num > 100000:
            QMessageBox.warning(self.gui, "Warning",
                              "Range too large! Limited to 100,000 numbers.")
            to_num = from_num + 100000

        numbers = [str(i) for i in range(from_num, to_num + 1)]

        # Append to current passwords
        current = self.gui.brute_passwords.toPlainText().strip()
        if current:
            current += '\n'

        self.gui.brute_passwords.setText(current + '\n'.join(numbers))
        self.gui.brute_status.setText(f"Generated {len(numbers)} numbers ({from_num}-{to_num})")

    def _generate_variants(self):
        """Generate password variants from a base word"""
        base = self.gui.brute_gen_base.text().strip()
        if not base:
            QMessageBox.warning(self.gui, "Error", "Please enter a base word")
            return

        variants = set()

        # Basic case variants
        variants.add(base)
        variants.add(base.lower())
        variants.add(base.upper())
        variants.add(base.capitalize())
        variants.add(base.title())

        # Number suffixes
        for suffix in ['1', '12', '123', '1234', '01', '007', '69', '99', '00', '11', '22']:
            variants.add(base + suffix)
            variants.add(base.capitalize() + suffix)

        # Year suffixes
        for year in range(2020, 2027):
            variants.add(base + str(year))
            variants.add(base.capitalize() + str(year))

        # Special character suffixes
        for suffix in ['!', '@', '#', '$', '*', '!@', '@!', '!!', '123!', '@123', '!1']:
            variants.add(base + suffix)
            variants.add(base.capitalize() + suffix)

        # Leet speak variants
        leet_map = {'a': '@', 'e': '3', 'i': '1', 'o': '0', 's': '$', 't': '7'}
        leet_word = base.lower()
        for char, leet in leet_map.items():
            leet_word = leet_word.replace(char, leet)
        if leet_word != base.lower():
            variants.add(leet_word)
            variants.add(leet_word.upper())

        # Append to current passwords
        current = self.gui.brute_passwords.toPlainText().strip()
        if current:
            current += '\n'

        self.gui.brute_passwords.setText(current + '\n'.join(sorted(variants)))
        self.gui.brute_status.setText(f"Generated {len(variants)} variants for '{base}'")

    def _generate_years(self):
        """Generate year-based passwords"""
        years = []

        # Years from 1990 to 2025
        for year in range(1990, 2026):
            years.append(str(year))

        # Common date formats
        for year in range(2000, 2026):
            short_year = str(year)[2:]  # 00-25
            years.append(short_year)

        # Append to current passwords
        current = self.gui.brute_passwords.toPlainText().strip()
        if current:
            current += '\n'

        self.gui.brute_passwords.setText(current + '\n'.join(years))
        self.gui.brute_status.setText(f"Generated {len(years)} year passwords")

    def _generate_dates(self):
        """Generate common date passwords"""
        dates = []

        # Common date formats (MMDD, DDMM, MMDDYY, DDMMYY)
        for month in range(1, 13):
            for day in range(1, 32):
                # Skip invalid dates roughly
                if day > 30 and month in [4, 6, 9, 11]:
                    continue
                if day > 29 and month == 2:
                    continue

                mm = f"{month:02d}"
                dd = f"{day:02d}"

                # MMDD format
                dates.append(f"{mm}{dd}")
                # DDMM format
                dates.append(f"{dd}{mm}")

        # Common years appended
        common_dates = []
        for date in dates[:50]:  # Limit to avoid too many combinations
            for year in ['2020', '2021', '2022', '2023', '2024', '2025', '20', '21', '22', '23', '24', '25']:
                common_dates.append(f"{date}{year}")

        dates.extend(common_dates)

        # Remove duplicates
        dates = list(set(dates))

        # Append to current passwords
        current = self.gui.brute_passwords.toPlainText().strip()
        if current:
            current += '\n'

        self.gui.brute_passwords.setText(current + '\n'.join(sorted(dates)))
        self.gui.brute_status.setText(f"Generated {len(dates)} date passwords")
