"""
CSRF (Cross-Site Request Forgery) Scanner Module

Detects missing CSRF protection in state-changing operations
Based on XVWA vulnerable code: Forms without anti-CSRF tokens
"""

from typing import List, Dict, Any
from core.base_module import BaseModule
from core.logger import get_logger
import re

logger = get_logger(__name__)


class CSRFModule(BaseModule):
    """CSRF Scanner Module"""

    def __init__(self, module_path: str, payload_limit: int = None):
        """Initialize CSRF module"""
        super().__init__(module_path, payload_limit=payload_limit)

        # Common CSRF token field names
        self.token_names = [
            'csrf', 'csrf_token', 'csrftoken', '_csrf', '_token',
            'authenticity_token', 'anti_csrf', 'xsrf', 'xsrf_token',
            'token', '__RequestVerificationToken', 'nonce'
        ]

        # Logout endpoints - critical CSRF targets
        self.logout_keywords = [
            'logout', 'logoff', 'signout', 'sign-out', 'sign_out',
            'disconnect', 'end_session', 'endsession', 'terminate',
            'exit', 'bye', 'leave', 'close_session'
        ]

        # State-changing operations (keywords in forms/URLs)
        # EXPANDED: Added missing keywords identified in Acunetix gap analysis
        self.state_changing_keywords = [
            # Authentication & account
            'password', 'passwd', 'pass', 'pwd',
            'email', 'username', 'user', 'login',

            # Data modification
            'delete', 'remove', 'change', 'update', 'modify', 'edit', 'save',
            'create', 'add', 'new', 'register', 'insert',

            # Communication & content (CRITICAL FIX: was missing for guestbook!)
            'comment', 'message', 'post', 'submit', 'reply',
            'text', 'content', 'body', 'title', 'description',
            'name',  # often used in guestbooks/comments

            # Financial
            'transfer', 'send', 'payment', 'purchase', 'buy', 'order',

            # Other state-changing
            'confirm', 'approve', 'upload', 'file'
        ]

        logger.info(f"CSRF module loaded: {len(self.token_names)} token patterns")

    def scan(self, targets: List[Dict[str, Any]], http_client: Any) -> List[Dict[str, Any]]:
        """
        Scan for CSRF vulnerabilities

        Args:
            targets: List of URLs with parameters
            http_client: HTTP client

        Returns:
            List of results
        """
        results = []

        logger.info(f"Starting CSRF scan on {len(targets)} targets")

        # CRITICAL FIX: CSRF affects ALL state-changing forms, not just keyword-based!
        # Previous logic skipped forms without keywords - WRONG!
        # POST forms are almost always state-changing (submit data to server)
        # Check ALL POST forms + GET forms that look state-changing

        post_forms = [t for t in targets if t.get('method', 'GET').upper() == 'POST']
        get_forms_stateful = [t for t in targets
                              if t.get('method', 'GET').upper() == 'GET'
                              and self._is_state_changing(t.get('url', ''), t.get('params', {}))]

        form_targets = post_forms + get_forms_stateful

        logger.info(f"Found {len(post_forms)} POST forms + {len(get_forms_stateful)} stateful GET forms = {len(form_targets)} total")

        for target in form_targets:
            url = target.get('url')
            params = target.get('params', {})
            method = target.get('method', 'GET').upper()

            if not params:
                continue

            logger.debug(f"Checking CSRF protection for: {url}")

            # Check for CSRF token
            has_csrf_token = self._has_csrf_token(params)

            if not has_csrf_token:
                # Check if form accepts requests without referer/origin validation
                detected, confidence, evidence = self._detect_csrf(
                    url, params, method, http_client
                )

                if detected:
                    result = self.create_result(
                        vulnerable=True,
                        url=url,
                        parameter="",  # CSRF is form-level, not parameter-level
                        payload="",
                        evidence=evidence,
                        description="Cross-Site Request Forgery (CSRF) vulnerability detected. "
                                  "Form accepts state-changing requests without anti-CSRF tokens.",
                        confidence=confidence
                    )

                    # Add metadata
                    result['cwe'] = self.config.get('cwe', 'CWE-352')
                    result['owasp'] = self.config.get('owasp', 'A01:2021')
                    result['cvss'] = self.config.get('cvss', '6.5')

                    # Generate POC HTML
                    result['poc'] = self._generate_csrf_poc(url, params, method)
                    result['additional_info'] = {
                        'poc_html': result['poc'],
                        'auto_submit_poc': self._generate_auto_submit_poc(url, params, method),
                        'xhr_poc': self._generate_xhr_poc(url, params, method),
                        'img_poc': self._generate_img_poc(url, params) if method == 'GET' else None
                    }

                    results.append(result)
                    logger.info(f"✓ CSRF vulnerability found in {url} "
                              f"(confidence: {confidence:.2f})")

        logger.info(f"CSRF scan complete: {len(results)} vulnerabilities found")

        # ADDITIONAL CHECK: No CSRF on Logout detection
        # Scan for logout endpoints without CSRF protection
        logout_results = self._check_logout_csrf(targets, http_client)
        results.extend(logout_results)

        return results

    def _is_state_changing(self, url: str, params: Dict[str, Any]) -> bool:
        """
        Check if form performs state-changing operation

        Args:
            url: Form URL
            params: Form parameters

        Returns:
            True if state-changing
        """
        # Check URL for state-changing keywords
        url_lower = url.lower()
        for keyword in self.state_changing_keywords:
            if keyword in url_lower:
                return True

        # Check parameter names for state-changing keywords
        for param_name in params.keys():
            param_lower = param_name.lower()
            for keyword in self.state_changing_keywords:
                if keyword in param_lower:
                    return True

        return False

    def _has_csrf_token(self, params: Dict[str, Any]) -> bool:
        """
        Check if form has CSRF token

        Args:
            params: Form parameters

        Returns:
            True if CSRF token present
        """
        for param_name in params.keys():
            param_lower = param_name.lower()
            for token_name in self.token_names:
                if token_name in param_lower:
                    logger.debug(f"CSRF token found: {param_name}")
                    return True

        return False

    def _detect_csrf(self, url: str, params: Dict[str, Any],
                    method: str, http_client: Any) -> tuple:
        """
        Detect CSRF vulnerability

        Returns:
            (detected: bool, confidence: float, evidence: str)
        """
        # STAGE 1: Send request without Referer header
        # (simulating cross-origin request)
        try:
            # Remove Referer/Origin headers if present
            headers = {
                'Referer': '',  # Empty referer
                'Origin': ''
            }

            # Send request using the form's method
            if method == 'POST':
                response = http_client.post(url, data=params, headers=headers)
            else:
                response = http_client.get(url, params=params, headers=headers)

            if not response:
                return False, 0.0, ""

            response_text = getattr(response, 'text', '')

        except Exception as e:
            logger.debug(f"CSRF test request failed: {e}")
            return False, 0.0, ""

        # STAGE 2: Check if request was accepted
        # Success indicators
        success_patterns = [
            'success',
            'changed',
            'updated',
            'saved',
            'completed',
            'thank you',
            'confirmed'
        ]

        response_lower = response_text.lower()
        success_count = sum(1 for pattern in success_patterns if pattern in response_lower)

        # If status is 200 and no error, likely accepted
        if response.status_code == 200:
            # Check for error messages (which would indicate rejection)
            error_patterns = ['error', 'invalid', 'failed', 'denied', 'forbidden']
            error_count = sum(1 for pattern in error_patterns if pattern in response_lower)

            if error_count == 0 or success_count > error_count:
                # Request was likely accepted without CSRF token
                confidence = 0.70

                # Higher confidence if we see success messages
                if success_count >= 2:
                    confidence = 0.85

                # BOOST confidence if form has state-changing keywords
                # (keywords used for confidence, NOT filtering!)
                has_keywords = self._is_state_changing(url, params)
                if has_keywords:
                    confidence = min(1.0, confidence + 0.10)

                # Check if using GET method (very bad for state-changing)
                if method == 'GET':
                    confidence = 0.90

                # Password forms are CRITICAL
                if any(k in url.lower() or k in str(params).lower()
                       for k in ['password', 'passwd', 'pass', 'pwd', 'login']):
                    confidence = 0.95

                evidence = f"{method} form accepts state-changing requests without CSRF token. "
                if method == 'GET':
                    evidence += "CRITICAL: State-changing operation uses GET method! "
                evidence += f"Form has {len(params)} parameters: {', '.join(list(params.keys())[:5])}. "
                evidence += "No anti-CSRF token field found (checked: csrf, csrf_token, _token, etc). "
                if has_keywords:
                    evidence += "Contains state-changing keywords. "

                if success_count > 0:
                    evidence += f"Request accepted (found {success_count} success indicators). "

                return True, confidence, evidence

        return False, 0.0, ""

    def _check_logout_csrf(self, targets: List[Dict[str, Any]],
                           http_client: Any) -> List[Dict[str, Any]]:
        """
        Check for logout endpoints without CSRF protection
        This is a specific vulnerability: "No CSRF on Logout"

        Attack scenario: Attacker can force-logout authenticated users
        by embedding logout links in images, iframes, etc.

        Returns:
            List of vulnerabilities found
        """
        results = []
        checked_urls = set()

        logger.info("Checking for No CSRF on Logout vulnerability...")

        for target in targets:
            url = target.get('url', '')
            url_lower = url.lower()

            # Skip already checked URLs
            if url in checked_urls:
                continue

            # Check if URL contains logout keywords
            is_logout = any(kw in url_lower for kw in self.logout_keywords)

            if not is_logout:
                continue

            checked_urls.add(url)
            logger.debug(f"Testing logout endpoint: {url}")

            # Check for CSRF protection
            params = target.get('params', {})
            method = target.get('method', 'GET').upper()

            # Check if form has CSRF token
            has_csrf_token = self._has_csrf_token(params)

            if has_csrf_token:
                logger.debug(f"Logout endpoint has CSRF protection: {url}")
                continue

            # Test if logout works without token/referer
            try:
                headers = {
                    'Referer': 'https://attacker.com',
                    'Origin': 'https://attacker.com'
                }

                if method == 'POST':
                    response = http_client.post(url, data=params, headers=headers)
                else:
                    response = http_client.get(url, headers=headers)

                if not response:
                    continue

                # Check if logout was triggered
                response_text = getattr(response, 'text', '').lower()
                status_code = response.status_code

                # Signs logout worked (redirects are common)
                logout_success = (
                    status_code in [200, 302, 303] or
                    'logged out' in response_text or
                    'signed out' in response_text or
                    'session' in response_text and 'ended' in response_text or
                    'goodbye' in response_text
                )

                # Check response headers for session cookie deletion
                set_cookie = response.headers.get('Set-Cookie', '')
                cookie_cleared = (
                    'expires=Thu, 01 Jan 1970' in set_cookie or
                    'max-age=0' in set_cookie.lower() or
                    '=""' in set_cookie or
                    '=deleted' in set_cookie.lower()
                )

                if logout_success or cookie_cleared:
                    confidence = 0.85

                    # Higher confidence for GET-based logout (worse)
                    if method == 'GET':
                        confidence = 0.95

                    evidence = f"Logout endpoint vulnerable to CSRF\n"
                    evidence += f"{'='*50}\n\n"
                    evidence += f"URL: {url}\n"
                    evidence += f"Method: {method}\n\n"
                    evidence += f"Issue: Logout functionality lacks CSRF protection.\n\n"
                    evidence += f"Attack Scenario:\n"
                    evidence += f"- Attacker embeds: <img src=\"{url}\">\n"
                    evidence += f"- When victim views attacker's page, they are logged out\n"
                    evidence += f"- Can be used for denial of service or session manipulation\n\n"

                    if method == 'GET':
                        evidence += "CRITICAL: Logout uses GET method - trivially exploitable!\n"
                    if cookie_cleared:
                        evidence += "Session cookie appears to be cleared on request.\n"

                    evidence += f"\nRemediation:\n"
                    evidence += f"- Require CSRF token for logout\n"
                    evidence += f"- Use POST method instead of GET\n"
                    evidence += f"- Validate Referer/Origin headers\n"

                    result = self.create_result(
                        vulnerable=True,
                        url=url,
                        parameter="logout",
                        payload="Cross-origin request",
                        evidence=evidence,
                        description="No CSRF on Logout: Logout endpoint accepts requests without "
                                  "CSRF token, allowing attackers to force-logout users.",
                        confidence=confidence
                    )

                    result['cwe'] = 'CWE-352'
                    result['owasp'] = 'A01:2021'
                    result['severity'] = 'medium' if method == 'POST' else 'high'
                    result['finding_type'] = 'no_csrf_logout'

                    results.append(result)
                    logger.info(f"✓ No CSRF on Logout found: {url}")

            except Exception as e:
                logger.debug(f"Error testing logout CSRF: {e}")

        if results:
            logger.info(f"Found {len(results)} logout endpoints without CSRF protection")

        return results


    def _generate_csrf_poc(self, url: str, params: Dict[str, Any], method: str) -> str:
        """Generate basic CSRF POC HTML form"""
        from html import escape

        form_inputs = ""
        for name, value in params.items():
            escaped_name = escape(str(name))
            escaped_value = escape(str(value) if value else "test")
            form_inputs += f'    <input type="hidden" name="{escaped_name}" value="{escaped_value}" />\n'

        poc = f'''<!DOCTYPE html>
<html>
<head>
    <title>CSRF POC - Dominator</title>
</head>
<body>
    <h1>CSRF Proof of Concept</h1>
    <p>Target: {escape(url)}</p>
    <p>Method: {method}</p>

    <form id="csrf_form" action="{escape(url)}" method="{method}">
{form_inputs}        <input type="submit" value="Submit Request" />
    </form>

    <h3>Instructions:</h3>
    <ol>
        <li>Victim must be logged into the target application</li>
        <li>Victim visits this page (attacker controlled)</li>
        <li>Form can be auto-submitted using JavaScript</li>
        <li>State-changing action is performed on victim's behalf</li>
    </ol>
</body>
</html>'''
        return poc

    def _generate_auto_submit_poc(self, url: str, params: Dict[str, Any], method: str) -> str:
        """Generate auto-submitting CSRF POC"""
        from html import escape

        form_inputs = ""
        for name, value in params.items():
            escaped_name = escape(str(name))
            escaped_value = escape(str(value) if value else "test")
            form_inputs += f'    <input type="hidden" name="{escaped_name}" value="{escaped_value}" />\n'

        poc = f'''<!DOCTYPE html>
<html>
<head>
    <title>Loading...</title>
</head>
<body>
    <form id="csrf_form" action="{escape(url)}" method="{method}">
{form_inputs}    </form>
    <script>
        // Auto-submit form when page loads
        document.getElementById("csrf_form").submit();
    </script>
</body>
</html>'''
        return poc

    def _generate_xhr_poc(self, url: str, params: Dict[str, Any], method: str) -> str:
        """Generate XHR/Fetch-based CSRF POC"""
        from html import escape
        import json

        poc = f'''<!DOCTYPE html>
<html>
<head>
    <title>CSRF XHR POC</title>
</head>
<body>
    <h1>CSRF via XMLHttpRequest</h1>
    <p>Target: {escape(url)}</p>
    <button onclick="sendCSRF()">Execute CSRF Attack</button>
    <div id="result"></div>

    <script>
    function sendCSRF() {{
        var xhr = new XMLHttpRequest();
        xhr.open("{method}", "{escape(url)}", true);
        xhr.withCredentials = true; // Include cookies
        xhr.setRequestHeader("Content-Type", "application/x-www-form-urlencoded");

        var params = {json.dumps(params)};
        var body = Object.keys(params).map(k => k + "=" + encodeURIComponent(params[k] || "test")).join("&");

        xhr.onreadystatechange = function() {{
            if (xhr.readyState === 4) {{
                document.getElementById("result").innerHTML =
                    "Status: " + xhr.status + "<br>Response: " + xhr.responseText.substring(0, 500);
            }}
        }};

        xhr.send(body);
    }}
    </script>

    <h3>Note:</h3>
    <p>This may be blocked by CORS. Works when:</p>
    <ul>
        <li>Target has permissive CORS headers</li>
        <li>Request is "simple" (no custom headers)</li>
        <li>Using form-based request</li>
    </ul>
</body>
</html>'''
        return poc

    def _generate_img_poc(self, url: str, params: Dict[str, Any]) -> str:
        """Generate IMG tag CSRF POC (for GET requests)"""
        from html import escape
        from urllib.parse import urlencode

        query_string = urlencode({k: (v if v else "test") for k, v in params.items()})
        full_url = f"{url}?{query_string}" if query_string else url

        poc = f'''<!DOCTYPE html>
<html>
<head>
    <title>Innocent Page</title>
</head>
<body>
    <h1>Welcome to our site!</h1>
    <p>Nothing suspicious here...</p>

    <!-- Hidden CSRF attack via IMG tag -->
    <img src="{escape(full_url)}" style="display:none" />

    <!-- Alternative methods -->
    <!--
    <iframe src="{escape(full_url)}" style="display:none"></iframe>
    <script src="{escape(full_url)}"></script>
    <link href="{escape(full_url)}" rel="stylesheet">
    -->

    <h3>Attack Details:</h3>
    <p>The following request is made when this page loads:</p>
    <code>GET {escape(full_url)}</code>
    <p>No user interaction required!</p>
</body>
</html>'''
        return poc


def get_module(module_path: str, payload_limit: int = None):
    """Create module instance"""
    return CSRFModule(module_path, payload_limit=payload_limit)
