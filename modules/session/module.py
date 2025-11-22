"""
Session Management Scanner
Tests for session fixation, hijacking, timeout, and other session vulnerabilities
"""

from core.base_module import BaseModule
from core.http_client import HTTPClient
from core.logger import get_logger
from typing import List, Dict, Any
import re
from http.cookies import SimpleCookie

logger = get_logger(__name__)


class SessionManagementScanner(BaseModule):
    """Scans for session management vulnerabilities"""

    def __init__(self, module_path: str, payload_limit: int = None):
        super().__init__(module_path, payload_limit=payload_limit)
        self.module_name = "Session Management"
        self.logger = logger

    def scan(self, targets: List[Dict[str, Any]], http_client: Any = None) -> List[Dict[str, Any]]:
        """
        Scan targets for session management vulnerabilities

        Args:
            targets: List of targets to scan
            http_client: HTTP client for making requests

        Returns:
            List of vulnerability findings
        """
        self.logger.info(f"Starting {self.module_name} scan on {len(targets)} targets")

        results = []
        client = http_client or HTTPClient(timeout=8)

        for target in targets:
            url = target.get('url')
            if not url:
                continue

            # First, make a request to get session cookies
            response = client.get(url)
            if not response:
                continue

            # Analyze session cookies
            cookie_findings = self._analyze_session_cookies(url, response)
            results.extend(cookie_findings)

            # Test specific session vulnerabilities
            for payload in self.payloads[:self.payload_limit]:
                payload = payload.strip()
                if not payload or payload.startswith('#'):
                    continue

                finding = self._test_session_payload(client, url, payload, response)
                if finding:
                    results.append(finding)

                    # Early exit if configured
                    if self.config.get('early_exit', False):
                        break

        client.close()
        self.logger.info(f"{self.module_name} scan complete: {len(results)} vulnerabilities found")
        return results

    def _get_set_cookie_headers(self, response) -> List[str]:
        """Extract Set-Cookie headers from response (compatible with requests library)"""
        try:
            # Try to get raw headers (works with requests library)
            if hasattr(response, 'raw') and hasattr(response.raw, 'headers'):
                return response.raw.headers.getlist('Set-Cookie') or []
            # Fallback: reconstruct from cookies jar
            if hasattr(response, 'cookies'):
                return [f"{name}={value}" for name, value in response.cookies.items()]
            return []
        except:
            return []

    def _analyze_session_cookies(self, url: str, response) -> List[Dict[str, Any]]:
        """Analyze session cookies for security issues"""

        findings = []

        # Get all Set-Cookie headers
        set_cookie_headers = self._get_set_cookie_headers(response)

        for cookie_header in set_cookie_headers:
            # Parse cookie
            cookie = SimpleCookie()
            try:
                cookie.load(cookie_header)
            except:
                continue

            for name, morsel in cookie.items():
                # Check if this is a session cookie
                if self._is_session_cookie(name):
                    # Check HttpOnly flag
                    if not morsel.get('httponly'):
                        findings.append({
                            'vulnerability': True,
                            'module': self.module_name,
                            'type': 'Missing HttpOnly Flag',
                            'severity': 'Medium',
                            'url': url,
                            'parameter': name,
                            'payload': 'N/A',
                            'method': 'GET',
                            'confidence': 0.95,
                            'description': f'Session cookie "{name}" is missing HttpOnly flag.',
                            'evidence': f'Cookie: {name}={morsel.value}',
                            'recommendation': 'Set HttpOnly flag on session cookies to prevent JavaScript access.',
                            'cwe': 'CWE-1004',
                            'cvss': 5.3,
                            'owasp': 'A05:2021',
                            'references': [
                                'https://owasp.org/www-community/HttpOnly',
                                'https://cwe.mitre.org/data/definitions/1004.html'
                            ]
                        })

                    # Check Secure flag
                    if not morsel.get('secure') and url.startswith('https://'):
                        findings.append({
                            'vulnerability': True,
                            'module': self.module_name,
                            'type': 'Missing Secure Flag',
                            'severity': 'Medium',
                            'url': url,
                            'parameter': name,
                            'payload': 'N/A',
                            'method': 'GET',
                            'confidence': 0.95,
                            'description': f'Session cookie "{name}" is missing Secure flag on HTTPS site.',
                            'evidence': f'Cookie: {name}={morsel.value}',
                            'recommendation': 'Set Secure flag on session cookies for HTTPS sites.',
                            'cwe': 'CWE-614',
                            'cvss': 5.9,
                            'owasp': 'A05:2021',
                            'references': [
                                'https://owasp.org/www-community/controls/SecureCookieAttribute',
                                'https://cwe.mitre.org/data/definitions/614.html'
                            ]
                        })

                    # Check SameSite attribute
                    if not morsel.get('samesite'):
                        findings.append({
                            'vulnerability': True,
                            'module': self.module_name,
                            'type': 'Missing SameSite Attribute',
                            'severity': 'Medium',
                            'url': url,
                            'parameter': name,
                            'payload': 'N/A',
                            'method': 'GET',
                            'confidence': 0.90,
                            'description': f'Session cookie "{name}" is missing SameSite attribute.',
                            'evidence': f'Cookie: {name}={morsel.value}',
                            'recommendation': 'Set SameSite=Strict or SameSite=Lax on session cookies to prevent CSRF attacks.',
                            'cwe': 'CWE-352',
                            'cvss': 6.5,
                            'owasp': 'A01:2021',
                            'references': [
                                'https://owasp.org/www-community/SameSite'
                            ]
                        })

                    # Check for weak session IDs
                    session_value = morsel.value
                    if self._is_weak_session_id(session_value):
                        findings.append({
                            'vulnerability': True,
                            'module': self.module_name,
                            'type': 'Weak Session ID',
                            'severity': 'High',
                            'url': url,
                            'parameter': name,
                            'payload': session_value,
                            'method': 'GET',
                            'confidence': 0.75,
                            'description': f'Session ID "{session_value}" appears to be weak or predictable.',
                            'evidence': f'Session ID length: {len(session_value)}, Pattern detected',
                            'recommendation': 'Use cryptographically strong random session IDs (128+ bits entropy).',
                            'cwe': 'CWE-330',
                            'cvss': 7.5,
                            'owasp': 'A02:2021',
                            'references': [
                                'https://owasp.org/www-community/vulnerabilities/Insufficient_Session-ID_Length'
                            ]
                        })

        return findings

    def _test_session_payload(self, client: HTTPClient, url: str, payload: str, initial_response) -> Dict[str, Any]:
        """Test a specific session vulnerability"""

        try:
            # Parse payload type
            if ':' not in payload:
                return None

            parts = payload.split(':', 1)
            test_type = parts[0]

            if test_type == 'FIXATION':
                return self._test_session_fixation(client, url, parts[1] if len(parts) > 1 else '')

            elif test_type == 'HIJACK':
                return self._test_session_hijacking(client, url, parts[1] if len(parts) > 1 else '')

            elif test_type == 'CONCURRENT':
                return self._test_concurrent_sessions(client, url)

            elif test_type == 'CSRF':
                return self._test_csrf_protection(client, url, parts[1] if len(parts) > 1 else '')

        except Exception as e:
            self.logger.debug(f"Error testing session payload: {str(e)}")

        return None

    def _test_session_fixation(self, client: HTTPClient, url: str, payload_data: str) -> Dict[str, Any]:
        """Test for session fixation vulnerability"""

        # Try to set a predetermined session ID
        test_session_id = 'attacker_controlled_session_123'

        # Send request with predetermined session cookie
        response = client.get(url, headers={'Cookie': f'sessionid={test_session_id}'})

        if response:
            # Check if the server accepted our session ID
            set_cookies = self._get_set_cookie_headers(response)

            for cookie_header in set_cookies:
                if test_session_id in cookie_header:
                    return {
                        'vulnerability': True,
                        'module': self.module_name,
                        'type': 'Session Fixation',
                        'severity': 'High',
                        'url': url,
                        'parameter': 'Session Cookie',
                        'payload': test_session_id,
                        'method': 'GET',
                        'confidence': 0.70,
                        'description': 'Application accepts predetermined session IDs, enabling session fixation attacks.',
                        'evidence': f'Server accepted session ID: {test_session_id}',
                        'recommendation': 'Regenerate session IDs after successful login. Reject externally provided session IDs.',
                        'cwe': 'CWE-384',
                        'cvss': 7.5,
                        'owasp': 'A07:2021',
                        'references': [
                            'https://owasp.org/www-community/attacks/Session_fixation',
                            'https://cwe.mitre.org/data/definitions/384.html'
                        ]
                    }

        return None

    def _test_session_hijacking(self, client: HTTPClient, url: str, payload_data: str) -> Dict[str, Any]:
        """Test for session hijacking vulnerabilities"""

        # Check if session ID appears in URL
        if 'SESSION_IN_URL' in payload_data:
            response = client.get(url)

            if response and ('sessionid=' in url.lower() or 'sid=' in url.lower() or 'session=' in url.lower()):
                return {
                    'vulnerability': True,
                    'module': self.module_name,
                    'type': 'Session ID in URL',
                    'severity': 'High',
                    'url': url,
                    'parameter': 'URL',
                    'payload': 'N/A',
                    'method': 'GET',
                    'confidence': 0.95,
                    'description': 'Session ID is exposed in URL, making it vulnerable to hijacking via referer headers or browser history.',
                    'evidence': 'Session parameter found in URL',
                    'recommendation': 'Use cookies for session management. Never expose session IDs in URLs.',
                    'cwe': 'CWE-598',
                    'cvss': 7.5,
                    'owasp': 'A04:2021',
                    'references': [
                        'https://cwe.mitre.org/data/definitions/598.html'
                    ]
                }

        return None

    def _test_concurrent_sessions(self, client: HTTPClient, url: str) -> Dict[str, Any]:
        """Test if multiple concurrent sessions are allowed"""

        # Make two requests and check if both sessions are valid
        response1 = client.get(url)
        response2 = client.get(url)

        if response1 and response2:
            cookies1 = self._extract_session_cookies(response1)
            cookies2 = self._extract_session_cookies(response2)

            # If we got different session IDs, concurrent sessions are allowed
            if cookies1 and cookies2 and cookies1 != cookies2:
                return {
                    'vulnerability': True,
                    'module': self.module_name,
                    'type': 'Concurrent Sessions Allowed',
                    'severity': 'Medium',
                    'url': url,
                    'parameter': 'Session Management',
                    'payload': 'N/A',
                    'method': 'GET',
                    'confidence': 0.65,
                    'description': 'Application allows multiple concurrent sessions for the same user.',
                    'evidence': f'Two different session IDs obtained: {cookies1[:20]}... and {cookies2[:20]}...',
                    'recommendation': 'Implement session limits or notify users of concurrent logins.',
                    'cwe': 'CWE-384',
                    'cvss': 5.3,
                    'owasp': 'A07:2021',
                    'references': []
                }

        return None

    def _test_csrf_protection(self, client: HTTPClient, url: str, payload_data: str) -> Dict[str, Any]:
        """Test for CSRF token presence"""

        response = client.get(url)

        if response and 'NO_CSRF_TOKEN' in payload_data:
            # Check if page contains forms without CSRF tokens
            if '<form' in response.text.lower():
                if not self._has_csrf_token(response.text):
                    return {
                        'vulnerability': True,
                        'module': self.module_name,
                        'type': 'Missing CSRF Protection',
                        'severity': 'High',
                        'url': url,
                        'parameter': 'CSRF Token',
                        'payload': 'N/A',
                        'method': 'GET',
                        'confidence': 0.80,
                        'description': 'Forms detected without CSRF protection tokens.',
                        'evidence': 'HTML forms found without CSRF tokens',
                        'recommendation': 'Implement CSRF tokens for all state-changing operations. Use SameSite cookie attribute.',
                        'cwe': 'CWE-352',
                        'cvss': 8.1,
                        'owasp': 'A01:2021',
                        'references': [
                            'https://owasp.org/www-community/attacks/csrf',
                            'https://cwe.mitre.org/data/definitions/352.html'
                        ]
                    }

        return None

    def _is_session_cookie(self, name: str) -> bool:
        """Check if cookie name indicates a session cookie"""

        session_cookie_names = [
            'sessionid', 'session', 'sid', 'phpsessid', 'jsessionid',
            'asp.net_sessionid', 'aspsessionid', 'cfid', 'cftoken',
            'session_id', 'sess', 'token', 'auth', 'authentication'
        ]

        return name.lower() in session_cookie_names or 'session' in name.lower()

    def _is_weak_session_id(self, session_id: str) -> bool:
        """Check if session ID appears weak or predictable"""

        # Too short
        if len(session_id) < 16:
            return True

        # Sequential numbers
        if session_id.isdigit():
            return True

        # Only lowercase or only uppercase
        if session_id.islower() or session_id.isupper():
            return True

        # Repeating patterns
        if len(set(session_id)) < len(session_id) / 2:
            return True

        return False

    def _extract_session_cookies(self, response) -> str:
        """Extract session cookie values from response"""

        set_cookies = self._get_set_cookie_headers(response)
        session_values = []

        for cookie_header in set_cookies:
            cookie = SimpleCookie()
            try:
                cookie.load(cookie_header)
                for name, morsel in cookie.items():
                    if self._is_session_cookie(name):
                        session_values.append(morsel.value)
            except:
                continue

        return ','.join(session_values)

    def _has_csrf_token(self, html: str) -> bool:
        """Check if HTML contains CSRF token"""

        csrf_patterns = [
            r'name=["\']csrf[_-]?token["\']',
            r'name=["\']_token["\']',
            r'name=["\']authenticity_token["\']',
            r'name=["\']csrfmiddlewaretoken["\']',
            r'X-CSRF-Token',
            r'X-XSRF-Token'
        ]

        for pattern in csrf_patterns:
            if re.search(pattern, html, re.IGNORECASE):
                return True

        return False


def get_module(module_path: str, payload_limit: int = None):
    """Factory function to create module instance"""
    return SessionManagementScanner(module_path, payload_limit=payload_limit)
