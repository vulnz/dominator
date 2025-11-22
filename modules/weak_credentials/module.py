"""
Weak Credentials Scanner Module

Detects weak passwords and authentication bypass by:
1. Testing login forms with common weak credentials
2. Detecting default username/password combinations
3. Testing SQL injection authentication bypass
4. Analyzing success/failure indicators in responses
5. Comparing response differences to detect successful logins
"""

from typing import List, Dict, Any
from core.base_module import BaseModule
from core.logger import get_logger
from detectors.weak_authentication_detector import WeakAuthenticationDetector

logger = get_logger(__name__)


class WeakCredentialsModule(BaseModule):
    """Weak credentials vulnerability scanner module"""

    def __init__(self, module_path: str, payload_limit: int = None):
        """Initialize Weak Credentials module"""
        super().__init__(module_path, payload_limit=payload_limit)

        # Parse username:password format from payloads
        self.credentials = []
        for payload in self.payloads:
            if ':' in payload:
                username, password = payload.split(':', 1)
                self.credentials.append({'username': username, 'password': password})

        # Add auth bypass payloads
        self.auth_bypass_payloads = WeakAuthenticationDetector.get_auth_bypass_payloads()

        logger.info(f"Weak Credentials module loaded: {len(self.credentials)} credential combinations, "
                   f"{len(self.auth_bypass_payloads)} bypass payloads")

    def scan(self, targets: List[Dict[str, Any]], http_client: Any) -> List[Dict[str, Any]]:
        """
        Scan for weak credentials and authentication bypass

        Args:
            targets: List of URLs with parameters and forms
            http_client: HTTP client

        Returns:
            List of results
        """
        results = []

        logger.info(f"Starting Weak Credentials scan on {len(targets)} targets")

        # Filter targets to only login forms (POST with username/password fields)
        login_forms = []
        for target in targets:
            if target.get('method', '').upper() == 'POST':
                params = target.get('params', {})

                # Check if form has username/password-like parameters
                has_username = any(p for p in params.keys()
                                 if p.lower() in ['username', 'user', 'login', 'email', 'uid'])
                has_password = any(p for p in params.keys()
                                 if p.lower() in ['password', 'pass', 'pwd', 'passwd'])

                if has_username and has_password:
                    login_forms.append(target)

        logger.info(f"Found {len(login_forms)} potential login forms")

        # Test each login form
        for form in login_forms[:5]:  # Limit to 5 forms to avoid too many requests
            url = form.get('url')
            params = form.get('params', {})

            logger.info(f"Testing login form: {url}")

            # Get baseline response (failed login)
            baseline_response = self._get_baseline_response(url, params, http_client)

            # Test weak credentials
            found_weak_creds = self._test_weak_credentials(
                url, params, baseline_response, http_client
            )

            for cred_info in found_weak_creds:
                result = self.create_result(
                    vulnerable=True,
                    url=url,
                    parameter=f"username={cred_info['username']}, password={cred_info['password']}",
                    payload=f"{cred_info['username']}:{cred_info['password']}",
                    evidence=cred_info['evidence'],
                    description=cred_info['description'],
                    confidence=cred_info['confidence']
                )

                result['cwe'] = cred_info['cwe']
                result['owasp'] = cred_info['owasp']
                result['cvss'] = cred_info['cvss']
                result['severity'] = cred_info['severity']
                result['remediation'] = cred_info.get('recommendation', self.config.get('remediation', ''))

                results.append(result)

        logger.info(f"Weak Credentials scan complete: {len(results)} vulnerabilities found")
        return results

    def _get_baseline_response(self, url: str, params: Dict[str, Any], http_client: Any) -> str:
        """
        Get baseline response with invalid credentials

        Args:
            url: Target URL
            params: Form parameters
            http_client: HTTP client

        Returns:
            Baseline response text
        """
        try:
            # Send request with obviously invalid credentials
            test_params = params.copy()

            for key in test_params.keys():
                if key.lower() in ['username', 'user', 'login', 'email', 'uid']:
                    test_params[key] = 'invalid_user_xyz123'
                elif key.lower() in ['password', 'pass', 'pwd', 'passwd']:
                    test_params[key] = 'invalid_pass_xyz123'

            response = http_client.post(url, data=test_params, allow_redirects=True)
            if response:
                return getattr(response, 'text', '')

        except Exception as e:
            logger.debug(f"Error getting baseline response: {e}")

        return ""

    def _test_weak_credentials(self, url: str, params: Dict[str, Any],
                               baseline_response: str, http_client: Any) -> List[Dict[str, Any]]:
        """
        Test weak credentials against login form

        Args:
            url: Target URL
            params: Form parameters
            baseline_response: Baseline failed login response
            http_client: HTTP client

        Returns:
            List of found weak credentials
        """
        found_credentials = []

        # Identify username and password parameter names
        username_param = None
        password_param = None

        for key in params.keys():
            if key.lower() in ['username', 'user', 'login', 'email', 'uid']:
                username_param = key
            elif key.lower() in ['password', 'pass', 'pwd', 'passwd']:
                password_param = key

        if not username_param or not password_param:
            logger.debug(f"Could not identify username/password parameters in form")
            return found_credentials

        # Test weak credentials
        max_attempts = self.config.get('max_attempts', 50)
        tested = 0

        for cred in self.credentials[:max_attempts]:
            username = cred['username']
            password = cred['password']

            try:
                # Prepare POST data
                post_data = params.copy()
                post_data[username_param] = username
                post_data[password_param] = password

                # Send POST request
                response = http_client.post(url, data=post_data, allow_redirects=True)
                tested += 1

                if not response:
                    continue

                response_text = getattr(response, 'text', '')
                response_code = response.status_code

                # Use WeakAuthenticationDetector to analyze response
                is_weak, evidence, severity, metadata = WeakAuthenticationDetector.detect_weak_authentication(
                    username, password, response_text, response_code, baseline_response
                )

                if is_weak:
                    description = f"Weak credentials detected! Login successful with username '{username}' and password '{password}'. "
                    description += "This application allows authentication with weak or default credentials, which is a critical security vulnerability."

                    found_credentials.append({
                        'username': username,
                        'password': password,
                        'evidence': evidence,
                        'description': description,
                        'confidence': 0.9,
                        'severity': severity,
                        'cwe': metadata.get('cwe', 'CWE-521'),
                        'owasp': metadata.get('owasp', 'A07:2021'),
                        'cvss': metadata.get('cvss', '9.8'),
                        'recommendation': metadata.get('recommendation', '')
                    })

                    logger.info(f"✓ Weak credentials found: {username}/{password} (HTTP {response_code})")

                    # Stop after first finding to avoid account lockout
                    break

            except Exception as e:
                logger.debug(f"Error testing credentials {username}:{password}: {e}")
                continue

        # Test SQL injection authentication bypass
        if not found_credentials:  # Only test bypass if no weak creds found
            bypass_results = self._test_auth_bypass(
                url, params, username_param, password_param, http_client
            )
            found_credentials.extend(bypass_results)

        return found_credentials

    def _test_auth_bypass(self, url: str, params: Dict[str, Any],
                         username_param: str, password_param: str,
                         http_client: Any) -> List[Dict[str, Any]]:
        """
        Test authentication bypass payloads

        Args:
            url: Target URL
            params: Form parameters
            username_param: Username parameter name
            password_param: Password parameter name
            http_client: HTTP client

        Returns:
            List of found bypass vulnerabilities
        """
        found_bypasses = []

        for bypass_payload in self.auth_bypass_payloads[:10]:  # Limit to 10 bypass tests
            try:
                post_data = params.copy()
                post_data[username_param] = bypass_payload['username']
                post_data[password_param] = bypass_payload['password']

                response = http_client.post(url, data=post_data, allow_redirects=True)

                if not response:
                    continue

                response_text = getattr(response, 'text', '')
                response_code = response.status_code

                # Check for authentication bypass
                payload_str = f"{bypass_payload['username']} / {bypass_payload['password']}"
                is_bypass, evidence, severity, metadata = WeakAuthenticationDetector.detect_auth_bypass(
                    payload_str, response_text, response_code
                )

                if is_bypass:
                    description = f"Authentication bypass vulnerability detected! "
                    description += f"Login successful with SQL injection payload: {payload_str}. "
                    description += "The application does not properly sanitize authentication inputs, allowing attackers to bypass login."

                    found_bypasses.append({
                        'username': bypass_payload['username'],
                        'password': bypass_payload['password'],
                        'evidence': evidence,
                        'description': description,
                        'confidence': 0.95,
                        'severity': severity,
                        'cwe': metadata.get('cwe', 'CWE-89'),
                        'owasp': metadata.get('owasp', 'A03:2021'),
                        'cvss': metadata.get('cvss', '9.8'),
                        'recommendation': metadata.get('recommendation', '')
                    })

                    logger.info(f"✓ Auth bypass found: {payload_str}")
                    break

            except Exception as e:
                logger.debug(f"Error testing bypass payload: {e}")
                continue

        return found_bypasses


def get_module(module_path: str, payload_limit: int = None):
    """Create module instance"""
    return WeakCredentialsModule(module_path, payload_limit=payload_limit)
