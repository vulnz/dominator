"""
HTTP Login Bruteforce Module

Bruteforce HTTP login forms with comprehensive features:
- Automatic login form detection
- CSRF token extraction and submission
- Success/failure detection via multiple methods
- Default credentials database (nndefaccts style)
- Custom username/password list support
- Rate limiting and lockout detection
- Admin panel detection and targeting
"""

from typing import List, Dict, Any, Optional, Tuple, Set
from core.base_module import BaseModule
from core.logger import get_logger
from urllib.parse import urljoin, urlparse, parse_qs, urlencode
import re
import time

logger = get_logger(__name__)


class HTTPBruteforceModule(BaseModule):
    """HTTP Login Bruteforce Scanner Module"""

    def __init__(self, module_path: str, payload_limit: int = None):
        """Initialize HTTP Bruteforce module"""
        super().__init__(module_path, payload_limit=payload_limit)

        self.tested_urls: Set[str] = set()

        # Common username field names
        self.username_fields = [
            'username', 'user', 'login', 'email', 'name', 'uname', 'userid',
            'user_name', 'user_login', 'log', 'usr', 'account', 'user_id',
            'userName', 'userLogin', 'loginId', 'j_username', 'txtUser',
            'txtUsername', 'ctl00$MainContent$LoginUser$UserName'
        ]

        # Common password field names
        self.password_fields = [
            'password', 'pass', 'pwd', 'passwd', 'secret', 'passw',
            'user_password', 'user_pass', 'loginpassword', 'j_password',
            'txtPassword', 'txtPass', 'ctl00$MainContent$LoginUser$Password'
        ]

        # CSRF token field names
        self.csrf_fields = [
            'csrf', 'csrf_token', 'csrftoken', '_csrf', 'token', '_token',
            'authenticity_token', 'csrfmiddlewaretoken', '__RequestVerificationToken',
            'anti-csrf-token', 'anticsrf', 'xsrf', '_xsrf', 'xsrf_token',
            'formToken', 'formkey', 'form_key', 'nonce', '_wpnonce',
            'security_token', 'YII_CSRF_TOKEN'
        ]

        # Default credentials database (nndefaccts style)
        self._init_default_credentials()

        # Success indicators (login worked)
        self.success_indicators = [
            'logout', 'sign out', 'sign-out', 'signout', 'log out', 'log-out',
            'dashboard', 'welcome', 'my account', 'my-account', 'myaccount',
            'profile', 'settings', 'admin panel', 'control panel', 'home',
            'successfully logged', 'login successful', 'authentication successful'
        ]

        # Failure indicators
        self.failure_indicators = [
            'invalid', 'incorrect', 'wrong', 'failed', 'error', 'denied',
            'unauthorized', 'bad credentials', 'login failed', 'try again',
            'authentication failed', 'access denied', 'invalid credentials',
            'invalid username', 'invalid password', 'user not found',
            'account locked', 'account disabled'
        ]

        # Lockout indicators
        self.lockout_indicators = [
            'locked', 'lockout', 'too many', 'blocked', 'banned', 'suspended',
            'temporarily disabled', 'try again later', 'rate limit',
            'captcha', 'recaptcha', 'verify you are human'
        ]

        logger.info(f"HTTP Bruteforce module loaded: {len(self.default_credentials)} default credential sets")

    def _init_default_credentials(self):
        """Initialize default credentials database (inspired by nndefaccts)"""
        # Format: (username, password, product/context)
        self.default_credentials = [
            # Generic defaults
            ('admin', 'admin', 'Generic'),
            ('admin', 'password', 'Generic'),
            ('admin', '123456', 'Generic'),
            ('admin', 'admin123', 'Generic'),
            ('admin', 'administrator', 'Generic'),
            ('administrator', 'administrator', 'Generic'),
            ('root', 'root', 'Generic'),
            ('root', 'toor', 'Generic'),
            ('root', 'password', 'Generic'),
            ('user', 'user', 'Generic'),
            ('user', 'password', 'Generic'),
            ('test', 'test', 'Generic'),
            ('guest', 'guest', 'Generic'),
            ('demo', 'demo', 'Generic'),

            # Web panels and CMS
            ('admin', 'admin', 'WordPress'),
            ('admin', 'changeme', 'Generic Panel'),
            ('admin', '', 'Router'),
            ('admin', '1234', 'Router'),

            # Routers and networking
            ('admin', 'admin', 'D-Link'),
            ('admin', 'password', 'Linksys'),
            ('admin', '1234', 'ZyXEL'),
            ('admin', '', 'TP-Link'),
            ('cisco', 'cisco', 'Cisco'),
            ('admin', 'motorola', 'Motorola'),
            ('admin', 'netgear1', 'Netgear'),
            ('admin', 'sky', 'Sky Router'),

            # Databases
            ('root', '', 'MySQL'),
            ('postgres', 'postgres', 'PostgreSQL'),
            ('sa', '', 'MSSQL'),
            ('sa', 'sa', 'MSSQL'),
            ('mongo', 'mongo', 'MongoDB'),

            # Application servers
            ('tomcat', 'tomcat', 'Tomcat'),
            ('admin', 'tomcat', 'Tomcat'),
            ('manager', 'manager', 'Tomcat'),
            ('admin', 'admin', 'JBoss'),
            ('weblogic', 'weblogic', 'WebLogic'),

            # Monitoring/DevOps
            ('admin', 'admin', 'Grafana'),
            ('admin', 'admin', 'Kibana'),
            ('admin', 'admin', 'Jenkins'),
            ('elastic', 'changeme', 'Elasticsearch'),
            ('admin', 'pfsense', 'pfSense'),

            # IoT and cameras
            ('admin', 'admin', 'IP Camera'),
            ('admin', '12345', 'Hikvision'),
            ('admin', '', 'Dahua'),
            ('root', 'vizxv', 'Dahua'),
            ('root', 'xc3511', 'Xiongmai'),
            ('root', 'hi3518', 'HiSilicon'),

            # Enterprise
            ('admin', 'admin', 'Oracle'),
            ('system', 'manager', 'Oracle'),
            ('admin', 'secret', 'Generic'),
            ('operator', 'operator', 'Generic'),
            ('user', '123456', 'Generic'),

            # Zendesk and SaaS
            ('admin', 'zendesk', 'Zendesk'),
            ('admin@example.com', 'admin', 'Zendesk'),

            # Custom additions
            ('superadmin', 'superadmin', 'Generic'),
            ('sysadmin', 'sysadmin', 'Generic'),
            ('support', 'support', 'Generic'),
            ('helpdesk', 'helpdesk', 'Generic'),
        ]

        # Product-specific mappings for targeted attacks
        self.product_credentials = {
            'wordpress': [('admin', 'admin'), ('admin', 'password'), ('admin', 'wordpress')],
            'joomla': [('admin', 'admin'), ('admin', 'joomla')],
            'drupal': [('admin', 'admin'), ('admin', 'drupal')],
            'tomcat': [('tomcat', 'tomcat'), ('admin', 'admin'), ('manager', 'manager')],
            'jenkins': [('admin', 'admin'), ('admin', 'password')],
            'grafana': [('admin', 'admin')],
            'phpmyadmin': [('root', ''), ('root', 'root'), ('root', 'password')],
            'adminer': [('root', ''), ('root', 'root')],
            'weblogic': [('weblogic', 'weblogic'), ('weblogic', 'welcome1')],
            'jboss': [('admin', 'admin'), ('jboss', 'jboss')],
            'glassfish': [('admin', 'admin'), ('admin', 'adminadmin')],
        }

    def scan(self, targets: List[Dict[str, Any]], http_client: Any) -> List[Dict[str, Any]]:
        """
        Scan for weak/default credentials

        Args:
            targets: List of URLs (login pages/admin panels)
            http_client: HTTP client

        Returns:
            List of vulnerability results
        """
        results = []
        self.tested_urls = set()

        # Get unique URLs
        urls_to_test = set()
        for target in targets:
            url = target.get('url', '')
            if url:
                urls_to_test.add(url)

        logger.info(f"HTTP Bruteforce scanning {len(urls_to_test)} URLs")

        for url in urls_to_test:
            if self.should_stop():
                break

            if url in self.tested_urls:
                continue
            self.tested_urls.add(url)

            try:
                # Detect if this is a login page
                login_form = self._detect_login_form(url, http_client)

                if login_form:
                    logger.info(f"Login form detected at {url}")

                    # Determine product for targeted credentials
                    product = self._detect_product(url, login_form.get('html', ''))

                    # Get credentials to try
                    credentials = self._get_credentials_for_product(product)

                    # Try credentials
                    valid_creds = self._bruteforce_login(
                        url, login_form, credentials, http_client
                    )

                    for cred in valid_creds:
                        result = self._create_finding(url, cred, login_form)
                        results.append(result)

            except Exception as e:
                logger.debug(f"Error testing {url}: {e}")

        logger.info(f"HTTP Bruteforce complete: {len(results)} weak credentials found")
        return results

    def _detect_login_form(self, url: str, http_client: Any) -> Optional[Dict]:
        """Detect and parse login form on page"""
        try:
            response = http_client.get(url, timeout=10)
            if not response or response.status_code != 200:
                return None

            html = getattr(response, 'text', '') or ''

            # Find forms
            form_pattern = r'<form[^>]*>(.*?)</form>'
            forms = re.findall(form_pattern, html, re.IGNORECASE | re.DOTALL)

            for form_html in forms:
                # Check if it looks like a login form
                has_password = bool(re.search(r'type=["\']password["\']', form_html, re.IGNORECASE))

                if not has_password:
                    continue

                # Extract form action
                action_match = re.search(r'<form[^>]*action=["\']([^"\']+)["\']', html, re.IGNORECASE)
                action = action_match.group(1) if action_match else url

                # Extract method
                method_match = re.search(r'<form[^>]*method=["\']([^"\']+)["\']', html, re.IGNORECASE)
                method = (method_match.group(1) if method_match else 'POST').upper()

                # Find input fields
                inputs = self._extract_form_inputs(form_html)

                # Identify username, password, and CSRF fields
                username_field = None
                password_field = None
                csrf_field = None
                csrf_value = None
                other_fields = {}

                for name, value, input_type in inputs:
                    name_lower = name.lower()

                    if input_type == 'password':
                        password_field = name
                    elif any(uf in name_lower for uf in self.username_fields):
                        username_field = name
                    elif any(cf in name_lower for cf in self.csrf_fields):
                        csrf_field = name
                        csrf_value = value
                    elif input_type == 'hidden' and value:
                        other_fields[name] = value
                    elif input_type == 'text' and not username_field:
                        # Fallback: first text field might be username
                        username_field = name

                if username_field and password_field:
                    return {
                        'url': url,
                        'action': urljoin(url, action),
                        'method': method,
                        'username_field': username_field,
                        'password_field': password_field,
                        'csrf_field': csrf_field,
                        'csrf_value': csrf_value,
                        'other_fields': other_fields,
                        'html': html
                    }

        except Exception as e:
            logger.debug(f"Error detecting login form: {e}")

        return None

    def _extract_form_inputs(self, form_html: str) -> List[Tuple[str, str, str]]:
        """Extract input fields from form HTML"""
        inputs = []

        # Match input tags
        input_pattern = r'<input[^>]*>'
        for match in re.finditer(input_pattern, form_html, re.IGNORECASE):
            tag = match.group(0)

            # Extract name
            name_match = re.search(r'name=["\']([^"\']+)["\']', tag, re.IGNORECASE)
            if not name_match:
                continue
            name = name_match.group(1)

            # Extract value
            value_match = re.search(r'value=["\']([^"\']*)["\']', tag, re.IGNORECASE)
            value = value_match.group(1) if value_match else ''

            # Extract type
            type_match = re.search(r'type=["\']([^"\']+)["\']', tag, re.IGNORECASE)
            input_type = type_match.group(1).lower() if type_match else 'text'

            inputs.append((name, value, input_type))

        return inputs

    def _detect_product(self, url: str, html: str) -> str:
        """Detect product/platform for targeted credential testing"""
        url_lower = url.lower()
        html_lower = html.lower()

        product_indicators = {
            'wordpress': ['wp-login', 'wordpress', 'wp-admin', 'wp-content'],
            'joomla': ['joomla', 'administrator/index.php', 'com_users'],
            'drupal': ['drupal', 'user/login', 'sites/default'],
            'tomcat': ['tomcat', 'manager/html', 'host-manager'],
            'jenkins': ['jenkins', 'j_acegi_security_check'],
            'grafana': ['grafana', '/login'],
            'phpmyadmin': ['phpmyadmin', 'pma', 'phpMyAdmin'],
            'adminer': ['adminer'],
            'weblogic': ['weblogic', '/console'],
            'jboss': ['jboss', '/jmx-console', '/admin-console'],
            'glassfish': ['glassfish', '/common/index.jsf'],
            'zendesk': ['zendesk', '.zendesk.com'],
        }

        for product, indicators in product_indicators.items():
            for indicator in indicators:
                if indicator in url_lower or indicator in html_lower:
                    return product

        return 'generic'

    def _get_credentials_for_product(self, product: str) -> List[Tuple[str, str, str]]:
        """Get credentials to try for a specific product"""
        credentials = []

        # Add product-specific credentials first
        if product in self.product_credentials:
            for username, password in self.product_credentials[product]:
                credentials.append((username, password, product))

        # Add generic defaults
        for username, password, context in self.default_credentials:
            if (username, password, context) not in credentials:
                credentials.append((username, password, context))

        # Limit total attempts
        max_attempts = self.config.get('parameters', {}).get('max_attempts', 50)
        return credentials[:max_attempts]

    def _bruteforce_login(self, url: str, form: Dict, credentials: List[Tuple],
                           http_client: Any) -> List[Dict]:
        """Attempt login with credentials"""
        valid_credentials = []
        delay = self.config.get('parameters', {}).get('delay_between_requests', 0.5)

        # Get baseline response for comparison
        baseline = self._get_baseline_response(url, form, http_client)

        for username, password, context in credentials:
            if self.should_stop():
                break

            try:
                # Refresh CSRF token if needed
                if form.get('csrf_field'):
                    new_form = self._detect_login_form(url, http_client)
                    if new_form:
                        form['csrf_value'] = new_form.get('csrf_value')

                # Build form data
                data = {
                    form['username_field']: username,
                    form['password_field']: password,
                }

                # Add CSRF token
                if form.get('csrf_field') and form.get('csrf_value'):
                    data[form['csrf_field']] = form['csrf_value']

                # Add other hidden fields
                for field, value in form.get('other_fields', {}).items():
                    data[field] = value

                # Submit login
                if form['method'] == 'POST':
                    response = http_client.post(form['action'], data=data,
                                                 allow_redirects=True, timeout=10)
                else:
                    response = http_client.get(form['action'], params=data,
                                                allow_redirects=True, timeout=10)

                if not response:
                    continue

                # Check for lockout
                if self._is_locked_out(response):
                    logger.warning(f"Account lockout detected at {url}")
                    break

                # Check if login succeeded
                if self._is_login_successful(response, baseline):
                    logger.warning(f"Valid credentials found: {username}:{password}")
                    valid_credentials.append({
                        'username': username,
                        'password': password,
                        'context': context,
                        'response_url': str(response.url) if hasattr(response, 'url') else url
                    })
                    # Don't continue after finding valid creds (to avoid lockout)
                    break

                time.sleep(delay)

            except Exception as e:
                logger.debug(f"Error testing {username}:{password}: {e}")

        return valid_credentials

    def _get_baseline_response(self, url: str, form: Dict, http_client: Any) -> Dict:
        """Get baseline response with known-bad credentials"""
        try:
            data = {
                form['username_field']: 'invalid_user_xyz123',
                form['password_field']: 'invalid_pass_xyz123',
            }

            if form.get('csrf_field') and form.get('csrf_value'):
                data[form['csrf_field']] = form['csrf_value']

            for field, value in form.get('other_fields', {}).items():
                data[field] = value

            if form['method'] == 'POST':
                response = http_client.post(form['action'], data=data,
                                             allow_redirects=True, timeout=10)
            else:
                response = http_client.get(form['action'], params=data,
                                            allow_redirects=True, timeout=10)

            if response:
                return {
                    'status_code': response.status_code,
                    'text': getattr(response, 'text', '') or '',
                    'url': str(response.url) if hasattr(response, 'url') else url,
                    'length': len(getattr(response, 'text', '') or '')
                }
        except:
            pass

        return {}

    def _is_login_successful(self, response, baseline: Dict) -> bool:
        """Determine if login was successful"""
        response_text = (getattr(response, 'text', '') or '').lower()
        response_url = str(response.url).lower() if hasattr(response, 'url') else ''

        # Check for success indicators
        for indicator in self.success_indicators:
            if indicator in response_text or indicator in response_url:
                # Make sure it's not in the baseline too
                if indicator not in baseline.get('text', '').lower():
                    return True

        # Check for absence of failure indicators
        has_failure = any(ind in response_text for ind in self.failure_indicators)

        if has_failure:
            return False

        # Check for significant changes from baseline
        if baseline:
            # Different URL (redirect to dashboard?)
            if response_url != baseline.get('url', '').lower():
                if 'login' not in response_url and 'error' not in response_url:
                    return True

            # Different content length (dashboard has more content)
            current_len = len(getattr(response, 'text', '') or '')
            baseline_len = baseline.get('length', 0)

            if current_len > baseline_len * 1.5:
                return True

        return False

    def _is_locked_out(self, response) -> bool:
        """Check if account is locked out"""
        response_text = (getattr(response, 'text', '') or '').lower()

        for indicator in self.lockout_indicators:
            if indicator in response_text:
                return True

        # Check for rate limiting status codes
        if response.status_code in [429, 403]:
            return True

        return False

    def _create_finding(self, url: str, cred: Dict, form: Dict) -> Dict[str, Any]:
        """Create a finding for valid credentials"""

        evidence = f"""Default/Weak Credentials Found

**Login URL:** {url}
**Form Action:** {form['action']}

**Valid Credentials:**
- Username: {cred['username']}
- Password: {cred['password']}
- Context/Product: {cred['context']}

**Form Details:**
- Username field: {form['username_field']}
- Password field: {form['password_field']}
- CSRF protected: {'Yes' if form.get('csrf_field') else 'No'}

**Post-Login URL:** {cred.get('response_url', 'N/A')}

**Security Impact:**
- Unauthorized access to the application
- Potential administrative access
- Data theft and manipulation
- Complete system compromise

**Remediation:**
- Change default credentials immediately
- Implement strong password policy
- Enable multi-factor authentication
- Implement account lockout after failed attempts
- Monitor for bruteforce attempts
"""

        result = self.create_result(
            vulnerable=True,
            url=url,
            parameter='Authentication',
            payload=f'{cred["username"]}:{cred["password"]}',
            evidence=evidence,
            description=f"Default/weak credentials found: {cred['username']}:{cred['password']}. Immediate action required.",
            confidence=0.98,
            severity='Critical',
            method='POST',
            response=f"Successfully authenticated as {cred['username']}"
        )

        result['username'] = cred['username']
        result['password'] = cred['password']
        result['product'] = cred['context']
        result['login_url'] = url
        result['form_action'] = form['action']
        result['verified'] = True

        return result


def get_module(module_path: str, payload_limit: int = None):
    """Create module instance"""
    return HTTPBruteforceModule(module_path, payload_limit=payload_limit)
