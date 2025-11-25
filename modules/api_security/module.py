"""
API Security Scanner
Advanced API security testing including BOLA, HTTP verb tampering, mass assignment, and auth bypass
"""

from core.base_module import BaseModule
from core.http_client import HTTPClient
from core.logger import get_logger
from typing import List, Dict, Any
import json
import re
from urllib.parse import urlparse, urljoin, parse_qs, urlunparse

logger = get_logger(__name__)


class APISecurityScanner(BaseModule):
    """Scans for API security vulnerabilities"""

    def __init__(self, module_path: str, payload_limit: int = None):
        super().__init__(module_path, payload_limit=payload_limit)
        self.module_name = "API Security"
        self.logger = logger

    def scan(self, targets: List[Dict[str, Any]], http_client: Any = None) -> List[Dict[str, Any]]:
        """
        Scan targets for API security vulnerabilities

        Args:
            targets: List of targets to scan
            http_client: HTTP client for making requests

        Returns:
            List of vulnerability findings
        """
        self.logger.info(f"Starting {self.module_name} scan on {len(targets)} targets")

        results = []
        client = http_client or HTTPClient(timeout=8)

        # Track consolidated findings (rate limit bypass headers, etc.)
        rate_limit_bypass_headers = {}  # url -> list of headers

        for target in targets:
            url = target.get('url')
            if not url:
                continue

            # Test each payload
            for payload in self.payloads[:self.payload_limit]:
                payload = payload.strip()
                if not payload or payload.startswith('#'):
                    continue

                # Special handling for rate limit - collect instead of creating individual findings
                if payload.startswith('RATE_LIMIT:'):
                    header_name = payload.split(':', 1)[1] if ':' in payload else payload
                    bypass_result = self._test_rate_limit_bypass_check(client, url, header_name)
                    if bypass_result:
                        if url not in rate_limit_bypass_headers:
                            rate_limit_bypass_headers[url] = []
                        rate_limit_bypass_headers[url].append(header_name)
                    continue

                finding = self._test_api_payload(client, url, payload)
                if finding:
                    results.append(finding)

                    # Early exit if configured
                    if self.config.get('early_exit', False):
                        break

        # Create consolidated rate limit bypass findings (one per URL)
        for url, headers in rate_limit_bypass_headers.items():
            if headers:
                results.append({
                    'vulnerability': True,
                    'module': self.module_name,
                    'type': 'Rate Limiting Bypass',
                    'severity': 'Medium',
                    'url': url,
                    'parameter': 'IP Spoofing Headers',
                    'payload': ', '.join(headers),
                    'method': 'GET',
                    'confidence': 0.70,
                    'description': f'Rate limiting can be bypassed using {len(headers)} different headers: {", ".join(headers)}',
                    'evidence': f'Bypass headers: {", ".join(headers)}',
                    'recommendation': 'Implement server-side rate limiting based on actual source IP. Do not trust client-supplied IP headers.',
                    'cwe': 'CWE-770',
                    'cvss': 5.3,
                    'owasp': 'API4:2023',
                    'references': []
                })

        client.close()
        self.logger.info(f"{self.module_name} scan complete: {len(results)} vulnerabilities found")
        return results

    def _test_api_payload(self, client: HTTPClient, url: str, payload: str) -> Dict[str, Any]:
        """Test a single API security payload"""

        try:
            # Parse payload type
            vuln_type = 'API Misconfiguration'
            severity = 'High'
            payload_type = 'UNKNOWN'
            payload_data = payload

            if ':' in payload:
                parts = payload.split(':', 1)
                payload_type = parts[0]
                if len(parts) > 1:
                    payload_data = parts[1]

            # Test based on payload type
            if payload_type == 'BOLA':
                return self._test_bola(client, url, payload_data)

            elif payload_type == 'VERB':
                return self._test_verb_tampering(client, url, payload_data)

            elif payload_type == 'MASS_ASSIGN':
                return self._test_mass_assignment(client, url, payload_data)

            elif payload_type == 'AUTH_BYPASS':
                return self._test_auth_bypass(client, url, payload_data)

            elif payload_type == 'POLLUTION':
                return self._test_parameter_pollution(client, url, payload_data)

            elif payload_type == 'CONTENT_TYPE':
                return self._test_content_type_tampering(client, url, payload_data)

            elif payload_type == 'RATE_LIMIT':
                return self._test_rate_limit_bypass(client, url, payload_data)

            elif payload_type in ['SQLI_API', 'NOSQL_API', 'XSS_API', 'PATH_TRAV', 'CMDI_API', 'SSRF_API', 'XXE_API']:
                return self._test_injection(client, url, payload_type, payload_data)

        except Exception as e:
            self.logger.debug(f"Error testing API payload: {str(e)}")

        return None

    def _test_bola(self, client: HTTPClient, url: str, payload_data: str) -> Dict[str, Any]:
        """Test for BOLA (Broken Object Level Authorization)"""

        # Extract ID type and value
        if ':' in payload_data:
            id_type, id_value = payload_data.split(':', 1)
        else:
            return None

        # Replace ID in URL path or query
        test_url = self._replace_id_in_url(url, id_value)

        # Send request with different ID
        response = client.get(test_url)

        if response and response.status_code == 200:
            # Check if response contains sensitive data
            if self._contains_sensitive_data(response.text):
                return {
                    'vulnerability': True,
                    'module': self.module_name,
                    'type': 'BOLA/IDOR (Broken Object Level Authorization)',
                    'severity': 'Critical',
                    'url': test_url,
                    'parameter': 'id',
                    'payload': id_value,
                    'method': 'GET',
                    'confidence': 0.75,
                    'description': f'BOLA vulnerability detected. Accessed object with ID "{id_value}" without proper authorization.',
                    'evidence': f'Response contains sensitive data (status: {response.status_code})',
                    'recommendation': 'Implement proper object-level authorization checks. Verify user has permission to access requested resources.',
                    'cwe': 'CWE-639',
                    'cvss': 8.2,
                    'owasp': 'API1:2023',
                    'references': [
                        'https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/',
                        'https://cwe.mitre.org/data/definitions/639.html'
                    ]
                }

        return None

    def _test_verb_tampering(self, client: HTTPClient, url: str, payload_data: str) -> Dict[str, Any]:
        """Test for HTTP verb tampering"""

        verb_map = {
            'GET_TO_POST': ('GET', 'POST'),
            'POST_TO_GET': ('POST', 'GET'),
            'GET_TO_PUT': ('GET', 'PUT'),
            'GET_TO_DELETE': ('GET', 'DELETE'),
            'POST_TO_PUT': ('POST', 'PUT'),
            'POST_TO_PATCH': ('POST', 'PATCH'),
            'POST_TO_DELETE': ('POST', 'DELETE'),
            'PUT_TO_POST': ('PUT', 'POST'),
            'DELETE_TO_GET': ('DELETE', 'GET')
        }

        if payload_data not in verb_map:
            return None

        original_verb, tampered_verb = verb_map[payload_data]

        # Send request with tampered verb
        response_tampered = client.request(tampered_verb, url)
        response_original = client.request(original_verb, url)

        if response_tampered and response_original:
            # Check if tampered verb bypasses restrictions
            if response_tampered.status_code == 200 and response_original.status_code != 200:
                return {
                    'vulnerability': True,
                    'module': self.module_name,
                    'type': 'HTTP Verb Tampering',
                    'severity': 'High',
                    'url': url,
                    'parameter': 'HTTP Method',
                    'payload': f'{original_verb} -> {tampered_verb}',
                    'method': tampered_verb,
                    'confidence': 0.80,
                    'description': f'HTTP verb tampering vulnerability. {tampered_verb} bypasses restrictions that apply to {original_verb}.',
                    'evidence': f'{tampered_verb} returned 200, {original_verb} returned {response_original.status_code}',
                    'recommendation': 'Implement consistent authorization checks across all HTTP methods.',
                    'cwe': 'CWE-650',
                    'cvss': 7.5,
                    'owasp': 'API3:2023',
                    'references': [
                        'https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/06-Test_HTTP_Methods'
                    ]
                }

        return None

    def _test_mass_assignment(self, client: HTTPClient, url: str, payload_data: str) -> Dict[str, Any]:
        """Test for mass assignment vulnerabilities"""

        try:
            # Parse JSON payload
            mass_assign_data = json.loads(payload_data)

            # Send POST/PUT request with mass assignment payload
            for method in ['POST', 'PUT', 'PATCH']:
                response = client.request(
                    method,
                    url,
                    data=json.dumps(mass_assign_data),
                    headers={'Content-Type': 'application/json'}
                )

                if response and response.status_code in [200, 201, 204]:
                    # Check if privileged fields were accepted
                    privileged_fields = ['isAdmin', 'role', 'admin', 'is_admin', 'user_role', 'permissions', 'access_level']
                    if any(field in payload_data for field in privileged_fields):
                        return {
                            'vulnerability': True,
                            'module': self.module_name,
                            'type': 'Mass Assignment',
                            'severity': 'Critical',
                            'url': url,
                            'parameter': 'JSON Body',
                            'payload': payload_data,
                            'method': method,
                            'confidence': 0.70,
                            'description': 'Mass assignment vulnerability detected. Privileged fields can be modified.',
                            'evidence': f'{method} request with privileged fields returned {response.status_code}',
                            'recommendation': 'Implement strict input validation. Use allow-lists for mass assignment. Never expose internal object properties.',
                            'cwe': 'CWE-915',
                            'cvss': 8.1,
                            'owasp': 'API6:2023',
                            'references': [
                                'https://owasp.org/API-Security/editions/2023/en/0xa6-unrestricted-access-to-sensitive-business-flows/',
                                'https://cwe.mitre.org/data/definitions/915.html'
                            ]
                        }

        except:
            pass

        return None

    def _test_auth_bypass(self, client: HTTPClient, url: str, payload_data: str) -> Dict[str, Any]:
        """Test for authentication bypass via headers"""

        if ':' not in payload_data:
            return None

        parts = payload_data.split(':', 1)
        if len(parts) != 2:
            return None

        bypass_type, bypass_value = parts

        if bypass_type == 'HEADER':
            header_parts = bypass_value.split(':', 1)
            if len(header_parts) != 2:
                return None

            header_name, header_value = header_parts

            # Send request with bypass header
            response = client.get(url, headers={header_name: header_value})

            if response and response.status_code == 200:
                # Check if admin/restricted content is accessible
                if any(keyword in response.text.lower() for keyword in ['admin', 'dashboard', 'management', 'privileged']):
                    return {
                        'vulnerability': True,
                        'module': self.module_name,
                        'type': 'Authentication Bypass',
                        'severity': 'Critical',
                        'url': url,
                        'parameter': header_name,
                        'payload': header_value,
                        'method': 'GET',
                        'confidence': 0.75,
                        'description': f'Authentication bypass via {header_name} header.',
                        'evidence': f'Restricted content accessible with {header_name}: {header_value}',
                        'recommendation': 'Do not trust client-supplied headers for authentication/authorization decisions.',
                        'cwe': 'CWE-290',
                        'cvss': 9.1,
                        'owasp': 'API2:2023',
                        'references': [
                            'https://owasp.org/API-Security/editions/2023/en/0xa2-broken-authentication/'
                        ]
                    }

        return None

    def _test_parameter_pollution(self, client: HTTPClient, url: str, payload_data: str) -> Dict[str, Any]:
        """Test for parameter pollution - DISABLED due to high false positive rate

        Note: Accepting duplicate parameters is NORMAL behavior for most frameworks.
        HPP is only exploitable in specific multi-component scenarios.
        This check has been disabled to prevent false positives.
        """
        # HPP detection disabled - accepting duplicate params is not a vulnerability by itself
        # Only specific HPP scenarios (like WAF bypass or component desync) are real vulnerabilities
        return None

    def _test_content_type_tampering(self, client: HTTPClient, url: str, content_type: str) -> Dict[str, Any]:
        """Test for content-type tampering"""

        test_data = '{"test": "data"}'
        response = client.post(url, data=test_data, headers={'Content-Type': content_type})

        if response and response.status_code in [200, 201]:
            return {
                'vulnerability': True,
                'module': self.module_name,
                'type': 'Content-Type Tampering',
                'severity': 'Medium',
                'url': url,
                'parameter': 'Content-Type',
                'payload': content_type,
                'method': 'POST',
                'confidence': 0.65,
                'description': 'Application accepts unexpected Content-Type headers.',
                'evidence': f'Request with Content-Type: {content_type} succeeded',
                'recommendation': 'Strictly validate Content-Type headers. Reject unexpected content types.',
                'cwe': 'CWE-436',
                'cvss': 5.3,
                'owasp': 'A03:2021',
                'references': []
            }

        return None

    def _test_rate_limit_bypass_check(self, client: HTTPClient, url: str, header_name: str) -> bool:
        """Check if rate limiting can be bypassed with header (returns True/False only)"""
        try:
            # Send multiple requests with different header values
            for i in range(5):
                headers = {header_name: f'192.168.1.{i}'}
                response = client.get(url, headers=headers)
                if not response or response.status_code != 200:
                    return False
            # If all 5 requests succeeded, header might bypass rate limiting
            return True
        except:
            return False

    def _test_rate_limit_bypass(self, client: HTTPClient, url: str, header_name: str) -> Dict[str, Any]:
        """Test for rate limiting bypass - DEPRECATED, use scan() consolidation instead"""
        # This is now handled in scan() to consolidate findings
        return None

    def _test_injection(self, client: HTTPClient, url: str, injection_type: str, payload: str) -> Dict[str, Any]:
        """Test for injection vulnerabilities in API parameters with STRONG detection"""

        # IMPORTANT: Don't add payload to NEW parameter - this causes false positives!
        # Instead, test on existing parameters from the target
        # For now, skip this test if no existing params (avoid FP)
        if '?' not in url:
            return None  # No existing parameters to test

        # Add payload to URL parameters
        test_url = f"{url}&test={payload}"
        response = client.get(test_url)

        if response:
            # STRONG detection indicators - use unique markers, not generic words
            indicators = {
                'SQLI_API': ['you have an error in your sql syntax', 'mysql_fetch', 'ora-01756', 'sqlite_error', 'postgresql error'],
                'NOSQL_API': ['mongodb error:', 'bson parse error', 'couchdb error'],
                # XSS_API: Use UNIQUE MARKER not the payload itself!
                'XSS_API': ['DMNTR'],  # Must use unique marker like <script>alert('DMNTR')</script>
                'PATH_TRAV': ['root:x:0:0:', '[boot loader]', 'windows\\system32'],
                'CMDI_API': ['uid=0(root)', 'uid=1000', 'gid=0(root)'],
                'SSRF_API': ['ec2.internal', 'instance-id', 'ami-id'],
                'XXE_API': ['<!ENTITY', '<!DOCTYPE']
            }

            if injection_type in indicators:
                for indicator in indicators[injection_type]:
                    if indicator.lower() in response.text.lower():
                        # Additional confidence check - avoid FP on generic words
                        confidence = 0.80

                        # Lower confidence for generic indicators
                        if len(indicator) < 10 and injection_type not in ['XSS_API']:
                            confidence = 0.60

                        return {
                            'vulnerability': True,
                            'module': self.module_name,
                            'type': f'API {injection_type.replace("_API", "")}',
                            'severity': 'Critical' if 'SQLI' in injection_type or 'CMDI' in injection_type else 'High',
                            'url': test_url,
                            'parameter': 'test',
                            'payload': payload,
                            'method': 'GET',
                            'confidence': confidence,
                            'description': f'{injection_type.replace("_API", "")} vulnerability in API parameter.',
                            'evidence': f'Strong indicator "{indicator}" found in response',
                            'recommendation': 'Implement input validation and output encoding. Use parameterized queries.',
                            'cwe': 'CWE-89' if 'SQL' in injection_type else 'CWE-78',
                            'cvss': 9.0 if 'SQL' in injection_type or 'CMD' in injection_type else 7.5,
                            'owasp': 'API8:2023',
                            'references': []
                        }

        return None

    def _replace_id_in_url(self, url: str, new_id: str) -> str:
        """Replace ID in URL path or query parameters"""

        # Try to replace numeric ID in path
        url = re.sub(r'/\d+([/?]|$)', f'/{new_id}\\1', url)

        # Try to replace id parameter
        if '?' in url:
            base, query = url.split('?', 1)
            params = parse_qs(query)

            # Replace id-like parameters
            for key in ['id', 'user_id', 'userId', 'uid']:
                if key in params:
                    params[key] = [new_id]

            # Reconstruct URL
            new_query = '&'.join([f'{k}={v[0]}' for k, v in params.items()])
            return f'{base}?{new_query}'

        return url

    def _contains_sensitive_data(self, text: str) -> bool:
        """Check if response contains sensitive data"""

        sensitive_keywords = [
            'password', 'ssn', 'social security', 'credit card', 'api_key', 'apiKey',
            'secret', 'token', 'private', 'confidential', 'salary', 'email',
            'phone', 'address', 'dob', 'birth'
        ]

        text_lower = text.lower()
        return any(keyword in text_lower for keyword in sensitive_keywords)


def get_module(module_path: str, payload_limit: int = None):
    """Factory function to create module instance"""
    return APISecurityScanner(module_path, payload_limit=payload_limit)
