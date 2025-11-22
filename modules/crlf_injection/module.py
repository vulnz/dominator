"""
CRLF Injection Scanner Module
Detects HTTP header injection and response splitting vulnerabilities
"""

import re
from typing import Dict, List, Any, Optional
from urllib.parse import urlencode, parse_qs, urlparse, quote
from core.base_module import BaseModule


class Module(BaseModule):
    """CRLF Injection vulnerability scanner"""

    def __init__(self, http_client=None, config: Optional[Dict] = None):
        super().__init__(http_client, config)
        self.name = "CRLF Injection Scanner"
        self.description = "Detects CRLF injection and HTTP response splitting"
        self.payloads = []
        self.canary_header = "X-CRLF-Test"
        self.canary_value = "dominator-crlf-detected"

    def load_payloads(self) -> List[str]:
        """Load CRLF injection payloads"""
        payloads = []
        try:
            import os
            payload_file = os.path.join(os.path.dirname(__file__), 'payloads.txt')
            if os.path.exists(payload_file):
                with open(payload_file, 'r', encoding='utf-8') as f:
                    for line in f:
                        line = line.strip()
                        if line and not line.startswith('#'):
                            payloads.append(line)
        except Exception:
            pass

        if not payloads:
            payloads = [
                '%0d%0a',
                '%0D%0A',
                '%0d%0aSet-Cookie:crlf=injection',
                '%0d%0aX-Injected:true',
                '%250d%250a',
                '\\r\\n',
            ]

        self.payloads = payloads
        return payloads

    def run(self, target: str, params: Optional[Dict] = None) -> List[Dict[str, Any]]:
        """Run CRLF injection scan"""
        results = []
        self.load_payloads()

        parsed = urlparse(target)
        query_params = parse_qs(parsed.query)

        # Test URL parameters
        for param_name in query_params:
            result = self._test_parameter(target, param_name)
            if result:
                results.append(result)
                break  # One finding per URL is enough

        # Test path injection
        path_result = self._test_path_injection(target)
        if path_result:
            results.append(path_result)

        return results

    def _test_parameter(self, url: str, param: str) -> Optional[Dict]:
        """Test a parameter for CRLF injection"""
        parsed = urlparse(url)
        base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
        query_params = parse_qs(parsed.query)

        # Key payloads to test (limited for efficiency)
        test_payloads = [
            f'%0d%0a{self.canary_header}:{self.canary_value}',
            f'%0D%0A{self.canary_header}:{self.canary_value}',
            '%0d%0aSet-Cookie:crlf=injected',
            '%250d%250a' + self.canary_header + ':' + self.canary_value,
        ]

        for payload in test_payloads:
            try:
                # Build test URL
                test_params = query_params.copy()
                original_value = test_params.get(param, [''])[0]
                test_params[param] = [original_value + payload]

                query_string = '&'.join([f"{k}={v[0]}" for k, v in test_params.items()])
                test_url = f"{base_url}?{query_string}"

                response = self.http_client.get(test_url, allow_redirects=False)

                if response and self._is_crlf_vulnerable(response, payload):
                    return {
                        'vulnerability': True,
                        'type': 'CRLF Injection',
                        'severity': 'Medium',
                        'url': url,
                        'parameter': param,
                        'payload': payload,
                        'method': 'GET',
                        'injection_type': self._get_injection_type(response, payload),
                        'evidence': self._get_evidence(response, payload),
                        'description': f"CRLF injection detected in parameter '{param}'. Attacker can inject HTTP headers or split responses.",
                        'recommendation': 'Sanitize user input by removing or encoding CR (\\r) and LF (\\n) characters. Use allowlists for header values.',
                        'cwe': 'CWE-93',
                        'owasp': 'A03:2021',
                        'cvss': 6.1,
                        'response': str(response.headers)
                    }
            except Exception:
                continue

        return None

    def _test_path_injection(self, url: str) -> Optional[Dict]:
        """Test URL path for CRLF injection"""
        parsed = urlparse(url)
        base = f"{parsed.scheme}://{parsed.netloc}"

        # Test path with CRLF
        payloads = [
            f'/test%0d%0a{self.canary_header}:{self.canary_value}',
            f'/%0d%0aSet-Cookie:crlf=path',
        ]

        for payload in payloads:
            try:
                test_url = base + payload
                response = self.http_client.get(test_url, allow_redirects=False)

                if response and self._is_crlf_vulnerable(response, payload):
                    return {
                        'vulnerability': True,
                        'type': 'CRLF Injection',
                        'severity': 'Medium',
                        'url': url,
                        'parameter': 'URL path',
                        'payload': payload,
                        'method': 'GET',
                        'injection_type': 'Path-based Header Injection',
                        'evidence': self._get_evidence(response, payload),
                        'description': 'CRLF injection detected in URL path. Attacker can inject HTTP headers.',
                        'recommendation': 'Properly encode URL paths and validate input.',
                        'cwe': 'CWE-93',
                        'owasp': 'A03:2021',
                        'cvss': 6.1,
                        'response': str(response.headers)
                    }
            except Exception:
                continue

        return None

    def _is_crlf_vulnerable(self, response, payload: str) -> bool:
        """Check if response indicates CRLF injection"""
        if not response:
            return False

        headers_str = str(response.headers).lower()

        # Check for injected header
        if self.canary_header.lower() in headers_str:
            return True

        if self.canary_value.lower() in headers_str:
            return True

        # Check for Set-Cookie injection
        if 'set-cookie' in headers_str:
            if 'crlf=' in headers_str or 'crlf%3d' in headers_str.lower():
                return True
            if 'injected' in headers_str:
                return True

        # Check for X-Injected header
        if 'x-injected' in headers_str:
            return True

        # Check response body for signs of response splitting
        if response.text:
            body_lower = response.text.lower()
            if 'http/1.1 200 ok' in body_lower:
                return True
            if '<html>injected</html>' in body_lower:
                return True

        return False

    def _get_injection_type(self, response, payload: str) -> str:
        """Determine the type of CRLF injection"""
        headers_str = str(response.headers).lower()

        if 'set-cookie' in payload.lower() and 'set-cookie' in headers_str:
            return 'Session Fixation via Header Injection'
        elif 'location' in payload.lower():
            return 'Open Redirect via Header Injection'
        elif 'http/1.1' in payload.lower():
            return 'HTTP Response Splitting'
        else:
            return 'HTTP Header Injection'

    def _get_evidence(self, response, payload: str) -> str:
        """Generate evidence string"""
        evidence_parts = []

        # Check headers
        for header, value in response.headers.items():
            header_lower = header.lower()
            if header_lower in ['x-crlf-test', 'x-injected'] or 'crlf' in value.lower():
                evidence_parts.append(f"Injected header found: {header}: {value}")

        if not evidence_parts:
            evidence_parts.append(f"CRLF payload accepted. Status: {response.status_code}")

        return '; '.join(evidence_parts)
