"""
CRLF Injection Scanner Module
Detects HTTP header injection and response splitting vulnerabilities
"""

from typing import List, Dict, Any
from urllib.parse import quote
from core.base_module import BaseModule
from core.logger import get_logger

logger = get_logger(__name__)


class CRLFModule(BaseModule):
    """CRLF Injection vulnerability scanner"""

    def __init__(self, module_path: str, payload_limit: int = None):
        """Initialize CRLF Injection module"""
        super().__init__(module_path, payload_limit=payload_limit)
        self.canary_header = "X-CRLF-Test"
        self.canary_value = "dominator-crlf-detected"
        logger.info(f"CRLF Injection module loaded: {len(self.payloads)} payloads")

    def scan(self, targets: List[Dict[str, Any]], http_client: Any) -> List[Dict[str, Any]]:
        """Scan for CRLF injection vulnerabilities"""
        results = []

        for target in targets:
            url = target.get('url')
            params = target.get('params', {})
            method = target.get('method', 'GET').upper()

            if not params:
                continue

            for param_name in params:
                # Test each parameter for CRLF injection
                for payload in self.get_limited_payloads()[:10]:
                    # Build full payload with header injection
                    full_payload = f"{payload}{self.canary_header}: {self.canary_value}"
                    test_params = params.copy()
                    test_params[param_name] = full_payload

                    try:
                        if method == 'POST':
                            response = http_client.post(url, data=test_params)
                        else:
                            response = http_client.get(url, params=test_params)

                        if self._check_crlf_injection(response):
                            results.append(self.create_result(
                                vulnerable=True,
                                url=url,
                                parameter=param_name,
                                payload=payload,
                                evidence=f"CRLF injection: Header '{self.canary_header}' injected",
                                severity='High',
                                method=method,
                                additional_info={
                                    'injection_type': 'CRLF Header Injection',
                                    'injected_header': self.canary_header,
                                    'cwe': 'CWE-93',
                                    'owasp': 'A03:2021',
                                    'cvss': 8.1
                                }
                            ))
                            break
                    except Exception:
                        continue

        # Also test redirect endpoints
        redirect_results = self._test_redirect_endpoints(targets, http_client)
        results.extend(redirect_results)

        return results

    def _check_crlf_injection(self, response) -> bool:
        """Check if CRLF injection was successful"""
        if not response:
            return False

        # Check if our canary header appears in response headers
        for header_name, header_value in response.headers.items():
            if self.canary_header.lower() in header_name.lower():
                return True
            if self.canary_value in str(header_value):
                return True

        # Check for Set-Cookie injection
        if 'crlf=injection' in response.headers.get('Set-Cookie', ''):
            return True

        return False

    def _test_redirect_endpoints(self, targets, http_client):
        """Test redirect parameters for CRLF injection"""
        results = []
        redirect_params = ['url', 'redirect', 'next', 'return', 'returnUrl', 'goto', 'dest']

        for target in targets:
            url = target.get('url')
            params = target.get('params', {})

            for param_name in params:
                if any(rp in param_name.lower() for rp in redirect_params):
                    # Test with CRLF payload
                    payload = f"http://example.com%0d%0a{self.canary_header}: {self.canary_value}"
                    test_params = params.copy()
                    test_params[param_name] = payload

                    try:
                        response = http_client.get(url, params=test_params, allow_redirects=False)

                        if self._check_crlf_injection(response):
                            results.append(self.create_result(
                                vulnerable=True,
                                url=url,
                                parameter=param_name,
                                payload=payload,
                                evidence=f"CRLF in redirect: {self.canary_header} injected via Location header",
                                severity='High',
                                method='GET',
                                additional_info={
                                    'injection_type': 'CRLF Redirect Injection',
                                    'cwe': 'CWE-113',
                                    'owasp': 'A03:2021',
                                    'cvss': 8.1
                                }
                            ))
                    except Exception:
                        continue

        return results


def get_module(module_path: str, payload_limit: int = None):
    """Factory function to create module instance"""
    return CRLFModule(module_path, payload_limit)
