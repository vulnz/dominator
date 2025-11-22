"""
CORS Misconfiguration Scanner Module
Detects insecure CORS configurations
"""

import re
from typing import Dict, List, Any, Optional
from urllib.parse import urlparse
from core.base_module import BaseModule


class Module(BaseModule):
    """CORS Misconfiguration vulnerability scanner"""

    def __init__(self, http_client=None, config: Optional[Dict] = None):
        super().__init__(http_client, config)
        self.name = "CORS Misconfiguration Scanner"
        self.description = "Detects CORS policy misconfigurations"

    def run(self, target: str, params: Optional[Dict] = None) -> List[Dict[str, Any]]:
        """Run CORS misconfiguration scan"""
        results = []
        parsed = urlparse(target)
        target_domain = parsed.netloc

        # Test origins to try
        test_origins = [
            'https://evil.com',
            'https://attacker.com',
            f'https://{target_domain}.evil.com',  # Subdomain bypass
            f'https://evil{target_domain}',  # Suffix bypass
            f'https://{target_domain}evil.com',  # Prefix bypass
            'null',  # Null origin
            f'https://{target_domain}',  # Same origin (baseline)
        ]

        for origin in test_origins:
            result = self._test_origin(target, origin, target_domain)
            if result:
                results.append(result)
                # Found a vulnerability, no need to test more
                if result.get('severity') in ['Critical', 'High']:
                    break

        return results

    def _test_origin(self, url: str, origin: str, target_domain: str) -> Optional[Dict]:
        """Test if a specific origin is allowed"""
        try:
            headers = {'Origin': origin}
            response = self.http_client.get(url, headers=headers)

            if not response:
                return None

            acao = response.headers.get('Access-Control-Allow-Origin', '')
            acac = response.headers.get('Access-Control-Allow-Credentials', '').lower()

            # Check for vulnerabilities
            if not acao:
                return None  # No CORS headers

            is_evil_origin = 'evil' in origin.lower() or 'attacker' in origin.lower()
            is_null = origin == 'null'

            # Critical: Reflects arbitrary origin with credentials
            if acao == origin and is_evil_origin and acac == 'true':
                return {
                    'vulnerability': True,
                    'type': 'CORS Misconfiguration',
                    'severity': 'Critical',
                    'url': url,
                    'parameter': 'Origin header',
                    'payload': origin,
                    'method': 'GET',
                    'injection_type': 'Origin Reflection with Credentials',
                    'evidence': f"ACAO: {acao}, ACAC: {acac}",
                    'description': f"Server reflects arbitrary Origin header ({origin}) and allows credentials. Attacker can steal sensitive data cross-origin.",
                    'recommendation': 'Implement a strict whitelist of allowed origins. Do not dynamically reflect the Origin header.',
                    'cwe': 'CWE-942',
                    'owasp': 'A05:2021',
                    'cvss': 8.1,
                    'response': str(response.headers)
                }

            # High: Reflects arbitrary origin without credentials
            if acao == origin and is_evil_origin:
                return {
                    'vulnerability': True,
                    'type': 'CORS Misconfiguration',
                    'severity': 'High',
                    'url': url,
                    'parameter': 'Origin header',
                    'payload': origin,
                    'method': 'GET',
                    'injection_type': 'Origin Reflection',
                    'evidence': f"ACAO: {acao}",
                    'description': f"Server reflects arbitrary Origin header ({origin}). May allow reading responses cross-origin.",
                    'recommendation': 'Use a whitelist of trusted origins instead of reflecting the Origin header.',
                    'cwe': 'CWE-942',
                    'owasp': 'A05:2021',
                    'cvss': 6.5,
                    'response': str(response.headers)
                }

            # Medium: Null origin allowed with credentials
            if acao == 'null' and is_null and acac == 'true':
                return {
                    'vulnerability': True,
                    'type': 'CORS Misconfiguration',
                    'severity': 'High',
                    'url': url,
                    'parameter': 'Origin header',
                    'payload': 'null',
                    'method': 'GET',
                    'injection_type': 'Null Origin Allowed',
                    'evidence': f"ACAO: null, ACAC: true",
                    'description': "Server allows 'null' origin with credentials. Sandboxed iframes can exploit this.",
                    'recommendation': 'Do not allow null origin. Use explicit whitelist of trusted origins.',
                    'cwe': 'CWE-942',
                    'owasp': 'A05:2021',
                    'cvss': 7.1,
                    'response': str(response.headers)
                }

            # Medium: Wildcard with credentials attempt (invalid but check)
            if acao == '*':
                # Wildcard doesn't work with credentials, but still a misconfiguration
                return {
                    'vulnerability': True,
                    'type': 'CORS Misconfiguration',
                    'severity': 'Low',
                    'url': url,
                    'parameter': 'Origin header',
                    'payload': origin,
                    'method': 'GET',
                    'injection_type': 'Wildcard Origin',
                    'evidence': f"ACAO: * (wildcard)",
                    'description': "Server uses wildcard (*) for Access-Control-Allow-Origin. Any site can read responses.",
                    'recommendation': 'Avoid wildcard CORS policies. Use specific trusted origins.',
                    'cwe': 'CWE-942',
                    'owasp': 'A05:2021',
                    'cvss': 4.3,
                    'response': str(response.headers)
                }

            # Check for subdomain/prefix/suffix bypass
            if acao == origin and target_domain in origin and origin != f'https://{target_domain}':
                return {
                    'vulnerability': True,
                    'type': 'CORS Misconfiguration',
                    'severity': 'Medium',
                    'url': url,
                    'parameter': 'Origin header',
                    'payload': origin,
                    'method': 'GET',
                    'injection_type': 'Origin Validation Bypass',
                    'evidence': f"ACAO: {acao} - weak origin validation",
                    'description': f"Server accepts origin '{origin}' which bypasses domain validation. Regex or string matching is too permissive.",
                    'recommendation': 'Use exact origin matching instead of substring/regex matching.',
                    'cwe': 'CWE-942',
                    'owasp': 'A05:2021',
                    'cvss': 5.3,
                    'response': str(response.headers)
                }

        except Exception:
            pass

        return None
