"""
CORS Misconfiguration Scanner Module
Detects insecure CORS configurations
"""

from typing import List, Dict, Any
from urllib.parse import urlparse
from core.base_module import BaseModule
from core.logger import get_logger

logger = get_logger(__name__)


class CORSModule(BaseModule):
    """CORS Misconfiguration vulnerability scanner"""

    def __init__(self, module_path: str, payload_limit: int = None):
        """Initialize CORS module"""
        super().__init__(module_path, payload_limit=payload_limit)
        logger.info("CORS Misconfiguration module loaded")

    def scan(self, targets: List[Dict[str, Any]], http_client: Any) -> List[Dict[str, Any]]:
        """Scan for CORS misconfigurations"""
        results = []
        tested_hosts = set()

        for target in targets:
            url = target.get('url')
            parsed = urlparse(url)
            host_key = parsed.netloc

            # Only test once per host
            if host_key in tested_hosts:
                continue
            tested_hosts.add(host_key)

            target_domain = parsed.netloc

            # Test origins
            test_origins = [
                ('https://evil.com', 'Arbitrary Origin'),
                ('https://attacker.com', 'Arbitrary Origin'),
                (f'https://{target_domain}.evil.com', 'Subdomain Bypass'),
                ('null', 'Null Origin'),
            ]

            for origin, origin_type in test_origins:
                result = self._test_origin(url, origin, origin_type, target_domain, http_client)
                if result:
                    results.append(result)
                    break  # Found vulnerability, stop testing this host

        return results

    def _test_origin(self, url: str, origin: str, origin_type: str, target_domain: str, http_client) -> Dict:
        """Test if a specific origin is allowed"""
        try:
            headers = {'Origin': origin}
            response = http_client.get(url, headers=headers)

            if not response:
                return None

            acao = response.headers.get('Access-Control-Allow-Origin', '')
            acac = response.headers.get('Access-Control-Allow-Credentials', '').lower()

            # Check for dangerous CORS configurations
            if not acao:
                return None

            # Origin reflected
            if acao == origin or acao == '*':
                # Determine severity
                if acac == 'true' and acao == origin:
                    severity = 'Critical'
                    desc = f"Origin '{origin}' reflected with credentials allowed. Full CORS bypass."
                elif acao == '*':
                    severity = 'Medium' if acac != 'true' else 'High'
                    desc = f"Wildcard CORS policy. Any origin can read responses."
                else:
                    severity = 'Medium'
                    desc = f"Origin '{origin}' ({origin_type}) is reflected in ACAO header."

                return self.create_result(
                    vulnerable=True,
                    url=url,
                    parameter='Origin',
                    payload=origin,
                    evidence=f"ACAO: {acao}, ACAC: {acac}",
                    severity=severity,
                    method='GET',
                    additional_info={
                        'injection_type': 'CORS Misconfiguration',
                        'bypass_type': origin_type,
                        'acao_header': acao,
                        'credentials_allowed': acac == 'true',
                        'description': desc,
                        'cwe': 'CWE-942',
                        'owasp': 'A05:2021',
                        'cvss': 8.6 if severity == 'Critical' else 6.5
                    }
                )

        except Exception:
            pass

        return None


def get_module(module_path: str, payload_limit: int = None):
    """Factory function to create module instance"""
    return CORSModule(module_path, payload_limit)
