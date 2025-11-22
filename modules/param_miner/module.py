"""
Parameter Miner Module
Discovers hidden parameters using wordlists and response analysis
"""

from typing import List, Dict, Any
from urllib.parse import urlparse, parse_qs, urlencode
from core.base_module import BaseModule
from core.logger import get_logger

logger = get_logger(__name__)


class ParamMinerModule(BaseModule):
    """Hidden parameter discovery scanner"""

    def __init__(self, module_path: str, payload_limit: int = None):
        """Initialize Parameter Miner module"""
        super().__init__(module_path, payload_limit=payload_limit)
        self.max_params_to_test = 50  # Limit for efficiency
        logger.info(f"Parameter Miner module loaded: {len(self.payloads)} parameters")

    def scan(self, targets: List[Dict[str, Any]], http_client: Any) -> List[Dict[str, Any]]:
        """Discover hidden parameters"""
        results = []
        tested_endpoints = set()

        for target in targets:
            url = target.get('url')
            parsed = urlparse(url)
            base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"

            # Only test each endpoint once
            if base_url in tested_endpoints:
                continue
            tested_endpoints.add(base_url)

            existing_params = parse_qs(parsed.query)

            # Get baseline response
            try:
                baseline = http_client.get(base_url)
                if not baseline:
                    continue
                baseline_len = len(baseline.text)
                baseline_status = baseline.status_code
            except Exception:
                continue

            # Test parameters from payloads
            discovered = []
            for param in self.get_limited_payloads()[:self.max_params_to_test]:
                if param in existing_params:
                    continue

                try:
                    test_url = f"{base_url}?{param}=test123"
                    response = http_client.get(test_url)

                    if self._is_param_reflected(response, 'test123', baseline_len, baseline_status):
                        discovered.append({
                            'param': param,
                            'reflected': 'test123' in response.text,
                            'status_changed': response.status_code != baseline_status,
                            'length_changed': abs(len(response.text) - baseline_len) > 50
                        })

                except Exception:
                    continue

            if discovered:
                results.append(self.create_result(
                    vulnerable=True,
                    url=base_url,
                    parameter='hidden',
                    payload=', '.join([d['param'] for d in discovered[:10]]),
                    evidence=f"Found {len(discovered)} hidden parameters: {', '.join([d['param'] for d in discovered[:5]])}",
                    severity='Low',
                    method='GET',
                    additional_info={
                        'injection_type': 'Parameter Discovery',
                        'discovered_params': discovered[:10],
                        'cwe': 'CWE-200',
                        'owasp': 'A05:2021',
                        'cvss': 3.7
                    }
                ))

        return results

    def _is_param_reflected(self, response, value: str, baseline_len: int, baseline_status: int) -> bool:
        """Check if parameter value is reflected or causes behavior change"""
        if not response:
            return False

        # Value reflected in response
        if value in response.text:
            return True

        # Significant length change
        if abs(len(response.text) - baseline_len) > 100:
            return True

        # Status code changed
        if response.status_code != baseline_status:
            return True

        return False


def get_module(module_path: str, payload_limit: int = None):
    """Factory function to create module instance"""
    return ParamMinerModule(module_path, payload_limit)
