"""
403 Forbidden Bypass Scanner Module
Attempts to bypass 403 responses using header and path manipulation
Limited attempts per scan to avoid excessive requests
"""

from typing import Dict, List, Any, Optional
from urllib.parse import urlparse, urljoin
from core.base_module import BaseModule


class Module(BaseModule):
    """403 Forbidden bypass scanner"""

    def __init__(self, http_client=None, config: Optional[Dict] = None):
        super().__init__(http_client, config)
        self.name = "403 Forbidden Bypass Scanner"
        self.description = "Bypasses 403 Forbidden using various techniques"
        self.scan_count = 0
        self.max_scans_per_session = 3  # Limit to prevent excessive requests
        self.tested_urls = set()

    def run(self, target: str, params: Optional[Dict] = None) -> List[Dict[str, Any]]:
        """Run 403 bypass scan - only on 403 responses, limited times"""
        results = []

        # Check if we've hit the limit for this session
        if self.scan_count >= self.max_scans_per_session:
            return results

        # Skip if already tested this URL
        parsed = urlparse(target)
        url_key = f"{parsed.netloc}{parsed.path}"
        if url_key in self.tested_urls:
            return results

        # First, check if the URL actually returns 403
        try:
            baseline = self.http_client.get(target)
            if not baseline or baseline.status_code != 403:
                return results  # Only scan 403 pages
        except Exception:
            return results

        self.tested_urls.add(url_key)
        self.scan_count += 1

        # Header-based bypasses (most effective)
        header_results = self._test_header_bypasses(target)
        results.extend(header_results)

        # Path-based bypasses
        path_results = self._test_path_bypasses(target)
        results.extend(path_results)

        # Method-based bypasses
        method_results = self._test_method_bypasses(target)
        results.extend(method_results)

        return results

    def _test_header_bypasses(self, url: str) -> List[Dict]:
        """Test header-based bypass techniques"""
        results = []

        # Key bypass headers (limited selection for efficiency)
        bypass_headers = [
            # IP spoofing
            {'X-Forwarded-For': '127.0.0.1'},
            {'X-Forwarded-For': '::1'},
            {'X-Original-URL': urlparse(url).path},
            {'X-Rewrite-URL': urlparse(url).path},
            {'X-Originating-IP': '127.0.0.1'},
            {'X-Remote-IP': '127.0.0.1'},
            {'X-Client-IP': '127.0.0.1'},
            {'X-Real-IP': '127.0.0.1'},
            {'X-Forwarded-Host': 'localhost'},
            {'X-Host': 'localhost'},
            # Override headers
            {'X-Custom-IP-Authorization': '127.0.0.1'},
            {'X-Forwarded-Proto': 'https'},
            {'Forwarded': 'for=127.0.0.1'},
        ]

        for headers in bypass_headers:
            try:
                response = self.http_client.get(url, headers=headers)

                if response and response.status_code == 200:
                    header_name = list(headers.keys())[0]
                    header_value = list(headers.values())[0]

                    results.append({
                        'vulnerability': True,
                        'type': '403 Bypass',
                        'severity': 'Medium',
                        'url': url,
                        'parameter': header_name,
                        'payload': f'{header_name}: {header_value}',
                        'method': 'GET',
                        'injection_type': 'Header-based Bypass',
                        'evidence': f"403 bypassed with header '{header_name}: {header_value}'. Status: 200",
                        'description': f"403 Forbidden was bypassed using the {header_name} header. Access control can be circumvented.",
                        'recommendation': 'Implement proper access control at the application layer, not just based on headers. Validate authorization server-side.',
                        'cwe': 'CWE-284',
                        'owasp': 'A01:2021',
                        'cvss': 5.3,
                        'response': response.text[:500] if response.text else ''
                    })
                    return results  # Found bypass, return immediately

            except Exception:
                continue

        return results

    def _test_path_bypasses(self, url: str) -> List[Dict]:
        """Test path-based bypass techniques"""
        results = []
        parsed = urlparse(url)
        path = parsed.path.rstrip('/')
        base = f"{parsed.scheme}://{parsed.netloc}"

        # Path variations to try
        path_variations = [
            f"{path}/",
            f"{path}//",
            f"{path}/.",
            f"{path}/..",
            f"{path}..;/",
            f"{path};/",
            f"{path}%20",
            f"{path}%09",
            f"{path}%00",
            f"{path}?",
            f"{path}??",
            f"{path}#",
            f"{path}/*",
            f"{path}.json",
            f"{path}.html",
            f"/{path.lstrip('/')}",  # Ensure leading slash
            f"//{path.lstrip('/')}",  # Double slash
        ]

        for variation in path_variations[:10]:  # Limit variations
            try:
                test_url = base + variation
                if parsed.query:
                    test_url += f"?{parsed.query}"

                response = self.http_client.get(test_url)

                if response and response.status_code == 200:
                    results.append({
                        'vulnerability': True,
                        'type': '403 Bypass',
                        'severity': 'Medium',
                        'url': url,
                        'parameter': 'URL path',
                        'payload': variation,
                        'method': 'GET',
                        'injection_type': 'Path-based Bypass',
                        'evidence': f"403 bypassed with path variation '{variation}'. Status: 200",
                        'description': f"403 Forbidden was bypassed using path modification. Original: {path}, Bypass: {variation}",
                        'recommendation': 'Normalize URL paths before access control checks. Use strict path matching.',
                        'cwe': 'CWE-284',
                        'owasp': 'A01:2021',
                        'cvss': 5.3,
                        'response': response.text[:500] if response.text else ''
                    })
                    return results  # Found bypass, return immediately

            except Exception:
                continue

        return results

    def _test_method_bypasses(self, url: str) -> List[Dict]:
        """Test HTTP method bypass techniques"""
        results = []

        # Alternative methods to try
        methods = ['POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS', 'HEAD', 'TRACE']

        for method in methods[:4]:  # Limit methods
            try:
                if method == 'POST':
                    response = self.http_client.post(url, data={})
                elif method == 'PUT':
                    response = self.http_client.put(url, data={})
                elif method == 'OPTIONS':
                    response = self.http_client.options(url)
                elif method == 'HEAD':
                    response = self.http_client.head(url)
                else:
                    continue

                if response and response.status_code == 200:
                    results.append({
                        'vulnerability': True,
                        'type': '403 Bypass',
                        'severity': 'Medium',
                        'url': url,
                        'parameter': 'HTTP Method',
                        'payload': method,
                        'method': method,
                        'injection_type': 'Method-based Bypass',
                        'evidence': f"403 bypassed using HTTP {method} method. Status: 200",
                        'description': f"403 Forbidden was bypassed using {method} instead of GET. Access control only applies to certain methods.",
                        'recommendation': 'Apply access control consistently across all HTTP methods.',
                        'cwe': 'CWE-284',
                        'owasp': 'A01:2021',
                        'cvss': 5.3,
                        'response': response.text[:500] if hasattr(response, 'text') and response.text else ''
                    })
                    return results  # Found bypass

            except Exception:
                continue

        return results

    def reset_scan_count(self):
        """Reset scan count for new session"""
        self.scan_count = 0
        self.tested_urls.clear()
