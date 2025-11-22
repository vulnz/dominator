"""
HTTP Methods Scanner Module (Nikto-style)

Tests for dangerous HTTP methods:
- PUT/DELETE - File manipulation
- TRACE - XST (Cross-Site Tracing)
- OPTIONS - Method enumeration
- CONNECT - Proxy abuse
- PROPFIND/PROPPATCH - WebDAV
- COPY/MOVE - WebDAV file operations

Based on Nikto and OWASP Testing Guide.
"""

from typing import List, Dict, Any
from core.base_module import BaseModule
from core.logger import get_logger

logger = get_logger(__name__)


class HTTPMethodsModule(BaseModule):
    """HTTP Methods vulnerability scanner"""

    # Dangerous methods and their risks
    DANGEROUS_METHODS = {
        'PUT': {
            'severity': 'critical',
            'description': 'PUT method enabled - may allow arbitrary file upload',
            'test_type': 'upload',
            'cwe': 'CWE-434',
        },
        'DELETE': {
            'severity': 'high',
            'description': 'DELETE method enabled - may allow file deletion',
            'test_type': 'simple',
            'cwe': 'CWE-749',
        },
        'TRACE': {
            'severity': 'medium',
            'description': 'TRACE method enabled - vulnerable to Cross-Site Tracing (XST)',
            'test_type': 'trace',
            'cwe': 'CWE-693',
        },
        'CONNECT': {
            'severity': 'high',
            'description': 'CONNECT method enabled - potential proxy abuse',
            'test_type': 'simple',
            'cwe': 'CWE-441',
        },
        'PROPFIND': {
            'severity': 'medium',
            'description': 'WebDAV PROPFIND enabled - directory listing possible',
            'test_type': 'webdav',
            'cwe': 'CWE-548',
        },
        'PROPPATCH': {
            'severity': 'medium',
            'description': 'WebDAV PROPPATCH enabled - property modification possible',
            'test_type': 'simple',
            'cwe': 'CWE-16',
        },
        'COPY': {
            'severity': 'high',
            'description': 'WebDAV COPY enabled - file duplication possible',
            'test_type': 'simple',
            'cwe': 'CWE-434',
        },
        'MOVE': {
            'severity': 'high',
            'description': 'WebDAV MOVE enabled - file relocation possible',
            'test_type': 'simple',
            'cwe': 'CWE-434',
        },
        'MKCOL': {
            'severity': 'medium',
            'description': 'WebDAV MKCOL enabled - directory creation possible',
            'test_type': 'simple',
            'cwe': 'CWE-434',
        },
    }

    def __init__(self, module_path: str, payload_limit: int = None):
        """Initialize HTTP Methods module"""
        super().__init__(module_path, payload_limit=payload_limit)
        logger.info("HTTP Methods module loaded")

    def scan(self, targets: List[Dict[str, Any]], http_client: Any) -> List[Dict[str, Any]]:
        """
        Scan targets for dangerous HTTP methods

        Args:
            targets: List of URLs to scan
            http_client: HTTP client

        Returns:
            List of HTTP method vulnerabilities
        """
        results = []
        scanned_hosts = set()

        logger.info(f"Starting HTTP Methods scan on {len(targets)} targets")

        for target in targets:
            url = target.get('url', '')

            # Extract host to avoid duplicate scans
            from urllib.parse import urlparse
            parsed = urlparse(url)
            host = parsed.netloc
            base_url = f"{parsed.scheme}://{parsed.netloc}"

            if host in scanned_hosts:
                continue
            scanned_hosts.add(host)

            # First, check OPTIONS to enumerate allowed methods
            allowed_methods = self._check_options(base_url, http_client)
            logger.debug(f"Allowed methods for {host}: {allowed_methods}")

            # Test each dangerous method
            for method, config in self.DANGEROUS_METHODS.items():
                # Check if method is in OPTIONS Allow header
                method_in_options = method in allowed_methods

                # Actually test the method
                is_enabled, evidence = self._test_method(
                    base_url, method, config['test_type'], http_client
                )

                if is_enabled:
                    result = self.create_result(
                        vulnerable=True,
                        url=base_url,
                        parameter='HTTP Method',
                        payload=method,
                        evidence=evidence,
                        description=config['description'],
                        confidence=0.90 if method_in_options else 0.75
                    )
                    result['cwe'] = config['cwe']
                    result['severity'] = config['severity']
                    result['owasp'] = 'A05:2021'
                    results.append(result)
                    logger.info(f"Dangerous method {method} enabled on {host}")

        logger.info(f"HTTP Methods scan complete: {len(results)} issues found")
        return results

    def _check_options(self, url: str, http_client: Any) -> List[str]:
        """Send OPTIONS request to enumerate allowed methods"""
        try:
            response = http_client.request('OPTIONS', url)
            if response and response.status_code in [200, 204]:
                allow_header = response.headers.get('Allow', '')
                return [m.strip().upper() for m in allow_header.split(',') if m.strip()]
        except Exception as e:
            logger.debug(f"OPTIONS request failed: {e}")
        return []

    def _test_method(self, url: str, method: str, test_type: str,
                     http_client: Any) -> tuple:
        """
        Test if a specific HTTP method is enabled and functional

        Returns:
            (is_enabled, evidence)
        """
        try:
            if test_type == 'trace':
                return self._test_trace(url, http_client)
            elif test_type == 'upload':
                return self._test_put(url, http_client)
            elif test_type == 'webdav':
                return self._test_webdav(url, http_client)
            else:
                return self._test_simple(url, method, http_client)
        except Exception as e:
            logger.debug(f"Error testing {method}: {e}")
            return False, ""

    def _test_trace(self, url: str, http_client: Any) -> tuple:
        """Test TRACE method for XST vulnerability"""
        try:
            # Add custom header to check if it's reflected
            headers = {'X-XST-Test': 'dominator-xst-check'}
            response = http_client.request('TRACE', url, headers=headers)

            if response:
                # TRACE should reflect the request
                if response.status_code == 200:
                    body = getattr(response, 'text', '')
                    if 'X-XST-Test' in body or 'dominator-xst-check' in body:
                        evidence = f"TRACE method reflects request headers (XST vulnerable).\n\n"
                        evidence += f"Status: {response.status_code}\n"
                        evidence += f"Response body reflects our custom header X-XST-Test.\n\n"
                        evidence += f"Response snippet: {body[:500]}"
                        return True, evidence
                    else:
                        evidence = f"TRACE method enabled but may not reflect headers.\n\n"
                        evidence += f"Status: {response.status_code}"
                        return True, evidence
                elif response.status_code == 405:
                    return False, ""  # Method not allowed - good!

        except Exception as e:
            logger.debug(f"TRACE test error: {e}")
        return False, ""

    def _test_put(self, url: str, http_client: Any) -> tuple:
        """Test PUT method for file upload capability"""
        try:
            # Try to PUT a test file
            test_filename = 'dominator_put_test.txt'
            test_url = f"{url.rstrip('/')}/{test_filename}"
            test_content = "Dominator PUT test - safe to delete"

            headers = {'Content-Type': 'text/plain'}
            response = http_client.request('PUT', test_url, data=test_content, headers=headers)

            if response:
                if response.status_code in [200, 201, 204]:
                    # PUT succeeded - verify file was created
                    verify = http_client.get(test_url)
                    if verify and verify.status_code == 200:
                        evidence = f"PUT method enabled - file upload possible!\n\n"
                        evidence += f"Test file created at: {test_url}\n"
                        evidence += f"PUT response: {response.status_code}\n"
                        evidence += f"GET verification: {verify.status_code}\n\n"
                        evidence += f"CRITICAL: Arbitrary file upload vulnerability!"
                        return True, evidence
                    else:
                        evidence = f"PUT method enabled (status: {response.status_code}).\n\n"
                        evidence += f"File may not persist but server accepts PUT requests."
                        return True, evidence
                elif response.status_code == 405:
                    return False, ""  # Method not allowed - good!

        except Exception as e:
            logger.debug(f"PUT test error: {e}")
        return False, ""

    def _test_webdav(self, url: str, http_client: Any) -> tuple:
        """Test WebDAV PROPFIND method"""
        try:
            propfind_body = """<?xml version="1.0"?>
<D:propfind xmlns:D="DAV:">
  <D:allprop/>
</D:propfind>"""

            headers = {
                'Content-Type': 'application/xml',
                'Depth': '1'
            }
            response = http_client.request('PROPFIND', url, data=propfind_body, headers=headers)

            if response:
                if response.status_code in [207, 200]:  # 207 = Multi-Status (WebDAV)
                    body = getattr(response, 'text', '')
                    evidence = f"WebDAV PROPFIND enabled!\n\n"
                    evidence += f"Status: {response.status_code}\n"
                    if '<D:' in body or '<d:' in body or 'DAV:' in body:
                        evidence += f"WebDAV response detected.\n\n"
                        evidence += f"Response snippet: {body[:500]}"
                    return True, evidence
                elif response.status_code == 405:
                    return False, ""

        except Exception as e:
            logger.debug(f"WebDAV test error: {e}")
        return False, ""

    def _test_simple(self, url: str, method: str, http_client: Any) -> tuple:
        """Simple method test - just check if it's accepted"""
        try:
            response = http_client.request(method, url)

            if response:
                # Methods that return 200, 201, 204, 207 are likely enabled
                if response.status_code in [200, 201, 204, 207]:
                    evidence = f"{method} method enabled.\n\n"
                    evidence += f"Status: {response.status_code}\n"
                    evidence += f"Response length: {len(getattr(response, 'text', ''))}"
                    return True, evidence
                elif response.status_code == 405:
                    return False, ""  # Method not allowed - good!

        except Exception as e:
            logger.debug(f"{method} test error: {e}")
        return False, ""


def get_module(module_path: str, payload_limit: int = None):
    """Create module instance"""
    return HTTPMethodsModule(module_path, payload_limit=payload_limit)
