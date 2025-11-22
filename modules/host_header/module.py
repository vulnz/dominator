"""
Host Header Injection Scanner
Detects vulnerabilities in Host header processing
"""

from core.base_module import BaseModule
from core.http_client import HTTPClient
from core.logger import get_logger
from typing import List, Dict, Any
import re

logger = get_logger(__name__)


class HostHeaderInjectionScanner(BaseModule):
    """Scans for Host header injection vulnerabilities"""

    def __init__(self, module_path: str, payload_limit: int = None):
        super().__init__(module_path, payload_limit=payload_limit)
        self.module_name = "Host Header Injection"
        self.logger = logger

    def scan(self, targets: List[Dict[str, Any]], http_client: Any = None) -> List[Dict[str, Any]]:
        """
        Scan targets for Host header injection

        Args:
            targets: List of targets to scan
            http_client: HTTP client for making requests

        Returns:
            List of vulnerability findings
        """
        self.logger.info(f"Starting {self.module_name} scan on {len(targets)} targets")

        results = []
        client = http_client or HTTPClient(timeout=8)

        for target in targets:
            url = target.get('url')
            if not url:
                continue

            # Test with malicious Host headers
            for payload in self.payloads[:self.payload_limit]:
                finding = self._test_host_header(client, url, payload.strip())
                if finding:
                    results.append(finding)
                    # Early exit on finding
                    if self.config.get('early_exit', True):
                        break

        client.close()
        self.logger.info(f"{self.module_name} scan complete: {len(results)} vulnerabilities found")
        return results

    def _test_host_header(self, client: HTTPClient, url: str, malicious_host: str) -> Dict[str, Any]:
        """Test a single Host header injection payload"""

        # Send request with malicious Host header
        response = client.get(url, headers={'Host': malicious_host})

        if not response:
            return None

        # Check if malicious host is reflected
        if malicious_host in response.text:
            # Verify it's not a false positive
            if self._is_vulnerable(response.text, malicious_host, url):
                return {
                    'vulnerability': True,
                    'module': self.module_name,
                    'type': 'Host Header Injection',
                    'severity': self.config.get('severity', 'High'),
                    'url': url,
                    'parameter': 'Host',
                    'payload': malicious_host,
                    'method': 'GET',
                    'confidence': 0.85,
                    'description': f'Host header injection detected. Malicious host "{malicious_host}" was reflected in the response.',
                    'evidence': f'Host header "{malicious_host}" reflected in response',
                    'recommendation': 'Validate and sanitize Host header values. Use a whitelist of allowed hosts.',
                    'cwe': self.config.get('cwe', 'CWE-444'),
                    'cvss': self.config.get('cvss', 7.5),
                    'owasp': self.config.get('owasp', 'A01:2021'),
                    'references': [
                        'https://portswigger.net/web-security/host-header',
                        'https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/17-Testing_for_Host_Header_Injection'
                    ]
                }

        return None

    def _is_vulnerable(self, response_text: str, payload: str, original_url: str) -> bool:
        """Validate if the injection is actually exploitable"""

        # Check for reflection in dangerous contexts
        dangerous_patterns = [
            r'<a\s+href=["\'].*?' + re.escape(payload),  # Link injection
            r'window\.location.*?' + re.escape(payload),  # JavaScript redirect
            r'Location:.*?' + re.escape(payload),  # HTTP redirect header
            r'<form\s+action=["\'].*?' + re.escape(payload),  # Form action
            r'password.*?reset.*?' + re.escape(payload),  # Password reset link
        ]

        for pattern in dangerous_patterns:
            if re.search(pattern, response_text, re.IGNORECASE):
                return True

        # Simple reflection is medium confidence
        return payload in response_text and payload not in original_url


def get_module(module_path: str, payload_limit: int = None):
    """Factory function to create module instance"""
    return HostHeaderInjectionScanner(module_path, payload_limit=payload_limit)
