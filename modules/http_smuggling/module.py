"""
HTTP Request Smuggling Scanner
Detects CL.TE, TE.CL, and TE.TE desync vulnerabilities
"""

from core.base_module import BaseModule
from core.http_client import HTTPClient
from core.logger import get_logger
from typing import List, Dict, Any
import socket
import time
import ssl
from urllib.parse import urlparse

logger = get_logger(__name__)


class HTTPRequestSmugglingScanner(BaseModule):
    """Scans for HTTP request smuggling vulnerabilities"""

    def __init__(self, module_path: str, payload_limit: int = None):
        super().__init__(module_path, payload_limit=payload_limit)
        self.module_name = "HTTP Request Smuggling"
        self.logger = logger

    def scan(self, targets: List[Dict[str, Any]], http_client: Any = None) -> List[Dict[str, Any]]:
        """
        Scan targets for HTTP request smuggling

        Args:
            targets: List of targets to scan
            http_client: HTTP client (unused - direct socket for smuggling)

        Returns:
            List of vulnerability findings
        """
        self.logger.info(f"Starting {self.module_name} scan on {len(targets)} targets")

        results = []

        for target in targets:
            url = target.get('url')
            if not url:
                continue

            # Test each smuggling payload
            for payload in self.payloads[:self.payload_limit]:
                payload = payload.strip()
                if not payload or payload.startswith('#'):
                    continue

                finding = self._test_smuggling(url, payload)
                if finding:
                    results.append(finding)
                    # Early exit on finding
                    if self.config.get('early_exit', True):
                        break

        self.logger.info(f"{self.module_name} scan complete: {len(results)} vulnerabilities found")
        return results

    def _test_smuggling(self, url: str, payload: str) -> Dict[str, Any]:
        """Test a single HTTP smuggling payload"""

        try:
            parsed = urlparse(url)
            host = parsed.hostname
            port = parsed.port or (443 if parsed.scheme == 'https' else 80)
            is_https = parsed.scheme == 'https'
            path = parsed.path or '/'

            # Parse payload type
            payload_type = 'UNKNOWN'
            if payload.startswith('CL.TE:'):
                payload_type = 'CL.TE'
                payload = payload[6:]
            elif payload.startswith('TE.CL:'):
                payload_type = 'TE.CL'
                payload = payload[6:]
            elif payload.startswith('TE.TE:'):
                payload_type = 'TE.TE'
                payload = payload[6:]

            # Check for detection method tags
            detection_method = 'differential'
            if ':TIMEOUT' in payload:
                detection_method = 'timeout'
                payload = payload.replace(':TIMEOUT', '')
            elif ':404' in payload:
                detection_method = '404'
                payload = payload.replace(':404', '')
            elif ':DIFF' in payload:
                detection_method = 'differential'
                payload = payload.replace(':DIFF', '')
            elif ':CACHE' in payload:
                detection_method = 'cache'
                payload = payload.replace(':CACHE', '')
            elif ':SESSION' in payload:
                detection_method = 'session'
                payload = payload.replace(':SESSION', '')

            # Replace REPLACED_HOST with actual host
            payload = payload.replace('REPLACED_HOST', host)

            # Send smuggling request
            vulnerable, evidence = self._send_smuggling_request(
                host, port, is_https, payload, detection_method
            )

            if vulnerable:
                return {
                    'vulnerability': True,
                    'module': self.module_name,
                    'type': f'HTTP Request Smuggling ({payload_type})',
                    'severity': self.config.get('severity', 'Critical'),
                    'url': url,
                    'parameter': 'HTTP Headers',
                    'payload': payload[:200] + '...' if len(payload) > 200 else payload,
                    'method': 'POST',
                    'confidence': 0.75,
                    'description': f'HTTP request smuggling vulnerability detected using {payload_type} desync attack. Detection method: {detection_method}.',
                    'evidence': evidence,
                    'recommendation': 'Disable support for conflicting Content-Length and Transfer-Encoding headers. Use HTTP/2 exclusively. Normalize ambiguous requests.',
                    'cwe': self.config.get('cwe', 'CWE-444'),
                    'cvss': self.config.get('cvss', 9.1),
                    'owasp': self.config.get('owasp', 'A03:2021'),
                    'references': [
                        'https://portswigger.net/web-security/request-smuggling',
                        'https://cwe.mitre.org/data/definitions/444.html',
                        'https://www.cgisecurity.com/lib/HTTP-Request-Smuggling.pdf'
                    ]
                }

        except Exception as e:
            self.logger.debug(f"Error testing smuggling on {url}: {str(e)}")

        return None

    def _send_smuggling_request(self, host: str, port: int, is_https: bool,
                                payload: str, detection_method: str) -> tuple:
        """Send raw HTTP request for smuggling detection"""

        try:
            # Create socket connection
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(10)

            # Wrap in SSL if needed
            if is_https:
                context = ssl.create_default_context()
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                sock = context.wrap_socket(sock, server_hostname=host)

            # Connect
            sock.connect((host, port))

            # Send smuggling payload
            start_time = time.time()
            sock.sendall(payload.encode('utf-8'))

            # Receive response
            response = b''
            try:
                while True:
                    chunk = sock.recv(4096)
                    if not chunk:
                        break
                    response += chunk
                    if len(response) > 1024 * 100:  # Max 100KB
                        break
            except socket.timeout:
                pass

            end_time = time.time()
            response_time = end_time - start_time

            sock.close()

            response_text = response.decode('utf-8', errors='ignore')

            # Analyze response based on detection method
            if detection_method == 'timeout':
                # Time-based detection - look for delay
                delay_threshold = self.config.get('delay_threshold', 5)
                if response_time >= delay_threshold:
                    return True, f'Response delayed by {response_time:.2f}s (threshold: {delay_threshold}s)'

            elif detection_method == '404':
                # Look for 404 from smuggled request
                if '404' in response_text or 'Not Found' in response_text:
                    if 'smuggled404notfound' in payload.lower():
                        return True, 'Smuggled request triggered 404 response'

            elif detection_method == 'differential':
                # Differential detection is unreliable - disable it
                # Different response sizes alone don't indicate smuggling
                # Need actual smuggled request evidence (poison, reflection, etc.)
                pass

            elif detection_method == 'cache':
                # Look for cache poisoning indicators
                if 'evil.com' in response_text or 'X-Cache-Poison' in response_text:
                    return True, 'Cache poisoning detected via smuggled request'

            elif detection_method == 'session':
                # Look for session hijacking indicators
                if 'victim_session' in response_text or 'myaccount' in response_text.lower():
                    return True, 'Potential session hijacking via smuggled request'

            # Generic detection disabled - too many false positives
            # Only timeout-based and explicit indicators are reliable
            pass

        except Exception as e:
            self.logger.debug(f"Error in smuggling request: {str(e)}")

        return False, ''

    def _send_normal_request(self, host: str, port: int, is_https: bool) -> str:
        """Send a normal request for comparison"""

        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)

            if is_https:
                context = ssl.create_default_context()
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                sock = context.wrap_socket(sock, server_hostname=host)

            sock.connect((host, port))

            request = f"GET / HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n"
            sock.sendall(request.encode('utf-8'))

            response = b''
            try:
                while True:
                    chunk = sock.recv(4096)
                    if not chunk:
                        break
                    response += chunk
                    if len(response) > 1024 * 100:
                        break
            except socket.timeout:
                pass

            sock.close()
            return response.decode('utf-8', errors='ignore')

        except Exception as e:
            self.logger.debug(f"Error in normal request: {str(e)}")
            return ''


def get_module(module_path: str, payload_limit: int = None):
    """Factory function to create module instance"""
    return HTTPRequestSmugglingScanner(module_path, payload_limit=payload_limit)
