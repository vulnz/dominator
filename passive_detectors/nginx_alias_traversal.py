"""
NGINX Alias Traversal Detection Module

Detects potential NGINX alias traversal vulnerabilities due to misconfiguration.

The vulnerability occurs when NGINX uses 'alias' directive without trailing slash:
    location /files {
        alias /var/www/files;   # VULNERABLE - missing trailing slash
    }

This allows accessing files outside the intended directory:
    /files../etc/passwd -> /var/www/etc/passwd

Reference: https://www.acunetix.com/vulnerabilities/web/nginx-alias-traversal/
"""

import re
from typing import Dict, List, Tuple, Any
from urllib.parse import urlparse


class NginxAliasTraversalDetector:
    """
    NGINX Alias Traversal Vulnerability Detector

    Detects NGINX server and checks for alias traversal indicators.
    """

    # NGINX detection patterns
    NGINX_PATTERNS = [
        re.compile(r'nginx', re.IGNORECASE),
        re.compile(r'server:\s*nginx/?[\d.]*', re.IGNORECASE),
    ]

    # Common paths that may be vulnerable
    # These are typical alias locations in NGINX configs
    VULNERABLE_PATHS = [
        '/static', '/assets', '/files', '/uploads', '/images', '/media',
        '/downloads', '/docs', '/documents', '/data', '/resources',
        '/content', '/public', '/storage', '/attachments', '/img',
        '/css', '/js', '/fonts', '/vendor', '/lib', '/includes',
    ]

    # Files to check for traversal success
    TRAVERSAL_FILES = [
        '../etc/passwd',
        '../etc/nginx/nginx.conf',
        '../proc/self/environ',
        '../var/log/nginx/access.log',
        '../var/log/nginx/error.log',
    ]

    # Patterns indicating successful traversal
    SUCCESS_PATTERNS = [
        re.compile(r'root:.*:0:0:', re.IGNORECASE),  # /etc/passwd
        re.compile(r'http\s*{', re.IGNORECASE),  # nginx.conf
        re.compile(r'server\s*{', re.IGNORECASE),  # nginx.conf
        re.compile(r'PATH=', re.IGNORECASE),  # environ
        re.compile(r'\[error\]|\[warn\]', re.IGNORECASE),  # nginx logs
    ]

    # Common NGINX error pages that indicate misconfiguration
    NGINX_ERRORS = [
        re.compile(r'403 Forbidden.*nginx', re.IGNORECASE | re.DOTALL),
        re.compile(r'404 Not Found.*nginx', re.IGNORECASE | re.DOTALL),
        re.compile(r'<center>nginx</center>', re.IGNORECASE),
    ]

    @classmethod
    def detect(cls, response_text: str, url: str, headers: Dict[str, str] = None) -> Tuple[bool, List[Dict[str, Any]]]:
        """
        Detect NGINX and check for alias traversal indicators.

        Args:
            response_text: HTTP response body
            url: URL being analyzed
            headers: HTTP response headers

        Returns:
            Tuple of (found_issues, list_of_findings)
        """
        findings = []

        headers = headers or {}
        headers_lower = {k.lower(): v for k, v in headers.items()}

        # First check if this is an NGINX server
        is_nginx = cls._detect_nginx(response_text, headers_lower)

        if not is_nginx:
            return False, findings

        # Report NGINX detection
        nginx_version = cls._get_nginx_version(headers_lower)
        findings.append({
            'type': 'NGINX Server Detected',
            'severity': 'Info',
            'url': url,
            'version': nginx_version,
            'description': f'NGINX web server detected{" (version: " + nginx_version + ")" if nginx_version else ""}. '
                          f'Checking for alias traversal vulnerability.',
            'category': 'nginx_detected',
            'location': 'Server Header',
            'recommendation': 'Ensure NGINX is properly configured and up-to-date.'
        })

        # Check URL for potential alias paths
        alias_findings = cls._check_alias_paths(url, response_text, headers_lower)
        findings.extend(alias_findings)

        # Check for traversal indicators in current response
        traversal_findings = cls._check_traversal_indicators(response_text, url)
        findings.extend(traversal_findings)

        return len(findings) > 0, findings

    @classmethod
    def _detect_nginx(cls, response_text: str, headers: Dict[str, str]) -> bool:
        """Detect if NGINX is the web server"""
        # Check Server header
        server_header = headers.get('server', '')
        if 'nginx' in server_header.lower():
            return True

        # Check X-Powered-By
        powered_by = headers.get('x-powered-by', '')
        if 'nginx' in powered_by.lower():
            return True

        # Check response body for NGINX signatures
        for pattern in cls.NGINX_PATTERNS:
            if pattern.search(response_text):
                return True

        # Check for NGINX error pages
        for pattern in cls.NGINX_ERRORS:
            if pattern.search(response_text):
                return True

        return False

    @classmethod
    def _get_nginx_version(cls, headers: Dict[str, str]) -> str:
        """Extract NGINX version from headers"""
        server_header = headers.get('server', '')
        match = re.search(r'nginx/?([\d.]+)', server_header, re.IGNORECASE)
        if match:
            return match.group(1)
        return ''

    @classmethod
    def _check_alias_paths(cls, url: str, response_text: str,
                           headers: Dict[str, str]) -> List[Dict[str, Any]]:
        """Check if URL path matches common alias locations"""
        findings = []

        try:
            parsed = urlparse(url)
            path = parsed.path.lower()
        except Exception:
            return findings

        # Check if path starts with a common alias location
        for alias_path in cls.VULNERABLE_PATHS:
            if path.startswith(alias_path):
                # Check if path could be vulnerable (no trailing slash after alias)
                # e.g., /static/file.js vs /static../etc/passwd
                remaining = path[len(alias_path):]

                if remaining and not remaining.startswith('/'):
                    # This could indicate missing trailing slash in alias config
                    findings.append({
                        'type': 'Potential NGINX Alias Path',
                        'severity': 'Low',
                        'url': url,
                        'alias_path': alias_path,
                        'description': f'URL path "{alias_path}" is a common NGINX alias location. '
                                      f'Test for traversal by appending "../" to access parent directories.',
                        'category': 'nginx_alias_path',
                        'location': 'URL Path',
                        'test_url': f'{parsed.scheme}://{parsed.netloc}{alias_path}../etc/passwd',
                        'recommendation': 'Verify NGINX alias configuration includes trailing slash: '
                                         f'alias /path/to/files/; (note the trailing slash)'
                    })

                # Special case: path already has traversal attempt
                if '..' in remaining:
                    findings.append({
                        'type': 'Path Traversal Attempt in Alias Location',
                        'severity': 'Medium',
                        'url': url,
                        'alias_path': alias_path,
                        'description': f'URL contains path traversal in NGINX alias location "{alias_path}". '
                                      f'If server responds with file content, alias traversal is confirmed.',
                        'category': 'nginx_alias_traversal_attempt',
                        'location': 'URL Path',
                        'recommendation': 'Fix NGINX alias configuration to include trailing slash.'
                    })

        return findings

    @classmethod
    def _check_traversal_indicators(cls, response_text: str, url: str) -> List[Dict[str, Any]]:
        """Check response for indicators of successful traversal"""
        findings = []

        # Check for successful traversal patterns in response
        for pattern in cls.SUCCESS_PATTERNS:
            if pattern.search(response_text):
                findings.append({
                    'type': 'NGINX Alias Traversal Confirmed',
                    'severity': 'Critical',
                    'url': url,
                    'pattern_matched': pattern.pattern,
                    'description': 'Response contains content indicating successful path traversal. '
                                  'NGINX alias misconfiguration allows reading arbitrary files.',
                    'category': 'nginx_alias_traversal_confirmed',
                    'location': 'Response Body',
                    'recommendation': 'IMMEDIATELY fix NGINX alias configuration. '
                                     'Ensure all alias directives end with trailing slash. '
                                     'Review exposed files for sensitive information.'
                })
                break

        # Check for NGINX-specific 403/404 that may indicate partial traversal
        if '403 Forbidden' in response_text and 'nginx' in response_text.lower():
            # May indicate traversal was attempted but blocked by permissions
            parsed = urlparse(url)
            if '..' in parsed.path:
                findings.append({
                    'type': 'NGINX Alias Traversal Blocked',
                    'severity': 'Low',
                    'url': url,
                    'description': 'Path traversal resulted in 403 Forbidden. '
                                  'Alias traversal may be possible but blocked by filesystem permissions.',
                    'category': 'nginx_alias_traversal_blocked',
                    'location': 'Response Body',
                    'recommendation': 'While access is blocked, the underlying vulnerability may still exist. '
                                     'Fix NGINX alias configuration.'
                })

        return findings

    @classmethod
    def get_test_payloads(cls, base_url: str) -> List[str]:
        """
        Generate test payloads for alias traversal testing.

        Args:
            base_url: Base URL with alias path (e.g., https://example.com/static)

        Returns:
            List of URLs to test for alias traversal
        """
        payloads = []

        for traversal in cls.TRAVERSAL_FILES:
            # Standard traversal
            payloads.append(f'{base_url.rstrip("/")}{traversal}')

            # URL encoded
            encoded = traversal.replace('../', '%2e%2e%2f')
            payloads.append(f'{base_url.rstrip("/")}{encoded}')

            # Double URL encoded
            double_encoded = traversal.replace('../', '%252e%252e%252f')
            payloads.append(f'{base_url.rstrip("/")}{double_encoded}')

        return payloads


def detect_nginx_alias_traversal(response_text: str, url: str,
                                  headers: Dict[str, str] = None) -> Tuple[bool, List[Dict[str, Any]]]:
    """Convenience function for NGINX alias traversal detection"""
    return NginxAliasTraversalDetector.detect(response_text, url, headers)
