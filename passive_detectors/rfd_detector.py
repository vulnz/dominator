"""
Reflected File Download (RFD) Vulnerability Detector

Passively detects potential Reflected File Download vulnerabilities.

RFD allows attackers to:
- Make users download malicious files that appear to come from trusted domains
- Bypass download warnings by using trusted domain reputation
- Execute arbitrary commands when downloaded "data" files are opened

Detection checks:
- JSON/JSONP responses with reflected user input
- Content-Disposition headers that can be manipulated
- API endpoints returning reflected data
- Filename parameters in URLs
"""

import re
from typing import Dict, List, Tuple, Any
from urllib.parse import urlparse, parse_qs


class RFDDetector:
    """
    Reflected File Download Vulnerability Detector

    Identifies conditions that may allow RFD attacks.
    """

    # Executable extensions that browsers may auto-execute
    DANGEROUS_EXTENSIONS = [
        '.bat', '.cmd', '.com', '.exe', '.msi', '.ps1', '.vbs', '.vbe',
        '.js', '.jse', '.wsf', '.wsh', '.scr', '.pif', '.hta', '.cpl',
        '.jar', '.sh', '.bash', '.py', '.pl', '.rb',
    ]

    # Content types that may be vulnerable to RFD
    VULNERABLE_CONTENT_TYPES = [
        'application/json',
        'text/json',
        'application/javascript',
        'text/javascript',
        'application/xml',
        'text/xml',
        'text/html',
        'text/plain',
    ]

    # Patterns indicating reflected content in response
    REFLECTION_PATTERNS = [
        # JSONP callback reflection
        re.compile(r'^\s*([a-zA-Z_$][a-zA-Z0-9_$]*)\s*\(\s*[\[{]', re.MULTILINE),
        # JSON with potential injection points
        re.compile(r'"[^"]*":\s*"[^"]*[<>|&;`$]', re.IGNORECASE),
        # HTML in JSON
        re.compile(r'"[^"]*":\s*"[^"]*<[a-z]+[^>]*>', re.IGNORECASE),
        # Command characters in output
        re.compile(r'[|&;`$()]'),
    ]

    # URL patterns that suggest downloadable content
    DOWNLOAD_URL_PATTERNS = [
        re.compile(r'[?&](?:file|filename|name|download|attachment|path)=', re.IGNORECASE),
        re.compile(r'[?&]callback=', re.IGNORECASE),  # JSONP callback
        re.compile(r'[?&]jsonp=', re.IGNORECASE),
        re.compile(r'\.(?:json|xml|csv|txt)(?:\?|$)', re.IGNORECASE),
    ]

    # Patterns in Content-Disposition that suggest vulnerability
    CD_VULNERABLE_PATTERNS = [
        re.compile(r'filename\s*=\s*["\']?[^"\';\s]*\.[a-z]{2,4}["\']?', re.IGNORECASE),
        re.compile(r'attachment', re.IGNORECASE),
    ]

    @classmethod
    def detect(cls, response_text: str, url: str, headers: Dict[str, str] = None) -> Tuple[bool, List[Dict[str, Any]]]:
        """
        Detect potential Reflected File Download vulnerabilities.

        Args:
            response_text: HTTP response body
            url: URL being analyzed
            headers: HTTP response headers

        Returns:
            Tuple of (found_issues, list_of_findings)
        """
        findings = []

        if not response_text:
            return False, findings

        headers = headers or {}
        headers_lower = {k.lower(): v for k, v in headers.items()}

        # Get content type
        content_type = headers_lower.get('content-type', '').lower()

        # Check URL patterns
        url_issues = cls._check_url_patterns(url)
        findings.extend(url_issues)

        # Check Content-Disposition header
        cd_issues = cls._check_content_disposition(headers_lower, url, response_text)
        findings.extend(cd_issues)

        # Check for JSONP callback reflection
        jsonp_issues = cls._check_jsonp(response_text, url, content_type)
        findings.extend(jsonp_issues)

        # Check for reflected content in JSON/XML responses
        if any(ct in content_type for ct in ['json', 'xml', 'javascript']):
            reflection_issues = cls._check_reflection(response_text, url, content_type)
            findings.extend(reflection_issues)

        # Check for semicolon/command injection in path
        path_issues = cls._check_path_injection(url)
        findings.extend(path_issues)

        return len(findings) > 0, findings

    @classmethod
    def _check_url_patterns(cls, url: str) -> List[Dict[str, Any]]:
        """Check URL for patterns that may enable RFD"""
        findings = []

        try:
            parsed = urlparse(url)
            query_params = parse_qs(parsed.query)
        except Exception:
            return findings

        # Check for filename parameters
        filename_params = ['file', 'filename', 'name', 'path', 'download', 'attachment']
        for param in filename_params:
            if param in query_params:
                value = query_params[param][0]

                # Check if value contains extension
                for ext in cls.DANGEROUS_EXTENSIONS:
                    if ext in value.lower():
                        findings.append({
                            'type': 'Dangerous Extension in Filename Parameter',
                            'severity': 'Medium',
                            'url': url,
                            'parameter': param,
                            'value': value,
                            'extension': ext,
                            'description': f'Filename parameter "{param}" contains executable extension "{ext}". '
                                          f'May allow Reflected File Download attacks.',
                            'category': 'rfd_filename',
                            'location': 'URL Query Parameter',
                            'recommendation': 'Validate and sanitize filename parameters. '
                                             'Use allowlist of permitted extensions. '
                                             'Set Content-Disposition with safe filename.'
                        })
                        break

        # Check for JSONP callback
        jsonp_params = ['callback', 'jsonp', 'cb', 'jsonpcallback']
        for param in jsonp_params:
            if param in query_params:
                callback = query_params[param][0]
                findings.append({
                    'type': 'JSONP Callback Parameter',
                    'severity': 'Low',
                    'url': url,
                    'parameter': param,
                    'callback': callback,
                    'description': f'JSONP callback parameter "{param}" detected. '
                                  f'May be exploitable for RFD if callback is reflected.',
                    'category': 'rfd_jsonp',
                    'location': 'URL Query Parameter',
                    'recommendation': 'Validate callback parameter against strict allowlist. '
                                     'Use CORS instead of JSONP where possible. '
                                     'Set X-Content-Type-Options: nosniff header.'
                })

        return findings

    @classmethod
    def _check_content_disposition(cls, headers: Dict[str, str], url: str,
                                   response_text: str) -> List[Dict[str, Any]]:
        """Check Content-Disposition header for RFD vulnerabilities"""
        findings = []

        cd_header = headers.get('content-disposition', '')
        if not cd_header:
            return findings

        # Check if attachment
        if 'attachment' in cd_header.lower():
            # Extract filename
            filename_match = re.search(r'filename\s*=\s*["\']?([^"\';\s]+)', cd_header, re.IGNORECASE)
            if filename_match:
                filename = filename_match.group(1)

                # Check for dangerous extension
                for ext in cls.DANGEROUS_EXTENSIONS:
                    if filename.lower().endswith(ext):
                        findings.append({
                            'type': 'Dangerous Extension in Content-Disposition',
                            'severity': 'High',
                            'url': url,
                            'filename': filename,
                            'header': cd_header,
                            'description': f'Content-Disposition header specifies executable filename "{filename}". '
                                          f'Users may be tricked into downloading and executing malicious content.',
                            'category': 'rfd_content_disposition',
                            'location': 'Content-Disposition Header',
                            'recommendation': 'Never allow user-controlled filenames in Content-Disposition. '
                                             'Use safe extensions only (.txt, .pdf, etc.). '
                                             'Validate and sanitize all filename inputs.'
                        })
                        break

                # Check if filename appears in response (reflected)
                if filename.split('.')[0] in response_text:
                    findings.append({
                        'type': 'Reflected Filename in Content-Disposition',
                        'severity': 'Medium',
                        'url': url,
                        'filename': filename,
                        'description': f'Filename "{filename}" in Content-Disposition appears to be reflected from input. '
                                      f'May allow RFD by manipulating the filename extension.',
                        'category': 'rfd_reflected_filename',
                        'location': 'Content-Disposition Header',
                        'recommendation': 'Do not reflect user input in Content-Disposition filename. '
                                         'Use server-generated safe filenames.'
                    })

        return findings

    @classmethod
    def _check_jsonp(cls, response_text: str, url: str, content_type: str) -> List[Dict[str, Any]]:
        """Check for JSONP callback reflection"""
        findings = []

        # Check for JSONP pattern
        jsonp_match = re.match(r'^\s*([a-zA-Z_$][a-zA-Z0-9_$]*)\s*\(\s*[\[{]', response_text)
        if jsonp_match:
            callback = jsonp_match.group(1)

            # Check if callback is in URL
            if callback in url:
                findings.append({
                    'type': 'JSONP Callback Reflected',
                    'severity': 'Medium',
                    'url': url,
                    'callback': callback,
                    'description': f'JSONP callback "{callback}" is reflected from URL into response. '
                                  f'Combined with semicolon in URL path, may enable RFD.',
                    'category': 'rfd_jsonp_reflected',
                    'location': 'Response Body',
                    'recommendation': 'Validate JSONP callbacks against strict allowlist. '
                                     'Set Content-Type: application/json with X-Content-Type-Options: nosniff. '
                                     'Consider using CORS instead of JSONP.'
                })

        return findings

    @classmethod
    def _check_reflection(cls, response_text: str, url: str, content_type: str) -> List[Dict[str, Any]]:
        """Check for potentially dangerous reflected content"""
        findings = []

        # Parse URL to get query parameters
        try:
            parsed = urlparse(url)
            query_params = parse_qs(parsed.query)
        except Exception:
            return findings

        # Check if any parameter value appears in response
        for param, values in query_params.items():
            for value in values:
                if len(value) > 3 and value in response_text:
                    # Check if response contains command characters around the value
                    escaped_value = re.escape(value)
                    pattern = re.compile(rf'[|&;`$]\s*{escaped_value}|{escaped_value}\s*[|&;`$]')

                    if pattern.search(response_text):
                        findings.append({
                            'type': 'Reflected Parameter with Command Characters',
                            'severity': 'Low',
                            'url': url,
                            'parameter': param,
                            'value': value,
                            'description': f'Parameter "{param}" value is reflected near command characters. '
                                          f'May be exploitable for RFD if downloaded as script.',
                            'category': 'rfd_reflection',
                            'location': 'Response Body',
                            'recommendation': 'Sanitize all reflected output. '
                                             'Set proper Content-Type and X-Content-Type-Options headers.'
                        })

        return findings

    @classmethod
    def _check_path_injection(cls, url: str) -> List[Dict[str, Any]]:
        """Check for semicolon injection in URL path"""
        findings = []

        try:
            parsed = urlparse(url)
            path = parsed.path
        except Exception:
            return findings

        # Check for semicolon in path (used for RFD with fake extensions)
        if ';' in path:
            # Extract what appears to be a fake extension
            parts = path.split(';')
            if len(parts) > 1:
                potential_ext = parts[-1].split('/')[0] if '/' in parts[-1] else parts[-1]

                for ext in cls.DANGEROUS_EXTENSIONS:
                    if potential_ext.lower() == ext.lstrip('.'):
                        findings.append({
                            'type': 'Semicolon Path Injection (RFD)',
                            'severity': 'Medium',
                            'url': url,
                            'injected_extension': potential_ext,
                            'description': f'URL path contains semicolon followed by "{potential_ext}". '
                                          f'This technique can force browsers to download content as executable.',
                            'category': 'rfd_semicolon',
                            'location': 'URL Path',
                            'recommendation': 'Block semicolons in URL paths at web server/WAF level. '
                                             'Normalize URLs before processing.'
                        })
                        break

        return findings


def detect_rfd(response_text: str, url: str, headers: Dict[str, str] = None) -> Tuple[bool, List[Dict[str, Any]]]:
    """Convenience function for RFD detection"""
    return RFDDetector.detect(response_text, url, headers)
