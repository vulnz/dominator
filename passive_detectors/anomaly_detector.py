"""
Anomaly Response Detector

Passively detects anomalous HTTP responses that may indicate:
- Information disclosure via unusual file types
- Misconfigured servers serving wrong content
- Backup files exposed
- Source code leakage
- Archive files exposed
- Database dumps
- Log file exposure

Designed for ZERO false positives:
- Context-aware detection (ignores GitHub, package managers, etc.)
- Strict magic byte verification
- Size anomaly detection
- Extension mismatch detection
- Content-Type verification
"""

import re
from typing import Dict, List, Tuple, Any, Optional, Set
from urllib.parse import urlparse


class AnomalyDetector:
    """
    Anomaly Response Detector

    Detects unusual server responses with high confidence and minimal false positives.
    """

    # Sites where code/archives are expected (whitelist - never flag these)
    CODE_HOSTING_DOMAINS = {
        'github.com', 'raw.githubusercontent.com', 'gist.github.com',
        'gitlab.com', 'bitbucket.org',
        'sourceforge.net', 'codeberg.org',
        'npmjs.com', 'registry.npmjs.org',
        'pypi.org', 'files.pythonhosted.org',
        'rubygems.org', 'packagist.org',
        'mvnrepository.com', 'repo.maven.apache.org',
        'nuget.org', 'crates.io',
        'cdn.jsdelivr.net', 'unpkg.com', 'cdnjs.cloudflare.com',
        'pastebin.com', 'hastebin.com', 'gist.io',
        'jsfiddle.net', 'codepen.io', 'replit.com',
        'archive.org', 'web.archive.org',
    }

    # CDN/Static hosting domains (partial match)
    CDN_PATTERNS = [
        'cdn.', 'static.', 'assets.', 'media.',
        'storage.googleapis.com', 'amazonaws.com/s3',
        's3.amazonaws.com', 'blob.core.windows.net',
        'cloudfront.net', 'akamaihd.net', 'fastly.net',
    ]

    # Download/file sharing domains
    FILE_SHARING_DOMAINS = {
        'dropbox.com', 'drive.google.com', 'onedrive.live.com',
        'box.com', 'mediafire.com', 'mega.nz',
        'wetransfer.com', 'sendspace.com',
    }

    # Magic bytes for detecting file types
    MAGIC_BYTES = {
        # Archives
        'zip': (b'PK\x03\x04', 'ZIP Archive'),
        'zip_empty': (b'PK\x05\x06', 'Empty ZIP Archive'),
        'rar': (b'Rar!\x1a\x07', 'RAR Archive'),
        'rar5': (b'Rar!\x1a\x07\x01\x00', 'RAR5 Archive'),
        '7z': (b'\x37\x7a\xbc\xaf\x27\x1c', '7-Zip Archive'),
        'gz': (b'\x1f\x8b', 'GZip Archive'),
        'bz2': (b'BZh', 'BZip2 Archive'),
        'tar': (b'ustar', 'TAR Archive'),  # At offset 257
        'xz': (b'\xfd7zXZ\x00', 'XZ Archive'),

        # Executables
        'exe': (b'MZ', 'Windows Executable'),
        'elf': (b'\x7fELF', 'Linux Executable'),
        'mach': (b'\xcf\xfa\xed\xfe', 'macOS Executable'),

        # Documents
        'pdf': (b'%PDF', 'PDF Document'),
        'doc': (b'\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1', 'MS Office Document'),

        # Databases
        'sqlite': (b'SQLite format 3', 'SQLite Database'),

        # Disk images
        'iso': (b'CD001', 'ISO Disk Image'),  # At offset 32769

        # Java
        'jar': (b'PK\x03\x04', 'Java JAR (ZIP)'),  # Same as ZIP
        'class': (b'\xca\xfe\xba\xbe', 'Java Class File'),

        # Git
        'git_pack': (b'PACK', 'Git Pack File'),
        'git_idx': (b'\xff\x74\x4f\x63', 'Git Index File'),
    }

    # Sensitive file extensions that shouldn't be served
    SENSITIVE_EXTENSIONS = {
        # Source code
        '.php', '.php3', '.php4', '.php5', '.phtml', '.phps',
        '.asp', '.aspx', '.ascx', '.ashx', '.asmx',
        '.jsp', '.jspx', '.jsf',
        '.py', '.pyc', '.pyo',
        '.rb', '.erb',
        '.pl', '.pm', '.cgi',
        '.go', '.java', '.class',
        '.c', '.cpp', '.h', '.hpp',
        '.cs', '.vb',

        # Configuration
        '.env', '.ini', '.cfg', '.conf', '.config',
        '.yml', '.yaml', '.toml',
        '.properties', '.settings',
        '.htaccess', '.htpasswd',
        'web.config', 'app.config',

        # Database
        '.sql', '.db', '.sqlite', '.sqlite3', '.mdb', '.accdb',
        '.dump', '.bak',

        # Archives (when served as downloads unexpectedly)
        '.zip', '.rar', '.7z', '.tar', '.gz', '.tgz', '.bz2',

        # Logs
        '.log', '.logs',

        # Keys/Credentials
        '.pem', '.key', '.crt', '.cer', '.p12', '.pfx',
        '.pgp', '.gpg', '.asc',

        # Version control
        '.git', '.svn', '.hg',

        # Backup
        '.bak', '.backup', '.old', '.orig', '.save',
        '.swp', '.swo', '~',
    }

    # Source code indicators (high confidence patterns)
    SOURCE_CODE_PATTERNS = {
        'PHP': [
            re.compile(r'^<\?php\s', re.MULTILINE),
            re.compile(r'<\?php\s+(?:namespace|use|class|function|require|include)', re.IGNORECASE),
        ],
        'ASP.NET': [
            re.compile(r'<%@\s*Page\s+', re.IGNORECASE),
            re.compile(r'<%@\s*(?:Import|Assembly|Register)', re.IGNORECASE),
        ],
        'JSP': [
            re.compile(r'<%@\s*page\s+', re.IGNORECASE),
            re.compile(r'<%@\s*taglib\s+', re.IGNORECASE),
        ],
        'Python': [
            re.compile(r'^#!/usr/bin/(?:env\s+)?python', re.MULTILINE),
            re.compile(r'^from\s+\w+\s+import\s+|^import\s+\w+', re.MULTILINE),
        ],
        'Ruby': [
            re.compile(r'^#!/usr/bin/(?:env\s+)?ruby', re.MULTILINE),
            re.compile(r'^require\s+[\'"]|^class\s+\w+\s*<', re.MULTILINE),
        ],
    }

    # Size thresholds for anomaly detection
    MIN_ANOMALY_SIZE = 100  # Ignore tiny responses
    LARGE_RESPONSE_THRESHOLD = 1024 * 1024  # 1MB

    # Expected Content-Types for code (when NOT expected)
    CODE_CONTENT_TYPES = {
        'text/x-php', 'application/x-php', 'application/x-httpd-php',
        'text/x-python', 'application/x-python',
        'text/x-ruby', 'application/x-ruby',
        'text/x-java', 'text/x-java-source',
        'text/x-c', 'text/x-c++',
    }

    @classmethod
    def detect(cls, response_text: str, url: str,
               headers: Dict[str, str] = None,
               response_bytes: bytes = None) -> Tuple[bool, List[Dict[str, Any]]]:
        """
        Detect anomalous responses.

        Args:
            response_text: HTTP response body as text
            url: URL being analyzed
            headers: HTTP response headers
            response_bytes: Raw response bytes (for magic byte detection)

        Returns:
            Tuple of (found_anomaly, list_of_findings)
        """
        findings = []
        headers = headers or {}

        # Skip whitelisted domains
        if cls._is_whitelisted_domain(url):
            return False, findings

        # Get content type
        content_type = headers.get('Content-Type', '') or headers.get('content-type', '')
        content_length = cls._get_content_length(headers)

        # Skip tiny responses
        if content_length and content_length < cls.MIN_ANOMALY_SIZE:
            return False, findings

        # Check for extension anomalies
        ext_findings = cls._check_extension_anomaly(url, response_text, content_type, headers)
        findings.extend(ext_findings)

        # Check for magic byte anomalies (if we have raw bytes)
        if response_bytes:
            magic_findings = cls._check_magic_bytes(url, response_bytes, content_type)
            findings.extend(magic_findings)

        # Check for source code exposure
        source_findings = cls._check_source_code(url, response_text, content_type)
        findings.extend(source_findings)

        # Check for size anomalies
        size_findings = cls._check_size_anomaly(url, content_length, content_type)
        findings.extend(size_findings)

        # Check Content-Type mismatches
        mismatch_findings = cls._check_content_type_mismatch(url, response_text, content_type)
        findings.extend(mismatch_findings)

        # Deduplicate
        seen = set()
        unique_findings = []
        for finding in findings:
            key = f"{finding['type']}:{finding.get('file_type', '')}"
            if key not in seen:
                seen.add(key)
                unique_findings.append(finding)

        return len(unique_findings) > 0, unique_findings

    @classmethod
    def _is_whitelisted_domain(cls, url: str) -> bool:
        """Check if URL is from a whitelisted domain"""
        try:
            parsed = urlparse(url)
            domain = parsed.netloc.lower()

            # Remove port
            if ':' in domain:
                domain = domain.split(':')[0]

            # Check exact matches
            if domain in cls.CODE_HOSTING_DOMAINS:
                return True

            # Check if subdomain of whitelisted
            for whitelist in cls.CODE_HOSTING_DOMAINS:
                if domain.endswith('.' + whitelist):
                    return True

            # Check CDN patterns
            for pattern in cls.CDN_PATTERNS:
                if pattern in domain:
                    return True

            # Check file sharing
            for sharing in cls.FILE_SHARING_DOMAINS:
                if sharing in domain:
                    return True

            # Check if path indicates download/release
            path = parsed.path.lower()
            download_indicators = ['/releases/', '/download/', '/downloads/',
                                  '/dist/', '/assets/', '/files/', '/packages/']
            if any(ind in path for ind in download_indicators):
                return True

        except Exception:
            pass

        return False

    @classmethod
    def _get_content_length(cls, headers: Dict[str, str]) -> Optional[int]:
        """Get content length from headers"""
        for key in ['Content-Length', 'content-length']:
            if key in headers:
                try:
                    return int(headers[key])
                except ValueError:
                    pass
        return None

    @classmethod
    def _check_extension_anomaly(cls, url: str, content: str,
                                 content_type: str, headers: Dict[str, str]) -> List[Dict[str, Any]]:
        """Check for sensitive file extensions being served"""
        findings = []

        try:
            parsed = urlparse(url)
            path = parsed.path.lower()

            # Get file extension
            if '.' in path:
                ext = '.' + path.rsplit('.', 1)[-1]

                if ext in cls.SENSITIVE_EXTENSIONS:
                    # Additional validation to reduce false positives

                    # Check if it's being served as download (intended behavior)
                    content_disp = headers.get('Content-Disposition', '') or \
                                   headers.get('content-disposition', '')
                    if 'attachment' in content_disp.lower():
                        return findings  # Intended download

                    # Check if content type matches expectation
                    is_code_type = any(ct in content_type.lower() for ct in
                                      ['text/plain', 'application/octet-stream'])

                    # For archives, check if actually being served
                    if ext in ['.zip', '.rar', '.7z', '.tar', '.gz']:
                        # Only flag if content-type suggests web page but content is binary
                        if 'text/html' in content_type.lower() and content:
                            # Might be error page, not actual archive
                            return findings

                    # For source code files, verify actual code content
                    if ext in ['.php', '.asp', '.aspx', '.jsp', '.py', '.rb']:
                        if not cls._contains_source_code(content):
                            return findings  # Probably not actual source

                    findings.append({
                        'type': 'Sensitive File Extension Served',
                        'severity': 'Medium' if ext in ['.log', '.bak'] else 'High',
                        'url': url,
                        'extension': ext,
                        'content_type': content_type,
                        'description': f'Sensitive file type ({ext}) is being served. '
                                      f'This may expose source code, configuration, or backups.',
                        'category': 'anomaly_extension',
                        'location': 'URL Path',
                        'recommendation': f'Block access to {ext} files via server configuration. '
                                         f'Move sensitive files outside web root.'
                    })

        except Exception:
            pass

        return findings

    @classmethod
    def _check_magic_bytes(cls, url: str, content: bytes,
                          content_type: str) -> List[Dict[str, Any]]:
        """Check for binary file magic bytes"""
        findings = []

        if len(content) < 10:
            return findings

        # Check each magic signature
        for file_type, (magic, description) in cls.MAGIC_BYTES.items():
            offset = 0

            # Special offsets for some formats
            if file_type == 'tar':
                offset = 257
            elif file_type == 'iso':
                offset = 32769

            if len(content) > offset + len(magic):
                if content[offset:offset + len(magic)] == magic:
                    # Verify this is unexpected

                    # Archives/executables on non-download URLs
                    path = urlparse(url).path.lower()

                    # Skip if URL suggests download
                    if any(x in path for x in ['/download', '/file', '/asset', '/release']):
                        continue

                    # Skip if Content-Type indicates binary download
                    if 'application/octet-stream' in content_type and \
                       'attachment' in (content_type.lower()):
                        continue

                    # For ZIP/RAR, only flag if served as wrong content type
                    if file_type in ['zip', 'rar', '7z'] and \
                       'application/' in content_type and 'zip' in content_type:
                        continue  # Proper content type

                    severity = 'High'
                    if file_type in ['pdf', 'doc']:
                        severity = 'Low'
                    elif file_type in ['exe', 'elf', 'class']:
                        severity = 'Critical'

                    findings.append({
                        'type': 'Binary File Detected',
                        'severity': severity,
                        'url': url,
                        'file_type': file_type,
                        'description_type': description,
                        'content_type': content_type,
                        'description': f'{description} detected. Binary files served from '
                                      f'unexpected locations may indicate misconfiguration.',
                        'category': 'anomaly_binary',
                        'location': 'Response Body',
                        'recommendation': 'Review why binary files are accessible. '
                                         'Ensure proper access controls and Content-Type headers.'
                    })
                    break  # One finding per response

        return findings

    @classmethod
    def _check_source_code(cls, url: str, content: str,
                          content_type: str) -> List[Dict[str, Any]]:
        """Check for source code exposure"""
        findings = []

        if not content or len(content) < 50:
            return findings

        # Skip if URL is for a known code file (js, css)
        path = urlparse(url).path.lower()
        if path.endswith(('.js', '.css', '.json', '.xml', '.txt')):
            return findings

        # Skip if content type is HTML (normal response)
        if 'text/html' in content_type.lower():
            # But check for PHP source in HTML response (misconfigured)
            if '<?php' in content[:1000]:
                pass  # Continue checking
            else:
                return findings

        # Check for source code patterns
        for language, patterns in cls.SOURCE_CODE_PATTERNS.items():
            for pattern in patterns:
                if pattern.search(content[:5000]):  # Check first 5KB
                    # Verify it's not just code snippet in article
                    # Must have multiple indicators
                    if cls._validate_source_code_exposure(content, language):
                        findings.append({
                            'type': 'Source Code Exposure',
                            'severity': 'Critical',
                            'url': url,
                            'language': language,
                            'content_type': content_type,
                            'description': f'{language} source code exposed! Server may be '
                                          f'misconfigured and serving raw source files.',
                            'category': 'anomaly_source_code',
                            'location': 'Response Body',
                            'evidence': content[:200].strip(),
                            'recommendation': f'Configure server to process {language} files '
                                             f'instead of serving as plain text. Check server '
                                             f'handler configuration.'
                        })
                        return findings  # One finding per response

        return findings

    @classmethod
    def _validate_source_code_exposure(cls, content: str, language: str) -> bool:
        """Validate that detected source code is genuine exposure, not snippet"""
        # Must have significant amount of code
        if len(content) < 200:
            return False

        # Check for multiple code indicators based on language
        indicators = 0

        if language == 'PHP':
            php_patterns = [
                r'\$\w+\s*=', r'function\s+\w+\s*\(',
                r'class\s+\w+', r'->\w+\s*\(',
                r'require|include|use\s+', r'namespace\s+'
            ]
            for pattern in php_patterns:
                if re.search(pattern, content):
                    indicators += 1

        elif language == 'Python':
            py_patterns = [
                r'def\s+\w+\s*\(', r'class\s+\w+\s*[:\(]',
                r'import\s+\w+', r'from\s+\w+\s+import',
                r'if\s+__name__\s*==', r'self\.\w+'
            ]
            for pattern in py_patterns:
                if re.search(pattern, content):
                    indicators += 1

        elif language in ['ASP.NET', 'JSP']:
            asp_patterns = [
                r'<%', r'%>', r'Response\.', r'Request\.',
                r'Session\[', r'Server\.'
            ]
            for pattern in asp_patterns:
                if re.search(pattern, content):
                    indicators += 1

        # Require at least 3 indicators for high confidence
        return indicators >= 3

    @classmethod
    def _check_size_anomaly(cls, url: str, content_length: Optional[int],
                           content_type: str) -> List[Dict[str, Any]]:
        """Check for unusual response sizes"""
        findings = []

        if not content_length:
            return findings

        # Very large HTML response might indicate dump
        if 'text/html' in content_type.lower():
            if content_length > 5 * 1024 * 1024:  # 5MB HTML is unusual
                findings.append({
                    'type': 'Unusually Large Response',
                    'severity': 'Low',
                    'url': url,
                    'size': content_length,
                    'size_mb': round(content_length / (1024 * 1024), 2),
                    'content_type': content_type,
                    'description': f'Unusually large HTML response ({content_length} bytes). '
                                  f'May indicate debug output or data dump.',
                    'category': 'anomaly_size',
                    'location': 'Response',
                    'recommendation': 'Review why response is unusually large. '
                                     'Check for debug output or unintended data exposure.'
                })

        return findings

    @classmethod
    def _check_content_type_mismatch(cls, url: str, content: str,
                                    content_type: str) -> List[Dict[str, Any]]:
        """Check for Content-Type mismatches"""
        findings = []

        if not content or len(content) < 100:
            return findings

        # HTML served as wrong type
        if '<!DOCTYPE html' in content[:500] or '<html' in content[:500]:
            if 'text/html' not in content_type.lower() and \
               'application/xhtml' not in content_type.lower():
                # Only flag if it's a concerning mismatch
                if 'text/plain' in content_type.lower() or \
                   'application/json' in content_type.lower():
                    findings.append({
                        'type': 'Content-Type Mismatch',
                        'severity': 'Low',
                        'url': url,
                        'expected': 'text/html',
                        'actual': content_type,
                        'description': 'HTML content served with incorrect Content-Type. '
                                      'May cause rendering issues or indicate misconfiguration.',
                        'category': 'anomaly_content_type',
                        'location': 'Response Headers',
                        'recommendation': 'Set correct Content-Type header for response.'
                    })

        # JSON served as text
        if content.strip().startswith(('{', '[')) and content.strip().endswith(('}', ']')):
            if 'application/json' not in content_type.lower() and \
               'text/json' not in content_type.lower():
                if 'text/html' in content_type.lower():
                    # Only if clearly JSON, not HTML with JS
                    try:
                        import json
                        json.loads(content)
                        # Valid JSON but wrong content type
                        findings.append({
                            'type': 'JSON with Wrong Content-Type',
                            'severity': 'Info',
                            'url': url,
                            'actual': content_type,
                            'description': 'JSON content served with non-JSON Content-Type.',
                            'category': 'anomaly_content_type',
                            'location': 'Response Headers',
                            'recommendation': 'Use application/json Content-Type for JSON responses.'
                        })
                    except:
                        pass  # Not valid JSON

        return findings

    @classmethod
    def _contains_source_code(cls, content: str) -> bool:
        """Quick check if content contains actual source code"""
        if not content:
            return False

        # Check for common source code patterns
        code_patterns = [
            r'<\?php', r'<%@', r'<%=',
            r'^#!/', r'^from\s+\w+\s+import',
            r'function\s+\w+\s*\(', r'def\s+\w+\s*\(',
            r'class\s+\w+\s*[:\{]', r'public\s+class',
        ]

        for pattern in code_patterns:
            if re.search(pattern, content[:2000], re.MULTILINE):
                return True

        return False


def detect_anomaly(response_text: str, url: str,
                   headers: Dict[str, str] = None,
                   response_bytes: bytes = None) -> Tuple[bool, List[Dict[str, Any]]]:
    """Convenience function for anomaly detection"""
    return AnomalyDetector.detect(response_text, url, headers, response_bytes)
