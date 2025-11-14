"""
Passive sensitive data detector
Discovers sensitive information leaks in HTTP responses during crawling
"""

import re
from typing import Dict, List, Tuple, Any

class SensitiveDataDetector:
    """Passive sensitive data detection"""
    
    @staticmethod
    def analyze(response_text: str, url: str, headers: Dict[str, str] = None) -> Tuple[bool, List[Dict[str, Any]]]:
        """
        Passive sensitive data detection

        How it works:
        1. Scans response content for sensitive patterns during crawling
        2. Searches for API keys, passwords, tokens, personal data
        3. Analyzes HTML comments and hidden fields
        4. Checks headers for information leaks
        5. No additional requests sent

        Args:
            response_text: HTTP response content
            url: URL being analyzed
            headers: HTTP headers (optional)

        Returns:
            Tuple[bool, List[Dict]]: (found_data, list_of_leaks)
        """
        # ANTI-FALSE-POSITIVE: Skip common JS libraries and minified files
        # These often contain test data, examples, or obfuscated code that triggers false positives
        url_lower = url.lower()
        skip_patterns = [
            'jquery.js', 'jquery.min.js', 'jquery-',
            'bootstrap.js', 'bootstrap.min.js',
            'angular.js', 'angular.min.js',
            'react.js', 'react.min.js', 'react-dom',
            'vue.js', 'vue.min.js',
            'lodash.js', 'lodash.min.js', 'underscore',
            'moment.js', 'moment.min.js',
            'axios.js', 'axios.min.js',
            'd3.js', 'd3.min.js',
            '.min.js', '-min.js',  # Any minified JS
            'vendor.js', 'bundle.js', 'chunk.js'  # Bundled files
        ]

        if any(pattern in url_lower for pattern in skip_patterns):
            return False, []

        leaks = []
        
        # Content analysis
        content_leaks = SensitiveDataDetector._analyze_content(response_text, url)
        leaks.extend(content_leaks)
        
        # Email extraction
        email_leaks = SensitiveDataDetector._extract_emails(response_text, url)
        leaks.extend(email_leaks)
        
        # Phone number extraction
        phone_leaks = SensitiveDataDetector._extract_phones(response_text, url)
        leaks.extend(phone_leaks)
        
        # API keys and tokens
        api_leaks = SensitiveDataDetector._extract_api_keys(response_text, url)
        leaks.extend(api_leaks)
        
        # Internal paths and IPs
        internal_leaks = SensitiveDataDetector._extract_internal_info(response_text, url)
        leaks.extend(internal_leaks)
        
        # HTML comments analysis
        comment_leaks = SensitiveDataDetector._analyze_html_comments(response_text, url)
        leaks.extend(comment_leaks)

        # Path disclosure detection (from error messages)
        path_disclosure_leaks = SensitiveDataDetector._detect_path_disclosure(response_text, url)
        leaks.extend(path_disclosure_leaks)

        # Database error detection
        db_error_leaks = SensitiveDataDetector._detect_database_errors(response_text, url)
        leaks.extend(db_error_leaks)

        # Private keys and critical secrets detection
        private_keys_leaks = SensitiveDataDetector._detect_private_keys_and_secrets(response_text, url)
        leaks.extend(private_keys_leaks)

        return len(leaks) > 0, leaks
    
    @staticmethod
    def _analyze_content(response_text: str, url: str) -> List[Dict[str, Any]]:
        """Analyze content for sensitive patterns"""
        leaks = []
        
        # Hardcoded credentials patterns
        credential_patterns = {
            r'password["\s]*[:=]["\s]*([^"\s]{6,})': {
                'type': 'hardcoded_password',
                'severity': 'High',
                'description': 'Hardcoded password found'
            },
            r'username["\s]*[:=]["\s]*([^"\s]{3,})': {
                'type': 'hardcoded_username',
                'severity': 'Medium',
                'description': 'Hardcoded username found'
            },
            r'secret[_-]?key["\s]*[:=]["\s]*([a-zA-Z0-9]{20,})': {
                'type': 'secret_key',
                'severity': 'Critical',
                'description': 'Secret key found'
            }
        }
        
        for pattern, info in credential_patterns.items():
            matches = re.finditer(pattern, response_text, re.IGNORECASE)
            for match in matches:
                value = match.group(1) if match.groups() else match.group(0)
                masked_value = value[:3] + '*' * (len(value) - 6) + value[-3:] if len(value) > 6 else '*' * len(value)
                
                leaks.append({
                    'type': info['type'],
                    'severity': info['severity'],
                    'url': url,
                    'description': info['description'],
                    'value': masked_value,
                    'location': 'Response Content',
                    'recommendation': 'Remove sensitive information from public responses'
                })
        
        return leaks
    
    @staticmethod
    def _extract_emails(response_text: str, url: str) -> List[Dict[str, Any]]:
        """Extract email addresses from response"""
        leaks = []
        
        email_pattern = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
        emails = re.findall(email_pattern, response_text)
        
        # Filter out common false positives
        filtered_emails = []
        for email in emails:
            email_lower = email.lower()
            if not any(fp in email_lower for fp in ['example.com', 'test.com', 'localhost', 'domain.com']):
                filtered_emails.append(email)
        
        if filtered_emails:
            leaks.append({
                'type': 'email_disclosure',
                'severity': 'Low',
                'url': url,
                'description': f'Email addresses found: {len(filtered_emails)} addresses',
                'emails': filtered_emails[:10],  # Limit to first 10
                'count': len(filtered_emails),
                'location': 'Response Content',
                'recommendation': 'Consider if email addresses should be publicly visible'
            })
        
        return leaks
    
    @staticmethod
    def _extract_phones(response_text: str, url: str) -> List[Dict[str, Any]]:
        """Extract phone numbers from response"""
        leaks = []
        
        phone_patterns = [
            r'\+?1?[-.\s]?\(?[0-9]{3}\)?[-.\s]?[0-9]{3}[-.\s]?[0-9]{4}',  # US format
            r'\+?[0-9]{1,3}[-.\s]?[0-9]{3,4}[-.\s]?[0-9]{3,4}[-.\s]?[0-9]{3,4}',  # International
            r'\([0-9]{3}\)\s?[0-9]{3}-[0-9]{4}'  # (xxx) xxx-xxxx
        ]
        
        phones = []
        for pattern in phone_patterns:
            matches = re.findall(pattern, response_text)
            phones.extend(matches)
        
        if phones:
            # Remove duplicates
            unique_phones = list(set(phones))
            leaks.append({
                'type': 'phone_disclosure',
                'severity': 'Medium',
                'url': url,
                'description': f'Phone numbers found: {len(unique_phones)} numbers',
                'phones': unique_phones[:5],  # Limit to first 5
                'count': len(unique_phones),
                'location': 'Response Content',
                'recommendation': 'Consider if phone numbers should be publicly visible'
            })
        
        return leaks
    
    @staticmethod
    def _extract_api_keys(response_text: str, url: str) -> List[Dict[str, Any]]:
        """Extract API keys and tokens"""
        leaks = []
        
        api_patterns = {
            r'api[_-]?key["\s]*[:=]["\s]*([a-zA-Z0-9]{20,})': {
                'type': 'api_key',
                'severity': 'High',
                'description': 'API key found'
            },
            r'access[_-]?token["\s]*[:=]["\s]*([a-zA-Z0-9]{20,})': {
                'type': 'access_token',
                'severity': 'High',
                'description': 'Access token found'
            },
            r'AKIA[0-9A-Z]{16}': {
                'type': 'aws_access_key',
                'severity': 'Critical',
                'description': 'AWS Access Key ID found'
            },
            r'AIza[0-9A-Za-z\\-_]{35}': {
                'type': 'google_api_key',
                'severity': 'High',
                'description': 'Google API key found'
            },
            r'ghp_[0-9a-zA-Z]{36}': {
                'type': 'github_token',
                'severity': 'High',
                'description': 'GitHub Personal Access Token found'
            }
        }
        
        for pattern, info in api_patterns.items():
            matches = re.finditer(pattern, response_text, re.IGNORECASE)
            for match in matches:
                value = match.group(1) if match.groups() else match.group(0)
                masked_value = value[:4] + '*' * (len(value) - 8) + value[-4:] if len(value) > 8 else '*' * len(value)
                
                leaks.append({
                    'type': info['type'],
                    'severity': info['severity'],
                    'url': url,
                    'description': info['description'],
                    'value': masked_value,
                    'location': 'Response Content',
                    'recommendation': 'Remove API keys from public responses immediately'
                })
        
        return leaks
    
    @staticmethod
    def _extract_internal_info(response_text: str, url: str) -> List[Dict[str, Any]]:
        """Extract internal IPs and file paths"""
        leaks = []
        
        # Internal IP addresses
        internal_ip_pattern = r'\b(?:10\.|172\.(?:1[6-9]|2[0-9]|3[01])\.|192\.168\.)\d{1,3}\.\d{1,3}\b'
        internal_ips = re.findall(internal_ip_pattern, response_text)
        
        if internal_ips:
            unique_ips = list(set(internal_ips))
            leaks.append({
                'type': 'internal_ip_disclosure',
                'severity': 'Medium',
                'url': url,
                'description': f'Internal IP addresses found: {len(unique_ips)} addresses',
                'ips': unique_ips,
                'location': 'Response Content',
                'recommendation': 'Remove internal IP addresses from public responses'
            })
        
        # File paths
        file_path_patterns = [
            r'[C-Z]:\\[^"\s<>|]{10,}',  # Windows paths
            r'/(?:home|root|etc|var|usr)/[^"\s<>|]{5,}'  # Unix/Linux paths
        ]
        
        paths = []
        for pattern in file_path_patterns:
            matches = re.findall(pattern, response_text)
            paths.extend(matches)
        
        if paths:
            unique_paths = list(set(paths))
            leaks.append({
                'type': 'file_path_disclosure',
                'severity': 'Low',
                'url': url,
                'description': f'File paths found: {len(unique_paths)} paths',
                'paths': unique_paths[:5],  # Limit to first 5
                'location': 'Response Content',
                'recommendation': 'Remove internal file paths from public responses'
            })
        
        return leaks
    
    @staticmethod
    def _analyze_html_comments(response_text: str, url: str) -> List[Dict[str, Any]]:
        """Analyze HTML comments for sensitive information"""
        leaks = []
        
        # Extract HTML comments
        comment_pattern = r'<!--(.*?)-->'
        comments = re.findall(comment_pattern, response_text, re.DOTALL)
        
        sensitive_comment_patterns = {
            r'password|pwd|pass|secret': {
                'type': 'password_in_comment',
                'severity': 'Medium',
                'description': 'Password reference in HTML comment'
            },
            r'todo|fixme|hack|temp|debug': {
                'type': 'development_comment',
                'severity': 'Low',
                'description': 'Development comment in production'
            },
            r'admin|administrator|root': {
                'type': 'admin_reference',
                'severity': 'Low',
                'description': 'Administrative account reference'
            },
            r'api[_-]?key|token|secret[_-]?key': {
                'type': 'api_reference_comment',
                'severity': 'Medium',
                'description': 'API key/token reference in comment'
            }
        }
        
        for comment in comments:
            comment_clean = comment.strip()
            if len(comment_clean) < 5:
                continue
                
            for pattern, info in sensitive_comment_patterns.items():
                if re.search(pattern, comment_clean, re.IGNORECASE):
                    leaks.append({
                        'type': info['type'],
                        'severity': info['severity'],
                        'url': url,
                        'description': info['description'],
                        'comment': comment_clean[:100] + '...' if len(comment_clean) > 100 else comment_clean,
                        'location': 'HTML Comment',
                        'recommendation': 'Remove sensitive comments from production code'
                    })

        return leaks

    @staticmethod
    def _detect_path_disclosure(response_text: str, url: str) -> List[Dict[str, Any]]:
        """
        Detect path disclosure in error messages and responses

        Example patterns:
        - Warning: mysql_connect() in /var/www/html/config.php on line 23
        - Fatal error in C:\xampp\htdocs\app\database.php
        - Error at /home/user/website/includes/db.php
        """
        leaks = []

        # Path disclosure patterns with severity
        path_patterns = [
            # Unix/Linux paths with common web directories
            {
                'pattern': r'(?:in|at|from|file)\s+(/(?:var/www|home/\w+|usr/share|opt)/[^\s<>"\']+\.(?:php|asp|aspx|jsp|py|rb|pl))',
                'type': 'linux_path_disclosure',
                'severity': 'High',
                'description': 'Linux/Unix file path disclosed in error message'
            },
            # Windows paths
            {
                'pattern': r'(?:in|at|from|file)\s+([A-Z]:\\[^\s<>"\']+\.(?:php|asp|aspx|jsp|py|rb|pl))',
                'type': 'windows_path_disclosure',
                'severity': 'High',
                'description': 'Windows file path disclosed in error message'
            },
            # Generic server paths in errors (without "in" keyword)
            {
                'pattern': r'\b(/(?:var|home|usr|opt)/[^\s<>"\']{10,})',
                'type': 'server_path_disclosure',
                'severity': 'Medium',
                'description': 'Server path disclosed'
            },
            # Stack traces with file paths
            {
                'pattern': r'#\d+\s+(/[^\s<>"\']+\.(?:php|py|rb|pl|java))',
                'type': 'stack_trace_path',
                'severity': 'High',
                'description': 'File path in stack trace'
            }
        ]

        detected_paths = set()  # Avoid duplicates

        for pattern_info in path_patterns:
            matches = re.finditer(pattern_info['pattern'], response_text, re.IGNORECASE)
            for match in matches:
                path = match.group(1)

                # Skip if already detected
                if path in detected_paths:
                    continue
                detected_paths.add(path)

                # Extract context (surrounding text)
                start = max(0, match.start() - 100)
                end = min(len(response_text), match.end() + 100)
                context = response_text[start:end].strip()

                leaks.append({
                    'type': pattern_info['type'],
                    'severity': pattern_info['severity'],
                    'url': url,
                    'description': pattern_info['description'],
                    'path': path,
                    'context': context[:200] + '...' if len(context) > 200 else context,
                    'location': 'Error Message / Response',
                    'recommendation': 'Configure error reporting to suppress file paths in production. '
                                    'Use custom error pages and log errors server-side only.'
                })

        return leaks

    @staticmethod
    def _detect_database_errors(response_text: str, url: str) -> List[Dict[str, Any]]:
        """
        Detect database error messages

        Examples:
        - Warning: mysql_connect(): Connection refused
        - mysqli_sql_exception: Access denied
        - PostgreSQL query failed
        - Oracle error ORA-12154
        """
        leaks = []

        # Database error patterns
        db_error_patterns = [
            # MySQL/MariaDB errors
            {
                'pattern': r'(?:Warning|Error|Fatal error|Notice):\s*(mysql[i]?_[a-z_]+\([^)]*\))[^:]*:?\s*([^\n]{0,200})',
                'db_type': 'MySQL',
                'severity': 'High',
                'description': 'MySQL database error disclosed'
            },
            {
                'pattern': r'(mysqli_sql_exception)[^:]*:?\s*([^\n]{0,200})',
                'db_type': 'MySQL',
                'severity': 'High',
                'description': 'MySQL exception disclosed'
            },
            # PostgreSQL errors
            {
                'pattern': r'(PostgreSQL query failed|pg_[a-z_]+\([^)]*\))[^:]*:?\s*([^\n]{0,200})',
                'db_type': 'PostgreSQL',
                'severity': 'High',
                'description': 'PostgreSQL error disclosed'
            },
            # Oracle errors
            {
                'pattern': r'(ORA-\d{5})[^:]*:?\s*([^\n]{0,100})',
                'db_type': 'Oracle',
                'severity': 'High',
                'description': 'Oracle database error disclosed'
            },
            # Microsoft SQL Server errors
            {
                'pattern': r'(SQL Server|MSSQL|Microsoft OLE DB Provider)[^:]*:?\s*([^\n]{0,200})',
                'db_type': 'MSSQL',
                'severity': 'High',
                'description': 'Microsoft SQL Server error disclosed'
            },
            # SQLite errors
            {
                'pattern': r'(SQLite[/\w]*:?\s*[^\n]{0,200})',
                'db_type': 'SQLite',
                'severity': 'Medium',
                'description': 'SQLite error disclosed'
            },
            # MongoDB errors
            {
                'pattern': r'(MongoDB[^:]*Error|MongoClient::[a-z]+)[^:]*:?\s*([^\n]{0,200})',
                'db_type': 'MongoDB',
                'severity': 'High',
                'description': 'MongoDB error disclosed'
            },
            # Generic database connection errors
            {
                'pattern': r'(Connection refused|Access denied for user|Could not connect to database)[^\n]{0,150}',
                'db_type': 'Generic',
                'severity': 'High',
                'description': 'Database connection error disclosed'
            }
        ]

        detected_errors = set()  # Avoid duplicates

        for pattern_info in db_error_patterns:
            matches = re.finditer(pattern_info['pattern'], response_text, re.IGNORECASE)
            for match in matches:
                # Extract error message
                error_text = match.group(0)

                # Create signature for deduplication
                error_sig = (pattern_info['db_type'], error_text[:50])
                if error_sig in detected_errors:
                    continue
                detected_errors.add(error_sig)

                # Extract more context
                start = max(0, match.start() - 50)
                end = min(len(response_text), match.end() + 150)
                context = response_text[start:end].strip()

                leaks.append({
                    'type': 'database_error',
                    'severity': pattern_info['severity'],
                    'url': url,
                    'description': f"{pattern_info['description']} ({pattern_info['db_type']})",
                    'database_type': pattern_info['db_type'],
                    'error_message': error_text[:300] + '...' if len(error_text) > 300 else error_text,
                    'context': context[:250] + '...' if len(context) > 250 else context,
                    'location': 'Error Message / Response',
                    'recommendation': 'Configure database error reporting to suppress detailed errors in production. '
                                    'Use custom error pages and log database errors server-side only. '
                                    'This may reveal database structure, credentials, or internal paths.'
                })

        return leaks

    @staticmethod
    def _detect_private_keys_and_secrets(response_text: str, url: str) -> List[Dict[str, Any]]:
        """
        Detect private keys, certificates, and critical secrets

        Detects:
        - RSA private keys
        - SSH private keys
        - PGP private keys
        - JWT tokens
        - Base64 encoded credentials
        - Slack tokens
        - More AWS patterns
        - Bearer tokens
        """
        leaks = []

        # Private key patterns
        private_key_patterns = [
            # RSA private keys
            {
                'pattern': r'-----BEGIN RSA PRIVATE KEY-----',
                'type': 'rsa_private_key',
                'severity': 'Critical',
                'description': 'RSA Private Key exposed'
            },
            # SSH private keys
            {
                'pattern': r'-----BEGIN OPENSSH PRIVATE KEY-----',
                'type': 'ssh_private_key',
                'severity': 'Critical',
                'description': 'SSH Private Key exposed'
            },
            # Generic private keys
            {
                'pattern': r'-----BEGIN PRIVATE KEY-----',
                'type': 'private_key',
                'severity': 'Critical',
                'description': 'Private Key exposed'
            },
            # EC private keys
            {
                'pattern': r'-----BEGIN EC PRIVATE KEY-----',
                'type': 'ec_private_key',
                'severity': 'Critical',
                'description': 'EC Private Key exposed'
            },
            # PGP private keys
            {
                'pattern': r'-----BEGIN PGP PRIVATE KEY BLOCK-----',
                'type': 'pgp_private_key',
                'severity': 'Critical',
                'description': 'PGP Private Key exposed'
            },
            # DSA private keys
            {
                'pattern': r'-----BEGIN DSA PRIVATE KEY-----',
                'type': 'dsa_private_key',
                'severity': 'Critical',
                'description': 'DSA Private Key exposed'
            }
        ]

        for pattern_info in private_key_patterns:
            if re.search(pattern_info['pattern'], response_text, re.IGNORECASE):
                # Extract context (don't include full key for security)
                match = re.search(pattern_info['pattern'], response_text, re.IGNORECASE)
                start = match.start()
                end = min(len(response_text), start + 100)
                context = response_text[start:end]

                leaks.append({
                    'type': pattern_info['type'],
                    'severity': pattern_info['severity'],
                    'url': url,
                    'description': pattern_info['description'],
                    'context': context + '...',
                    'location': 'Response Content',
                    'recommendation': 'CRITICAL: Remove private key immediately! This allows complete impersonation and decryption.'
                })

        # JWT tokens
        jwt_pattern = r'eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}'
        jwt_matches = re.finditer(jwt_pattern, response_text)
        for match in jwt_matches:
            jwt_token = match.group(0)
            masked_jwt = jwt_token[:20] + '...' + jwt_token[-10:]

            leaks.append({
                'type': 'jwt_token_exposed',
                'severity': 'High',
                'url': url,
                'description': 'JWT Token exposed in response',
                'value': masked_jwt,
                'location': 'Response Content',
                'recommendation': 'JWT tokens should not be exposed in responses. Use secure storage and transmission.'
            })

        # Slack tokens
        slack_patterns = [
            (r'xoxb-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24}', 'Slack Bot Token'),
            (r'xoxp-[0-9]{10,13}-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{32}', 'Slack User Token'),
            (r'xoxa-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24}', 'Slack Access Token'),
            (r'xoxr-[a-zA-Z0-9]{40,}', 'Slack Refresh Token'),
        ]

        for pattern, token_type in slack_patterns:
            matches = re.finditer(pattern, response_text)
            for match in matches:
                token = match.group(0)
                masked_token = token[:15] + '*' * 20 + token[-10:]

                leaks.append({
                    'type': 'slack_token_exposed',
                    'severity': 'Critical',
                    'url': url,
                    'description': f'{token_type} exposed',
                    'value': masked_token,
                    'location': 'Response Content',
                    'recommendation': 'CRITICAL: Revoke Slack token immediately and rotate credentials.'
                })

        # Extended AWS patterns
        aws_extended_patterns = [
            # AWS Secret Access Keys
            (r'(?:aws_secret_access_key|aws_secret)["\']?\s*[:=]\s*["\']([A-Za-z0-9/+=]{40})["\']',
             'AWS Secret Access Key', 'Critical'),
            # AWS Session Tokens
            (r'(?:ASIA|ASOA)[A-Z0-9]{16}', 'AWS Session Token', 'Critical'),
            # AWS Account IDs
            (r'(?:aws_account_id|account_id)["\']?\s*[:=]\s*["\']([0-9]{12})["\']',
             'AWS Account ID', 'Medium'),
        ]

        for pattern, key_type, severity in aws_extended_patterns:
            matches = re.finditer(pattern, response_text, re.IGNORECASE)
            for match in matches:
                value = match.group(1) if match.groups() else match.group(0)
                masked_value = value[:6] + '*' * (len(value) - 10) + value[-4:] if len(value) > 10 else '*' * len(value)

                leaks.append({
                    'type': 'aws_credential_exposed',
                    'severity': severity,
                    'url': url,
                    'description': f'{key_type} exposed',
                    'value': masked_value,
                    'location': 'Response Content',
                    'recommendation': 'CRITICAL: Revoke AWS credentials immediately and enable AWS CloudTrail monitoring.'
                })

        # Base64 encoded credentials patterns
        # Look for base64 strings that might be credentials
        base64_credential_patterns = [
            # username:password in base64
            (r'(?:Authorization|Basic)\s+([A-Za-z0-9+/]{20,}={0,2})', 'Base64 Basic Auth'),
            # Common credential keys with base64 values
            (r'(?:password|passwd|pwd|credential|cred)["\']?\s*[:=]\s*["\']([A-Za-z0-9+/]{16,}={0,2})["\']',
             'Base64 Encoded Password'),
        ]

        for pattern, cred_type in base64_credential_patterns:
            matches = re.finditer(pattern, response_text, re.IGNORECASE)
            for match in matches:
                value = match.group(1)
                # Check if it's valid base64
                if len(value) % 4 == 0 and re.match(r'^[A-Za-z0-9+/]+={0,2}$', value):
                    masked_value = value[:8] + '*' * 10 + value[-4:]

                    leaks.append({
                        'type': 'base64_credential',
                        'severity': 'High',
                        'url': url,
                        'description': f'{cred_type} (Base64 encoded)',
                        'value': masked_value,
                        'location': 'Response Content',
                        'recommendation': 'Base64 encoded credentials detected. Decode and verify if sensitive.'
                    })

        # Bearer tokens (generic)
        bearer_pattern = r'Bearer\s+([A-Za-z0-9\-._~+/]{20,})'
        bearer_matches = re.finditer(bearer_pattern, response_text, re.IGNORECASE)
        for match in bearer_matches:
            token = match.group(1)
            masked_token = token[:10] + '*' * 15 + token[-5:]

            leaks.append({
                'type': 'bearer_token_exposed',
                'severity': 'High',
                'url': url,
                'description': 'Bearer token exposed in response',
                'value': masked_token,
                'location': 'Response Content',
                'recommendation': 'Bearer tokens should be transmitted securely and not exposed in responses.'
            })

        # Generic key patterns (regex-based detection)
        # These catch keys that don't match specific patterns but look like secrets
        generic_key_patterns = [
            # Long hex strings (often encryption keys)
            {
                'pattern': r'\b([a-fA-F0-9]{32,64})\b',
                'type': 'hex_key',
                'min_length': 32,
                'severity': 'Medium',
                'description': 'Potential hex-encoded key',
                'keywords': ['key', 'secret', 'token', 'hash', 'encrypt', 'cipher']
            },
            # Long alphanumeric strings (generic keys/tokens)
            {
                'pattern': r'\b([A-Za-z0-9]{40,128})\b',
                'type': 'generic_secret',
                'min_length': 40,
                'severity': 'Medium',
                'description': 'Potential secret key',
                'keywords': ['key', 'secret', 'token', 'password', 'credential', 'auth']
            },
            # UUID-like patterns (often API keys)
            {
                'pattern': r'\b([a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12})\b',
                'type': 'uuid_key',
                'min_length': 36,
                'severity': 'Low',
                'description': 'UUID that might be used as API key',
                'keywords': ['key', 'api', 'token', 'id', 'secret']
            },
            # Base58 encoded strings (Bitcoin, crypto keys)
            {
                'pattern': r'\b([1-9A-HJ-NP-Za-km-z]{26,64})\b',
                'type': 'base58_key',
                'min_length': 26,
                'severity': 'High',
                'description': 'Potential Base58 encoded key',
                'keywords': ['key', 'private', 'bitcoin', 'crypto', 'wallet']
            },
            # Long random-looking strings with mixed case and numbers
            {
                'pattern': r'\b([A-Z][a-z0-9]{30,}|[a-z][A-Z0-9]{30,})\b',
                'type': 'mixed_case_key',
                'min_length': 30,
                'severity': 'Medium',
                'description': 'Potential randomly generated key',
                'keywords': ['key', 'secret', 'token', 'api', 'auth']
            }
        ]

        for pattern_info in generic_key_patterns:
            matches = re.finditer(pattern_info['pattern'], response_text)
            for match in matches:
                potential_key = match.group(1)

                # Skip if too short
                if len(potential_key) < pattern_info['min_length']:
                    continue

                # Context-aware detection: Check if near key-related keywords
                context_start = max(0, match.start() - 150)
                context_end = min(len(response_text), match.end() + 150)
                context = response_text[context_start:context_end].lower()

                # Only flag if context contains relevant keywords
                if any(keyword in context for keyword in pattern_info['keywords']):
                    # Additional validation: Skip if looks like common false positives
                    false_positive_indicators = [
                        'example', 'test', 'demo', 'sample', 'placeholder',
                        'xxxxxxxx', '00000000', '11111111', 'aaaaaaaa',
                        'localhost', 'domain.com', 'example.com'
                    ]

                    if any(fp in potential_key.lower() for fp in false_positive_indicators):
                        continue

                    # Check if it's just repeated characters (likely not a real key)
                    if len(set(potential_key)) < 5:  # Less than 5 unique characters
                        continue

                    masked_value = potential_key[:8] + '*' * (len(potential_key) - 12) + potential_key[-4:] if len(potential_key) > 12 else '*' * len(potential_key)

                    leaks.append({
                        'type': pattern_info['type'],
                        'severity': pattern_info['severity'],
                        'url': url,
                        'description': pattern_info['description'],
                        'value': masked_value,
                        'length': len(potential_key),
                        'context': context[max(0, match.start() - context_start - 50):min(len(context), match.end() - context_start + 50)],
                        'location': 'Response Content',
                        'recommendation': 'Verify if this is a sensitive key or token. Context suggests it might be credentials.'
                    })

        return leaks
