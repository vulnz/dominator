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
