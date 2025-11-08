"""
Information Disclosure vulnerability detector
Detects sensitive information leaks and directory listings
"""

import re
from typing import List, Dict, Any, Tuple

class InformationDisclosureDetector:
    """Information Disclosure vulnerability detection logic"""
    
    @staticmethod
    def get_sensitive_files() -> List[str]:
        """Get list of sensitive files to check"""
        return [
            # Configuration files
            '.htaccess',
            'web.config',
            'config.php',
            'database.php',
            'settings.php',
            'wp-config.php',
            
            # Backup files
            'index.zip',
            'backup.zip',
            'site.zip',
            'www.zip',
            'database.sql',
            'dump.sql',
            
            # Development files
            '.git/config',
            '.svn/entries',
            'CVS/Root',
            '.idea/workspace.xml',
            'composer.json',
            'package.json',
            
            # System files
            'phpinfo.php',
            'info.php',
            'test.php',
            'crossdomain.xml',
            'robots.txt',
            'sitemap.xml'
        ]
    
    @staticmethod
    def get_directory_listing_indicators() -> List[str]:
        """Get directory listing indicators"""
        return [
            'Index of /',
            'Directory Listing',
            'Parent Directory',
            '[DIR]',
            '[   ]',
            'Last modified',
            'Size',
            'Description',
            '<title>Index of',
            'Apache/2.',
            'nginx/1.'
        ]
    
    @staticmethod
    def get_sensitive_info_patterns() -> Dict[str, List[str]]:
        """Get patterns for sensitive information"""
        return {
            'email_addresses': [
                r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
            ],
            'ip_addresses': [
                r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b',
                r'\b127\.0\.0\.1\b'
            ],
            'database_credentials': [
                r'mysql://[^:]+:[^@]+@[^/]+',
                r'postgresql://[^:]+:[^@]+@[^/]+',
                r'DB_PASSWORD\s*=\s*["\']([^"\']+)["\']',
                r'DB_USER\s*=\s*["\']([^"\']+)["\']'
            ],
            'api_keys': [
                r'api[_-]?key["\s]*[:=]["\s]*([a-zA-Z0-9]{20,})',
                r'secret[_-]?key["\s]*[:=]["\s]*([a-zA-Z0-9]{20,})',
                r'access[_-]?token["\s]*[:=]["\s]*([a-zA-Z0-9]{20,})'
            ],
            'file_paths': [
                r'[C-Z]:\\[^"\s<>|]{10,}',
                r'/(?:home|root|etc|var|usr)/[^"\s<>|]{5,}'
            ]
        }
    
    @staticmethod
    def detect_directory_listing(response_text: str, response_code: int, url: str) -> Tuple[bool, str, str, Dict[str, Any]]:
        """Detect directory listing vulnerabilities"""
        if response_code != 200:
            return False, "", "", {}
        
        indicators = InformationDisclosureDetector.get_directory_listing_indicators()
        found_indicators = []
        
        for indicator in indicators:
            if indicator in response_text:
                found_indicators.append(indicator)
        
        if len(found_indicators) >= 2:
            return True, f"Directory listing detected. Indicators: {', '.join(found_indicators[:3])}", "Medium", {
                'cwe': 'CWE-200',
                'cvss': '5.3',
                'owasp': 'A01:2021 – Broken Access Control',
                'recommendation': 'Disable directory listing in web server configuration.'
            }
        
        return False, "", "", {}
    
    @staticmethod
    def detect_sensitive_file_exposure(response_text: str, response_code: int, url: str) -> Tuple[bool, str, str, Dict[str, Any]]:
        """Detect sensitive file exposure"""
        if response_code != 200:
            return False, "", "", {}
        
        sensitive_files = InformationDisclosureDetector.get_sensitive_files()
        
        # Check if URL contains sensitive file
        for sensitive_file in sensitive_files:
            if sensitive_file.lower() in url.lower():
                # Check if file content is actually exposed
                if len(response_text) > 100:  # Not empty response
                    severity = "High"
                    cvss = "7.5"
                    
                    # Critical files get higher severity
                    critical_files = ['config.php', 'wp-config.php', 'database.php', '.htaccess']
                    if any(critical in sensitive_file.lower() for critical in critical_files):
                        severity = "Critical"
                        cvss = "9.1"
                    
                    return True, f"Sensitive file exposed: {sensitive_file}", severity, {
                        'cwe': 'CWE-200',
                        'cvss': cvss,
                        'owasp': 'A01:2021 – Broken Access Control',
                        'recommendation': 'Restrict access to sensitive files and directories.'
                    }
        
        return False, "", "", {}
    
    @staticmethod
    def detect_information_leakage(response_text: str, response_code: int, url: str) -> Tuple[bool, str, str, Dict[str, Any]]:
        """Detect information leakage in responses"""
        if response_code != 200:
            return False, "", "", {}
        
        patterns = InformationDisclosureDetector.get_sensitive_info_patterns()
        found_info = {}
        
        for info_type, pattern_list in patterns.items():
            for pattern in pattern_list:
                matches = re.findall(pattern, response_text, re.IGNORECASE)
                if matches:
                    found_info[info_type] = matches[:5]  # Limit to first 5 matches
        
        if found_info:
            info_types = list(found_info.keys())
            evidence = f"Information leakage detected: {', '.join(info_types)}"
            
            # Determine severity based on type of information
            severity = "Low"
            cvss = "3.7"
            
            if 'database_credentials' in found_info or 'api_keys' in found_info:
                severity = "Critical"
                cvss = "9.1"
            elif 'email_addresses' in found_info or 'ip_addresses' in found_info:
                severity = "Medium"
                cvss = "5.3"
            
            return True, evidence, severity, {
                'cwe': 'CWE-200',
                'cvss': cvss,
                'owasp': 'A01:2021 – Broken Access Control',
                'recommendation': 'Remove sensitive information from public responses. Implement proper access controls.'
            }
        
        return False, "", "", {}
    
    @staticmethod
    def get_sensitive_file_payloads() -> List[str]:
        """Get sensitive file test payloads"""
        return [
            # Common sensitive files
            '/.htaccess',
            '/web.config',
            '/config.php',
            '/wp-config.php',
            '/database.php',
            '/settings.php',
            
            # Backup files
            '/index.zip',
            '/backup.zip',
            '/site.zip',
            '/www.zip',
            '/database.sql',
            '/dump.sql',
            
            # Development files
            '/.git/config',
            '/.svn/entries',
            '/CVS/Root',
            '/.idea/workspace.xml',
            '/composer.json',
            '/package.json',
            
            # Info disclosure
            '/phpinfo.php',
            '/info.php',
            '/test.php',
            '/crossdomain.xml'
        ]
