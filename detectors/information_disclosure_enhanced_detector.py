"""
Enhanced Information Disclosure detector for testphp.vulnweb.com
Detects sensitive information leakage with improved accuracy
"""

import re
from typing import List, Dict, Tuple, Any

class InformationDisclosureEnhancedDetector:
    """Enhanced Information Disclosure vulnerability detection logic"""
    
    @staticmethod
    def detect_information_disclosure(response_text: str, response_code: int, url: str) -> Tuple[bool, List[Dict[str, Any]]]:
        """
        Enhanced information disclosure detection
        
        Args:
            response_text: HTTP response content
            response_code: HTTP response status code
            url: Request URL
            
        Returns:
            Tuple[bool, List[Dict]]: (found_disclosures, list_of_disclosures)
        """
        disclosures = []
        
        # Email addresses (confirmed in testphp.vulnweb.com)
        email_patterns = [
            r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',
            r'wvs@acunetix\.com',
            r'test@gmail\.com',
            r'wasp@acunetix\.com',
        ]
        
        for pattern in email_patterns:
            matches = re.findall(pattern, response_text, re.IGNORECASE)
            for match in matches:
                disclosures.append({
                    'type': 'email_disclosure',
                    'value': match,
                    'severity': 'Low',
                    'description': f'Email address disclosed: {match}',
                    'pattern': pattern
                })
        
        # Internal IP addresses (confirmed in testphp.vulnweb.com)
        ip_patterns = [
            r'\b127\.0\.0\.1\b',
            r'\bhttp://127\.0\.0\.1\b',
            r'\b192\.168\.\d{1,3}\.\d{1,3}\b',
            r'\b10\.\d{1,3}\.\d{1,3}\.\d{1,3}\b',
            r'\b172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}\b',
        ]
        
        for pattern in ip_patterns:
            matches = re.findall(pattern, response_text)
            for match in matches:
                disclosures.append({
                    'type': 'internal_ip_disclosure',
                    'value': match,
                    'severity': 'Medium',
                    'description': f'Internal IP address disclosed: {match}',
                    'pattern': pattern
                })
        
        # Database connection strings
        db_patterns = [
            r'mysql_connect\s*\(\s*["\']([^"\']+)["\']',
            r'mysqli_connect\s*\(\s*["\']([^"\']+)["\']',
            r'host\s*=\s*["\']?([^"\';\s]+)["\']?',
            r'database\s*=\s*["\']?([^"\';\s]+)["\']?',
            r'username\s*=\s*["\']?([^"\';\s]+)["\']?',
            r'password\s*=\s*["\']?([^"\';\s]+)["\']?',
        ]
        
        for pattern in db_patterns:
            matches = re.findall(pattern, response_text, re.IGNORECASE)
            for match in matches:
                disclosures.append({
                    'type': 'database_info_disclosure',
                    'value': match,
                    'severity': 'High',
                    'description': f'Database connection information disclosed: {match}',
                    'pattern': pattern
                })
        
        # File paths and system information
        path_patterns = [
            r'[A-Za-z]:\\[^<>\s"]+',  # Windows paths
            r'/[a-zA-Z0-9_/.-]+\.php',  # PHP file paths
            r'/var/www/[^<>\s"]+',  # Web root paths
            r'/etc/[^<>\s"]+',  # System config paths
            r'/home/[^<>\s"]+',  # Home directory paths
        ]
        
        for pattern in path_patterns:
            matches = re.findall(pattern, response_text)
            for match in matches:
                if len(match) > 10:  # Filter out short matches
                    disclosures.append({
                        'type': 'path_disclosure',
                        'value': match,
                        'severity': 'Low',
                        'description': f'File path disclosed: {match}',
                        'pattern': pattern
                    })
        
        # PHP errors and debug information
        error_patterns = [
            r'Fatal error:.*in\s+([^\s]+)\s+on line\s+(\d+)',
            r'Warning:.*in\s+([^\s]+)\s+on line\s+(\d+)',
            r'Notice:.*in\s+([^\s]+)\s+on line\s+(\d+)',
            r'Parse error:.*in\s+([^\s]+)\s+on line\s+(\d+)',
            r'Call to undefined function.*in\s+([^\s]+)',
        ]
        
        for pattern in error_patterns:
            matches = re.findall(pattern, response_text, re.IGNORECASE)
            for match in matches:
                if isinstance(match, tuple):
                    file_path = match[0] if len(match) > 0 else 'unknown'
                    line_num = match[1] if len(match) > 1 else 'unknown'
                    value = f"{file_path}:{line_num}"
                else:
                    value = str(match)
                
                disclosures.append({
                    'type': 'error_disclosure',
                    'value': value,
                    'severity': 'Medium',
                    'description': f'PHP error disclosed file path: {value}',
                    'pattern': pattern
                })
        
        # Version information
        version_patterns = [
            r'PHP/(\d+\.\d+\.\d+)',
            r'Apache/(\d+\.\d+\.\d+)',
            r'MySQL\s+(\d+\.\d+\.\d+)',
            r'Server:\s*([^\r\n]+)',
            r'X-Powered-By:\s*([^\r\n]+)',
        ]
        
        for pattern in version_patterns:
            matches = re.findall(pattern, response_text, re.IGNORECASE)
            for match in matches:
                disclosures.append({
                    'type': 'version_disclosure',
                    'value': match,
                    'severity': 'Low',
                    'description': f'Software version disclosed: {match}',
                    'pattern': pattern
                })
        
        # Comments with sensitive information
        comment_patterns = [
            r'<!--.*?(?:password|user|admin|key|secret|token).*?-->',
            r'//.*?(?:password|user|admin|key|secret|token).*',
            r'/\*.*?(?:password|user|admin|key|secret|token).*?\*/',
        ]
        
        for pattern in comment_patterns:
            matches = re.findall(pattern, response_text, re.IGNORECASE | re.DOTALL)
            for match in matches:
                disclosures.append({
                    'type': 'comment_disclosure',
                    'value': match[:100] + '...' if len(match) > 100 else match,
                    'severity': 'Medium',
                    'description': f'Sensitive information in comment: {match[:50]}...',
                    'pattern': pattern
                })
        
        # Directory listings
        if InformationDisclosureEnhancedDetector._is_directory_listing(response_text):
            disclosures.append({
                'type': 'directory_listing',
                'value': url,
                'severity': 'Medium',
                'description': 'Directory listing enabled',
                'pattern': 'directory_listing_detection'
            })
        
        # Backup files indicators
        backup_indicators = [
            r'\.bak\b',
            r'\.backup\b',
            r'\.old\b',
            r'\.orig\b',
            r'\.tmp\b',
            r'~$',
            r'\.zip\b',
            r'\.tar\.gz\b',
        ]
        
        for pattern in backup_indicators:
            if re.search(pattern, response_text, re.IGNORECASE):
                disclosures.append({
                    'type': 'backup_file_disclosure',
                    'value': pattern,
                    'severity': 'Medium',
                    'description': f'Potential backup file pattern found: {pattern}',
                    'pattern': pattern
                })
        
        return len(disclosures) > 0, disclosures
    
    @staticmethod
    def _is_directory_listing(response_text: str) -> bool:
        """Check if response contains directory listing"""
        directory_indicators = [
            'Index of /',
            'Directory Listing',
            'Parent Directory',
            '<title>Index of',
            'Last modified</th>',
            'Size</th>',
            '[DIR]',
            '[   ]',
        ]
        
        return any(indicator in response_text for indicator in directory_indicators)
    
    @staticmethod
    def get_evidence(disclosures: List[Dict[str, Any]]) -> str:
        """Get detailed evidence for information disclosure"""
        if not disclosures:
            return "No information disclosure detected"
        
        evidence = f"Information disclosure detected ({len(disclosures)} items):\n"
        
        # Group by type
        by_type = {}
        for disclosure in disclosures:
            disc_type = disclosure['type']
            if disc_type not in by_type:
                by_type[disc_type] = []
            by_type[disc_type].append(disclosure)
        
        for disc_type, items in by_type.items():
            evidence += f"\n{disc_type.replace('_', ' ').title()}:\n"
            for item in items[:3]:  # Show first 3 items of each type
                evidence += f"  - {item['description']}\n"
            if len(items) > 3:
                evidence += f"  - ... and {len(items) - 3} more\n"
        
        return evidence
    
    @staticmethod
    def get_response_snippet(disclosures: List[Dict[str, Any]], response_text: str) -> str:
        """Get response snippet highlighting disclosures"""
        if not disclosures:
            return response_text[:200] + "..." if len(response_text) > 200 else response_text
        
        # Show first few disclosure values
        snippet = "Disclosed information: "
        values = [d['value'] for d in disclosures[:5]]
        snippet += ", ".join(values)
        
        if len(disclosures) > 5:
            snippet += f" and {len(disclosures) - 5} more items"
        
        return snippet
    
    @staticmethod
    def get_remediation_advice() -> str:
        """Get remediation advice for information disclosure"""
        return (
            "1. Remove or obfuscate sensitive information from responses\n"
            "2. Disable directory listings\n"
            "3. Remove debug/error information from production\n"
            "4. Clean up comments containing sensitive data\n"
            "5. Implement proper error handling\n"
            "6. Remove backup files from web directories\n"
            "7. Configure web server to hide version information"
        )
