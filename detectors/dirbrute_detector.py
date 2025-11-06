"""
Directory and file bruteforce detector
"""

import re
from typing import Tuple, List, Dict, Any

class DirBruteDetector:
    """Directory bruteforce detection logic"""
    
    @staticmethod
    def is_valid_response(response_text: str, response_code: int, content_length: int) -> Tuple[bool, str]:
        """
        Check if response indicates a valid directory/file
        Returns (is_valid, evidence)
        """
        # Success codes
        if response_code in [200, 201, 202, 203, 206]:
            return True, f"HTTP {response_code} - Resource found"
        
        # Redirect codes (might indicate valid resource)
        if response_code in [301, 302, 303, 307, 308]:
            return True, f"HTTP {response_code} - Redirect found"
        
        # Forbidden (resource exists but access denied)
        if response_code == 403:
            return True, f"HTTP 403 - Forbidden (resource exists)"
        
        # Method not allowed (resource exists)
        if response_code == 405:
            return True, f"HTTP 405 - Method not allowed (resource exists)"
        
        return False, f"HTTP {response_code} - Resource not found"
    
    @staticmethod
    def detect_directory_listing(response_text: str) -> bool:
        """Detect if response contains directory listing"""
        directory_indicators = [
            'Index of /',
            'Directory Listing',
            'Parent Directory',
            '<title>Index of',
            'Directory listing for',
            '[To Parent Directory]',
            'folder.gif',
            'dir.gif'
        ]
        
        response_lower = response_text.lower()
        return any(indicator.lower() in response_lower for indicator in directory_indicators)
    
    @staticmethod
    def detect_sensitive_file(response_text: str, file_path: str) -> Tuple[bool, str]:
        """Detect if file contains sensitive information"""
        sensitive_patterns = {
            'database_config': [
                r'mysql_connect', r'mysqli_connect', r'PDO', r'database',
                r'DB_HOST', r'DB_USER', r'DB_PASS', r'DB_NAME'
            ],
            'credentials': [
                r'password\s*=', r'passwd\s*=', r'pwd\s*=',
                r'username\s*=', r'user\s*=', r'login\s*='
            ],
            'api_keys': [
                r'api_key', r'apikey', r'secret_key', r'access_token',
                r'private_key', r'public_key'
            ],
            'system_info': [
                r'phpinfo\(\)', r'system\(', r'exec\(', r'shell_exec\(',
                r'passthru\(', r'eval\('
            ]
        }
        
        response_lower = response_text.lower()
        found_patterns = []
        
        for category, patterns in sensitive_patterns.items():
            for pattern in patterns:
                if re.search(pattern, response_lower, re.IGNORECASE):
                    found_patterns.append(f"{category}: {pattern}")
        
        if found_patterns:
            evidence = f"Sensitive content detected: {', '.join(found_patterns)}"
            return True, evidence
        
        return False, "No sensitive content detected"
    
    @staticmethod
    def get_response_snippet(response_text: str, max_length: int = 300) -> str:
        """Get relevant response snippet"""
        if len(response_text) > max_length:
            return response_text[:max_length] + "..."
        return response_text
    
    @staticmethod
    def analyze_response_size(content_length: int, baseline_size: int = 0) -> str:
        """Analyze response size for anomalies"""
        if baseline_size > 0:
            size_diff = abs(content_length - baseline_size)
            if size_diff > 100:  # Significant difference
                return f"Size anomaly detected: {content_length} bytes (baseline: {baseline_size})"
        
        if content_length == 0:
            return "Empty response"
        elif content_length < 100:
            return f"Small response: {content_length} bytes"
        elif content_length > 10000:
            return f"Large response: {content_length} bytes"
        
        return f"Normal response: {content_length} bytes"
