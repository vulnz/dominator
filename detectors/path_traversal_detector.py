"""
Path Traversal vulnerability detection logic (different from directory traversal)
"""

import re
from typing import Tuple, List, Dict, Any

class PathTraversalDetector:
    """Path Traversal vulnerability detection logic"""
    
    @staticmethod
    def get_path_indicators() -> List[str]:
        """Get path traversal indicators"""
        return [
            '/etc/passwd', '/etc/shadow', '/etc/hosts',
            '/proc/version', '/proc/self/environ',
            'C:\\Windows\\System32', 'C:\\boot.ini',
            'C:\\Windows\\win.ini', 'C:\\autoexec.bat',
            'root:x:0:0', 'daemon:x:1:1',
            '[boot loader]', '[operating systems]',
            'Microsoft Windows', 'WINDOWS',
            'for 16-bit app support'
        ]
    
    @staticmethod
    def detect_path_traversal(response_text: str, response_code: int, payload: str) -> bool:
        """
        Detect path traversal vulnerability
        Returns True if path traversal is detected
        """
        if response_code >= 500:
            return False
        
        response_lower = response_text.lower()
        indicators = PathTraversalDetector.get_path_indicators()
        
        # Check for file content indicators
        for indicator in indicators:
            if indicator.lower() in response_lower:
                return True
        
        # Check for specific file patterns
        file_patterns = [
            r'root:x:\d+:\d+:',  # /etc/passwd format
            r'\[boot loader\]',   # boot.ini format
            r'# /etc/hosts',      # hosts file comment
            r'Linux version \d+', # /proc/version
        ]
        
        for pattern in file_patterns:
            if re.search(pattern, response_text, re.IGNORECASE):
                return True
        
        return False
    
    @staticmethod
    def get_evidence(payload: str, response_text: str) -> str:
        """Get evidence of path traversal vulnerability"""
        indicators = PathTraversalDetector.get_path_indicators()
        found_indicators = []
        
        response_lower = response_text.lower()
        for indicator in indicators:
            if indicator.lower() in response_lower:
                found_indicators.append(indicator)
        
        if found_indicators:
            return f"Path traversal detected. Accessed files: {', '.join(found_indicators[:3])}"
        
        return "Path traversal vulnerability detected based on file content patterns"
    
    @staticmethod
    def get_response_snippet(payload: str, response_text: str) -> str:
        """Get relevant response snippet"""
        indicators = PathTraversalDetector.get_path_indicators()
        
        for indicator in indicators:
            if indicator.lower() in response_text.lower():
                start = max(0, response_text.lower().find(indicator.lower()) - 30)
                end = min(len(response_text), start + 150)
                return response_text[start:end]
        
        return response_text[:200]
    
    @staticmethod
    def get_remediation_advice() -> str:
        """Get remediation advice for path traversal vulnerabilities"""
        return (
            "Validate and sanitize all file path inputs. "
            "Use whitelist-based validation for allowed file paths. "
            "Implement proper access controls and chroot jails. "
            "Avoid direct file system access based on user input."
        )
