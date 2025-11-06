"""
Directory traversal vulnerability detector
"""

import re
from typing import Tuple, List, Dict, Any

class DirectoryTraversalDetector:
    """Directory traversal vulnerability detection logic"""
    
    @staticmethod
    def detect_directory_traversal(response_text: str, response_code: int, payload: str) -> bool:
        """
        Detect directory traversal vulnerability
        Returns True if vulnerability is detected
        """
        if response_code != 200:
            return False
        
        # Check for common file content patterns that indicate successful traversal
        traversal_indicators = DirectoryTraversalDetector.get_traversal_indicators()
        
        response_lower = response_text.lower()
        found_indicators = []
        
        for indicator in traversal_indicators:
            if indicator['pattern'].lower() in response_lower:
                found_indicators.append(indicator)
        
        # Need at least one strong indicator
        return len(found_indicators) > 0
    
    @staticmethod
    def get_traversal_indicators() -> List[Dict[str, str]]:
        """Get indicators that suggest successful directory traversal"""
        return [
            # Linux/Unix system files
            {'pattern': 'root:x:0:0:', 'description': 'Linux /etc/passwd file'},
            {'pattern': 'daemon:x:1:1:', 'description': 'Linux /etc/passwd file'},
            {'pattern': 'bin:x:2:2:', 'description': 'Linux /etc/passwd file'},
            {'pattern': 'sys:x:3:3:', 'description': 'Linux /etc/passwd file'},
            {'pattern': 'nobody:x:', 'description': 'Linux /etc/passwd file'},
            {'pattern': '[boot loader]', 'description': 'Windows boot.ini file'},
            {'pattern': 'operating systems', 'description': 'Windows boot.ini file'},
            {'pattern': 'multi(0)disk(0)', 'description': 'Windows boot.ini file'},
            
            # Windows system files
            {'pattern': '[version]', 'description': 'Windows system file'},
            {'pattern': 'signature="$chicago$"', 'description': 'Windows system file'},
            {'pattern': '[autorun]', 'description': 'Windows autorun.inf'},
            {'pattern': 'shellexecute=', 'description': 'Windows autorun.inf'},
            
            # Configuration files
            {'pattern': '[mysqld]', 'description': 'MySQL configuration'},
            {'pattern': 'datadir=', 'description': 'MySQL configuration'},
            {'pattern': 'bind-address=', 'description': 'MySQL configuration'},
            {'pattern': 'ServerRoot', 'description': 'Apache configuration'},
            {'pattern': 'DocumentRoot', 'description': 'Apache configuration'},
            {'pattern': 'LoadModule', 'description': 'Apache configuration'},
            
            # Log files
            {'pattern': 'access_log', 'description': 'Apache access log'},
            {'pattern': 'error_log', 'description': 'Apache error log'},
            {'pattern': 'GET /', 'description': 'HTTP access log'},
            {'pattern': 'POST /', 'description': 'HTTP access log'},
            {'pattern': '[error]', 'description': 'Error log file'},
            {'pattern': '[warn]', 'description': 'Warning log file'},
            
            # Source code files
            {'pattern': '<?php', 'description': 'PHP source code'},
            {'pattern': 'mysql_connect', 'description': 'PHP database code'},
            {'pattern': 'mysqli_connect', 'description': 'PHP database code'},
            {'pattern': '$_GET', 'description': 'PHP source code'},
            {'pattern': '$_POST', 'description': 'PHP source code'},
            {'pattern': 'include_once', 'description': 'PHP include'},
            {'pattern': 'require_once', 'description': 'PHP require'},
        ]
    
    @staticmethod
    def get_evidence(payload: str, response_text: str) -> str:
        """Get evidence for directory traversal"""
        indicators = DirectoryTraversalDetector.get_traversal_indicators()
        response_lower = response_text.lower()
        
        found_indicators = []
        for indicator in indicators:
            if indicator['pattern'].lower() in response_lower:
                found_indicators.append(indicator['description'])
        
        if found_indicators:
            return f"Directory traversal successful with payload '{payload}'. Found: {', '.join(found_indicators[:3])}"
        
        return f"Directory traversal detected with payload '{payload}'"
    
    @staticmethod
    def get_response_snippet(payload: str, response_text: str) -> str:
        """Get relevant response snippet"""
        indicators = DirectoryTraversalDetector.get_traversal_indicators()
        response_lower = response_text.lower()
        
        # Find the first matching indicator and return surrounding context
        for indicator in indicators:
            pattern = indicator['pattern'].lower()
            if pattern in response_lower:
                start_pos = response_lower.find(pattern)
                # Get 200 characters around the match
                snippet_start = max(0, start_pos - 100)
                snippet_end = min(len(response_text), start_pos + len(pattern) + 100)
                return response_text[snippet_start:snippet_end]
        
        # Fallback: return first 300 characters
        return response_text[:300] + "..." if len(response_text) > 300 else response_text
