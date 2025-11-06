"""
LFI vulnerability detector
"""

class LFIDetector:
    """LFI vulnerability detection logic"""
    
    @staticmethod
    def get_linux_patterns():
        """Get Linux file content patterns"""
        return [
            "root:x:0:0:",
            "daemon:x:1:1:",
            "bin:x:2:2:",
            "sys:x:3:3:",
            "sync:x:4:65534:",
            "games:x:5:60:",
            "man:x:6:12:",
            "lp:x:7:7:",
            "mail:x:8:8:",
            "news:x:9:9:",
            "uucp:x:10:10:",
            "proxy:x:13:13:",
            "www-data:x:33:33:",
            "backup:x:34:34:",
            "list:x:38:38:",
            "irc:x:39:39:",
            "gnats:x:41:41:",
            "nobody:x:65534:65534:",
            "systemd-network:x:",
            "systemd-resolve:x:"
        ]
    
    @staticmethod
    def get_windows_patterns():
        """Get Windows file content patterns"""
        return [
            "# Copyright (c) 1993-2009 Microsoft Corp.",
            "# This is a sample HOSTS file used by Microsoft TCP/IP for Windows.",
            "127.0.0.1       localhost",
            "::1             localhost",
            "[fonts]",
            "[extensions]",
            "[mci extensions]",
            "[files]",
            "[Mail]",
            "MAPI=1"
        ]
    
    @staticmethod
    def detect_lfi(response_text: str, response_code: int) -> tuple:
        """Detect LFI vulnerability"""
        if response_code != 200:
            return False, None
        
        # Check response length - very short responses are likely not file contents
        if len(response_text.strip()) < 50:
            return False, None
            
        linux_patterns = LFIDetector.get_linux_patterns()
        windows_patterns = LFIDetector.get_windows_patterns()
        
        found_linux = 0
        found_windows = 0
        matched_pattern = None
        
        # Count Linux patterns
        for pattern in linux_patterns:
            if pattern in response_text:
                found_linux += 1
                if not matched_pattern:
                    matched_pattern = pattern
        
        # Count Windows patterns  
        for pattern in windows_patterns:
            if pattern in response_text:
                found_windows += 1
                if not matched_pattern:
                    matched_pattern = pattern
        
        # Require multiple patterns for Linux /etc/passwd (more reliable)
        if found_linux >= 3:
            return True, matched_pattern
        
        # Windows patterns are more unique, so 1 is enough
        if found_windows >= 1:
            return True, matched_pattern
        
        return False, None
    
    @staticmethod
    def get_evidence(pattern: str) -> str:
        """Get evidence of LFI vulnerability"""
        return f"File content pattern found: {pattern}"
    
    @staticmethod
    def get_response_snippet(pattern: str, response_text: str) -> str:
        """Get response snippet showing file content context"""
        if pattern in response_text:
            start_pos = response_text.find(pattern)
            context_start = max(0, start_pos - 40)
            context_end = min(len(response_text), start_pos + len(pattern) + 40)
            return response_text[context_start:context_end]
        return "File pattern not found in response"
