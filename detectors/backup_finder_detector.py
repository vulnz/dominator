"""
Backup files finder detector
"""

import re
from typing import Tuple, List

class BackupFinderDetector:
    """Backup files detection logic"""
    
    @staticmethod
    def get_backup_extensions() -> list:
        """Get common backup file extensions"""
        return [
            '.bak', '.backup', '.old', '.orig', '.copy', '.tmp', '.temp',
            '.save', '.swp', '.swo', '.~', '.bkp', '.back', '.archive',
            '.1', '.2', '.3', '.001', '.002', '.003', '.zip', '.tar',
            '.tar.gz', '.rar', '.7z', '.sql', '.dump', '.db'
        ]
    
    @staticmethod
    def get_backup_patterns() -> list:
        """Get backup file naming patterns"""
        return [
            r'\.bak$', r'\.backup$', r'\.old$', r'\.orig$', r'\.copy$',
            r'\.tmp$', r'\.temp$', r'\.save$', r'\.swp$', r'\.swo$',
            r'~$', r'\.bkp$', r'\.back$', r'\.archive$',
            r'\.\d+$', r'\.00\d$', r'_backup\.',  r'_bak\.',
            r'_old\.', r'_copy\.', r'_orig\.', r'backup_',
            r'old_', r'copy_', r'orig_', r'bak_'
        ]
    
    @staticmethod
    def detect_backup_file(response_text: str, response_code: int, url: str, 
                          content_length: int) -> Tuple[bool, str, str]:
        """Detect if response contains backup file content"""
        
        if response_code != 200:
            return False, None, None
        
        # Check if response is too small to be meaningful
        if content_length < 50:
            return False, None, None
        
        # Check for source code patterns (indicates backup of source files)
        source_code_patterns = [
            # PHP patterns
            r'<\?php', r'<\?=', r'\$_GET\[', r'\$_POST\[', r'\$_SESSION\[',
            r'mysql_connect\s*\(', r'mysqli_connect\s*\(',
            r'include\s*\(', r'require\s*\(', r'function\s+\w+\s*\(',
            
            # ASP/ASP.NET patterns
            r'<%@', r'<%=', r'Response\.Write', r'Request\.Form',
            r'Server\.MapPath', r'Session\[',
            
            # JSP patterns
            r'<%@\s*page', r'<%=', r'request\.getParameter',
            r'session\.getAttribute',
            
            # JavaScript patterns
            r'function\s+\w+\s*\(', r'var\s+\w+\s*=', r'document\.getElementById',
            r'window\.location', r'XMLHttpRequest',
            
            # Configuration file patterns
            r'database\s*=', r'password\s*=', r'username\s*=',
            r'host\s*=', r'port\s*=', r'server\s*=',
            r'\[mysqld\]', r'\[database\]', r'ServerRoot',
            
            # SQL dump patterns
            r'CREATE\s+TABLE', r'INSERT\s+INTO', r'DROP\s+TABLE',
            r'-- MySQL dump', r'-- PostgreSQL database dump',
            
            # Log file patterns
            r'\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}',
            r'\[\d{2}/\w{3}/\d{4}:', r'GET\s+/', r'POST\s+/',
            r'\[error\]', r'\[warn\]', r'\[info\]'
        ]
        
        found_patterns = []
        response_lower = response_text.lower()
        
        for pattern in source_code_patterns:
            if re.search(pattern, response_text, re.IGNORECASE):
                found_patterns.append(pattern)
        
        # Determine file type based on patterns
        file_type = BackupFinderDetector._determine_file_type(found_patterns, response_text)
        
        if found_patterns:
            return True, file_type, f"Found {len(found_patterns)} source code patterns"
        
        # Check for directory listings (backup directories)
        directory_patterns = [
            r'<title>Index of /', r'Directory Listing',
            r'<h1>Index of', r'Parent Directory',
            r'\[DIR\]', r'\[   \]', r'<img[^>]*alt="\[DIR\]"'
        ]
        
        for pattern in directory_patterns:
            if re.search(pattern, response_text, re.IGNORECASE):
                return True, "directory_listing", "Directory listing detected"
        
        return False, None, None
    
    @staticmethod
    def _determine_file_type(patterns: List[str], response_text: str) -> str:
        """Determine the type of backup file based on patterns"""
        response_lower = response_text.lower()
        
        # PHP file
        if any(php in pattern for pattern in patterns for php in ['php', '$_', 'mysql_', 'mysqli_']):
            return "php_source"
        
        # ASP/ASP.NET file
        if any(asp in pattern for pattern in patterns for asp in ['<%', 'Response.', 'Request.', 'Server.']):
            return "asp_source"
        
        # JSP file
        if any(jsp in pattern for pattern in patterns for jsp in ['<%@', 'request.', 'session.']):
            return "jsp_source"
        
        # JavaScript file
        if any(js in pattern for pattern in patterns for js in ['function', 'var ', 'document.', 'window.']):
            return "javascript_source"
        
        # Configuration file
        if any(conf in pattern for pattern in patterns for conf in ['database', 'password', 'username', 'ServerRoot']):
            return "config_file"
        
        # SQL dump
        if any(sql in pattern for pattern in patterns for sql in ['CREATE', 'INSERT', 'DROP', 'dump']):
            return "sql_dump"
        
        # Log file
        if any(log in pattern for pattern in patterns for log in ['error', 'warn', 'info', 'GET ', 'POST ']):
            return "log_file"
        
        return "unknown_backup"
    
    @staticmethod
    def get_evidence(file_type: str, details: str) -> str:
        """Get evidence of backup file discovery"""
        type_descriptions = {
            "php_source": "PHP source code backup file",
            "asp_source": "ASP/ASP.NET source code backup file", 
            "jsp_source": "JSP source code backup file",
            "javascript_source": "JavaScript source code backup file",
            "config_file": "Configuration file backup",
            "sql_dump": "SQL database dump file",
            "log_file": "Log file backup",
            "directory_listing": "Backup directory listing",
            "unknown_backup": "Unknown backup file type"
        }
        
        description = type_descriptions.get(file_type, "Backup file")
        return f"{description} detected. {details}"
    
    @staticmethod
    def get_response_snippet(response_text: str, max_length: int = 500) -> str:
        """Get response snippet showing backup file content"""
        if len(response_text) <= max_length:
            return response_text
        
        # Try to get meaningful snippet from the beginning
        return response_text[:max_length] + "..."
