"""
Enhanced File Inclusion detector for testphp.vulnweb.com
Detects both LFI and RFI vulnerabilities with improved accuracy
"""

import re
from typing import List, Dict, Tuple, Any

class FileInclusionEnhancedDetector:
    """Enhanced File Inclusion vulnerability detection logic"""
    
    @staticmethod
    def detect_file_inclusion(response_text: str, response_code: int, payload: str) -> Tuple[bool, str, str]:
        """
        Enhanced file inclusion detection
        
        Args:
            response_text: HTTP response content
            response_code: HTTP response status code
            payload: The payload used in the request
            
        Returns:
            Tuple[bool, str, str]: (is_vulnerable, inclusion_type, evidence)
        """
        if response_code >= 400:
            return False, "", ""
        
        # LFI indicators for testphp.vulnweb.com
        lfi_indicators = [
            # Linux/Unix files
            'root:x:0:0:root:/root:/bin/bash',
            'root:x:0:0:root:/root:/bin/sh',
            'daemon:x:1:1:daemon:/usr/sbin:/bin/sh',
            'bin:x:2:2:bin:/bin:/bin/sh',
            'sys:x:3:3:sys:/dev:/bin/sh',
            'nobody:x:65534:65534:nobody:/nonexistent:/bin/sh',
            
            # Windows files
            '[fonts]',
            '[extensions]',
            '; for 16-bit app support',
            '[mci extensions]',
            '[files]',
            '[Mail]',
            'MAPI=1',
            
            # PHP files
            '<?php',
            '<?=',
            '<script language="php">',
            'function ',
            'class ',
            'include',
            'require',
            '$_GET',
            '$_POST',
            '$_REQUEST',
            
            # Configuration files
            'mysql_connect',
            'mysqli_connect',
            'database',
            'username',
            'password',
            'host',
            'localhost',
            
            # Apache files
            'DocumentRoot',
            'ServerRoot',
            'LoadModule',
            'DirectoryIndex',
            
            # Error messages that indicate file access
            'failed to open stream',
            'No such file or directory',
            'Permission denied',
            'include_path',
            'fopen',
            'file_get_contents',
        ]
        
        # RFI indicators
        rfi_indicators = [
            # Remote file inclusion success
            'http://',
            'https://',
            'ftp://',
            'Remote file',
            'URL include',
            
            # PHP wrappers
            'php://input',
            'php://filter',
            'data://',
            'expect://',
            'zip://',
            
            # Base64 encoded content
            'base64',
            'convert.base64',
        ]
        
        # SSRF indicators (for showimage.php)
        ssrf_indicators = [
            '127.0.0.1',
            'localhost',
            '192.168.',
            '10.',
            '172.16.',
            '172.17.',
            '172.18.',
            '172.19.',
            '172.20.',
            '172.21.',
            '172.22.',
            '172.23.',
            '172.24.',
            '172.25.',
            '172.26.',
            '172.27.',
            '172.28.',
            '172.29.',
            '172.30.',
            '172.31.',
            'file://',
            'gopher://',
        ]
        
        response_lower = response_text.lower()
        
        # Check for LFI
        for indicator in lfi_indicators:
            if indicator.lower() in response_lower:
                return True, "LFI", f"Local file inclusion detected - found: {indicator}"
        
        # Check for RFI
        for indicator in rfi_indicators:
            if indicator.lower() in response_lower:
                return True, "RFI", f"Remote file inclusion detected - found: {indicator}"
        
        # Check for SSRF (specific to showimage.php)
        if 'showimage.php' in payload or 'file=' in payload:
            for indicator in ssrf_indicators:
                if indicator in response_text:
                    return True, "SSRF", f"Server-Side Request Forgery detected - found: {indicator}"
        
        # Check for PHP filter responses
        if 'php://filter' in payload and len(response_text) > 100:
            # Look for base64 encoded content
            base64_pattern = r'[A-Za-z0-9+/]{50,}={0,2}'
            if re.search(base64_pattern, response_text):
                return True, "LFI", "PHP filter base64 encoding detected"
        
        # Check for file path traversal success
        if '../' in payload or '..\\' in payload:
            # Look for signs that traversal worked
            traversal_success = [
                'root:',
                '[fonts]',
                '<?php',
                'mysql_connect',
                'DocumentRoot'
            ]
            for success_indicator in traversal_success:
                if success_indicator in response_text:
                    return True, "LFI", f"Directory traversal successful - found: {success_indicator}"
        
        return False, "", ""
    
    @staticmethod
    def get_evidence(inclusion_type: str, indicator: str, response_text: str) -> str:
        """Get detailed evidence for file inclusion"""
        evidence = f"{inclusion_type} vulnerability detected"
        
        if indicator:
            evidence += f" - Indicator: {indicator}"
        
        # Add context around the indicator
        if indicator and indicator.lower() in response_text.lower():
            start_pos = response_text.lower().find(indicator.lower())
            if start_pos >= 0:
                context_start = max(0, start_pos - 50)
                context_end = min(len(response_text), start_pos + len(indicator) + 50)
                context = response_text[context_start:context_end].replace('\n', ' ').replace('\r', ' ')
                evidence += f" - Context: ...{context}..."
        
        return evidence
    
    @staticmethod
    def get_response_snippet(response_text: str, max_length: int = 200) -> str:
        """Get response snippet for reporting"""
        if len(response_text) <= max_length:
            return response_text
        
        # Try to get meaningful content
        lines = response_text.split('\n')
        snippet = ""
        for line in lines:
            if len(snippet + line) <= max_length:
                snippet += line + "\n"
            else:
                break
        
        if len(snippet) < max_length // 2:
            # If we didn't get much, just take the first part
            snippet = response_text[:max_length]
        
        return snippet + "..." if len(response_text) > len(snippet) else snippet
    
    @staticmethod
    def get_remediation_advice() -> str:
        """Get remediation advice for file inclusion vulnerabilities"""
        return (
            "1. Validate and sanitize all file path inputs\n"
            "2. Use whitelist of allowed files/directories\n"
            "3. Disable remote file inclusion (allow_url_include=Off)\n"
            "4. Use basename() to prevent directory traversal\n"
            "5. Implement proper access controls\n"
            "6. Use realpath() to resolve symbolic links\n"
            "7. Avoid user input in file operations"
        )
