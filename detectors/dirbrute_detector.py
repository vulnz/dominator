"""
Directory and file bruteforce detector
"""

import re
from typing import Tuple, List, Dict, Any

class DirBruteDetector:
    """Directory bruteforce detection logic"""
    
    @staticmethod
    def is_valid_response(response_text: str, response_code: int, content_length: int, 
                         baseline_404: str = None, baseline_size: int = 0) -> Tuple[bool, str]:
        """
        Check if response indicates a valid directory/file using enhanced 404 detection
        Returns (is_valid, evidence)
        """
        from .real404_detector import Real404Detector
        
        # Use improved 404 detection with baseline patterns and size analysis
        is_404, real_404_evidence, confidence = Real404Detector.detect_real_404(
            response_text, response_code, content_length, baseline_404, baseline_size
        )
        
        # Very high confidence 404 detection
        if is_404 and confidence > 0.85:
            return False, f"Real 404 detected (very high confidence: {confidence:.3f}): {real_404_evidence}"
        
        # High confidence 404 detection
        if is_404 and confidence > 0.7:
            return False, f"Real 404 detected (high confidence: {confidence:.3f}): {real_404_evidence}"
        
        # Medium confidence 404 detection - additional validation
        if is_404 and confidence > 0.5:
            # Check for strong valid content indicators
            if DirBruteDetector._has_strong_valid_content(response_text):
                return True, f"Valid content overrides medium confidence 404 (confidence: {confidence:.3f})"
            else:
                return False, f"Real 404 detected (medium confidence: {confidence:.3f}): {real_404_evidence}"
        
        # Low confidence 404 - be very careful
        if is_404 and confidence > 0.3:
            # Multiple validation checks for low confidence cases
            has_valid_content = DirBruteDetector._has_strong_valid_content(response_text)
            has_dir_content = DirBruteDetector._has_directory_file_content(response_text)
            
            if has_valid_content or has_dir_content:
                return True, f"Valid content overrides low confidence 404 (confidence: {confidence:.3f})"
            else:
                return False, f"Real 404 detected (low confidence: {confidence:.3f}): {real_404_evidence}"
        
        # For 200 responses that don't match 404 patterns
        if response_code == 200:
            # Enhanced validation for directory/file content
            if DirBruteDetector._has_directory_file_content(response_text):
                return True, f"HTTP 200 - Valid directory/file content found"
            elif DirBruteDetector._has_strong_valid_content(response_text):
                return True, f"HTTP 200 - Strong valid content indicators found"
            elif content_length > 2000:  # Large responses are likely valid
                return True, f"HTTP 200 - Large response likely valid ({content_length} bytes)"
            else:
                # Small 200 responses need more scrutiny
                if DirBruteDetector._looks_like_error_page(response_text):
                    return False, f"HTTP 200 - Appears to be error page despite status code"
                return True, f"HTTP 200 - Content appears valid (no 404 patterns matched)"
        
        # Success codes
        if response_code in [201, 202, 203, 206]:
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
    def _has_strong_valid_content(response_text: str) -> bool:
        """Check if response has strong indicators of valid content"""
        response_lower = response_text.lower()
        
        # Strong indicators that this is definitely valid content
        strong_indicators = [
            # Functional elements
            '<form', '<input type=', '<textarea', '<select', '<button',
            
            # Rich content
            '<table', '<tr', '<td', 'function(', 'var ', 'class ',
            
            # Data content
            'json', 'xml', 'csv', 'database', 'config',
            
            # Interactive content
            'onclick', 'onsubmit', 'javascript:', 'ajax',
            
            # Media content
            '<img', '<video', '<audio', '<iframe',
            
            # Navigation elements
            '<nav', '<menu', '<ul class=', '<ol class=',
            
            # Content structure
            '<article', '<section', '<main', '<header', '<footer'
        ]
        
        # Count strong indicators
        strong_count = sum(1 for indicator in strong_indicators 
                          if indicator in response_lower)
        
        # Enhanced threshold - need more indicators for high confidence
        return strong_count >= 4
    
    @staticmethod
    def _looks_like_error_page(response_text: str) -> bool:
        """Check if response looks like an error page despite 200 status"""
        response_lower = response_text.lower()
        
        error_indicators = [
            'page not found', 'not found', '404', 'file not found',
            'error occurred', 'something went wrong', 'oops',
            'page does not exist', 'invalid request', 'access denied',
            'страница не найдена', 'файл не найден', 'ошибка'
        ]
        
        # Check title for error indicators
        import re
        title_match = re.search(r'<title[^>]*>(.*?)</title>', response_text, re.IGNORECASE | re.DOTALL)
        if title_match:
            title = title_match.group(1).strip().lower()
            if any(indicator in title for indicator in error_indicators):
                return True
        
        # Check main content for error indicators
        error_count = sum(1 for indicator in error_indicators 
                         if indicator in response_lower)
        
        return error_count >= 2
    
    @staticmethod
    def _has_directory_file_content(response_text: str) -> bool:
        """Check if response contains content typical of valid directories/files"""
        response_lower = response_text.lower()
        
        # Indicators of valid file/directory content
        valid_content_indicators = [
            # Directory listing indicators
            'index of', 'directory listing', 'parent directory',
            
            # File content indicators  
            '<?php', '<!doctype', '<html', '<head>', '<body>',
            'function', 'var ', 'class ', 'import ', 'include',
            
            # Configuration file indicators
            'config', 'settings', 'database', 'connection',
            
            # Log file indicators
            'error', 'warning', 'info', 'debug', 'log',
            
            # Data file indicators
            'json', 'xml', 'csv', 'data',
            
            # Backup file indicators
            'backup', 'dump', 'export'
        ]
        
        # Count indicators found
        indicators_found = sum(1 for indicator in valid_content_indicators 
                             if indicator in response_lower)
        
        # If we find multiple indicators, it's likely valid content
        return indicators_found >= 2
    
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
