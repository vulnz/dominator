"""
Directory and file bruteforce detector
"""

import re
from typing import Tuple, List, Dict, Any

class DirBruteDetector:
    """Directory bruteforce detection logic"""
    
    @staticmethod
    def is_valid_response(response_text: str, response_code: int, content_length: int, 
                         baseline_404: str = None, baseline_size: int = 0, 
                         response_headers: dict = None, session=None, url: str = None) -> Tuple[bool, str]:
        """
        Check if response indicates a valid directory/file using enhanced 404 detection
        Returns (is_valid, evidence)
        """
        from .real404_detector import Real404Detector
        from libs.response_analyzer import ResponseAnalyzer
        
        # Use response analyzer for better analysis
        analyzer = ResponseAnalyzer()
        analysis = analyzer.analyze_response(response_text, response_code)
        
        # Use improved 404 detection with baseline patterns and size analysis
        is_404, real_404_evidence, confidence = Real404Detector.detect_real_404(
            response_text, response_code, content_length, baseline_404, baseline_size
        )
        
        # Very high confidence 404 detection - strict filtering
        if is_404 and confidence > 0.9:
            return False, f"Real 404 detected (very high confidence: {confidence:.3f}): {real_404_evidence}"
        
        # High confidence 404 detection with additional checks
        if is_404 and confidence > 0.8:
            # Check if response has meaningful structure despite 404 detection
            if analysis['structure_score'] > 0.5 and analysis['has_forms']:
                return True, f"Valid content overrides high confidence 404 (structure score: {analysis['structure_score']:.2f})"
            return False, f"Real 404 detected (high confidence: {confidence:.3f}): {real_404_evidence}"
        
        # Medium confidence 404 detection - more careful validation
        if is_404 and confidence > 0.6:
            # Check for strong valid content indicators
            if (DirBruteDetector._has_strong_valid_content(response_text) and 
                analysis['structure_score'] > 0.3):
                return True, f"Valid content overrides medium confidence 404 (confidence: {confidence:.3f})"
            else:
                return False, f"Real 404 detected (medium confidence: {confidence:.3f}): {real_404_evidence}"
        
        # Low confidence 404 - very careful validation
        if is_404 and confidence > 0.4:
            # Multiple validation checks for low confidence cases
            has_valid_content = DirBruteDetector._has_strong_valid_content(response_text)
            has_dir_content = DirBruteDetector._has_directory_file_content(response_text)
            has_meaningful_content = analyzer.is_meaningful_content(response_text)
            
            if (has_valid_content or has_dir_content or has_meaningful_content) and analysis['structure_score'] > 0.2:
                return True, f"Valid content overrides low confidence 404 (confidence: {confidence:.3f})"
            else:
                return False, f"Real 404 detected (low confidence: {confidence:.3f}): {real_404_evidence}"
        
        # For 200 responses that don't match 404 patterns
        if response_code == 200:
            # Enhanced validation using response analyzer
            if analysis['structure_score'] > 0.4:
                return True, f"HTTP 200 - High structure score ({analysis['structure_score']:.2f})"
            elif DirBruteDetector._has_directory_file_content(response_text):
                return True, f"HTTP 200 - Valid directory/file content found"
            elif DirBruteDetector._has_strong_valid_content(response_text):
                return True, f"HTTP 200 - Strong valid content indicators found"
            elif content_length > 3000:  # Increased threshold for large responses
                return True, f"HTTP 200 - Large response likely valid ({content_length} bytes)"
            else:
                # Small 200 responses need more scrutiny
                if DirBruteDetector._looks_like_error_page(response_text):
                    return False, f"HTTP 200 - Appears to be error page despite status code"
                elif analysis['has_errors'] and analysis['structure_score'] < 0.1:
                    return False, f"HTTP 200 - Contains errors with low structure score"
                return True, f"HTTP 200 - Content appears valid (no 404 patterns matched)"
        
        # Success codes
        if response_code in [201, 202, 203, 206]:
            return True, f"HTTP {response_code} - Resource found"
        
        # Enhanced redirect handling - check where redirect leads
        if response_code in [301, 302, 303, 307, 308]:
            return DirBruteDetector._validate_redirect(
                response_headers, session, url, baseline_404, baseline_size
            )
        
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
        """Detect if response contains directory listing with improved accuracy"""
        response_lower = response_text.lower()
        
        # Enhanced directory listing indicators
        directory_indicators = [
            'index of /',
            'directory listing',
            'parent directory',
            '<title>index of',
            'directory listing for',
            '[to parent directory]',
            'folder.gif',
            'dir.gif',
            '[dir]',
            '[   ]',  # Apache directory listing spacing
            'last modified',
            'size</th>',
            'name</th>',
            '<pre><a href="../">../</a>',  # Common Apache format
        ]
        
        # Count indicators found
        indicators_found = sum(1 for indicator in directory_indicators 
                             if indicator in response_lower)
        
        # Check for typical directory listing structure
        has_parent_dir = '../' in response_text or '[to parent directory]' in response_lower
        has_file_links = len([m for m in re.finditer(r'<a href="[^"?]*">[^<]+</a>', response_text)]) > 2
        has_size_column = 'size' in response_lower and ('kb' in response_lower or 'mb' in response_lower or 'bytes' in response_lower)
        
        # Filter out false positives from sorting parameters
        has_sorting_params = bool(re.search(r'\?[Cc]=[NnMmSsDd];?[Oo]=[AaDd]', response_text))
        if has_sorting_params:
            print(f"    [DIRBRUTE] Directory listing with sorting parameters detected")
            # If we detect sorting parameters, we need stronger evidence
            return indicators_found >= 3 or (has_parent_dir and has_file_links and has_size_column)
        
        # Directory listing detected if we have multiple indicators or strong structural evidence
        return indicators_found >= 2 or (has_parent_dir and has_file_links) or (has_file_links and has_size_column)
    
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
    def _validate_redirect(response_headers: dict, session, url: str, 
                          baseline_404: str = None, baseline_size: int = 0) -> Tuple[bool, str]:
        """
        Validate redirect responses by following them and checking final destination
        Returns (is_valid, evidence)
        """
        if not response_headers or not session or not url:
            return False, "HTTP 302 - Cannot validate redirect (missing data)"
        
        # Get redirect location
        location = response_headers.get('Location') or response_headers.get('location')
        if not location:
            return False, "HTTP 302 - No redirect location found"
        
        try:
            # Handle relative redirects
            if location.startswith('/'):
                from urllib.parse import urlparse
                parsed_url = urlparse(url)
                location = f"{parsed_url.scheme}://{parsed_url.netloc}{location}"
            elif not location.startswith('http'):
                # Relative to current path
                base_url = url.rsplit('/', 1)[0]
                location = f"{base_url}/{location}"
            
            print(f"    [DIRBRUTE] Following redirect: {location}")
            
            # Follow redirect with timeout
            redirect_response = session.get(location, timeout=10, verify=False, allow_redirects=True)
            
            # Analyze final destination
            from .real404_detector import Real404Detector
            
            # Check if final destination is a 404 page
            is_404, evidence, confidence = Real404Detector.detect_real_404(
                redirect_response.text, redirect_response.status_code, 
                len(redirect_response.text), baseline_404, baseline_size
            )
            
            # Lower threshold for 404 detection in redirects - be more strict
            if is_404 and confidence > 0.5:
                return False, f"HTTP 302 -> {redirect_response.status_code} - Redirect leads to 404: {evidence}"
            
            # Check if redirected to main page or login page (common false positive)
            if DirBruteDetector._is_redirect_to_main_page(location, redirect_response.text):
                return False, f"HTTP 302 -> {redirect_response.status_code} - Redirect to main/login page"
            
            # Additional check: if redirect response is identical to baseline 404, it's likely a false positive
            if baseline_404 and len(baseline_404) > 100:
                from libs.response_analyzer import ResponseAnalyzer
                analyzer = ResponseAnalyzer()
                redirect_fingerprint = analyzer.generate_fingerprint(redirect_response.text)
                baseline_fingerprint = analyzer.generate_fingerprint(baseline_404)
                
                # If fingerprints are very similar, it's likely the same 404 page
                if redirect_fingerprint == baseline_fingerprint:
                    return False, f"HTTP 302 -> {redirect_response.status_code} - Redirect to baseline 404 page"
            
            # Check if redirected to same domain (good sign)
            from urllib.parse import urlparse
            original_domain = urlparse(url).netloc
            redirect_domain = urlparse(location).netloc
            
            if original_domain != redirect_domain:
                return False, f"HTTP 302 -> {redirect_response.status_code} - External redirect to {redirect_domain}"
            
            # If final response is successful and has content, consider valid
            if redirect_response.status_code == 200:
                if len(redirect_response.text) > 1000:
                    return True, f"HTTP 302 -> 200 - Valid redirect to content ({len(redirect_response.text)} bytes)"
                elif DirBruteDetector._has_directory_file_content(redirect_response.text):
                    return True, f"HTTP 302 -> 200 - Valid redirect to directory/file content"
                else:
                    return False, f"HTTP 302 -> 200 - Redirect to minimal content ({len(redirect_response.text)} bytes)"
            
            # Other successful status codes
            if redirect_response.status_code in [201, 202, 203]:
                return True, f"HTTP 302 -> {redirect_response.status_code} - Valid redirect"
            
            # Forbidden or method not allowed (resource exists)
            if redirect_response.status_code in [403, 405]:
                return True, f"HTTP 302 -> {redirect_response.status_code} - Redirect to existing resource"
            
            return False, f"HTTP 302 -> {redirect_response.status_code} - Redirect to error page"
            
        except Exception as e:
            print(f"    [DIRBRUTE] Error following redirect: {e}")
            return False, f"HTTP 302 - Error following redirect: {str(e)}"
    
    @staticmethod
    def _is_redirect_to_main_page(redirect_url: str, redirect_content: str) -> bool:
        """Check if redirect leads to main page, login page, or index page"""
        redirect_url_lower = redirect_url.lower()
        content_lower = redirect_content.lower()
        
        # Check URL patterns that suggest main page
        main_page_patterns = [
            '/index.php', '/index.html', '/index.htm', '/main.php',
            '/home.php', '/login.php', '/default.php', '/welcome.php',
            '/dashboard.php', '/portal.php', '/admin.php'
        ]
        
        for pattern in main_page_patterns:
            if pattern in redirect_url_lower:
                return True
        
        # Check if URL ends with just domain (root) or common main page paths
        from urllib.parse import urlparse
        parsed = urlparse(redirect_url)
        if parsed.path in ['/', '', '/index', '/main', '/home', '/dashboard', '/portal']:
            return True
        
        # Check if redirect URL is significantly shorter than original (likely going to root/main)
        # This catches cases where /admin/ redirects to /xvwa/ (main application path)
        if len(parsed.path) <= 10 and ('/' in parsed.path or parsed.path.endswith('/')):
            # Additional check: if path contains common application names
            app_indicators = ['xvwa', 'dvwa', 'app', 'web', 'site', 'portal']
            path_parts = parsed.path.lower().strip('/').split('/')
            if any(indicator in part for part in path_parts for indicator in app_indicators):
                return True
        
        # Check content for main page indicators
        main_content_indicators = [
            'welcome to', 'home page', 'main page', 'dashboard',
            'login form', 'sign in', 'username', 'password',
            '<title>home', '<title>main', '<title>welcome', '<title>login',
            'navigation', 'menu', 'sidebar', 'header', 'footer',
            'copyright', '&copy;', 'all rights reserved'
        ]
        
        main_indicators_found = sum(1 for indicator in main_content_indicators 
                                  if indicator in content_lower)
        
        # Check for specific application indicators (like XVWA)
        app_indicators = [
            'xvwa', 'damn vulnerable', 'dvwa', 'vulnerable web application',
            'security testing', 'penetration testing', 'vulnerability scanner'
        ]
        
        app_indicators_found = sum(1 for indicator in app_indicators 
                                 if indicator in content_lower)
        
        # If multiple main page indicators found OR app-specific indicators, likely redirected to main page
        return main_indicators_found >= 2 or app_indicators_found >= 1
    
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
