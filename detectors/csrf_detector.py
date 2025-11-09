"""
CSRF (Cross-Site Request Forgery) vulnerability detector
"""

import re
from typing import Tuple, List

class CSRFDetector:
    """CSRF vulnerability detection logic"""
    
    @staticmethod
    def get_csrf_indicators() -> List[str]:
        """Get CSRF protection indicators to look for"""
        return [
            # Common CSRF token names
            'csrf_token', 'csrf-token', '_token', 'token',
            'authenticity_token', 'csrfmiddlewaretoken', 
            'anti-csrf-token', '_csrf', 'csrf_param',
            
            # Framework-specific tokens
            '__RequestVerificationToken',  # ASP.NET
            'YII_CSRF_TOKEN',             # Yii Framework
            '_wpnonce',                   # WordPress
            'form_token',                 # phpBB
            'sid',                        # Session ID
            'security_token',             # Generic
            'xsrf_token',                 # Alternative naming
            
            # Meta tag indicators
            'csrf-token', 'x-csrf-token', 'xsrf-token'
        ]
    
    @staticmethod
    def get_csrf_headers() -> List[str]:
        """Get CSRF protection headers"""
        return [
            # CSRF-specific headers
            'X-CSRF-Token', 'X-CSRFToken', 'X-XSRF-TOKEN',
            'X-CSRF-TOKEN', 'csrf-token', 'CSRF-Token',
            
            # Framework headers
            'X-Requested-With',           # AJAX protection
            'X-PINGOTHER',               # CORS preflight
            'X-Custom-Header',           # Custom protection
            
            # Security headers
            'X-Frame-Options',           # Clickjacking protection
            'Content-Security-Policy',   # CSP protection
            'Referrer-Policy'            # Referrer validation
        ]
    
    @staticmethod
    def detect_csrf_protection(response_text: str, response_headers: dict, form_data: dict = None) -> Tuple[bool, str]:
        """
        Detect if CSRF protection is present
        Returns (has_protection, evidence)
        """
        evidence_parts = []
        has_protection = False
        
        # Check for CSRF tokens in response body
        csrf_indicators = CSRFDetector.get_csrf_indicators()
        for indicator in csrf_indicators:
            # Check for hidden input fields
            pattern = rf'<input[^>]*name=["\']?{re.escape(indicator)}["\']?[^>]*>'
            if re.search(pattern, response_text, re.IGNORECASE):
                has_protection = True
                evidence_parts.append(f"Found CSRF token field: {indicator}")
            
            # Check for meta tags
            pattern = rf'<meta[^>]*name=["\']?{re.escape(indicator)}["\']?[^>]*>'
            if re.search(pattern, response_text, re.IGNORECASE):
                has_protection = True
                evidence_parts.append(f"Found CSRF meta tag: {indicator}")
        
        # Check for CSRF protection headers
        csrf_headers = CSRFDetector.get_csrf_headers()
        for header in csrf_headers:
            if header.lower() in [h.lower() for h in response_headers.keys()]:
                has_protection = True
                evidence_parts.append(f"Found CSRF header: {header}")
        
        # Check for SameSite cookie attribute
        set_cookie_headers = response_headers.get('Set-Cookie', '')
        if isinstance(set_cookie_headers, list):
            set_cookie_headers = '; '.join(set_cookie_headers)
        
        if 'samesite' in set_cookie_headers.lower():
            has_protection = True
            evidence_parts.append("Found SameSite cookie attribute")
        
        # Check for Referer header validation patterns
        if 'referer' in response_text.lower() or 'origin' in response_text.lower():
            # This is a weak indicator, so we don't mark as protected
            evidence_parts.append("Possible referer/origin validation")
        
        evidence = "; ".join(evidence_parts) if evidence_parts else "No CSRF protection detected"
        
        return has_protection, evidence
    
    @staticmethod
    def detect_csrf_vulnerability(response_text: str, response_headers: dict, form_data: dict = None) -> Tuple[bool, str]:
        """
        Detect CSRF vulnerability (absence of protection)
        Returns (is_vulnerable, evidence)
        """
        # Check if this is an error page (404, 500, etc.) - not vulnerable
        error_indicators = [
            '404 not found',
            '404 - not found',
            'page not found',
            '500 internal server error',
            '403 forbidden',
            'error 404',
            'error 500',
            'error 403',
            'not found',
            'file not found'
        ]
        
        response_lower = response_text.lower()
        if any(indicator in response_lower for indicator in error_indicators):
            evidence = "Error page detected - not testing for CSRF vulnerabilities"
            return False, evidence
        
        # Check if response is too short to contain meaningful content
        if len(response_text.strip()) < 100:
            evidence = "Response too short to analyze for CSRF vulnerabilities"
            return False, evidence
        
        # Look for POST forms specifically
        post_form_pattern = r'<form[^>]*method=["\']?post["\']?[^>]*>(.*?)</form>'
        post_forms = re.findall(post_form_pattern, response_text, re.IGNORECASE | re.DOTALL)
        
        if not post_forms:
            evidence = "No POST forms found - not vulnerable to CSRF"
            return False, evidence
        
        vulnerable_forms = 0
        csrf_indicators = CSRFDetector.get_csrf_indicators()
        
        for form_content in post_forms:
            has_csrf_token = False
            
            # Check for CSRF tokens in form
            for indicator in csrf_indicators:
                if indicator.lower() in form_content.lower():
                    has_csrf_token = True
                    break
            
            if not has_csrf_token:
                vulnerable_forms += 1
        
        if vulnerable_forms > 0:
            evidence = f"Found {vulnerable_forms} POST form(s) without CSRF protection out of {len(post_forms)} total POST forms"
            return True, evidence
        else:
            evidence = f"All {len(post_forms)} POST form(s) have CSRF protection"
            return False, evidence
    
    @staticmethod
    def get_evidence(protection_status: str, details: str) -> str:
        """Get formatted evidence string"""
        return f"CSRF Protection Status: {protection_status}. Details: {details}"
    
    @staticmethod
    def get_response_snippet(response_text: str, max_length: int = 500) -> str:
        """Get relevant response snippet for CSRF analysis"""
        # Look for form tags and surrounding context
        form_pattern = r'<form[^>]*>.*?</form>'
        forms = re.findall(form_pattern, response_text, re.IGNORECASE | re.DOTALL)
        
        if forms:
            # Return first form found, truncated if necessary
            form_snippet = forms[0]
            if len(form_snippet) > max_length:
                form_snippet = form_snippet[:max_length] + "..."
            return form_snippet
        
        # If no forms, return beginning of response
        if len(response_text) > max_length:
            return response_text[:max_length] + "..."
        return response_text
import re
from typing import List, Dict, Any, Tuple
from urllib.parse import parse_qs, urlparse

class CSRFDetector:
    """CSRF vulnerability detection logic optimized for XVWA"""
    
    @staticmethod
    def get_csrf_indicators() -> List[str]:
        """Get CSRF token field names commonly used"""
        return [
            'csrf_token',
            'csrftoken',
            'csrf-token',
            '_token',
            'authenticity_token',
            'anti_csrf_token',
            'csrf_protection',
            'csrf_key',
            'csrf_hash',
            'csrf_value',
            'xsrf_token',
            'xsrftoken',
            'request_token',
            'form_token',
            'security_token',
            'session_token',
            'nonce',
            'state'
        ]

    @staticmethod
    def get_csrf_headers() -> List[str]:
        """Get CSRF protection headers"""
        return [
            'X-CSRF-Token',
            'X-CSRFToken',
            'X-XSRF-TOKEN',
            'X-Requested-With',
            'Referer',
            'Origin'
        ]

    @staticmethod
    def detect_csrf_vulnerability(response_text: str, response_headers: Dict[str, str], url: str) -> Tuple[bool, str, str, Dict[str, Any]]:
        """Detect CSRF vulnerabilities in forms with enhanced login form detection"""
        if not response_text:
            return False, "", "", {}

        # Find all forms in the response
        form_pattern = r'<form[^>]*>(.*?)</form>'
        forms = re.findall(form_pattern, response_text, re.IGNORECASE | re.DOTALL)
        
        vulnerable_forms = []
        login_forms = []
        csrf_indicators = CSRFDetector.get_csrf_indicators()
        
        for form in forms:
            # Check if form has CSRF protection
            has_csrf_token = False
            for indicator in csrf_indicators:
                if re.search(rf'name\s*=\s*["\']?{indicator}["\']?', form, re.IGNORECASE):
                    has_csrf_token = True
                    break
            
            # Check if this is a login form
            is_login_form = CSRFDetector._is_login_form(form)
            
            # Check if form modifies data (POST, PUT, DELETE methods)
            method_match = re.search(r'method\s*=\s*["\']?(post|put|delete)["\']?', form, re.IGNORECASE)
            if method_match and not has_csrf_token:
                action_match = re.search(r'action\s*=\s*["\']?([^"\'>\s]+)["\']?', form, re.IGNORECASE)
                action = action_match.group(1) if action_match else "current page"
                
                form_info = f"Form with action '{action}' (method: {method_match.group(1).upper()})"
                
                if is_login_form:
                    login_forms.append(form_info + " [LOGIN FORM]")
                else:
                    vulnerable_forms.append(form_info)

        # Prioritize login forms as they are more critical
        all_vulnerable = login_forms + vulnerable_forms
        
        if all_vulnerable:
            severity = "High" if login_forms else "Medium"
            evidence = f"Found {len(all_vulnerable)} form(s) without CSRF protection: {'; '.join(all_vulnerable)}"
            
            return True, evidence, severity, {
                'cwe': 'CWE-352',
                'cvss': '8.8' if login_forms else '6.5',
                'owasp': 'A01:2021 – Broken Access Control',
                'recommendation': 'Implement CSRF tokens in all state-changing forms, especially login forms. Use SameSite cookie attributes and validate Referer headers.',
                'login_forms_affected': len(login_forms),
                'total_forms_affected': len(all_vulnerable)
            }

        return False, "", "", {}
    
    @staticmethod
    def _is_login_form(form_content: str) -> bool:
        """Check if form is a login form"""
        form_lower = form_content.lower()
        
        # Check for password fields
        has_password = bool(re.search(r'type\s*=\s*["\']?password["\']?', form_lower))
        
        # Check for login-related field names
        login_indicators = [
            'username', 'user', 'login', 'email', 'password', 'pass',
            'signin', 'log-in', 'authenticate', 'auth'
        ]
        
        has_login_fields = any(
            re.search(rf'name\s*=\s*["\']?[^"\']*{indicator}[^"\']*["\']?', form_lower)
            for indicator in login_indicators
        )
        
        # Check for login-related submit buttons
        login_submit_patterns = [
            'login', 'sign in', 'log in', 'authenticate', 'enter'
        ]
        
        has_login_submit = any(
            re.search(rf'value\s*=\s*["\']?[^"\']*{pattern}[^"\']*["\']?', form_lower)
            for pattern in login_submit_patterns
        )
        
        return has_password and (has_login_fields or has_login_submit)

    @staticmethod
    def check_csrf_headers(headers: Dict[str, str]) -> Tuple[bool, str]:
        """Check for CSRF protection headers"""
        csrf_headers = CSRFDetector.get_csrf_headers()
        missing_headers = []
        
        for header in csrf_headers:
            if header.lower() not in [h.lower() for h in headers.keys()]:
                missing_headers.append(header)
        
        if missing_headers:
            return True, f"Missing CSRF protection headers: {', '.join(missing_headers)}"
        
        return False, ""
