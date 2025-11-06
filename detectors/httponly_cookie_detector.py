"""
HttpOnly cookie detection logic
"""

import re
from typing import List, Dict, Any, Tuple

class HttpOnlyCookieDetector:
    """HttpOnly cookie detection logic"""
    
    @staticmethod
    def detect_httponly_cookies(response_headers: Dict[str, str]) -> List[Dict[str, Any]]:
        """
        Detect cookies without HttpOnly flag
        Returns list of insecure cookies
        """
        insecure_cookies = []
        
        # Get all Set-Cookie headers
        set_cookie_headers = []
        
        # Handle both single and multiple Set-Cookie headers
        for header_name, header_value in response_headers.items():
            if header_name.lower() == 'set-cookie':
                if isinstance(header_value, list):
                    set_cookie_headers.extend(header_value)
                else:
                    set_cookie_headers.append(header_value)
        
        # Also check for cookies in other common header formats
        if 'Set-Cookie' in response_headers:
            cookie_header = response_headers['Set-Cookie']
            if isinstance(cookie_header, str):
                set_cookie_headers.append(cookie_header)
            elif isinstance(cookie_header, list):
                set_cookie_headers.extend(cookie_header)
        
        for cookie_header in set_cookie_headers:
            cookie_analysis = HttpOnlyCookieDetector._analyze_cookie_security(cookie_header)
            
            if cookie_analysis['issues']:
                insecure_cookies.append(cookie_analysis)
        
        return insecure_cookies
    
    @staticmethod
    def _analyze_cookie_security(cookie_header: str) -> Dict[str, Any]:
        """Analyze individual cookie for security issues"""
        issues = []
        cookie_name = "unknown"
        
        # Extract cookie name
        cookie_parts = cookie_header.split(';')
        if cookie_parts:
            name_value = cookie_parts[0].strip()
            if '=' in name_value:
                cookie_name = name_value.split('=')[0].strip()
        
        cookie_lower = cookie_header.lower()
        
        # Check for HttpOnly flag
        if 'httponly' not in cookie_lower:
            issues.append({
                'issue': 'Missing HttpOnly Flag',
                'severity': 'Medium',
                'description': 'Cookie can be accessed via JavaScript, making it vulnerable to XSS attacks'
            })
        
        # Check for Secure flag (if not localhost/development)
        if 'secure' not in cookie_lower:
            issues.append({
                'issue': 'Missing Secure Flag',
                'severity': 'Medium',
                'description': 'Cookie can be transmitted over unencrypted HTTP connections'
            })
        
        # Check for SameSite attribute
        if 'samesite' not in cookie_lower:
            issues.append({
                'issue': 'Missing SameSite Attribute',
                'severity': 'Low',
                'description': 'Cookie lacks CSRF protection via SameSite attribute'
            })
        
        # Check for session cookies without expiration
        has_expires = 'expires' in cookie_lower
        has_max_age = 'max-age' in cookie_lower
        
        if not has_expires and not has_max_age:
            # This is a session cookie - check if it's a sensitive cookie
            sensitive_patterns = ['session', 'auth', 'login', 'token', 'csrf', 'jsessionid', 'phpsessid']
            if any(pattern in cookie_name.lower() for pattern in sensitive_patterns):
                issues.append({
                    'issue': 'Session Cookie Without Expiration',
                    'severity': 'Low',
                    'description': 'Sensitive session cookie lacks explicit expiration time'
                })
        
        return {
            'cookie_name': cookie_name,
            'cookie_header': cookie_header,
            'issues': issues
        }
    
    @staticmethod
    def get_remediation_advice(issue_type: str) -> str:
        """Get remediation advice for cookie security issues"""
        advice = {
            'Missing HttpOnly Flag': (
                "Add the HttpOnly flag to cookies to prevent access via JavaScript. "
                "This helps protect against XSS attacks that attempt to steal cookies."
            ),
            'Missing Secure Flag': (
                "Add the Secure flag to cookies to ensure they are only transmitted over HTTPS. "
                "This prevents cookie interception over unencrypted connections."
            ),
            'Missing SameSite Attribute': (
                "Add the SameSite attribute to cookies to provide CSRF protection. "
                "Use 'SameSite=Strict' for maximum security or 'SameSite=Lax' for better compatibility."
            ),
            'Session Cookie Without Expiration': (
                "Set explicit expiration times for session cookies using Max-Age or Expires attributes. "
                "This ensures cookies don't persist indefinitely in the browser."
            )
        }
        
        return advice.get(issue_type, "Review and improve cookie security configuration.")
