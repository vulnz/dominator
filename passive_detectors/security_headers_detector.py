"""
Passive security headers detector
Analyzes HTTP response headers for security misconfigurations without sending additional requests
"""

from typing import Dict, List, Tuple, Any

class SecurityHeadersDetector:
    """Passive security headers analysis"""
    
    @staticmethod
    def analyze(headers: Dict[str, str], url: str) -> Tuple[bool, List[Dict[str, Any]]]:
        """
        Passive security headers analysis
        
        How it works:
        1. Receives HTTP response headers from crawler
        2. Checks for presence of critical security headers
        3. Analyzes their values for misconfigurations
        4. Returns list of found issues without sending additional requests
        
        Args:
            headers: Dictionary of HTTP headers
            url: URL being analyzed
            
        Returns:
            Tuple[bool, List[Dict]]: (has_issues, list_of_issues)
        """
        issues = []
        
        # Critical security headers
        security_headers = {
            'X-Frame-Options': {
                'required': True,
                'safe_values': ['DENY', 'SAMEORIGIN'],
                'description': 'Protection against clickjacking attacks'
            },
            'X-Content-Type-Options': {
                'required': True,
                'safe_values': ['nosniff'],
                'description': 'Prevents MIME-type sniffing'
            },
            'Strict-Transport-Security': {
                'required': True,
                'safe_values': None,
                'description': 'Enforces HTTPS usage'
            },
            'Content-Security-Policy': {
                'required': True,
                'safe_values': None,
                'description': 'Protection against XSS and injection attacks'
            }
        }
        
        # Check for missing headers
        for header_name, config in security_headers.items():
            header_value = headers.get(header_name, '').strip()
            
            if not header_value and config['required']:
                issues.append({
                    'type': 'missing_security_header',
                    'severity': 'Medium',
                    'url': url,
                    'header': header_name,
                    'description': f"Missing {header_name} header: {config['description']}",
                    'recommendation': f"Add {header_name} header for improved security"
                })
        
        # Check dangerous headers
        dangerous_headers = ['Server', 'X-Powered-By', 'X-AspNet-Version']
        for header_name in dangerous_headers:
            if header_name in headers:
                issues.append({
                    'type': 'information_disclosure',
                    'severity': 'Low',
                    'url': url,
                    'header': header_name,
                    'value': headers[header_name],
                    'description': f"Information disclosure via {header_name} header",
                    'recommendation': f"Remove or hide {header_name} header"
                })
        
        return len(issues) > 0, issues
    
    @staticmethod
    def analyze_cookies(headers: Dict[str, str], url: str) -> Tuple[bool, List[Dict[str, Any]]]:
        """Passive cookie security analysis"""
        issues = []
        
        set_cookie_headers = []
        for key, value in headers.items():
            if key.lower() == 'set-cookie':
                set_cookie_headers.append(value)
        
        for cookie_header in set_cookie_headers:
            cookie_name = cookie_header.split('=')[0].strip()
            cookie_lower = cookie_header.lower()
            
            if 'secure' not in cookie_lower:
                issues.append({
                    'type': 'insecure_cookie',
                    'severity': 'Medium',
                    'url': url,
                    'cookie': cookie_name,
                    'description': f"Cookie '{cookie_name}' missing Secure flag",
                    'recommendation': 'Add Secure flag to transmit cookie only over HTTPS'
                })
            
            if 'httponly' not in cookie_lower:
                issues.append({
                    'type': 'accessible_cookie',
                    'severity': 'Medium',
                    'url': url,
                    'cookie': cookie_name,
                    'description': f"Cookie '{cookie_name}' missing HttpOnly flag",
                    'recommendation': 'Add HttpOnly flag to protect from XSS attacks'
                })
        
        return len(issues) > 0, issues
