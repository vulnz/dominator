"""
Security headers detector
"""

from typing import Tuple, List, Dict, Any

class SecurityHeadersDetector:
    """Security headers detection logic"""
    
    @staticmethod
    def detect_missing_security_headers(response_headers: dict) -> List[Dict[str, Any]]:
        """
        Detect missing security headers
        Returns list of missing headers with details
        """
        missing_headers = []
        
        # Convert headers to lowercase for case-insensitive comparison
        headers_lower = {k.lower(): v for k, v in response_headers.items()}
        
        # Check each security header
        security_headers = SecurityHeadersDetector.get_security_headers()
        
        for header_info in security_headers:
            header_name = header_info['name'].lower()
            
            if header_name not in headers_lower:
                missing_headers.append({
                    'header': header_info['name'],
                    'description': header_info['description'],
                    'severity': header_info['severity'],
                    'recommendation': header_info['recommendation']
                })
            else:
                # Check if header value is secure
                header_value = headers_lower[header_name]
                if 'insecure_values' in header_info:
                    for insecure_value in header_info['insecure_values']:
                        if insecure_value.lower() in header_value.lower():
                            missing_headers.append({
                                'header': header_info['name'],
                                'description': f"{header_info['description']} (insecure value: {header_value})",
                                'severity': header_info['severity'],
                                'recommendation': header_info['recommendation'],
                                'current_value': header_value
                            })
                            break
        
        return missing_headers
    
    @staticmethod
    def get_security_headers() -> List[Dict[str, Any]]:
        """Get list of important security headers"""
        return [
            {
                'name': 'X-Frame-Options',
                'description': 'Prevents clickjacking attacks',
                'severity': 'Low',
                'recommendation': 'Set to DENY or SAMEORIGIN',
                'insecure_values': ['ALLOWALL']
            },
            {
                'name': 'X-Content-Type-Options',
                'description': 'Prevents MIME type sniffing',
                'severity': 'Low',
                'recommendation': 'Set to nosniff'
            },
            {
                'name': 'X-XSS-Protection',
                'description': 'Enables XSS filtering in browsers',
                'severity': 'Low',
                'recommendation': 'Set to 1; mode=block',
                'insecure_values': ['0']
            },
            {
                'name': 'Strict-Transport-Security',
                'description': 'Enforces HTTPS connections',
                'severity': 'Low',
                'recommendation': 'Set to max-age=31536000; includeSubDomains'
            },
            {
                'name': 'Content-Security-Policy',
                'description': 'Prevents XSS and data injection attacks',
                'severity': 'Low',
                'recommendation': 'Configure appropriate CSP policy',
                'insecure_values': ['unsafe-inline', 'unsafe-eval', '*']
            },
            {
                'name': 'Referrer-Policy',
                'description': 'Controls referrer information',
                'severity': 'Low',
                'recommendation': 'Set to strict-origin-when-cross-origin or no-referrer'
            },
            {
                'name': 'Permissions-Policy',
                'description': 'Controls browser features',
                'severity': 'Low',
                'recommendation': 'Configure to disable unnecessary features'
            },
            {
                'name': 'X-Permitted-Cross-Domain-Policies',
                'description': 'Controls cross-domain policies',
                'severity': 'Low',
                'recommendation': 'Set to none or master-only'
            }
        ]
    
    @staticmethod
    def detect_insecure_cookies(response_headers: dict) -> List[Dict[str, Any]]:
        """
        Detect cookies without security flags
        Returns list of insecure cookies
        """
        insecure_cookies = []
        
        # Get all Set-Cookie headers
        set_cookie_headers = []
        for header_name, header_value in response_headers.items():
            if header_name.lower() == 'set-cookie':
                if isinstance(header_value, list):
                    set_cookie_headers.extend(header_value)
                else:
                    set_cookie_headers.append(header_value)
        
        for cookie_header in set_cookie_headers:
            cookie_analysis = SecurityHeadersDetector._analyze_cookie(cookie_header)
            if cookie_analysis['issues']:
                insecure_cookies.append(cookie_analysis)
        
        return insecure_cookies
    
    @staticmethod
    def _analyze_cookie(cookie_header: str) -> Dict[str, Any]:
        """Analyze a single cookie for security issues"""
        cookie_lower = cookie_header.lower()
        
        # Extract cookie name
        cookie_name = cookie_header.split('=')[0].strip() if '=' in cookie_header else 'unknown'
        
        issues = []
        
        # Check for missing Secure flag
        if 'secure' not in cookie_lower:
            issues.append({
                'issue': 'Missing Secure flag',
                'severity': 'Low',
                'description': 'Cookie can be transmitted over unencrypted connections'
            })
        
        # Check for missing HttpOnly flag
        if 'httponly' not in cookie_lower:
            issues.append({
                'issue': 'Missing HttpOnly flag',
                'severity': 'Low',
                'description': 'Cookie accessible via JavaScript (XSS risk)'
            })
        
        # Check for missing SameSite attribute
        if 'samesite' not in cookie_lower:
            issues.append({
                'issue': 'Missing SameSite attribute',
                'severity': 'Low',
                'description': 'Cookie vulnerable to CSRF attacks'
            })
        
        # Check for weak SameSite value
        elif 'samesite=none' in cookie_lower:
            issues.append({
                'issue': 'Weak SameSite value',
                'severity': 'Low',
                'description': 'SameSite=None allows cross-site requests'
            })
        
        return {
            'cookie_name': cookie_name,
            'cookie_header': cookie_header,
            'issues': issues
        }
    
    @staticmethod
    def get_evidence(missing_headers: List[Dict[str, Any]], insecure_cookies: List[Dict[str, Any]]) -> str:
        """Get evidence for security headers issues"""
        evidence_parts = []
        
        if missing_headers:
            header_names = [h['header'] for h in missing_headers]
            evidence_parts.append(f"Missing security headers: {', '.join(header_names)}")
        
        if insecure_cookies:
            cookie_issues = []
            for cookie in insecure_cookies:
                issues = [issue['issue'] for issue in cookie['issues']]
                cookie_issues.append(f"{cookie['cookie_name']}: {', '.join(issues)}")
            evidence_parts.append(f"Insecure cookies: {'; '.join(cookie_issues)}")
        
        return '; '.join(evidence_parts)
