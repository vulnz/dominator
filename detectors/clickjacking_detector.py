"""
Clickjacking vulnerability detection logic
"""

class ClickjackingDetector:
    """Clickjacking vulnerability detection logic"""
    
    @staticmethod
    def get_frame_options_headers() -> list:
        """Get frame options headers to check"""
        return [
            'x-frame-options',
            'content-security-policy'
        ]
    
    @staticmethod
    def detect_clickjacking(response_headers: dict) -> dict:
        """Detect clickjacking vulnerability"""
        result = {
            'vulnerable': False,
            'missing_headers': [],
            'weak_headers': [],
            'evidence': ''
        }
        
        headers_lower = {k.lower(): v.lower() for k, v in response_headers.items()}
        
        # Check X-Frame-Options header
        if 'x-frame-options' not in headers_lower:
            result['missing_headers'].append('X-Frame-Options')
            result['vulnerable'] = True
        else:
            xfo_value = headers_lower['x-frame-options']
            if xfo_value not in ['deny', 'sameorigin']:
                result['weak_headers'].append(f'X-Frame-Options: {xfo_value}')
                result['vulnerable'] = True
        
        # Check Content-Security-Policy for frame-ancestors
        if 'content-security-policy' in headers_lower:
            csp_value = headers_lower['content-security-policy']
            if 'frame-ancestors' not in csp_value:
                result['weak_headers'].append('CSP missing frame-ancestors directive')
                result['vulnerable'] = True
        else:
            result['missing_headers'].append('Content-Security-Policy')
        
        # Generate evidence
        if result['missing_headers']:
            result['evidence'] = f"Missing headers: {', '.join(result['missing_headers'])}"
        elif result['weak_headers']:
            result['evidence'] = f"Weak configuration: {', '.join(result['weak_headers'])}"
        
        return result
    
    @staticmethod
    def get_remediation_advice() -> str:
        """Get remediation advice for clickjacking"""
        return """
        To prevent clickjacking attacks:
        1. Add X-Frame-Options header with value 'DENY' or 'SAMEORIGIN'
        2. Implement Content-Security-Policy with frame-ancestors directive
        3. Use JavaScript frame-busting code as additional protection
        """
