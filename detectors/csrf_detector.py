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
            'csrf_token',
            'csrf-token',
            '_token',
            'authenticity_token',
            'csrfmiddlewaretoken',
            'anti-csrf-token',
            '__RequestVerificationToken',
            'YII_CSRF_TOKEN',
            '_csrf',
            'csrf_param'
        ]
    
    @staticmethod
    def get_csrf_headers() -> List[str]:
        """Get CSRF protection headers"""
        return [
            'X-CSRF-Token',
            'X-CSRFToken',
            'X-XSRF-TOKEN',
            'X-Requested-With'
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
