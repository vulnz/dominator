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
        
        has_protection, protection_evidence = CSRFDetector.detect_csrf_protection(
            response_text, response_headers, form_data
        )
        
        # Look for forms that could be vulnerable
        form_patterns = [
            r'<form[^>]*method=["\']?post["\']?[^>]*>',
            r'<form[^>]*action=["\'][^"\']*["\'][^>]*>',
        ]
        
        forms_found = []
        for pattern in form_patterns:
            matches = re.findall(pattern, response_text, re.IGNORECASE)
            forms_found.extend(matches)
        
        # Only report vulnerability if we have forms AND no protection
        if not has_protection and forms_found:
            evidence = f"Found {len(forms_found)} form(s) without CSRF protection. {protection_evidence}"
            return True, evidence
        elif not has_protection and forms_found:
            evidence = f"No forms found that require CSRF protection. {protection_evidence}"
            return False, evidence
        else:
            evidence = f"CSRF protection appears to be implemented or no vulnerable forms found. {protection_evidence}"
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
