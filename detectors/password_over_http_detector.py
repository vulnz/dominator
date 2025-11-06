"""
Password over HTTP detection logic
"""

import re
from typing import Dict, Any, List, Tuple
from urllib.parse import urlparse

class PasswordOverHTTPDetector:
    """Password over HTTP vulnerability detection logic"""
    
    @staticmethod
    def get_password_field_patterns() -> List[str]:
        """Get patterns that indicate password fields"""
        return [
            r'<input[^>]*type\s*=\s*["\']password["\'][^>]*>',
            r'<input[^>]*name\s*=\s*["\'].*?pass.*?["\'][^>]*>',
            r'<input[^>]*name\s*=\s*["\'].*?pwd.*?["\'][^>]*>',
            r'<input[^>]*id\s*=\s*["\'].*?pass.*?["\'][^>]*>',
            r'<input[^>]*id\s*=\s*["\'].*?pwd.*?["\'][^>]*>'
        ]
    
    @staticmethod
    def get_login_form_patterns() -> List[str]:
        """Get patterns that indicate login forms"""
        return [
            r'<form[^>]*action\s*=\s*["\'][^"\']*login[^"\']*["\'][^>]*>',
            r'<form[^>]*action\s*=\s*["\'][^"\']*auth[^"\']*["\'][^>]*>',
            r'<form[^>]*action\s*=\s*["\'][^"\']*signin[^"\']*["\'][^>]*>',
            r'<form[^>]*name\s*=\s*["\'].*?login.*?["\'][^>]*>',
            r'<form[^>]*id\s*=\s*["\'].*?login.*?["\'][^>]*>'
        ]
    
    @staticmethod
    def detect_password_over_http(url: str, response_text: str, response_code: int) -> Tuple[bool, str, List[Dict[str, str]]]:
        """
        Detect password transmission over HTTP
        
        Args:
            url: The URL being tested
            response_text: HTTP response text
            response_code: HTTP response code
        
        Returns:
            Tuple of (is_vulnerable, evidence, forms_found)
        """
        parsed_url = urlparse(url)
        
        # Only check HTTP URLs
        if parsed_url.scheme.lower() != 'http':
            return False, "URL uses HTTPS - secure", []
        
        if response_code >= 400:
            return False, f"Error response ({response_code})", []
        
        password_patterns = PasswordOverHTTPDetector.get_password_field_patterns()
        login_form_patterns = PasswordOverHTTPDetector.get_login_form_patterns()
        
        forms_found = []
        has_password_field = False
        
        # Check for password fields
        for pattern in password_patterns:
            matches = re.finditer(pattern, response_text, re.IGNORECASE)
            for match in matches:
                has_password_field = True
                
                # Extract form context
                form_start = response_text.rfind('<form', 0, match.start())
                if form_start != -1:
                    form_end = response_text.find('</form>', match.end())
                    if form_end != -1:
                        form_content = response_text[form_start:form_end + 7]
                        
                        # Extract form action
                        action_match = re.search(r'action\s*=\s*["\']([^"\']*)["\']', form_content, re.IGNORECASE)
                        action = action_match.group(1) if action_match else ''
                        
                        # Extract form method
                        method_match = re.search(r'method\s*=\s*["\']([^"\']*)["\']', form_content, re.IGNORECASE)
                        method = method_match.group(1).upper() if method_match else 'GET'
                        
                        forms_found.append({
                            'action': action,
                            'method': method,
                            'password_field': match.group(0)
                        })
        
        if has_password_field:
            evidence = f"Password field found on HTTP page: {url}"
            return True, evidence, forms_found
        
        return False, "No password fields found", []
    
    @staticmethod
    def get_evidence(forms_found: List[Dict[str, str]]) -> str:
        """Get evidence of password over HTTP vulnerability"""
        if not forms_found:
            return "Password fields detected on HTTP page"
        
        evidence_parts = []
        for form in forms_found:
            action = form.get('action', '')
            method = form.get('method', 'GET')
            evidence_parts.append(f"Form with action '{action}' (method: {method}) contains password field")
        
        return "; ".join(evidence_parts)
    
    @staticmethod
    def get_remediation_advice() -> str:
        """Get remediation advice for password over HTTP"""
        return (
            "Implement HTTPS/TLS encryption for all pages containing password fields. "
            "Ensure login forms and password change forms are served over HTTPS. "
            "Consider implementing HTTP Strict Transport Security (HSTS) headers."
        )
