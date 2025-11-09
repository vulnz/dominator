"""
CSRF (Cross-Site Request Forgery) vulnerability detector
"""

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
        """Detect CSRF vulnerabilities in forms with enhanced login form detection and detailed form analysis"""
        if not response_text:
            return False, "", "", {}

        # Find all forms in the response with detailed extraction
        form_pattern = r'<form([^>]*)>(.*?)</form>'
        forms = re.findall(form_pattern, response_text, re.IGNORECASE | re.DOTALL)
        
        vulnerable_forms = []
        login_forms = []
        csrf_indicators = CSRFDetector.get_csrf_indicators()
        form_details = []
        
        for form_attrs, form_content in forms:
            # Extract form method
            method_match = re.search(r'method\s*=\s*["\']?(get|post|put|delete)["\']?', form_attrs, re.IGNORECASE)
            method = method_match.group(1).upper() if method_match else "GET"
            
            # Extract form action
            action_match = re.search(r'action\s*=\s*["\']?([^"\'>\s]+)["\']?', form_attrs, re.IGNORECASE)
            action = action_match.group(1) if action_match else "current page"
            
            # Extract form inputs
            input_pattern = r'<input([^>]*)>'
            inputs = re.findall(input_pattern, form_content, re.IGNORECASE)
            
            input_details = []
            for input_attrs in inputs:
                name_match = re.search(r'name\s*=\s*["\']?([^"\'>\s]+)["\']?', input_attrs, re.IGNORECASE)
                type_match = re.search(r'type\s*=\s*["\']?([^"\'>\s]+)["\']?', input_attrs, re.IGNORECASE)
                
                input_name = name_match.group(1) if name_match else "unnamed"
                input_type = type_match.group(1) if type_match else "text"
                
                input_details.append({
                    'name': input_name,
                    'type': input_type
                })
            
            # Check if form has CSRF protection
            has_csrf_token = False
            csrf_token_found = None
            for indicator in csrf_indicators:
                if re.search(rf'name\s*=\s*["\']?{indicator}["\']?', form_content, re.IGNORECASE):
                    has_csrf_token = True
                    csrf_token_found = indicator
                    break
            
            # Check if this is a login form
            is_login_form = CSRFDetector._is_login_form(form_content)
            
            # Store detailed form information
            form_detail = {
                'method': method,
                'action': action,
                'inputs': input_details,
                'has_csrf_token': has_csrf_token,
                'csrf_token': csrf_token_found,
                'is_login_form': is_login_form,
                'input_count': len(input_details)
            }
            form_details.append(form_detail)
            
            # Check if form modifies data (POST, PUT, DELETE methods)
            if method in ['POST', 'PUT', 'DELETE'] and not has_csrf_token:
                form_info = f"Form with action '{action}' (method: {method}, inputs: {len(input_details)})"
                
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
                'total_forms_affected': len(all_vulnerable),
                'form_details': form_details,
                'total_forms_found': len(forms)
            }

        return False, "", "", {
            'form_details': form_details,
            'total_forms_found': len(forms)
        }
    
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
