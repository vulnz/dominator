"""
Bruteforce attack detection and execution logic
"""

import requests
import time
from typing import List, Dict, Any, Tuple

class BruteforceDetector:
    """Bruteforce attack detection logic"""
    
    @staticmethod
    def get_login_indicators() -> List[str]:
        """Get indicators that suggest a login page"""
        return [
            'login', 'signin', 'sign-in', 'log-in', 'auth', 'authenticate',
            'password', 'username', 'user', 'email', 'admin', 'administrator',
            'panel', 'dashboard', 'control', 'manager', 'staff'
        ]
    
    @staticmethod
    def get_success_indicators() -> List[str]:
        """Get indicators of successful login"""
        return [
            'welcome', 'dashboard', 'logout', 'profile', 'settings',
            'admin panel', 'control panel', 'management', 'успешно',
            'добро пожаловать', 'панель управления', 'выход'
        ]
    
    @staticmethod
    def get_failure_indicators() -> List[str]:
        """Get indicators of failed login"""
        return [
            'invalid', 'incorrect', 'wrong', 'failed', 'error', 'denied',
            'неверный', 'ошибка', 'неправильный', 'отказано'
        ]
    
    @staticmethod
    def detect_login_form(response_text: str, url: str) -> Tuple[bool, Dict[str, Any]]:
        """
        Detect login form in response
        Returns (has_login_form, form_info)
        """
        import re
        
        # Look for password input fields
        password_patterns = [
            r'<input[^>]*type=["\']?password["\']?[^>]*>',
            r'<input[^>]*name=["\']?[^"\']*pass[^"\']*["\']?[^>]*>',
            r'<input[^>]*id=["\']?[^"\']*pass[^"\']*["\']?[^>]*>'
        ]
        
        has_password_field = False
        for pattern in password_patterns:
            if re.search(pattern, response_text, re.IGNORECASE):
                has_password_field = True
                break
        
        if not has_password_field:
            return False, {}
        
        # Extract form details
        form_pattern = r'<form[^>]*>(.*?)</form>'
        forms = re.findall(form_pattern, response_text, re.IGNORECASE | re.DOTALL)
        
        for form_content in forms:
            if 'password' in form_content.lower():
                # Extract form action
                action_match = re.search(r'action=["\']?([^"\'>\s]+)["\']?', form_content, re.IGNORECASE)
                action = action_match.group(1) if action_match else ''
                
                # Extract method
                method_match = re.search(r'method=["\']?([^"\'>\s]+)["\']?', form_content, re.IGNORECASE)
                method = method_match.group(1).upper() if method_match else 'POST'
                
                # Extract input fields
                input_pattern = r'<input[^>]*name=["\']?([^"\'>\s]+)["\']?[^>]*>'
                inputs = re.findall(input_pattern, form_content, re.IGNORECASE)
                
                # Find username and password fields
                username_field = None
                password_field = None
                
                for input_name in inputs:
                    input_lower = input_name.lower()
                    if 'pass' in input_lower:
                        password_field = input_name
                    elif any(user_word in input_lower for user_word in ['user', 'login', 'email', 'name']):
                        username_field = input_name
                
                if password_field:
                    return True, {
                        'action': action,
                        'method': method,
                        'username_field': username_field,
                        'password_field': password_field,
                        'all_inputs': inputs,
                        'form_content': form_content
                    }
        
        return False, {}
    
    @staticmethod
    def attempt_login(url: str, form_info: Dict[str, Any], username: str, password: str, 
                     headers: Dict[str, str] = None, timeout: int = 10) -> Tuple[bool, str, str]:
        """
        Attempt login with given credentials
        Returns (success, response_text, evidence)
        """
        if not form_info or not form_info.get('password_field'):
            return False, "", "No login form found"
        
        # Build form URL
        action = form_info.get('action', '')
        if action.startswith('/'):
            from urllib.parse import urlparse
            parsed = urlparse(url)
            form_url = f"{parsed.scheme}://{parsed.netloc}{action}"
        elif action.startswith('http'):
            form_url = action
        else:
            form_url = f"{url.rstrip('/')}/{action}" if action else url
        
        # Prepare form data
        form_data = {}
        
        # Add username if field exists
        if form_info.get('username_field'):
            form_data[form_info['username_field']] = username
        
        # Add password
        form_data[form_info['password_field']] = password
        
        # Add other form fields with default values
        for input_name in form_info.get('all_inputs', []):
            if input_name not in form_data:
                # Skip submit buttons and hidden fields with specific patterns
                input_lower = input_name.lower()
                if 'submit' in input_lower or 'button' in input_lower:
                    continue
                elif 'csrf' in input_lower or 'token' in input_lower:
                    form_data[input_name] = 'test_token'
                else:
                    form_data[input_name] = 'test'
        
        try:
            method = form_info.get('method', 'POST').upper()
            
            if method == 'POST':
                response = requests.post(
                    form_url,
                    data=form_data,
                    headers=headers or {},
                    timeout=timeout,
                    verify=False,
                    allow_redirects=True
                )
            else:
                response = requests.get(
                    form_url,
                    params=form_data,
                    headers=headers or {},
                    timeout=timeout,
                    verify=False,
                    allow_redirects=True
                )
            
            # Analyze response for success/failure
            response_lower = response.text.lower()
            
            # Check for success indicators
            success_indicators = BruteforceDetector.get_success_indicators()
            success_found = sum(1 for indicator in success_indicators if indicator in response_lower)
            
            # Check for failure indicators
            failure_indicators = BruteforceDetector.get_failure_indicators()
            failure_found = sum(1 for indicator in failure_indicators if indicator in response_lower)
            
            # Determine success based on indicators and response code
            if response.status_code in [200, 302, 303] and success_found > failure_found:
                evidence = f"Login successful - Status: {response.status_code}, Success indicators: {success_found}"
                return True, response.text, evidence
            elif failure_found > 0:
                evidence = f"Login failed - Status: {response.status_code}, Failure indicators: {failure_found}"
                return False, response.text, evidence
            else:
                evidence = f"Login result unclear - Status: {response.status_code}"
                return False, response.text, evidence
                
        except Exception as e:
            return False, "", f"Request failed: {str(e)}"
    
    @staticmethod
    def load_credentials(username_file: str = "wordlists/usernames.txt", 
                        password_file: str = "wordlists/passwords.txt") -> Tuple[List[str], List[str]]:
        """Load usernames and passwords from files"""
        usernames = []
        passwords = []
        
        try:
            with open(username_file, 'r', encoding='utf-8') as f:
                usernames = [line.strip() for line in f if line.strip()]
        except FileNotFoundError:
            # Default usernames if file not found
            usernames = [
                'admin', 'administrator', 'root', 'user', 'test', 'guest',
                'demo', 'manager', 'operator', 'support', 'service'
            ]
        
        try:
            with open(password_file, 'r', encoding='utf-8') as f:
                passwords = [line.strip() for line in f if line.strip()]
        except FileNotFoundError:
            # Default passwords if file not found
            passwords = [
                'admin', 'password', '123456', 'admin123', 'root', 'test',
                'guest', 'demo', 'manager', '12345', 'qwerty', 'password123'
            ]
        
        return usernames, passwords
    
    @staticmethod
    def get_remediation_advice() -> str:
        """Get remediation advice for bruteforce vulnerabilities"""
        return (
            "Implement account lockout after failed attempts. "
            "Use strong password policies. Implement CAPTCHA after failed attempts. "
            "Use multi-factor authentication (MFA). Monitor and log authentication attempts. "
            "Implement rate limiting for login attempts."
        )
