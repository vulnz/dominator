"""
Weak Authentication detector
Detects weak passwords and authentication bypass vulnerabilities
"""

import re
from typing import List, Dict, Any, Tuple

class WeakAuthenticationDetector:
    """Weak Authentication vulnerability detection logic"""
    
    @staticmethod
    def get_weak_credentials() -> List[Dict[str, str]]:
        """Get common weak credential combinations from TXT file or fallback"""
        try:
            # Try to load from TXT file first
            from utils.payload_loader import PayloadLoader
            credentials_data = PayloadLoader.load_payloads('weak_credentials')
            
            weak_creds = []
            for line in credentials_data:
                if ':' in line:
                    username, password = line.split(':', 1)
                    weak_creds.append({'username': username.strip(), 'password': password.strip()})
            
            if weak_creds:
                return weak_creds
        except:
            pass
        
        # Fallback to hardcoded list if file not available
        return [
            {'username': 'admin', 'password': 'admin'},
            {'username': 'admin', 'password': 'password'},
            {'username': 'admin', 'password': '123456'},
            {'username': 'admin', 'password': 'admin123'},
            {'username': 'test', 'password': 'test'},
            {'username': 'guest', 'password': 'guest'},
            {'username': 'user', 'password': 'user'},
            {'username': 'root', 'password': 'root'},
            {'username': 'administrator', 'password': 'administrator'},
            {'username': 'demo', 'password': 'demo'},
            {'username': 'sa', 'password': ''},
            {'username': 'admin', 'password': ''},
            {'username': '', 'password': 'admin'},
            {'username': 'admin', 'password': 'root'},
            {'username': 'root', 'password': 'admin'},
            {'username': 'mysql', 'password': 'mysql'},
            {'username': 'oracle', 'password': 'oracle'},
            {'username': 'postgres', 'password': 'postgres'},
            {'username': 'tomcat', 'password': 'tomcat'}
        ]
    
    @staticmethod
    def get_auth_success_indicators() -> List[str]:
        """Get authentication success indicators"""
        return [
            'welcome',
            'dashboard',
            'logout',
            'profile',
            'settings',
            'admin panel',
            'control panel',
            'successfully logged in',
            'login successful',
            'authentication successful',
            'session established',
            'user authenticated'
        ]
    
    @staticmethod
    def get_auth_failure_indicators() -> List[str]:
        """Get authentication failure indicators"""
        return [
            'invalid username',
            'invalid password',
            'incorrect username',
            'incorrect password',
            'login failed',
            'authentication failed',
            'access denied',
            'unauthorized',
            'wrong credentials',
            'bad credentials',
            'login error'
        ]
    
    @staticmethod
    def detect_weak_authentication(username: str, password: str, response_text: str, response_code: int, 
                                 baseline_response: str = "") -> Tuple[bool, str, str, Dict[str, Any]]:
        """Detect weak authentication vulnerabilities with enhanced analysis"""
        if response_code not in [200, 201, 202, 302, 301]:
            return False, "", "", {}
        
        success_indicators = WeakAuthenticationDetector.get_auth_success_indicators()
        failure_indicators = WeakAuthenticationDetector.get_auth_failure_indicators()
        
        response_lower = response_text.lower()
        baseline_lower = baseline_response.lower() if baseline_response else ""
        
        # Check for authentication success
        success_found = any(indicator in response_lower for indicator in success_indicators)
        failure_found = any(indicator in response_lower for indicator in failure_indicators)
        
        # Enhanced success detection via response analysis
        significant_difference = False
        if baseline_response:
            # Compare response lengths
            length_diff = abs(len(response_text) - len(baseline_response))
            if length_diff > 100:
                significant_difference = True
            
            # Check for new content in response that suggests successful login
            if not failure_found and len(response_text) > len(baseline_response):
                # Look for admin/dashboard content that wasn't in baseline
                admin_content = ['admin', 'dashboard', 'control', 'panel', 'logout', 'settings']
                new_admin_content = any(content in response_lower and content not in baseline_lower 
                                      for content in admin_content)
                if new_admin_content:
                    significant_difference = True
        
        # Determine if login was successful
        login_successful = (success_found and not failure_found) or significant_difference
        
        if login_successful:
            # Check if credentials are weak
            weak_creds = WeakAuthenticationDetector.get_weak_credentials()
            for cred in weak_creds:
                if (username.lower() == cred['username'].lower() and 
                    password.lower() == cred['password'].lower()):
                    
                    severity = "Critical" if cred['username'] == 'admin' else "High"
                    cvss = "9.8" if cred['username'] == 'admin' else "8.8"
                    
                    return True, f"Weak credentials detected: {username}/{password}", severity, {
                        'cwe': 'CWE-521',
                        'cvss': cvss,
                        'owasp': 'A07:2021 – Identification and Authentication Failures',
                        'recommendation': 'Implement strong password policies and multi-factor authentication.'
                    }
            
            # Check for empty or very weak passwords
            if not password or len(password) < 4:
                return True, f"Very weak password detected: '{password}'", "Critical", {
                    'cwe': 'CWE-521',
                    'cvss': '9.8',
                    'owasp': 'A07:2021 – Identification and Authentication Failures',
                    'recommendation': 'Implement strong password policies with minimum length requirements.'
                }
            
            # If login successful but credentials not in common list, still report as potential issue
            if significant_difference:
                return True, f"Potential weak credentials detected via response analysis: {username}/{password}", "Medium", {
                    'cwe': 'CWE-521',
                    'cvss': '6.5',
                    'owasp': 'A07:2021 – Identification and Authentication Failures',
                    'recommendation': 'Verify if these credentials are appropriately strong and implement MFA.'
                }
        
        return False, "", "", {}
    
    @staticmethod
    def detect_auth_bypass(payload: str, response_text: str, response_code: int) -> Tuple[bool, str, str, Dict[str, Any]]:
        """Detect authentication bypass vulnerabilities"""
        if response_code not in [200, 201, 202, 302, 301]:
            return False, "", "", {}
        
        # SQL injection based auth bypass
        sql_bypass_patterns = [
            r"'\s*or\s*'1'\s*=\s*'1",
            r"'\s*or\s*1\s*=\s*1",
            r"admin'\s*--",
            r"admin'\s*#",
            r"'\s*or\s*'a'\s*=\s*'a"
        ]
        
        for pattern in sql_bypass_patterns:
            if re.search(pattern, payload, re.IGNORECASE):
                success_indicators = WeakAuthenticationDetector.get_auth_success_indicators()
                if any(indicator in response_text.lower() for indicator in success_indicators):
                    return True, f"SQL injection authentication bypass detected: {pattern}", "Critical", {
                        'cwe': 'CWE-89',
                        'cvss': '9.8',
                        'owasp': 'A03:2021 – Injection',
                        'recommendation': 'Use parameterized queries for authentication. Implement proper input validation.'
                    }
        
        return False, "", "", {}
    
    @staticmethod
    def get_auth_bypass_payloads() -> List[Dict[str, str]]:
        """Get authentication bypass test payloads"""
        return [
            # SQL injection bypasses
            {'username': "admin' or '1'='1' --", 'password': 'anything'},
            {'username': "admin' or 1=1 --", 'password': 'anything'},
            {'username': "admin'/*", 'password': '*/or/**/1=1#'},
            {'username': "' or 'a'='a", 'password': "' or 'a'='a"},
            {'username': "admin' --", 'password': ''},
            {'username': "admin' #", 'password': ''},
            
            # NoSQL injection bypasses
            {'username': '{"$ne": null}', 'password': '{"$ne": null}'},
            {'username': '{"$gt": ""}', 'password': '{"$gt": ""}'},
            
            # LDAP injection bypasses
            {'username': 'admin)(&)', 'password': 'anything'},
            {'username': 'admin)(|(objectClass=*))', 'password': 'anything'}
        ]
