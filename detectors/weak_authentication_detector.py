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
        """Get common weak credential combinations"""
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
            {'username': '', 'password': ''},  # Empty credentials
            {'username': 'admin', 'password': ''},  # Empty password
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
    def detect_weak_authentication(username: str, password: str, response_text: str, response_code: int) -> Tuple[bool, str, str, Dict[str, Any]]:
        """Detect weak authentication vulnerabilities"""
        if response_code not in [200, 201, 202, 302, 301]:
            return False, "", "", {}
        
        success_indicators = WeakAuthenticationDetector.get_auth_success_indicators()
        failure_indicators = WeakAuthenticationDetector.get_auth_failure_indicators()
        
        response_lower = response_text.lower()
        
        # Check for authentication success
        success_found = any(indicator in response_lower for indicator in success_indicators)
        failure_found = any(indicator in response_lower for indicator in failure_indicators)
        
        if success_found and not failure_found:
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
