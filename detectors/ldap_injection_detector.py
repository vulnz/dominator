"""
LDAP Injection vulnerability detection logic
"""

import re
from typing import Tuple, List, Dict, Any

class LDAPInjectionDetector:
    """LDAP Injection vulnerability detection logic"""
    
    @staticmethod
    def get_ldap_error_patterns() -> List[str]:
        """Get LDAP error patterns"""
        return [
            'ldap_search', 'ldap_bind', 'ldap_connect',
            'Invalid DN syntax', 'Bad search filter',
            'LDAP: error code', 'javax.naming.directory',
            'com.sun.jndi.ldap', 'LdapException',
            'SearchResult', 'NamingException',
            'ldap://', 'ldaps://',
            'objectClass=', 'distinguishedName',
            'cn=', 'ou=', 'dc=', 'uid='
        ]
    
    @staticmethod
    def detect_ldap_injection(response_text: str, response_code: int, payload: str) -> bool:
        """
        Detect LDAP injection vulnerability
        Returns True if LDAP injection is detected
        """
        if response_code >= 500:
            return False
        
        response_lower = response_text.lower()
        patterns = LDAPInjectionDetector.get_ldap_error_patterns()
        
        # Check for LDAP-specific errors or responses
        found_patterns = 0
        for pattern in patterns:
            if pattern.lower() in response_lower:
                found_patterns += 1
        
        # Need multiple indicators for confidence
        if found_patterns >= 2:
            return True
        
        # Check for LDAP injection-specific patterns
        ldap_patterns = [
            r'ldap_search.*error',
            r'invalid dn syntax',
            r'bad search filter',
            r'ldap: error code \d+',
            r'javax\.naming\.directory\.',
            r'objectclass=.*person'
        ]
        
        for pattern in ldap_patterns:
            if re.search(pattern, response_text, re.IGNORECASE):
                return True
        
        return False
    
    @staticmethod
    def get_evidence(payload: str, response_text: str) -> str:
        """Get evidence of LDAP injection vulnerability"""
        patterns = LDAPInjectionDetector.get_ldap_error_patterns()
        found_patterns = []
        
        response_lower = response_text.lower()
        for pattern in patterns:
            if pattern.lower() in response_lower:
                found_patterns.append(pattern)
        
        if found_patterns:
            return f"LDAP injection detected. Found LDAP indicators: {', '.join(found_patterns[:3])}"
        
        return "LDAP injection vulnerability detected based on response patterns"
    
    @staticmethod
    def get_response_snippet(payload: str, response_text: str) -> str:
        """Get relevant response snippet"""
        patterns = LDAPInjectionDetector.get_ldap_error_patterns()
        
        for pattern in patterns:
            if pattern.lower() in response_text.lower():
                start = max(0, response_text.lower().find(pattern.lower()) - 50)
                end = min(len(response_text), start + 200)
                return response_text[start:end]
        
        return response_text[:200]
    
    @staticmethod
    def get_remediation_advice() -> str:
        """Get remediation advice for LDAP injection vulnerabilities"""
        return (
            "Use parameterized LDAP queries and proper input validation. "
            "Escape special LDAP characters in user input. "
            "Implement proper access controls and use least privilege principles. "
            "Consider using prepared statements for LDAP queries."
        )
