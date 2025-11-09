"""
HTTP Parameter Pollution (HPP) vulnerability detector
"""

import re
from typing import Tuple, List, Dict, Any
from urllib.parse import parse_qs, urlparse

class HPPDetector:
    """HTTP Parameter Pollution detection logic"""
    
    @staticmethod
    def get_hpp_test_parameters() -> List[str]:
        """Get common parameters to test for HPP"""
        return [
            'id', 'user', 'username', 'email', 'search', 'query', 'q',
            'name', 'value', 'data', 'input', 'param', 'var', 'field',
            'action', 'cmd', 'command', 'page', 'file', 'path', 'url',
            'redirect', 'return', 'callback', 'next', 'goto', 'target'
        ]
    
    @staticmethod
    def get_hpp_payloads() -> List[Dict[str, Any]]:
        """Get HPP test payloads"""
        return [
            {
                'name': 'duplicate_numeric',
                'values': ['1', '2', '3'],
                'expected_behavior': 'parameter_confusion'
            },
            {
                'name': 'duplicate_string',
                'values': ['test', 'admin', 'user'],
                'expected_behavior': 'value_override'
            },
            {
                'name': 'duplicate_boolean',
                'values': ['true', 'false', '1'],
                'expected_behavior': 'logic_bypass'
            },
            {
                'name': 'duplicate_special',
                'values': ['', 'null', '0'],
                'expected_behavior': 'validation_bypass'
            },
            {
                'name': 'duplicate_injection',
                'values': ["'", '"', '<script>'],
                'expected_behavior': 'security_bypass'
            }
        ]
    
    @staticmethod
    def detect_hpp_vulnerability(url: str, response_text: str, response_code: int, 
                                original_response: str) -> Tuple[bool, str, str, Dict[str, Any]]:
        """Detect HTTP Parameter Pollution vulnerabilities"""
        if response_code >= 400:
            return False, "", "", {}
        
        # Check for different response behavior
        response_diff = HPPDetector._analyze_response_differences(
            original_response, response_text
        )
        
        if response_diff['significant_change']:
            evidence = f"HPP detected: {response_diff['change_type']} - {response_diff['details']}"
            
            # Determine severity based on change type
            severity = "Medium"
            if response_diff['change_type'] in ['authentication_bypass', 'authorization_bypass']:
                severity = "High"
            elif response_diff['change_type'] in ['parameter_confusion', 'logic_bypass']:
                severity = "Medium"
            else:
                severity = "Low"
            
            return True, evidence, severity, {
                'cwe': 'CWE-235',
                'cvss': '6.5' if severity == "High" else '4.3',
                'owasp': 'A03:2021 – Injection',
                'recommendation': 'Implement proper parameter handling and validation. Use parameter arrays or reject duplicate parameters.'
            }
        
        return False, "", "", {}
    
    @staticmethod
    def _analyze_response_differences(original: str, modified: str) -> Dict[str, Any]:
        """Analyze differences between original and modified responses"""
        result = {
            'significant_change': False,
            'change_type': 'none',
            'details': '',
            'confidence': 0.0
        }
        
        # Check content length difference
        length_diff = abs(len(modified) - len(original))
        if length_diff > 100:
            result['significant_change'] = True
            result['change_type'] = 'content_change'
            result['details'] = f'Content length changed by {length_diff} bytes'
            result['confidence'] = 0.7
        
        # Check for authentication/authorization indicators
        auth_indicators = [
            'login', 'admin', 'dashboard', 'profile', 'settings',
            'unauthorized', 'forbidden', 'access denied'
        ]
        
        original_lower = original.lower()
        modified_lower = modified.lower()
        
        original_auth = sum(1 for indicator in auth_indicators if indicator in original_lower)
        modified_auth = sum(1 for indicator in auth_indicators if indicator in modified_lower)
        
        if modified_auth > original_auth:
            result['significant_change'] = True
            result['change_type'] = 'authentication_bypass'
            result['details'] = 'Authentication/authorization content appeared'
            result['confidence'] = 0.9
        
        # Check for error message changes
        error_patterns = [
            'error', 'exception', 'warning', 'invalid', 'failed',
            'mysql', 'sql', 'database', 'query'
        ]
        
        original_errors = sum(1 for pattern in error_patterns if pattern in original_lower)
        modified_errors = sum(1 for pattern in error_patterns if pattern in modified_lower)
        
        if modified_errors != original_errors:
            result['significant_change'] = True
            result['change_type'] = 'parameter_confusion'
            result['details'] = f'Error patterns changed from {original_errors} to {modified_errors}'
            result['confidence'] = 0.8
        
        return result
    
    @staticmethod
    def get_evidence(change_type: str, details: str, url: str) -> str:
        """Get formatted evidence for HPP vulnerability"""
        return f"HTTP Parameter Pollution detected: {change_type}. {details}. URL: {url}"
    
    @staticmethod
    def get_response_snippet(response_text: str, max_length: int = 300) -> str:
        """Get response snippet for HPP analysis"""
        if len(response_text) > max_length:
            return response_text[:max_length] + "..."
        return response_text
    
    @staticmethod
    def get_remediation_advice() -> str:
        """Get remediation advice for HPP vulnerabilities"""
        return (
            "Implement proper parameter handling: "
            "1) Use parameter arrays for multiple values, "
            "2) Validate and sanitize all parameters, "
            "3) Reject requests with duplicate parameters, "
            "4) Use consistent parameter parsing across application layers."
        )
