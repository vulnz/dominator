"""
CORS (Cross-Origin Resource Sharing) misconfiguration detection logic
"""

import re
from typing import Tuple, List, Dict, Any

class CORSDetector:
    """CORS misconfiguration detection logic"""
    
    @staticmethod
    def get_cors_headers() -> List[str]:
        """Get CORS-related headers"""
        return [
            'Access-Control-Allow-Origin',
            'Access-Control-Allow-Credentials',
            'Access-Control-Allow-Methods',
            'Access-Control-Allow-Headers',
            'Access-Control-Expose-Headers',
            'Access-Control-Max-Age'
        ]
    
    @staticmethod
    def detect_cors_misconfiguration(response_headers: Dict[str, str], request_origin: str = None) -> Tuple[bool, str, str, List[Dict[str, Any]]]:
        """
        Detect CORS misconfigurations
        Returns: (is_vulnerable, evidence, severity, issues)
        """
        issues = []
        
        # Check for Access-Control-Allow-Origin header
        allow_origin = response_headers.get('Access-Control-Allow-Origin', '')
        allow_credentials = response_headers.get('Access-Control-Allow-Credentials', '').lower()
        
        # Critical: Wildcard with credentials
        if allow_origin == '*' and allow_credentials == 'true':
            issues.append({
                'issue': 'Wildcard Origin with Credentials',
                'severity': 'High',
                'description': 'Access-Control-Allow-Origin is set to * while Access-Control-Allow-Credentials is true'
            })
        
        # High: Wildcard origin
        elif allow_origin == '*':
            issues.append({
                'issue': 'Wildcard Origin',
                'severity': 'Medium',
                'description': 'Access-Control-Allow-Origin is set to * allowing any origin'
            })
        
        # Check for null origin
        if allow_origin.lower() == 'null':
            issues.append({
                'issue': 'Null Origin Allowed',
                'severity': 'High',
                'description': 'Access-Control-Allow-Origin allows null origin which can be exploited'
            })
        
        # Check for reflected origin (if we have request origin)
        if request_origin and allow_origin == request_origin:
            issues.append({
                'issue': 'Origin Reflection',
                'severity': 'High',
                'description': 'Server reflects the Origin header value without validation'
            })
        
        # Check for overly permissive methods
        allow_methods = response_headers.get('Access-Control-Allow-Methods', '').upper()
        dangerous_methods = ['DELETE', 'PUT', 'PATCH']
        
        for method in dangerous_methods:
            if method in allow_methods:
                issues.append({
                    'issue': f'Dangerous Method Allowed: {method}',
                    'severity': 'Medium',
                    'description': f'CORS allows potentially dangerous HTTP method: {method}'
                })
        
        # Check for overly permissive headers
        allow_headers = response_headers.get('Access-Control-Allow-Headers', '').lower()
        if 'authorization' in allow_headers or '*' in allow_headers:
            issues.append({
                'issue': 'Sensitive Headers Allowed',
                'severity': 'Medium',
                'description': 'CORS allows sensitive headers like Authorization'
            })
        
        if issues:
            severity = 'High' if any(issue['severity'] == 'High' for issue in issues) else 'Medium'
            evidence = f"CORS misconfiguration detected: {', '.join([issue['issue'] for issue in issues])}"
            return True, evidence, severity, issues
        
        return False, "No CORS misconfigurations detected", "None", []
    
    @staticmethod
    def get_evidence(issues: List[Dict[str, Any]], response_headers: Dict[str, str]) -> str:
        """Get detailed evidence of CORS misconfiguration"""
        evidence_parts = []
        
        for issue in issues:
            evidence_parts.append(f"{issue['issue']}: {issue['description']}")
        
        # Add relevant header values
        cors_headers = CORSDetector.get_cors_headers()
        header_info = []
        
        for header in cors_headers:
            if header in response_headers:
                header_info.append(f"{header}: {response_headers[header]}")
        
        if header_info:
            evidence_parts.append(f"CORS headers: {'; '.join(header_info)}")
        
        return ". ".join(evidence_parts)
    
    @staticmethod
    def get_remediation_advice(issue_type: str) -> str:
        """Get remediation advice for CORS issues"""
        advice = {
            'Wildcard Origin with Credentials': (
                "Never use Access-Control-Allow-Origin: * with Access-Control-Allow-Credentials: true. "
                "Specify exact origins that should be allowed to make credentialed requests."
            ),
            'Wildcard Origin': (
                "Avoid using Access-Control-Allow-Origin: * in production. "
                "Specify exact origins that should be allowed to access the resource."
            ),
            'Null Origin Allowed': (
                "Never allow null origin as it can be easily exploited. "
                "Remove 'null' from allowed origins and specify exact domains."
            ),
            'Origin Reflection': (
                "Do not reflect the Origin header without proper validation. "
                "Maintain a whitelist of allowed origins and validate against it."
            ),
            'Dangerous Method Allowed': (
                "Restrict CORS to only necessary HTTP methods. "
                "Avoid allowing dangerous methods like DELETE, PUT, PATCH unless absolutely necessary."
            ),
            'Sensitive Headers Allowed': (
                "Be restrictive with Access-Control-Allow-Headers. "
                "Only allow headers that are actually needed by your application."
            )
        }
        
        return advice.get(issue_type, "Review and tighten CORS configuration according to security best practices.")
