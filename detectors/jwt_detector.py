"""
JWT (JSON Web Token) vulnerability detection logic
"""

import re
import json
import base64
from typing import Tuple, List, Dict, Any

class JWTDetector:
    """JWT vulnerability detection logic"""
    
    @staticmethod
    def get_jwt_patterns() -> List[str]:
        """Get JWT token patterns"""
        return [
            r'eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*',  # JWT pattern
            r'Bearer\s+eyJ[A-Za-z0-9_-]+',  # Bearer token
            r'jwt["\s:=]+eyJ[A-Za-z0-9_-]+',  # JWT in response
            r'token["\s:=]+eyJ[A-Za-z0-9_-]+',  # Token in response
        ]
    
    @staticmethod
    def detect_jwt_vulnerabilities(response_text: str, response_headers: Dict[str, str], url: str) -> Tuple[bool, str, str, List[Dict[str, Any]]]:
        """
        Detect JWT vulnerabilities
        Returns: (is_vulnerable, evidence, severity, issues)
        """
        issues = []
        jwt_tokens = []
        
        # Find JWT tokens in response
        patterns = JWTDetector.get_jwt_patterns()
        
        for pattern in patterns:
            matches = re.findall(pattern, response_text, re.IGNORECASE)
            for match in matches:
                # Extract just the JWT part
                jwt_match = re.search(r'eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*', match)
                if jwt_match:
                    jwt_tokens.append(jwt_match.group(0))
        
        # Also check headers for JWT
        for header_name, header_value in response_headers.items():
            if 'authorization' in header_name.lower() or 'token' in header_name.lower():
                jwt_match = re.search(r'eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*', header_value)
                if jwt_match:
                    jwt_tokens.append(jwt_match.group(0))
        
        if not jwt_tokens:
            return False, "No JWT tokens found", "None", []
        
        # Analyze each JWT token
        for token in jwt_tokens[:3]:  # Limit to first 3 tokens
            token_issues = JWTDetector._analyze_jwt_token(token)
            issues.extend(token_issues)
        
        if issues:
            severity = 'High' if any(issue['severity'] == 'High' for issue in issues) else 'Medium'
            evidence = f"JWT vulnerabilities detected: {', '.join([issue['issue'] for issue in issues])}"
            return True, evidence, severity, issues
        
        return True, f"JWT tokens found ({len(jwt_tokens)} tokens) - manual analysis recommended", "Low", []
    
    @staticmethod
    def _analyze_jwt_token(token: str) -> List[Dict[str, Any]]:
        """Analyze a single JWT token for vulnerabilities"""
        issues = []
        
        try:
            # Split JWT into parts
            parts = token.split('.')
            if len(parts) != 3:
                return issues
            
            header_part, payload_part, signature_part = parts
            
            # Decode header
            try:
                # Add padding if needed
                header_padded = header_part + '=' * (4 - len(header_part) % 4)
                header_decoded = base64.urlsafe_b64decode(header_padded)
                header_json = json.loads(header_decoded)
            except:
                header_json = {}
            
            # Decode payload
            try:
                payload_padded = payload_part + '=' * (4 - len(payload_part) % 4)
                payload_decoded = base64.urlsafe_b64decode(payload_padded)
                payload_json = json.loads(payload_decoded)
            except:
                payload_json = {}
            
            # Check for algorithm vulnerabilities
            alg = header_json.get('alg', '').upper()
            
            if alg == 'NONE':
                issues.append({
                    'issue': 'Algorithm None',
                    'severity': 'High',
                    'description': 'JWT uses "none" algorithm which bypasses signature verification'
                })
            
            if alg in ['HS256', 'HS384', 'HS512'] and 'kid' in header_json:
                issues.append({
                    'issue': 'HMAC with Key ID',
                    'severity': 'Medium',
                    'description': 'HMAC algorithm with key ID may be vulnerable to key confusion attacks'
                })
            
            # Check for missing signature
            if not signature_part or signature_part == '':
                issues.append({
                    'issue': 'Missing Signature',
                    'severity': 'High',
                    'description': 'JWT token has no signature'
                })
            
            # Check for sensitive information in payload
            sensitive_fields = ['password', 'secret', 'key', 'private', 'admin', 'root']
            for field in sensitive_fields:
                if any(field in str(value).lower() for value in payload_json.values()):
                    issues.append({
                        'issue': 'Sensitive Data in Payload',
                        'severity': 'Medium',
                        'description': f'JWT payload contains potentially sensitive information'
                    })
                    break
            
            # Check for long expiration or no expiration
            if 'exp' not in payload_json:
                issues.append({
                    'issue': 'No Expiration',
                    'severity': 'Medium',
                    'description': 'JWT token has no expiration time'
                })
            else:
                import time
                current_time = int(time.time())
                exp_time = payload_json.get('exp', 0)
                if exp_time - current_time > 86400 * 30:  # More than 30 days
                    issues.append({
                        'issue': 'Long Expiration',
                        'severity': 'Low',
                        'description': 'JWT token has very long expiration time (>30 days)'
                    })
            
        except Exception as e:
            issues.append({
                'issue': 'Token Analysis Error',
                'severity': 'Low',
                'description': f'Could not fully analyze JWT token: {str(e)}'
            })
        
        return issues
    
    @staticmethod
    def get_evidence(issues: List[Dict[str, Any]], tokens_found: int) -> str:
        """Get detailed evidence of JWT vulnerabilities"""
        evidence_parts = []
        
        evidence_parts.append(f"Found {tokens_found} JWT token(s)")
        
        for issue in issues:
            evidence_parts.append(f"{issue['issue']}: {issue['description']}")
        
        return ". ".join(evidence_parts)
    
    @staticmethod
    def get_response_snippet(response_text: str) -> str:
        """Get relevant response snippet containing JWT"""
        patterns = JWTDetector.get_jwt_patterns()
        
        for pattern in patterns:
            match = re.search(pattern, response_text, re.IGNORECASE)
            if match:
                start = max(0, match.start() - 30)
                end = min(len(response_text), match.end() + 30)
                return response_text[start:end]
        
        return response_text[:200]
    
    @staticmethod
    def get_remediation_advice(issue_type: str) -> str:
        """Get remediation advice for JWT issues"""
        advice = {
            'Algorithm None': (
                "Never use 'none' algorithm in production. "
                "Always use strong cryptographic algorithms like RS256 or ES256."
            ),
            'HMAC with Key ID': (
                "Be careful with HMAC algorithms and key IDs. "
                "Ensure proper key management and avoid key confusion attacks."
            ),
            'Missing Signature': (
                "Always include a valid signature in JWT tokens. "
                "Implement proper signature verification on the server side."
            ),
            'Sensitive Data in Payload': (
                "Never include sensitive information in JWT payloads. "
                "JWT payloads are only base64 encoded, not encrypted."
            ),
            'No Expiration': (
                "Always set expiration times for JWT tokens. "
                "Implement reasonable token lifetimes based on your security requirements."
            ),
            'Long Expiration': (
                "Use shorter expiration times for JWT tokens. "
                "Implement token refresh mechanisms for longer sessions."
            )
        }
        
        return advice.get(issue_type, "Review JWT implementation according to security best practices.")
