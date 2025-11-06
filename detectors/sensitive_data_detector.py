"""
Sensitive data detector - finds API keys, tokens, and sensitive information
"""

import re
from typing import List, Dict, Tuple, Any

class SensitiveDataDetector:
    """Sensitive data detection logic"""
    
    @staticmethod
    def get_api_key_patterns() -> Dict[str, List[str]]:
        """Get API key and token patterns"""
        return {
            "aws": [
                r'AKIA[0-9A-Z]{16}',  # AWS Access Key ID
                r'aws_access_key_id\s*=\s*["\']?([A-Z0-9]{20})["\']?',
                r'aws_secret_access_key\s*=\s*["\']?([A-Za-z0-9/+=]{40})["\']?'
            ],
            "google": [
                r'AIza[0-9A-Za-z\\-_]{35}',  # Google API Key
                r'ya29\.[0-9A-Za-z\\-_]+',   # Google OAuth Access Token
                r'google.*api.*key["\']?\s*[:=]\s*["\']?([A-Za-z0-9_-]{39})["\']?'
            ],
            "github": [
                r'ghp_[A-Za-z0-9]{36}',      # GitHub Personal Access Token
                r'gho_[A-Za-z0-9]{36}',      # GitHub OAuth Access Token
                r'ghu_[A-Za-z0-9]{36}',      # GitHub User Access Token
                r'ghs_[A-Za-z0-9]{36}',      # GitHub Server Access Token
                r'github.*token["\']?\s*[:=]\s*["\']?([A-Za-z0-9_-]{40})["\']?'
            ],
            "slack": [
                r'xox[baprs]-[0-9]{12}-[0-9]{12}-[0-9a-zA-Z]{24}',  # Slack Token
                r'slack.*token["\']?\s*[:=]\s*["\']?([A-Za-z0-9_-]{50,})["\']?'
            ],
            "stripe": [
                r'sk_live_[0-9a-zA-Z]{24}',   # Stripe Live Secret Key
                r'pk_live_[0-9a-zA-Z]{24}',   # Stripe Live Publishable Key
                r'sk_test_[0-9a-zA-Z]{24}',   # Stripe Test Secret Key
                r'pk_test_[0-9a-zA-Z]{24}'    # Stripe Test Publishable Key
            ],
            "twitter": [
                r'twitter.*api.*key["\']?\s*[:=]\s*["\']?([A-Za-z0-9]{25})["\']?',
                r'twitter.*secret["\']?\s*[:=]\s*["\']?([A-Za-z0-9]{50})["\']?'
            ],
            "facebook": [
                r'facebook.*app.*id["\']?\s*[:=]\s*["\']?([0-9]{15,})["\']?',
                r'facebook.*secret["\']?\s*[:=]\s*["\']?([A-Za-z0-9]{32})["\']?'
            ],
            "jwt": [
                r'eyJ[A-Za-z0-9_-]*\.eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*',  # JWT Token
                r'jwt["\']?\s*[:=]\s*["\']?(eyJ[A-Za-z0-9_.-]+)["\']?'
            ],
            "generic": [
                r'api[_-]?key["\']?\s*[:=]\s*["\']?([A-Za-z0-9_-]{20,})["\']?',
                r'secret[_-]?key["\']?\s*[:=]\s*["\']?([A-Za-z0-9_-]{20,})["\']?',
                r'access[_-]?token["\']?\s*[:=]\s*["\']?([A-Za-z0-9_-]{20,})["\']?',
                r'auth[_-]?token["\']?\s*[:=]\s*["\']?([A-Za-z0-9_-]{20,})["\']?'
            ]
        }
    
    @staticmethod
    def get_sensitive_patterns() -> Dict[str, List[str]]:
        """Get patterns for other sensitive information"""
        return {
            "database": [
                r'mysql://[^:\s]+:[^@\s]+@[^/\s]+/[^\s]+',
                r'postgresql://[^:\s]+:[^@\s]+@[^/\s]+/[^\s]+',
                r'mongodb://[^:\s]+:[^@\s]+@[^/\s]+/[^\s]+',
                r'database[_-]?password["\']?\s*[:=]\s*["\']?([^"\';\s]{8,})["\']?',
                r'db[_-]?pass["\']?\s*[:=]\s*["\']?([^"\';\s]{8,})["\']?'
            ],
            "email": [
                r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}',
                r'email["\']?\s*[:=]\s*["\']?([^"\';\s]+@[^"\';\s]+)["\']?'
            ],
            "phone": [
                r'\+?[1-9]\d{1,14}',  # International phone format
                r'phone["\']?\s*[:=]\s*["\']?([+]?[\d\s\-\(\)]{10,})["\']?'
            ],
            "ip_address": [
                r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b',
                r'server[_-]?ip["\']?\s*[:=]\s*["\']?((?:[0-9]{1,3}\.){3}[0-9]{1,3})["\']?'
            ],
            "password": [
                r'password["\']?\s*[:=]\s*["\']?([^"\';\s]{8,})["\']?',
                r'passwd["\']?\s*[:=]\s*["\']?([^"\';\s]{8,})["\']?',
                r'pwd["\']?\s*[:=]\s*["\']?([^"\';\s]{8,})["\']?'
            ],
            "private_key": [
                r'-----BEGIN PRIVATE KEY-----',
                r'-----BEGIN RSA PRIVATE KEY-----',
                r'-----BEGIN OPENSSH PRIVATE KEY-----'
            ]
        }
    
    @staticmethod
    def detect_sensitive_data(response_text: str, response_headers: Dict[str, str], 
                            cookies: str = None) -> List[Dict[str, Any]]:
        """Detect sensitive data in response"""
        findings = []
        
        # Check response body
        findings.extend(SensitiveDataDetector._scan_text(response_text, "response_body"))
        
        # Check response headers
        headers_text = '\n'.join([f"{k}: {v}" for k, v in response_headers.items()])
        findings.extend(SensitiveDataDetector._scan_text(headers_text, "response_headers"))
        
        # Check cookies
        if cookies:
            findings.extend(SensitiveDataDetector._scan_text(cookies, "cookies"))
        
        # Check for cookies in Set-Cookie headers
        set_cookie_headers = [v for k, v in response_headers.items() if k.lower() == 'set-cookie']
        for cookie_header in set_cookie_headers:
            findings.extend(SensitiveDataDetector._scan_text(cookie_header, "set_cookie_header"))
        
        return findings
    
    @staticmethod
    def _scan_text(text: str, source: str) -> List[Dict[str, Any]]:
        """Scan text for sensitive patterns"""
        findings = []
        
        # Scan for API keys and tokens
        api_patterns = SensitiveDataDetector.get_api_key_patterns()
        for service, patterns in api_patterns.items():
            for pattern in patterns:
                matches = re.finditer(pattern, text, re.IGNORECASE)
                for match in matches:
                    findings.append({
                        'type': 'api_key',
                        'service': service,
                        'pattern': pattern,
                        'match': match.group(0),
                        'source': source,
                        'position': match.span(),
                        'severity': SensitiveDataDetector._get_severity('api_key', service)
                    })
        
        # Scan for other sensitive data
        sensitive_patterns = SensitiveDataDetector.get_sensitive_patterns()
        for data_type, patterns in sensitive_patterns.items():
            for pattern in patterns:
                matches = re.finditer(pattern, text, re.IGNORECASE)
                for match in matches:
                    # Filter out common false positives
                    if SensitiveDataDetector._is_false_positive(data_type, match.group(0)):
                        continue
                    
                    findings.append({
                        'type': 'sensitive_data',
                        'data_type': data_type,
                        'pattern': pattern,
                        'match': match.group(0),
                        'source': source,
                        'position': match.span(),
                        'severity': SensitiveDataDetector._get_severity('sensitive_data', data_type)
                    })
        
        return findings
    
    @staticmethod
    def _is_false_positive(data_type: str, match: str) -> bool:
        """Check if match is likely a false positive"""
        false_positive_patterns = {
            'email': [
                r'example\.com$', r'test\.com$', r'localhost$',
                r'noreply@', r'no-reply@', r'admin@example'
            ],
            'phone': [
                r'^[01]+$',  # All zeros or ones
                r'^123+$',   # All 123s
                r'^\d{1,3}$'  # Too short
            ],
            'ip_address': [
                r'^127\.0\.0\.1$', r'^0\.0\.0\.0$', r'^255\.255\.255\.255$',
                r'^192\.168\.', r'^10\.', r'^172\.(1[6-9]|2[0-9]|3[01])\.'  # Private IPs
            ],
            'password': [
                r'^password$', r'^123456$', r'^admin$', r'^test$',
                r'^example$', r'^sample$', r'^demo$'
            ]
        }
        
        if data_type in false_positive_patterns:
            for fp_pattern in false_positive_patterns[data_type]:
                if re.search(fp_pattern, match, re.IGNORECASE):
                    return True
        
        return False
    
    @staticmethod
    def _get_severity(finding_type: str, subtype: str) -> str:
        """Get severity level for finding"""
        high_severity = {
            'api_key': ['aws', 'stripe', 'github'],
            'sensitive_data': ['private_key', 'database', 'password']
        }
        
        medium_severity = {
            'api_key': ['google', 'slack', 'twitter', 'facebook'],
            'sensitive_data': ['jwt', 'email']
        }
        
        if finding_type in high_severity and subtype in high_severity[finding_type]:
            return 'high'
        elif finding_type in medium_severity and subtype in medium_severity[finding_type]:
            return 'medium'
        else:
            return 'low'
    
    @staticmethod
    def get_evidence(findings: List[Dict[str, Any]]) -> str:
        """Get evidence summary for sensitive data findings"""
        if not findings:
            return "No sensitive data detected"
        
        evidence_parts = []
        
        # Group findings by type and severity
        by_severity = {'high': [], 'medium': [], 'low': []}
        for finding in findings:
            by_severity[finding['severity']].append(finding)
        
        for severity in ['high', 'medium', 'low']:
            if by_severity[severity]:
                count = len(by_severity[severity])
                evidence_parts.append(f"{count} {severity} severity findings")
        
        # Add specific examples
        examples = []
        for finding in findings[:3]:  # Show first 3 findings
            if finding['type'] == 'api_key':
                examples.append(f"{finding['service']} API key in {finding['source']}")
            else:
                examples.append(f"{finding['data_type']} in {finding['source']}")
        
        if examples:
            evidence_parts.append(f"Examples: {', '.join(examples)}")
        
        return '; '.join(evidence_parts)
    
    @staticmethod
    def get_response_snippet(findings: List[Dict[str, Any]], response_text: str, 
                           max_length: int = 400) -> str:
        """Get response snippet showing sensitive data context"""
        if not findings:
            return "No sensitive data found"
        
        # Get context around first high-severity finding
        high_severity_findings = [f for f in findings if f['severity'] == 'high']
        target_finding = high_severity_findings[0] if high_severity_findings else findings[0]
        
        if target_finding['source'] == 'response_body':
            start_pos = target_finding['position'][0]
            context_start = max(0, start_pos - 100)
            context_end = min(len(response_text), start_pos + max_length - 100)
            
            snippet = response_text[context_start:context_end]
            
            # Mask the sensitive data in snippet
            match = target_finding['match']
            if len(match) > 8:
                masked = match[:4] + '*' * (len(match) - 8) + match[-4:]
            else:
                masked = '*' * len(match)
            
            snippet = snippet.replace(match, masked)
            return snippet
        
        return f"Sensitive data found in {target_finding['source']}: {target_finding['data_type']}"
