"""
CRLF Injection vulnerability detector
Detects HTTP Response Splitting and CRLF injection vulnerabilities
"""

import re
from typing import List, Dict, Any, Tuple

class CRLFInjectionDetector:
    """CRLF Injection vulnerability detection logic"""
    
    @staticmethod
    def get_crlf_indicators() -> List[str]:
        """Get CRLF injection indicators"""
        return [
            # HTTP response splitting indicators
            'HTTP/1.1 200 OK',
            'Content-Type:',
            'Content-Length:',
            'Set-Cookie:',
            'Location:',
            'Cache-Control:',
            
            # CRLF sequences
            '\r\n',
            '%0d%0a',
            '%0D%0A',
            '\n',
            '%0a',
            '%0A',
            
            # Injection success indicators
            'injected-header:',
            'evil-header:',
            'test-header:',
            'x-injected:'
        ]
    
    @staticmethod
    def detect_crlf_injection(payload: str, response_text: str, response_code: int, response_headers: Dict[str, str] = None) -> Tuple[bool, str, str, Dict[str, Any]]:
        """Enhanced CRLF injection detection"""
        if response_code not in [200, 201, 202, 302, 301, 500]:
            return False, "", "", {}
        
        # Check for CRLF sequences in payload
        crlf_patterns = [
            r'%0d%0a',
            r'%0D%0A',
            r'\\r\\n',
            r'\\n',
            r'%0a',
            r'%0A'
        ]
        
        payload_has_crlf = False
        for pattern in crlf_patterns:
            if re.search(pattern, payload, re.IGNORECASE):
                payload_has_crlf = True
                break
        
        if not payload_has_crlf:
            return False, "", "", {}
        
        # Check response headers for injection
        if response_headers:
            for header_name, header_value in response_headers.items():
                # Look for injected headers
                if any(injected in header_name.lower() for injected in ['injected', 'evil', 'test', 'x-']):
                    return True, f"CRLF injection detected in header: {header_name}", "High", {
                        'cwe': 'CWE-93',
                        'cvss': '6.1',
                        'owasp': 'A03:2021 – Injection',
                        'recommendation': 'Sanitize user input before including in HTTP headers. Remove CRLF characters.'
                    }
                
                # Look for multiple values in single header (response splitting)
                if '\r\n' in header_value or '\n' in header_value:
                    return True, f"HTTP Response Splitting detected in header: {header_name}", "High", {
                        'cwe': 'CWE-113',
                        'cvss': '6.1',
                        'owasp': 'A03:2021 – Injection',
                        'recommendation': 'Sanitize user input before including in HTTP headers. Remove CRLF characters.'
                    }
        
        # Check response body for HTTP response splitting
        response_splitting_patterns = [
            r'HTTP/1\.[01]\s+\d{3}',
            r'Content-Type:\s*text/html',
            r'Content-Length:\s*\d+',
            r'Set-Cookie:\s*\w+='
        ]
        
        found_patterns = 0
        for pattern in response_splitting_patterns:
            if re.search(pattern, response_text, re.IGNORECASE):
                found_patterns += 1
        
        if found_patterns >= 2:
            return True, "HTTP Response Splitting detected in response body", "High", {
                'cwe': 'CWE-113',
                'cvss': '6.1',
                'owasp': 'A03:2021 – Injection',
                'recommendation': 'Sanitize user input before including in HTTP headers. Remove CRLF characters.'
            }
        
        # Check for reflected CRLF sequences
        indicators = CRLFInjectionDetector.get_crlf_indicators()
        found_indicators = []
        
        for indicator in indicators:
            if indicator.lower() in response_text.lower():
                found_indicators.append(indicator)
        
        if len(found_indicators) >= 2:
            return True, f"CRLF injection indicators found: {', '.join(found_indicators[:3])}", "Medium", {
                'cwe': 'CWE-93',
                'cvss': '5.3',
                'owasp': 'A03:2021 – Injection',
                'recommendation': 'Sanitize user input before including in HTTP headers. Remove CRLF characters.'
            }
        
        return False, "", "", {}
    
    @staticmethod
    def get_crlf_payloads() -> List[str]:
        """Get CRLF injection test payloads"""
        return [
            # Basic CRLF injection
            '%0d%0aContent-Type: text/html',
            '%0D%0ASet-Cookie: injected=true',
            '\\r\\nLocation: http://evil.com',
            '\\nX-Injected: true',
            
            # Response splitting
            '%0d%0a%0d%0aHTTP/1.1 200 OK%0d%0aContent-Type: text/html%0d%0a%0d%0a<script>alert(1)</script>',
            '\\r\\n\\r\\nHTTP/1.1 200 OK\\r\\nContent-Length: 0\\r\\n\\r\\n',
            
            # Header injection
            '%0aSet-Cookie: admin=true',
            '%0dLocation: javascript:alert(1)',
            '\\nCache-Control: no-cache',
            
            # Double encoding
            '%250d%250a',
            '%250D%250A',
            
            # Unicode encoding
            '%u000d%u000a',
            '%u000D%u000A'
        ]
