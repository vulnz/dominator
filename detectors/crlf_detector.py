"""
CRLF (Carriage Return Line Feed) injection vulnerability detection logic
"""

import re
from typing import List, Tuple, Dict, Any

class CRLFDetector:
    """CRLF injection vulnerability detection logic"""
    
    @staticmethod
    def get_crlf_indicators() -> List[str]:
        """Get CRLF injection indicators"""
        return [
            # Injected headers
            'X-Injected-Header:', 'Set-Cookie:', 'Location:',
            'Content-Type:', 'Content-Length:', 'Cache-Control:',
            
            # Response splitting indicators
            'HTTP/1.1 200 OK', 'HTTP/1.0 200 OK',
            'Content-Type: text/html',
            
            # Custom test headers
            'X-CRLF-Test:', 'X-Response-Split:',
            'Injected-By-CRLF:', 'CRLF-Injection-Test:'
        ]
    
    @staticmethod
    def detect_crlf_injection(response_text: str, response_code: int, payload: str, response_headers: Dict[str, str]) -> bool:
        """Detect CRLF injection vulnerability"""
        # Check if payload contains CRLF sequences
        crlf_sequences = ['\r\n', '%0d%0a', '%0a', '%0d', '\n', '\r']
        has_crlf_payload = any(seq in payload.lower() for seq in crlf_sequences)
        
        if not has_crlf_payload:
            return False
        
        # Check for injected headers in response headers
        if CRLFDetector._check_injected_headers(response_headers, payload):
            return True
        
        # Check for response splitting in response body
        if CRLFDetector._check_response_splitting(response_text, payload):
            return True
        
        # Check for header injection in response text
        if CRLFDetector._check_header_injection_in_body(response_text, payload):
            return True
        
        return False
    
    @staticmethod
    def _check_injected_headers(response_headers: Dict[str, str], payload: str) -> bool:
        """Check for injected headers in response"""
        # Look for test headers that might have been injected
        test_headers = [
            'x-injected-header', 'x-crlf-test', 'x-response-split',
            'injected-by-crlf', 'crlf-injection-test'
        ]
        
        for header_name in response_headers.keys():
            if header_name.lower() in test_headers:
                return True
        
        # Check if any header values contain our payload markers
        payload_markers = ['crlf', 'injected', 'test123', 'pwned']
        for header_value in response_headers.values():
            if header_value and any(marker in header_value.lower() for marker in payload_markers):
                return True
        
        return False
    
    @staticmethod
    def _check_response_splitting(response_text: str, payload: str) -> bool:
        """Check for HTTP response splitting"""
        # Look for multiple HTTP responses in single response
        http_response_pattern = r'HTTP/1\.[01]\s+\d{3}'
        http_responses = re.findall(http_response_pattern, response_text)
        
        if len(http_responses) > 1:
            return True
        
        # Look for injected content after headers
        if 'Content-Type:' in response_text and 'Content-Length:' in response_text:
            # Check if there's HTML content after headers (possible response splitting)
            if '<html>' in response_text.lower() or '<script>' in response_text.lower():
                return True
        
        return False
    
    @staticmethod
    def _check_header_injection_in_body(response_text: str, payload: str) -> bool:
        """Check for header injection reflected in response body"""
        indicators = CRLFDetector.get_crlf_indicators()
        
        for indicator in indicators:
            if indicator.lower() in response_text.lower():
                # Make sure it's not just normal HTML content
                if 'Set-Cookie:' in response_text and 'document.cookie' not in response_text.lower():
                    return True
                elif any(header in response_text for header in ['X-Injected-Header:', 'X-CRLF-Test:', 'Location:']):
                    return True
        
        return False
    
    @staticmethod
    def get_evidence(payload: str, response_text: str, response_headers: Dict[str, str]) -> str:
        """Get evidence of CRLF injection"""
        evidence_parts = []
        
        # Check for injected headers
        injected_headers = []
        test_headers = [
            'x-injected-header', 'x-crlf-test', 'x-response-split',
            'injected-by-crlf', 'crlf-injection-test'
        ]
        
        for header_name in response_headers.keys():
            if header_name.lower() in test_headers:
                injected_headers.append(header_name)
        
        if injected_headers:
            evidence_parts.append(f"Injected headers detected: {', '.join(injected_headers)}")
        
        # Check for response splitting
        http_response_pattern = r'HTTP/1\.[01]\s+\d{3}'
        http_responses = re.findall(http_response_pattern, response_text)
        if len(http_responses) > 1:
            evidence_parts.append(f"Multiple HTTP responses detected ({len(http_responses)} responses)")
        
        # Check for header injection in body
        indicators = CRLFDetector.get_crlf_indicators()
        found_indicators = []
        
        for indicator in indicators:
            if indicator.lower() in response_text.lower():
                found_indicators.append(indicator)
        
        if found_indicators:
            evidence_parts.append(f"Header injection indicators in response: {', '.join(found_indicators[:3])}")
        
        return "; ".join(evidence_parts) if evidence_parts else "CRLF injection indicators detected"
    
    @staticmethod
    def get_response_snippet(payload: str, response_text: str) -> str:
        """Get relevant response snippet"""
        # Look for injected headers first
        indicators = CRLFDetector.get_crlf_indicators()
        
        for indicator in indicators:
            if indicator.lower() in response_text.lower():
                pos = response_text.lower().find(indicator.lower())
                start = max(0, pos - 100)
                end = min(len(response_text), pos + len(indicator) + 100)
                return response_text[start:end]
        
        # Look for HTTP response patterns
        http_pattern = r'HTTP/1\.[01]\s+\d{3}'
        match = re.search(http_pattern, response_text)
        if match:
            start = max(0, match.start() - 50)
            end = min(len(response_text), match.end() + 200)
            return response_text[start:end]
        
        return response_text[:300] + "..." if len(response_text) > 300 else response_text
    
    @staticmethod
    def get_remediation_advice() -> str:
        """Get remediation advice for CRLF injection"""
        return """
        1. Validate and sanitize all user input before using in HTTP headers
        2. Remove or encode CR (\\r) and LF (\\n) characters from user input
        3. Use proper HTTP header APIs instead of string concatenation
        4. Implement strict input validation for redirect URLs
        5. Use URL encoding for user-controlled data in headers
        6. Implement Content Security Policy (CSP) headers
        7. Regular security testing for header injection vulnerabilities
        """
