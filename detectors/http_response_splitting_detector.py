"""
HTTP Response Splitting vulnerability detection logic
"""

import re
from typing import Tuple, List, Dict, Any

class HTTPResponseSplittingDetector:
    """HTTP Response Splitting vulnerability detection logic"""
    
    @staticmethod
    def get_splitting_indicators() -> List[str]:
        """Get HTTP response splitting indicators"""
        return [
            '\r\n\r\n',  # CRLF injection
            '\n\n',      # LF injection
            'Set-Cookie:', 'Location:', 'Content-Type:',
            'HTTP/1.1 200', 'HTTP/1.0 200',
            'Content-Length:', 'Cache-Control:',
            '<script>', '<html>', '<body>'
        ]
    
    @staticmethod
    def detect_response_splitting(response_text: str, response_code: int, payload: str, response_headers: Dict[str, str]) -> bool:
        """
        Detect HTTP response splitting vulnerability
        Returns True if response splitting is detected
        """
        if response_code >= 500:
            return False
        
        # Check if payload contains CRLF injection attempts
        if not any(char in payload for char in ['\r', '\n', '%0d', '%0a', '%0D', '%0A']):
            return False
        
        response_lower = response_text.lower()
        
        # Look for signs that our payload caused response splitting
        splitting_patterns = [
            r'set-cookie:.*' + re.escape(payload.replace('%0d%0a', '\r\n').replace('%0a', '\n')),
            r'location:.*' + re.escape(payload.replace('%0d%0a', '\r\n').replace('%0a', '\n')),
            r'content-type:.*' + re.escape(payload.replace('%0d%0a', '\r\n').replace('%0a', '\n'))
        ]
        
        for pattern in splitting_patterns:
            if re.search(pattern, response_text, re.IGNORECASE):
                return True
        
        # Check for double CRLF in response (indicating header injection)
        if '\r\n\r\n' in response_text and payload.replace('%0d%0a', '\r\n') in response_text:
            return True
        
        # Check for injected headers in response headers
        payload_decoded = payload.replace('%0d%0a', '\r\n').replace('%0a', '\n').replace('%0d', '\r')
        
        for header_name, header_value in response_headers.items():
            if payload_decoded in header_value:
                return True
        
        # Check for HTML injection after header splitting
        if any(tag in response_lower for tag in ['<script>', '<html>', '<body>']):
            if any(crlf in payload.lower() for crlf in ['%0d%0a', '%0a', '%0d', '\r\n', '\n']):
                return True
        
        return False
    
    @staticmethod
    def get_evidence(payload: str, response_text: str, response_headers: Dict[str, str]) -> str:
        """Get evidence of HTTP response splitting vulnerability"""
        evidence_parts = []
        
        # Check what was injected
        payload_decoded = payload.replace('%0d%0a', '\r\n').replace('%0a', '\n').replace('%0d', '\r')
        
        if payload_decoded in response_text:
            evidence_parts.append("Payload reflected in response body")
        
        # Check headers
        injected_headers = []
        for header_name, header_value in response_headers.items():
            if payload_decoded in header_value:
                injected_headers.append(header_name)
        
        if injected_headers:
            evidence_parts.append(f"Payload injected into headers: {', '.join(injected_headers)}")
        
        # Check for CRLF sequences
        if '\r\n\r\n' in response_text:
            evidence_parts.append("Double CRLF sequence detected in response")
        
        if evidence_parts:
            return f"HTTP Response Splitting detected: {'; '.join(evidence_parts)}"
        
        return "HTTP Response Splitting vulnerability detected based on payload reflection"
    
    @staticmethod
    def get_response_snippet(payload: str, response_text: str) -> str:
        """Get relevant response snippet"""
        payload_decoded = payload.replace('%0d%0a', '\r\n').replace('%0a', '\n').replace('%0d', '\r')
        
        # Find where payload appears in response
        if payload_decoded in response_text:
            start = max(0, response_text.find(payload_decoded) - 50)
            end = min(len(response_text), start + 200)
            return response_text[start:end]
        
        # Look for CRLF sequences
        crlf_pos = response_text.find('\r\n\r\n')
        if crlf_pos != -1:
            start = max(0, crlf_pos - 50)
            end = min(len(response_text), crlf_pos + 100)
            return response_text[start:end]
        
        return response_text[:200]
    
    @staticmethod
    def get_remediation_advice() -> str:
        """Get remediation advice for HTTP response splitting vulnerabilities"""
        return (
            "Validate and sanitize all user input before including in HTTP headers. "
            "Remove or encode CRLF characters (\\r\\n) from user input. "
            "Use proper output encoding and avoid direct header manipulation. "
            "Implement Content Security Policy (CSP) to mitigate XSS risks from response splitting."
        )
