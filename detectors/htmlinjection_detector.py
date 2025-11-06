"""
HTML Injection vulnerability detection logic
"""

import re

class HTMLInjectionDetector:
    """HTML Injection vulnerability detection logic"""
    
    @staticmethod
    def detect_html_injection(response_text, response_code, payload):
        """Detect HTML injection vulnerability"""
        if response_code >= 500:
            return False
            
        # Check if payload is reflected in response
        if payload in response_text:
            # Check for HTML tag patterns
            html_patterns = [
                r'<[^>]+>',
                r'&lt;[^&]+&gt;',
                r'<!--.*?-->',
                r'<!\[CDATA\[.*?\]\]>'
            ]
            
            for pattern in html_patterns:
                if re.search(pattern, payload, re.IGNORECASE):
                    # Check if HTML is rendered (not encoded)
                    if not HTMLInjectionDetector._is_html_encoded(payload, response_text):
                        return True
        
        return False
    
    @staticmethod
    def _is_html_encoded(payload, response_text):
        """Check if HTML payload is properly encoded"""
        encoded_chars = {
            '<': '&lt;',
            '>': '&gt;',
            '"': '&quot;',
            "'": '&#x27;',
            '&': '&amp;'
        }
        
        for char, encoded in encoded_chars.items():
            if char in payload:
                # If we find the raw character but not the encoded version, it's not encoded
                if char in response_text and encoded not in response_text:
                    return False
        
        return True
    
    @staticmethod
    def get_evidence(payload, response_text):
        """Get evidence for HTML injection"""
        if '<' in payload and '>' in payload:
            return f"HTML injection payload '{payload}' was reflected without proper encoding"
        return f"HTML injection detected with payload: {payload}"
    
    @staticmethod
    def get_response_snippet(payload, response_text):
        """Get response snippet showing injection"""
        if payload in response_text:
            start_pos = response_text.find(payload)
            start = max(0, start_pos - 50)
            end = min(len(response_text), start_pos + len(payload) + 50)
            return response_text[start:end]
        return response_text[:200] + "..." if len(response_text) > 200 else response_text
    
    @staticmethod
    def get_remediation_advice():
        """Get remediation advice for HTML injection"""
        return "Implement proper HTML encoding and Content Security Policy (CSP) to prevent HTML injection attacks."
