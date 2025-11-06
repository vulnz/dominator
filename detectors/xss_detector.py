"""
XSS vulnerability detector
"""

import re

class XSSDetector:
    """XSS vulnerability detection logic"""
    
    @staticmethod
    def detect_reflected_xss(payload: str, response_text: str, response_code: int) -> bool:
        """Detect reflected XSS vulnerability with improved detection logic"""
        if response_code not in [200, 201, 202]:
            return False
        
        # Convert response to lowercase for case-insensitive matching
        response_lower = response_text.lower()
        payload_lower = payload.lower()
        
        # Check for exact payload reflection first
        if payload in response_text:
            return XSSDetector._is_dangerous_context(payload, response_text)
        
        # Check for URL-decoded payload reflection
        import urllib.parse
        try:
            decoded_payload = urllib.parse.unquote(payload)
            if decoded_payload != payload and decoded_payload in response_text:
                return XSSDetector._is_dangerous_context(decoded_payload, response_text)
        except:
            pass
        
        # Check for HTML-encoded payload reflection
        import html
        try:
            encoded_payload = html.escape(payload)
            if encoded_payload != payload and encoded_payload in response_text:
                # If payload is HTML-encoded, it's likely safe
                return False
        except:
            pass
        
        # Check for partial payload reflection (key parts)
        if '<script' in payload_lower:
            if '<script' in response_lower and 'alert' in response_lower:
                return True
        
        if 'javascript:' in payload_lower:
            if 'javascript:' in response_lower:
                return True
        
        if 'onerror' in payload_lower or 'onload' in payload_lower:
            if ('onerror' in response_lower or 'onload' in response_lower) and payload_lower.split('=')[0] in response_lower:
                return True
        
        # Check for XSS indicators in response
        xss_indicators = [
            'alert(',
            'confirm(',
            'prompt(',
            'document.cookie',
            'document.write',
            'eval(',
            'javascript:',
            'vbscript:',
            'onload=',
            'onerror=',
            'onclick=',
            'onmouseover='
        ]
        
        # If payload contains XSS patterns and they appear unescaped in response
        for indicator in xss_indicators:
            if indicator in payload_lower and indicator in response_lower:
                # Check if it's not just in comments or escaped
                if not XSSDetector._is_safely_encoded(indicator, response_text):
                    return True
        
        return False
    
    @staticmethod
    def _is_dangerous_context(payload: str, response_text: str) -> bool:
        """Check if payload appears in dangerous HTML context"""
        # Check if payload is in dangerous context (not just in comments or text)
        dangerous_contexts = [
            r'<script[^>]*>[^<]*' + re.escape(payload),
            r'<[^>]*\s+on\w+\s*=\s*["\']?[^"\']*' + re.escape(payload),
            r'<[^>]*\s+href\s*=\s*["\']?javascript:[^"\']*' + re.escape(payload),
            r'<[^>]*\s+src\s*=\s*["\']?[^"\']*' + re.escape(payload),
            r'<input[^>]*\s+value\s*=\s*["\']?' + re.escape(payload),
            r'<textarea[^>]*>[^<]*' + re.escape(payload)
        ]
        
        # Check if payload appears in dangerous context
        for context_pattern in dangerous_contexts:
            if re.search(context_pattern, response_text, re.IGNORECASE | re.DOTALL):
                return True
        
        # Check if payload contains HTML tags and they're not escaped
        if '<' in payload and '>' in payload:
            # Look for unescaped angle brackets
            if payload in response_text and '&lt;' not in response_text.replace(payload, ''):
                return True
        
        return False
    
    @staticmethod
    def _is_safely_encoded(indicator: str, response_text: str) -> bool:
        """Check if XSS indicator is safely encoded in response"""
        # Check for HTML encoding
        import html
        encoded_indicator = html.escape(indicator)
        if encoded_indicator in response_text:
            return True
        
        # Check for URL encoding
        import urllib.parse
        url_encoded = urllib.parse.quote(indicator)
        if url_encoded in response_text:
            return True
        
        # Check if it's in HTML comments
        if f'<!--{indicator}' in response_text or f'{indicator}-->' in response_text:
            return True
        
        return False
    
    @staticmethod
    def detect_dom_xss(payload: str, response_text: str, response_code: int) -> bool:
        """Detect DOM-based XSS vulnerability"""
        if response_code != 200:
            return False
            
        # Look for JavaScript that might execute the payload
        dom_indicators = [
            'document.write',
            'innerHTML',
            'outerHTML',
            'eval(',
            'setTimeout(',
            'setInterval('
        ]
        
        return (payload in response_text and 
                any(indicator in response_text for indicator in dom_indicators))
    
    @staticmethod
    def get_evidence(payload: str, response_text: str) -> str:
        """Get evidence of XSS vulnerability"""
        if payload in response_text:
            # Find context where payload appears
            start_pos = response_text.find(payload)
            context_start = max(0, start_pos - 40)
            context_end = min(len(response_text), start_pos + len(payload) + 40)
            context = response_text[context_start:context_end]
            return f"Payload reflected in response: ...{context}..."
        return "Payload not found in response"
    
    @staticmethod
    def get_response_snippet(payload: str, response_text: str) -> str:
        """Get response snippet showing payload context"""
        if payload in response_text:
            start_pos = response_text.find(payload)
            context_start = max(0, start_pos - 40)
            context_end = min(len(response_text), start_pos + len(payload) + 40)
            return response_text[context_start:context_end]
        return "Payload not found in response"
