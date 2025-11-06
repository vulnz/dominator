"""
XSS vulnerability detector
"""

class XSSDetector:
    """XSS vulnerability detection logic"""
    
    @staticmethod
    def detect_reflected_xss(payload: str, response_text: str, response_code: int) -> bool:
        """Detect reflected XSS vulnerability"""
        if response_code != 200:
            return False
        
        # Check if payload is reflected in response
        if payload not in response_text:
            return False
        
        # Additional checks to reduce false positives
        # 1. Check if payload is in dangerous context (not just in comments or text)
        dangerous_contexts = [
            r'<script[^>]*>' + re.escape(payload),
            r'<[^>]*\s+on\w+\s*=\s*["\']?[^"\']*' + re.escape(payload),
            r'<[^>]*\s+href\s*=\s*["\']?javascript:[^"\']*' + re.escape(payload),
            r'<[^>]*\s+src\s*=\s*["\']?[^"\']*' + re.escape(payload),
            r'<[^>]*>' + re.escape(payload) + r'</[^>]*>',
            r'<input[^>]*\s+value\s*=\s*["\']?[^"\']*' + re.escape(payload)
        ]
        
        # Check if payload appears in dangerous context
        for context_pattern in dangerous_contexts:
            if re.search(context_pattern, response_text, re.IGNORECASE):
                return True
        
        # 2. Check if payload is unescaped in HTML context
        if '<' in payload and '>' in payload:
            # Look for unescaped angle brackets
            if payload in response_text and '&lt;' not in response_text.replace(payload, ''):
                return True
        
        # 3. Check for JavaScript execution context
        if 'javascript:' in payload.lower() or 'eval(' in payload.lower():
            if payload in response_text:
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
