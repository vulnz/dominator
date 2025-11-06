"""
Text Injection vulnerability detection logic
"""

class TextInjectionDetector:
    """Text Injection vulnerability detection logic"""
    
    @staticmethod
    def detect_text_injection(response_text, response_code, payload):
        """Detect text injection vulnerability"""
        if response_code >= 500:
            return False
            
        # Check if payload is reflected in response
        if payload in response_text:
            # Check for context indicators
            context_indicators = [
                'injected',
                '\n',
                '\r',
                '%0a',
                '%0d'
            ]
            
            for indicator in context_indicators:
                if indicator in payload and indicator in response_text:
                    return True
        
        return False
    
    @staticmethod
    def get_evidence(payload, response_text):
        """Get evidence for text injection"""
        if 'injected' in payload:
            return f"Text injection payload '{payload}' was reflected in the response"
        return f"Text injection detected with payload: {payload}"
    
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
        """Get remediation advice for text injection"""
        return "Implement proper input validation and output encoding to prevent text injection attacks."
