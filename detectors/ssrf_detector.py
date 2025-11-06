"""
Server-Side Request Forgery (SSRF) vulnerability detection logic
"""

class SSRFDetector:
    """SSRF vulnerability detection logic"""
    
    @staticmethod
    def get_ssrf_indicators() -> list:
        """Get SSRF response indicators"""
        return [
            # DNS resolution indicators
            'nslookup',
            'dig',
            'host',
            # HTTP request indicators
            'curl',
            'wget',
            'fetch',
            # Error messages that might indicate SSRF
            'connection refused',
            'connection timeout',
            'no route to host',
            'name resolution failed',
            # Cloud metadata endpoints
            'metadata',
            'instance-data',
            # Internal network responses
            '192.168.',
            '10.',
            '172.16.',
            '127.0.0.1',
            'localhost'
        ]
    
    @staticmethod
    def detect_ssrf(response_text: str, response_code: int, payload: str) -> bool:
        """Detect SSRF vulnerability"""
        if response_code >= 500:
            return False
            
        response_lower = response_text.lower()
        indicators = SSRFDetector.get_ssrf_indicators()
        
        # Check for SSRF indicators in response
        for indicator in indicators:
            if indicator in response_lower:
                return True
                
        # Check for successful external requests
        if response_code == 200 and len(response_text) > 0:
            # Look for signs that external request was made
            if any(sign in response_lower for sign in ['http://', 'https://', 'ftp://']):
                return True
                
        return False
    
    @staticmethod
    def get_evidence(payload: str, response_text: str) -> str:
        """Get evidence of SSRF vulnerability"""
        indicators = SSRFDetector.get_ssrf_indicators()
        response_lower = response_text.lower()
        
        found_indicators = []
        for indicator in indicators:
            if indicator in response_lower:
                found_indicators.append(indicator)
        
        if found_indicators:
            return f"SSRF detected with payload '{payload}'. Found indicators: {', '.join(found_indicators[:3])}"
        
        return f"Possible SSRF with payload '{payload}'. Server made external request."
    
    @staticmethod
    def get_response_snippet(payload: str, response_text: str, max_length: int = 300) -> str:
        """Get response snippet for evidence"""
        if len(response_text) <= max_length:
            return response_text
        
        # Try to find relevant part of response
        indicators = SSRFDetector.get_ssrf_indicators()
        response_lower = response_text.lower()
        
        for indicator in indicators:
            pos = response_lower.find(indicator)
            if pos != -1:
                start = max(0, pos - 50)
                end = min(len(response_text), pos + max_length - 50)
                return response_text[start:end]
        
        return response_text[:max_length]
