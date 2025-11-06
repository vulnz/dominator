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
    
    @staticmethod
    def get_evidence(payload: str, response_text: str) -> str:
        """Get evidence for SSRF"""
        evidence_parts = []
        
        # Check for internal network responses
        if 'localhost' in response_text or '127.0.0.1' in response_text:
            evidence_parts.append("localhost/127.0.0.1 response detected")
        
        # Check for cloud metadata responses
        if 'instance-id' in response_text or 'ami-id' in response_text:
            evidence_parts.append("AWS metadata response detected")
        elif 'project-id' in response_text or 'instance/id' in response_text:
            evidence_parts.append("GCP metadata response detected")
        
        # Check for internal service responses
        if 'HTTP/1.' in response_text or 'Server:' in response_text:
            evidence_parts.append("HTTP service response detected")
        
        if evidence_parts:
            return f"SSRF detected: {'; '.join(evidence_parts)}"
        else:
            return f"Potential SSRF with payload: {payload}"
    
    @staticmethod
    def get_response_snippet(payload: str, response_text: str) -> str:
        """Get response snippet for SSRF"""
        if len(response_text) > 400:
            return response_text[:400] + "..."
        return response_text
