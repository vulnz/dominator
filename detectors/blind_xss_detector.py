"""
Blind XSS vulnerability detection logic
"""

import re
from typing import Dict, Any, List, Tuple

class BlindXSSDetector:
    """Blind XSS vulnerability detection logic"""
    
    @staticmethod
    def get_blind_xss_indicators() -> List[str]:
        """Get indicators that suggest blind XSS might be present"""
        return [
            'DNS request captured',
            'HTTP request captured',
            'Callback received',
            'External request detected',
            'Out-of-band interaction',
            'Blind payload executed'
        ]
    
    @staticmethod
    def detect_blind_xss(payload: str, response_text: str, response_code: int, callback_received: bool = False) -> bool:
        """
        Detect blind XSS vulnerability
        
        Args:
            payload: The XSS payload used
            response_text: HTTP response text
            response_code: HTTP response code
            callback_received: Whether a callback was received (DNS/HTTP)
        
        Returns:
            bool: True if blind XSS is detected
        """
        # If we received a callback, it's a strong indicator of blind XSS
        if callback_received:
            return True
        
        # Check if payload was reflected without encoding
        if payload in response_text:
            # Look for script tags or event handlers that might execute later
            script_patterns = [
                r'<script[^>]*>.*?' + re.escape(payload) + r'.*?</script>',
                r'on\w+\s*=\s*["\'].*?' + re.escape(payload) + r'.*?["\']',
                r'javascript:.*?' + re.escape(payload),
                r'<iframe[^>]*src\s*=\s*["\'].*?' + re.escape(payload) + r'.*?["\']'
            ]
            
            for pattern in script_patterns:
                if re.search(pattern, response_text, re.IGNORECASE | re.DOTALL):
                    return True
        
        # Check for stored context indicators
        storage_indicators = [
            'comment saved',
            'message posted',
            'profile updated',
            'data stored',
            'entry added',
            'successfully submitted'
        ]
        
        response_lower = response_text.lower()
        for indicator in storage_indicators:
            if indicator in response_lower:
                return True
        
        return False
    
    @staticmethod
    def get_evidence(payload: str, response_text: str, callback_received: bool = False) -> str:
        """Get evidence of blind XSS vulnerability"""
        if callback_received:
            return f"Blind XSS confirmed: External callback received for payload '{payload[:50]}...'"
        
        if payload in response_text:
            return f"Potential blind XSS: Payload '{payload[:50]}...' reflected in response and may execute in stored context"
        
        return f"Possible blind XSS: Payload '{payload[:50]}...' submitted to potentially stored context"
    
    @staticmethod
    def get_response_snippet(payload: str, response_text: str, max_length: int = 300) -> str:
        """Get relevant response snippet"""
        if payload in response_text:
            # Find the payload in response and return surrounding context
            payload_index = response_text.find(payload)
            start = max(0, payload_index - 100)
            end = min(len(response_text), payload_index + len(payload) + 100)
            snippet = response_text[start:end]
            
            if len(snippet) > max_length:
                snippet = snippet[:max_length] + "..."
            
            return snippet
        
        # Return first part of response if payload not found
        return response_text[:max_length] + ("..." if len(response_text) > max_length else "")
    
    @staticmethod
    def get_evidence(payload: str, response_text: str, callback_received: bool) -> str:
        """Get evidence for blind XSS"""
        if callback_received:
            return f"Blind XSS confirmed: callback received for payload {payload[:50]}"
        else:
            return f"Potential blind XSS: payload {payload[:50]} injected, monitoring for callback"
    
    @staticmethod
    def get_response_snippet(payload: str, response_text: str) -> str:
        """Get response snippet for blind XSS"""
        if len(response_text) > 300:
            return response_text[:300] + "..."
        return response_text
