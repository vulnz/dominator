"""
Remote File Inclusion (RFI) vulnerability detection logic
"""

class RFIDetector:
    """RFI vulnerability detection logic"""
    
    @staticmethod
    def get_rfi_indicators() -> list:
        """Get RFI response indicators"""
        return [
            # PHP code execution indicators
            '<?php',
            '<?=',
            'eval(',
            'system(',
            'exec(',
            'shell_exec(',
            'passthru(',
            # Remote file inclusion success indicators
            'include(',
            'require(',
            'include_once(',
            'require_once(',
            # Error messages
            'failed to open stream',
            'no such file or directory',
            'permission denied',
            'connection refused',
            'getaddrinfo failed',
            # Remote content indicators
            'http://',
            'https://',
            'ftp://',
            # Common remote file contents
            'netsparker',
            'acunetix',
            'test_rfi_payload'
        ]
    
    @staticmethod
    def detect_rfi(response_text: str, response_code: int, payload: str) -> bool:
        """Detect RFI vulnerability"""
        if response_code >= 500:
            return False
        
        # Check if response is too short to contain meaningful RFI content
        if len(response_text.strip()) < 20:
            return False
            
        response_lower = response_text.lower()
        
        # Strong RFI indicators (high confidence)
        strong_indicators = [
            '<?php', 'eval(', 'system(', 'exec(', 'shell_exec(',
            'netsparker', 'acunetix', 'test_rfi_payload'
        ]
        
        # Check for strong indicators first
        strong_found = 0
        for indicator in strong_indicators:
            if indicator in response_lower:
                strong_found += 1
        
        # If we have strong indicators and the payload contains URL, likely RFI
        if strong_found >= 1 and ('http://' in payload.lower() or 'https://' in payload.lower()):
            return True
        
        # Check for multiple weaker indicators
        weak_indicators = [
            'include(', 'require(', 'include_once(', 'require_once(',
            'failed to open stream', 'no such file or directory',
            'permission denied', 'connection refused'
        ]
        
        weak_found = 0
        for indicator in weak_indicators:
            if indicator in response_lower:
                weak_found += 1
        
        # Require multiple weak indicators AND URL in payload
        if weak_found >= 2 and ('http://' in payload.lower() or 'https://' in payload.lower()):
            return True
                
        return False
    
    @staticmethod
    def get_evidence(payload: str, response_text: str) -> str:
        """Get evidence of RFI vulnerability"""
        indicators = RFIDetector.get_rfi_indicators()
        response_lower = response_text.lower()
        
        found_indicators = []
        for indicator in indicators:
            if indicator in response_lower:
                found_indicators.append(indicator)
        
        if found_indicators:
            return f"RFI detected with payload '{payload}'. Found indicators: {', '.join(found_indicators[:3])}"
        
        return f"Possible RFI with payload '{payload}'. Remote file inclusion attempted."
    
    @staticmethod
    def get_response_snippet(payload: str, response_text: str, max_length: int = 300) -> str:
        """Get response snippet for evidence"""
        if len(response_text) <= max_length:
            return response_text
        
        # Try to find relevant part of response
        indicators = RFIDetector.get_rfi_indicators()
        response_lower = response_text.lower()
        
        for indicator in indicators:
            pos = response_lower.find(indicator)
            if pos != -1:
                start = max(0, pos - 50)
                end = min(len(response_text), pos + max_length - 50)
                return response_text[start:end]
        
        return response_text[:max_length]
