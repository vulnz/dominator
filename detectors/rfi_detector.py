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
            'test_rfi_payload',
            # P0wny shell specific indicators
            '<div id="shell-logo">',
            'p0wny@shell',
            '___                         ____      _          _ _        _  _',
            'p0wny shell',
            '| \'_ \\| | | |\\ \\ /\\ / / \'_ \\| | | |/ / _` / __| \'_ \\ / _ \\ | (_)/\\/_  ..  _|'
        ]
    
    @staticmethod
    def get_p0wny_shell_url() -> str:
        """Get p0wny shell URL for testing"""
        return 'https://raw.githubusercontent.com/flozz/p0wny-shell/refs/heads/master/shell.php'
    
    @staticmethod
    def detect_rfi(response_text: str, response_code: int, payload: str) -> bool:
        """Detect RFI vulnerability with enhanced p0wny shell detection"""
        if response_code >= 500:
            return False
        
        # Check if response is too short to contain meaningful RFI content
        if len(response_text.strip()) < 20:
            return False
            
        response_lower = response_text.lower()
        payload_lower = payload.lower()
        
        # Check if payload contains URL
        if not any(protocol in payload_lower for protocol in ['http://', 'https://', 'ftp://']):
            return False
        
        # High confidence p0wny shell indicators
        p0wny_indicators = [
            '<div id="shell-logo">',
            'p0wny@shell',
            '___                         ____      _          _ _        _  _',
            'p0wny shell'
        ]
        
        # Check for p0wny shell specific indicators (highest confidence)
        p0wny_matches = 0
        for indicator in p0wny_indicators:
            if indicator.lower() in response_lower:
                p0wny_matches += 1
        
        # If we find p0wny shell indicators, it's definitely RFI
        if p0wny_matches >= 2:
            return True
        
        # Check for single strong p0wny indicator
        if '<div id="shell-logo">' in response_text:
            return True
        
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
        if strong_found >= 1:
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
        
        # Require multiple weak indicators for positive detection
        if weak_found >= 2:
            return True
                
        return False
    
    @staticmethod
    def get_evidence(payload: str, response_text: str) -> str:
        """Get evidence of RFI vulnerability"""
        # Check for p0wny shell first
        if '<div id="shell-logo">' in response_text:
            return f"RFI detected with p0wny shell execution! Payload: '{payload}'. Shell interface loaded successfully."
        
        p0wny_indicators = ['p0wny@shell', 'p0wny shell', '___                         ____']
        found_p0wny = [ind for ind in p0wny_indicators if ind.lower() in response_text.lower()]
        
        if found_p0wny:
            return f"RFI detected with p0wny shell indicators! Payload: '{payload}'. Found: {', '.join(found_p0wny)}"
        
        # Check for other indicators
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
        # Prioritize p0wny shell content
        if '<div id="shell-logo">' in response_text:
            logo_pos = response_text.find('<div id="shell-logo">')
            start = max(0, logo_pos - 50)
            end = min(len(response_text), logo_pos + 500)
            return response_text[start:end]
        
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
    
    @staticmethod
    def get_remediation_advice() -> str:
        """Get remediation advice for RFI vulnerabilities"""
        return (
            "Disable remote file inclusion in PHP (allow_url_include=Off). "
            "Validate and sanitize all file inclusion parameters. "
            "Use whitelist of allowed files. Implement proper input validation. "
            "Consider using absolute paths and avoiding user-controlled file inclusion."
        )
    
