"""
Enhanced SSRF detector for testphp.vulnweb.com
Specifically designed to detect SSRF in showimage.php and similar endpoints
"""

import re
from typing import List, Dict, Tuple, Any

class SSRFEnhancedDetector:
    """Enhanced SSRF vulnerability detection logic"""
    
    @staticmethod
    def detect_ssrf(response_text: str, response_code: int, payload: str, url: str) -> Tuple[bool, str, str]:
        """
        Enhanced SSRF detection for testphp.vulnweb.com
        
        Args:
            response_text: HTTP response content
            response_code: HTTP response status code
            payload: The payload used in the request
            url: The request URL
            
        Returns:
            Tuple[bool, str, str]: (is_vulnerable, evidence, severity)
        """
        # SSRF indicators for testphp.vulnweb.com
        ssrf_indicators = [
            # Internal network responses
            '127.0.0.1',
            'localhost',
            '192.168.',
            '10.',
            '172.16.', '172.17.', '172.18.', '172.19.',
            '172.20.', '172.21.', '172.22.', '172.23.',
            '172.24.', '172.25.', '172.26.', '172.27.',
            '172.28.', '172.29.', '172.30.', '172.31.',
            
            # Service banners
            'SSH-2.0',
            'SSH-1.99',
            'OpenSSH',
            'HTTP/1.1',
            'HTTP/1.0',
            'Server:',
            'Apache',
            'nginx',
            'IIS',
            
            # Port scan responses
            'Connection refused',
            'Connection timeout',
            'No route to host',
            'Network is unreachable',
            'Connection reset',
            
            # Protocol responses
            'SMTP',
            'POP3',
            'IMAP',
            'FTP',
            '220 ',
            '250 ',
            '+OK',
            
            # File protocol
            'file://',
            'gopher://',
            'dict://',
            'ldap://',
            'tftp://',
            
            # Cloud metadata
            'metadata',
            'instance-data',
            'user-data',
            'ami-id',
            'instance-id',
            
            # Error messages indicating SSRF attempt
            'curl error',
            'file_get_contents',
            'fsockopen',
            'stream_socket_client',
            'Invalid URL',
            'URL not allowed',
        ]
        
        # Time-based SSRF indicators
        time_indicators = [
            'timeout',
            'timed out',
            'connection timeout',
            'read timeout',
            'execution time',
        ]
        
        # Check for direct SSRF indicators
        for indicator in ssrf_indicators:
            if indicator in response_text:
                severity = SSRFEnhancedDetector._get_severity(indicator, payload)
                return True, f"SSRF detected - Response contains: {indicator}", severity
        
        # Check for time-based SSRF
        for indicator in time_indicators:
            if indicator.lower() in response_text.lower():
                return True, f"Potential SSRF detected - Time-based indicator: {indicator}", "Medium"
        
        # Check for specific testphp.vulnweb.com patterns
        if 'showimage.php' in url and 'file=' in url:
            # Check for successful internal requests
            if response_code == 200 and len(response_text) > 0:
                # Look for signs of internal service responses
                if any(pattern in payload for pattern in ['127.0.0.1', 'localhost', '192.168.']):
                    if len(response_text) > 10:  # Got some response
                        return True, "SSRF detected - Internal network access successful", "High"
        
        # Check for error messages that indicate SSRF attempt
        error_patterns = [
            r'failed to open stream.*HTTP request failed',
            r'file_get_contents.*failed to open stream',
            r'curl.*couldn\'t connect to host',
            r'fsockopen.*connection refused',
            r'Invalid URL.*not allowed',
        ]
        
        for pattern in error_patterns:
            if re.search(pattern, response_text, re.IGNORECASE):
                return True, f"SSRF attempt detected - Error pattern: {pattern}", "Medium"
        
        # Check for successful HTTP responses from internal services
        if payload.startswith(('http://127.0.0.1', 'http://localhost', 'http://192.168.')):
            if 'HTTP/' in response_text or '<html' in response_text.lower():
                return True, "SSRF detected - HTTP response from internal service", "High"
        
        return False, "", ""
    
    @staticmethod
    def _get_severity(indicator: str, payload: str) -> str:
        """Determine severity based on indicator and payload"""
        high_risk_indicators = [
            '127.0.0.1', 'localhost', 'SSH-2.0', 'metadata', 'instance-data'
        ]
        
        medium_risk_indicators = [
            '192.168.', '10.', '172.', 'Connection refused', 'timeout'
        ]
        
        if any(high_risk in indicator for high_risk in high_risk_indicators):
            return "High"
        elif any(medium_risk in indicator for medium_risk in medium_risk_indicators):
            return "Medium"
        else:
            return "Low"
    
    @staticmethod
    def get_evidence(indicator: str, response_text: str, payload: str) -> str:
        """Get detailed evidence for SSRF"""
        evidence = f"SSRF vulnerability detected - Indicator: {indicator}"
        
        # Add payload information
        evidence += f" - Payload: {payload}"
        
        # Add context around the indicator
        if indicator in response_text:
            start_pos = response_text.find(indicator)
            if start_pos >= 0:
                context_start = max(0, start_pos - 30)
                context_end = min(len(response_text), start_pos + len(indicator) + 30)
                context = response_text[context_start:context_end].replace('\n', ' ').replace('\r', ' ')
                evidence += f" - Context: ...{context}..."
        
        return evidence
    
    @staticmethod
    def get_response_snippet(response_text: str, max_length: int = 200) -> str:
        """Get response snippet for reporting"""
        if len(response_text) <= max_length:
            return response_text
        
        return response_text[:max_length] + "..."
    
    @staticmethod
    def get_remediation_advice() -> str:
        """Get remediation advice for SSRF vulnerabilities"""
        return (
            "1. Validate and whitelist allowed URLs/domains\n"
            "2. Disable unnecessary URL schemes (file://, gopher://, etc.)\n"
            "3. Implement network-level restrictions\n"
            "4. Use DNS resolution restrictions\n"
            "5. Validate response content types\n"
            "6. Implement timeout controls\n"
            "7. Log and monitor outbound requests"
        )
    
    @staticmethod
    def get_ssrf_payloads() -> List[str]:
        """Get SSRF-specific payloads for testphp.vulnweb.com"""
        return [
            # Internal network
            'http://127.0.0.1',
            'http://localhost',
            'http://127.0.0.1:22',
            'http://127.0.0.1:80',
            'http://127.0.0.1:443',
            'http://127.0.0.1:3306',
            'http://127.0.0.1:8080',
            'http://localhost:22',
            'http://localhost:80',
            
            # Private networks
            'http://192.168.1.1',
            'http://192.168.0.1',
            'http://10.0.0.1',
            'http://172.16.0.1',
            
            # File protocol
            'file:///etc/passwd',
            'file:///windows/win.ini',
            'file://localhost/etc/passwd',
            
            # Other protocols
            'gopher://127.0.0.1:22',
            'dict://127.0.0.1:11211',
            'ldap://127.0.0.1',
            
            # Cloud metadata
            'http://169.254.169.254/latest/meta-data/',
            'http://metadata.google.internal/computeMetadata/v1/',
            
            # Bypass attempts
            'http://127.1',
            'http://0.0.0.0',
            'http://[::1]',
            'http://127.0.0.1.xip.io',
            
            # URL encoding
            'http://127.0.0.1%2F',
            'http://127.0.0.1%3A22',
            
            # Decimal/Hex encoding
            'http://2130706433',  # 127.0.0.1 in decimal
            'http://0x7f000001',  # 127.0.0.1 in hex
        ]
