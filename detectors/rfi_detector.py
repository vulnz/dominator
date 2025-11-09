"""
Remote File Inclusion (RFI) vulnerability detection logic
"""

import re
from typing import Tuple, List, Dict, Any

class RFIDetector:
    """Remote File Inclusion vulnerability detection logic"""
    
    @staticmethod
    def get_rfi_test_urls() -> List[str]:
        """Get list of RFI test URLs to check for successful inclusion"""
        return [
            'https://raw.githubusercontent.com/flozz/p0wny-shell/refs/heads/master/shell.php',
            'http://www.google.com/humans.txt',
            'https://httpbin.org/robots.txt',
            'http://example.com/robots.txt'
        ]
    
    @staticmethod
    def get_shell_indicators() -> List[str]:
        """Get indicators that suggest a web shell was successfully included"""
        return [
            # p0wny shell specific indicators (highest priority)
            'p0wny@shell',
            '$SHELL_CONFIG',
            'featureShell',
            'executeCommand',
            'p0wny',
            'shell-prompt',
            'shell-content',
            'shell-input',
            '<div id="shell-logo">',
            '___                         ____      _          _ _        _  _',
            'p0wny shell',
            
            # Generic web shell indicators
            'web shell',
            'webshell',
            'shell_exec',
            'system(',
            'exec(',
            'passthru(',
            'proc_open',
            'popen(',
            
            # Command execution indicators
            'cmd=',
            'command=',
            'execute',
            'terminal',
            'console',
            
            # File system indicators
            'getcwd()',
            'chdir(',
            'file_get_contents',
            'fopen(',
            'readfile(',
            
            # PHP shell indicators
            '<?php',
            'php_uname',
            'phpinfo',
            'eval(',
            'base64_decode'
        ]
    
    @staticmethod
    def get_remote_content_indicators() -> List[str]:
        """Get indicators of successful remote content inclusion"""
        return [
            # HTML structure from remote sites
            '<!DOCTYPE html>',
            '<html',
            '<head>',
            '<body>',
            '<title>',
            
            # Common remote file contents
            'User-agent:',
            'Disallow:',
            'Allow:',
            'Sitemap:',
            
            # HTTP response indicators
            'HTTP/',
            'Content-Type:',
            'Server:',
            
            # Remote script indicators
            '<script',
            'javascript:',
            'function(',
            'var ',
            'const ',
            'let ',
            
            # CSS indicators
            '<style',
            'css',
            'font-family',
            'background',
            
            # External service indicators
            'google',
            'github',
            'httpbin',
            'example.com'
        ]
    
    @staticmethod
    def detect_rfi(response_text: str, response_code: int, payload: str, 
                   baseline_content: str = "", baseline_length: int = 0) -> Tuple[bool, str, str]:
        """
        Enhanced RFI detection with shell detection priority
        
        Args:
            response_text: HTTP response content
            response_code: HTTP response status code
            payload: RFI payload used
            baseline_content: Original page content for comparison
            baseline_length: Original page content length
            
        Returns:
            Tuple of (is_vulnerable, evidence, severity)
        """
        try:
            # Skip error responses
            if response_code >= 400:
                return False, "Error response", "None"
            
            # Check for significant content change
            if baseline_length > 0:
                content_diff = abs(len(response_text) - baseline_length)
                if content_diff < 50:  # Minimal content change
                    return False, "No significant content change", "None"
            
            response_lower = response_text.lower()
            baseline_lower = baseline_content.lower() if baseline_content else ""
            
            # Priority 1: Check for web shell indicators (Critical severity)
            shell_indicators = RFIDetector.get_shell_indicators()
            shell_matches = []
            
            for indicator in shell_indicators:
                if indicator.lower() in response_lower:
                    # Ensure it's not in the baseline (new content)
                    if not baseline_lower or indicator.lower() not in baseline_lower:
                        shell_matches.append(indicator)
            
            if len(shell_matches) >= 2:  # Require multiple shell indicators
                evidence = f"Web shell detected - indicators found: {', '.join(shell_matches[:5])}"
                return True, evidence, "Critical"
            
            # Special case: p0wny shell logo is definitive
            if '<div id="shell-logo">' in response_text:
                evidence = "p0wny shell successfully included - shell interface loaded"
                return True, evidence, "Critical"
            
            # Priority 2: Check for remote content inclusion (High severity)
            remote_indicators = RFIDetector.get_remote_content_indicators()
            remote_matches = []
            
            for indicator in remote_indicators:
                if indicator.lower() in response_lower:
                    # Ensure it's not in the baseline
                    if not baseline_lower or indicator.lower() not in baseline_lower:
                        remote_matches.append(indicator)
            
            if len(remote_matches) >= 3:  # Require multiple remote indicators
                evidence = f"Remote content inclusion detected - indicators: {', '.join(remote_matches[:5])}"
                return True, evidence, "High"
            
            # Priority 3: Check for URL reflection in response (Medium severity)
            if payload.startswith(('http://', 'https://', 'ftp://')):
                # Extract domain from payload
                try:
                    from urllib.parse import urlparse
                    parsed_url = urlparse(payload)
                    domain = parsed_url.netloc
                    
                    if domain and domain in response_text:
                        # Check if domain wasn't in baseline
                        if not baseline_lower or domain not in baseline_lower:
                            evidence = f"Remote URL reflected in response: {domain}"
                            return True, evidence, "Medium"
                except:
                    pass
            
            # Priority 4: Check for specific error messages that indicate RFI attempt
            rfi_error_patterns = [
                'failed to open stream',
                'no such file or directory',
                'permission denied',
                'connection refused',
                'could not resolve host',
                'network is unreachable',
                'include_path',
                'allow_url_include',
                'allow_url_fopen'
            ]
            
            error_matches = []
            for pattern in rfi_error_patterns:
                if pattern in response_lower:
                    if not baseline_lower or pattern not in baseline_lower:
                        error_matches.append(pattern)
            
            if len(error_matches) >= 1 and payload.startswith(('http://', 'https://')):
                evidence = f"RFI attempt detected - error patterns: {', '.join(error_matches)}"
                return True, evidence, "Low"
            
            return False, "No RFI indicators found", "None"
            
        except Exception as e:
            return False, f"Detection error: {e}", "None"
    
    @staticmethod
    def get_evidence(payload: str, response_text: str, shell_url: str = "") -> str:
        """Generate detailed evidence for RFI vulnerability"""
        evidence_parts = []
        
        if shell_url:
            evidence_parts.append(f"Remote shell URL: {shell_url}")
        
        evidence_parts.append(f"RFI payload: {payload}")
        
        # Find specific indicators in response
        shell_indicators = RFIDetector.get_shell_indicators()
        found_indicators = []
        
        response_lower = response_text.lower()
        for indicator in shell_indicators[:10]:  # Limit to first 10 matches
            if indicator.lower() in response_lower:
                found_indicators.append(indicator)
        
        if found_indicators:
            evidence_parts.append(f"Shell indicators found: {', '.join(found_indicators)}")
        
        # Check response size
        if len(response_text) > 1000:
            evidence_parts.append(f"Large response size: {len(response_text)} bytes")
        
        return " | ".join(evidence_parts)
    
    @staticmethod
    def get_response_snippet(payload: str, response_text: str, max_length: int = 300) -> str:
        """Get relevant response snippet for RFI detection"""
        if not response_text:
            return "Empty response"
        
        # Try to find shell-specific content first
        shell_indicators = ['p0wny', 'shell-prompt', 'executeCommand', 'featureShell', '<div id="shell-logo">']
        
        for indicator in shell_indicators:
            pos = response_text.lower().find(indicator.lower())
            if pos >= 0:
                start = max(0, pos - 50)
                end = min(len(response_text), pos + len(indicator) + 100)
                snippet = response_text[start:end]
                return f"...{snippet}..." if start > 0 or end < len(response_text) else snippet
        
        # Fallback to beginning of response
        snippet = response_text[:max_length]
        return snippet + "..." if len(response_text) > max_length else snippet
    
    @staticmethod
    def get_remediation_advice() -> str:
        """Get remediation advice for RFI vulnerabilities"""
        return (
            "1. Disable remote file inclusion (allow_url_include = Off in php.ini). "
            "2. Validate and sanitize all file path inputs using whitelisting. "
            "3. Use absolute paths and avoid user-controlled file paths. "
            "4. Implement proper input validation and filtering. "
            "5. Use secure coding practices for file operations."
        )
    
