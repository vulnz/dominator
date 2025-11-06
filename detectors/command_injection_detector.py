"""
Command Injection vulnerability detection logic
"""

import re
from typing import Tuple, List, Dict, Any

class CommandInjectionDetector:
    """Command Injection vulnerability detection logic"""
    
    @staticmethod
    def get_command_indicators() -> List[str]:
        """Get command injection indicators"""
        return [
            'uid=', 'gid=', 'groups=',  # id command output
            'total ', 'drwx', '-rw-',   # ls command output
            'root:', 'bin:', 'daemon:', # /etc/passwd content
            'PING ', 'ping statistics', # ping command output
            'Directory of C:\\', 'Volume in drive', # Windows dir command
            'Microsoft Windows', 'Copyright (c)', # Windows ver command
            'Linux', 'GNU/', 'kernel',  # uname output
            'command not found', 'is not recognized',
            'syntax error', 'unexpected token',
            '/bin/sh', '/bin/bash', 'cmd.exe'
        ]
    
    @staticmethod
    def detect_command_injection(response_text: str, response_code: int, payload: str) -> bool:
        """
        Detect command injection vulnerability
        Returns True if command injection is detected
        """
        if response_code >= 500:
            return False
        
        response_lower = response_text.lower()
        indicators = CommandInjectionDetector.get_command_indicators()
        
        # Check for command output indicators
        found_indicators = 0
        for indicator in indicators:
            if indicator.lower() in response_lower:
                found_indicators += 1
        
        # Need multiple indicators for confidence
        if found_indicators >= 2:
            return True
        
        # Check for specific command outputs
        command_patterns = [
            r'uid=\d+.*gid=\d+',  # id command
            r'total \d+',         # ls -l command
            r'PING .* \(\d+\.\d+\.\d+\.\d+\)',  # ping command
            r'Directory of [A-Z]:\\',  # Windows dir
            r'Linux.*\d+\.\d+\.\d+',   # uname -a
        ]
        
        for pattern in command_patterns:
            if re.search(pattern, response_text, re.IGNORECASE):
                return True
        
        return False
    
    @staticmethod
    def get_evidence(payload: str, response_text: str) -> str:
        """Get evidence of command injection vulnerability"""
        indicators = CommandInjectionDetector.get_command_indicators()
        found_indicators = []
        
        response_lower = response_text.lower()
        for indicator in indicators:
            if indicator.lower() in response_lower:
                found_indicators.append(indicator)
        
        if found_indicators:
            return f"Command injection detected. Found command output: {', '.join(found_indicators[:3])}"
        
        return "Command injection vulnerability detected based on response patterns"
    
    @staticmethod
    def get_response_snippet(payload: str, response_text: str) -> str:
        """Get relevant response snippet"""
        # Look for command output patterns
        patterns = [
            r'uid=\d+.*gid=\d+.*',
            r'total \d+.*',
            r'PING .*',
            r'Directory of .*',
            r'Linux.*\d+\.\d+\.\d+.*'
        ]
        
        for pattern in patterns:
            match = re.search(pattern, response_text, re.IGNORECASE)
            if match:
                start = max(0, match.start() - 20)
                end = min(len(response_text), match.end() + 100)
                return response_text[start:end]
        
        return response_text[:200]
    
    @staticmethod
    def get_evidence(payload: str, response_text: str) -> str:
        """Get evidence for command injection"""
        evidence_parts = []
        
        # Check for command output
        if 'uid=' in response_text and 'gid=' in response_text:
            evidence_parts.append("Unix command output detected (id command)")
        elif 'Volume in drive' in response_text:
            evidence_parts.append("Windows command output detected (dir command)")
        elif 'total ' in response_text and 'drwx' in response_text:
            evidence_parts.append("Unix ls command output detected")
        elif 'root:' in response_text:
            evidence_parts.append("System file access detected")
        
        if evidence_parts:
            return f"Command injection detected: {'; '.join(evidence_parts)}"
        else:
            return f"Potential command injection with payload: {payload}"
    
    @staticmethod
    def get_response_snippet(payload: str, response_text: str) -> str:
        """Get response snippet for command injection"""
        # Look for command output
        lines = response_text.split('\n')
        relevant_lines = []
        
        for line in lines[:15]:
            if any(indicator in line for indicator in ['uid=', 'Volume in drive', 'total ', 'root:']):
                relevant_lines.append(line.strip())
        
        if relevant_lines:
            snippet = '\n'.join(relevant_lines[:8])
            if len(snippet) > 400:
                return snippet[:400] + "..."
            return snippet
        
        if len(response_text) > 300:
            return response_text[:300] + "..."
        return response_text
    
    @staticmethod
    def get_remediation_advice() -> str:
        """Get remediation advice for command injection"""
        return (
            "Use parameterized commands and avoid shell execution. "
            "Implement input validation and sanitization. "
            "Use whitelisting for allowed commands and parameters."
        )
    
    @staticmethod
    def get_remediation_advice() -> str:
        """Get remediation advice for command injection vulnerabilities"""
        return (
            "Never execute user input directly as system commands. "
            "Use parameterized APIs instead of shell commands where possible. "
            "If shell commands are necessary, use proper input validation and sanitization. "
            "Run applications with minimal privileges and use sandboxing."
        )
