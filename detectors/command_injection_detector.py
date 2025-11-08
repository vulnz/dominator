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
        """Get remediation advice for command injection vulnerabilities"""
        return (
            "Never execute user input directly as system commands. "
            "Use parameterized APIs instead of shell commands where possible. "
            "If shell commands are necessary, use proper input validation and sanitization. "
            "Run applications with minimal privileges and use sandboxing."
        )
import re
from typing import List, Dict, Any, Tuple

class CommandInjectionDetector:
    """Command Injection vulnerability detection logic optimized for XVWA"""
    
    @staticmethod
    def get_command_indicators() -> List[str]:
        """Get command injection indicators commonly found in XVWA"""
        return [
            # Linux/Unix command indicators
            'uid=', 'gid=', 'groups=',
            'root:x:0:0:', 'daemon:x:1:1:', 'bin:x:2:2:',
            'Linux', 'GNU/Linux', 'Ubuntu',
            'total ', 'drwx', '-rw-', '-rwx',
            'PID', 'TTY', 'TIME', 'CMD',
            '/bin/bash', '/bin/sh', '/usr/bin/',
            'Permission denied', 'No such file or directory',
            'command not found', 'bash:', 'sh:',
            
            # Windows command indicators
            'Volume in drive', 'Directory of',
            'Windows NT', 'Microsoft Windows',
            'SYSTEM', 'Administrator',
            'C:\\Windows', 'C:\\Program Files',
            'The system cannot find', 'Access is denied',
            'is not recognized as an internal or external command',
            
            # Network command indicators
            'PING', 'ping statistics', 'packets transmitted',
            'Tracing route to', 'traceroute to',
            'nslookup', 'Non-authoritative answer:',
            
            # File system indicators
            'etc/passwd', 'etc/shadow', 'etc/hosts',
            'boot.ini', 'win.ini', 'system.ini'
        ]

    @staticmethod
    def detect_command_injection(payload: str, response_text: str, response_code: int) -> Tuple[bool, str, str, Dict[str, Any]]:
        """Enhanced command injection detection for XVWA"""
        if response_code not in [200, 201, 202, 500, 400, 403]:
            return False, "", "", {}

        indicators = CommandInjectionDetector.get_command_indicators()
        
        # Check for command execution indicators in response
        found_indicators = []
        for indicator in indicators:
            if indicator.lower() in response_text.lower():
                found_indicators.append(indicator)
        
        if found_indicators:
            evidence = f"Command injection indicators found: {', '.join(found_indicators[:3])}"
            if len(found_indicators) > 3:
                evidence += f" and {len(found_indicators) - 3} more"
            
            return True, evidence, "Critical", {
                'cwe': 'CWE-78',
                'cvss': '9.8',
                'owasp': 'A03:2021 – Injection',
                'recommendation': 'Avoid executing system commands with user input. Use parameterized APIs and input validation.'
            }

        # Check for specific command injection patterns
        injection_patterns = [
            r'uid=\d+\(.*?\)\s+gid=\d+\(.*?\)',
            r'total\s+\d+.*?drwx.*?-rw-.*?',
            r'PID\s+TTY\s+TIME\s+CMD',
            r'Volume in drive [A-Z] is.*?Directory of',
            r'ping statistics.*?packets transmitted',
            r'root:x:0:0:.*?:/bin/bash',
            r'Windows NT.*?Microsoft Windows'
        ]
        
        for pattern in injection_patterns:
            if re.search(pattern, response_text, re.IGNORECASE | re.DOTALL):
                return True, f"Command injection pattern detected: {pattern}", "Critical", {
                    'cwe': 'CWE-78',
                    'cvss': '9.8',
                    'owasp': 'A03:2021 – Injection',
                    'recommendation': 'Avoid executing system commands with user input. Use parameterized APIs and input validation.'
                }

        return False, "", "", {}

    @staticmethod
    def _determine_severity(indicators: List[str]) -> Tuple[str, str]:
        """Determine severity based on found indicators"""
        critical_indicators = [
            'uid=', 'gid=', 'root:x:0:0:', '/etc/passwd',
            'Administrator', 'SYSTEM', 'C:\\Windows\\System32'
        ]
        
        high_indicators = [
            'Linux', 'Windows NT', 'Microsoft Windows',
            'ping statistics', 'PID', 'TTY', 'CMD'
        ]
        
        for indicator in indicators:
            if any(critical in indicator.lower() for critical in critical_indicators):
                return "Critical", "9.8"
        
        for indicator in indicators:
            if any(high in indicator.lower() for high in high_indicators):
                return "High", "8.8"
        
        return "Medium", "6.5"
