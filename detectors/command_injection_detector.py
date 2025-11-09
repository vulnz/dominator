"""
Enhanced Command Injection vulnerability detection with false positive filtering
"""

import re
import time
from typing import Tuple, List, Dict, Any

class CommandInjectionDetector:
    """Enhanced Command Injection vulnerability detection logic"""
    
    @staticmethod
    def detect_command_injection(response_text: str, response_code: int, payload: str) -> Tuple[bool, float, str]:
        """
        Enhanced command injection detection with confidence scoring
        Returns: (is_vulnerable, confidence_score, evidence)
        """
        try:
            # Skip error responses that are likely unrelated
            if response_code >= 500:
                return False, 0.0, "Server error response"
            
            # Get command output indicators with confidence scores
            indicators = CommandInjectionDetector.get_command_indicators()
            
            # Calculate confidence based on multiple factors
            confidence_factors = []
            evidence_parts = []
            
            # Check for specific command output patterns
            response_lower = response_text.lower()
            
            for category, patterns in indicators.items():
                category_matches = 0
                for pattern in patterns:
                    if pattern['pattern'].lower() in response_lower:
                        confidence_factors.append(pattern['confidence'])
                        evidence_parts.append(f"{category}: {pattern['description']}")
                        category_matches += 1
                        
                        # Bonus for multiple matches in same category
                        if category_matches > 1:
                            confidence_factors.append(0.1)
            
            # Check payload-specific indicators
            payload_confidence = CommandInjectionDetector._analyze_payload_response(payload, response_text)
            if payload_confidence > 0:
                confidence_factors.append(payload_confidence)
                evidence_parts.append("Payload-specific command output detected")
            
            # Filter out potential false positives
            if CommandInjectionDetector._is_likely_false_positive(response_text, payload):
                # Reduce confidence for potential false positives
                confidence_factors = [c * 0.5 for c in confidence_factors]
                evidence_parts.append("Potential false positive detected - confidence reduced")
            
            # Calculate final confidence
            if not confidence_factors:
                return False, 0.0, "No command execution indicators found"
            
            # Average confidence with bonus for multiple indicators
            base_confidence = sum(confidence_factors) / len(confidence_factors)
            multiple_indicator_bonus = min(0.3, (len(confidence_factors) - 1) * 0.05)
            final_confidence = min(1.0, base_confidence + multiple_indicator_bonus)
            
            evidence = "; ".join(evidence_parts[:5])  # Limit evidence length
            
            return final_confidence >= 0.5, final_confidence, evidence
            
        except Exception as e:
            return False, 0.0, f"Detection error: {e}"
    
    @staticmethod
    def get_command_indicators() -> Dict[str, List[Dict[str, Any]]]:
        """Get command execution indicators with confidence scores"""
        return {
            'unix_user_info': [
                {'pattern': 'uid=', 'confidence': 0.95, 'description': 'Unix user ID output'},
                {'pattern': 'gid=', 'confidence': 0.95, 'description': 'Unix group ID output'},
                {'pattern': 'groups=', 'confidence': 0.85, 'description': 'Unix groups output'},
                {'pattern': 'root:x:0:0:', 'confidence': 0.98, 'description': '/etc/passwd root entry'},
                {'pattern': 'bin:x:1:1:', 'confidence': 0.95, 'description': '/etc/passwd bin entry'},
                {'pattern': 'daemon:x:1:1:', 'confidence': 0.95, 'description': '/etc/passwd daemon entry'},
            ],
            
            'unix_system_info': [
                {'pattern': 'linux', 'confidence': 0.4, 'description': 'Linux system identifier'},
                {'pattern': 'kernel', 'confidence': 0.6, 'description': 'Kernel information'},
                {'pattern': 'gnu/linux', 'confidence': 0.8, 'description': 'GNU/Linux identifier'},
                {'pattern': 'ubuntu', 'confidence': 0.7, 'description': 'Ubuntu system'},
                {'pattern': 'debian', 'confidence': 0.7, 'description': 'Debian system'},
                {'pattern': 'centos', 'confidence': 0.7, 'description': 'CentOS system'},
                {'pattern': 'red hat', 'confidence': 0.7, 'description': 'Red Hat system'},
            ],
            
            'unix_file_system': [
                {'pattern': 'total ', 'confidence': 0.7, 'description': 'ls command total line'},
                {'pattern': 'drwx', 'confidence': 0.8, 'description': 'Directory permissions'},
                {'pattern': '-rw-', 'confidence': 0.7, 'description': 'File permissions'},
                {'pattern': '-rwx', 'confidence': 0.8, 'description': 'Executable permissions'},
                {'pattern': '/bin/', 'confidence': 0.5, 'description': 'Unix binary path'},
                {'pattern': '/usr/', 'confidence': 0.4, 'description': 'Unix system path'},
                {'pattern': '/etc/', 'confidence': 0.5, 'description': 'Unix config path'},
                {'pattern': '/var/', 'confidence': 0.4, 'description': 'Unix variable path'},
            ],
            
            'unix_network': [
                {'pattern': 'eth0', 'confidence': 0.8, 'description': 'Ethernet interface'},
                {'pattern': 'lo:', 'confidence': 0.7, 'description': 'Loopback interface'},
                {'pattern': 'inet addr:', 'confidence': 0.85, 'description': 'IP address info'},
                {'pattern': 'netmask', 'confidence': 0.7, 'description': 'Network mask'},
                {'pattern': 'broadcast', 'confidence': 0.7, 'description': 'Broadcast address'},
            ],
            
            'unix_processes': [
                {'pattern': 'pid', 'confidence': 0.4, 'description': 'Process ID'},
                {'pattern': 'ppid', 'confidence': 0.6, 'description': 'Parent process ID'},
                {'pattern': '/usr/bin/', 'confidence': 0.5, 'description': 'Process binary path'},
                {'pattern': '/sbin/', 'confidence': 0.6, 'description': 'System binary path'},
            ],
            
            'windows_system': [
                {'pattern': 'volume in drive', 'confidence': 0.95, 'description': 'Windows dir command'},
                {'pattern': 'directory of', 'confidence': 0.9, 'description': 'Windows directory listing'},
                {'pattern': 'windows ip configuration', 'confidence': 0.95, 'description': 'ipconfig output'},
                {'pattern': 'c:\\windows\\', 'confidence': 0.8, 'description': 'Windows system path'},
                {'pattern': 'c:\\users\\', 'confidence': 0.8, 'description': 'Windows user path'},
                {'pattern': 'c:\\program files', 'confidence': 0.7, 'description': 'Windows program path'},
                {'pattern': 'microsoft windows', 'confidence': 0.8, 'description': 'Windows system info'},
            ],
            
            'windows_network': [
                {'pattern': 'ping ', 'confidence': 0.5, 'description': 'Ping command output'},
                {'pattern': 'ttl=', 'confidence': 0.8, 'description': 'Ping TTL value'},
                {'pattern': 'reply from', 'confidence': 0.85, 'description': 'Ping reply'},
                {'pattern': 'active connections', 'confidence': 0.9, 'description': 'netstat output'},
                {'pattern': 'tcp ', 'confidence': 0.3, 'description': 'TCP connection'},
                {'pattern': 'udp ', 'confidence': 0.3, 'description': 'UDP connection'},
            ],
            
            'windows_processes': [
                {'pattern': 'image name', 'confidence': 0.9, 'description': 'tasklist header'},
                {'pattern': 'session name', 'confidence': 0.8, 'description': 'tasklist session'},
                {'pattern': 'mem usage', 'confidence': 0.8, 'description': 'tasklist memory'},
            ],
            
            'command_errors': [
                {'pattern': 'command not found', 'confidence': 0.8, 'description': 'Unix command error'},
                {'pattern': 'is not recognized as an internal', 'confidence': 0.95, 'description': 'Windows command error'},
                {'pattern': 'permission denied', 'confidence': 0.6, 'description': 'Permission error'},
                {'pattern': 'access denied', 'confidence': 0.6, 'description': 'Access error'},
                {'pattern': 'no such file or directory', 'confidence': 0.5, 'description': 'File not found error'},
            ],
            
            'environment_variables': [
                {'pattern': 'path=', 'confidence': 0.7, 'description': 'PATH environment variable'},
                {'pattern': 'home=', 'confidence': 0.7, 'description': 'HOME environment variable'},
                {'pattern': 'user=', 'confidence': 0.6, 'description': 'USER environment variable'},
                {'pattern': 'shell=', 'confidence': 0.8, 'description': 'SHELL environment variable'},
                {'pattern': 'pwd=', 'confidence': 0.6, 'description': 'PWD environment variable'},
            ]
        }
    
    @staticmethod
    def _analyze_payload_response(payload: str, response_text: str) -> float:
        """Analyze response for payload-specific indicators"""
        confidence = 0.0
        payload_lower = payload.lower()
        response_lower = response_text.lower()
        
        # Check for specific command outputs based on payload
        if 'whoami' in payload_lower:
            # Look for username patterns
            username_patterns = [
                r'\b[a-zA-Z][a-zA-Z0-9_-]{2,15}\b',  # Typical username format
                r'\b(root|admin|administrator|www-data|apache|nginx|nobody)\b'  # Common service users
            ]
            for pattern in username_patterns:
                if re.search(pattern, response_text, re.IGNORECASE):
                    confidence += 0.4
                    break
        
        if 'id' in payload_lower:
            # Look for uid/gid patterns
            if re.search(r'uid=\d+', response_text):
                confidence += 0.5
            if re.search(r'gid=\d+', response_text):
                confidence += 0.4
            if re.search(r'groups=', response_text):
                confidence += 0.3
        
        if 'uname' in payload_lower:
            # Look for system information
            system_keywords = ['linux', 'unix', 'kernel', 'gnu']
            matches = sum(1 for keyword in system_keywords if keyword in response_lower)
            confidence += min(0.4, matches * 0.15)
        
        if 'systeminfo' in payload_lower:
            # Look for Windows system info
            windows_keywords = ['windows', 'microsoft', 'system type', 'processor']
            matches = sum(1 for keyword in windows_keywords if keyword in response_lower)
            confidence += min(0.4, matches * 0.15)
        
        if any(cmd in payload_lower for cmd in ['ls', 'dir']):
            # Look for directory listing patterns
            if re.search(r'\d{4}-\d{2}-\d{2}', response_text):  # Date patterns
                confidence += 0.2
            if re.search(r'[drwx-]{10}', response_text):  # Unix permissions
                confidence += 0.3
            if 'total ' in response_lower:
                confidence += 0.3
        
        if any(net_cmd in payload_lower for net_cmd in ['ifconfig', 'ipconfig']):
            # Look for network configuration
            ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
            if re.search(ip_pattern, response_text):
                confidence += 0.3
            if 'netmask' in response_lower or 'subnet mask' in response_lower:
                confidence += 0.2
        
        if 'ping' in payload_lower:
            # Look for ping output
            if 'ttl=' in response_lower or 'reply from' in response_lower:
                confidence += 0.5
            if 'packets transmitted' in response_lower:
                confidence += 0.4
        
        if any(cmd in payload_lower for cmd in ['ps', 'tasklist']):
            # Look for process listing
            if 'pid' in response_lower:
                confidence += 0.3
            if 'image name' in response_lower:  # Windows tasklist
                confidence += 0.4
        
        return min(1.0, confidence)
    
    @staticmethod
    def _is_likely_false_positive(response_text: str, payload: str) -> bool:
        """Check if response is likely a false positive"""
        response_lower = response_text.lower()
        
        # Common false positive patterns
        false_positive_indicators = [
            # SQL error messages that might contain command-like text
            'you have an error in your sql syntax',
            'mysql_fetch_array',
            'syntax error',
            'near \'',
            'at line 1',
            
            # Generic application errors
            'application error',
            'system error', 
            'internal server error',
            'processing error',
            
            # Debug/development messages
            'debug',
            'stack trace',
            'exception',
            'warning:',
            'notice:',
            
            # HTML/JavaScript content that might contain command-like strings
            '<script',
            '<html',
            'function(',
            'var ',
            'document.',
        ]
        
        # Count false positive indicators
        fp_count = sum(1 for indicator in false_positive_indicators if indicator in response_lower)
        
        # If response has many false positive indicators and is relatively short, likely FP
        if fp_count >= 3 and len(response_text) < 2000:
            return True
        
        # Check if response is primarily HTML/JavaScript
        html_indicators = ['<html', '<body', '<script', '<div', '<span', '<p>']
        html_count = sum(1 for indicator in html_indicators if indicator in response_lower)
        
        if html_count >= 3:
            return True
        
        return False
    
    @staticmethod
    def get_evidence(payload: str, response_text: str, detection_result: Dict[str, Any] = None) -> str:
        """Get detailed evidence for command injection"""
        evidence_parts = []
        
        # Add payload information
        payload_snippet = payload[:100] + ('...' if len(payload) > 100 else '')
        evidence_parts.append(f"Command injection payload: {payload_snippet}")
        
        # Add specific indicators found
        if detection_result and 'indicators' in detection_result:
            evidence_parts.append(f"Indicators found: {', '.join(detection_result['indicators'][:3])}")
        
        # Add response analysis
        response_snippet = response_text[:200].replace('\n', ' ').replace('\r', ' ')
        evidence_parts.append(f"Response contains command output: {response_snippet}")
        
        return "; ".join(evidence_parts)
    
    @staticmethod
    def get_response_snippet(payload: str, response_text: str) -> str:
        """Get relevant response snippet for command injection"""
        # Find the most relevant part of the response
        indicators = CommandInjectionDetector.get_command_indicators()
        
        best_snippet = ""
        best_score = 0
        
        # Split response into chunks and score them
        chunks = [response_text[i:i+400] for i in range(0, len(response_text), 200)]
        
        for chunk in chunks:
            score = 0
            chunk_lower = chunk.lower()
            
            # Score based on command indicators
            for category, patterns in indicators.items():
                for pattern in patterns:
                    if pattern['pattern'].lower() in chunk_lower:
                        score += pattern['confidence']
            
            if score > best_score:
                best_score = score
                best_snippet = chunk
        
        if best_snippet:
            # Clean up the snippet
            snippet = best_snippet.strip()
            snippet = re.sub(r'\s+', ' ', snippet)  # Normalize whitespace
            return snippet
        
        # Fallback to beginning of response
        fallback = response_text[:400]
        fallback = re.sub(r'\s+', ' ', fallback.strip())
        return fallback + ("..." if len(response_text) > 400 else "")
    
    @staticmethod
    def get_remediation_advice() -> str:
        """Get remediation advice for command injection"""
        return (
            "Avoid executing system commands with user input. "
            "Use parameterized APIs and input validation. "
            "Implement proper sandboxing and least privilege principles. "
            "Consider using safe alternatives to system commands."
        )
    
    @staticmethod
    def is_time_based_payload(payload: str) -> bool:
        """Check if payload is time-based for blind detection"""
        time_commands = ['sleep', 'timeout', 'ping']
        return any(cmd in payload.lower() for cmd in time_commands)
    
    @staticmethod
    def measure_response_time(start_time: float, end_time: float, payload: str) -> Tuple[bool, str]:
        """Measure response time for time-based detection"""
        response_time = end_time - start_time
        
        # Extract expected delay from payload
        expected_delay = 0
        payload_lower = payload.lower()
        
        if 'sleep' in payload_lower:
            match = re.search(r'sleep\s+(\d+)', payload_lower)
            if match:
                expected_delay = int(match.group(1))
        elif 'timeout' in payload_lower:
            match = re.search(r'timeout\s+(\d+)', payload_lower)
            if match:
                expected_delay = int(match.group(1))
        elif 'ping' in payload_lower:
            if '-c' in payload_lower:
                match = re.search(r'-c\s+(\d+)', payload_lower)
                if match:
                    expected_delay = int(match.group(1))
            elif '-n' in payload_lower:
                match = re.search(r'-n\s+(\d+)', payload_lower)
                if match:
                    expected_delay = int(match.group(1))
        
        # Check if response time matches expected delay (with tolerance)
        if expected_delay > 0:
            tolerance = 2.0  # 2 second tolerance
            if response_time >= (expected_delay - tolerance):
                return True, f"Response time {response_time:.2f}s matches expected delay {expected_delay}s"
        
        return False, f"Response time {response_time:.2f}s does not indicate command execution"
