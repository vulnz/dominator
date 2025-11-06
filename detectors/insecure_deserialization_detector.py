"""
Insecure Deserialization vulnerability detection logic
"""

import re
from typing import Tuple, List, Dict, Any

class InsecureDeserializationDetector:
    """Insecure Deserialization vulnerability detection logic"""
    
    @staticmethod
    def get_serialization_patterns() -> Dict[str, List[str]]:
        """Get serialization format patterns"""
        return {
            'java': [
                'rO0AB', 'aced0005',  # Java serialization magic bytes (base64)
                'java.lang.', 'java.util.',
                'ObjectInputStream', 'readObject',
                'Serializable', 'serialVersionUID'
            ],
            'php': [
                'O:', 'a:', 's:', 'i:',  # PHP serialization
                'unserialize', 'serialize',
                '__wakeup', '__destruct',
                'PD9waHA'  # <?php in base64
            ],
            'python': [
                'pickle', 'cPickle', '_pickle',
                'loads', 'dumps',
                'protocol', '__reduce__'
            ],
            'dotnet': [
                'BinaryFormatter', 'SoapFormatter',
                'System.Runtime.Serialization',
                'DataContractSerializer',
                'XmlSerializer'
            ]
        }
    
    @staticmethod
    def detect_insecure_deserialization(response_text: str, response_code: int, payload: str) -> Tuple[bool, str, str]:
        """
        Detect insecure deserialization vulnerability
        Returns: (is_vulnerable, evidence, severity)
        """
        if response_code >= 500:
            return False, "Server error response", "None"
        
        response_lower = response_text.lower()
        patterns = InsecureDeserializationDetector.get_serialization_patterns()
        
        found_patterns = []
        detected_format = None
        
        # Check for serialization patterns
        for format_name, format_patterns in patterns.items():
            format_matches = 0
            for pattern in format_patterns:
                if pattern.lower() in response_lower:
                    found_patterns.append(pattern)
                    format_matches += 1
            
            if format_matches >= 2:
                detected_format = format_name
                break
        
        if not found_patterns:
            return False, "No serialization patterns detected", "None"
        
        # Check for deserialization errors
        error_patterns = [
            'deserialization', 'unserialize', 'unmarshal',
            'classnotfoundexception', 'invalidclassexception',
            'streamcorruptedexception', 'optionaldata',
            'magic number', 'invalid stream header',
            'unexpected end of stream'
        ]
        
        error_found = False
        for error in error_patterns:
            if error in response_lower:
                error_found = True
                break
        
        if error_found:
            severity = "High"
            evidence = f"Insecure deserialization detected ({detected_format or 'unknown format'}). Found patterns: {', '.join(found_patterns[:3])}"
        else:
            severity = "Medium"
            evidence = f"Potential deserialization detected ({detected_format or 'unknown format'}). Found patterns: {', '.join(found_patterns[:3])}"
        
        return True, evidence, severity
    
    @staticmethod
    def get_evidence(patterns: List[str], format_type: str, response_text: str) -> str:
        """Get detailed evidence of insecure deserialization"""
        evidence_parts = []
        
        if format_type:
            evidence_parts.append(f"Detected {format_type.upper()} serialization format")
        
        if patterns:
            evidence_parts.append(f"Found serialization indicators: {', '.join(patterns[:5])}")
        
        # Look for specific vulnerability indicators
        vuln_indicators = [
            'remote code execution', 'arbitrary code',
            'command execution', 'file system access',
            'privilege escalation'
        ]
        
        response_lower = response_text.lower()
        found_vulns = [indicator for indicator in vuln_indicators if indicator in response_lower]
        
        if found_vulns:
            evidence_parts.append(f"Potential impact indicators: {', '.join(found_vulns)}")
        
        return ". ".join(evidence_parts)
    
    @staticmethod
    def get_response_snippet(payload: str, response_text: str) -> str:
        """Get relevant response snippet"""
        patterns = []
        for format_patterns in InsecureDeserializationDetector.get_serialization_patterns().values():
            patterns.extend(format_patterns)
        
        for pattern in patterns:
            if pattern.lower() in response_text.lower():
                start = max(0, response_text.lower().find(pattern.lower()) - 50)
                end = min(len(response_text), start + 200)
                return response_text[start:end]
        
        return response_text[:200]
    
    @staticmethod
    def get_evidence(original_response: str, modified_response: str) -> str:
        """Get evidence for IDOR"""
        evidence_parts = []
        
        # Compare response lengths
        orig_len = len(original_response)
        mod_len = len(modified_response)
        
        if abs(orig_len - mod_len) > 100:
            evidence_parts.append(f"response size difference: {orig_len} vs {mod_len} bytes")
        
        # Check for different content
        if 'user' in modified_response.lower() and 'user' not in original_response.lower():
            evidence_parts.append("different user data detected")
        elif 'id' in modified_response.lower() and 'id' not in original_response.lower():
            evidence_parts.append("different ID data detected")
        
        if evidence_parts:
            return f"IDOR detected: {'; '.join(evidence_parts)}"
        else:
            return "Different response content suggests IDOR vulnerability"
    
    @staticmethod
    def get_response_snippet(response_text: str) -> str:
        """Get response snippet for IDOR"""
        if len(response_text) > 300:
            return response_text[:300] + "..."
        return response_text
    
    @staticmethod
    def get_remediation_advice() -> str:
        """Get remediation advice for IDOR"""
        return (
            "Implement proper access controls and authorization checks. "
            "Use indirect object references or UUIDs instead of sequential IDs. "
            "Validate user permissions before returning sensitive data."
        )
    
    @staticmethod
    def get_evidence(payload: str, response_text: str) -> str:
        """Get evidence for directory traversal"""
        evidence_parts = []
        
        # Check for file content indicators
        if 'root:' in response_text and '/bin/' in response_text:
            evidence_parts.append("Unix passwd file content detected")
        elif '[extensions]' in response_text or '[files]' in response_text:
            evidence_parts.append("Windows ini file content detected")
        elif '<?php' in response_text:
            evidence_parts.append("PHP source code exposed")
        elif 'function' in response_text and 'var ' in response_text:
            evidence_parts.append("Source code content detected")
        
        if evidence_parts:
            return f"Directory traversal successful: {'; '.join(evidence_parts)}"
        else:
            return f"Potential directory traversal with payload: {payload}"
    
    @staticmethod
    def get_response_snippet(payload: str, response_text: str) -> str:
        """Get response snippet for directory traversal"""
        # Look for file content
        lines = response_text.split('\n')
        relevant_lines = []
        
        for line in lines[:20]:  # First 20 lines
            if any(indicator in line for indicator in ['root:', '[extensions]', '<?php', 'function']):
                relevant_lines.append(line.strip())
        
        if relevant_lines:
            snippet = '\n'.join(relevant_lines[:10])
            if len(snippet) > 400:
                return snippet[:400] + "..."
            return snippet
        
        # Fallback
        if len(response_text) > 300:
            return response_text[:300] + "..."
        return response_text
    
    @staticmethod
    def get_remediation_advice() -> str:
        """Get remediation advice for insecure deserialization vulnerabilities"""
        return (
            "Avoid deserializing untrusted data. "
            "Use safe serialization formats like JSON instead of native serialization. "
            "Implement integrity checks and digital signatures for serialized data. "
            "Use whitelist-based deserialization and run deserialization in sandboxed environments. "
            "Keep serialization libraries updated and monitor for known vulnerabilities."
        )
    
    @staticmethod
    def get_response_snippet(payload: str, response_text: str) -> str:
        """Get response snippet for deserialization"""
        if len(response_text) > 300:
            return response_text[:300] + "..."
        return response_text
