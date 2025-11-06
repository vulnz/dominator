"""
XXE (XML External Entity) vulnerability detection logic
"""

import re
from typing import Tuple, List, Dict, Any

class XXEDetector:
    """XXE vulnerability detection logic"""
    
    @staticmethod
    def get_xxe_indicators() -> List[str]:
        """Get XXE vulnerability indicators"""
        return [
            'file://',
            '/etc/passwd',
            '/etc/hosts',
            'root:x:0:0',
            'localhost',
            'SYSTEM',
            'DOCTYPE',
            'ENTITY',
            'C:\\Windows\\System32',
            'C:\\boot.ini',
            'file:///c:',
            'file:///etc',
            'xml parsing error',
            'external entity',
            'entity reference'
        ]
    
    @staticmethod
    def detect_xxe(response_text: str, response_code: int, payload: str) -> bool:
        """
        Detect XXE vulnerability
        Returns True if XXE is detected
        """
        if response_code >= 500:
            return False
        
        response_lower = response_text.lower()
        indicators = XXEDetector.get_xxe_indicators()
        
        # Check for file content disclosure
        file_indicators = [
            'root:x:0:0',  # /etc/passwd content
            'localhost',   # /etc/hosts content
            '[boot loader]',  # boot.ini content
            'system32',    # Windows system files
        ]
        
        for indicator in file_indicators:
            if indicator.lower() in response_lower:
                return True
        
        # Check for XML parsing errors that might indicate XXE processing
        xml_errors = [
            'xml parsing error',
            'external entity',
            'entity reference',
            'dtd',
            'doctype'
        ]
        
        for error in xml_errors:
            if error in response_lower and any(p in payload.lower() for p in ['entity', 'doctype', 'system']):
                return True
        
        return False
    
    @staticmethod
    def get_evidence(payload: str, response_text: str) -> str:
        """Get evidence of XXE vulnerability"""
        indicators = XXEDetector.get_xxe_indicators()
        found_indicators = []
        
        response_lower = response_text.lower()
        for indicator in indicators:
            if indicator.lower() in response_lower:
                found_indicators.append(indicator)
        
        if found_indicators:
            return f"XXE vulnerability detected. Found indicators: {', '.join(found_indicators[:3])}"
        
        return "Potential XXE vulnerability detected based on response patterns"
    
    @staticmethod
    def get_response_snippet(payload: str, response_text: str) -> str:
        """Get relevant response snippet"""
        indicators = XXEDetector.get_xxe_indicators()
        
        for indicator in indicators:
            if indicator.lower() in response_text.lower():
                # Find the context around the indicator
                start = max(0, response_text.lower().find(indicator.lower()) - 50)
                end = min(len(response_text), start + 200)
                return response_text[start:end]
        
        return response_text[:200]
    
    @staticmethod
    def get_remediation_advice() -> str:
        """Get remediation advice for XXE vulnerabilities"""
        return (
            "Disable XML external entity processing in XML parsers. "
            "Use secure XML parsing libraries and configure them to reject DTDs and external entities. "
            "Validate and sanitize all XML input. Consider using JSON instead of XML where possible."
        )
    
    @staticmethod
    def get_evidence(payload: str, response_text: str) -> str:
        """Get evidence for XXE"""
        evidence_parts = []
        
        # Check for file content
        if 'root:' in response_text:
            evidence_parts.append("System file content detected")
        elif '[extensions]' in response_text:
            evidence_parts.append("Windows configuration file detected")
        
        # Check for XML parsing errors
        if 'xml' in response_text.lower() and 'error' in response_text.lower():
            evidence_parts.append("XML parsing error detected")
        
        if evidence_parts:
            return f"XXE detected: {'; '.join(evidence_parts)}"
        else:
            return f"Potential XXE with payload: {payload}"
    
    @staticmethod
    def get_response_snippet(payload: str, response_text: str) -> str:
        """Get response snippet for XXE"""
        if len(response_text) > 300:
            return response_text[:300] + "..."
        return response_text
