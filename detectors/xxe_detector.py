"""
XXE vulnerability detection logic with enhanced validation
"""

import re

class XXEDetector:
    """XXE vulnerability detection logic"""
    
    @staticmethod
    def detect_xxe(response_text, response_code, payload):
        """Detect XXE vulnerability with enhanced validation"""
        if response_code >= 500:
            return False
        
        # Check for XXE-specific markers in payload
        if 'xxe_marker' not in payload.lower():
            return False
        
        # Look for file content indicators that suggest successful XXE
        file_indicators = [
            # /etc/passwd patterns
            r'root:.*?:0:0:',
            r'daemon:.*?:/usr/sbin/nologin',
            r'bin:.*?:/bin/sh',
            r'sys:.*?:/dev/null',
            r'nobody:.*?:65534',
            
            # Windows win.ini patterns
            r'\[fonts\]',
            r'\[extensions\]',
            r'\[mci extensions\]',
            r'for 16-bit app support',
            
            # /etc/hosts patterns
            r'127\.0\.0\.1\s+localhost',
            r'::1\s+localhost',
            r'# Host Database',
            
            # Generic system file patterns
            r'# This file was automatically generated',
            r'# /etc/',
            r'# System',
            r'\[boot loader\]',
            r'\[operating systems\]'
        ]
        
        # Check for multiple indicators to reduce false positives
        matches = 0
        matched_patterns = []
        
        for pattern in file_indicators:
            if re.search(pattern, response_text, re.IGNORECASE | re.MULTILINE):
                matches += 1
                matched_patterns.append(pattern)
        
        # Require at least 2 matches for /etc/passwd or 1 strong match for Windows
        if matches >= 2:
            return True
        elif matches >= 1 and any('fonts' in p or 'extensions' in p or 'boot loader' in p for p in matched_patterns):
            return True
        
        # Check for XML parsing errors that might indicate XXE processing
        xml_error_patterns = [
            r'XML.*?entity.*?not.*?found',
            r'External.*?entity.*?reference',
            r'DOCTYPE.*?declaration',
            r'Entity.*?resolution',
            r'XML.*?parsing.*?error'
        ]
        
        for pattern in xml_error_patterns:
            if re.search(pattern, response_text, re.IGNORECASE):
                # Only consider as XXE if we also have entity references in payload
                if 'ENTITY' in payload and ('SYSTEM' in payload or 'PUBLIC' in payload):
                    return True
        
        return False
    
    @staticmethod
    def get_evidence(payload, response_text):
        """Get evidence for XXE vulnerability"""
        evidence_parts = []
        
        # Check what type of file content was found
        if re.search(r'root:.*?:0:0:', response_text):
            evidence_parts.append("Unix /etc/passwd file content detected")
        if re.search(r'\[fonts\]|\[extensions\]', response_text, re.IGNORECASE):
            evidence_parts.append("Windows win.ini file content detected")
        if re.search(r'127\.0\.0\.1\s+localhost', response_text):
            evidence_parts.append("System hosts file content detected")
        
        if evidence_parts:
            return f"XXE vulnerability confirmed: {', '.join(evidence_parts)}"
        else:
            return f"XXE vulnerability detected with payload containing entity references"
    
    @staticmethod
    def get_response_snippet(payload, response_text):
        """Get response snippet showing XXE"""
        # Find the most relevant part of the response
        file_patterns = [
            r'root:.*?:0:0:.*',
            r'\[fonts\].*?\[.*?\]',
            r'127\.0\.0\.1\s+localhost.*'
        ]
        
        for pattern in file_patterns:
            match = re.search(pattern, response_text, re.IGNORECASE | re.MULTILINE)
            if match:
                start = max(0, match.start() - 50)
                end = min(len(response_text), match.end() + 50)
                return response_text[start:end]
        
        return response_text[:200] + "..." if len(response_text) > 200 else response_text
    
    @staticmethod
    def get_remediation_advice():
        """Get remediation advice for XXE"""
        return "Disable external entity processing in XML parsers, use whitelisting for allowed XML elements, and implement proper input validation."
