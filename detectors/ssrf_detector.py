"""
Server-Side Request Forgery (SSRF) vulnerability detector
"""

import re
from typing import List, Dict, Any, Tuple

class SSRFDetector:
    """SSRF vulnerability detection logic"""
    
    @staticmethod
    def get_ssrf_indicators() -> List[str]:
        """Get SSRF detection indicators"""
        return [
            # Internal network responses
            '127.0.0.1',
            'localhost',
            '192.168.',
            '10.',
            '172.16.',
            '172.17.',
            '172.18.',
            '172.19.',
            '172.20.',
            '172.21.',
            '172.22.',
            '172.23.',
            '172.24.',
            '172.25.',
            '172.26.',
            '172.27.',
            '172.28.',
            '172.29.',
            '172.30.',
            '172.31.',
            
            # Service banners
            'SSH-2.0',
            'HTTP/1.1',
            'HTTP/1.0',
            'FTP',
            'SMTP',
            'POP3',
            'IMAP',
            
            # Error messages
            'Connection refused',
            'Connection timed out',
            'No route to host',
            'Network is unreachable',
            'Connection reset by peer',
            
            # Cloud metadata
            'ami-id',
            'instance-id',
            'local-hostname',
            'public-hostname',
            'security-groups'
        ]
    
    @staticmethod
    def detect_ssrf(payload: str, response_text: str, response_code: int) -> Tuple[bool, str, str, Dict[str, Any]]:
        """Enhanced SSRF detection"""
        if response_code not in [200, 201, 202, 500, 400, 403, 404]:
            return False, "", "", {}
        
        indicators = SSRFDetector.get_ssrf_indicators()
        found_indicators = []
        
        for indicator in indicators:
            if indicator.lower() in response_text.lower():
                found_indicators.append(indicator)
        
        if found_indicators:
            # Determine severity based on indicators
            severity = "High"
            cvss = "8.6"
            
            # Check for critical indicators
            critical_indicators = ['ami-id', 'instance-id', 'SSH-2.0', '127.0.0.1', 'localhost']
            if any(critical in found_indicators for critical in critical_indicators):
                severity = "Critical"
                cvss = "9.1"
            
            evidence = f"SSRF detected. Found indicators: {', '.join(found_indicators[:3])}"
            return True, evidence, severity, {
                'cwe': 'CWE-918',
                'cvss': cvss,
                'owasp': 'A10:2021 – Server-Side Request Forgery',
                'recommendation': 'Implement URL validation and whitelist allowed destinations. Use network segmentation.'
            }
        
        # Check for URL patterns in payload
        url_patterns = [
            r'https?://127\.0\.0\.1',
            r'https?://localhost',
            r'https?://192\.168\.',
            r'https?://10\.',
            r'https?://172\.(1[6-9]|2[0-9]|3[01])\.',
            r'file://',
            r'gopher://',
            r'dict://'
        ]
        
        for pattern in url_patterns:
            if re.search(pattern, payload, re.IGNORECASE):
                if SSRFDetector._check_ssrf_response(response_text, response_code):
                    return True, f"SSRF attempt detected with URL pattern: {pattern}", "High", {
                        'cwe': 'CWE-918',
                        'cvss': '8.6',
                        'owasp': 'A10:2021 – Server-Side Request Forgery',
                        'recommendation': 'Implement URL validation and whitelist allowed destinations.'
                    }
        
        return False, "", "", {}
    
    @staticmethod
    def _check_ssrf_response(response_text: str, response_code: int) -> bool:
        """Check if response indicates successful SSRF"""
        # Different response than normal indicates potential SSRF
        ssrf_response_indicators = [
            'Connection refused',
            'Connection timed out',
            'HTTP/1.1',
            'SSH-2.0',
            'FTP',
            'SMTP',
            'ami-id',
            'instance-id'
        ]
        
        for indicator in ssrf_response_indicators:
            if indicator in response_text:
                return True
        
        # Response code changes might indicate SSRF
        if response_code in [500, 502, 503, 504]:
            return True
        
        return False
    
    @staticmethod
    def get_ssrf_payloads() -> List[str]:
        """Get SSRF test payloads"""
        return [
            # Internal network
            'http://127.0.0.1',
            'http://localhost',
            'http://192.168.1.1',
            'http://10.0.0.1',
            'http://172.16.0.1',
            
            # Port scanning
            'http://127.0.0.1:22',
            'http://127.0.0.1:80',
            'http://127.0.0.1:443',
            'http://127.0.0.1:3306',
            'http://127.0.0.1:5432',
            
            # Cloud metadata
            'http://169.254.169.254/latest/meta-data/',
            'http://169.254.169.254/latest/meta-data/ami-id',
            'http://169.254.169.254/latest/meta-data/instance-id',
            
            # Protocol smuggling
            'gopher://127.0.0.1:22',
            'dict://127.0.0.1:22',
            'file:///etc/passwd',
            'file:///c:/windows/win.ini'
        ]
    
    @staticmethod
    def get_evidence(payload, response_text):
        """Get evidence for SSRF vulnerability"""
        evidence_parts = []
        
        # Check what type of internal service was accessed
        if re.search(r'ami-[a-f0-9]{8,}|i-[a-f0-9]{8,}', response_text):
            evidence_parts.append("AWS EC2 metadata service accessed")
        if re.search(r'metadata.google.internal|computeMetadata', response_text, re.IGNORECASE):
            evidence_parts.append("GCP metadata service accessed")
        if re.search(r'vmId.*?[a-f0-9-]{36}', response_text):
            evidence_parts.append("Azure metadata service accessed")
        if re.search(r'root:.*?:0:0:', response_text):
            evidence_parts.append("Internal file system accessed")
        if re.search(r'MySQL.*?protocol|PostgreSQL.*?server', response_text, re.IGNORECASE):
            evidence_parts.append("Internal database service accessed")
        
        if evidence_parts:
            return f"SSRF vulnerability confirmed: {', '.join(evidence_parts)}"
        else:
            return f"SSRF vulnerability detected - internal service response received"
    
    @staticmethod
    def get_response_snippet(payload, response_text):
        """Get response snippet showing SSRF"""
        # Find the most relevant part of the response
        ssrf_patterns = [
            r'ami-[a-f0-9]{8,}.*',
            r'metadata\.google\.internal.*',
            r'vmId.*?[a-f0-9-]{36}.*',
            r'root:.*?:0:0:.*',
            r'ssrf_marker.*'
        ]
        
        for pattern in ssrf_patterns:
            match = re.search(pattern, response_text, re.IGNORECASE | re.MULTILINE)
            if match:
                start = max(0, match.start() - 50)
                end = min(len(response_text), match.end() + 50)
                return response_text[start:end]
        
        return response_text[:200] + "..." if len(response_text) > 200 else response_text
    
    @staticmethod
    def get_remediation_advice():
        """Get remediation advice for SSRF"""
        return "Implement URL validation, use allowlists for permitted domains, disable unused URL schemes, and add network-level protections."
