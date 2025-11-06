"""
SSRF vulnerability detection logic with enhanced validation
"""

import re

class SSRFDetector:
    """SSRF vulnerability detection logic"""
    
    @staticmethod
    def detect_ssrf(response_text, response_code, payload):
        """Detect SSRF vulnerability with enhanced validation"""
        if response_code >= 500:
            return False
        
        # Check for SSRF-specific markers in payload
        if 'ssrf_marker' not in payload.lower():
            return False
        
        # Look for internal service responses
        internal_service_indicators = [
            # AWS metadata service
            r'ami-[a-f0-9]{8,}',
            r'i-[a-f0-9]{8,}',
            r'"instanceId"\s*:\s*"i-[a-f0-9]+"',
            r'"imageId"\s*:\s*"ami-[a-f0-9]+"',
            r'iam/security-credentials',
            
            # GCP metadata service
            r'"machineType".*?zones/.*?/machineTypes/',
            r'"name".*?"gce-"',
            r'metadata.google.internal',
            r'computeMetadata',
            
            # Azure metadata service
            r'"vmId".*?"[a-f0-9-]{36}"',
            r'"subscriptionId".*?"[a-f0-9-]{36}"',
            r'metadata.azure.com',
            
            # Internal network responses
            r'Apache.*?Server at.*?Port \d+',
            r'nginx/[\d.]+',
            r'IIS/[\d.]+',
            r'Server: Microsoft-',
            
            # Database connection responses
            r'MySQL.*?protocol version',
            r'PostgreSQL.*?server',
            r'Redis.*?server',
            r'MongoDB.*?server',
            
            # SSH service responses
            r'SSH-[\d.]+-OpenSSH',
            r'Protocol mismatch',
            
            # File system access
            r'root:.*?:0:0:',
            r'daemon:.*?:/usr/sbin/nologin',
            
            # Internal application responses
            r'X-Powered-By:.*?PHP',
            r'Set-Cookie:.*?PHPSESSID',
            r'Server:.*?Apache',
            
            # Error messages indicating internal access
            r'Connection refused',
            r'No route to host',
            r'Network is unreachable',
            r'Connection timed out'
        ]
        
        # Check for multiple indicators to reduce false positives
        matches = 0
        matched_indicators = []
        
        for pattern in internal_service_indicators:
            if re.search(pattern, response_text, re.IGNORECASE | re.MULTILINE):
                matches += 1
                matched_indicators.append(pattern)
        
        # Strong indicators that suggest SSRF
        strong_indicators = [
            r'ami-[a-f0-9]{8,}',
            r'i-[a-f0-9]{8,}',
            r'metadata.google.internal',
            r'computeMetadata',
            r'vmId.*?[a-f0-9-]{36}',
            r'root:.*?:0:0:'
        ]
        
        # Check for strong indicators
        for pattern in strong_indicators:
            if re.search(pattern, response_text, re.IGNORECASE):
                return True
        
        # Require multiple weak indicators
        if matches >= 2:
            return True
        
        # Check for specific SSRF response patterns
        ssrf_response_patterns = [
            r'ssrf_marker.*?internal',
            r'ssrf_marker.*?localhost',
            r'ssrf_marker.*?aws',
            r'ssrf_marker.*?gcp',
            r'ssrf_marker.*?metadata'
        ]
        
        for pattern in ssrf_response_patterns:
            if re.search(pattern, response_text, re.IGNORECASE):
                return True
        
        return False
    
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
