"""
Version disclosure vulnerability detection logic
"""
import re

class VersionDisclosureDetector:
    """Version disclosure detection logic"""
    
    @staticmethod
    def get_version_patterns() -> dict:
        """Get version detection patterns"""
        return {
            'php': [
                r'PHP/(\d+\.\d+\.\d+)',
                r'X-Powered-By:\s*PHP/(\d+\.\d+\.\d+)',
                r'php version (\d+\.\d+\.\d+)',
            ],
            'apache': [
                r'Apache/(\d+\.\d+\.\d+)',
                r'Server:\s*Apache/(\d+\.\d+\.\d+)',
            ],
            'nginx': [
                r'nginx/(\d+\.\d+\.\d+)',
                r'Server:\s*nginx/(\d+\.\d+\.\d+)',
            ],
            'mysql': [
                r'MySQL (\d+\.\d+\.\d+)',
                r'mysql_version.*?(\d+\.\d+\.\d+)',
            ],
            'wordpress': [
                r'WordPress (\d+\.\d+\.\d+)',
                r'wp-includes/version\.php.*?(\d+\.\d+\.\d+)',
            ]
        }
    
    @staticmethod
    def detect_version_disclosure(response_text: str, response_headers: dict) -> list:
        """Detect version disclosures"""
        disclosures = []
        patterns = VersionDisclosureDetector.get_version_patterns()
        
        # Check headers
        headers_text = ' '.join([f"{k}: {v}" for k, v in response_headers.items()])
        full_text = headers_text + ' ' + response_text
        
        for software, pattern_list in patterns.items():
            for pattern in pattern_list:
                matches = re.findall(pattern, full_text, re.IGNORECASE)
                for match in matches:
                    disclosures.append({
                        'software': software,
                        'version': match,
                        'pattern': pattern,
                        'location': 'headers' if pattern in headers_text else 'body'
                    })
        
        return disclosures
    
    @staticmethod
    def get_evidence(disclosures: list) -> str:
        """Get evidence of version disclosure"""
        if not disclosures:
            return "No version disclosures found"
        
        evidence_parts = []
        for disclosure in disclosures[:3]:  # Limit to first 3
            evidence_parts.append(f"{disclosure['software']} {disclosure['version']}")
        
        return f"Version disclosure found: {', '.join(evidence_parts)}"
    
    @staticmethod
    def get_severity(software: str, version: str) -> str:
        """Get severity based on software and version"""
        # This is a simplified severity assessment
        # In real implementation, you'd check against CVE databases
        
        critical_software = ['php', 'apache', 'nginx', 'mysql']
        if software.lower() in critical_software:
            return 'Medium'
        
        return 'Low'
