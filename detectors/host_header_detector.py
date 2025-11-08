"""
Host Header vulnerability detector
"""

import requests
from typing import Dict, List, Tuple, Any

class HostHeaderDetector:
    """Host Header vulnerability detection logic"""
    
    @staticmethod
    def detect_host_header_injection(base_url: str, headers: Dict[str, str], timeout: int = 10) -> Tuple[bool, str, str, List[Dict[str, Any]]]:
        """Detect Host Header injection vulnerabilities"""
        vulnerabilities = []
        
        # Test payloads for Host header
        test_hosts = [
            'evil.com',
            'attacker.example.com',
            'localhost',
            '127.0.0.1',
            'internal.local',
            'admin.local'
        ]
        
        original_response = None
        try:
            original_response = requests.get(base_url, headers=headers, timeout=timeout, verify=False)
        except:
            return False, "Could not get original response", "Info", []
        
        for test_host in test_hosts:
            try:
                test_headers = headers.copy()
                test_headers['Host'] = test_host
                
                response = requests.get(base_url, headers=test_headers, timeout=timeout, verify=False)
                
                # Check for Host header reflection
                if test_host in response.text:
                    vulnerabilities.append({
                        'type': 'host_reflection',
                        'payload': test_host,
                        'evidence': f"Host header '{test_host}' reflected in response",
                        'severity': 'Medium'
                    })
                
                # Check for password reset poisoning indicators
                if any(indicator in response.text.lower() for indicator in ['reset', 'password', 'link', 'click']):
                    if test_host in response.text:
                        vulnerabilities.append({
                            'type': 'password_reset_poisoning',
                            'payload': test_host,
                            'evidence': f"Potential password reset poisoning with host '{test_host}'",
                            'severity': 'High'
                        })
                
                # Check for cache poisoning
                if response.status_code != original_response.status_code:
                    vulnerabilities.append({
                        'type': 'cache_poisoning',
                        'payload': test_host,
                        'evidence': f"Different response code with host '{test_host}': {response.status_code} vs {original_response.status_code}",
                        'severity': 'Medium'
                    })
                
            except Exception as e:
                continue
        
        if vulnerabilities:
            highest_severity = max(vuln['severity'] for vuln in vulnerabilities)
            evidence = f"Found {len(vulnerabilities)} Host header vulnerabilities"
            return True, evidence, highest_severity, vulnerabilities
        
        return False, "No Host header vulnerabilities found", "Info", []
    
    @staticmethod
    def get_evidence(vulnerabilities: List[Dict[str, Any]]) -> str:
        """Get detailed evidence of Host header vulnerabilities"""
        evidence_parts = []
        for vuln in vulnerabilities:
            evidence_parts.append(f"• {vuln['type']}: {vuln['evidence']}")
        return "\n".join(evidence_parts)
    
    @staticmethod
    def get_remediation_advice() -> str:
        """Get remediation advice for Host header vulnerabilities"""
        return "Validate Host header values against a whitelist of allowed hosts. Implement proper input validation and avoid reflecting Host header in responses."
