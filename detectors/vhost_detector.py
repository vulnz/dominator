"""
Virtual Host (VHost) discovery detector
"""

import requests
from typing import Dict, List, Tuple, Any
from urllib.parse import urlparse

class VHostDetector:
    """Virtual Host discovery detection logic"""
    
    @staticmethod
    def get_common_vhosts() -> List[str]:
        """Get common virtual host names"""
        return [
            'admin', 'administrator', 'api', 'app', 'apps',
            'backend', 'beta', 'blog', 'cms', 'control',
            'dashboard', 'dev', 'development', 'ftp', 'git',
            'internal', 'intranet', 'mail', 'mobile', 'portal',
            'secure', 'staging', 'static', 'test', 'testing',
            'vpn', 'web', 'webmail', 'www2', 'www3'
        ]
    
    @staticmethod
    def detect_virtual_hosts(base_url: str, headers: Dict[str, str], timeout: int = 10) -> Tuple[bool, str, str, List[Dict[str, Any]]]:
        """Detect virtual hosts"""
        discovered_vhosts = []
        
        # Get base domain
        parsed = urlparse(base_url)
        base_domain = parsed.netloc
        
        # Get baseline response
        try:
            baseline_response = requests.get(base_url, headers=headers, timeout=timeout, verify=False)
            baseline_length = len(baseline_response.text)
            baseline_status = baseline_response.status_code
        except:
            return False, "Could not get baseline response", "Info", []
        
        # Test common vhost names
        common_vhosts = VHostDetector.get_common_vhosts()
        
        for vhost in common_vhosts:
            try:
                # Create test host header
                if '.' in base_domain:
                    domain_parts = base_domain.split('.')
                    if len(domain_parts) >= 2:
                        test_host = f"{vhost}.{'.'.join(domain_parts[-2:])}"
                    else:
                        test_host = f"{vhost}.{base_domain}"
                else:
                    test_host = f"{vhost}.{base_domain}"
                
                test_headers = headers.copy()
                test_headers['Host'] = test_host
                
                response = requests.get(base_url, headers=test_headers, timeout=timeout, verify=False)
                
                # Check for different responses
                if (response.status_code != baseline_status or 
                    abs(len(response.text) - baseline_length) > 100):
                    
                    discovered_vhosts.append({
                        'vhost': test_host,
                        'status_code': response.status_code,
                        'content_length': len(response.text),
                        'evidence': f"Virtual host '{test_host}' returned different response: {response.status_code} ({len(response.text)} bytes) vs baseline: {baseline_status} ({baseline_length} bytes)"
                    })
                
            except Exception as e:
                continue
        
        if discovered_vhosts:
            evidence = f"Discovered {len(discovered_vhosts)} virtual hosts"
            return True, evidence, "Medium", discovered_vhosts
        
        return False, "No virtual hosts discovered", "Info", []
    
    @staticmethod
    def get_evidence(vhosts: List[Dict[str, Any]]) -> str:
        """Get detailed evidence of discovered virtual hosts"""
        evidence_parts = []
        for vhost in vhosts:
            evidence_parts.append(f"• {vhost['evidence']}")
        return "\n".join(evidence_parts)
    
    @staticmethod
    def get_remediation_advice() -> str:
        """Get remediation advice for virtual host discovery"""
        return "Configure proper virtual host restrictions. Disable unused virtual hosts. Implement proper access controls for administrative interfaces."
