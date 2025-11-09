"""
Reverse Tabnabbing vulnerability detector
"""

import re
from typing import Tuple, List, Dict, Any

class ReverseTabnabbingDetector:
    """Reverse Tabnabbing detection logic"""
    
    @staticmethod
    def get_dangerous_link_patterns() -> List[str]:
        """Get patterns for dangerous external links"""
        return [
            r'<a[^>]+href=["\']?https?://[^"\'>\s]+["\']?[^>]*target=["\']?_blank["\']?[^>]*>',
            r'<a[^>]+target=["\']?_blank["\']?[^>]*href=["\']?https?://[^"\'>\s]+["\']?[^>]*>',
            r'window\.open\s*\([^)]*["\']https?://[^"\']+["\'][^)]*\)',
            r'<form[^>]+target=["\']?_blank["\']?[^>]*action=["\']?https?://[^"\'>\s]+["\']?[^>]*>'
        ]
    
    @staticmethod
    def detect_reverse_tabnabbing(response_text: str, response_code: int, url: str) -> Tuple[bool, str, str, Dict[str, Any]]:
        """Detect Reverse Tabnabbing vulnerabilities"""
        if response_code != 200:
            return False, "", "", {}
        
        vulnerable_links = []
        dangerous_patterns = ReverseTabnabbingDetector.get_dangerous_link_patterns()
        
        # Find all external links with target="_blank"
        for pattern in dangerous_patterns:
            matches = re.finditer(pattern, response_text, re.IGNORECASE)
            for match in matches:
                link_html = match.group(0)
                
                # Check if link has rel="noopener" or rel="noreferrer"
                if not re.search(r'rel=["\'][^"\']*(?:noopener|noreferrer)[^"\']*["\']', link_html, re.IGNORECASE):
                    # Extract href URL
                    href_match = re.search(r'(?:href|action)=["\']?([^"\'>\s]+)["\']?', link_html, re.IGNORECASE)
                    if href_match:
                        target_url = href_match.group(1)
                        
                        # Check if it's external link
                        if ReverseTabnabbingDetector._is_external_link(target_url, url):
                            vulnerable_links.append({
                                'url': target_url,
                                'html': link_html[:100] + ('...' if len(link_html) > 100 else ''),
                                'type': 'external_link'
                            })
        
        # Check for JavaScript window.open without noopener
        js_pattern = r'window\.open\s*\([^)]*["\']https?://[^"\']+["\'][^)]*\)'
        js_matches = re.finditer(js_pattern, response_text, re.IGNORECASE)
        
        for match in js_matches:
            js_code = match.group(0)
            if 'noopener' not in js_code.lower():
                vulnerable_links.append({
                    'url': 'JavaScript window.open',
                    'html': js_code,
                    'type': 'javascript_open'
                })
        
        if vulnerable_links:
            evidence = f"Found {len(vulnerable_links)} vulnerable external links without rel='noopener noreferrer'"
            severity = "Medium"
            
            return True, evidence, severity, {
                'cwe': 'CWE-1021',
                'cvss': '4.3',
                'owasp': 'A05:2021 – Security Misconfiguration',
                'recommendation': 'Add rel="noopener noreferrer" to all external links with target="_blank"',
                'vulnerable_links': vulnerable_links
            }
        
        return False, "", "", {}
    
    @staticmethod
    def _is_external_link(target_url: str, current_url: str) -> bool:
        """Check if target URL is external"""
        from urllib.parse import urlparse
        
        try:
            current_domain = urlparse(current_url).netloc.lower()
            target_domain = urlparse(target_url).netloc.lower()
            
            # If target has no domain, it's relative (not external)
            if not target_domain:
                return False
            
            # Different domains = external
            return current_domain != target_domain
        except:
            return False
    
    @staticmethod
    def get_evidence(vulnerable_links: List[Dict[str, Any]]) -> str:
        """Get detailed evidence for reverse tabnabbing"""
        evidence_parts = []
        
        for link in vulnerable_links[:5]:  # Show first 5 links
            if link['type'] == 'external_link':
                evidence_parts.append(f"External link to {link['url']} without noopener")
            else:
                evidence_parts.append(f"JavaScript window.open without noopener")
        
        if len(vulnerable_links) > 5:
            evidence_parts.append(f"... and {len(vulnerable_links) - 5} more vulnerable links")
        
        return "; ".join(evidence_parts)
    
    @staticmethod
    def get_response_snippet(vulnerable_links: List[Dict[str, Any]]) -> str:
        """Get response snippet showing vulnerable links"""
        if not vulnerable_links:
            return "No vulnerable links found"
        
        snippets = []
        for link in vulnerable_links[:3]:
            snippets.append(link['html'])
        
        result = "\n".join(snippets)
        if len(vulnerable_links) > 3:
            result += f"\n... and {len(vulnerable_links) - 3} more"
        
        return result
    
    @staticmethod
    def get_remediation_advice() -> str:
        """Get remediation advice for reverse tabnabbing"""
        return (
            "Add rel='noopener noreferrer' to all external links with target='_blank'. "
            "For JavaScript window.open(), use 'noopener' in features parameter. "
            "This prevents the new page from accessing window.opener property."
        )
