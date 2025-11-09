"""
Mixed Content detector
"""

import re
from typing import Tuple, List, Dict, Any
from urllib.parse import urlparse

class MixedContentDetector:
    """Mixed Content detection logic"""
    
    @staticmethod
    def get_mixed_content_patterns() -> List[Dict[str, Any]]:
        """Get patterns for detecting mixed content"""
        return [
            {
                'name': 'http_images',
                'pattern': r'<img[^>]+src=["\']?http://[^"\'>\s]+["\']?[^>]*>',
                'type': 'passive',
                'severity': 'Medium',
                'description': 'HTTP image loaded on HTTPS page'
            },
            {
                'name': 'http_stylesheets',
                'pattern': r'<link[^>]+href=["\']?http://[^"\'>\s]+\.css[^"\'>\s]*["\']?[^>]*>',
                'type': 'passive',
                'severity': 'Medium',
                'description': 'HTTP stylesheet loaded on HTTPS page'
            },
            {
                'name': 'http_scripts',
                'pattern': r'<script[^>]+src=["\']?http://[^"\'>\s]+["\']?[^>]*>',
                'type': 'active',
                'severity': 'High',
                'description': 'HTTP script loaded on HTTPS page'
            },
            {
                'name': 'http_iframes',
                'pattern': r'<iframe[^>]+src=["\']?http://[^"\'>\s]+["\']?[^>]*>',
                'type': 'active',
                'severity': 'High',
                'description': 'HTTP iframe loaded on HTTPS page'
            },
            {
                'name': 'http_forms',
                'pattern': r'<form[^>]+action=["\']?http://[^"\'>\s]+["\']?[^>]*>',
                'type': 'active',
                'severity': 'High',
                'description': 'Form submits to HTTP URL from HTTPS page'
            },
            {
                'name': 'http_ajax',
                'pattern': r'(?:fetch|XMLHttpRequest|\.get|\.post)\s*\([^)]*["\']http://[^"\']+["\'][^)]*\)',
                'type': 'active',
                'severity': 'High',
                'description': 'AJAX request to HTTP URL from HTTPS page'
            },
            {
                'name': 'http_websockets',
                'pattern': r'new\s+WebSocket\s*\([^)]*["\']ws://[^"\']+["\'][^)]*\)',
                'type': 'active',
                'severity': 'High',
                'description': 'Insecure WebSocket connection from HTTPS page'
            }
        ]
    
    @staticmethod
    def detect_mixed_content(response_text: str, response_code: int, 
                           current_url: str) -> Tuple[bool, str, str, List[Dict[str, Any]]]:
        """Detect mixed content vulnerabilities"""
        if response_code != 200:
            return False, "", "", []
        
        # Only check HTTPS pages for mixed content
        if not current_url.startswith('https://'):
            return False, "", "", []
        
        mixed_content_issues = []
        patterns = MixedContentDetector.get_mixed_content_patterns()
        
        for pattern_info in patterns:
            matches = re.finditer(pattern_info['pattern'], response_text, re.IGNORECASE)
            
            for match in matches:
                matched_content = match.group(0)
                
                # Extract the HTTP URL
                url_match = re.search(r'http://[^"\'>\s]+', matched_content)
                if url_match:
                    http_url = url_match.group(0)
                    
                    mixed_content_issues.append({
                        'type': pattern_info['type'],
                        'name': pattern_info['name'],
                        'url': http_url,
                        'html': matched_content[:100] + ('...' if len(matched_content) > 100 else ''),
                        'severity': pattern_info['severity'],
                        'description': pattern_info['description']
                    })
        
        if mixed_content_issues:
            # Determine overall severity
            active_issues = [issue for issue in mixed_content_issues if issue['type'] == 'active']
            passive_issues = [issue for issue in mixed_content_issues if issue['type'] == 'passive']
            
            if active_issues:
                overall_severity = 'High'
                evidence = f"Found {len(active_issues)} active and {len(passive_issues)} passive mixed content issues"
            else:
                overall_severity = 'Medium'
                evidence = f"Found {len(passive_issues)} passive mixed content issues"
            
            return True, evidence, overall_severity, mixed_content_issues
        
        return False, "", "", []
    
    @staticmethod
    def _extract_domain(url: str) -> str:
        """Extract domain from URL"""
        try:
            return urlparse(url).netloc.lower()
        except:
            return ""
    
    @staticmethod
    def get_evidence(mixed_content_issues: List[Dict[str, Any]]) -> str:
        """Get detailed evidence for mixed content"""
        evidence_parts = []
        
        # Group by type
        active_issues = [issue for issue in mixed_content_issues if issue['type'] == 'active']
        passive_issues = [issue for issue in mixed_content_issues if issue['type'] == 'passive']
        
        if active_issues:
            active_types = list(set(issue['name'] for issue in active_issues))
            evidence_parts.append(f"Active mixed content: {', '.join(active_types)}")
        
        if passive_issues:
            passive_types = list(set(issue['name'] for issue in passive_issues))
            evidence_parts.append(f"Passive mixed content: {', '.join(passive_types)}")
        
        # Show specific URLs
        for issue in mixed_content_issues[:3]:
            evidence_parts.append(f"{issue['name']}: {issue['url']}")
        
        if len(mixed_content_issues) > 3:
            evidence_parts.append(f"... and {len(mixed_content_issues) - 3} more")
        
        return "; ".join(evidence_parts)
    
    @staticmethod
    def get_response_snippet(mixed_content_issues: List[Dict[str, Any]]) -> str:
        """Get response snippet showing mixed content"""
        snippets = []
        
        for issue in mixed_content_issues[:3]:
            snippets.append(f"{issue['description']}: {issue['html']}")
        
        if len(mixed_content_issues) > 3:
            snippets.append(f"... and {len(mixed_content_issues) - 3} more issues")
        
        return "\n".join(snippets)
    
    @staticmethod
    def get_remediation_advice() -> str:
        """Get remediation advice for mixed content"""
        return (
            "Fix mixed content issues: "
            "1) Change all HTTP URLs to HTTPS, "
            "2) Use protocol-relative URLs (//example.com), "
            "3) Implement Content Security Policy with upgrade-insecure-requests, "
            "4) Use HTTPS for all external resources, "
            "5) Update WebSocket connections to use WSS instead of WS."
        )
