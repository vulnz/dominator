"""
Content Security Policy (CSP) detector
"""

import re
from typing import Tuple, List, Dict, Any

class CSPDetector:
    """Content Security Policy detection logic"""
    
    @staticmethod
    def get_csp_directives() -> Dict[str, Dict[str, Any]]:
        """Get important CSP directives and their security implications"""
        return {
            'default-src': {
                'importance': 'High',
                'description': 'Default policy for loading content',
                'secure_values': ["'self'", "'none'"],
                'insecure_values': ['*', 'data:', 'unsafe-inline', 'unsafe-eval']
            },
            'script-src': {
                'importance': 'High',
                'description': 'Policy for JavaScript execution',
                'secure_values': ["'self'", "'none'", 'nonce-', 'sha256-'],
                'insecure_values': ['*', 'unsafe-inline', 'unsafe-eval', 'data:']
            },
            'object-src': {
                'importance': 'High',
                'description': 'Policy for plugins (Flash, etc.)',
                'secure_values': ["'none'"],
                'insecure_values': ['*', "'self'"]
            },
            'style-src': {
                'importance': 'Medium',
                'description': 'Policy for stylesheets',
                'secure_values': ["'self'", 'nonce-', 'sha256-'],
                'insecure_values': ['*', 'unsafe-inline']
            },
            'img-src': {
                'importance': 'Medium',
                'description': 'Policy for images',
                'secure_values': ["'self'", 'data:'],
                'insecure_values': ['*']
            },
            'frame-ancestors': {
                'importance': 'High',
                'description': 'Policy for embedding in frames',
                'secure_values': ["'none'", "'self'"],
                'insecure_values': ['*']
            },
            'base-uri': {
                'importance': 'Medium',
                'description': 'Policy for base tag URLs',
                'secure_values': ["'self'", "'none'"],
                'insecure_values': ['*']
            }
        }
    
    @staticmethod
    def detect_csp_issues(response_headers: Dict[str, str], response_text: str) -> Tuple[bool, str, str, List[Dict[str, Any]]]:
        """Detect CSP configuration issues"""
        issues = []
        
        # Check for CSP header presence
        csp_header = None
        csp_header_name = None
        
        for header_name, header_value in response_headers.items():
            if header_name.lower() == 'content-security-policy':
                csp_header = header_value
                csp_header_name = header_name
                break
            elif header_name.lower() == 'content-security-policy-report-only':
                csp_header = header_value
                csp_header_name = header_name + ' (Report-Only)'
                break
        
        if not csp_header:
            # Check for CSP in meta tags
            meta_csp = CSPDetector._check_meta_csp(response_text)
            if meta_csp:
                csp_header = meta_csp
                csp_header_name = 'meta tag'
            else:
                issues.append({
                    'type': 'missing_csp',
                    'directive': 'Content-Security-Policy',
                    'issue': 'CSP header not found',
                    'severity': 'Medium',
                    'description': 'No Content-Security-Policy header found'
                })
                
                evidence = "Content Security Policy (CSP) header is missing"
                return True, evidence, 'Medium', issues
        
        # Parse and analyze CSP
        csp_analysis = CSPDetector._analyze_csp(csp_header)
        issues.extend(csp_analysis)
        
        if issues:
            # Determine overall severity
            severities = [issue['severity'] for issue in issues]
            if 'High' in severities:
                overall_severity = 'High'
            elif 'Medium' in severities:
                overall_severity = 'Medium'
            else:
                overall_severity = 'Low'
            
            evidence = f"Found {len(issues)} CSP issues in {csp_header_name}"
            return True, evidence, overall_severity, issues
        
        return False, "", "", []
    
    @staticmethod
    def _check_meta_csp(response_text: str) -> str:
        """Check for CSP in meta tags"""
        meta_pattern = r'<meta[^>]+http-equiv=["\']?content-security-policy["\']?[^>]+content=["\']([^"\']+)["\'][^>]*>'
        match = re.search(meta_pattern, response_text, re.IGNORECASE)
        return match.group(1) if match else ""
    
    @staticmethod
    def _analyze_csp(csp_header: str) -> List[Dict[str, Any]]:
        """Analyze CSP header for security issues"""
        issues = []
        directives_info = CSPDetector.get_csp_directives()
        
        # Parse CSP directives
        directives = {}
        for directive_pair in csp_header.split(';'):
            directive_pair = directive_pair.strip()
            if ' ' in directive_pair:
                directive_name, directive_values = directive_pair.split(' ', 1)
                directives[directive_name.strip()] = directive_values.strip()
            else:
                directives[directive_pair] = ''
        
        # Check each important directive
        for directive_name, directive_info in directives_info.items():
            if directive_name not in directives:
                if directive_info['importance'] == 'High':
                    issues.append({
                        'type': 'missing_directive',
                        'directive': directive_name,
                        'issue': f'Missing {directive_name} directive',
                        'severity': 'Medium',
                        'description': f"Missing {directive_name}: {directive_info['description']}"
                    })
            else:
                # Check directive values for security issues
                directive_value = directives[directive_name]
                
                for insecure_value in directive_info['insecure_values']:
                    if insecure_value in directive_value:
                        severity = 'High' if directive_info['importance'] == 'High' else 'Medium'
                        issues.append({
                            'type': 'insecure_directive',
                            'directive': directive_name,
                            'issue': f'Insecure value: {insecure_value}',
                            'severity': severity,
                            'description': f"{directive_name} contains insecure value '{insecure_value}'"
                        })
        
        # Check for deprecated directives
        deprecated_directives = ['script-src-elem', 'script-src-attr', 'style-src-elem', 'style-src-attr']
        for deprecated in deprecated_directives:
            if deprecated in directives:
                issues.append({
                    'type': 'deprecated_directive',
                    'directive': deprecated,
                    'issue': 'Deprecated directive',
                    'severity': 'Low',
                    'description': f"Directive {deprecated} is deprecated"
                })
        
        return issues
    
    @staticmethod
    def get_evidence(issues: List[Dict[str, Any]], csp_header: str) -> str:
        """Get detailed evidence for CSP issues"""
        evidence_parts = []
        
        for issue in issues[:5]:
            evidence_parts.append(f"{issue['directive']}: {issue['issue']}")
        
        if len(issues) > 5:
            evidence_parts.append(f"... and {len(issues) - 5} more issues")
        
        return "; ".join(evidence_parts)
    
    @staticmethod
    def get_response_snippet(csp_header: str, issues: List[Dict[str, Any]]) -> str:
        """Get response snippet showing CSP issues"""
        if not csp_header:
            return "Content-Security-Policy header: Not present"
        
        snippet = f"Content-Security-Policy: {csp_header[:200]}"
        if len(csp_header) > 200:
            snippet += "..."
        
        return snippet
    
    @staticmethod
    def get_remediation_advice() -> str:
        """Get remediation advice for CSP issues"""
        return (
            "Implement proper Content Security Policy: "
            "1) Add Content-Security-Policy header, "
            "2) Use 'self' instead of '*' for sources, "
            "3) Avoid 'unsafe-inline' and 'unsafe-eval', "
            "4) Set object-src to 'none', "
            "5) Configure frame-ancestors to prevent clickjacking, "
            "6) Use nonces or hashes for inline scripts/styles."
        )
