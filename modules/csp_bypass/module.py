"""
CSP Bypass Analyzer Module
Analyzes Content-Security-Policy for known bypass techniques
"""

import re
from typing import List, Dict, Any
from urllib.parse import urlparse
from core.base_module import BaseModule
from core.logger import get_logger

logger = get_logger(__name__)


class CSPBypassModule(BaseModule):
    """CSP Bypass vulnerability analyzer"""

    def __init__(self, module_path: str, payload_limit: int = None):
        """Initialize CSP Bypass module"""
        super().__init__(module_path, payload_limit=payload_limit)

        # Known vulnerable CDNs/domains with JSONP or script gadgets
        self.vulnerable_domains = {
            'www.google.com': 'JSONP', 'apis.google.com': 'JSONP',
            'ajax.googleapis.com': 'AngularJS', 'cdnjs.cloudflare.com': 'Libraries',
            'cdn.jsdelivr.net': 'Libraries', 'unpkg.com': 'Libraries',
            'www.google-analytics.com': 'JSONP', 'connect.facebook.net': 'JSONP',
            'platform.twitter.com': 'JSONP', 'www.youtube.com': 'JSONP',
            'raw.githubusercontent.com': 'Any script', 'pastebin.com': 'Any content',
        }

        # Dangerous CSP directives
        self.dangerous_directives = {
            "'unsafe-inline'": ('Critical', 'Allows inline scripts'),
            "'unsafe-eval'": ('High', 'Allows eval()'),
            'data:': ('High', 'Allows data: URLs for scripts'),
            '*': ('Critical', 'Wildcard allows any source'),
        }

        logger.info("CSP Bypass Analyzer module loaded")

    def scan(self, targets: List[Dict[str, Any]], http_client: Any) -> List[Dict[str, Any]]:
        """Scan for CSP bypass vectors"""
        results = []
        tested_hosts = set()

        for target in targets:
            url = target.get('url')
            parsed = urlparse(url)
            host_key = parsed.netloc

            if host_key in tested_hosts:
                continue
            tested_hosts.add(host_key)

            try:
                response = http_client.get(url)
                if not response:
                    continue

                # Get CSP headers
                csp = response.headers.get('Content-Security-Policy', '')
                csp_ro = response.headers.get('Content-Security-Policy-Report-Only', '')

                if csp:
                    csp_results = self._analyze_csp(url, csp, 'Content-Security-Policy')
                    results.extend(csp_results)

                if csp_ro:
                    csp_results = self._analyze_csp(url, csp_ro, 'Content-Security-Policy-Report-Only')
                    results.extend(csp_results)

                # Check meta tag CSP
                meta_match = re.search(r'<meta[^>]+content-security-policy[^>]+content=["\']([^"\']+)["\']',
                                       response.text, re.IGNORECASE)
                if meta_match:
                    csp_results = self._analyze_csp(url, meta_match.group(1), 'meta-csp')
                    results.extend(csp_results)

            except Exception:
                continue

        return results

    def _analyze_csp(self, url: str, csp: str, header_type: str) -> List[Dict]:
        """Analyze CSP for bypass vectors"""
        bypasses = []

        # Parse directives
        directives = {}
        for part in csp.split(';'):
            part = part.strip()
            if ' ' in part:
                directive, value = part.split(' ', 1)
                directives[directive.lower()] = value

        script_src = directives.get('script-src', directives.get('default-src', ''))

        # 1. Check dangerous directives
        for dangerous, (severity, desc) in self.dangerous_directives.items():
            if dangerous in script_src or dangerous in csp:
                bypasses.append({
                    'type': 'Dangerous Directive',
                    'vector': dangerous,
                    'severity': severity,
                    'description': desc
                })

        # 2. Check vulnerable domains
        for domain, bypass_type in self.vulnerable_domains.items():
            if domain in csp:
                bypasses.append({
                    'type': f'Vulnerable Domain ({bypass_type})',
                    'vector': domain,
                    'severity': 'High',
                    'description': f'{domain} has known {bypass_type} bypass gadgets'
                })

        # 3. Check missing directives
        missing = []
        if 'base-uri' not in csp:
            missing.append('base-uri')
        if 'form-action' not in csp:
            missing.append('form-action')
        if 'frame-ancestors' not in csp:
            missing.append('frame-ancestors')

        for directive in missing:
            bypasses.append({
                'type': 'Missing Directive',
                'vector': directive,
                'severity': 'Medium',
                'description': f'Missing {directive} directive'
            })

        # Create result if bypasses found
        if bypasses:
            critical = sum(1 for b in bypasses if b['severity'] == 'Critical')
            high = sum(1 for b in bypasses if b['severity'] == 'High')

            max_severity = 'Critical' if critical else ('High' if high else 'Medium')

            evidence = f"CSP Header: {header_type}\nPolicy: {csp[:300]}...\n\nBypass Vectors ({len(bypasses)}):\n"
            for b in bypasses[:5]:
                evidence += f"- [{b['severity']}] {b['type']}: {b['vector']}\n"

            return [self.create_result(
                vulnerable=True,
                url=url,
                parameter=header_type,
                payload=f"{len(bypasses)} bypass vectors",
                evidence=evidence,
                severity=max_severity,
                method='GET',
                additional_info={
                    'injection_type': 'CSP Bypass',
                    'bypasses': bypasses,
                    'critical_count': critical,
                    'high_count': high,
                    'cwe': 'CWE-79',
                    'owasp': 'A05:2021',
                    'cvss': 8.1 if critical else 7.2
                }
            )]

        return []


def get_module(module_path: str, payload_limit: int = None):
    """Factory function to create module instance"""
    return CSPBypassModule(module_path, payload_limit)
