"""
Tabnabbing (Reverse Tabnabbing) Detection Scanner
Detects links with target="_blank" missing rel="noopener noreferrer"
"""

from core.base_module import BaseModule
from core.logger import get_logger
from typing import List, Dict, Any
from urllib.parse import urljoin, urlparse
import re

logger = get_logger(__name__)


class TabnabbingScanner(BaseModule):
    """Scans for reverse tabnabbing vulnerabilities"""

    def __init__(self, module_path: str, payload_limit: int = None):
        super().__init__(module_path, payload_limit=payload_limit)
        self.module_name = "Tabnabbing Scanner"
        self.logger = logger

    def scan(self, targets: List[Dict[str, Any]], http_client: Any = None) -> List[Dict[str, Any]]:
        """Scan for tabnabbing vulnerabilities"""
        self.logger.info(f"Starting {self.module_name} scan on {len(targets)} targets")

        results = []
        tested_urls = set()

        for target in targets:
            url = target.get('url') if isinstance(target, dict) else target
            if not url:
                continue

            if url in tested_urls:
                continue
            tested_urls.add(url)

            findings = self._analyze_page(http_client, url)
            results.extend(findings)

            if self.payload_limit and len(results) >= self.payload_limit:
                break

        self.logger.info(f"{self.module_name} scan complete: {len(results)} findings")
        return results

    def _analyze_page(self, http_client, url: str) -> List[Dict[str, Any]]:
        """Analyze a page for tabnabbing vulnerabilities"""
        results = []

        try:
            response = http_client.get(url)
            if not response or response.status_code != 200:
                return results

            content = response.text
            if not content:
                return results

            # Find all anchor tags with target="_blank"
            # Pattern matches <a ... target="_blank" ... > or <a ... target='_blank' ... >
            anchor_pattern = r'<a\s+[^>]*target\s*=\s*["\']_blank["\'][^>]*>'
            vulnerable_links = []
            safe_links = []

            for match in re.finditer(anchor_pattern, content, re.IGNORECASE):
                anchor_tag = match.group(0)

                # Extract href
                href_match = re.search(r'href\s*=\s*["\']([^"\']+)["\']', anchor_tag, re.IGNORECASE)
                href = href_match.group(1) if href_match else 'unknown'

                # Check for rel attribute with noopener/noreferrer
                rel_match = re.search(r'rel\s*=\s*["\']([^"\']+)["\']', anchor_tag, re.IGNORECASE)

                is_safe = False
                if rel_match:
                    rel_value = rel_match.group(1).lower()
                    # Must have noopener OR noreferrer (noreferrer implies noopener)
                    if 'noopener' in rel_value or 'noreferrer' in rel_value:
                        is_safe = True

                # Skip internal links (same origin) - less risky
                parsed_href = urlparse(href)
                parsed_url = urlparse(url)
                is_external = parsed_href.netloc and parsed_href.netloc != parsed_url.netloc

                if not is_safe:
                    vulnerable_links.append({
                        'href': href,
                        'tag': anchor_tag[:200],  # Truncate long tags
                        'external': is_external
                    })
                else:
                    safe_links.append(href)

            # Also check for window.open without noopener
            window_open_pattern = r'window\.open\s*\([^)]*["\'][^"\']+["\'][^)]*\)'
            window_opens = re.findall(window_open_pattern, content)

            vulnerable_window_opens = []
            for wo in window_opens:
                if 'noopener' not in wo.lower() and 'noreferrer' not in wo.lower():
                    vulnerable_window_opens.append(wo[:150])

            # Report findings
            if vulnerable_links:
                external_vuln = [l for l in vulnerable_links if l['external']]
                internal_vuln = [l for l in vulnerable_links if not l['external']]

                # External links are higher risk
                if external_vuln:
                    hrefs = [l['href'] for l in external_vuln[:10]]
                    results.append(self.create_result(
                        vulnerable=True,
                        url=url,
                        parameter='target="_blank"',
                        payload='External links without rel="noopener"',
                        evidence=f"Found {len(external_vuln)} external links vulnerable to reverse tabnabbing: {', '.join(hrefs[:5])}",
                        severity='Medium',
                        method='GET',
                        additional_info={
                            'injection_type': 'Reverse Tabnabbing',
                            'vulnerable_links': external_vuln[:20],
                            'total_vulnerable': len(external_vuln),
                            'description': 'External links with target="_blank" without rel="noopener noreferrer" allow the opened page to access window.opener',
                            'impact': 'Opened page can redirect parent to phishing page via window.opener.location',
                            'cwe': 'CWE-1022',
                            'owasp': 'A05:2021',
                            'remediation': 'Add rel="noopener noreferrer" to all external links with target="_blank"',
                            'poc': self._generate_poc(url, external_vuln[0]['href'] if external_vuln else '')
                        }
                    ))

                # Internal links are lower risk but still worth noting
                if internal_vuln and len(internal_vuln) > 3:
                    results.append(self.create_result(
                        vulnerable=True,
                        url=url,
                        parameter='target="_blank"',
                        payload='Internal links without rel="noopener"',
                        evidence=f"Found {len(internal_vuln)} internal links without rel='noopener'",
                        severity='Info',
                        method='GET',
                        additional_info={
                            'injection_type': 'Reverse Tabnabbing (Internal)',
                            'total_vulnerable': len(internal_vuln),
                            'description': 'Internal links with target="_blank" without rel="noopener" - lower risk but best practice to fix',
                            'cwe': 'CWE-1022',
                            'owasp': 'A05:2021'
                        }
                    ))

            # Report vulnerable window.open calls
            if vulnerable_window_opens:
                results.append(self.create_result(
                    vulnerable=True,
                    url=url,
                    parameter='window.open()',
                    payload='window.open without noopener',
                    evidence=f"Found {len(vulnerable_window_opens)} window.open() calls without noopener: {vulnerable_window_opens[0]}",
                    severity='Medium',
                    method='GET',
                    additional_info={
                        'injection_type': 'Reverse Tabnabbing (JavaScript)',
                        'vulnerable_calls': vulnerable_window_opens[:10],
                        'description': 'window.open() without noopener feature allows opened page to access opener',
                        'remediation': 'Use window.open(url, "_blank", "noopener,noreferrer")',
                        'cwe': 'CWE-1022',
                        'owasp': 'A05:2021'
                    }
                ))

        except Exception as e:
            self.logger.debug(f"Error analyzing {url}: {e}")

        return results

    def _generate_poc(self, victim_url: str, example_href: str) -> str:
        """Generate a proof-of-concept HTML for tabnabbing"""
        poc = f'''<!DOCTYPE html>
<html>
<head>
    <title>Tabnabbing PoC</title>
</head>
<body>
    <h1>Reverse Tabnabbing Proof of Concept</h1>
    <p>Target: {victim_url}</p>
    <p>This page was opened from a link without rel="noopener"</p>
    <p>The opener window can be redirected using window.opener:</p>

    <script>
    // This demonstrates the vulnerability
    // In a real attack, this would redirect to a phishing page
    if (window.opener) {{
        document.write('<p style="color:red">VULNERABLE: window.opener is accessible!</p>');
        document.write('<button onclick="exploitTabnabbing()">Demonstrate Attack</button>');
    }} else {{
        document.write('<p style="color:green">SAFE: window.opener is null (noopener in effect)</p>');
    }}

    function exploitTabnabbing() {{
        // In a real attack, this would be a phishing page
        window.opener.location = 'https://evil-site.example.com/fake-login';
        alert('Parent window redirected! (In real attack: to phishing page)');
    }}
    </script>

    <h2>Remediation</h2>
    <p>Add rel="noopener noreferrer" to links:</p>
    <code>&lt;a href="..." target="_blank" rel="noopener noreferrer"&gt;Link&lt;/a&gt;</code>
</body>
</html>'''
        return poc


def get_module(module_path: str, payload_limit: int = None):
    """Factory function to create module instance"""
    return TabnabbingScanner(module_path, payload_limit=payload_limit)
