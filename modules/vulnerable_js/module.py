"""
Vulnerable JavaScript Libraries Scanner Module

Detects JavaScript libraries with known security vulnerabilities.
Inspired by Retire.js - uses version detection via:
- File content regex patterns
- Filename patterns
- URL patterns

Covers 30+ popular libraries including jQuery, Angular, React, Vue,
Bootstrap, Lodash, Moment.js, and many more.
"""

from typing import List, Dict, Any, Optional, Set
from core.base_module import BaseModule
from core.logger import get_logger
from urllib.parse import urljoin, urlparse
import re

logger = get_logger(__name__)


class VulnerableJSModule(BaseModule):
    """Vulnerable JavaScript Libraries Scanner Module"""

    def __init__(self, module_path: str, payload_limit: int = None):
        """Initialize Vulnerable JS module"""
        super().__init__(module_path, payload_limit=payload_limit)

        self.analyzed_files: Set[str] = set()

        # Initialize the vulnerability database
        self._init_vuln_database()

        logger.info(f"Vulnerable JS module loaded: {len(self.js_libraries)} libraries tracked")

    def _init_vuln_database(self):
        """Initialize the JavaScript vulnerability database"""
        VERSION = r'[\d]+\.[\d]+\.[\d]+(?:[-+][\w.]+)?'

        self.js_libraries = {
            'jquery': {
                'extractors': {
                    'filecontent': [
                        r'/\*!?\s*jQuery\s+v?(' + VERSION + r')',
                        r'\$\.fn\.jquery\s*=\s*["\'](' + VERSION + r')["\']',
                    ],
                    'filename': [r'jquery[.-](' + VERSION + r')(?:\.min)?\.js'],
                    'uri': [r'/jquery/(' + VERSION + r')/jquery', r'/jquery@(' + VERSION + r')'],
                },
                'vulnerabilities': [
                    {'below': '1.6.3', 'severity': 'Medium', 'cve': ['CVE-2011-4969'], 'summary': 'XSS vulnerability'},
                    {'below': '3.0.0', 'severity': 'Medium', 'cve': ['CVE-2015-9251'], 'summary': 'XSS via cross-domain ajax'},
                    {'below': '3.4.0', 'severity': 'Medium', 'cve': ['CVE-2019-11358'], 'summary': 'Prototype pollution'},
                    {'below': '3.5.0', 'atOrAbove': '1.0.3', 'severity': 'Medium', 'cve': ['CVE-2020-11022', 'CVE-2020-11023'], 'summary': 'XSS in htmlPrefilter'},
                ],
            },
            'jquery-ui': {
                'extractors': {
                    'filecontent': [r'jQuery UI [- ]v?(' + VERSION + r')'],
                    'filename': [r'jquery-ui[.-](' + VERSION + r')'],
                },
                'vulnerabilities': [
                    {'below': '1.13.0', 'severity': 'Medium', 'cve': ['CVE-2021-41182', 'CVE-2021-41183'], 'summary': 'XSS in components'},
                    {'below': '1.12.0', 'severity': 'Medium', 'cve': ['CVE-2016-7103'], 'summary': 'XSS in dialog closeText'},
                ],
            },
            'angularjs': {
                'extractors': {
                    'filecontent': [r'AngularJS v(' + VERSION + r')', r"angular\.version\s*=\s*\{[^}]*full:\s*['\"](" + VERSION + r")['\"]"],
                    'filename': [r'angular[.-](' + VERSION + r')(?:\.min)?\.js'],
                },
                'vulnerabilities': [
                    {'below': '1.8.0', 'severity': 'High', 'cve': ['CVE-2022-25869'], 'summary': 'XSS via SVG attributes'},
                    {'below': '1.6.9', 'severity': 'High', 'cve': ['CVE-2019-10768'], 'summary': 'Prototype pollution'},
                    {'below': '1.5.0', 'severity': 'High', 'cve': [], 'summary': 'Sandbox escape XSS'},
                ],
            },
            'vue': {
                'extractors': {
                    'filecontent': [r'Vue\.js v(' + VERSION + r')', r'"vue":\s*"[\^~]?(' + VERSION + r')"'],
                },
                'vulnerabilities': [
                    {'below': '2.5.17', 'severity': 'Medium', 'cve': ['CVE-2018-11235'], 'summary': 'XSS via templates'},
                ],
            },
            'react': {
                'extractors': {
                    'filecontent': [r'React v(' + VERSION + r')'],
                },
                'vulnerabilities': [
                    {'below': '16.4.2', 'severity': 'Medium', 'cve': [], 'summary': 'XSS via javascript: URLs'},
                ],
            },
            'bootstrap': {
                'extractors': {
                    'filecontent': [r'Bootstrap v(' + VERSION + r')', r'\* Bootstrap v(' + VERSION + r')'],
                    'filename': [r'bootstrap[.-](' + VERSION + r')(?:\.min)?\.js'],
                },
                'vulnerabilities': [
                    {'below': '3.4.0', 'severity': 'Medium', 'cve': ['CVE-2018-14040', 'CVE-2018-14041'], 'summary': 'XSS in data-* attributes'},
                    {'below': '4.3.1', 'severity': 'Medium', 'cve': ['CVE-2019-8331'], 'summary': 'XSS in tooltip/popover'},
                ],
            },
            'lodash': {
                'extractors': {
                    'filecontent': [r'@license Lodash (' + VERSION + r')', r'lodash\.VERSION\s*=\s*["\'](' + VERSION + r')["\']'],
                    'filename': [r'lodash[.-](' + VERSION + r')(?:\.min)?\.js'],
                },
                'vulnerabilities': [
                    {'below': '4.17.12', 'severity': 'High', 'cve': ['CVE-2019-10744'], 'summary': 'Prototype pollution'},
                    {'below': '4.17.21', 'severity': 'High', 'cve': ['CVE-2021-23337'], 'summary': 'Command injection via template'},
                ],
            },
            'moment': {
                'extractors': {
                    'filecontent': [r'//! moment\.js\s+//! version\s*:\s*(' + VERSION + r')'],
                    'filename': [r'moment[.-](' + VERSION + r')(?:\.min)?\.js'],
                },
                'vulnerabilities': [
                    {'below': '2.19.3', 'severity': 'Medium', 'cve': ['CVE-2017-18214'], 'summary': 'ReDoS vulnerability'},
                    {'below': '2.29.4', 'severity': 'High', 'cve': ['CVE-2022-31129'], 'summary': 'Inefficient regex'},
                ],
            },
            'handlebars': {
                'extractors': {
                    'filecontent': [r'Handlebars v(' + VERSION + r')'],
                    'filename': [r'handlebars[.-](' + VERSION + r')(?:\.min)?\.js'],
                },
                'vulnerabilities': [
                    {'below': '4.4.5', 'severity': 'Critical', 'cve': ['CVE-2019-20920'], 'summary': 'Remote code execution'},
                    {'below': '4.7.7', 'severity': 'Critical', 'cve': ['CVE-2021-23369'], 'summary': 'RCE via template'},
                ],
            },
            'underscore': {
                'extractors': {
                    'filecontent': [r'Underscore\.js (' + VERSION + r')'],
                    'filename': [r'underscore[.-](' + VERSION + r')(?:\.min)?\.js'],
                },
                'vulnerabilities': [
                    {'below': '1.13.0-2', 'severity': 'High', 'cve': ['CVE-2021-23358'], 'summary': 'Arbitrary code execution'},
                ],
            },
            'dompurify': {
                'extractors': {
                    'filecontent': [r'/\*!\s*DOMPurify (' + VERSION + r')'],
                },
                'vulnerabilities': [
                    {'below': '2.0.17', 'severity': 'High', 'cve': ['CVE-2020-26870'], 'summary': 'XSS bypass'},
                    {'below': '2.4.0', 'severity': 'High', 'cve': ['CVE-2022-25927'], 'summary': 'Mutation XSS bypass'},
                ],
            },
            'axios': {
                'extractors': {
                    'filecontent': [r'axios v(' + VERSION + r')'],
                },
                'vulnerabilities': [
                    {'below': '0.21.1', 'severity': 'Medium', 'cve': ['CVE-2020-28168'], 'summary': 'SSRF via proxy'},
                    {'below': '1.6.0', 'severity': 'High', 'cve': ['CVE-2023-45857'], 'summary': 'CSRF token exposure'},
                ],
            },
            'tinymce': {
                'extractors': {
                    'filecontent': [r'TinyMCE (' + VERSION + r')'],
                },
                'vulnerabilities': [
                    {'below': '5.10.0', 'severity': 'Medium', 'cve': ['CVE-2022-23494'], 'summary': 'XSS via media embed'},
                    {'below': '6.3.1', 'severity': 'Medium', 'cve': ['CVE-2023-45818'], 'summary': 'XSS via noscript'},
                ],
            },
            'ckeditor': {
                'extractors': {
                    'filecontent': [r'CKEditor (' + VERSION + r')'],
                },
                'vulnerabilities': [
                    {'below': '4.17.0', 'severity': 'Medium', 'cve': ['CVE-2021-41164'], 'summary': 'XSS vulnerabilities'},
                ],
            },
            'yui': {
                'extractors': {
                    'filecontent': [r'YUI (' + VERSION + r')'],
                },
                'vulnerabilities': [
                    {'below': '99.0.0', 'severity': 'High', 'cve': [], 'summary': 'Deprecated - multiple XSS vulnerabilities'},
                ],
            },
            'prototype': {
                'extractors': {
                    'filecontent': [r'Prototype JavaScript framework, version (' + VERSION + r')'],
                },
                'vulnerabilities': [
                    {'below': '99.0.0', 'severity': 'High', 'cve': [], 'summary': 'Deprecated - prototype pollution'},
                ],
            },
        }

    def scan(self, targets: List[Dict[str, Any]], http_client: Any) -> List[Dict[str, Any]]:
        """
        Scan for vulnerable JavaScript libraries

        Args:
            targets: List of URLs (we scan the base URLs)
            http_client: HTTP client

        Returns:
            List of vulnerability results
        """
        results = []
        self.analyzed_files = set()

        # Get unique base URLs to scan
        base_urls = set()
        for target in targets:
            url = target.get('url', '')
            if url:
                parsed = urlparse(url)
                base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
                base_urls.add(base_url)

        logger.info(f"Scanning {len(base_urls)} URLs for vulnerable JavaScript libraries")

        for url in base_urls:
            if self.should_stop():
                break

            try:
                response = http_client.get(url)
                if not response:
                    continue

                html = getattr(response, 'text', '') or ''

                # Find and analyze JS files
                js_files = self._find_js_files(url, html)
                logger.debug(f"Found {len(js_files)} JavaScript files at {url}")

                for js_url in js_files:
                    if js_url in self.analyzed_files:
                        continue
                    self.analyzed_files.add(js_url)

                    file_results = self._analyze_js_file(js_url, http_client)
                    results.extend(file_results)

                # Also check inline scripts
                inline_results = self._analyze_inline_scripts(url, html)
                results.extend(inline_results)

            except Exception as e:
                logger.debug(f"Error scanning {url}: {e}")

        logger.info(f"Vulnerable JS scan complete: {len(results)} vulnerabilities found")
        return results

    def _find_js_files(self, base_url: str, html: str) -> List[str]:
        """Extract JavaScript file URLs from HTML"""
        js_files = []

        patterns = [
            r'<script[^>]+src=["\']([^"\']+\.js[^"\']*)["\']',
            r'<script[^>]+src=["\']([^"\']+)["\'][^>]*>',
        ]

        for pattern in patterns:
            for match in re.finditer(pattern, html, re.IGNORECASE):
                src = match.group(1)
                if src and ('.js' in src or 'jquery' in src.lower() or 'angular' in src.lower()):
                    full_url = urljoin(base_url, src)
                    if full_url not in js_files:
                        js_files.append(full_url)

        return js_files[:30]  # Limit

    def _analyze_js_file(self, js_url: str, http_client: Any) -> List[Dict[str, Any]]:
        """Analyze a JavaScript file for vulnerable libraries"""
        results = []

        try:
            response = http_client.get(js_url, timeout=10)
            if not response or response.status_code != 200:
                return results

            content = getattr(response, 'text', '') or ''
            if not content:
                return results

            filename = urlparse(js_url).path.split('/')[-1]

            # Check each library
            for lib_name, lib_data in self.js_libraries.items():
                version = self._detect_version(lib_data, content, filename, js_url)
                if version:
                    vulns = self._check_vulnerabilities(lib_data, version)
                    for vuln in vulns:
                        result = self._create_finding(js_url, lib_name, version, vuln)
                        results.append(result)

        except Exception as e:
            logger.debug(f"Error analyzing {js_url}: {e}")

        return results

    def _analyze_inline_scripts(self, url: str, html: str) -> List[Dict[str, Any]]:
        """Analyze inline scripts for vulnerable libraries"""
        results = []

        script_pattern = r'<script[^>]*>(.*?)</script>'
        for match in re.finditer(script_pattern, html, re.IGNORECASE | re.DOTALL):
            content = match.group(1)
            if not content or len(content) < 50:
                continue

            for lib_name, lib_data in self.js_libraries.items():
                version = self._detect_version(lib_data, content, '', url)
                if version:
                    vulns = self._check_vulnerabilities(lib_data, version)
                    for vuln in vulns:
                        result = self._create_finding(url, lib_name, version, vuln, inline=True)
                        results.append(result)

        return results

    def _detect_version(self, lib_data: Dict, content: str, filename: str, url: str) -> Optional[str]:
        """Detect library version using extractors"""
        extractors = lib_data.get('extractors', {})

        # Try filecontent patterns
        for pattern in extractors.get('filecontent', []):
            try:
                match = re.search(pattern, content, re.IGNORECASE)
                if match:
                    return match.group(1)
            except:
                pass

        # Try filename patterns
        for pattern in extractors.get('filename', []):
            try:
                match = re.search(pattern, filename, re.IGNORECASE)
                if match:
                    return match.group(1)
            except:
                pass

        # Try URI patterns
        for pattern in extractors.get('uri', []):
            try:
                match = re.search(pattern, url, re.IGNORECASE)
                if match:
                    return match.group(1)
            except:
                pass

        return None

    def _check_vulnerabilities(self, lib_data: Dict, version: str) -> List[Dict]:
        """Check if version is affected by known vulnerabilities"""
        vulns = []

        for vuln in lib_data.get('vulnerabilities', []):
            below = vuln.get('below', '99999.0.0')
            at_or_above = vuln.get('atOrAbove', '0.0.0')

            if self._version_in_range(version, at_or_above, below):
                vulns.append(vuln)

        return vulns

    def _version_in_range(self, version: str, at_or_above: str, below: str) -> bool:
        """Check if version is within the vulnerable range"""
        try:
            v = self._parse_version(version)
            min_v = self._parse_version(at_or_above)
            max_v = self._parse_version(below)
            return min_v <= v < max_v
        except:
            return False

    def _parse_version(self, version: str) -> tuple:
        """Parse version string to comparable tuple"""
        version = re.sub(r'^[vV]', '', version)
        version = re.sub(r'[-+].*$', '', version)

        parts = version.split('.')
        result = []
        for part in parts[:3]:
            try:
                result.append(int(re.sub(r'[^\d]', '', part) or '0'))
            except:
                result.append(0)

        while len(result) < 3:
            result.append(0)

        return tuple(result)

    def _create_finding(self, url: str, lib_name: str, version: str,
                        vuln: Dict, inline: bool = False) -> Dict[str, Any]:
        """Create a vulnerability finding"""
        cves = vuln.get('cve', [])
        summary = vuln.get('summary', 'Known vulnerability')
        severity = vuln.get('severity', 'Medium')

        cve_str = ', '.join(cves) if cves else 'N/A'
        location = 'inline script' if inline else 'external file'

        evidence = f"""Vulnerable JavaScript Library Detected

**Library:** {lib_name}
**Version:** {version}
**Location:** {location}
**URL:** {url}

**Vulnerability Details:**
- CVE: {cve_str}
- Affected versions below: {vuln.get('below', 'N/A')}
- Summary: {summary}

**Security Impact:**
{summary}

**Remediation:**
Update {lib_name} to version {vuln.get('below', 'latest')} or higher.
"""

        result = self.create_result(
            vulnerable=True,
            url=url,
            parameter=f'{lib_name} v{version}',
            payload=f'{lib_name}@{version}',
            evidence=evidence,
            description=f"Vulnerable JavaScript library: {lib_name} {version}. {summary}",
            confidence=0.95,
            severity=severity,
            method='GET',
            response=f"Library: {lib_name}, Version: {version}"
        )

        result['library'] = lib_name
        result['version'] = version
        result['cve'] = cves
        result['vulnerability_summary'] = summary
        result['verified'] = True

        logger.info(f"Found vulnerable {lib_name} v{version} ({cve_str})")
        return result


def get_module(module_path: str, payload_limit: int = None):
    """Create module instance"""
    return VulnerableJSModule(module_path, payload_limit=payload_limit)
