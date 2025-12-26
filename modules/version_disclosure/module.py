"""
Version Disclosure Scanner

Detects version information disclosure in:
- HTTP headers (Server, X-Powered-By, etc.)
- HTML meta tags and comments
- Error pages
- Common files (robots.txt, package.json, etc.)
"""

from typing import List, Dict, Any, Optional
from core.base_module import BaseModule
from core.logger import get_logger
import re

logger = get_logger(__name__)


class VersionDisclosureModule(BaseModule):
    """Version Disclosure vulnerability scanner"""

    # Headers that may disclose versions
    VERSION_HEADERS = [
        'server',
        'x-powered-by',
        'x-aspnet-version',
        'x-aspnetmvc-version',
        'x-generator',
        'x-drupal-cache',
        'x-drupal-dynamic-cache',
        'x-varnish',
        'via',
        'x-amz-cf-id',
        'x-cache',
    ]

    # Version patterns
    VERSION_PATTERNS = [
        # Web servers
        (r'Apache/(\d+\.\d+(?:\.\d+)?)', 'Apache'),
        (r'nginx/(\d+\.\d+(?:\.\d+)?)', 'nginx'),
        (r'Microsoft-IIS/(\d+\.\d+)', 'IIS'),
        (r'LiteSpeed', 'LiteSpeed'),

        # Languages/Frameworks
        (r'PHP/(\d+\.\d+(?:\.\d+)?)', 'PHP'),
        (r'ASP\.NET(?: Version)?[:\s]+(\d+\.\d+(?:\.\d+)?)', 'ASP.NET'),
        (r'Python/(\d+\.\d+(?:\.\d+)?)', 'Python'),
        (r'Express', 'Express.js'),
        (r'Django', 'Django'),
        (r'Rails', 'Ruby on Rails'),
        (r'Laravel', 'Laravel'),
        (r'WordPress (\d+\.\d+(?:\.\d+)?)', 'WordPress'),
        (r'Drupal (\d+)', 'Drupal'),
        (r'Joomla', 'Joomla'),

        # Caching/CDN
        (r'Varnish', 'Varnish'),
        (r'CloudFlare', 'Cloudflare'),
        (r'Akamai', 'Akamai'),

        # Databases (in errors)
        (r'MySQL(?: Server)?[\s/]+(\d+\.\d+(?:\.\d+)?)', 'MySQL'),
        (r'PostgreSQL (\d+\.\d+(?:\.\d+)?)', 'PostgreSQL'),
        (r'MongoDB (\d+\.\d+(?:\.\d+)?)', 'MongoDB'),
    ]

    # Meta tag patterns
    META_PATTERNS = [
        r'<meta\s+name=["\']generator["\']\s+content=["\']([^"\']+)["\']',
        r'<meta\s+content=["\']([^"\']+)["\']\s+name=["\']generator["\']',
    ]

    def __init__(self, module_path: str, payload_limit: int = None):
        super().__init__(module_path, payload_limit=payload_limit)
        logger.info("Version Disclosure module initialized")

    def scan(self, targets: List[Dict[str, Any]], http_client: Any) -> List[Dict[str, Any]]:
        """Scan for version disclosure"""
        results = []
        scanned_hosts = set()

        logger.info(f"Starting Version Disclosure scan on {len(targets)} targets")

        for target in targets:
            url = target.get('url', '')
            if not url:
                continue

            # Only scan once per host
            from urllib.parse import urlparse
            host = urlparse(url).netloc
            if host in scanned_hosts:
                continue
            scanned_hosts.add(host)

            # Get response
            try:
                response = http_client.get(url)
                if not response:
                    continue

                # Check headers
                header_findings = self._check_headers(response)

                # Check body
                body_findings = self._check_body(response.text)

                all_findings = header_findings + body_findings

                if all_findings:
                    result = self._create_result(url, all_findings)
                    results.append(result)

            except Exception as e:
                logger.debug(f"Error scanning {url}: {e}")

        logger.info(f"Version Disclosure scan complete: {len(results)} findings")
        return results

    def _check_headers(self, response: Any) -> List[Dict]:
        """Check response headers for version info"""
        findings = []

        headers_dict = {}
        if hasattr(response, 'headers'):
            if isinstance(response.headers, dict):
                headers_dict = response.headers
            else:
                headers_dict = dict(response.headers)

        for header_name, header_value in headers_dict.items():
            header_lower = header_name.lower()

            if header_lower in self.VERSION_HEADERS:
                # Check for version patterns
                for pattern, tech in self.VERSION_PATTERNS:
                    match = re.search(pattern, str(header_value), re.I)
                    if match:
                        version = match.group(1) if match.lastindex else 'detected'
                        findings.append({
                            'source': f'Header: {header_name}',
                            'technology': tech,
                            'version': version,
                            'raw': str(header_value)[:100]
                        })
                        break
                else:
                    # Header exists but no specific version found
                    if header_value and len(str(header_value)) > 0:
                        findings.append({
                            'source': f'Header: {header_name}',
                            'technology': 'Unknown',
                            'version': 'disclosed',
                            'raw': str(header_value)[:100]
                        })

        return findings

    def _check_body(self, body: str) -> List[Dict]:
        """Check response body for version info"""
        findings = []

        if not body:
            return findings

        # Check meta generator tags
        for pattern in self.META_PATTERNS:
            matches = re.findall(pattern, body, re.I)
            for match in matches:
                # Try to identify technology
                for vpattern, tech in self.VERSION_PATTERNS:
                    vmatch = re.search(vpattern, match, re.I)
                    if vmatch:
                        version = vmatch.group(1) if vmatch.lastindex else 'detected'
                        findings.append({
                            'source': 'Meta Generator Tag',
                            'technology': tech,
                            'version': version,
                            'raw': match[:100]
                        })
                        break
                else:
                    findings.append({
                        'source': 'Meta Generator Tag',
                        'technology': 'CMS/Framework',
                        'version': 'detected',
                        'raw': match[:100]
                    })

        # Check for version patterns in body (comments, errors)
        body_lower = body.lower()
        if 'version' in body_lower or 'powered by' in body_lower:
            for pattern, tech in self.VERSION_PATTERNS[:10]:  # Limit checks
                match = re.search(pattern, body, re.I)
                if match:
                    version = match.group(1) if match.lastindex else 'detected'
                    findings.append({
                        'source': 'Page Content',
                        'technology': tech,
                        'version': version,
                        'raw': match.group(0)[:100]
                    })

        return findings

    def _create_result(self, url: str, findings: List[Dict]) -> Dict:
        """Create result from findings"""
        # Deduplicate findings by technology
        unique = {}
        for f in findings:
            key = f['technology']
            if key not in unique or f['version'] != 'disclosed':
                unique[key] = f

        findings = list(unique.values())

        evidence = "**Technology/Version Disclosure Detected**\n\n"

        for finding in findings:
            evidence += f"**{finding['technology']}**\n"
            evidence += f"  Source: {finding['source']}\n"
            evidence += f"  Version: {finding['version']}\n"
            evidence += f"  Raw: `{finding['raw']}`\n\n"

        evidence += "**Risk:** Version information helps attackers:\n"
        evidence += "- Find known vulnerabilities (CVEs)\n"
        evidence += "- Craft targeted exploits\n"
        evidence += "- Fingerprint technology stack\n\n"
        evidence += "**Recommendation:** Suppress version headers and remove generator meta tags."

        # Determine severity based on what was disclosed
        severity = 'low'
        if any(f['technology'] in ['PHP', 'WordPress', 'Drupal', 'Joomla'] for f in findings):
            severity = 'medium'  # CMS versions are more useful to attackers

        result = self.create_result(
            vulnerable=True,
            url=url,
            parameter="HTTP Headers / HTML",
            payload="N/A (passive detection)",
            evidence=evidence,
            description=f"Version disclosed: {', '.join(f['technology'] for f in findings[:3])}",
            confidence=0.95
        )
        result['cwe'] = 'CWE-200'
        result['cwe_name'] = 'Exposure of Sensitive Information to an Unauthorized Actor'
        result['owasp'] = 'A05:2021'
        result['owasp_name'] = 'Security Misconfiguration'
        result['severity'] = severity
        return result


def get_module(module_path: str, payload_limit: int = None):
    return VersionDisclosureModule(module_path, payload_limit=payload_limit)
