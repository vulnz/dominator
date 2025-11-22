"""
Security Headers Scanner Module (DrHeader-style)

Analyzes HTTP security headers like:
- Content-Security-Policy (CSP)
- X-Frame-Options
- X-Content-Type-Options
- X-XSS-Protection
- Strict-Transport-Security (HSTS)
- Referrer-Policy
- Permissions-Policy

Based on OWASP Secure Headers Project recommendations.
"""

from typing import List, Dict, Any
from core.base_module import BaseModule
from core.logger import get_logger

logger = get_logger(__name__)


class SecurityHeadersModule(BaseModule):
    """HTTP Security Headers analyzer"""

    # Security header requirements (based on OWASP recommendations)
    REQUIRED_HEADERS = {
        'Strict-Transport-Security': {
            'severity': 'high',
            'description': 'HSTS not set - vulnerable to SSL stripping attacks',
            'recommendation': 'Set Strict-Transport-Security: max-age=31536000; includeSubDomains',
            'cwe': 'CWE-319',
            'min_max_age': 31536000,
        },
        'X-Frame-Options': {
            'severity': 'medium',
            'description': 'X-Frame-Options not set - vulnerable to clickjacking',
            'recommendation': 'Set X-Frame-Options: DENY or SAMEORIGIN',
            'cwe': 'CWE-1021',
            'valid_values': ['DENY', 'SAMEORIGIN'],
        },
        'X-Content-Type-Options': {
            'severity': 'medium',
            'description': 'X-Content-Type-Options not set - vulnerable to MIME sniffing',
            'recommendation': 'Set X-Content-Type-Options: nosniff',
            'cwe': 'CWE-430',
            'valid_values': ['nosniff'],
        },
        'Content-Security-Policy': {
            'severity': 'high',
            'description': 'CSP not set - increased XSS attack surface',
            'recommendation': "Set Content-Security-Policy with strict directives",
            'cwe': 'CWE-79',
        },
        'Referrer-Policy': {
            'severity': 'low',
            'description': 'Referrer-Policy not set - may leak sensitive URL data',
            'recommendation': 'Set Referrer-Policy: strict-origin-when-cross-origin',
            'cwe': 'CWE-200',
        },
        'Permissions-Policy': {
            'severity': 'low',
            'description': 'Permissions-Policy not set - browser features not restricted',
            'recommendation': 'Set Permissions-Policy to restrict browser features',
            'cwe': 'CWE-16',
        },
    }

    # Dangerous headers that should NOT be present
    DANGEROUS_HEADERS = {
        'X-Powered-By': {
            'severity': 'low',
            'description': 'Server technology disclosed',
            'recommendation': 'Remove X-Powered-By header',
            'cwe': 'CWE-200',
        },
        'Server': {
            'severity': 'low',
            'description': 'Server version disclosed',
            'recommendation': 'Remove or obfuscate Server header',
            'cwe': 'CWE-200',
            'check_version': True,  # Only flag if version is included
        },
        'X-AspNet-Version': {
            'severity': 'medium',
            'description': 'ASP.NET version disclosed',
            'recommendation': 'Remove X-AspNet-Version header',
            'cwe': 'CWE-200',
        },
        'X-AspNetMvc-Version': {
            'severity': 'medium',
            'description': 'ASP.NET MVC version disclosed',
            'recommendation': 'Remove X-AspNetMvc-Version header',
            'cwe': 'CWE-200',
        },
    }

    # CSP directive analysis
    UNSAFE_CSP_DIRECTIVES = [
        "'unsafe-inline'",
        "'unsafe-eval'",
        "data:",
        "*",
    ]

    def __init__(self, module_path: str, payload_limit: int = None):
        """Initialize Security Headers module"""
        super().__init__(module_path, payload_limit=payload_limit)
        logger.info("Security Headers module loaded")

    def scan(self, targets: List[Dict[str, Any]], http_client: Any) -> List[Dict[str, Any]]:
        """
        Scan targets for security header issues

        Args:
            targets: List of URLs to scan
            http_client: HTTP client

        Returns:
            List of security header findings
        """
        results = []
        scanned_hosts = set()

        logger.info(f"Starting Security Headers scan on {len(targets)} targets")

        for target in targets:
            url = target.get('url', '')

            # Extract host to avoid duplicate scans
            from urllib.parse import urlparse
            parsed = urlparse(url)
            host = parsed.netloc

            if host in scanned_hosts:
                continue
            scanned_hosts.add(host)

            # Make request to get headers
            try:
                response = http_client.get(url)
                if not response:
                    continue

                headers = dict(response.headers)

                # Check for missing required headers
                missing_results = self._check_missing_headers(url, headers)
                results.extend(missing_results)

                # Check for dangerous headers
                dangerous_results = self._check_dangerous_headers(url, headers)
                results.extend(dangerous_results)

                # Analyze CSP if present
                csp_results = self._analyze_csp(url, headers)
                results.extend(csp_results)

                # Analyze HSTS if present
                hsts_results = self._analyze_hsts(url, headers)
                results.extend(hsts_results)

            except Exception as e:
                logger.debug(f"Error scanning {url}: {e}")

        logger.info(f"Security Headers scan complete: {len(results)} issues found")
        return results

    def _check_missing_headers(self, url: str, headers: Dict) -> List[Dict]:
        """Check for missing required security headers - CONSOLIDATED into single finding"""
        headers_lower = {k.lower(): v for k, v in headers.items()}

        # Collect all missing headers
        missing_high = []
        missing_medium = []
        missing_low = []

        for header_name, config in self.REQUIRED_HEADERS.items():
            if header_name.lower() not in headers_lower:
                severity = config['severity']
                if severity == 'high':
                    missing_high.append(header_name)
                elif severity == 'medium':
                    missing_medium.append(header_name)
                else:
                    missing_low.append(header_name)

        results = []

        # Create ONE finding for high severity missing headers
        if missing_high:
            result = self.create_result(
                vulnerable=True,
                url=url,
                parameter='HTTP Headers',
                payload=f"Missing: {', '.join(missing_high)}",
                evidence=f"Critical security headers missing:\n" +
                         "\n".join([f"  - {h}: {self.REQUIRED_HEADERS[h]['description']}" for h in missing_high]),
                description=f"{len(missing_high)} critical security headers missing: {', '.join(missing_high)}",
                confidence=0.95
            )
            result['cwe'] = 'CWE-693'
            result['severity'] = 'high'
            result['recommendation'] = '\n'.join([f"{h}: {self.REQUIRED_HEADERS[h]['recommendation']}" for h in missing_high])
            result['owasp'] = 'A05:2021'
            results.append(result)

        # Create ONE finding for medium severity missing headers
        if missing_medium:
            result = self.create_result(
                vulnerable=True,
                url=url,
                parameter='HTTP Headers',
                payload=f"Missing: {', '.join(missing_medium)}",
                evidence=f"Important security headers missing:\n" +
                         "\n".join([f"  - {h}: {self.REQUIRED_HEADERS[h]['description']}" for h in missing_medium]),
                description=f"{len(missing_medium)} security headers missing: {', '.join(missing_medium)}",
                confidence=0.95
            )
            result['cwe'] = 'CWE-693'
            result['severity'] = 'medium'
            result['recommendation'] = '\n'.join([f"{h}: {self.REQUIRED_HEADERS[h]['recommendation']}" for h in missing_medium])
            result['owasp'] = 'A05:2021'
            results.append(result)

        # Create ONE finding for low severity missing headers (informational)
        if missing_low:
            result = self.create_result(
                vulnerable=True,
                url=url,
                parameter='HTTP Headers',
                payload=f"Missing: {', '.join(missing_low)}",
                evidence=f"Optional security headers missing:\n" +
                         "\n".join([f"  - {h}: {self.REQUIRED_HEADERS[h]['description']}" for h in missing_low]),
                description=f"{len(missing_low)} optional security headers missing: {', '.join(missing_low)}",
                confidence=0.90
            )
            result['cwe'] = 'CWE-693'
            result['severity'] = 'low'
            result['recommendation'] = '\n'.join([f"{h}: {self.REQUIRED_HEADERS[h]['recommendation']}" for h in missing_low])
            result['owasp'] = 'A05:2021'
            results.append(result)

        return results

    def _check_dangerous_headers(self, url: str, headers: Dict) -> List[Dict]:
        """Check for dangerous/information disclosure headers - CONSOLIDATED"""
        headers_lower = {k.lower(): v for k, v in headers.items()}

        # Collect all dangerous headers found
        found_dangerous = []
        import re

        for header_name, config in self.DANGEROUS_HEADERS.items():
            header_key = header_name.lower()
            if header_key in headers_lower:
                value = headers_lower[header_key]

                # For Server header, only flag if version is included
                if config.get('check_version') and header_key == 'server':
                    if not re.search(r'\d+\.', value):
                        continue

                found_dangerous.append((header_name, value))

        results = []
        if found_dangerous:
            result = self.create_result(
                vulnerable=True,
                url=url,
                parameter='HTTP Headers',
                payload=', '.join([h[0] for h in found_dangerous]),
                evidence=f"Information disclosure headers found:\n" +
                         "\n".join([f"  - {h}: {v}" for h, v in found_dangerous]),
                description=f"{len(found_dangerous)} information disclosure headers present",
                confidence=0.90
            )
            result['cwe'] = 'CWE-200'
            result['severity'] = 'low'
            result['recommendation'] = 'Remove or obfuscate these headers: ' + ', '.join([h[0] for h in found_dangerous])
            result['owasp'] = 'A05:2021'
            results.append(result)

        return results

    def _analyze_csp(self, url: str, headers: Dict) -> List[Dict]:
        """Analyze Content-Security-Policy for weaknesses - CONSOLIDATED"""
        results = []
        headers_lower = {k.lower(): v for k, v in headers.items()}

        csp = headers_lower.get('content-security-policy', '')
        if not csp:
            return results

        # Collect all unsafe directives found
        found_unsafe = []
        for unsafe in self.UNSAFE_CSP_DIRECTIVES:
            if unsafe in csp:
                found_unsafe.append(unsafe)

        if found_unsafe:
            descriptions = []
            for unsafe in found_unsafe:
                if unsafe == "'unsafe-inline'":
                    descriptions.append("unsafe-inline weakens XSS protection")
                elif unsafe == "'unsafe-eval'":
                    descriptions.append("unsafe-eval allows code injection")
                elif unsafe == "data:":
                    descriptions.append("data: URLs are potential XSS vectors")
                else:
                    descriptions.append("wildcard (*) is overly permissive")

            result = self.create_result(
                vulnerable=True,
                url=url,
                parameter='Content-Security-Policy',
                payload=f"Unsafe: {', '.join(found_unsafe)}",
                evidence=f"CSP contains {len(found_unsafe)} unsafe directives:\n" +
                         "\n".join([f"  - {u}" for u in found_unsafe]) +
                         f"\n\nFull CSP: {csp[:300]}...",
                description=f"Weak CSP: {'; '.join(descriptions)}",
                confidence=0.90
            )
            result['cwe'] = 'CWE-79'
            result['severity'] = 'high' if any(u in ["'unsafe-inline'", "'unsafe-eval'"] for u in found_unsafe) else 'medium'
            result['owasp'] = 'A05:2021'
            results.append(result)

        return results

    def _analyze_hsts(self, url: str, headers: Dict) -> List[Dict]:
        """Analyze HSTS header for weaknesses - CONSOLIDATED"""
        results = []
        headers_lower = {k.lower(): v for k, v in headers.items()}

        hsts = headers_lower.get('strict-transport-security', '')
        if not hsts:
            return results

        # Collect all HSTS issues
        issues = []
        import re

        max_age_match = re.search(r'max-age=(\d+)', hsts)
        if max_age_match:
            max_age = int(max_age_match.group(1))
            if max_age < 31536000:  # Less than 1 year
                issues.append(f"max-age too short ({max_age}s, recommend 31536000)")

        if 'includesubdomains' not in hsts.lower():
            issues.append("missing includeSubDomains directive")

        if issues:
            result = self.create_result(
                vulnerable=True,
                url=url,
                parameter='Strict-Transport-Security',
                payload=f"{len(issues)} issues",
                evidence=f"HSTS configuration issues:\n" +
                         "\n".join([f"  - {i}" for i in issues]) +
                         f"\n\nCurrent: {hsts}",
                description=f"Weak HSTS configuration: {'; '.join(issues)}",
                confidence=0.80
            )
            result['cwe'] = 'CWE-319'
            result['severity'] = 'low'
            result['owasp'] = 'A05:2021'
            results.append(result)

        return results


def get_module(module_path: str, payload_limit: int = None):
    """Create module instance"""
    return SecurityHeadersModule(module_path, payload_limit=payload_limit)
