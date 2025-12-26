"""
Subresource Integrity (SRI) Check Passive Detector

Checks for missing Subresource Integrity attributes on external resources.

Detects:
- External scripts without integrity attribute
- External stylesheets without integrity attribute
- Mixed security (SRI on some resources but not others)

Security implications:
- Missing SRI allows CDN compromise to affect your site
- Supply chain attacks via compromised third-party resources
"""

import re
from typing import Dict, List, Tuple, Any, Set
from urllib.parse import urlparse


class SRIChecker:
    """
    Subresource Integrity Checker

    Identifies external resources missing SRI protection.
    """

    # Script tag pattern
    SCRIPT_PATTERN = re.compile(
        r'<script[^>]*\ssrc=["\']([^"\']+)["\'][^>]*>',
        re.IGNORECASE | re.DOTALL
    )

    # Link/stylesheet pattern
    LINK_PATTERN = re.compile(
        r'<link[^>]*\shref=["\']([^"\']+)["\'][^>]*>',
        re.IGNORECASE | re.DOTALL
    )

    # Integrity attribute pattern
    INTEGRITY_PATTERN = re.compile(r'\sintegrity=["\']([^"\']+)["\']', re.IGNORECASE)

    # Crossorigin attribute pattern
    CROSSORIGIN_PATTERN = re.compile(r'\scrossorigin(?:=["\']([^"\']*)["\'])?', re.IGNORECASE)

    # Common CDN domains that should have SRI
    CDN_DOMAINS = {
        'cdnjs.cloudflare.com', 'cdn.jsdelivr.net', 'unpkg.com',
        'code.jquery.com', 'stackpath.bootstrapcdn.com', 'maxcdn.bootstrapcdn.com',
        'ajax.googleapis.com', 'ajax.aspnetcdn.com', 'cdn.bootcdn.net',
        'cdnjs.com', 'rawcdn.githack.com', 'gitcdn.xyz', 'cdn.rawgit.com',
        'fonts.googleapis.com', 'use.fontawesome.com', 'kit.fontawesome.com',
    }

    @classmethod
    def detect(cls, response_text: str, url: str, headers: Dict[str, str] = None) -> Tuple[bool, List[Dict[str, Any]]]:
        """
        Check for missing SRI on external resources.

        Args:
            response_text: HTTP response body
            url: URL being analyzed
            headers: HTTP response headers

        Returns:
            Tuple of (found_issues, list_of_findings)
        """
        findings = []

        if not response_text:
            return False, findings

        # Get page domain
        try:
            parsed = urlparse(url)
            page_domain = parsed.netloc.lower()
        except Exception:
            page_domain = ''

        # Check scripts
        script_findings = cls._check_scripts(response_text, page_domain, url)
        findings.extend(script_findings)

        # Check stylesheets
        style_findings = cls._check_stylesheets(response_text, page_domain, url)
        findings.extend(style_findings)

        # Add summary finding if issues found
        missing_sri_count = len([f for f in findings if 'Missing SRI' in f['type']])
        if missing_sri_count > 0:
            # Determine severity based on CDN usage
            cdn_issues = [f for f in findings if f.get('is_cdn', False)]
            severity = 'Medium' if cdn_issues else 'Low'

            findings.insert(0, {
                'type': 'SRI Summary',
                'severity': severity,
                'url': url,
                'missing_count': missing_sri_count,
                'cdn_without_sri': len(cdn_issues),
                'description': f'{missing_sri_count} external resources missing SRI '
                              f'({len(cdn_issues)} from CDN domains)',
                'category': 'sri_summary',
                'location': 'Response Body',
                'recommendation': 'Add integrity attributes to all external scripts and stylesheets. '
                                 'Generate SRI hashes using https://www.srihash.org/'
            })

        return len(findings) > 0, findings

    @classmethod
    def _check_scripts(cls, html: str, page_domain: str, url: str) -> List[Dict[str, Any]]:
        """Check script tags for SRI"""
        findings = []

        # Find all script tags with src
        for match in re.finditer(r'<script([^>]*)>', html, re.IGNORECASE | re.DOTALL):
            tag_attrs = match.group(1)

            # Skip if no src attribute
            src_match = re.search(r'\ssrc=["\']([^"\']+)["\']', tag_attrs, re.IGNORECASE)
            if not src_match:
                continue

            src = src_match.group(1)

            # Determine if external
            is_external, resource_domain = cls._is_external_resource(src, page_domain)
            if not is_external:
                continue

            # Check for integrity attribute
            has_integrity = cls.INTEGRITY_PATTERN.search(tag_attrs) is not None
            has_crossorigin = cls.CROSSORIGIN_PATTERN.search(tag_attrs) is not None

            # Check if CDN
            is_cdn = any(cdn in resource_domain for cdn in cls.CDN_DOMAINS)

            if not has_integrity:
                severity = 'Medium' if is_cdn else 'Low'

                findings.append({
                    'type': 'Missing SRI on External Script',
                    'severity': severity,
                    'url': url,
                    'resource': src,
                    'resource_domain': resource_domain,
                    'is_cdn': is_cdn,
                    'has_crossorigin': has_crossorigin,
                    'description': f'External script from {resource_domain} lacks integrity attribute',
                    'category': 'missing_sri_script',
                    'location': 'Script Tag',
                    'recommendation': f'Add integrity and crossorigin attributes: '
                                     f'<script src="{src}" integrity="sha384-..." crossorigin="anonymous">'
                })

            # Warn if integrity without crossorigin
            elif has_integrity and not has_crossorigin:
                findings.append({
                    'type': 'SRI Without Crossorigin',
                    'severity': 'Info',
                    'url': url,
                    'resource': src,
                    'description': 'Script has integrity but missing crossorigin attribute. '
                                  'SRI may not work correctly for CORS resources.',
                    'category': 'sri_no_crossorigin',
                    'location': 'Script Tag',
                    'recommendation': 'Add crossorigin="anonymous" attribute alongside integrity.'
                })

        return findings

    @classmethod
    def _check_stylesheets(cls, html: str, page_domain: str, url: str) -> List[Dict[str, Any]]:
        """Check link tags for SRI on stylesheets"""
        findings = []

        # Find all link tags
        for match in re.finditer(r'<link([^>]*)/?>', html, re.IGNORECASE | re.DOTALL):
            tag_attrs = match.group(1)

            # Check if stylesheet
            if 'stylesheet' not in tag_attrs.lower():
                continue

            # Get href
            href_match = re.search(r'\shref=["\']([^"\']+)["\']', tag_attrs, re.IGNORECASE)
            if not href_match:
                continue

            href = href_match.group(1)

            # Determine if external
            is_external, resource_domain = cls._is_external_resource(href, page_domain)
            if not is_external:
                continue

            # Check for integrity attribute
            has_integrity = cls.INTEGRITY_PATTERN.search(tag_attrs) is not None
            has_crossorigin = cls.CROSSORIGIN_PATTERN.search(tag_attrs) is not None

            # Check if CDN
            is_cdn = any(cdn in resource_domain for cdn in cls.CDN_DOMAINS)

            if not has_integrity:
                severity = 'Medium' if is_cdn else 'Low'

                findings.append({
                    'type': 'Missing SRI on External Stylesheet',
                    'severity': severity,
                    'url': url,
                    'resource': href,
                    'resource_domain': resource_domain,
                    'is_cdn': is_cdn,
                    'has_crossorigin': has_crossorigin,
                    'description': f'External stylesheet from {resource_domain} lacks integrity attribute',
                    'category': 'missing_sri_stylesheet',
                    'location': 'Link Tag',
                    'recommendation': f'Add integrity and crossorigin attributes: '
                                     f'<link rel="stylesheet" href="{href}" integrity="sha384-..." crossorigin="anonymous">'
                })

        return findings

    @classmethod
    def _is_external_resource(cls, resource_url: str, page_domain: str) -> Tuple[bool, str]:
        """
        Check if resource is external (different domain).

        Returns:
            Tuple of (is_external, resource_domain)
        """
        # Skip data URIs and relative paths without protocol
        if resource_url.startswith('data:') or resource_url.startswith('#'):
            return False, ''

        # Parse resource URL
        if resource_url.startswith('//'):
            resource_url = 'https:' + resource_url
        elif not resource_url.startswith(('http://', 'https://')):
            # Relative URL - same domain
            return False, page_domain

        try:
            parsed = urlparse(resource_url)
            resource_domain = parsed.netloc.lower()

            # Check if same domain
            if resource_domain == page_domain:
                return False, resource_domain

            # Check if subdomain of page domain
            if resource_domain.endswith('.' + page_domain):
                return False, resource_domain

            return True, resource_domain

        except Exception:
            return False, ''


def check_sri(response_text: str, url: str, headers: Dict[str, str] = None) -> Tuple[bool, List[Dict[str, Any]]]:
    """Convenience function for SRI checking"""
    return SRIChecker.detect(response_text, url, headers)
