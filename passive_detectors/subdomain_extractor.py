"""
Subdomain Extractor Passive Detector

Passively extracts subdomains from HTTP responses for reconnaissance.

Extracts subdomains from:
- HTML links (href, src attributes)
- JavaScript code (URLs, API endpoints)
- CSS files (@import, url())
- Response headers (Location, Content-Security-Policy, etc.)
- JSON responses
- Comments and inline scripts
"""

import re
from typing import Dict, List, Tuple, Any, Set
from urllib.parse import urlparse


class SubdomainExtractor:
    """
    Subdomain Extractor for Passive Reconnaissance

    Extracts unique subdomains from HTTP traffic for further enumeration.
    """

    # URL patterns in various contexts
    URL_PATTERNS = [
        # Standard URLs
        re.compile(r'https?://([a-zA-Z0-9][-a-zA-Z0-9]*(?:\.[a-zA-Z0-9][-a-zA-Z0-9]*)+)', re.IGNORECASE),
        # src/href attributes
        re.compile(r'(?:src|href|action|data-url|data-src)=["\'](?:https?:)?//([a-zA-Z0-9][-a-zA-Z0-9]*(?:\.[a-zA-Z0-9][-a-zA-Z0-9]*)+)', re.IGNORECASE),
        # JavaScript strings
        re.compile(r'["\']https?://([a-zA-Z0-9][-a-zA-Z0-9]*(?:\.[a-zA-Z0-9][-a-zA-Z0-9]*)+)["\'/]', re.IGNORECASE),
        # CSS url()
        re.compile(r'url\(["\']?https?://([a-zA-Z0-9][-a-zA-Z0-9]*(?:\.[a-zA-Z0-9][-a-zA-Z0-9]*)+)', re.IGNORECASE),
        # @import
        re.compile(r'@import\s+["\']?(?:url\(["\']?)?https?://([a-zA-Z0-9][-a-zA-Z0-9]*(?:\.[a-zA-Z0-9][-a-zA-Z0-9]*)+)', re.IGNORECASE),
    ]

    # Email domain extraction
    EMAIL_PATTERN = re.compile(r'[a-zA-Z0-9._%+-]+@([a-zA-Z0-9][-a-zA-Z0-9]*(?:\.[a-zA-Z0-9][-a-zA-Z0-9]*)+)', re.IGNORECASE)

    # Headers that may contain domains
    DOMAIN_HEADERS = [
        'location', 'content-security-policy', 'content-security-policy-report-only',
        'access-control-allow-origin', 'link', 'x-frame-options', 'referrer-policy',
        'report-to', 'nel', 'set-cookie'
    ]

    # Common CDN/third-party domains to optionally filter
    COMMON_THIRD_PARTY = {
        'google.com', 'googleapis.com', 'gstatic.com', 'googletagmanager.com',
        'google-analytics.com', 'facebook.com', 'facebook.net', 'fbcdn.net',
        'twitter.com', 'twimg.com', 'linkedin.com', 'youtube.com', 'ytimg.com',
        'cloudflare.com', 'cloudfront.net', 'amazonaws.com', 'akamaihd.net',
        'akamai.net', 'jsdelivr.net', 'cdnjs.cloudflare.com', 'bootstrapcdn.com',
        'jquery.com', 'unpkg.com', 'fontawesome.com', 'fonts.googleapis.com',
        'gravatar.com', 'wp.com', 'wordpress.com', 'doubleclick.net',
        'googleadservices.com', 'googlesyndication.com', 'hotjar.com',
        'segment.io', 'segment.com', 'mixpanel.com', 'amplitude.com',
        'sentry.io', 'newrelic.com', 'nr-data.net', 'optimizely.com',
        'intercom.io', 'zendesk.com', 'stripe.com', 'paypal.com',
    }

    @classmethod
    def detect(cls, response_text: str, url: str, headers: Dict[str, str] = None,
               include_third_party: bool = False) -> Tuple[bool, List[Dict[str, Any]]]:
        """
        Extract subdomains from HTTP response.

        Args:
            response_text: HTTP response body
            url: URL being analyzed (used to identify target domain)
            headers: HTTP response headers
            include_third_party: If True, include common third-party domains

        Returns:
            Tuple of (found_subdomains, list_of_findings)
        """
        findings = []
        all_domains: Set[str] = set()

        # Get target domain from URL
        try:
            parsed = urlparse(url)
            target_domain = cls._get_root_domain(parsed.netloc)
        except Exception:
            target_domain = None

        # Extract from response body
        if response_text:
            body_domains = cls._extract_from_text(response_text)
            all_domains.update(body_domains)

        # Extract from headers
        if headers:
            header_domains = cls._extract_from_headers(headers)
            all_domains.update(header_domains)

        # Categorize domains
        target_subdomains: Set[str] = set()
        related_domains: Set[str] = set()
        third_party_domains: Set[str] = set()

        for domain in all_domains:
            domain_lower = domain.lower()
            root = cls._get_root_domain(domain_lower)

            # Skip invalid domains
            if not cls._is_valid_domain(domain_lower):
                continue

            if target_domain and (root == target_domain or domain_lower.endswith('.' + target_domain)):
                target_subdomains.add(domain_lower)
            elif root in cls.COMMON_THIRD_PARTY or any(domain_lower.endswith('.' + tp) for tp in cls.COMMON_THIRD_PARTY):
                if include_third_party:
                    third_party_domains.add(domain_lower)
            else:
                related_domains.add(domain_lower)

        # Create findings for target subdomains
        if target_subdomains:
            findings.append({
                'type': 'Subdomains Discovered',
                'severity': 'Info',
                'url': url,
                'target_domain': target_domain,
                'subdomains': sorted(target_subdomains),
                'count': len(target_subdomains),
                'description': f'Discovered {len(target_subdomains)} subdomains of {target_domain}',
                'category': 'subdomain_discovery',
                'location': 'Response Body/Headers',
                'recommendation': 'Use discovered subdomains for further enumeration and testing.'
            })

        # Create findings for related domains (potentially interesting)
        if related_domains:
            findings.append({
                'type': 'Related Domains Discovered',
                'severity': 'Info',
                'url': url,
                'domains': sorted(related_domains),
                'count': len(related_domains),
                'description': f'Discovered {len(related_domains)} related domains (non-CDN)',
                'category': 'related_domains',
                'location': 'Response Body/Headers',
                'recommendation': 'Review related domains for potential scope expansion.'
            })

        # Optionally include third-party
        if include_third_party and third_party_domains:
            findings.append({
                'type': 'Third-Party Services',
                'severity': 'Info',
                'url': url,
                'domains': sorted(third_party_domains),
                'count': len(third_party_domains),
                'description': f'Detected {len(third_party_domains)} third-party service domains',
                'category': 'third_party_services',
                'location': 'Response Body/Headers',
                'recommendation': 'Review third-party dependencies for supply chain risks.'
            })

        return len(findings) > 0, findings

    @classmethod
    def _extract_from_text(cls, text: str) -> Set[str]:
        """Extract domains from text content"""
        domains = set()

        for pattern in cls.URL_PATTERNS:
            matches = pattern.findall(text)
            for match in matches:
                # Clean domain
                domain = match.lower().strip('.')
                if domain:
                    domains.add(domain)

        # Extract from email addresses
        email_matches = cls.EMAIL_PATTERN.findall(text)
        for domain in email_matches:
            domain = domain.lower().strip('.')
            if domain:
                domains.add(domain)

        return domains

    @classmethod
    def _extract_from_headers(cls, headers: Dict[str, str]) -> Set[str]:
        """Extract domains from HTTP headers"""
        domains = set()

        for header_name in cls.DOMAIN_HEADERS:
            for key, value in headers.items():
                if key.lower() == header_name:
                    # Extract domains from header value
                    for pattern in cls.URL_PATTERNS:
                        matches = pattern.findall(value)
                        domains.update(m.lower() for m in matches)

                    # Special handling for CSP
                    if 'security-policy' in key.lower():
                        csp_domains = cls._parse_csp_domains(value)
                        domains.update(csp_domains)

        return domains

    @classmethod
    def _parse_csp_domains(cls, csp: str) -> Set[str]:
        """Parse domains from Content-Security-Policy header"""
        domains = set()

        # CSP directives that contain URLs/domains
        directives = csp.split(';')
        for directive in directives:
            parts = directive.strip().split()
            for part in parts:
                # Skip CSP keywords
                if part.startswith("'") or part in ['self', 'unsafe-inline', 'unsafe-eval', 'none']:
                    continue

                # Extract domain from URL or domain pattern
                if '://' in part:
                    match = re.match(r'https?://([^/]+)', part)
                    if match:
                        domains.add(match.group(1).lower())
                elif '.' in part and not part.startswith('data:'):
                    # Direct domain reference
                    domain = part.lstrip('*.').lower()
                    if cls._is_valid_domain(domain):
                        domains.add(domain)

        return domains

    @classmethod
    def _get_root_domain(cls, domain: str) -> str:
        """Extract root domain from subdomain"""
        parts = domain.lower().split('.')

        # Handle common TLDs
        if len(parts) >= 2:
            # Check for country code TLDs with second level (e.g., .co.uk, .com.au)
            if len(parts) >= 3 and parts[-2] in ['co', 'com', 'org', 'net', 'gov', 'edu', 'ac']:
                return '.'.join(parts[-3:])
            return '.'.join(parts[-2:])

        return domain

    @classmethod
    def _is_valid_domain(cls, domain: str) -> bool:
        """Check if domain is valid"""
        if not domain or len(domain) < 4:
            return False

        # Must have at least one dot
        if '.' not in domain:
            return False

        # Check for valid characters
        if not re.match(r'^[a-zA-Z0-9][-a-zA-Z0-9.]*[a-zA-Z0-9]$', domain):
            return False

        # Check TLD
        tld = domain.split('.')[-1]
        if len(tld) < 2 or not tld.isalpha():
            return False

        # Filter out IP addresses
        if re.match(r'^\d+\.\d+\.\d+\.\d+$', domain):
            return False

        return True


def extract_subdomains(response_text: str, url: str, headers: Dict[str, str] = None,
                       include_third_party: bool = False) -> Tuple[bool, List[Dict[str, Any]]]:
    """Convenience function for subdomain extraction"""
    return SubdomainExtractor.detect(response_text, url, headers, include_third_party)
