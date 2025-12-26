"""
Subdomain Takeover Detection Module

Detects vulnerable subdomains that can potentially be taken over due to:
- Dangling DNS records pointing to unclaimed cloud services
- Expired/deleted cloud resources (S3, Azure, GitHub Pages, Heroku, etc.)
- Misconfigured CNAME records

Checks for common takeover signatures from major cloud providers.
"""

from typing import List, Dict, Any, Set
from core.base_module import BaseModule
from core.logger import get_logger
from urllib.parse import urlparse
import socket
import concurrent.futures

logger = get_logger(__name__)


class SubdomainTakeoverModule(BaseModule):
    """Subdomain takeover vulnerability scanner"""

    # Fingerprints for detecting vulnerable services
    # Format: (service_name, cname_patterns, response_patterns, is_edge_case)
    TAKEOVER_FINGERPRINTS = {
        # AWS Services
        'aws_s3': {
            'cnames': ['s3.amazonaws.com', '.s3.', 's3-website'],
            'response_patterns': [
                'NoSuchBucket',
                'The specified bucket does not exist',
            ],
            'severity': 'High',
            'takeover_possible': True,
        },
        'aws_elastic_beanstalk': {
            'cnames': ['elasticbeanstalk.com'],
            'response_patterns': [],
            'nxdomain': True,
            'severity': 'High',
            'takeover_possible': True,
        },
        'aws_cloudfront': {
            'cnames': ['cloudfront.net'],
            'response_patterns': [
                'The request could not be satisfied',
                "ERROR: The request could not be satisfied",
                'Bad request',
            ],
            'severity': 'Medium',
            'takeover_possible': False,  # Usually not takeover-able
        },

        # Azure Services
        'azure_blob': {
            'cnames': ['blob.core.windows.net'],
            'response_patterns': [
                'BlobNotFound',
                'The specified container does not exist',
                'ResourceNotFound',
            ],
            'severity': 'High',
            'takeover_possible': True,
        },
        'azure_websites': {
            'cnames': ['azurewebsites.net', 'azure-api.net'],
            'response_patterns': [],
            'nxdomain': True,
            'severity': 'High',
            'takeover_possible': True,
        },
        'azure_cloudapp': {
            'cnames': ['cloudapp.net', 'cloudapp.azure.com'],
            'response_patterns': [],
            'nxdomain': True,
            'severity': 'High',
            'takeover_possible': True,
        },
        'azure_trafficmanager': {
            'cnames': ['trafficmanager.net'],
            'response_patterns': [],
            'nxdomain': True,
            'severity': 'High',
            'takeover_possible': True,
        },

        # GitHub
        'github_pages': {
            'cnames': ['github.io', 'githubusercontent.com'],
            'response_patterns': [
                "There isn't a GitHub Pages site here",
                'For root URLs (like http://example.com/) you must provide an index.html file',
            ],
            'severity': 'High',
            'takeover_possible': True,
        },

        # Heroku
        'heroku': {
            'cnames': ['herokuapp.com', 'herokussl.com', 'herokudns.com'],
            'response_patterns': [
                'No such app',
                "There's nothing here, yet.",
                'herokucdn.com/error-pages/no-such-app.html',
            ],
            'nxdomain': True,
            'severity': 'High',
            'takeover_possible': True,
        },

        # Shopify
        'shopify': {
            'cnames': ['myshopify.com'],
            'response_patterns': [
                'Sorry, this shop is currently unavailable',
                'Only one step left!',
            ],
            'severity': 'High',
            'takeover_possible': True,
        },

        # Tumblr
        'tumblr': {
            'cnames': ['tumblr.com'],
            'response_patterns': [
                "There's nothing here.",
                "Whatever you were looking for doesn't currently exist",
            ],
            'severity': 'Medium',
            'takeover_possible': True,
        },

        # WordPress.com
        'wordpress': {
            'cnames': ['wordpress.com'],
            'response_patterns': [
                "Do you want to register",
            ],
            'severity': 'Medium',
            'takeover_possible': True,
        },

        # Pantheon
        'pantheon': {
            'cnames': ['pantheonsite.io', 'pantheon.io'],
            'response_patterns': [
                'The gods are wise',
                '404 error unknown site',
            ],
            'severity': 'High',
            'takeover_possible': True,
        },

        # Fastly
        'fastly': {
            'cnames': ['fastly.net', 'fastlylb.net'],
            'response_patterns': [
                'Fastly error: unknown domain',
            ],
            'severity': 'High',
            'takeover_possible': True,
        },

        # Zendesk
        'zendesk': {
            'cnames': ['zendesk.com'],
            'response_patterns': [
                'Help Center Closed',
                'This help center no longer exists',
            ],
            'severity': 'Medium',
            'takeover_possible': True,
        },

        # Surge.sh
        'surge': {
            'cnames': ['surge.sh'],
            'response_patterns': [
                'project not found',
            ],
            'nxdomain': True,
            'severity': 'High',
            'takeover_possible': True,
        },

        # Netlify
        'netlify': {
            'cnames': ['netlify.app', 'netlify.com'],
            'response_patterns': [
                'Not Found - Request ID',
            ],
            'severity': 'Medium',
            'takeover_possible': False,  # Harder to takeover now
        },

        # Vercel (Zeit)
        'vercel': {
            'cnames': ['vercel.app', 'now.sh', 'zeit.co'],
            'response_patterns': [],
            'nxdomain': True,
            'severity': 'Medium',
            'takeover_possible': False,  # Harder to takeover now
        },

        # Unbounce
        'unbounce': {
            'cnames': ['unbouncepages.com'],
            'response_patterns': [
                'The requested URL was not found on this server',
                'The page you are looking for is no longer here',
            ],
            'severity': 'High',
            'takeover_possible': True,
        },

        # HubSpot
        'hubspot': {
            'cnames': ['hubspot.net', 'hs-sites.com'],
            'response_patterns': [],
            'nxdomain': True,
            'severity': 'Medium',
            'takeover_possible': False,
        },

        # Ghost.io
        'ghost': {
            'cnames': ['ghost.io'],
            'response_patterns': [
                'The thing you were looking for is no longer here',
            ],
            'severity': 'High',
            'takeover_possible': True,
        },

        # Cargo
        'cargo': {
            'cnames': ['cargocollective.com'],
            'response_patterns': [
                '404 Not Found',
            ],
            'severity': 'Medium',
            'takeover_possible': True,
        },

        # UserVoice
        'uservoice': {
            'cnames': ['uservoice.com'],
            'response_patterns': [
                'This UserVoice subdomain is currently available',
            ],
            'severity': 'High',
            'takeover_possible': True,
        },

        # Smartling
        'smartling': {
            'cnames': ['smartling.com'],
            'response_patterns': [],
            'nxdomain': True,
            'severity': 'Medium',
            'takeover_possible': True,
        },

        # Bitbucket
        'bitbucket': {
            'cnames': ['bitbucket.io', 'bitbucket.org'],
            'response_patterns': [
                'Repository not found',
            ],
            'severity': 'High',
            'takeover_possible': True,
        },

        # Fly.io
        'flyio': {
            'cnames': ['fly.dev', 'fly.io'],
            'response_patterns': [],
            'nxdomain': True,
            'severity': 'High',
            'takeover_possible': True,
        },

        # Readme.io
        'readme': {
            'cnames': ['readme.io'],
            'response_patterns': [
                'Project doesnt exist',
            ],
            'severity': 'High',
            'takeover_possible': True,
        },

        # Desk.com (Salesforce)
        'desk': {
            'cnames': ['desk.com'],
            'response_patterns': [
                'Sorry, We Couldn\'t Find That Page',
                'Please try again or visit Desk.com',
            ],
            'severity': 'Medium',
            'takeover_possible': True,
        },

        # Tictail (Shopify)
        'tictail': {
            'cnames': ['tictail.com'],
            'response_patterns': [],
            'nxdomain': True,
            'severity': 'Medium',
            'takeover_possible': True,
        },

        # Campaignmonitor
        'campaignmonitor': {
            'cnames': ['createsend.com', 'cmail*.com'],
            'response_patterns': [
                "Trying to access your account?",
                "Double check the URL",
            ],
            'severity': 'Medium',
            'takeover_possible': True,
        },

        # Acquia
        'acquia': {
            'cnames': ['acquia-test.co', 'acquia.com'],
            'response_patterns': [
                'The site you are looking for could not be found',
                'If you are an Acquia Cloud customer',
            ],
            'severity': 'High',
            'takeover_possible': True,
        },

        # Agile CRM
        'agilecrm': {
            'cnames': ['agilecrm.com'],
            'response_patterns': [
                'Sorry, this page is no longer available',
            ],
            'severity': 'Medium',
            'takeover_possible': True,
        },
    }

    def __init__(self, module_path: str, payload_limit: int = None):
        """Initialize Subdomain Takeover module"""
        super().__init__(module_path, payload_limit=payload_limit)
        logger.info(f"Subdomain Takeover module loaded with {len(self.TAKEOVER_FINGERPRINTS)} service fingerprints")

    def scan(self, targets: List[Dict[str, Any]], http_client: Any) -> List[Dict[str, Any]]:
        """
        Scan subdomains for takeover vulnerabilities

        Args:
            targets: List of URLs/subdomains to check
            http_client: HTTP client for requests

        Returns:
            List of takeover vulnerability findings
        """
        results = []
        checked_domains = set()

        logger.info(f"Starting Subdomain Takeover scan on {len(targets)} targets")

        for target in targets:
            url = target.get('url', '')
            parsed = urlparse(url)
            hostname = parsed.netloc.split(':')[0] if parsed.netloc else url

            if not hostname or hostname in checked_domains:
                continue
            checked_domains.add(hostname)

            # Check for takeover vulnerability
            takeover_result = self._check_takeover(hostname, http_client)
            if takeover_result:
                results.append(takeover_result)

        logger.info(f"Subdomain Takeover scan complete: {len(results)} vulnerabilities found")
        return results

    def _check_takeover(self, hostname: str, http_client: Any) -> Dict[str, Any]:
        """Check a single hostname for takeover vulnerability"""

        # Step 1: Get CNAME record
        cname = self._get_cname(hostname)
        if not cname:
            # No CNAME, check for NXDOMAIN on A record
            if self._is_nxdomain(hostname):
                # Dangling record, but need CNAME to determine service
                return None
            return None

        logger.debug(f"  {hostname} -> CNAME: {cname}")

        # Step 2: Check CNAME against fingerprints
        for service_name, fingerprint in self.TAKEOVER_FINGERPRINTS.items():
            cname_match = False
            for pattern in fingerprint['cnames']:
                if pattern.lower() in cname.lower():
                    cname_match = True
                    break

            if not cname_match:
                continue

            # Found matching service, check for vulnerability indicators
            is_vulnerable = False
            evidence_details = []

            # Check if CNAME target is NXDOMAIN
            if fingerprint.get('nxdomain'):
                if self._is_nxdomain(cname.rstrip('.')):
                    is_vulnerable = True
                    evidence_details.append(f"CNAME target {cname} returns NXDOMAIN")

            # Check response patterns
            if fingerprint.get('response_patterns') and not is_vulnerable:
                response = self._fetch_page(hostname, http_client)
                if response:
                    for pattern in fingerprint['response_patterns']:
                        if pattern.lower() in response.lower():
                            is_vulnerable = True
                            evidence_details.append(f"Response contains: '{pattern}'")
                            break

            if is_vulnerable and fingerprint.get('takeover_possible', True):
                return self._create_takeover_finding(
                    hostname=hostname,
                    service=service_name,
                    cname=cname,
                    severity=fingerprint['severity'],
                    evidence=evidence_details
                )

        return None

    def _get_cname(self, hostname: str) -> str:
        """Get CNAME record for hostname"""
        try:
            import dns.resolver
            answers = dns.resolver.resolve(hostname, 'CNAME')
            for rdata in answers:
                return str(rdata.target)
        except ImportError:
            # Fallback without dnspython
            try:
                result = socket.gethostbyname_ex(hostname)
                # Check if there's a canonical name
                if result[0] != hostname:
                    return result[0]
            except:
                pass
        except Exception:
            pass
        return None

    def _is_nxdomain(self, hostname: str) -> bool:
        """Check if hostname returns NXDOMAIN"""
        try:
            socket.gethostbyname(hostname)
            return False
        except socket.gaierror as e:
            # NXDOMAIN or similar
            return True
        except Exception:
            return False

    def _fetch_page(self, hostname: str, http_client: Any) -> str:
        """Fetch page content from hostname"""
        for scheme in ['https', 'http']:
            try:
                url = f"{scheme}://{hostname}"
                response = http_client.get(url, timeout=10)
                if response and hasattr(response, 'text'):
                    return response.text
            except Exception:
                continue
        return None

    def _create_takeover_finding(self, hostname: str, service: str,
                                  cname: str, severity: str,
                                  evidence: List[str]) -> Dict[str, Any]:
        """Create takeover vulnerability finding"""

        evidence_text = f"""
=== SUBDOMAIN TAKEOVER VULNERABILITY ===

Subdomain: {hostname}
CNAME Points To: {cname}
Vulnerable Service: {service.replace('_', ' ').title()}

INDICATORS:
{chr(10).join(f'  - {e}' for e in evidence)}

RISK:
An attacker can claim the unconfigured cloud service and serve
malicious content from this subdomain. This can be used for:
  - Phishing attacks
  - Cookie theft
  - Session hijacking
  - Malware distribution
  - Brand damage

REMEDIATION:
  1. Remove the dangling DNS record pointing to {cname}
  2. OR reclaim the cloud resource before an attacker does
  3. Regularly audit DNS records for orphaned entries
"""

        result = self.create_result(
            vulnerable=True,
            url=f"https://{hostname}",
            parameter='CNAME',
            payload=cname,
            evidence=evidence_text,
            description=f"Subdomain {hostname} is vulnerable to takeover via {service}",
            confidence=0.95
        )

        result['severity'] = severity
        result['type'] = 'Subdomain Takeover'
        result['service'] = service
        result['cname'] = cname
        result['cwe'] = 'CWE-284'
        result['owasp'] = 'A05:2021'
        result['cvss'] = 8.0 if severity == 'High' else 6.0
        result['recommendation'] = f"Remove DNS record for {hostname} or reclaim the {service} resource"

        return result


def get_module(module_path: str, payload_limit: int = None):
    """Create module instance"""
    return SubdomainTakeoverModule(module_path, payload_limit=payload_limit)
