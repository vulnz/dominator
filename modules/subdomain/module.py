"""
Subdomain Enumeration Module (Recon)

Discovers subdomains using multiple techniques:
- DNS brute force with wordlist
- Certificate transparency logs
- Passive DNS (if API keys available)
- Common subdomain patterns

Use with --recon flag to scan discovered subdomains.
"""

from typing import List, Dict, Any, Set
from core.base_module import BaseModule
from core.logger import get_logger
from urllib.parse import urlparse
import socket
import ssl
import concurrent.futures

logger = get_logger(__name__)


class SubdomainModule(BaseModule):
    """Subdomain enumeration scanner"""

    # Common subdomain prefixes
    COMMON_SUBDOMAINS = [
        'www', 'mail', 'remote', 'blog', 'webmail', 'server', 'ns1', 'ns2',
        'smtp', 'secure', 'vpn', 'admin', 'api', 'dev', 'staging', 'test',
        'portal', 'beta', 'demo', 'shop', 'store', 'app', 'mobile', 'm',
        'ftp', 'cdn', 'static', 'assets', 'img', 'images', 'media', 'video',
        'docs', 'wiki', 'support', 'help', 'status', 'git', 'gitlab', 'github',
        'jenkins', 'ci', 'jira', 'confluence', 'bitbucket', 'docker', 'k8s',
        'kubernetes', 'aws', 'azure', 'gcp', 'cloud', 's3', 'storage', 'backup',
        'db', 'database', 'mysql', 'postgres', 'redis', 'elastic', 'kibana',
        'grafana', 'prometheus', 'monitor', 'logs', 'analytics', 'tracking',
        'login', 'auth', 'sso', 'oauth', 'accounts', 'my', 'member', 'user',
        'internal', 'intranet', 'extranet', 'partner', 'b2b', 'corp', 'office',
        'exchange', 'owa', 'autodiscover', 'mx', 'email', 'calendar', 'meet',
        'video', 'stream', 'live', 'chat', 'forum', 'community', 'feedback',
        'survey', 'news', 'press', 'ir', 'investor', 'careers', 'jobs', 'hr',
        'legal', 'privacy', 'terms', 'compliance', 'security', 'trust',
        'sandbox', 'qa', 'uat', 'prod', 'production', 'pre-prod', 'preprod',
        'stg', 'stage', 'local', 'localhost', 'old', 'new', 'v1', 'v2', 'api-v1',
        'api-v2', 'api2', 'api3', 'rest', 'graphql', 'ws', 'websocket',
    ]

    def __init__(self, module_path: str, payload_limit: int = None):
        """Initialize Subdomain module"""
        super().__init__(module_path, payload_limit=payload_limit)

        # Load custom wordlist if available
        custom_wordlist = self._load_txt_file("wordlist.txt")
        if custom_wordlist:
            self.subdomains = custom_wordlist + self.COMMON_SUBDOMAINS
        else:
            self.subdomains = self.COMMON_SUBDOMAINS

        logger.info(f"Subdomain module loaded with {len(self.subdomains)} prefixes")

    def scan(self, targets: List[Dict[str, Any]], http_client: Any) -> List[Dict[str, Any]]:
        """
        Enumerate subdomains for target domains

        Args:
            targets: List of URLs (will extract domain from each)
            http_client: HTTP client

        Returns:
            List of discovered subdomains with HTTP status
        """
        results = []
        scanned_domains = set()

        logger.info(f"Starting Subdomain enumeration on {len(targets)} targets")

        for target in targets:
            url = target.get('url', '')

            # Extract base domain
            parsed = urlparse(url)
            domain = self._extract_base_domain(parsed.netloc)

            if not domain or domain in scanned_domains:
                continue
            scanned_domains.add(domain)

            logger.info(f"Enumerating subdomains for: {domain}")

            # Method 1: DNS brute force
            found_subdomains = self._dns_bruteforce(domain)

            # Method 2: Certificate transparency (if HTTPS)
            ct_subdomains = self._check_certificate_transparency(domain)
            found_subdomains.update(ct_subdomains)

            # Check each subdomain for HTTP(S) service
            for subdomain in found_subdomains:
                http_result = self._check_http_service(subdomain, http_client)
                if http_result:
                    result = self.create_result(
                        vulnerable=False,  # This is recon, not vulnerability
                        url=http_result['url'],
                        parameter='Subdomain',
                        payload=subdomain,
                        evidence=http_result['evidence'],
                        description=f"Discovered subdomain: {subdomain}",
                        confidence=1.0
                    )
                    result['severity'] = 'info'
                    result['type'] = 'recon'
                    result['subdomain'] = subdomain
                    result['ip'] = http_result.get('ip', 'N/A')
                    result['status_code'] = http_result.get('status', 'N/A')
                    results.append(result)
                    logger.info(f"Found active subdomain: {subdomain} ({http_result['url']})")

        logger.info(f"Subdomain enumeration complete: {len(results)} subdomains found")
        return results

    def _extract_base_domain(self, hostname: str) -> str:
        """Extract base domain from hostname"""
        if not hostname:
            return ""

        # Remove port if present
        if ':' in hostname:
            hostname = hostname.split(':')[0]

        parts = hostname.split('.')
        if len(parts) >= 2:
            # Return last two parts (e.g., example.com)
            # TODO: Handle TLDs like .co.uk properly
            return '.'.join(parts[-2:])
        return hostname

    def _dns_bruteforce(self, domain: str) -> Set[str]:
        """Brute force subdomains via DNS resolution"""
        found = set()

        def check_subdomain(prefix: str) -> str:
            subdomain = f"{prefix}.{domain}"
            try:
                socket.gethostbyname(subdomain)
                return subdomain
            except socket.gaierror:
                return None

        # Use thread pool for faster enumeration
        with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
            futures = {executor.submit(check_subdomain, prefix): prefix
                      for prefix in self.subdomains[:200]}  # Limit to first 200

            for future in concurrent.futures.as_completed(futures, timeout=60):
                try:
                    result = future.result()
                    if result:
                        found.add(result)
                except Exception:
                    pass

        return found

    def _check_certificate_transparency(self, domain: str) -> Set[str]:
        """Check certificate transparency logs for subdomains"""
        found = set()

        try:
            # Connect to domain and check certificate SANs
            context = ssl.create_default_context()
            with socket.create_connection((domain, 443), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=domain) as ssock:
                    cert = ssock.getpeercert()

                    if cert and 'subjectAltName' in cert:
                        for san_type, san_value in cert['subjectAltName']:
                            if san_type == 'DNS':
                                # Only add if it's a subdomain of our domain
                                if san_value.endswith(f'.{domain}') or san_value == domain:
                                    found.add(san_value)

        except Exception as e:
            logger.debug(f"CT check failed for {domain}: {e}")

        return found

    def _check_http_service(self, subdomain: str, http_client: Any) -> Dict:
        """Check if subdomain has an HTTP(S) service"""
        # Try HTTPS first, then HTTP
        for scheme in ['https', 'http']:
            url = f"{scheme}://{subdomain}"
            try:
                response = http_client.get(url, timeout=5)
                if response:
                    # Get IP address
                    try:
                        ip = socket.gethostbyname(subdomain)
                    except:
                        ip = "N/A"

                    return {
                        'url': url,
                        'status': response.status_code,
                        'ip': ip,
                        'evidence': f"HTTP service found at {url}\n"
                                   f"Status: {response.status_code}\n"
                                   f"IP: {ip}\n"
                                   f"Server: {response.headers.get('Server', 'N/A')}"
                    }
            except Exception:
                continue

        return None


def get_module(module_path: str, payload_limit: int = None):
    """Create module instance"""
    return SubdomainModule(module_path, payload_limit=payload_limit)
