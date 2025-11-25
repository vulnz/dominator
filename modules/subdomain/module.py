"""
Subdomain Enumeration Module (Enhanced Recon)

Discovers subdomains using multiple techniques:
- DNS brute force with wordlist
- Certificate Transparency (crt.sh API)
- SSL Certificate SANs extraction
- DNS Zone Transfer (AXFR)
- DNS Record enumeration (MX, NS, TXT, SOA)
- Reverse DNS lookups

Use with --recon flag to scan discovered subdomains.
"""

from typing import List, Dict, Any, Set
from core.base_module import BaseModule
from core.logger import get_logger
from urllib.parse import urlparse
import socket
import ssl
import concurrent.futures
import json
import ipaddress
import re

logger = get_logger(__name__)

# Local/private hostnames and IP ranges that don't make sense for subdomain enumeration
LOCAL_HOSTNAMES = {'localhost', 'localhost.localdomain', 'local', 'host.docker.internal'}
PRIVATE_IP_PATTERNS = [
    r'^127\.',           # 127.0.0.0/8 loopback
    r'^10\.',            # 10.0.0.0/8 private
    r'^172\.(1[6-9]|2[0-9]|3[0-1])\.', # 172.16.0.0/12 private
    r'^192\.168\.',      # 192.168.0.0/16 private
    r'^169\.254\.',      # 169.254.0.0/16 link-local
    r'^0\.',             # 0.0.0.0/8
    r'^::1$',            # IPv6 loopback
    r'^fe80:',           # IPv6 link-local
    r'^fc[0-9a-f]{2}:',  # IPv6 unique local
    r'^fd[0-9a-f]{2}:',  # IPv6 unique local
]


class SubdomainModule(BaseModule):
    """Enhanced subdomain enumeration scanner"""

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
    ]

    def __init__(self, module_path: str, payload_limit: int = None):
        """Initialize Subdomain module"""
        super().__init__(module_path, payload_limit=payload_limit)

        # Load custom wordlist if available
        custom_wordlist = self._load_txt_file("wordlist.txt")
        if custom_wordlist:
            self.subdomains = list(set(custom_wordlist + self.COMMON_SUBDOMAINS))
        else:
            self.subdomains = self.COMMON_SUBDOMAINS

        logger.info(f"Subdomain module loaded with {len(self.subdomains)} prefixes")

    def _is_local_or_private(self, host: str) -> bool:
        """
        Check if the host is a local/private address where subdomain enumeration doesn't make sense.

        Returns True for:
        - localhost, 127.x.x.x
        - Private IP ranges (10.x.x.x, 172.16-31.x.x, 192.168.x.x)
        - Link-local addresses
        - IPv6 local addresses
        """
        if not host:
            return True

        # Remove port if present
        host = host.split(':')[0].lower().strip()

        # Check against known local hostnames
        if host in LOCAL_HOSTNAMES:
            return True

        # Check if it looks like an IP address
        try:
            # Try to parse as IP
            ip = ipaddress.ip_address(host)
            return ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved
        except ValueError:
            pass

        # Check against regex patterns for IP-like strings
        for pattern in PRIVATE_IP_PATTERNS:
            if re.match(pattern, host, re.IGNORECASE):
                return True

        # Check if domain doesn't have a proper TLD (like "mycomputer" or "local-server")
        # Domains must have at least one dot and a valid TLD to be worth scanning
        if '.' not in host:
            return True

        # Check for .local, .localdomain, .internal TLDs
        local_tlds = {'.local', '.localdomain', '.internal', '.lan', '.home', '.corp', '.test', '.example', '.invalid', '.localhost'}
        for tld in local_tlds:
            if host.endswith(tld):
                return True

        return False

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

        logger.info(f"Starting enhanced Subdomain enumeration on {len(targets)} targets")

        for target in targets:
            url = target.get('url', '')

            # Extract base domain
            parsed = urlparse(url)
            host = parsed.netloc.split(':')[0]  # Remove port

            # Skip localhost and private IPs - subdomain enumeration makes no sense for these
            if self._is_local_or_private(host):
                logger.info(f"Skipping subdomain enumeration for local/private target: {host}")
                continue

            domain = self._extract_base_domain(parsed.netloc)

            if not domain or domain in scanned_domains:
                continue
            scanned_domains.add(domain)

            logger.info(f"Enumerating subdomains for: {domain}")
            found_subdomains = set()

            # Method 1: Certificate Transparency (crt.sh API) - BEST SOURCE
            logger.info(f"  [1/5] Querying Certificate Transparency logs (crt.sh)...")
            ct_subdomains = self._query_crtsh(domain, http_client)
            found_subdomains.update(ct_subdomains)
            logger.info(f"       Found {len(ct_subdomains)} from crt.sh")

            # Method 2: SSL Certificate SANs from direct connection
            logger.info(f"  [2/5] Extracting SSL certificate SANs...")
            ssl_subdomains = self._extract_ssl_sans(domain)
            found_subdomains.update(ssl_subdomains)
            logger.info(f"       Found {len(ssl_subdomains)} from SSL SANs")

            # Method 3: DNS Zone Transfer (AXFR)
            logger.info(f"  [3/5] Attempting DNS zone transfer (AXFR)...")
            axfr_subdomains = self._attempt_zone_transfer(domain)
            found_subdomains.update(axfr_subdomains)
            if axfr_subdomains:
                logger.info(f"       Zone transfer successful! Found {len(axfr_subdomains)} records")
                # Report zone transfer vulnerability
                results.append(self._create_zone_transfer_finding(domain, axfr_subdomains))

            # Method 4: DNS Record Enumeration (MX, NS, TXT, SOA)
            logger.info(f"  [4/5] Enumerating DNS records (MX, NS, TXT, SOA)...")
            dns_info = self._enumerate_dns_records(domain)
            if dns_info:
                results.append(self._create_dns_info_finding(domain, dns_info))

            # Method 5: DNS brute force
            logger.info(f"  [5/5] DNS brute force ({len(self.subdomains)} prefixes)...")
            brute_subdomains = self._dns_bruteforce(domain)
            found_subdomains.update(brute_subdomains)
            logger.info(f"       Found {len(brute_subdomains)} from brute force")

            # Remove duplicates and validate
            found_subdomains = {s for s in found_subdomains if s and domain in s}
            logger.info(f"  Total unique subdomains: {len(found_subdomains)}")

            # Check each subdomain for HTTP(S) service
            for subdomain in found_subdomains:
                http_result = self._check_http_service(subdomain, http_client)
                if http_result:
                    result = self.create_result(
                        vulnerable=False,
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
                    result['discovery_method'] = http_result.get('method', 'unknown')
                    results.append(result)

        logger.info(f"Subdomain enumeration complete: {len(results)} findings")
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
            return '.'.join(parts[-2:])
        return hostname

    def _query_crtsh(self, domain: str, http_client: Any) -> Set[str]:
        """Query crt.sh Certificate Transparency API"""
        found = set()

        try:
            url = f"https://crt.sh/?q=%.{domain}&output=json"
            response = http_client.get(url, timeout=15)

            if response and response.status_code == 200:
                try:
                    data = response.json()
                    for entry in data:
                        name_value = entry.get('name_value', '')
                        # Split by newlines (crt.sh returns multiple names per entry)
                        for name in name_value.split('\n'):
                            name = name.strip().lower()
                            # Skip wildcards and validate domain
                            if name and not name.startswith('*') and domain in name:
                                found.add(name)
                except json.JSONDecodeError:
                    logger.debug("Failed to parse crt.sh JSON response")

        except Exception as e:
            logger.debug(f"crt.sh query failed for {domain}: {e}")

        return found

    def _extract_ssl_sans(self, domain: str) -> Set[str]:
        """Extract subdomains from SSL certificate SANs"""
        found = set()

        try:
            context = ssl.create_default_context()
            with socket.create_connection((domain, 443), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=domain) as ssock:
                    cert = ssock.getpeercert()

                    if cert and 'subjectAltName' in cert:
                        for san_type, san_value in cert['subjectAltName']:
                            if san_type == 'DNS':
                                san_value = san_value.lower()
                                if domain in san_value and not san_value.startswith('*'):
                                    found.add(san_value)

        except Exception as e:
            logger.debug(f"SSL SAN extraction failed for {domain}: {e}")

        return found

    def _attempt_zone_transfer(self, domain: str) -> Set[str]:
        """Attempt DNS zone transfer (AXFR)"""
        found = set()

        try:
            import dns.resolver
            import dns.zone
            import dns.query

            # Get NS records
            ns_records = dns.resolver.resolve(domain, 'NS')

            for ns in ns_records:
                ns_host = str(ns.target).rstrip('.')
                try:
                    # Attempt zone transfer
                    zone = dns.zone.from_xfr(dns.query.xfr(ns_host, domain, timeout=5))
                    for name, node in zone.nodes.items():
                        subdomain = str(name)
                        if subdomain != '@':
                            found.add(f"{subdomain}.{domain}")
                    logger.warning(f"DNS Zone Transfer SUCCESSFUL from {ns_host}!")
                    break
                except Exception:
                    continue

        except ImportError:
            logger.debug("dnspython not installed, skipping zone transfer")
        except Exception as e:
            logger.debug(f"Zone transfer failed for {domain}: {e}")

        return found

    def _enumerate_dns_records(self, domain: str) -> Dict[str, Any]:
        """Enumerate various DNS record types and extract intelligence"""
        dns_info = {'domain': domain, 'records': {}, 'intelligence': {}}

        try:
            import dns.resolver

            record_types = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'SOA', 'CNAME', 'CAA']

            for rtype in record_types:
                try:
                    answers = dns.resolver.resolve(domain, rtype)
                    records = []
                    for rdata in answers:
                        records.append(str(rdata))
                    if records:
                        dns_info['records'][rtype] = records
                except dns.resolver.NoAnswer:
                    pass
                except dns.resolver.NXDOMAIN:
                    break
                except Exception:
                    pass

            # Extract intelligence from records
            dns_info['intelligence'] = self._extract_dns_intelligence(dns_info['records'], domain)

        except ImportError:
            # Fallback to socket for basic A record
            try:
                ip = socket.gethostbyname(domain)
                dns_info['records']['A'] = [ip]
                dns_info['intelligence'] = self._extract_dns_intelligence({'A': [ip]}, domain)
            except Exception:
                pass

        return dns_info if dns_info['records'] else None

    def _extract_dns_intelligence(self, records: Dict, domain: str) -> Dict[str, Any]:
        """Extract hosting, mail provider, and other intelligence from DNS records"""
        intel = {
            'hosting_provider': None,
            'mail_provider': None,
            'cdn_provider': None,
            'dns_provider': None,
            'security_services': [],
            'technologies': [],
            'spf_record': None,
            'dmarc_record': None,
            'dkim_selectors': [],
            'ca_authorized': [],
        }

        # Hosting provider detection (from A records and CNAMEs)
        hosting_signatures = {
            'amazonaws.com': 'Amazon AWS',
            'cloudfront.net': 'Amazon CloudFront',
            'elasticbeanstalk.com': 'AWS Elastic Beanstalk',
            'azure': 'Microsoft Azure',
            'azurewebsites.net': 'Azure App Service',
            'cloudflare': 'Cloudflare',
            'fastly': 'Fastly CDN',
            'akamai': 'Akamai',
            'googleusercontent.com': 'Google Cloud',
            'appspot.com': 'Google App Engine',
            'herokuapp.com': 'Heroku',
            'netlify': 'Netlify',
            'vercel': 'Vercel',
            'github.io': 'GitHub Pages',
            'digitalocean': 'DigitalOcean',
            'linode': 'Linode',
            'vultr': 'Vultr',
            'ovh': 'OVH',
            'hetzner': 'Hetzner',
            'godaddy': 'GoDaddy',
            'bluehost': 'Bluehost',
            'hostgator': 'HostGator',
            'wpengine': 'WP Engine',
            'squarespace': 'Squarespace',
            'wix': 'Wix',
            'shopify': 'Shopify',
        }

        # Mail provider detection (from MX records)
        mail_signatures = {
            'google.com': 'Google Workspace',
            'googlemail.com': 'Google Workspace',
            'outlook.com': 'Microsoft 365',
            'protection.outlook.com': 'Microsoft 365',
            'pphosted.com': 'Proofpoint',
            'mimecast': 'Mimecast',
            'barracuda': 'Barracuda',
            'messagelabs': 'Symantec Email',
            'mailgun': 'Mailgun',
            'sendgrid': 'SendGrid',
            'mailchimp': 'Mailchimp',
            'zoho': 'Zoho Mail',
            'secureserver.net': 'GoDaddy Email',
            'emailsrvr.com': 'Rackspace Email',
            'yahoodns': 'Yahoo Mail',
            'protonmail': 'ProtonMail',
            'fastmail': 'Fastmail',
        }

        # DNS provider detection (from NS records)
        dns_signatures = {
            'cloudflare.com': 'Cloudflare DNS',
            'awsdns': 'Amazon Route 53',
            'azure-dns': 'Azure DNS',
            'googledomains': 'Google Domains',
            'dns.google': 'Google Cloud DNS',
            'domaincontrol.com': 'GoDaddy DNS',
            'nsone.net': 'NS1',
            'ultradns': 'Neustar UltraDNS',
            'dnsmadeeasy': 'DNS Made Easy',
            'dnsimple': 'DNSimple',
        }

        # Check CNAME records for hosting/CDN
        for record in records.get('CNAME', []):
            record_lower = record.lower()
            for sig, provider in hosting_signatures.items():
                if sig in record_lower:
                    if 'cdn' in sig or 'cloudfront' in sig or 'fastly' in sig or 'akamai' in sig:
                        intel['cdn_provider'] = provider
                    else:
                        intel['hosting_provider'] = provider
                    break

        # Check MX records for mail provider
        for record in records.get('MX', []):
            record_lower = record.lower()
            for sig, provider in mail_signatures.items():
                if sig in record_lower:
                    intel['mail_provider'] = provider
                    break

        # Check NS records for DNS provider
        for record in records.get('NS', []):
            record_lower = record.lower()
            for sig, provider in dns_signatures.items():
                if sig in record_lower:
                    intel['dns_provider'] = provider
                    break

        # Check TXT records for SPF, DMARC, security services
        for record in records.get('TXT', []):
            record_clean = record.strip('"')

            # SPF record
            if record_clean.startswith('v=spf1'):
                intel['spf_record'] = record_clean
                # Extract allowed senders
                if 'include:' in record_clean:
                    includes = [i.split(':')[1] for i in record_clean.split() if i.startswith('include:')]
                    for inc in includes:
                        if 'google' in inc.lower():
                            intel['technologies'].append('Google Workspace SPF')
                        elif 'outlook' in inc.lower() or 'microsoft' in inc.lower():
                            intel['technologies'].append('Microsoft 365 SPF')
                        elif 'sendgrid' in inc.lower():
                            intel['technologies'].append('SendGrid')
                        elif 'mailchimp' in inc.lower():
                            intel['technologies'].append('Mailchimp')

            # DMARC record
            if record_clean.startswith('v=DMARC1'):
                intel['dmarc_record'] = record_clean

            # Security services
            if 'docusign' in record_clean.lower():
                intel['security_services'].append('DocuSign')
            if 'salesforce' in record_clean.lower():
                intel['technologies'].append('Salesforce')
            if 'facebook-domain-verification' in record_clean.lower():
                intel['technologies'].append('Facebook Business')
            if 'google-site-verification' in record_clean.lower():
                intel['technologies'].append('Google Search Console')
            if 'MS=' in record_clean:
                intel['technologies'].append('Microsoft Domain Verification')

        # Check CAA records for authorized CAs
        for record in records.get('CAA', []):
            if 'issue' in record.lower():
                # Extract CA name
                parts = record.split()
                if len(parts) >= 3:
                    intel['ca_authorized'].append(parts[-1].strip('"'))

        # Reverse lookup for IP intelligence
        for ip in records.get('A', []):
            provider = self._identify_ip_provider(ip)
            if provider and not intel['hosting_provider']:
                intel['hosting_provider'] = provider

        return intel

    def _identify_ip_provider(self, ip: str) -> str:
        """Identify hosting provider from IP address ranges"""
        try:
            # Common cloud provider IP ranges (simplified)
            ip_parts = ip.split('.')
            if len(ip_parts) != 4:
                return None

            first_octet = int(ip_parts[0])
            second_octet = int(ip_parts[1])

            # AWS ranges (simplified)
            if first_octet in [3, 13, 15, 18, 34, 35, 44, 46, 52, 54, 99]:
                return 'Amazon AWS'

            # Google Cloud
            if first_octet == 35 and second_octet >= 184:
                return 'Google Cloud'

            # Azure
            if first_octet in [13, 20, 23, 40, 51, 52, 65, 104]:
                return 'Microsoft Azure'

            # Cloudflare
            if ip.startswith('104.') or ip.startswith('172.64.') or ip.startswith('173.245.'):
                return 'Cloudflare'

            # DigitalOcean
            if first_octet in [67, 134, 138, 139, 157, 159, 161, 162, 164, 165, 167]:
                return 'DigitalOcean'

        except Exception:
            pass

        return None

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
        with concurrent.futures.ThreadPoolExecutor(max_workers=30) as executor:
            futures = {executor.submit(check_subdomain, prefix): prefix
                      for prefix in self.subdomains[:500]}  # Increased limit

            for future in concurrent.futures.as_completed(futures, timeout=120):
                try:
                    result = future.result()
                    if result:
                        found.add(result)
                except Exception:
                    pass

        return found

    def _check_http_service(self, subdomain: str, http_client: Any) -> Dict:
        """Check if subdomain has an HTTP(S) service"""
        for scheme in ['https', 'http']:
            url = f"{scheme}://{subdomain}"
            try:
                response = http_client.get(url, timeout=5)
                if response:
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

    def _create_zone_transfer_finding(self, domain: str, subdomains: Set[str]) -> Dict:
        """Create finding for successful zone transfer"""
        result = self.create_result(
            vulnerable=True,
            url=f"dns://{domain}",
            parameter='AXFR',
            payload='Zone Transfer',
            evidence=f"DNS Zone Transfer successful!\nDiscovered {len(subdomains)} records:\n" +
                    '\n'.join(list(subdomains)[:20]),
            description=f"DNS Zone Transfer (AXFR) is enabled for {domain}",
            confidence=1.0
        )
        result['severity'] = 'High'
        result['type'] = 'DNS Zone Transfer'
        result['cwe'] = 'CWE-200'
        result['owasp'] = 'A01:2021'
        result['cvss'] = 7.5
        result['recommendation'] = 'Disable zone transfers to unauthorized hosts. Configure allow-transfer in DNS server.'
        return result

    def _create_dns_info_finding(self, domain: str, dns_info: Dict) -> Dict:
        """Create finding for DNS enumeration results"""
        evidence_lines = [f"=== DNS Intelligence Report for {domain} ===\n"]

        # Add intelligence summary first
        intel = dns_info.get('intelligence', {})
        if intel:
            evidence_lines.append("📊 INFRASTRUCTURE INTELLIGENCE:")
            if intel.get('hosting_provider'):
                evidence_lines.append(f"  🖥️  Hosting: {intel['hosting_provider']}")
            if intel.get('cdn_provider'):
                evidence_lines.append(f"  🌐 CDN: {intel['cdn_provider']}")
            if intel.get('mail_provider'):
                evidence_lines.append(f"  📧 Mail Provider: {intel['mail_provider']}")
            if intel.get('dns_provider'):
                evidence_lines.append(f"  🔤 DNS Provider: {intel['dns_provider']}")

            if intel.get('technologies'):
                evidence_lines.append(f"\n🔧 TECHNOLOGIES DETECTED:")
                for tech in intel['technologies']:
                    evidence_lines.append(f"  - {tech}")

            if intel.get('ca_authorized'):
                evidence_lines.append(f"\n🔐 AUTHORIZED CAs:")
                for ca in intel['ca_authorized']:
                    evidence_lines.append(f"  - {ca}")

            if intel.get('spf_record'):
                evidence_lines.append(f"\n📝 SPF Record: {intel['spf_record'][:100]}...")
            if intel.get('dmarc_record'):
                evidence_lines.append(f"📝 DMARC Record: {intel['dmarc_record'][:100]}...")

        # Add raw DNS records
        evidence_lines.append(f"\n📋 DNS RECORDS:")
        for rtype, records in dns_info.get('records', {}).items():
            evidence_lines.append(f"\n  {rtype} Records:")
            for record in records[:10]:
                evidence_lines.append(f"    - {record}")

        result = self.create_result(
            vulnerable=False,
            url=f"dns://{domain}",
            parameter='DNS',
            payload='Intelligence Gathering',
            evidence='\n'.join(evidence_lines),
            description=f"DNS intelligence gathered for {domain}",
            confidence=1.0
        )
        result['severity'] = 'info'
        result['type'] = 'recon'
        result['dns_records'] = dns_info.get('records', {})
        result['intelligence'] = intel
        return result


def get_module(module_path: str, payload_limit: int = None):
    """Create module instance"""
    return SubdomainModule(module_path, payload_limit=payload_limit)
