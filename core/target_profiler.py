"""
Target Profiler - Comprehensive Pre-Scan Intelligence Gathering

Performs extensive reconnaissance before active scanning:
1. Technology Stack Detection (CMS, Framework, Language, Server)
2. WAF/Security Detection (Cloudflare, Akamai, ModSecurity, etc.)
3. Geographic/Infrastructure Info (Country, Hosting, CDN)
4. Security Headers Analysis
5. SSL/TLS Configuration
6. DNS Information
7. Basic Site Intelligence (Title, Meta, Robots, Sitemap)
8. Screenshot Capture (for GUI)
"""

import re
import socket
import ssl
import json
from typing import Dict, List, Any, Optional, Tuple
from urllib.parse import urlparse, urljoin
from dataclasses import dataclass, field, asdict
from datetime import datetime
from core.logger import get_logger

logger = get_logger(__name__)


@dataclass
class TargetProfile:
    """Complete profile of a target"""
    url: str
    domain: str
    ip_address: str = ""

    # Basic Info
    title: str = ""
    description: str = ""
    favicon_hash: str = ""
    response_time_ms: float = 0
    status_code: int = 0
    content_length: int = 0

    # Technology Stack
    web_server: str = ""
    programming_language: str = ""
    framework: str = ""
    cms: str = ""
    javascript_libraries: List[str] = field(default_factory=list)

    # Security
    waf_detected: str = ""
    waf_confidence: float = 0
    security_headers: Dict[str, str] = field(default_factory=dict)
    missing_security_headers: List[str] = field(default_factory=list)

    # SSL/TLS
    ssl_enabled: bool = False
    ssl_issuer: str = ""
    ssl_expiry: str = ""
    ssl_protocol: str = ""
    ssl_grade: str = ""

    # Infrastructure
    country: str = ""
    country_code: str = ""
    hosting_provider: str = ""
    cdn: str = ""
    asn: str = ""

    # DNS
    dns_records: Dict[str, List[str]] = field(default_factory=dict)
    nameservers: List[str] = field(default_factory=list)

    # Site Intelligence
    robots_txt: bool = False
    sitemap_xml: bool = False
    admin_panels: List[str] = field(default_factory=list)
    interesting_paths: List[str] = field(default_factory=list)
    forms_detected: int = 0
    login_page: bool = False

    # Additional Findings
    emails_found: List[str] = field(default_factory=list)
    subdomains_found: List[str] = field(default_factory=list)
    technologies: List[Dict[str, Any]] = field(default_factory=list)

    # Screenshot
    screenshot_path: str = ""
    screenshot_base64: str = ""

    # Metadata
    profile_time: str = ""
    profile_duration_seconds: float = 0

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class WAFDetector:
    """Detect Web Application Firewalls"""

    # WAF signatures based on response headers and behavior
    WAF_SIGNATURES = {
        'Cloudflare': {
            'headers': ['cf-ray', 'cf-cache-status', '__cfduid', 'cf-request-id'],
            'cookies': ['__cfduid', '__cf_bm', 'cf_clearance'],
            'server': ['cloudflare'],
            'body': ['attention required! | cloudflare', 'cf-browser-verification'],
        },
        'AWS WAF': {
            'headers': ['x-amzn-requestid', 'x-amz-cf-id', 'x-amz-id-2'],
            'cookies': ['awsalb', 'awsalbcors'],
            'body': ['aws waf', 'request blocked'],
        },
        'Akamai': {
            'headers': ['x-akamai-transformed', 'akamai-origin-hop', 'x-akamai-session-info'],
            'server': ['akamaighost', 'akamai'],
            'cookies': ['ak_bmsc', 'bm_sz', 'bm_sv'],
        },
        'Imperva/Incapsula': {
            'headers': ['x-iinfo', 'x-cdn'],
            'cookies': ['incap_ses', 'visid_incap', 'nlbi_'],
            'body': ['incapsula incident', 'request unsuccessful'],
        },
        'Sucuri': {
            'headers': ['x-sucuri-id', 'x-sucuri-cache'],
            'server': ['sucuri'],
            'body': ['sucuri website firewall', 'access denied - sucuri'],
        },
        'ModSecurity': {
            'headers': ['mod_security', 'modsecurity'],
            'server': ['mod_security'],
            'body': ['mod_security', 'modsecurity', 'not acceptable'],
        },
        'F5 BIG-IP ASM': {
            'headers': ['x-wa-info'],
            'cookies': ['ts', 'bigipserver'],
            'server': ['big-ip', 'bigip'],
        },
        'Barracuda': {
            'headers': ['barra_counter_session'],
            'cookies': ['barra_counter_session'],
            'body': ['barracuda networks'],
        },
        'Fortinet FortiWeb': {
            'headers': ['fortiwafsid'],
            'cookies': ['cookiesession1'],
            'body': ['fortigate', 'fortiweb'],
        },
        'Wordfence': {
            'body': ['wordfence', 'this request was blocked by wordfence'],
            'headers': ['x-wordfence'],
        },
        'DDoS-Guard': {
            'headers': ['x-ddos-protection'],
            'server': ['ddos-guard'],
            'cookies': ['__ddg'],
        },
        'StackPath': {
            'headers': ['x-sp-url', 'x-sp-waf'],
            'cookies': ['sp_waf'],
        },
        'Reblaze': {
            'headers': ['x-reblaze-protected'],
            'cookies': ['rbzid'],
        },
    }

    def detect(self, response) -> Tuple[str, float, List[str]]:
        """
        Detect WAF from response

        Returns:
            Tuple of (waf_name, confidence, evidence_list)
        """
        if not response:
            return "", 0, []

        detections = []

        # Get response components
        headers = {}
        if hasattr(response, 'headers'):
            headers = {k.lower(): v.lower() for k, v in response.headers.items()}

        cookies = []
        if 'set-cookie' in headers:
            cookies = [c.lower() for c in headers['set-cookie'].split(';')]

        server = headers.get('server', '').lower()
        body = ""
        if hasattr(response, 'text'):
            body = response.text[:5000].lower()

        for waf_name, signatures in self.WAF_SIGNATURES.items():
            evidence = []
            score = 0

            # Check headers
            for sig_header in signatures.get('headers', []):
                if sig_header.lower() in headers:
                    evidence.append(f"Header: {sig_header}")
                    score += 30

            # Check cookies
            for sig_cookie in signatures.get('cookies', []):
                if any(sig_cookie.lower() in c for c in cookies):
                    evidence.append(f"Cookie: {sig_cookie}")
                    score += 25

            # Check server header
            for sig_server in signatures.get('server', []):
                if sig_server.lower() in server:
                    evidence.append(f"Server: {sig_server}")
                    score += 35

            # Check body
            for sig_body in signatures.get('body', []):
                if sig_body.lower() in body:
                    evidence.append(f"Body pattern: {sig_body[:30]}...")
                    score += 20

            if score > 0:
                detections.append((waf_name, min(score, 100), evidence))

        # Return highest confidence detection
        if detections:
            detections.sort(key=lambda x: x[1], reverse=True)
            return detections[0]

        return "", 0, []


class TechnologyDetector:
    """Comprehensive technology detection"""

    # Server signatures
    SERVERS = {
        r'Apache/(\d+\.\d+(?:\.\d+)?)': 'Apache',
        r'nginx/(\d+\.\d+(?:\.\d+)?)': 'Nginx',
        r'Microsoft-IIS/(\d+\.\d+)': 'IIS',
        r'LiteSpeed': 'LiteSpeed',
        r'openresty': 'OpenResty',
        r'Caddy': 'Caddy',
        r'gunicorn': 'Gunicorn',
        r'Werkzeug': 'Werkzeug',
        r'Kestrel': 'Kestrel',
        r'Cowboy': 'Cowboy',
    }

    # Language/Framework signatures
    FRAMEWORKS = {
        # PHP
        r'X-Powered-By:\s*PHP/(\d+\.\d+)': ('PHP', 'language'),
        r'PHPSESSID': ('PHP', 'language'),
        r'\.php': ('PHP', 'language'),

        # ASP.NET
        r'X-AspNet-Version': ('ASP.NET', 'framework'),
        r'X-AspNetMvc-Version': ('ASP.NET MVC', 'framework'),
        r'__VIEWSTATE': ('ASP.NET WebForms', 'framework'),
        r'\.aspx|\.asmx|\.ashx': ('ASP.NET', 'framework'),

        # Python
        r'X-Powered-By:\s*Python': ('Python', 'language'),
        r'django': ('Django', 'framework'),
        r'flask': ('Flask', 'framework'),
        r'tornado': ('Tornado', 'framework'),

        # Java
        r'X-Powered-By:\s*Servlet|JSP': ('Java', 'language'),
        r'JSESSIONID': ('Java', 'language'),
        r'\.jsp|\.do|\.action': ('Java', 'language'),
        r'Spring': ('Spring', 'framework'),
        r'Struts': ('Struts', 'framework'),

        # Node.js
        r'X-Powered-By:\s*Express': ('Express.js', 'framework'),
        r'connect\.sid': ('Node.js', 'language'),

        # Ruby
        r'X-Powered-By:\s*Phusion Passenger': ('Ruby', 'language'),
        r'_session_id.*rack': ('Ruby on Rails', 'framework'),

        # Go
        r'X-Powered-By:\s*Go': ('Go', 'language'),
    }

    # CMS signatures
    CMS_SIGNATURES = {
        'WordPress': [
            r'/wp-content/',
            r'/wp-includes/',
            r'/wp-admin/',
            r'wp-json',
            r'<meta name="generator" content="WordPress',
        ],
        'Drupal': [
            r'Drupal',
            r'/sites/default/',
            r'/core/misc/drupal',
            r'X-Drupal-Cache',
        ],
        'Joomla': [
            r'/media/jui/',
            r'/templates/.*joomla',
            r'<meta name="generator" content="Joomla',
        ],
        'Magento': [
            r'/skin/frontend/',
            r'/static/frontend/',
            r'Mage.Cookies',
            r'X-Magento-',
        ],
        'Shopify': [
            r'cdn\.shopify\.com',
            r'Shopify\.theme',
            r'myshopify\.com',
        ],
        'Wix': [
            r'wix\.com',
            r'X-Wix-',
            r'wixstatic\.com',
        ],
        'Squarespace': [
            r'squarespace\.com',
            r'static\.squarespace',
        ],
    }

    # JavaScript libraries
    JS_LIBRARIES = {
        r'jquery[.-](\d+\.\d+(?:\.\d+)?)?': 'jQuery',
        r'react[.-](?:dom)?': 'React',
        r'angular(?:\.min)?\.js': 'Angular',
        r'vue(?:\.min)?\.js': 'Vue.js',
        r'bootstrap[.-](\d+)?': 'Bootstrap',
        r'lodash': 'Lodash',
        r'moment(?:\.min)?\.js': 'Moment.js',
        r'axios': 'Axios',
        r'underscore': 'Underscore.js',
        r'backbone': 'Backbone.js',
        r'ember': 'Ember.js',
        r'next': 'Next.js',
        r'nuxt': 'Nuxt.js',
        r'gatsby': 'Gatsby',
        r'svelte': 'Svelte',
    }

    def detect_all(self, response, url: str) -> Dict[str, Any]:
        """Detect all technologies from response"""
        result = {
            'web_server': '',
            'programming_language': '',
            'framework': '',
            'cms': '',
            'javascript_libraries': [],
            'all_technologies': [],
        }

        if not response:
            return result

        headers = {}
        if hasattr(response, 'headers'):
            headers = {k.lower(): str(v) for k, v in response.headers.items()}

        body = ""
        if hasattr(response, 'text'):
            body = response.text[:50000]

        all_text = str(headers) + body

        # Detect web server
        server = headers.get('server', '')
        for pattern, name in self.SERVERS.items():
            if re.search(pattern, server, re.I):
                result['web_server'] = name
                result['all_technologies'].append({'name': name, 'category': 'Web Server'})
                break

        # Detect language/framework
        for pattern, (name, category) in self.FRAMEWORKS.items():
            if re.search(pattern, all_text, re.I):
                if category == 'language' and not result['programming_language']:
                    result['programming_language'] = name
                elif category == 'framework' and not result['framework']:
                    result['framework'] = name
                result['all_technologies'].append({'name': name, 'category': category.title()})

        # Detect CMS
        for cms_name, patterns in self.CMS_SIGNATURES.items():
            for pattern in patterns:
                if re.search(pattern, all_text, re.I):
                    result['cms'] = cms_name
                    result['all_technologies'].append({'name': cms_name, 'category': 'CMS'})
                    break
            if result['cms']:
                break

        # Detect JS libraries
        js_libs = set()
        for pattern, name in self.JS_LIBRARIES.items():
            if re.search(pattern, body, re.I):
                js_libs.add(name)
        result['javascript_libraries'] = list(js_libs)
        for lib in js_libs:
            result['all_technologies'].append({'name': lib, 'category': 'JavaScript Library'})

        return result


class TargetProfiler:
    """Main profiler class that coordinates all detection"""

    # Important security headers to check
    SECURITY_HEADERS = [
        'Strict-Transport-Security',
        'Content-Security-Policy',
        'X-Content-Type-Options',
        'X-Frame-Options',
        'X-XSS-Protection',
        'Referrer-Policy',
        'Permissions-Policy',
        'Cross-Origin-Opener-Policy',
        'Cross-Origin-Resource-Policy',
        'Cross-Origin-Embedder-Policy',
    ]

    # Common admin panel paths to check
    ADMIN_PATHS = [
        '/admin', '/admin/', '/administrator/', '/wp-admin/',
        '/admin/login', '/admin.php', '/admincp/', '/cpanel/',
        '/manager/', '/dashboard/', '/backend/', '/login/',
        '/user/login', '/accounts/login/', '/auth/login',
    ]

    # Interesting paths to check
    INTERESTING_PATHS = [
        '/robots.txt', '/sitemap.xml', '/sitemap_index.xml',
        '/.git/config', '/.env', '/config.php', '/wp-config.php',
        '/api/', '/graphql', '/swagger/', '/api-docs/',
        '/.well-known/security.txt', '/security.txt',
        '/crossdomain.xml', '/clientaccesspolicy.xml',
    ]

    def __init__(self, http_client=None):
        self.http_client = http_client
        self.waf_detector = WAFDetector()
        self.tech_detector = TechnologyDetector()

    def profile(self, url: str) -> TargetProfile:
        """
        Create comprehensive profile of target

        Args:
            url: Target URL to profile

        Returns:
            TargetProfile with all gathered intelligence
        """
        import time
        start_time = time.time()

        parsed = urlparse(url)
        domain = parsed.netloc

        profile = TargetProfile(
            url=url,
            domain=domain,
            profile_time=datetime.now().isoformat(),
        )

        logger.info(f"[PROFILER] Starting comprehensive profile of {domain}")

        # 1. Resolve IP address
        profile.ip_address = self._resolve_ip(domain)
        logger.info(f"  [+] IP Address: {profile.ip_address}")

        # 2. Get main page response
        response = self._get_response(url)
        if response:
            profile.status_code = response.status_code
            profile.content_length = len(response.text) if hasattr(response, 'text') else 0
            profile.response_time_ms = getattr(response, 'elapsed', None)
            if profile.response_time_ms:
                profile.response_time_ms = profile.response_time_ms.total_seconds() * 1000

            # 3. Extract basic info
            self._extract_basic_info(response, profile)
            logger.info(f"  [+] Title: {profile.title[:50]}..." if profile.title else "  [-] No title found")

            # 4. Detect WAF
            waf_name, waf_conf, evidence = self.waf_detector.detect(response)
            profile.waf_detected = waf_name
            profile.waf_confidence = waf_conf
            if waf_name:
                logger.info(f"  [!] WAF Detected: {waf_name} (confidence: {waf_conf}%)")

            # 5. Detect technologies
            tech_info = self.tech_detector.detect_all(response, url)
            profile.web_server = tech_info['web_server']
            profile.programming_language = tech_info['programming_language']
            profile.framework = tech_info['framework']
            profile.cms = tech_info['cms']
            profile.javascript_libraries = tech_info['javascript_libraries']
            profile.technologies = tech_info['all_technologies']

            if profile.web_server:
                logger.info(f"  [+] Web Server: {profile.web_server}")
            if profile.programming_language:
                logger.info(f"  [+] Language: {profile.programming_language}")
            if profile.framework:
                logger.info(f"  [+] Framework: {profile.framework}")
            if profile.cms:
                logger.info(f"  [+] CMS: {profile.cms}")

            # 6. Check security headers
            self._check_security_headers(response, profile)
            logger.info(f"  [+] Security Headers: {len(profile.security_headers)} present, {len(profile.missing_security_headers)} missing")

            # 7. Extract emails
            profile.emails_found = self._extract_emails(response.text if hasattr(response, 'text') else '')
            if profile.emails_found:
                logger.info(f"  [+] Emails Found: {len(profile.emails_found)}")

        # 8. Check SSL/TLS
        if parsed.scheme == 'https':
            self._check_ssl(domain, profile)
            logger.info(f"  [+] SSL: {profile.ssl_issuer}, expires {profile.ssl_expiry}")

        # 9. Get geolocation
        if profile.ip_address:
            self._get_geolocation(profile)
            if profile.country:
                logger.info(f"  [+] Location: {profile.country} ({profile.hosting_provider})")

        # 10. Check interesting paths
        self._check_paths(url, profile)
        logger.info(f"  [+] Robots.txt: {'Found' if profile.robots_txt else 'Not found'}")
        logger.info(f"  [+] Sitemap.xml: {'Found' if profile.sitemap_xml else 'Not found'}")

        # 11. Check for login/admin pages
        self._check_admin_paths(url, profile)
        if profile.admin_panels:
            logger.info(f"  [+] Admin Panels Found: {len(profile.admin_panels)}")

        profile.profile_duration_seconds = time.time() - start_time
        logger.info(f"[PROFILER] Complete in {profile.profile_duration_seconds:.2f}s")

        return profile

    def _resolve_ip(self, domain: str) -> str:
        """Resolve domain to IP address"""
        try:
            # Remove port if present
            host = domain.split(':')[0]
            return socket.gethostbyname(host)
        except Exception:
            return ""

    def _get_response(self, url: str):
        """Get HTTP response from URL"""
        try:
            if self.http_client:
                return self.http_client.get(url)
            else:
                import requests
                return requests.get(url, timeout=10, verify=False, allow_redirects=True)
        except Exception as e:
            logger.debug(f"Failed to get response: {e}")
            return None

    def _extract_basic_info(self, response, profile: TargetProfile):
        """Extract basic page info"""
        if not hasattr(response, 'text'):
            return

        body = response.text

        # Extract title
        title_match = re.search(r'<title[^>]*>([^<]+)</title>', body, re.I)
        if title_match:
            profile.title = title_match.group(1).strip()

        # Extract meta description
        desc_match = re.search(r'<meta[^>]+name=["\']description["\'][^>]+content=["\']([^"\']+)["\']', body, re.I)
        if not desc_match:
            desc_match = re.search(r'<meta[^>]+content=["\']([^"\']+)["\'][^>]+name=["\']description["\']', body, re.I)
        if desc_match:
            profile.description = desc_match.group(1).strip()

        # Count forms
        profile.forms_detected = len(re.findall(r'<form[^>]*>', body, re.I))

        # Check for login indicators
        login_patterns = [
            r'type=["\']password["\']',
            r'login|signin|log.?in|sign.?in',
            r'username|password|credential',
        ]
        for pattern in login_patterns:
            if re.search(pattern, body, re.I):
                profile.login_page = True
                break

    def _check_security_headers(self, response, profile: TargetProfile):
        """Check security headers"""
        if not hasattr(response, 'headers'):
            return

        headers = {k.lower(): v for k, v in response.headers.items()}

        for header in self.SECURITY_HEADERS:
            header_lower = header.lower()
            if header_lower in headers:
                profile.security_headers[header] = headers[header_lower]
            else:
                profile.missing_security_headers.append(header)

    def _check_ssl(self, domain: str, profile: TargetProfile):
        """Check SSL certificate info"""
        try:
            host = domain.split(':')[0]
            port = 443
            if ':' in domain:
                port = int(domain.split(':')[1])

            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE

            with socket.create_connection((host, port), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=host) as ssock:
                    cert = ssock.getpeercert(binary_form=False)
                    if cert:
                        profile.ssl_enabled = True
                        profile.ssl_protocol = ssock.version()

                        # Get issuer
                        issuer = dict(x[0] for x in cert.get('issuer', []))
                        profile.ssl_issuer = issuer.get('organizationName', 'Unknown')

                        # Get expiry
                        profile.ssl_expiry = cert.get('notAfter', 'Unknown')
        except Exception as e:
            logger.debug(f"SSL check failed: {e}")

    def _get_geolocation(self, profile: TargetProfile):
        """Get IP geolocation info"""
        try:
            import requests
            # Using ip-api.com (free, no API key needed)
            resp = requests.get(
                f"http://ip-api.com/json/{profile.ip_address}?fields=status,country,countryCode,isp,org,as,hosting",
                timeout=5
            )
            if resp.status_code == 200:
                data = resp.json()
                if data.get('status') == 'success':
                    profile.country = data.get('country', '')
                    profile.country_code = data.get('countryCode', '')
                    profile.hosting_provider = data.get('isp', '') or data.get('org', '')
                    profile.asn = data.get('as', '')

                    # Detect CDN based on hosting info
                    hosting_lower = profile.hosting_provider.lower()
                    if 'cloudflare' in hosting_lower:
                        profile.cdn = 'Cloudflare'
                    elif 'akamai' in hosting_lower:
                        profile.cdn = 'Akamai'
                    elif 'fastly' in hosting_lower:
                        profile.cdn = 'Fastly'
                    elif 'amazon' in hosting_lower or 'aws' in hosting_lower:
                        profile.cdn = 'AWS CloudFront'
        except Exception as e:
            logger.debug(f"Geolocation failed: {e}")

    def _extract_emails(self, content: str) -> List[str]:
        """Extract email addresses from content"""
        pattern = r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'
        emails = list(set(re.findall(pattern, content)))
        # Filter out common false positives
        filtered = [e for e in emails if not any(fp in e.lower() for fp in
            ['example.com', 'domain.com', 'email.com', 'test.com', 'sample.'])]
        return filtered[:20]  # Limit to 20

    def _check_paths(self, base_url: str, profile: TargetProfile):
        """Check for interesting paths"""
        for path in self.INTERESTING_PATHS:
            try:
                url = urljoin(base_url, path)
                resp = self._get_response(url)
                if resp and resp.status_code == 200:
                    if path == '/robots.txt':
                        profile.robots_txt = True
                    elif 'sitemap' in path:
                        profile.sitemap_xml = True
                    else:
                        profile.interesting_paths.append(path)
            except Exception:
                pass

    def _check_admin_paths(self, base_url: str, profile: TargetProfile):
        """Check for admin panel paths"""
        for path in self.ADMIN_PATHS:
            try:
                url = urljoin(base_url, path)
                resp = self._get_response(url)
                if resp and resp.status_code in [200, 401, 403]:
                    # 401/403 often indicates protected admin area
                    profile.admin_panels.append(path)
                    if len(profile.admin_panels) >= 5:  # Limit checks
                        break
            except Exception:
                pass

    def generate_report(self, profile: TargetProfile) -> str:
        """Generate human-readable profile report"""
        lines = [
            "=" * 70,
            f"TARGET PROFILE: {profile.domain}",
            "=" * 70,
            "",
            "BASIC INFORMATION",
            "-" * 40,
            f"  URL:              {profile.url}",
            f"  IP Address:       {profile.ip_address}",
            f"  Title:            {profile.title[:60]}..." if len(profile.title) > 60 else f"  Title:            {profile.title}",
            f"  Status Code:      {profile.status_code}",
            f"  Response Time:    {profile.response_time_ms:.0f}ms" if profile.response_time_ms else "",
            f"  Content Length:   {profile.content_length:,} bytes",
            "",
            "TECHNOLOGY STACK",
            "-" * 40,
            f"  Web Server:       {profile.web_server or 'Unknown'}",
            f"  Language:         {profile.programming_language or 'Unknown'}",
            f"  Framework:        {profile.framework or 'Unknown'}",
            f"  CMS:              {profile.cms or 'Not detected'}",
            f"  JS Libraries:     {', '.join(profile.javascript_libraries[:5]) or 'None detected'}",
            "",
            "SECURITY",
            "-" * 40,
            f"  WAF Detected:     {profile.waf_detected or 'None detected'}" + (f" ({profile.waf_confidence}% confidence)" if profile.waf_detected else ""),
            f"  Security Headers: {len(profile.security_headers)} present",
            f"  Missing Headers:  {', '.join(profile.missing_security_headers[:5])}",
            "",
            "SSL/TLS",
            "-" * 40,
            f"  SSL Enabled:      {'Yes' if profile.ssl_enabled else 'No'}",
            f"  SSL Issuer:       {profile.ssl_issuer}" if profile.ssl_enabled else "",
            f"  SSL Expiry:       {profile.ssl_expiry}" if profile.ssl_enabled else "",
            f"  Protocol:         {profile.ssl_protocol}" if profile.ssl_protocol else "",
            "",
            "INFRASTRUCTURE",
            "-" * 40,
            f"  Country:          {profile.country} ({profile.country_code})" if profile.country else "  Country:          Unknown",
            f"  Hosting:          {profile.hosting_provider}" if profile.hosting_provider else "",
            f"  CDN:              {profile.cdn or 'Not detected'}",
            f"  ASN:              {profile.asn}" if profile.asn else "",
            "",
            "SITE INTELLIGENCE",
            "-" * 40,
            f"  Robots.txt:       {'Found' if profile.robots_txt else 'Not found'}",
            f"  Sitemap.xml:      {'Found' if profile.sitemap_xml else 'Not found'}",
            f"  Forms Detected:   {profile.forms_detected}",
            f"  Login Page:       {'Yes' if profile.login_page else 'No'}",
            f"  Admin Panels:     {', '.join(profile.admin_panels[:3]) or 'None found'}",
            "",
        ]

        if profile.emails_found:
            lines.extend([
                "EMAILS FOUND",
                "-" * 40,
                *[f"  - {email}" for email in profile.emails_found[:10]],
                "",
            ])

        lines.extend([
            "=" * 70,
            f"Profile completed in {profile.profile_duration_seconds:.2f} seconds",
            "=" * 70,
        ])

        return "\n".join(filter(None, lines))


def profile_target(url: str, http_client=None) -> TargetProfile:
    """Convenience function to profile a target"""
    profiler = TargetProfiler(http_client)
    return profiler.profile(url)
