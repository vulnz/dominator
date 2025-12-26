"""
Secrets and API Keys Scanner Module

Scans JavaScript files and HTTP responses for exposed secrets:
- AWS Access Keys, Secret Keys
- Google Cloud API Keys, Service Accounts
- Azure Keys and Connection Strings
- Stripe, Twilio, SendGrid API Keys
- Zendesk API Keys
- GitHub, GitLab, Bitbucket Tokens
- Slack, Discord Webhooks/Tokens
- Database connection strings
- JWT tokens, Private keys
- Generic API keys and secrets

Shows context around each finding for accurate assessment.
"""

from typing import List, Dict, Any, Set, Tuple
from core.base_module import BaseModule
from core.logger import get_logger
from urllib.parse import urljoin, urlparse
import re

logger = get_logger(__name__)


class SecretsModule(BaseModule):
    """Secrets and API Keys Scanner Module"""

    def __init__(self, module_path: str, payload_limit: int = None):
        """Initialize Secrets module"""
        super().__init__(module_path, payload_limit=payload_limit)

        self.scanned_urls: Set[str] = set()

        # Initialize secret detection patterns
        self._init_patterns()

        logger.info(f"Secrets Scanner loaded: {len(self.secret_patterns)} patterns")

    def _init_patterns(self):
        """Initialize secret detection patterns with context"""

        self.secret_patterns = [
            # AWS
            {
                'name': 'AWS Access Key ID',
                'pattern': r'(?:A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}',
                'severity': 'Critical',
                'service': 'AWS',
                'description': 'AWS Access Key ID found. Can be used with secret key for AWS access.'
            },
            {
                'name': 'AWS Secret Access Key',
                'pattern': r'(?i)(?:aws_secret_access_key|aws_secret_key|secret_access_key)["\s:=]+["\']?([A-Za-z0-9/+=]{40})["\']?',
                'severity': 'Critical',
                'service': 'AWS',
                'description': 'AWS Secret Access Key exposed. Immediate rotation required.'
            },

            # Google Cloud
            {
                'name': 'Google API Key',
                'pattern': r'AIza[0-9A-Za-z\-_]{35}',
                'severity': 'High',
                'service': 'Google Cloud',
                'description': 'Google API key found. May allow access to Google services.'
            },
            {
                'name': 'Google OAuth Client Secret',
                'pattern': r'(?i)client_secret["\s:=]+["\']?([a-zA-Z0-9_-]{24})["\']?',
                'severity': 'High',
                'service': 'Google OAuth',
                'description': 'Google OAuth client secret exposed.'
            },
            {
                'name': 'Google Service Account',
                'pattern': r'"type":\s*"service_account"',
                'severity': 'Critical',
                'service': 'Google Cloud',
                'description': 'Google Cloud service account JSON found.'
            },

            # Azure
            {
                'name': 'Azure Storage Key',
                'pattern': r'(?i)(?:DefaultEndpointsProtocol|AccountKey)[=:][^;\s"\']{20,}',
                'severity': 'Critical',
                'service': 'Azure',
                'description': 'Azure Storage connection string or key exposed.'
            },
            {
                'name': 'Azure AD Client Secret',
                'pattern': r'(?i)(?:azure|ad|aad)[\w]*(?:secret|key|password)["\s:=]+["\']?([a-zA-Z0-9~._-]{34,})["\']?',
                'severity': 'Critical',
                'service': 'Azure AD',
                'description': 'Azure AD client secret found.'
            },

            # Stripe
            {
                'name': 'Stripe API Key',
                'pattern': r'(?:sk|pk)_(?:test|live)_[0-9a-zA-Z]{24,}',
                'severity': 'Critical',
                'service': 'Stripe',
                'description': 'Stripe API key found. sk_live keys are especially critical.'
            },

            # Twilio
            {
                'name': 'Twilio API Key',
                'pattern': r'SK[0-9a-fA-F]{32}',
                'severity': 'High',
                'service': 'Twilio',
                'description': 'Twilio API key exposed.'
            },
            {
                'name': 'Twilio Account SID',
                'pattern': r'AC[a-zA-Z0-9]{32}',
                'severity': 'Medium',
                'service': 'Twilio',
                'description': 'Twilio Account SID found.'
            },

            # SendGrid
            {
                'name': 'SendGrid API Key',
                'pattern': r'SG\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9_-]{43}',
                'severity': 'High',
                'service': 'SendGrid',
                'description': 'SendGrid API key found. Can send emails.'
            },

            # Zendesk
            {
                'name': 'Zendesk API Token',
                'pattern': r'(?i)zendesk[\w]*(?:token|key|api)["\s:=]+["\']?([a-zA-Z0-9]{40})["\']?',
                'severity': 'High',
                'service': 'Zendesk',
                'description': 'Zendesk API token exposed.'
            },
            {
                'name': 'Zendesk OAuth Token',
                'pattern': r'(?i)(?:zendesk|zd)[\w]*oauth["\s:=]+["\']?([a-zA-Z0-9_-]{64,})["\']?',
                'severity': 'High',
                'service': 'Zendesk',
                'description': 'Zendesk OAuth token found.'
            },

            # GitHub
            {
                'name': 'GitHub Personal Access Token',
                'pattern': r'ghp_[a-zA-Z0-9]{36}',
                'severity': 'Critical',
                'service': 'GitHub',
                'description': 'GitHub Personal Access Token exposed.'
            },
            {
                'name': 'GitHub OAuth Token',
                'pattern': r'gho_[a-zA-Z0-9]{36}',
                'severity': 'Critical',
                'service': 'GitHub',
                'description': 'GitHub OAuth Access Token found.'
            },
            {
                'name': 'GitHub App Token',
                'pattern': r'(?:ghu|ghs)_[a-zA-Z0-9]{36}',
                'severity': 'Critical',
                'service': 'GitHub',
                'description': 'GitHub App Token exposed.'
            },

            # GitLab
            {
                'name': 'GitLab Personal Access Token',
                'pattern': r'glpat-[a-zA-Z0-9_-]{20}',
                'severity': 'Critical',
                'service': 'GitLab',
                'description': 'GitLab Personal Access Token found.'
            },

            # Slack
            {
                'name': 'Slack Bot Token',
                'pattern': r'xoxb-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24}',
                'severity': 'High',
                'service': 'Slack',
                'description': 'Slack Bot Token exposed.'
            },
            {
                'name': 'Slack Webhook',
                'pattern': r'https://hooks\.slack\.com/services/T[a-zA-Z0-9_]+/B[a-zA-Z0-9_]+/[a-zA-Z0-9_]+',
                'severity': 'Medium',
                'service': 'Slack',
                'description': 'Slack Webhook URL found.'
            },

            # Discord
            {
                'name': 'Discord Bot Token',
                'pattern': r'(?:discord|bot)[\w]*token["\s:=]+["\']?([a-zA-Z0-9_-]{24}\.[a-zA-Z0-9_-]{6}\.[a-zA-Z0-9_-]{27})["\']?',
                'severity': 'High',
                'service': 'Discord',
                'description': 'Discord Bot Token exposed.'
            },
            {
                'name': 'Discord Webhook',
                'pattern': r'https://discord(?:app)?\.com/api/webhooks/[0-9]+/[a-zA-Z0-9_-]+',
                'severity': 'Medium',
                'service': 'Discord',
                'description': 'Discord Webhook URL found.'
            },

            # NPM
            {
                'name': 'NPM Token',
                'pattern': r'npm_[a-zA-Z0-9]{36}',
                'severity': 'Critical',
                'service': 'NPM',
                'description': 'NPM access token found. Can publish packages.'
            },

            # PyPI
            {
                'name': 'PyPI Token',
                'pattern': r'pypi-AgEIcHlwaS5vcmc[A-Za-z0-9_-]{50,}',
                'severity': 'Critical',
                'service': 'PyPI',
                'description': 'PyPI API token found.'
            },

            # Heroku
            {
                'name': 'Heroku API Key',
                'pattern': r'(?i)heroku[\w]*(?:api)?[\w]*key["\s:=]+["\']?([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})["\']?',
                'severity': 'High',
                'service': 'Heroku',
                'description': 'Heroku API key exposed.'
            },

            # Mailchimp
            {
                'name': 'Mailchimp API Key',
                'pattern': r'[a-f0-9]{32}-us[0-9]{1,2}',
                'severity': 'High',
                'service': 'Mailchimp',
                'description': 'Mailchimp API key found.'
            },

            # Private Keys
            {
                'name': 'RSA Private Key',
                'pattern': r'-----BEGIN (?:RSA )?PRIVATE KEY-----',
                'severity': 'Critical',
                'service': 'Cryptography',
                'description': 'RSA private key found in response.'
            },
            {
                'name': 'SSH Private Key',
                'pattern': r'-----BEGIN (?:OPENSSH|EC|DSA) PRIVATE KEY-----',
                'severity': 'Critical',
                'service': 'SSH',
                'description': 'SSH private key exposed.'
            },
            {
                'name': 'PGP Private Key',
                'pattern': r'-----BEGIN PGP PRIVATE KEY BLOCK-----',
                'severity': 'Critical',
                'service': 'PGP',
                'description': 'PGP private key found.'
            },

            # JWT
            {
                'name': 'JWT Token',
                'pattern': r'eyJ[a-zA-Z0-9_-]*\.eyJ[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]*',
                'severity': 'Medium',
                'service': 'JWT',
                'description': 'JWT token found. May contain sensitive claims.'
            },

            # Database Connection Strings
            {
                'name': 'MongoDB Connection String',
                'pattern': r'mongodb(?:\+srv)?://[^\s"\'<>]+',
                'severity': 'Critical',
                'service': 'MongoDB',
                'description': 'MongoDB connection string with potential credentials.'
            },
            {
                'name': 'PostgreSQL Connection String',
                'pattern': r'postgres(?:ql)?://[^\s"\'<>]+',
                'severity': 'Critical',
                'service': 'PostgreSQL',
                'description': 'PostgreSQL connection string exposed.'
            },
            {
                'name': 'MySQL Connection String',
                'pattern': r'mysql://[^\s"\'<>]+',
                'severity': 'Critical',
                'service': 'MySQL',
                'description': 'MySQL connection string found.'
            },
            {
                'name': 'Redis Connection String',
                'pattern': r'redis://[^\s"\'<>]+',
                'severity': 'High',
                'service': 'Redis',
                'description': 'Redis connection string exposed.'
            },

            # Firebase
            {
                'name': 'Firebase Cloud Messaging Key',
                'pattern': r'AAAA[A-Za-z0-9_-]{7}:[A-Za-z0-9_-]{140}',
                'severity': 'High',
                'service': 'Firebase',
                'description': 'Firebase Cloud Messaging server key found.'
            },
            {
                'name': 'Firebase Database URL',
                'pattern': r'https://[a-z0-9-]+\.firebaseio\.com',
                'severity': 'Medium',
                'service': 'Firebase',
                'description': 'Firebase Realtime Database URL found.'
            },

            # Shopify
            {
                'name': 'Shopify Access Token',
                'pattern': r'shpat_[a-fA-F0-9]{32}',
                'severity': 'High',
                'service': 'Shopify',
                'description': 'Shopify Admin API access token found.'
            },
            {
                'name': 'Shopify Shared Secret',
                'pattern': r'shpss_[a-fA-F0-9]{32}',
                'severity': 'High',
                'service': 'Shopify',
                'description': 'Shopify shared secret found.'
            },

            # Telegram
            {
                'name': 'Telegram Bot Token',
                'pattern': r'[0-9]{8,10}:[a-zA-Z0-9_-]{35}',
                'severity': 'High',
                'service': 'Telegram',
                'description': 'Telegram Bot API token found.'
            },

            # Square
            {
                'name': 'Square Access Token',
                'pattern': r'sq0atp-[0-9A-Za-z\-_]{22}',
                'severity': 'Critical',
                'service': 'Square',
                'description': 'Square OAuth access token found.'
            },
            {
                'name': 'Square Application Secret',
                'pattern': r'sq0csp-[0-9A-Za-z\-_]{43}',
                'severity': 'Critical',
                'service': 'Square',
                'description': 'Square application secret found.'
            },

            # PayPal
            {
                'name': 'PayPal Braintree Access Token',
                'pattern': r'access_token\$production\$[0-9a-z]{16}\$[0-9a-f]{32}',
                'severity': 'Critical',
                'service': 'PayPal/Braintree',
                'description': 'PayPal Braintree access token found.'
            },

            # Atlassian
            {
                'name': 'Atlassian API Token',
                'pattern': r'(?i)atlassian[\w]*(?:token|key)["\s:=]+["\']?([a-zA-Z0-9]{24})["\']?',
                'severity': 'High',
                'service': 'Atlassian',
                'description': 'Atlassian API token found.'
            },

            # Sentry
            {
                'name': 'Sentry DSN',
                'pattern': r'https://[a-f0-9]{32}@(?:o[0-9]+\.)?(?:sentry\.io|sentry\.[a-z]+\.com)/[0-9]+',
                'severity': 'Medium',
                'service': 'Sentry',
                'description': 'Sentry DSN found. May allow sending events.'
            },

            # DataDog
            {
                'name': 'DataDog API Key',
                'pattern': r'(?i)(?:datadog|dd)[\w]*(?:api)?[\w]*key["\s:=]+["\']?([a-f0-9]{32})["\']?',
                'severity': 'High',
                'service': 'DataDog',
                'description': 'DataDog API key exposed.'
            },

            # New Relic
            {
                'name': 'New Relic License Key',
                'pattern': r'[a-f0-9]{40}NRAL',
                'severity': 'High',
                'service': 'New Relic',
                'description': 'New Relic license key found.'
            },

            # PagerDuty
            {
                'name': 'PagerDuty API Key',
                'pattern': r'(?i)pagerduty[\w]*(?:api)?[\w]*key["\s:=]+["\']?([a-zA-Z0-9+_]{20})["\']?',
                'severity': 'High',
                'service': 'PagerDuty',
                'description': 'PagerDuty API key found.'
            },

            # Algolia
            {
                'name': 'Algolia Admin API Key',
                'pattern': r'(?i)algolia[\w]*(?:admin)?[\w]*key["\s:=]+["\']?([a-f0-9]{32})["\']?',
                'severity': 'High',
                'service': 'Algolia',
                'description': 'Algolia Admin API key found.'
            },

            # Contentful
            {
                'name': 'Contentful Delivery Token',
                'pattern': r'(?i)contentful[\w]*token["\s:=]+["\']?([a-zA-Z0-9_-]{43})["\']?',
                'severity': 'Medium',
                'service': 'Contentful',
                'description': 'Contentful delivery token found.'
            },

            # OpenAI
            {
                'name': 'OpenAI API Key',
                'pattern': r'sk-[a-zA-Z0-9]{48}',
                'severity': 'Critical',
                'service': 'OpenAI',
                'description': 'OpenAI API key found. Can incur significant charges.'
            },

            # Anthropic
            {
                'name': 'Anthropic API Key',
                'pattern': r'sk-ant-api[a-zA-Z0-9_-]{37,}',
                'severity': 'Critical',
                'service': 'Anthropic',
                'description': 'Anthropic (Claude) API key found.'
            },

            # Hugging Face
            {
                'name': 'Hugging Face Token',
                'pattern': r'hf_[a-zA-Z0-9]{34}',
                'severity': 'High',
                'service': 'Hugging Face',
                'description': 'Hugging Face API token found.'
            },

            # Mapbox
            {
                'name': 'Mapbox Access Token',
                'pattern': r'pk\.[a-zA-Z0-9]{60,}\.[a-zA-Z0-9_-]{22}',
                'severity': 'Medium',
                'service': 'Mapbox',
                'description': 'Mapbox access token found.'
            },
            {
                'name': 'Mapbox Secret Token',
                'pattern': r'sk\.[a-zA-Z0-9]{60,}\.[a-zA-Z0-9_-]{22}',
                'severity': 'High',
                'service': 'Mapbox',
                'description': 'Mapbox secret token found.'
            },

            # DigitalOcean
            {
                'name': 'DigitalOcean Personal Access Token',
                'pattern': r'dop_v1_[a-f0-9]{64}',
                'severity': 'Critical',
                'service': 'DigitalOcean',
                'description': 'DigitalOcean personal access token found.'
            },
            {
                'name': 'DigitalOcean OAuth Token',
                'pattern': r'doo_v1_[a-f0-9]{64}',
                'severity': 'Critical',
                'service': 'DigitalOcean',
                'description': 'DigitalOcean OAuth token found.'
            },

            # Cloudflare
            {
                'name': 'Cloudflare API Key',
                'pattern': r'(?i)cloudflare[\w]*(?:api)?[\w]*key["\s:=]+["\']?([a-f0-9]{37})["\']?',
                'severity': 'High',
                'service': 'Cloudflare',
                'description': 'Cloudflare API key found.'
            },

            # Plaid
            {
                'name': 'Plaid Client ID',
                'pattern': r'(?i)plaid[\w]*client[\w]*id["\s:=]+["\']?([a-f0-9]{24})["\']?',
                'severity': 'High',
                'service': 'Plaid',
                'description': 'Plaid client ID found.'
            },
            {
                'name': 'Plaid Secret',
                'pattern': r'(?i)plaid[\w]*secret["\s:=]+["\']?([a-f0-9]{30})["\']?',
                'severity': 'Critical',
                'service': 'Plaid',
                'description': 'Plaid secret key found.'
            },

            # Linear
            {
                'name': 'Linear API Key',
                'pattern': r'lin_api_[a-zA-Z0-9]{40}',
                'severity': 'High',
                'service': 'Linear',
                'description': 'Linear API key found.'
            },

            # Doppler
            {
                'name': 'Doppler API Token',
                'pattern': r'dp\.pt\.[a-zA-Z0-9]{44}',
                'severity': 'Critical',
                'service': 'Doppler',
                'description': 'Doppler API token found.'
            },

            # Supabase
            {
                'name': 'Supabase Service Key',
                'pattern': r'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9\.[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+',
                'severity': 'High',
                'service': 'Supabase',
                'description': 'Supabase service role JWT found. Check if it has admin access.'
            },

            # Vercel
            {
                'name': 'Vercel Token',
                'pattern': r'(?i)vercel[\w]*token["\s:=]+["\']?([a-zA-Z0-9]{24})["\']?',
                'severity': 'High',
                'service': 'Vercel',
                'description': 'Vercel API token found.'
            },

            # Netlify
            {
                'name': 'Netlify Access Token',
                'pattern': r'(?i)netlify[\w]*token["\s:=]+["\']?([a-zA-Z0-9_-]{40,})["\']?',
                'severity': 'High',
                'service': 'Netlify',
                'description': 'Netlify access token found.'
            },

            # CircleCI
            {
                'name': 'CircleCI API Token',
                'pattern': r'(?i)circle[\w]*token["\s:=]+["\']?([a-f0-9]{40})["\']?',
                'severity': 'High',
                'service': 'CircleCI',
                'description': 'CircleCI API token found.'
            },

            # Travis CI
            {
                'name': 'Travis CI API Token',
                'pattern': r'(?i)travis[\w]*token["\s:=]+["\']?([a-zA-Z0-9_-]{22})["\']?',
                'severity': 'High',
                'service': 'Travis CI',
                'description': 'Travis CI API token found.'
            },

            # Asana
            {
                'name': 'Asana Access Token',
                'pattern': r'[0-9]/[0-9]{16}:[A-Za-z0-9]{32}',
                'severity': 'High',
                'service': 'Asana',
                'description': 'Asana personal access token found.'
            },

            # Airtable
            {
                'name': 'Airtable API Key',
                'pattern': r'key[a-zA-Z0-9]{14}',
                'severity': 'High',
                'service': 'Airtable',
                'description': 'Airtable API key found.'
            },

            # Intercom
            {
                'name': 'Intercom Access Token',
                'pattern': r'dG9rO[a-zA-Z0-9_-]{36,}=',
                'severity': 'High',
                'service': 'Intercom',
                'description': 'Intercom access token found.'
            },

            # Notion
            {
                'name': 'Notion Integration Token',
                'pattern': r'secret_[a-zA-Z0-9]{43}',
                'severity': 'High',
                'service': 'Notion',
                'description': 'Notion integration token found.'
            },

            # Generic Patterns
            {
                'name': 'Generic API Key',
                'pattern': r'(?i)(?:api_key|apikey|api-key)["\s:=]+["\']?([a-zA-Z0-9_-]{20,})["\']?',
                'severity': 'High',
                'service': 'Generic',
                'description': 'API key found in code.'
            },
            {
                'name': 'Generic Secret',
                'pattern': r'(?i)(?:secret|password|passwd|pwd)["\s:=]+["\']?([^\s"\']{8,})["\']?',
                'severity': 'High',
                'service': 'Generic',
                'description': 'Hardcoded secret or password found.'
            },
            {
                'name': 'Bearer Token',
                'pattern': r'(?i)bearer\s+[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+',
                'severity': 'High',
                'service': 'Generic',
                'description': 'Bearer authentication token found.'
            },
            {
                'name': 'Basic Auth Credentials',
                'pattern': r'(?i)basic\s+[a-zA-Z0-9+/=]{20,}',
                'severity': 'High',
                'service': 'Generic',
                'description': 'Basic authentication credentials found.'
            },
            {
                'name': 'Authorization Header',
                'pattern': r'(?i)authorization["\s:=]+["\']?(?:bearer|basic|token)\s+[a-zA-Z0-9_.-]+["\']?',
                'severity': 'High',
                'service': 'Generic',
                'description': 'Authorization header value found.'
            },
        ]

    def scan(self, targets: List[Dict[str, Any]], http_client: Any) -> List[Dict[str, Any]]:
        """
        Scan for exposed secrets

        Args:
            targets: List of URLs
            http_client: HTTP client

        Returns:
            List of vulnerability results
        """
        results = []
        self.scanned_urls = set()

        # Get unique URLs
        urls_to_scan = set()
        for target in targets:
            url = target.get('url', '')
            if url:
                parsed = urlparse(url)
                base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
                urls_to_scan.add(base_url)

        logger.info(f"Secrets Scanner checking {len(urls_to_scan)} URLs")

        for url in urls_to_scan:
            if self.should_stop():
                break

            if url in self.scanned_urls:
                continue
            self.scanned_urls.add(url)

            try:
                response = http_client.get(url, timeout=10)
                if not response:
                    continue

                html = getattr(response, 'text', '') or ''

                # Scan the main page
                page_results = self._scan_content(url, html, 'HTML Response')
                results.extend(page_results)

                # Find and scan JS files
                js_files = self._find_js_files(url, html)

                for js_url in js_files[:20]:
                    if js_url in self.scanned_urls:
                        continue
                    self.scanned_urls.add(js_url)

                    js_results = self._scan_js_file(js_url, http_client)
                    results.extend(js_results)

            except Exception as e:
                logger.debug(f"Error scanning {url}: {e}")

        logger.info(f"Secrets scan complete: {len(results)} secrets found")
        return results

    def _find_js_files(self, base_url: str, html: str) -> List[str]:
        """Find JavaScript files in HTML"""
        js_files = []

        pattern = r'<script[^>]+src=["\']([^"\']+)["\']'
        for match in re.finditer(pattern, html, re.IGNORECASE):
            src = match.group(1)
            if src and not src.startswith('data:'):
                full_url = urljoin(base_url, src)
                if full_url not in js_files:
                    js_files.append(full_url)

        return js_files

    def _scan_js_file(self, js_url: str, http_client: Any) -> List[Dict[str, Any]]:
        """Scan a JavaScript file for secrets"""
        try:
            response = http_client.get(js_url, timeout=10)
            if not response or response.status_code != 200:
                return []

            content = getattr(response, 'text', '') or ''
            if not content:
                return []

            return self._scan_content(js_url, content, 'JavaScript')

        except Exception as e:
            logger.debug(f"Error scanning {js_url}: {e}")
            return []

    def _scan_content(self, url: str, content: str, content_type: str) -> List[Dict[str, Any]]:
        """Scan content for secrets"""
        results = []
        found_secrets: Set[str] = set()

        for pattern_info in self.secret_patterns:
            try:
                pattern = pattern_info['pattern']

                for match in re.finditer(pattern, content, re.IGNORECASE):
                    secret_value = match.group(0)

                    # Skip if already found (dedup)
                    if secret_value in found_secrets:
                        continue
                    found_secrets.add(secret_value)

                    # Get context around the secret
                    context = self._get_context(content, match.start(), match.end())

                    result = self._create_finding(
                        url=url,
                        pattern_info=pattern_info,
                        secret_value=secret_value,
                        context=context,
                        content_type=content_type
                    )
                    results.append(result)

            except Exception as e:
                logger.debug(f"Error with pattern {pattern_info['name']}: {e}")

        return results

    def _get_context(self, content: str, start: int, end: int, context_chars: int = 150) -> str:
        """Get context around a secret for understanding where it's used"""
        # Find line boundaries
        lines = content.split('\n')
        current_pos = 0
        secret_line = 0

        for i, line in enumerate(lines):
            line_end = current_pos + len(line) + 1
            if current_pos <= start < line_end:
                secret_line = i
                break
            current_pos = line_end

        # Get surrounding lines
        start_line = max(0, secret_line - 2)
        end_line = min(len(lines), secret_line + 3)

        context_lines = lines[start_line:end_line]
        context = '\n'.join(context_lines)

        # Truncate if too long
        if len(context) > 500:
            context = context[:500] + '...'

        return context

    def _create_finding(self, url: str, pattern_info: Dict, secret_value: str,
                        context: str, content_type: str) -> Dict[str, Any]:
        """Create a finding for an exposed secret"""

        # Mask the secret for display (show first and last 4 chars)
        if len(secret_value) > 12:
            masked = f"{secret_value[:4]}...{secret_value[-4:]}"
        else:
            masked = secret_value[:4] + '...'

        evidence = f"""Exposed Secret Detected

**Secret Type:** {pattern_info['name']}
**Service:** {pattern_info['service']}
**Found in:** {content_type}
**URL:** {url}

**Secret Value (masked):** {masked}

**Context (surrounding code):**
```
{context}
```

**Security Impact:**
{pattern_info['description']}

**Remediation:**
1. Rotate the exposed credential immediately
2. Remove hardcoded secrets from source code
3. Use environment variables or secret management
4. Add secrets scanning to CI/CD pipeline
5. Review access logs for unauthorized usage
"""

        result = self.create_result(
            vulnerable=True,
            url=url,
            parameter=pattern_info['name'],
            payload=masked,
            evidence=evidence,
            description=f"Exposed {pattern_info['name']}: {pattern_info['description']}",
            confidence=0.90,
            severity=pattern_info['severity'],
            method='GET',
            response=f"Secret found in {content_type}"
        )

        result['secret_type'] = pattern_info['name']
        result['service'] = pattern_info['service']
        result['secret_masked'] = masked
        result['content_type'] = content_type
        result['context'] = context
        result['verified'] = True

        logger.warning(f"Found {pattern_info['name']} at {url}")
        return result


def get_module(module_path: str, payload_limit: int = None):
    """Create module instance"""
    return SecretsModule(module_path, payload_limit=payload_limit)
