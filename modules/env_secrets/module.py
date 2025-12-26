"""
Environment Files & API Keys Scanner Module

Detects:
1. Exposed .env files and configuration files
2. Leaked API keys and secrets using regex patterns
3. Hard-coded credentials
4. AWS keys, tokens, private keys
"""

import re
from typing import List, Dict, Any, Tuple
from core.base_module import BaseModule
from core.logger import get_logger
from urllib.parse import urljoin, urlparse

logger = get_logger(__name__)


class EnvSecretsModule(BaseModule):
    """Environment files and API keys scanner"""

    # API key regex patterns - COMPREHENSIVE with high-confidence patterns
    # Only patterns with specific, unique prefixes that are unlikely to match random data
    API_KEY_PATTERNS = {
        # ===== CLOUD PROVIDERS =====
        # AWS - specific prefixes (AKIA, etc.)
        'AWS Access Key': r'(?:A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}',
        'AWS MWS Key': r'amzn\.mws\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}',
        'AWS S3 Signed URL': r'https://[a-z0-9-]+\.s3\.[a-z0-9-]+\.amazonaws\.com/[^\s\'\"<>]+\?.*X-Amz-Signature=[a-fA-F0-9]{64}',

        # Google Cloud - service account keys
        'GCP Service Account': r'"type"\s*:\s*"service_account"',
        'GCP Private Key ID': r'"private_key_id"\s*:\s*"[a-f0-9]{40}"',
        'GCP OAuth Token': r'ya29\.[0-9A-Za-z_-]{100,}',

        # Azure - specific patterns
        'Azure Storage SAS': r'\?sv=[0-9]{4}-[0-9]{2}-[0-9]{2}&s[a-z]=[a-z]+&s[a-z]+=[^&\s]+&sig=[A-Za-z0-9%+/=]+',
        'Azure AD Client Secret': r'[a-zA-Z0-9~_.-]{34,40}',  # Only in context of azure
        'Azure Connection String': r'DefaultEndpointsProtocol=https;AccountName=[^;]+;AccountKey=[A-Za-z0-9+/=]{86,88};',

        # DigitalOcean
        'DigitalOcean Token': r'dop_v1_[a-f0-9]{64}',
        'DigitalOcean OAuth': r'doo_v1_[a-f0-9]{64}',
        'DigitalOcean Refresh': r'dor_v1_[a-f0-9]{64}',

        # Alibaba Cloud
        'Alibaba Cloud Key': r'LTAI[A-Za-z0-9]{20}',

        # ===== VERSION CONTROL =====
        # GitHub - very specific format with prefix
        'GitHub Token': r'gh[pousr]_[A-Za-z0-9_]{36,}',
        'GitHub Personal Access Token': r'ghp_[A-Za-z0-9]{36}',
        'GitHub OAuth Token': r'gho_[A-Za-z0-9]{36}',
        'GitHub App Token': r'ghs_[A-Za-z0-9]{36}',
        'GitHub Refresh Token': r'ghr_[A-Za-z0-9]{36}',
        'GitHub Fine-Grained PAT': r'github_pat_[A-Za-z0-9_]{22,82}',

        # GitLab - specific prefix
        'GitLab Token': r'glpat-[A-Za-z0-9\-_]{20,}',
        'GitLab Pipeline Token': r'glptt-[A-Za-z0-9\-_]{20,}',
        'GitLab Runner Token': r'glrt-[A-Za-z0-9\-_]{20,}',
        'GitLab OAuth': r'gloas-[A-Za-z0-9\-_]{20,}',
        'GitLab SCIM': r'glsoat-[A-Za-z0-9\-_]{20,}',

        # Bitbucket
        'Bitbucket App Password': r'ATBB[A-Za-z0-9_]{32}',

        # ===== CI/CD =====
        # CircleCI
        'CircleCI Token': r'circle-token-[a-f0-9]{40}',

        # Travis CI
        'Travis CI Token': r'travis-ci-[a-zA-Z0-9]{20,}',

        # Jenkins
        'Jenkins API Token': r'[a-f0-9]{32}',  # Only in jenkins context

        # Buildkite
        'Buildkite Agent Token': r'bk[a-zA-Z0-9_-]{40,}',

        # ===== COMMUNICATION =====
        # Slack - specific format
        'Slack Token': r'xox[pborsa]-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24,}',
        'Slack Webhook': r'https://hooks\.slack\.com/services/T[a-zA-Z0-9_]+/B[a-zA-Z0-9_]+/[a-zA-Z0-9_]{24}',
        'Slack App Token': r'xapp-[0-9]-[A-Z0-9]+-[0-9]+-[a-zA-Z0-9]+',
        'Slack Config Token': r'xoxe\.xox[bp]-[0-9]-[A-Z0-9]+-[0-9]+-[a-zA-Z0-9]+',

        # Discord
        'Discord Bot Token': r'[MN][A-Za-z0-9]{23,}\.[A-Za-z0-9_-]{6}\.[A-Za-z0-9_-]{27,}',
        'Discord Webhook': r'https://discord(?:app)?\.com/api/webhooks/[0-9]+/[A-Za-z0-9_-]+',

        # Telegram
        'Telegram Bot Token': r'[0-9]{8,10}:[A-Za-z0-9_-]{35}',

        # Microsoft Teams
        'Teams Webhook': r'https://[a-z0-9]+\.webhook\.office\.com/webhookb2/[a-f0-9-]+@[a-f0-9-]+/IncomingWebhook/[a-zA-Z0-9]+/[a-f0-9-]+',

        # ===== PAYMENT PROCESSORS =====
        # Stripe - SECRET keys only (sk_live), NOT publishable
        'Stripe Secret Key': r'sk_live_[0-9a-zA-Z]{24,}',
        'Stripe Restricted Key': r'rk_live_[0-9a-zA-Z]{24,}',

        # PayPal
        'PayPal Client Secret': r'E[A-Za-z0-9_-]{60,80}',  # Only in paypal context

        # Square
        'Square Access Token': r'sq0atp-[A-Za-z0-9_-]{22}',
        'Square OAuth': r'sq0csp-[A-Za-z0-9_-]{43}',

        # Braintree
        'Braintree Access Token': r'access_token\$production\$[0-9a-z]{16}\$[0-9a-f]{32}',

        # ===== EMAIL/SMS SERVICES =====
        # Twilio - specific prefixes
        'Twilio API Key': r'SK[a-f0-9]{32}',
        'Twilio Account SID': r'AC[a-f0-9]{32}',

        # SendGrid - very specific format
        'SendGrid API Key': r'SG\.[a-zA-Z0-9_\-]{22}\.[a-zA-Z0-9_\-]{43}',

        # Mailgun - specific prefix
        'Mailgun API Key': r'key-[0-9a-zA-Z]{32}',

        # Mailchimp
        'Mailchimp API Key': r'[a-f0-9]{32}-us[0-9]{1,2}',

        # Postmark
        'Postmark Server Token': r'[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}',  # in postmark context

        # ===== MONITORING/LOGGING =====
        # Datadog
        'Datadog API Key': r'dd[a-z]{1,2}_[a-zA-Z0-9]{32,40}',

        # New Relic
        'New Relic API Key': r'NRAK-[A-Z0-9]{27}',
        'New Relic License Key': r'[a-fA-F0-9]{40}NRAL',

        # Sentry
        'Sentry DSN': r'https://[a-f0-9]{32}@[a-z0-9.]+\.ingest\.sentry\.io/[0-9]+',

        # Splunk
        'Splunk HEC Token': r'Splunk [a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}',

        # PagerDuty
        'PagerDuty API Key': r'[uU]\+[a-zA-Z0-9_-]{18}',

        # ===== PACKAGE MANAGERS =====
        # NPM - specific prefix
        'NPM Token': r'npm_[A-Za-z0-9]{36}',
        'NPM Publish Token': r'//registry\.npmjs\.org/:_authToken=[A-Za-z0-9-_]+',

        # PyPI
        'PyPI Token': r'pypi-AgEIcHlwaS5vcmc[A-Za-z0-9-_]{70,}',

        # RubyGems
        'RubyGems API Key': r'rubygems_[a-f0-9]{48}',

        # NuGet
        'NuGet API Key': r'oy2[a-z0-9]{43}',

        # ===== DATABASE =====
        # Database URLs WITH credentials embedded (username:password@)
        'Database URL with Auth': r'(?:mysql|postgresql|postgres|mongodb|mongodb\+srv|redis|amqp|mssql)://[^:]+:[^@]+@[^\s\'"<>]+',

        # Firebase
        'Firebase Cloud Messaging': r'AAAA[A-Za-z0-9_-]{7}:[A-Za-z0-9_-]{140}',
        'Firebase Database URL': r'https://[a-z0-9-]+\.firebaseio\.com',

        # ===== SOCIAL/AUTH =====
        # Auth0
        'Auth0 Client Secret': r'[A-Za-z0-9_-]{64}',  # Only in auth0 context

        # Okta
        'Okta API Token': r'00[A-Za-z0-9_-]{40}',

        # Facebook/Meta
        'Facebook App Secret': r'[a-f0-9]{32}',  # Only in facebook context

        # Twitter/X
        'Twitter Bearer Token': r'AAAAAAAAAAAAAAAAAAA[A-Za-z0-9%]+',

        # LinkedIn
        'LinkedIn Client Secret': r'[A-Za-z0-9]{16}',  # Only in linkedin context

        # ===== OTHER SERVICES =====
        # Shopify
        'Shopify Access Token': r'shpat_[a-f0-9]{32}',
        'Shopify Shared Secret': r'shpss_[a-f0-9]{32}',
        'Shopify Private App': r'shppa_[a-f0-9]{32}',
        'Shopify Custom App': r'shpca_[a-f0-9]{32}',

        # Heroku
        'Heroku API Key': r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}',  # in heroku context

        # Vercel
        'Vercel Token': r'[A-Za-z0-9]{24}',  # Only in vercel context

        # Netlify
        'Netlify Access Token': r'[A-Za-z0-9_-]{40,50}',  # Only in netlify context

        # Algolia
        'Algolia Admin Key': r'[a-f0-9]{32}',  # Only in algolia context

        # Mapbox
        'Mapbox Secret Token': r'sk\.[a-zA-Z0-9]{60,}',

        # Cloudinary
        'Cloudinary URL': r'cloudinary://[0-9]+:[A-Za-z0-9_-]+@[a-z0-9-]+',

        # Zendesk
        'Zendesk API Token': r'[A-Za-z0-9]{40}',  # Only in zendesk context

        # HubSpot
        'HubSpot API Key': r'pat-[a-z]{2,}-[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}',

        # Intercom
        'Intercom Access Token': r'dG9rO[a-zA-Z0-9_-]{40,}',

        # Asana
        'Asana Personal Token': r'[0-9]/[0-9]{16}:[A-Za-z0-9]{32}',

        # Atlassian
        'Atlassian API Token': r'[A-Za-z0-9]{24}',  # Only in atlassian context

        # ===== PRIVATE KEYS & CERTS =====
        # Private Keys - very specific
        'Private Key': r'-----BEGIN (?:RSA |DSA |EC |OPENSSH |PGP )?PRIVATE KEY-----',
        'Encrypted Private Key': r'-----BEGIN ENCRYPTED PRIVATE KEY-----',
        'Certificate': r'-----BEGIN CERTIFICATE-----',
        'PGP Private Key Block': r'-----BEGIN PGP PRIVATE KEY BLOCK-----',

        # ===== CREDENTIALS =====
        # URLs with embedded credentials
        'URL with Credentials': r'https?://[a-zA-Z0-9_]+:[a-zA-Z0-9_!@#$%^&*]+@[a-zA-Z0-9\-\.]+',

        # Password in config patterns
        'Password Assignment': r'(?:password|passwd|pwd|secret|api_key|apikey|access_token|auth_token)\s*[=:]\s*[\'"][^\'"]{8,}[\'"]',

        # Basic Auth Header
        'Basic Auth Header': r'[Aa]uthorization:\s*Basic\s+[A-Za-z0-9+/=]{20,}',
        'Bearer Token Header': r'[Aa]uthorization:\s*Bearer\s+[A-Za-z0-9._-]{20,}',
    }

    def __init__(self, module_path: str, payload_limit: int = None):
        """Initialize Environment Files scanner"""
        super().__init__(module_path, payload_limit=payload_limit)

        # Compile regex patterns for performance
        self.compiled_patterns = {
            name: re.compile(pattern)
            for name, pattern in self.API_KEY_PATTERNS.items()
        }

        logger.info(f"Environment Files scanner loaded: {len(self.payloads)} files, {len(self.compiled_patterns)} API key patterns")

    def scan(self, targets: List[Dict[str, Any]], http_client: Any) -> List[Dict[str, Any]]:
        """
        Scan for exposed environment files and API keys

        Args:
            targets: List of URLs
            http_client: HTTP client

        Returns:
            List of results
        """
        results = []

        logger.info(f"Starting Environment Files & API Keys scan")

        # Extract unique base URLs
        base_urls = set()
        for target in targets:
            url = target.get('url')
            if not url:
                continue

            parsed = urlparse(url)
            base_url = f"{parsed.scheme}://{parsed.netloc}/"
            base_urls.add(base_url)

            # Also check parent directories
            path = parsed.path.rstrip('/')
            if path:
                path_parts = path.split('/')
                for i in range(1, len(path_parts)):
                    dir_path = '/'.join(path_parts[:i]) + '/'
                    dir_url = f"{parsed.scheme}://{parsed.netloc}{dir_path}"
                    base_urls.add(dir_url)

        logger.info(f"Testing {len(base_urls)} base URLs for exposed files")

        # Test each base URL
        for base_url in list(base_urls)[:20]:  # Limit to 20
            logger.debug(f"Testing env files: {base_url}")

            # Test environment file paths
            for env_file in self.get_limited_payloads():  # Test top 30 files
                test_url = urljoin(base_url, env_file.strip())

                try:
                    response = http_client.get(test_url)

                    if not response:
                        continue

                    # Check if file is accessible
                    if response.status_code == 200:
                        content = getattr(response, 'text', '')

                        # Validate it's actually an env/config file
                        if self._validate_env_file(content, env_file):
                            # Scan content for API keys
                            found_secrets = self._scan_for_secrets(content)

                            if found_secrets or self._is_sensitive_file(env_file):
                                severity = 'Critical' if found_secrets else 'High'
                                confidence = 0.95 if found_secrets else 0.80

                                # Build evidence with ACTUAL password values (user requested this)
                                evidence = f"Exposed file at: {test_url}\n"
                                evidence += f"File size: {len(content)} bytes\n\n"

                                if found_secrets:
                                    evidence += "=" * 60 + "\n"
                                    evidence += f"FOUND {len(found_secrets)} HARDCODED SECRETS:\n"
                                    evidence += "=" * 60 + "\n\n"

                                    for i, (name, value) in enumerate(found_secrets[:10], 1):
                                        evidence += f"[{i}] {name}\n"
                                        evidence += f"    Value: {value}\n"
                                        evidence += f"    Length: {len(value)} chars\n"
                                        evidence += "-" * 60 + "\n"

                                    if len(found_secrets) > 10:
                                        evidence += f"\n... and {len(found_secrets) - 10} more secrets\n"
                                else:
                                    evidence += f"Sensitive configuration file exposed"

                                result = self.create_result(
                                    vulnerable=True,
                                    url=test_url,
                                    payload=env_file,
                                    evidence=evidence,
                                    description=f"Exposed environment/configuration file: {env_file}. " +
                                              (f"Contains {len(found_secrets)} API keys/secrets" if found_secrets else "May contain sensitive configuration"),
                                    confidence=confidence
                                )

                                result['severity'] = severity
                                result['cwe'] = self.config.get('cwe')
                                result['owasp'] = self.config.get('owasp')
                                result['cvss'] = self.config.get('cvss')
                                result['secrets_found'] = len(found_secrets)
                                result['secret_types'] = [name for name, _ in found_secrets]

                                results.append(result)
                                logger.info(f"✓ Exposed file found: {test_url} ({len(found_secrets)} secrets)")
                                break  # Don't test more files for this URL

                except Exception as e:
                    logger.debug(f"Error testing {test_url}: {e}")

        logger.info(f"Environment Files scan complete: {len(results)} exposures found")
        return results

    def _validate_env_file(self, content: str, filename: str) -> bool:
        """Validate if content looks like an env/config file"""
        if not content or len(content) < 10:
            return False

        # Check for env file patterns
        env_patterns = [
            r'^\w+=[^\s]',  # KEY=value
            r'[\'\"]:\s*[\'\"]',  # JSON "key": "value"
            r'^\w+:',  # YAML key:
            r'^\[\w+\]',  # INI [section]
        ]

        for pattern in env_patterns:
            if re.search(pattern, content, re.MULTILINE):
                return True

        # Check if it looks like a config file based on filename
        config_extensions = ['.env', '.json', '.yml', '.yaml', '.xml', '.ini', '.config']
        if any(filename.endswith(ext) for ext in config_extensions):
            return True

        return False

    def _is_sensitive_file(self, filename: str) -> bool:
        """Check if filename is inherently sensitive"""
        sensitive = ['.env', 'credentials', 'secrets', 'api_keys', 'token', 'password',
                    'private', '.aws', '.ssh', 'id_rsa', '.htpasswd']
        return any(s in filename.lower() for s in sensitive)

    def _scan_for_secrets(self, content: str) -> List[Tuple[str, str]]:
        """
        Scan content for API keys and secrets using regex patterns

        Returns:
            List of (secret_type, secret_value) tuples
        """
        found_secrets = []

        for name, pattern in self.compiled_patterns.items():
            matches = pattern.findall(content)

            for match in matches:
                # Extract the actual secret value (handle tuple results from groups)
                if isinstance(match, tuple):
                    secret = match[0] if match[0] else match[-1]
                else:
                    secret = match

                # Skip obvious false positives (pass content for context validation)
                if self._is_false_positive(secret, name, content):
                    continue

                # Mask the secret for logging
                found_secrets.append((name, secret))

        return found_secrets

    # Patterns that require context validation (to avoid FPs on generic patterns)
    CONTEXT_REQUIRED_PATTERNS = {
        'Azure AD Client Secret': ['azure', 'client_secret', 'aad', 'tenant'],
        'PayPal Client Secret': ['paypal', 'client_secret'],
        'Jenkins API Token': ['jenkins', 'api_token', 'crumb'],
        'Postmark Server Token': ['postmark', 'server_token', 'x-postmark'],
        'Auth0 Client Secret': ['auth0', 'client_secret'],
        'Facebook App Secret': ['facebook', 'fb_', 'app_secret', 'fb_secret'],
        'LinkedIn Client Secret': ['linkedin', 'li_'],
        'Heroku API Key': ['heroku', 'heroku_api'],
        'Vercel Token': ['vercel', 'vercel_token'],
        'Netlify Access Token': ['netlify'],
        'Algolia Admin Key': ['algolia', 'algoliasearch'],
        'Zendesk API Token': ['zendesk'],
        'Atlassian API Token': ['atlassian', 'jira', 'confluence'],
    }

    def _is_false_positive(self, value: str, pattern_name: str, content: str = '') -> bool:
        """Check if detected secret is a false positive"""
        # Skip example/placeholder values
        placeholders = [
            'example', 'placeholder', 'your_', 'insert_', 'replace_',
            'xxxxxxxx', '12345678', 'abcdefgh', 'test_key', 'sample_',
            'demo_', 'fake_', 'null', 'none', 'undefined', 'xxx',
            'change_me', 'todo', 'fixme', 'enter_', 'put_', 'add_',
            'my_key', 'your_key', 'secret_here', 'token_here',
            'api_key_here', 'key_goes_here', 'paste_', '<your',
            '${', '{{', '%{', 'process.env', 'os.environ', 'getenv',
            'dummy', 'mock', 'stub', 'template', 'default'
        ]

        value_lower = value.lower()
        if any(p in value_lower for p in placeholders):
            return True

        # Skip too short values (except for specific patterns)
        if len(value) < 8 and 'Account ID' not in pattern_name:
            return True

        # Skip values that are just repeated characters
        if len(set(value)) < 4:
            return True

        # Skip values that are all the same character
        if len(set(value.replace('-', '').replace('_', ''))) < 3:
            return True

        # Context validation for generic patterns
        if pattern_name in self.CONTEXT_REQUIRED_PATTERNS:
            context_keywords = self.CONTEXT_REQUIRED_PATTERNS[pattern_name]
            content_lower = content.lower()
            if not any(kw in content_lower for kw in context_keywords):
                return True

        # Skip common UUID false positives (unless in specific context)
        if re.match(r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$', value, re.I):
            # UUIDs are only secrets in specific contexts
            uuid_secret_contexts = ['heroku', 'postmark', 'splunk']
            if pattern_name not in ['Heroku API Key', 'Postmark Server Token', 'Splunk HEC Token']:
                return True

        # Skip documentation/readme patterns
        doc_indicators = ['example:', 'e.g.', 'for example', 'sample:', 'usage:',
                          '# TODO', '// TODO', '/* TODO', 'README', 'documentation']
        if any(ind in content[:500].lower() for ind in doc_indicators):
            # More strict validation for docs
            if value.count('x') > 3 or value.count('0') > len(value) // 2:
                return True

        return False


def get_module(module_path: str, payload_limit: int = None):
    """Create module instance"""
    return EnvSecretsModule(module_path, payload_limit=payload_limit)
