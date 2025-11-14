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

    # Comprehensive API key regex patterns
    API_KEY_PATTERNS = {
        # AWS
        'AWS Access Key': r'(?:A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}',
        'AWS Secret Key': r'(?i)aws(.{0,20})?[\'\"][0-9a-zA-Z\/+]{40}[\'\"]',
        'AWS Account ID': r'[0-9]{12}',

        # Google
        'Google API Key': r'AIza[0-9A-Za-z\\-_]{35}',
        'Google Cloud Platform API Key': r'(?i)(?:gcp|google|gcloud)(.{0,20})?[\'\"][0-9a-zA-Z\\-_]{20,}[\'\"]',
        'Google OAuth': r'[0-9]+-[0-9A-Za-z_]{32}\\.apps\\.googleusercontent\\.com',
        'Google OAuth Secret': r'(?i)client_secret[\'\"]?\\s*[:=]\\s*[\'\"]([0-9A-Za-z\\-_]{24})[\'\"]',

        # GitHub
        'GitHub Token': r'gh[pousr]_[A-Za-z0-9_]{36,}',
        'GitHub OAuth': r'gho_[A-Za-z0-9_]{36}',
        'GitHub App Token': r'(?i)github(.{0,20})?[\'\"]([a-zA-Z0-9]{35,40})[\'\"]',
        'GitHub Personal Access Token': r'ghp_[A-Za-z0-9]{36}',

        # GitLab
        'GitLab Token': r'glpat-[A-Za-z0-9\\-_]{20}',

        # Slack
        'Slack Token': r'xox[pborsa]-[0-9]{12}-[0-9]{12}-[0-9]{12}-[a-z0-9]{32}',
        'Slack Webhook': r'https://hooks\\.slack\\.com/services/T[a-zA-Z0-9_]{8}/B[a-zA-Z0-9_]{8}/[a-zA-Z0-9_]{24}',

        # Stripe
        'Stripe API Key': r'(?i)stripe(.{0,20})?[\'\"]([sr]k_live_[0-9a-zA-Z]{24,})[\'\"]',
        'Stripe Test Key': r'(?i)stripe(.{0,20})?[\'\"]([sr]k_test_[0-9a-zA-Z]{24,})[\'\"]',

        # Twilio
        'Twilio API Key': r'SK[a-z0-9]{32}',
        'Twilio Account SID': r'AC[a-z0-9]{32}',

        # SendGrid
        'SendGrid API Key': r'SG\\.[a-zA-Z0-9_\\-]{22}\\.[a-zA-Z0-9_\\-]{43}',

        # Mailgun
        'Mailgun API Key': r'key-[0-9a-zA-Z]{32}',

        # Azure
        'Azure Storage Account Key': r'(?i)(?:azure|storage)(.{0,20})?[\'\"][0-9a-zA-Z\/+]{86}==[\'\"]',

        # Heroku
        'Heroku API Key': r'[h|H][e|E][r|R][o|O][k|K][u|U].*[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}',

        # Facebook
        'Facebook Access Token': r'EAACEdEose0cBA[0-9A-Za-z]+',
        'Facebook OAuth': r'(?i)facebook(.{0,20})?[\'\"][0-9a-f]{32}[\'\"]',

        # Twitter
        'Twitter API Key': r'(?i)twitter(.{0,20})?[\'\"][0-9a-zA-Z]{35,44}[\'\"]',
        'Twitter OAuth': r'[t|T][w|W][i|I][t|T][t|T][e|E][r|R].*[1-9][0-9]+-[0-9a-zA-Z]{40}',

        # NPM
        'NPM Token': r'npm_[A-Za-z0-9]{36}',

        # PyPI
        'PyPI Token': r'pypi-AgEIcHlwaS5vcmc[A-Za-z0-9\\-_]{50,}',

        # Docker
        'Docker Auth': r'(?i)docker(.{0,20})?[\'\"]([a-zA-Z0-9]{40})[\'\"]',

        # Generic patterns
        'Generic API Key': r'(?i)api[_\\-]?key[\'\"]?\\s*[:=]\\s*[\'\"]([a-zA-Z0-9_\\-]{20,})[\'\"]',
        'Generic Secret': r'(?i)secret[\'\"]?\\s*[:=]\\s*[\'\"]([a-zA-Z0-9_\\-]{20,})[\'\"]',
        'Generic Token': r'(?i)token[\'\"]?\\s*[:=]\\s*[\'\"]([a-zA-Z0-9_\\-\\.]{20,})[\'\"]',
        'Generic Password': r'(?i)password[\'\"]?\\s*[:=]\\s*[\'\"]([^\\s\'\"]{8,})[\'\"]',
        'Private Key': r'-----BEGIN (?:RSA |DSA |EC )?PRIVATE KEY-----',
        'JWT Token': r'eyJ[A-Za-z0-9_-]*\\.[A-Za-z0-9_-]*\\.[A-Za-z0-9_-]*',

        # Database connection strings
        'Database URL': r'(?i)(mysql|postgresql|mongodb|redis)://[^\\s\'\"]+',
        'Connection String': r'(?i)(?:server|host|data source)=([^;\'\"\\s]+)',

        # URLs with embedded credentials
        'URL with Credentials': r'(?i)https?://[a-zA-Z0-9_]+:[a-zA-Z0-9_]+@[a-zA-Z0-9\\-\\.]+',
    }

    def __init__(self, module_path: str):
        """Initialize Environment Files scanner"""
        super().__init__(module_path)

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
            for env_file in self.payloads[:30]:  # Test top 30 files
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

                # Skip obvious false positives
                if self._is_false_positive(secret, name):
                    continue

                # Mask the secret for logging
                found_secrets.append((name, secret))

        return found_secrets

    def _is_false_positive(self, value: str, pattern_name: str) -> bool:
        """Check if detected secret is a false positive"""
        # Skip example/placeholder values
        placeholders = [
            'example', 'placeholder', 'your_', 'insert_', 'replace_',
            'xxxxxxxx', '12345678', 'abcdefgh', 'test_key', 'sample_',
            'demo_', 'fake_', 'null', 'none', 'undefined'
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

        return False


def get_module(module_path: str):
    """Create module instance"""
    return EnvSecretsModule(module_path)
