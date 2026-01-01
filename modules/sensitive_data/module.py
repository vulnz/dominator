"""
Sensitive Data Detection Scanner
Detects exposed PII, credentials, and sensitive information in responses
"""

from core.base_module import BaseModule
from core.logger import get_logger
from typing import List, Dict, Any
from urllib.parse import urlparse
import re

logger = get_logger(__name__)


class SensitiveDataScanner(BaseModule):
    """Scans for exposed sensitive data in web responses"""

    def __init__(self, module_path: str, payload_limit: int = None):
        super().__init__(module_path, payload_limit=payload_limit)
        self.module_name = "Sensitive Data Scanner"
        self.logger = logger

        # Sensitive data patterns - COMPREHENSIVE with high-confidence patterns
        # Only patterns that indicate real security issues
        self.patterns = {
            # ===== CREDIT CARDS =====
            # Credit card numbers - validated by Luhn algorithm
            'credit_card_visa': {
                'pattern': r'\b4[0-9]{3}[-\s]?[0-9]{4}[-\s]?[0-9]{4}[-\s]?[0-9]{4}\b',
                'severity': 'Critical',
                'description': 'Visa credit card number exposed',
                'cwe': 'CWE-311'
            },
            'credit_card_mastercard': {
                'pattern': r'\b5[1-5][0-9]{2}[-\s]?[0-9]{4}[-\s]?[0-9]{4}[-\s]?[0-9]{4}\b',
                'severity': 'Critical',
                'description': 'Mastercard credit card number exposed',
                'cwe': 'CWE-311'
            },
            'credit_card_amex': {
                'pattern': r'\b3[47][0-9]{2}[-\s]?[0-9]{6}[-\s]?[0-9]{5}\b',
                'severity': 'Critical',
                'description': 'American Express card number exposed',
                'cwe': 'CWE-311'
            },
            'credit_card_discover': {
                'pattern': r'\b6(?:011|5[0-9]{2})[-\s]?[0-9]{4}[-\s]?[0-9]{4}[-\s]?[0-9]{4}\b',
                'severity': 'Critical',
                'description': 'Discover card number exposed',
                'cwe': 'CWE-311'
            },
            'credit_card_cvv': {
                'pattern': r'(?:cvv|cvc|csc|cvv2|cvc2)\s*[=:]\s*["\']?\d{3,4}["\']?',
                'severity': 'Critical',
                'description': 'Card CVV/CVC code exposed',
                'cwe': 'CWE-311'
            },

            # ===== CLOUD PROVIDER KEYS =====
            # AWS Access Key - very specific pattern
            'aws_access_key': {
                'pattern': r'\b(?:A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}\b',
                'severity': 'Critical',
                'description': 'AWS Access Key ID exposed',
                'cwe': 'CWE-798'
            },
            'gcp_service_account': {
                'pattern': r'"type"\s*:\s*"service_account"',
                'severity': 'Critical',
                'description': 'GCP Service Account key exposed',
                'cwe': 'CWE-798'
            },
            'azure_storage_key': {
                'pattern': r'DefaultEndpointsProtocol=https;AccountName=[^;]+;AccountKey=[A-Za-z0-9+/=]{86,88};',
                'severity': 'Critical',
                'description': 'Azure Storage connection string exposed',
                'cwe': 'CWE-798'
            },

            # ===== VERSION CONTROL TOKENS =====
            # GitHub token - very specific pattern
            'github_token': {
                'pattern': r'\b(ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{36,}\b',
                'severity': 'Critical',
                'description': 'GitHub token exposed',
                'cwe': 'CWE-798'
            },
            'github_fine_grained_pat': {
                'pattern': r'\bgithub_pat_[A-Za-z0-9_]{22,82}\b',
                'severity': 'Critical',
                'description': 'GitHub Fine-Grained PAT exposed',
                'cwe': 'CWE-798'
            },
            'gitlab_token': {
                'pattern': r'\bglpat-[A-Za-z0-9\-_]{20,}\b',
                'severity': 'Critical',
                'description': 'GitLab token exposed',
                'cwe': 'CWE-798'
            },
            'bitbucket_token': {
                'pattern': r'\bATBB[A-Za-z0-9_]{32}\b',
                'severity': 'Critical',
                'description': 'Bitbucket App Password exposed',
                'cwe': 'CWE-798'
            },

            # ===== COMMUNICATION SERVICES =====
            'slack_token': {
                'pattern': r'\bxox[pborsa]-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24,}\b',
                'severity': 'Critical',
                'description': 'Slack token exposed',
                'cwe': 'CWE-798'
            },
            'slack_webhook': {
                'pattern': r'https://hooks\.slack\.com/services/T[a-zA-Z0-9_]+/B[a-zA-Z0-9_]+/[a-zA-Z0-9_]{24}',
                'severity': 'High',
                'description': 'Slack webhook URL exposed',
                'cwe': 'CWE-200'
            },
            'discord_token': {
                'pattern': r'[MN][A-Za-z0-9]{23,}\.[A-Za-z0-9_-]{6}\.[A-Za-z0-9_-]{27,}',
                'severity': 'Critical',
                'description': 'Discord bot token exposed',
                'cwe': 'CWE-798'
            },
            'discord_webhook': {
                'pattern': r'https://discord(?:app)?\.com/api/webhooks/[0-9]+/[A-Za-z0-9_-]+',
                'severity': 'High',
                'description': 'Discord webhook URL exposed',
                'cwe': 'CWE-200'
            },
            'telegram_token': {
                'pattern': r'\b[0-9]{8,10}:[A-Za-z0-9_-]{35}\b',
                'severity': 'Critical',
                'description': 'Telegram bot token exposed',
                'cwe': 'CWE-798'
            },

            # ===== PAYMENT SERVICES =====
            'stripe_secret_key': {
                'pattern': r'\bsk_live_[0-9a-zA-Z]{24,}\b',
                'severity': 'Critical',
                'description': 'Stripe secret key exposed',
                'cwe': 'CWE-798'
            },
            'stripe_restricted_key': {
                'pattern': r'\brk_live_[0-9a-zA-Z]{24,}\b',
                'severity': 'Critical',
                'description': 'Stripe restricted key exposed',
                'cwe': 'CWE-798'
            },
            'square_access_token': {
                'pattern': r'\bsq0atp-[A-Za-z0-9_-]{22}\b',
                'severity': 'Critical',
                'description': 'Square access token exposed',
                'cwe': 'CWE-798'
            },
            'braintree_token': {
                'pattern': r'access_token\$production\$[0-9a-z]{16}\$[0-9a-f]{32}',
                'severity': 'Critical',
                'description': 'Braintree access token exposed',
                'cwe': 'CWE-798'
            },

            # ===== EMAIL/SMS SERVICES =====
            'twilio_api_key': {
                'pattern': r'\bSK[a-f0-9]{32}\b',
                'severity': 'Critical',
                'description': 'Twilio API key exposed',
                'cwe': 'CWE-798'
            },
            'sendgrid_key': {
                'pattern': r'\bSG\.[a-zA-Z0-9_\-]{22}\.[a-zA-Z0-9_\-]{43}\b',
                'severity': 'Critical',
                'description': 'SendGrid API key exposed',
                'cwe': 'CWE-798'
            },
            'mailgun_key': {
                'pattern': r'\bkey-[0-9a-zA-Z]{32}\b',
                'severity': 'Critical',
                'description': 'Mailgun API key exposed',
                'cwe': 'CWE-798'
            },
            'mailchimp_key': {
                'pattern': r'\b[a-f0-9]{32}-us[0-9]{1,2}\b',
                'severity': 'High',
                'description': 'Mailchimp API key exposed',
                'cwe': 'CWE-798'
            },

            # ===== PRIVATE KEYS & CERTIFICATES =====
            'private_key': {
                'pattern': r'-----BEGIN (RSA |DSA |EC |OPENSSH |PGP )?PRIVATE KEY-----',
                'severity': 'Critical',
                'description': 'Private key exposed',
                'cwe': 'CWE-321'
            },
            'encrypted_private_key': {
                'pattern': r'-----BEGIN ENCRYPTED PRIVATE KEY-----',
                'severity': 'High',
                'description': 'Encrypted private key exposed',
                'cwe': 'CWE-321'
            },
            'pgp_private_key': {
                'pattern': r'-----BEGIN PGP PRIVATE KEY BLOCK-----',
                'severity': 'Critical',
                'description': 'PGP private key exposed',
                'cwe': 'CWE-321'
            },

            # ===== DATABASE CONNECTIONS =====
            'db_connection_with_auth': {
                'pattern': r'(?i)(mongodb|mongodb\+srv|mysql|postgresql|postgres|redis|amqp|mssql)://[^:]+:[^@]+@[^\s\'\"<>]+',
                'severity': 'Critical',
                'description': 'Database connection string with credentials exposed',
                'cwe': 'CWE-200'
            },

            # ===== PACKAGE MANAGERS =====
            'npm_token': {
                'pattern': r'\bnpm_[A-Za-z0-9]{36}\b',
                'severity': 'Critical',
                'description': 'NPM token exposed',
                'cwe': 'CWE-798'
            },
            'pypi_token': {
                'pattern': r'pypi-AgEIcHlwaS5vcmc[A-Za-z0-9-_]{70,}',
                'severity': 'Critical',
                'description': 'PyPI token exposed',
                'cwe': 'CWE-798'
            },
            'rubygems_key': {
                'pattern': r'\brubygems_[a-f0-9]{48}\b',
                'severity': 'Critical',
                'description': 'RubyGems API key exposed',
                'cwe': 'CWE-798'
            },

            # ===== MONITORING/LOGGING =====
            'sentry_dsn': {
                'pattern': r'https://[a-f0-9]{32}@[a-z0-9.]+\.ingest\.sentry\.io/[0-9]+',
                'severity': 'High',
                'description': 'Sentry DSN exposed',
                'cwe': 'CWE-200'
            },
            'datadog_key': {
                'pattern': r'\bdd[a-z]{1,2}_[a-zA-Z0-9]{32,40}\b',
                'severity': 'Critical',
                'description': 'Datadog API key exposed',
                'cwe': 'CWE-798'
            },
            'newrelic_key': {
                'pattern': r'\bNRAK-[A-Z0-9]{27}\b',
                'severity': 'Critical',
                'description': 'New Relic API key exposed',
                'cwe': 'CWE-798'
            },

            # ===== OTHER TOKENS =====
            'shopify_token': {
                'pattern': r'\bshp(at|ss|pa|ca)_[a-f0-9]{32}\b',
                'severity': 'Critical',
                'description': 'Shopify token exposed',
                'cwe': 'CWE-798'
            },
            'digitalocean_token': {
                'pattern': r'\bdo[por]_v1_[a-f0-9]{64}\b',
                'severity': 'Critical',
                'description': 'DigitalOcean token exposed',
                'cwe': 'CWE-798'
            },
            'firebase_key': {
                'pattern': r'\bAAAA[A-Za-z0-9_-]{7}:[A-Za-z0-9_-]{140}\b',
                'severity': 'Critical',
                'description': 'Firebase Cloud Messaging key exposed',
                'cwe': 'CWE-798'
            },
            'hubspot_key': {
                'pattern': r'\bpat-[a-z]{2,}-[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}\b',
                'severity': 'High',
                'description': 'HubSpot API key exposed',
                'cwe': 'CWE-798'
            },

            # ===== CREDENTIALS =====
            'basic_auth_header': {
                'pattern': r'[Aa]uthorization:\s*Basic\s+[A-Za-z0-9+/=]{20,}',
                'severity': 'Critical',
                'description': 'Basic Auth header with credentials exposed',
                'cwe': 'CWE-798'
            },
            'bearer_token_header': {
                'pattern': r'[Aa]uthorization:\s*Bearer\s+[A-Za-z0-9._-]{20,}',
                'severity': 'High',
                'description': 'Bearer token in header exposed',
                'cwe': 'CWE-798'
            },
            'password_in_url': {
                'pattern': r'https?://[a-zA-Z0-9_]+:[a-zA-Z0-9_!@#$%^&*]+@[a-zA-Z0-9\-\.]+',
                'severity': 'Critical',
                'description': 'Password exposed in URL',
                'cwe': 'CWE-798'
            },
            'hardcoded_password': {
                'pattern': r'(?:password|passwd|pwd)\s*[=:]\s*[\'"][^\'"]{8,64}[\'"]',
                'severity': 'High',
                'description': 'Hardcoded password detected',
                'cwe': 'CWE-798'
            },
        }

        # SRI integrity attribute pattern (to exclude from hash detection)
        self.sri_pattern = r'integrity\s*=\s*[\'"]sha(256|384|512)-[A-Za-z0-9+/=]+'

    def scan(self, targets: List[Dict[str, Any]], http_client: Any = None) -> List[Dict[str, Any]]:
        """Scan for sensitive data exposure"""
        self.logger.info(f"Starting {self.module_name} scan on {len(targets)} targets")

        results = []
        tested_urls = set()

        for target in targets:
            url = target.get('url') if isinstance(target, dict) else target
            if not url:
                continue

            if url in tested_urls:
                continue
            tested_urls.add(url)

            findings = self._scan_page(http_client, url)
            results.extend(findings)

            if self.payload_limit and len(results) >= self.payload_limit:
                break

        self.logger.info(f"{self.module_name} scan complete: {len(results)} findings")
        return results

    def _scan_page(self, http_client, url: str) -> List[Dict[str, Any]]:
        """Scan a single page for sensitive data"""
        results = []

        try:
            response = http_client.get(url)
            if not response or response.status_code != 200:
                return results

            content = response.text
            if not content or len(content) < 20:
                return results

            # Find all SRI hashes to exclude
            sri_hashes = set()
            for match in re.finditer(self.sri_pattern, content):
                # Extract the hash portion
                hash_match = re.search(r'-([A-Za-z0-9+/=]{43,128})', match.group())
                if hash_match:
                    sri_hashes.add(hash_match.group(1))

            # Scan for each pattern type
            findings_by_type = {}

            for data_type, config in self.patterns.items():
                matches = re.findall(config['pattern'], content)

                # Filter matches
                filtered_matches = []
                for match in matches:
                    # Skip SRI integrity hashes
                    if data_type.endswith('_hash'):
                        if match in sri_hashes or self._is_sri_context(content, match):
                            continue

                    # Validate and filter false positives
                    if self._validate_match(data_type, match, content):
                        filtered_matches.append(match)

                if filtered_matches:
                    # Deduplicate
                    unique_matches = list(set(filtered_matches))[:10]
                    findings_by_type[data_type] = {
                        'matches': unique_matches,
                        'config': config
                    }

            # Create results grouped by severity using dict comprehension
            findings_by_severity = {
                sev: {k: v for k, v in findings_by_type.items() if v['config']['severity'] == sev}
                for sev in ('Critical', 'High', 'Medium', 'Low')
            }
            critical_findings, high_findings = findings_by_severity['Critical'], findings_by_severity['High']
            medium_findings, low_findings = findings_by_severity['Medium'], findings_by_severity['Low']

            # Report critical findings individually
            for data_type, data in critical_findings.items():
                results.append(self._create_finding(url, data_type, data))

            # Report high findings individually
            for data_type, data in high_findings.items():
                results.append(self._create_finding(url, data_type, data))

            # Group medium findings
            if medium_findings:
                all_hashes = []
                for data_type, data in medium_findings.items():
                    all_hashes.extend(data['matches'][:5])

                results.append(self.create_result(
                    vulnerable=True,
                    url=url,
                    parameter='Response Body',
                    payload='Hash detection',
                    evidence=f"Found {len(all_hashes)} hash values (not SRI): {', '.join(all_hashes[:5])}...",
                    severity='Medium',
                    method='GET',
                    additional_info={
                        'injection_type': 'Hash Exposure',
                        'hash_count': len(all_hashes),
                        'samples': all_hashes[:10],
                        'description': 'Hash values found - may be password hashes or sensitive data',
                        'note': 'Excludes SRI integrity hashes',
                        'cwe': 'CWE-327',
                        'owasp': 'A02:2021'
                    }
                ))

            # Group low findings (emails, phones, IPs) with actual proof
            if low_findings:
                evidence_parts = [
                    "**Sensitive Data Exposure Detected**\n",
                    f"**URL:** {url}",
                    "\n**Data Found:**"
                ]

                all_data = {}
                for data_type, data in low_findings.items():
                    matches = data['matches'][:10]
                    all_data[data_type] = matches

                    evidence_parts.append(f"\n**{data_type}** ({len(data['matches'])} found):")
                    for match in matches[:5]:
                        # Mask sensitive data partially
                        if data_type == 'emails' and '@' in match:
                            parts = match.split('@')
                            masked = parts[0][:2] + '***@' + parts[1]
                        elif data_type == 'credit_cards':
                            masked = match[:4] + '-****-****-' + match[-4:]
                        elif data_type == 'phones':
                            masked = match[:3] + '-***-' + match[-4:] if len(match) > 7 else match
                        else:
                            masked = match[:20] + '...' if len(match) > 20 else match
                        evidence_parts.append(f"  - `{masked}`")

                    if len(matches) > 5:
                        evidence_parts.append(f"  ... and {len(matches) - 5} more")

                results.append(self.create_result(
                    vulnerable=True,
                    url=url,
                    parameter='Response Body',
                    payload='PII detection',
                    evidence='\n'.join(evidence_parts),
                    severity='Info',
                    method='GET',
                    additional_info={
                        'injection_type': 'PII Exposure',
                        'data': all_data,
                        'description': 'Personal identifiable information found in response',
                        'cwe': 'CWE-200',
                        'owasp': 'A01:2021'
                    }
                ))

        except Exception as e:
            self.logger.debug(f"Error scanning {url}: {e}")

        return results

    def _is_sri_context(self, content: str, hash_value: str) -> bool:
        """Check if hash appears in SRI integrity context"""
        # Look for the hash near integrity= attribute
        idx = content.find(hash_value)
        if idx == -1:
            return False

        # Check surrounding context (100 chars before)
        start = max(0, idx - 100)
        context = content[start:idx].lower()

        return 'integrity' in context or 'sha256-' in context or 'sha384-' in context or 'sha512-' in context

    def _validate_match(self, data_type: str, match: str, content: str) -> bool:
        """Validate if match is a real finding or false positive"""
        # General false positive checks
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

        match_lower = match.lower()
        if any(p in match_lower for p in placeholders):
            return False

        # Skip values with too little entropy (repeated chars)
        if len(set(match.replace('-', '').replace('_', ''))) < 4:
            return False

        # SSN validation - exclude common false positives
        if data_type == 'ssn':
            # Check if it looks like a date or other number
            if match.startswith('000') or match.startswith('666'):
                return False
            # Look for context that suggests it's actually an SSN
            idx = content.find(match)
            if idx != -1:
                context = content[max(0, idx - 50):idx + len(match) + 50].lower()
                if 'ssn' not in context and 'social' not in context and 'security' not in context:
                    return False

        # Credit card - validate with Luhn algorithm
        if data_type.startswith('credit_card') and 'cvv' not in data_type:
            digits = re.sub(r'[-\s]', '', match)
            if not self._luhn_check(digits):
                return False

        # Hash - check if it's in a meaningful context
        if data_type.endswith('_hash'):
            idx = content.find(match)
            if idx != -1:
                context = content[max(0, idx - 100):idx + len(match) + 50].lower()
                # Skip if it's clearly a file hash or commit hash
                if 'commit' in context or 'version' in context or 'checksum' in context:
                    return False

        # Password validation - ensure it's not just a config key name
        if data_type == 'hardcoded_password':
            # Extract the actual value
            pwd_match = re.search(r'[\'"]([^\'"]+)[\'"]', match)
            if pwd_match:
                pwd_value = pwd_match.group(1)
                # Skip if it looks like a placeholder or env var reference
                if any(p in pwd_value.lower() for p in placeholders):
                    return False
                # Skip if too short
                if len(pwd_value) < 8:
                    return False

        return True

    def _luhn_check(self, card_number: str) -> bool:
        """Validate credit card number using Luhn algorithm"""
        try:
            digits = [int(d) for d in card_number]
            odd_digits = digits[-1::-2]
            even_digits = digits[-2::-2]
            total = sum(odd_digits)
            for d in even_digits:
                total += sum(divmod(d * 2, 10))
            return total % 10 == 0
        except:
            return False

    def _create_finding(self, url: str, data_type: str, data: dict) -> Dict[str, Any]:
        """Create a result for a specific data type"""
        config = data['config']
        matches = data['matches']

        # Mask sensitive data in evidence
        masked_matches = [self._mask_data(m, data_type) for m in matches[:5]]

        return self.create_result(
            vulnerable=True,
            url=url,
            parameter='Response Body',
            payload=data_type,
            evidence=f"{config['description']}: {', '.join(masked_matches)}",
            severity=config['severity'],
            method='GET',
            additional_info={
                'injection_type': config['description'],
                'data_type': data_type,
                'count': len(matches),
                'samples_masked': masked_matches,
                'cwe': config['cwe'],
                'owasp': 'A01:2021'
            }
        )

    def _mask_data(self, data: str, data_type: str) -> str:
        """Mask sensitive data for safe display"""
        if data_type.startswith('credit_card'):
            # Show only last 4 digits
            return '*' * (len(data) - 4) + data[-4:]
        elif data_type == 'ssn':
            return '***-**-' + data[-4:]
        elif data_type == 'email':
            parts = data.split('@')
            if len(parts) == 2:
                return parts[0][:2] + '***@' + parts[1]
        elif 'key' in data_type or 'token' in data_type:
            return data[:8] + '...' + data[-4:] if len(data) > 12 else '***'
        return data


def get_module(module_path: str, payload_limit: int = None):
    """Factory function to create module instance"""
    return SensitiveDataScanner(module_path, payload_limit=payload_limit)
