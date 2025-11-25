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

        # Sensitive data patterns
        self.patterns = {
            # Email addresses
            'email': {
                'pattern': r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',
                'severity': 'Low',
                'description': 'Email address exposed',
                'cwe': 'CWE-200'
            },

            # Phone numbers (various formats)
            'phone_us': {
                'pattern': r'\b(?:\+?1[-.\s]?)?\(?[0-9]{3}\)?[-.\s]?[0-9]{3}[-.\s]?[0-9]{4}\b',
                'severity': 'Low',
                'description': 'US phone number exposed',
                'cwe': 'CWE-200'
            },
            'phone_intl': {
                'pattern': r'\b\+[0-9]{1,3}[-.\s]?[0-9]{1,4}[-.\s]?[0-9]{1,4}[-.\s]?[0-9]{1,9}\b',
                'severity': 'Low',
                'description': 'International phone number exposed',
                'cwe': 'CWE-200'
            },

            # Credit card numbers
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
                'description': 'American Express credit card number exposed',
                'cwe': 'CWE-311'
            },

            # SSN
            'ssn': {
                'pattern': r'\b[0-9]{3}[-\s]?[0-9]{2}[-\s]?[0-9]{4}\b',
                'severity': 'Critical',
                'description': 'Social Security Number exposed',
                'cwe': 'CWE-359'
            },

            # Hashes (excluding SRI hashes)
            'md5_hash': {
                'pattern': r'\b[a-fA-F0-9]{32}\b',
                'severity': 'Medium',
                'description': 'MD5 hash exposed (potential password hash)',
                'cwe': 'CWE-327'
            },
            'sha1_hash': {
                'pattern': r'\b[a-fA-F0-9]{40}\b',
                'severity': 'Medium',
                'description': 'SHA-1 hash exposed (potential password hash)',
                'cwe': 'CWE-327'
            },
            'sha256_hash': {
                'pattern': r'\b[a-fA-F0-9]{64}\b',
                'severity': 'Medium',
                'description': 'SHA-256 hash exposed (potential password hash)',
                'cwe': 'CWE-327'
            },

            # API keys and tokens
            'aws_access_key': {
                'pattern': r'\bAKIA[0-9A-Z]{16}\b',
                'severity': 'Critical',
                'description': 'AWS Access Key ID exposed',
                'cwe': 'CWE-798'
            },
            'aws_secret_key': {
                'pattern': r'(?i)aws(.{0,20})?[\'"][0-9a-zA-Z/+]{40}[\'"]',
                'severity': 'Critical',
                'description': 'AWS Secret Key exposed',
                'cwe': 'CWE-798'
            },
            'github_token': {
                'pattern': r'\b(ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{36}\b',
                'severity': 'Critical',
                'description': 'GitHub token exposed',
                'cwe': 'CWE-798'
            },
            'jwt_token': {
                'pattern': r'\beyJ[A-Za-z0-9-_]+\.eyJ[A-Za-z0-9-_]+\.[A-Za-z0-9-_.+/=]*\b',
                'severity': 'High',
                'description': 'JWT token exposed',
                'cwe': 'CWE-200'
            },
            'generic_api_key': {
                'pattern': r'(?i)(api[_-]?key|apikey|api[_-]?secret)[\'"\s:=]+[\'"]?[A-Za-z0-9_-]{20,}[\'"]?',
                'severity': 'High',
                'description': 'API key/secret exposed',
                'cwe': 'CWE-798'
            },
            'private_key': {
                'pattern': r'-----BEGIN (RSA |DSA |EC |OPENSSH )?PRIVATE KEY-----',
                'severity': 'Critical',
                'description': 'Private key exposed',
                'cwe': 'CWE-321'
            },

            # Database connection strings
            'db_connection': {
                'pattern': r'(?i)(mongodb|mysql|postgresql|redis|mssql)://[^\s\'\"<>]+',
                'severity': 'Critical',
                'description': 'Database connection string exposed',
                'cwe': 'CWE-200'
            },

            # IP addresses (internal)
            'internal_ip': {
                'pattern': r'\b(10\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}|172\.(1[6-9]|2[0-9]|3[0-1])\.[0-9]{1,3}\.[0-9]{1,3}|192\.168\.[0-9]{1,3}\.[0-9]{1,3})\b',
                'severity': 'Low',
                'description': 'Internal IP address exposed',
                'cwe': 'CWE-200'
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

            # Create results grouped by severity
            critical_findings = {k: v for k, v in findings_by_type.items() if v['config']['severity'] == 'Critical'}
            high_findings = {k: v for k, v in findings_by_type.items() if v['config']['severity'] == 'High'}
            medium_findings = {k: v for k, v in findings_by_type.items() if v['config']['severity'] == 'Medium'}
            low_findings = {k: v for k, v in findings_by_type.items() if v['config']['severity'] == 'Low'}

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

            # Group low findings (emails, phones, IPs)
            if low_findings:
                summary = []
                all_data = {}
                for data_type, data in low_findings.items():
                    summary.append(f"{data_type}: {len(data['matches'])} found")
                    all_data[data_type] = data['matches'][:10]

                results.append(self.create_result(
                    vulnerable=True,
                    url=url,
                    parameter='Response Body',
                    payload='PII detection',
                    evidence=f"Sensitive data found: {', '.join(summary)}",
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
        if data_type.startswith('credit_card'):
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
