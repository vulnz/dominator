"""
API Excessive Data Exposure Scanner

Detects APIs returning more data than necessary:
- PII data in responses (SSN, credit cards, etc.)
- Exposed secrets (API keys, tokens, private keys)
- Password hashes
- Sensitive business data

IMPORTANT: Uses strict detection to avoid false positives.
Only flags CONFIRMED sensitive data with actual values.
"""

from typing import List, Dict, Any
from core.base_module import BaseModule
from core.logger import get_logger
import re
import json

logger = get_logger(__name__)


class APIExcessiveDataModule(BaseModule):
    """API Excessive Data Exposure scanner with FP prevention"""

    # CRITICAL severity - these patterns CONFIRM sensitive data exposure
    # Must have actual VALUES, not just field names
    CRITICAL_PATTERNS = {
        'private_key': (
            r'-----BEGIN (RSA |EC |DSA |OPENSSH |PGP |)PRIVATE KEY-----',
            'Private cryptographic key exposed'
        ),
        'aws_key': (
            r'AKIA[0-9A-Z]{16}',
            'AWS Access Key ID exposed'
        ),
        'aws_secret': (
            r'"(aws_secret|AWS_SECRET_ACCESS_KEY)":\s*"[A-Za-z0-9/+=]{40}"',
            'AWS Secret Key exposed'
        ),
        'jwt_token': (
            r'"(access_token|auth_token|bearer|jwt)":\s*"eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+"',
            'JWT token exposed in response'
        ),
        'password_plaintext': (
            r'"(password|passwd|user_password)":\s*"(?![\*x]+)[^"]{6,}"',
            'Password value exposed (not masked)'
        ),
        'password_hash': (
            r'"(password_hash|passwd_hash|hashed_password)":\s*"(\$2[ayb]\$|\$argon2|\$pbkdf2|sha256:|sha512:)[^"]+"',
            'Password hash exposed'
        ),
        'credit_card_full': (
            r'"(card_number|cardNumber|cc_number|pan|primary_account_number)":\s*"?[0-9]{13,16}"?',
            'Full credit card number exposed'
        ),
        'ssn_full': (
            r'"(ssn|social_security_number|social_security)":\s*"[0-9]{3}-?[0-9]{2}-?[0-9]{4}"',
            'Social Security Number exposed'
        ),
        'cvv_exposed': (
            r'"(cvv|cvc|cvv2|cvc2|security_code)":\s*"?[0-9]{3,4}"?',
            'CVV/CVC code exposed'
        ),
    }

    # HIGH severity - sensitive but needs value inspection
    HIGH_SEVERITY_PATTERNS = {
        'api_key_value': (
            r'"(api_key|apiKey|x-api-key)":\s*"[a-zA-Z0-9_-]{20,}"',
            'API key with significant length'
        ),
        'database_connection': (
            r'"(connection_string|database_url|dsn|db_url)":\s*"[^"]+"',
            'Database connection string exposed'
        ),
        'encryption_key': (
            r'"(encryption_key|aes_key|secret_key)":\s*"[a-fA-F0-9]{32,}"',
            'Encryption key exposed'
        ),
    }

    # Fields to IGNORE - these cause false positives
    # Common API fields that are NOT vulnerabilities
    IGNORE_PATTERNS = [
        r'"_id":\s*"[^"]+"',           # MongoDB _id is normal
        r'"id":\s*[0-9]+',             # Numeric IDs are normal
        r'"__v":\s*[0-9]+',            # MongoDB version field
        r'"token":\s*"[^"]+"',         # Generic token (could be CSRF)
        r'"is_admin":\s*(true|false)', # Role info is normal to return
        r'"role":\s*"[^"]+"',          # Role info is normal
        r'"email":\s*"[^"]+"',         # Email in profile is normal
        r'"debug":\s*false',           # Debug off is fine
    ]

    def __init__(self, module_path: str, payload_limit: int = None):
        super().__init__(module_path, payload_limit=payload_limit)
        logger.info("API Excessive Data Exposure module initialized")

    def scan(self, targets: List[Dict[str, Any]], http_client: Any) -> List[Dict[str, Any]]:
        """Scan for excessive data exposure with strict FP prevention"""
        results = []

        logger.info(f"Starting Excessive Data Exposure scan on {len(targets)} endpoints")

        for target in targets:
            url = target.get('url', '')
            method = target.get('method', 'GET').upper()
            params = target.get('params', {})
            headers = target.get('headers', {})

            try:
                # Make request
                if method == 'GET':
                    response = http_client.get(url, params=params, headers=headers)
                elif method == 'POST':
                    response = http_client.post(url, json=target.get('body', {}), headers=headers)
                else:
                    response = http_client.request(method, url, headers=headers)

                if not response or response.status_code != 200:
                    continue

                # Skip very short responses
                if len(response.text) < 50:
                    continue

                # Analyze response for CONFIRMED sensitive data
                findings = self._analyze_response(response.text, url)

                if findings:
                    # Determine overall severity based on findings
                    has_critical = any(f['severity'] == 'critical' for f in findings)
                    has_high = any(f['severity'] == 'high' for f in findings)

                    severity = 'critical' if has_critical else ('high' if has_high else 'medium')
                    confidence = 0.90 if has_critical else 0.80

                    evidence = "**CONFIRMED Excessive Data Exposure**\n\n"
                    evidence += "Sensitive data found in API response:\n\n"

                    for finding in findings[:5]:  # Limit to 5 findings
                        evidence += f"**{finding['type']}** ({finding['severity'].upper()})\n"
                        evidence += f"  Description: {finding['description']}\n"
                        evidence += f"  Match: `{finding['match'][:60]}...`\n\n"

                    evidence += "**Recommendation:** Remove sensitive fields from API responses. "
                    evidence += "Implement field-level filtering based on user permissions."

                    result = self.create_result(
                        vulnerable=True,
                        url=url,
                        parameter="Response Body",
                        payload="N/A (passive detection)",
                        evidence=evidence,
                        description=f"API exposes sensitive data: {', '.join(set(f['type'] for f in findings))}",
                        confidence=confidence
                    )
                    result['cwe'] = 'CWE-200'
                    result['cwe_name'] = 'Exposure of Sensitive Information to an Unauthorized Actor'
                    result['owasp'] = 'API3:2023'
                    result['owasp_name'] = 'Broken Object Property Level Authorization'
                    result['severity'] = severity
                    results.append(result)

            except Exception as e:
                logger.debug(f"Error scanning {url}: {e}")

        logger.info(f"Excessive Data scan complete: {len(results)} findings")
        return results

    def _analyze_response(self, response_text: str, url: str) -> List[Dict]:
        """Analyze response for CONFIRMED sensitive data exposure"""
        findings = []

        # Check CRITICAL patterns first
        for pattern_name, (pattern, description) in self.CRITICAL_PATTERNS.items():
            matches = re.findall(pattern, response_text, re.I)
            if matches:
                for match in matches[:2]:  # Max 2 per type
                    if isinstance(match, tuple):
                        match = match[0] if match[0] else str(match)

                    # Validate it's not in ignore list
                    if not self._should_ignore(response_text, match):
                        findings.append({
                            'type': pattern_name,
                            'severity': 'critical',
                            'description': description,
                            'match': str(match)[:100]
                        })

        # Check HIGH severity patterns
        for pattern_name, (pattern, description) in self.HIGH_SEVERITY_PATTERNS.items():
            matches = re.findall(pattern, response_text, re.I)
            if matches:
                for match in matches[:2]:
                    if isinstance(match, tuple):
                        match = match[0] if match[0] else str(match)

                    if not self._should_ignore(response_text, match):
                        findings.append({
                            'type': pattern_name,
                            'severity': 'high',
                            'description': description,
                            'match': str(match)[:100]
                        })

        return findings

    def _should_ignore(self, response_text: str, match: str) -> bool:
        """Check if match should be ignored (false positive prevention)"""
        match_lower = str(match).lower()

        # Ignore common false positive values
        fp_values = [
            'null', 'undefined', 'none', 'n/a', 'test', 'example',
            'xxxxxxxx', '********', 'redacted', '[redacted]',
            'placeholder', 'changeme', 'secret123', 'password123'
        ]
        if match_lower in fp_values:
            return True

        # Ignore if value is clearly masked
        if 'xxxx' in match_lower or '****' in match_lower:
            return True

        # Ignore very short matches (likely field names only)
        if len(match) < 10:
            return True

        return False


def get_module(module_path: str, payload_limit: int = None):
    return APIExcessiveDataModule(module_path, payload_limit=payload_limit)
