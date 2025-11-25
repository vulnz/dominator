"""
API Excessive Data Exposure Scanner

Detects APIs returning more data than necessary:
- PII data in responses (emails, SSN, credit cards, etc.)
- Internal/debug fields
- Password hashes or tokens
- Sensitive business data
"""

from typing import List, Dict, Any
from core.base_module import BaseModule
from core.logger import get_logger
import re
import json

logger = get_logger(__name__)


class APIExcessiveDataModule(BaseModule):
    """API Excessive Data Exposure scanner"""

    # Patterns for sensitive data
    SENSITIVE_PATTERNS = {
        'password_hash': r'"(password|passwd|pwd|hash|password_hash)":\s*"[^"]{20,}"',
        'api_key': r'"(api_key|apiKey|api_secret|apiSecret|secret_key|secretKey)":\s*"[^"]+"',
        'access_token': r'"(access_token|accessToken|auth_token|authToken|bearer)":\s*"[^"]+"',
        'private_key': r'-----BEGIN (RSA |EC |DSA |)PRIVATE KEY-----',
        'ssn': r'"(ssn|social_security|socialSecurity)":\s*"?\d{3}-?\d{2}-?\d{4}"?',
        'credit_card': r'"(card_number|cardNumber|cc_number|ccNumber)":\s*"?\d{13,19}"?',
        'cvv': r'"(cvv|cvc|security_code|securityCode)":\s*"?\d{3,4}"?',
        'bank_account': r'"(account_number|accountNumber|bank_account)":\s*"?[A-Z0-9]{10,}"?',
        'internal_id': r'"(_id|internal_id|internalId|__v)":\s*',
        'debug_info': r'"(debug|_debug|trace|stack_trace|stackTrace)":\s*',
        'database_id': r'"(db_id|dbId|database_id|mongo_id)":\s*',
        'admin_field': r'"(is_admin|isAdmin|admin|superuser|is_superuser)":\s*(true|1)',
    }

    # Sensitive field names that shouldn't be exposed
    SENSITIVE_FIELDS = [
        'password', 'passwd', 'pwd', 'secret', 'token', 'api_key', 'apiKey',
        'access_token', 'accessToken', 'refresh_token', 'refreshToken',
        'private_key', 'privateKey', 'ssn', 'social_security', 'credit_card',
        'card_number', 'cardNumber', 'cvv', 'cvc', 'pin', 'security_code',
        'bank_account', 'accountNumber', 'routing_number', 'iban', 'swift',
        'license_number', 'passport', 'tax_id', 'taxId', 'ein', 'itin',
        'medical_record', 'health_info', 'diagnosis', 'prescription',
        'salary', 'income', 'compensation', 'bonus', 'stock_options',
        '_internal', '__private', 'debug', 'trace', 'stack_trace',
        'database_password', 'db_password', 'connection_string', 'dsn',
        'encryption_key', 'signing_key', 'jwt_secret', 'session_secret'
    ]

    def __init__(self, module_path: str, payload_limit: int = None):
        super().__init__(module_path, payload_limit=payload_limit)
        logger.info("API Excessive Data Exposure module initialized")

    def scan(self, targets: List[Dict[str, Any]], http_client: Any) -> List[Dict[str, Any]]:
        """Scan for excessive data exposure"""
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

                # Analyze response for sensitive data
                findings = self._analyze_response(response.text, url)

                if findings:
                    evidence = "Excessive Data Exposure detected!\n\n"
                    evidence += "**Sensitive data found in response:**\n"
                    for finding_type, details in findings.items():
                        evidence += f"\n**{finding_type}:**\n"
                        for detail in details[:3]:  # Limit output
                            evidence += f"  - {detail}\n"
                    evidence += f"\n**Recommendation:** Filter sensitive fields before sending response"

                    result = self.create_result(
                        vulnerable=True,
                        url=url,
                        parameter="Response Body",
                        payload="N/A (passive detection)",
                        evidence=evidence,
                        description=f"API returns sensitive data: {', '.join(findings.keys())}",
                        confidence=0.75
                    )
                    result['cwe'] = 'CWE-213'
                    result['owasp'] = 'API3:2023'
                    result['severity'] = 'medium'
                    results.append(result)

            except Exception as e:
                logger.debug(f"Error scanning {url}: {e}")

        logger.info(f"Excessive Data scan complete: {len(results)} findings")
        return results

    def _analyze_response(self, response_text: str, url: str) -> Dict[str, List[str]]:
        """Analyze response for sensitive data exposure"""
        findings = {}

        # Check regex patterns
        for pattern_name, pattern in self.SENSITIVE_PATTERNS.items():
            matches = re.findall(pattern, response_text, re.I)
            if matches:
                if pattern_name not in findings:
                    findings[pattern_name] = []
                for match in matches[:3]:
                    if isinstance(match, tuple):
                        match = match[0]
                    findings[pattern_name].append(f"Found: {match[:50]}...")

        # Check JSON structure for sensitive fields
        try:
            data = json.loads(response_text)
            sensitive_found = self._find_sensitive_fields(data)
            if sensitive_found:
                findings['sensitive_fields'] = sensitive_found
        except json.JSONDecodeError:
            pass

        return findings

    def _find_sensitive_fields(self, data: Any, path: str = "") -> List[str]:
        """Recursively find sensitive field names in JSON"""
        found = []

        if isinstance(data, dict):
            for key, value in data.items():
                current_path = f"{path}.{key}" if path else key

                # Check if field name is sensitive
                key_lower = key.lower()
                for sensitive in self.SENSITIVE_FIELDS:
                    if sensitive.lower() in key_lower:
                        # Don't flag empty/null values
                        if value not in [None, '', [], {}]:
                            found.append(f"{current_path} = {str(value)[:30]}...")
                        break

                # Recurse into nested objects
                if isinstance(value, (dict, list)):
                    found.extend(self._find_sensitive_fields(value, current_path))

        elif isinstance(data, list):
            for i, item in enumerate(data[:3]):  # Only check first 3 items
                found.extend(self._find_sensitive_fields(item, f"{path}[{i}]"))

        return found


def get_module(module_path: str, payload_limit: int = None):
    return APIExcessiveDataModule(module_path, payload_limit=payload_limit)
