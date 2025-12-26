"""
API Mass Assignment Scanner

Detects Mass Assignment vulnerabilities by:
- Adding privileged fields to requests (role, admin, isAdmin, etc.)
- Testing field injection in PUT/POST requests
- Checking if hidden fields can be modified

IMPORTANT: Only reports CONFIRMED vulnerabilities where injected
fields are reflected in the response with our values.
"""

from typing import List, Dict, Any, Optional, Tuple
from core.base_module import BaseModule
from core.logger import get_logger
import json

logger = get_logger(__name__)


class APIMassAssignmentModule(BaseModule):
    """API Mass Assignment vulnerability scanner with FP prevention"""

    # HIGH IMPACT fields - privilege escalation (requires confirmation)
    HIGH_IMPACT_FIELDS = [
        # Role/Permission fields
        ('role', 'admin'),
        ('isAdmin', True),
        ('is_admin', True),
        ('is_superuser', True),
        ('admin', True),
        ('permissions', ['admin', 'write', 'delete']),
        ('access_level', 999),
    ]

    # MEDIUM IMPACT fields - account manipulation
    MEDIUM_IMPACT_FIELDS = [
        ('verified', True),
        ('is_verified', True),
        ('email_verified', True),
        ('banned', False),
        ('is_banned', False),
        ('is_active', True),
        ('approved', True),
    ]

    # FINANCIAL fields - money/credits
    FINANCIAL_FIELDS = [
        ('balance', 999999),
        ('credits', 999999),
        ('discount', 100),
        ('price', 0),
    ]

    def __init__(self, module_path: str, payload_limit: int = None):
        super().__init__(module_path, payload_limit=payload_limit)
        logger.info("API Mass Assignment module initialized")

    def scan(self, targets: List[Dict[str, Any]], http_client: Any) -> List[Dict[str, Any]]:
        """Scan for Mass Assignment vulnerabilities"""
        results = []

        logger.info(f"Starting Mass Assignment scan on {len(targets)} endpoints")

        for target in targets:
            url = target.get('url', '')
            method = target.get('method', 'GET').upper()
            body = target.get('body', {})
            headers = target.get('headers', {})

            # Only test POST, PUT, PATCH methods
            if method not in ['POST', 'PUT', 'PATCH']:
                continue

            # Skip if no body or not a data endpoint
            if not self._is_data_endpoint(url):
                continue

            # Test mass assignment
            result = self._test_mass_assignment(url, method, body, headers, http_client)
            if result:
                results.append(result)

        logger.info(f"Mass Assignment scan complete: {len(results)} vulnerabilities found")
        return results

    def _is_data_endpoint(self, url: str) -> bool:
        """Check if URL looks like a data/resource endpoint"""
        url_lower = url.lower()

        # Skip static/auth endpoints
        skip_patterns = [
            '/login', '/logout', '/auth', '/oauth', '/token',
            '/static/', '/assets/', '/images/', '/css/', '/js/'
        ]
        if any(p in url_lower for p in skip_patterns):
            return False

        # Target resource endpoints
        target_patterns = [
            '/user', '/profile', '/account', '/settings',
            '/api/', '/v1/', '/v2/', '/update', '/edit',
            '/register', '/signup'
        ]
        return any(p in url_lower for p in target_patterns)

    def _test_mass_assignment(self, url: str, method: str, body: Dict,
                               headers: Dict, http_client: Any) -> Optional[Dict]:
        """Test endpoint for mass assignment with strict confirmation"""
        try:
            test_headers = headers.copy()
            test_headers['Content-Type'] = 'application/json'

            # Get baseline response for comparison
            baseline = http_client.request(method, url, json=body, headers=test_headers)
            if not baseline or baseline.status_code not in [200, 201, 204]:
                return None

            # Test fields by category
            confirmed_findings = []

            # Test HIGH IMPACT fields first
            for field_name, field_value in self.HIGH_IMPACT_FIELDS:
                result = self._test_field(url, method, body, test_headers,
                                         http_client, field_name, field_value, 'high')
                if result:
                    confirmed_findings.append(result)
                    break  # One high impact is enough

            # Test MEDIUM IMPACT if no high found
            if not confirmed_findings:
                for field_name, field_value in self.MEDIUM_IMPACT_FIELDS[:5]:
                    result = self._test_field(url, method, body, test_headers,
                                             http_client, field_name, field_value, 'medium')
                    if result:
                        confirmed_findings.append(result)
                        break

            # Test FINANCIAL fields
            for field_name, field_value in self.FINANCIAL_FIELDS[:3]:
                result = self._test_field(url, method, body, test_headers,
                                         http_client, field_name, field_value, 'high')
                if result:
                    confirmed_findings.append(result)
                    break

            # Only report if we have CONFIRMED findings
            if confirmed_findings:
                severity = 'critical' if any(f['impact'] == 'high' for f in confirmed_findings) else 'high'

                evidence = "**CONFIRMED Mass Assignment Vulnerability**\n\n"
                evidence += "The following privileged fields were accepted and reflected:\n\n"

                for finding in confirmed_findings:
                    evidence += f"**Field:** `{finding['field']}`\n"
                    evidence += f"**Injected Value:** `{finding['value']}`\n"
                    evidence += f"**Response Value:** `{finding['response_value']}`\n"
                    evidence += f"**Impact:** {finding['impact'].upper()}\n\n"

                evidence += "**Attack Impact:**\n"
                evidence += "- Privilege escalation (admin access)\n"
                evidence += "- Account manipulation\n"
                evidence += "- Unauthorized data modification\n\n"
                evidence += "**Remediation:** Implement strict field allowlist. "
                evidence += "Never bind request data directly to model objects."

                result = self.create_result(
                    vulnerable=True,
                    url=url,
                    parameter="Request Body",
                    payload=f"Injected: {', '.join(f['field'] for f in confirmed_findings)}",
                    evidence=evidence,
                    description=f"Mass Assignment: {len(confirmed_findings)} privileged fields accepted",
                    confidence=0.95  # High confidence - confirmed reflection
                )
                result['cwe'] = 'CWE-915'
                result['cwe_name'] = 'Improperly Controlled Modification of Dynamically-Determined Object Attributes'
                result['owasp'] = 'API6:2023'
                result['owasp_name'] = 'Unrestricted Access to Sensitive Business Flows'
                result['severity'] = severity
                return result

        except Exception as e:
            logger.debug(f"Error in mass assignment test: {e}")

        return None

    def _test_field(self, url: str, method: str, body: Dict, headers: Dict,
                    http_client: Any, field_name: str, field_value: Any,
                    impact: str) -> Optional[Dict]:
        """Test a single field and check for CONFIRMED reflection"""
        try:
            # Skip if field already in body
            if field_name in body:
                return None

            # Create test body
            test_body = body.copy() if isinstance(body, dict) else {}
            test_body[field_name] = field_value

            response = http_client.request(method, url, json=test_body, headers=headers)
            if not response or response.status_code not in [200, 201, 204]:
                return None

            # Parse response
            if not response.text or len(response.text) < 10:
                return None

            try:
                response_data = json.loads(response.text)
            except json.JSONDecodeError:
                return None

            # STRICT CHECK: Field must appear in response with our value
            if isinstance(response_data, dict):
                # Direct field match
                if field_name in response_data:
                    response_value = response_data[field_name]
                    if self._values_match(response_value, field_value):
                        return {
                            'field': field_name,
                            'value': field_value,
                            'response_value': response_value,
                            'impact': impact
                        }

                # Check nested 'data' or 'user' objects
                for nested_key in ['data', 'user', 'result', 'body']:
                    if nested_key in response_data and isinstance(response_data[nested_key], dict):
                        nested = response_data[nested_key]
                        if field_name in nested:
                            response_value = nested[field_name]
                            if self._values_match(response_value, field_value):
                                return {
                                    'field': field_name,
                                    'value': field_value,
                                    'response_value': response_value,
                                    'impact': impact
                                }

        except Exception as e:
            logger.debug(f"Error testing field {field_name}: {e}")

        return None

    def _values_match(self, response_value: Any, injected_value: Any) -> bool:
        """Check if response value matches injected value"""
        # Direct equality
        if response_value == injected_value:
            return True

        # String comparison
        if str(response_value).lower() == str(injected_value).lower():
            return True

        # Boolean variations
        if isinstance(injected_value, bool):
            if response_value in [True, 'true', 'True', 1, '1'] and injected_value is True:
                return True
            if response_value in [False, 'false', 'False', 0, '0'] and injected_value is False:
                return True

        return False


def get_module(module_path: str, payload_limit: int = None):
    return APIMassAssignmentModule(module_path, payload_limit=payload_limit)
