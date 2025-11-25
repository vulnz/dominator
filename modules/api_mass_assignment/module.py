"""
API Mass Assignment Scanner

Detects Mass Assignment vulnerabilities by:
- Adding privileged fields to requests (role, admin, isAdmin, etc.)
- Testing field injection in PUT/POST requests
- Checking if hidden fields can be modified
"""

from typing import List, Dict, Any, Optional
from core.base_module import BaseModule
from core.logger import get_logger
import json

logger = get_logger(__name__)


class APIMassAssignmentModule(BaseModule):
    """API Mass Assignment vulnerability scanner"""

    # Fields that could lead to privilege escalation if modifiable
    PRIVILEGED_FIELDS = [
        # Role/Permission fields
        ('role', 'admin'),
        ('role', 'administrator'),
        ('role_id', 1),
        ('roles', ['admin']),
        ('user_role', 'admin'),
        ('userRole', 'admin'),
        ('permission', 'admin'),
        ('permissions', ['*']),
        ('access_level', 'admin'),
        ('accessLevel', 9999),

        # Admin flags
        ('admin', True),
        ('isAdmin', True),
        ('is_admin', True),
        ('is_superuser', True),
        ('isSuperuser', True),
        ('superuser', True),
        ('privileged', True),
        ('is_staff', True),
        ('isStaff', True),

        # Account status
        ('verified', True),
        ('is_verified', True),
        ('isVerified', True),
        ('active', True),
        ('is_active', True),
        ('isActive', True),
        ('approved', True),
        ('is_approved', True),
        ('enabled', True),
        ('banned', False),
        ('is_banned', False),

        # Financial/Credit
        ('balance', 999999),
        ('credits', 999999),
        ('credit', 999999),
        ('points', 999999),
        ('discount', 100),
        ('price', 0),
        ('amount', 0),

        # Ownership
        ('owner_id', 1),
        ('ownerId', 1),
        ('user_id', 1),
        ('userId', 1),
        ('created_by', 1),
        ('createdBy', 1),

        # Subscription/Plan
        ('plan', 'enterprise'),
        ('subscription', 'premium'),
        ('tier', 'enterprise'),
        ('level', 'premium'),

        # Internal fields
        ('internal', True),
        ('debug', True),
        ('hidden', False),
        ('deleted', False),
        ('is_deleted', False),
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

            # Test mass assignment
            result = self._test_mass_assignment(url, method, body, headers, http_client)
            if result:
                results.append(result)

        logger.info(f"Mass Assignment scan complete: {len(results)} vulnerabilities found")
        return results

    def _test_mass_assignment(self, url: str, method: str, body: Dict,
                               headers: Dict, http_client: Any) -> Optional[Dict]:
        """Test endpoint for mass assignment"""
        try:
            # Ensure Content-Type is JSON
            test_headers = headers.copy()
            test_headers['Content-Type'] = 'application/json'

            # Get baseline response
            baseline = http_client.request(method, url, json=body, headers=test_headers)
            if not baseline:
                return None

            baseline_status = baseline.status_code

            # Test each privileged field
            vulnerable_fields = []

            for field_name, field_value in self.PRIVILEGED_FIELDS[:20]:  # Limit tests
                # Skip if field already exists in body
                if field_name in body:
                    continue

                # Create test body with injected field
                test_body = body.copy() if isinstance(body, dict) else {}
                test_body[field_name] = field_value

                try:
                    response = http_client.request(method, url, json=test_body, headers=test_headers)
                    if not response:
                        continue

                    # Check for successful injection
                    if response.status_code in [200, 201, 204]:
                        # Check if field was accepted
                        try:
                            # FIX: HTTPResponse doesn't have .json() method
                            response_data = json.loads(response.text) if response.text and response.text.strip().startswith(('{', '[')) else {}

                            # Field appears in response = likely accepted
                            if isinstance(response_data, dict):
                                if field_name in response_data:
                                    if response_data[field_name] == field_value:
                                        vulnerable_fields.append((field_name, field_value))
                                        continue

                            # No error returned when adding field = potentially vulnerable
                            if response.status_code == baseline_status:
                                vulnerable_fields.append((field_name, field_value))

                        except json.JSONDecodeError:
                            # Non-JSON response but success status = potentially vulnerable
                            if response.status_code in [200, 201]:
                                vulnerable_fields.append((field_name, field_value))

                except Exception as e:
                    logger.debug(f"Error testing field {field_name}: {e}")

            # Report findings
            if vulnerable_fields:
                evidence = "Mass Assignment vulnerability detected!\n\n"
                evidence += "**Injected privileged fields accepted:**\n"
                for field, value in vulnerable_fields[:10]:
                    evidence += f"  - {field}: {value}\n"
                evidence += f"\n**Impact:** Potential privilege escalation, unauthorized data modification\n"
                evidence += f"**Recommendation:** Implement allowlist for accepted fields"

                result = self.create_result(
                    vulnerable=True,
                    url=url,
                    parameter="Request Body",
                    payload=f"Injected {len(vulnerable_fields)} privileged fields",
                    evidence=evidence,
                    description=f"Mass Assignment vulnerability allows injecting privileged fields: "
                              f"{', '.join([f[0] for f in vulnerable_fields[:5]])}",
                    confidence=0.80
                )
                result['cwe'] = 'CWE-915'
                result['owasp'] = 'API6:2023'
                result['severity'] = 'high'
                return result

        except Exception as e:
            logger.debug(f"Error in mass assignment test: {e}")

        return None


def get_module(module_path: str, payload_limit: int = None):
    return APIMassAssignmentModule(module_path, payload_limit=payload_limit)
