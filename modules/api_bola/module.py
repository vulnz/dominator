"""
API BOLA (Broken Object Level Authorization) Scanner

Detects IDOR/BOLA vulnerabilities in REST APIs by:
- Testing numeric ID manipulation (id=1 -> id=2)
- Testing UUID guessing
- Testing predictable resource IDs
- Comparing responses between different ID values
"""

from typing import List, Dict, Any, Optional
from core.base_module import BaseModule
from core.logger import get_logger
import re
import json

logger = get_logger(__name__)


class APIBOLAModule(BaseModule):
    """API Broken Object Level Authorization Scanner"""

    # Patterns to detect IDs in URLs and parameters
    ID_PATTERNS = [
        r'/(\d+)(?:/|$|\?)',           # Numeric IDs in path: /users/123
        r'/([a-f0-9-]{36})(?:/|$|\?)', # UUIDs: /users/550e8400-e29b-41d4-a716-446655440000
        r'[?&]id=(\d+)',               # Query param: ?id=123
        r'[?&]user_id=(\d+)',          # user_id param
        r'[?&]userId=(\d+)',           # userId param (camelCase)
        r'[?&]order_id=(\d+)',         # order_id param
        r'[?&]account_id=(\d+)',       # account_id param
        r'[?&]profile_id=(\d+)',       # profile_id param
    ]

    # ID parameter names to test
    ID_PARAM_NAMES = [
        'id', 'user_id', 'userId', 'uid', 'account_id', 'accountId',
        'order_id', 'orderId', 'profile_id', 'profileId', 'customer_id',
        'customerId', 'item_id', 'itemId', 'product_id', 'productId',
        'document_id', 'file_id', 'record_id', 'entry_id', 'object_id'
    ]

    def __init__(self, module_path: str, payload_limit: int = None):
        """Initialize BOLA module"""
        super().__init__(module_path, payload_limit=payload_limit)
        logger.info("API BOLA module initialized")

    def scan(self, targets: List[Dict[str, Any]], http_client: Any) -> List[Dict[str, Any]]:
        """
        Scan for BOLA vulnerabilities

        Args:
            targets: List of API endpoints
            http_client: HTTP client

        Returns:
            List of vulnerability results
        """
        results = []
        tested_endpoints = set()

        logger.info(f"Starting API BOLA scan on {len(targets)} endpoints")

        for target in targets:
            url = target.get('url', '')
            method = target.get('method', 'GET').upper()
            params = target.get('params', {})
            body = target.get('body', {})

            # Create endpoint signature for deduplication
            endpoint_sig = f"{method}:{self._normalize_url(url)}"
            if endpoint_sig in tested_endpoints:
                continue
            tested_endpoints.add(endpoint_sig)

            # Test URL path for BOLA
            path_result = self._test_url_path_bola(url, method, http_client, target)
            if path_result:
                results.append(path_result)

            # Test query parameters
            param_results = self._test_param_bola(url, method, params, http_client, target)
            results.extend(param_results)

            # Test request body (for POST/PUT/PATCH)
            if method in ['POST', 'PUT', 'PATCH'] and body:
                body_results = self._test_body_bola(url, method, body, http_client, target)
                results.extend(body_results)

        logger.info(f"BOLA scan complete: {len(results)} vulnerabilities found")
        return results

    def _normalize_url(self, url: str) -> str:
        """Normalize URL by replacing IDs with placeholders"""
        normalized = url
        for pattern in self.ID_PATTERNS:
            normalized = re.sub(pattern, r'/ID/', normalized)
        return normalized

    def _test_url_path_bola(self, url: str, method: str, http_client: Any,
                            target: Dict) -> Optional[Dict[str, Any]]:
        """Test for BOLA in URL path IDs"""
        # Find numeric IDs in path
        path_id_match = re.search(r'/(\d+)(?:/|$|\?)', url)
        if not path_id_match:
            return None

        original_id = path_id_match.group(1)

        # Skip if ID is too small (might be version number like /v1/)
        if int(original_id) < 2:
            return None

        # Test adjacent IDs
        test_ids = self._generate_test_ids(original_id)

        try:
            # Get baseline response
            headers = target.get('headers', {})
            baseline_response = self._make_request(http_client, method, url, headers=headers)
            if not baseline_response:
                return None

            baseline_status = baseline_response.status_code
            baseline_length = len(baseline_response.text)

            # Test each alternative ID
            for test_id in test_ids:
                test_url = url.replace(f'/{original_id}', f'/{test_id}')

                test_response = self._make_request(http_client, method, test_url, headers=headers)
                if not test_response:
                    continue

                # Check for BOLA indicators
                is_vulnerable, evidence = self._check_bola_response(
                    baseline_response, test_response, original_id, test_id
                )

                if is_vulnerable:
                    return self.create_result(
                        vulnerable=True,
                        url=url,
                        parameter=f"Path ID: {original_id}",
                        payload=f"Changed ID from {original_id} to {test_id}",
                        evidence=evidence,
                        description=f"BOLA vulnerability detected. Changing resource ID in path from "
                                  f"{original_id} to {test_id} returned different object data without "
                                  f"proper authorization check.",
                        confidence=0.85
                    )

        except Exception as e:
            logger.debug(f"Error testing path BOLA: {e}")

        return None

    def _test_param_bola(self, url: str, method: str, params: Dict,
                         http_client: Any, target: Dict) -> List[Dict[str, Any]]:
        """Test for BOLA in query/body parameters"""
        results = []

        for param_name, param_value in params.items():
            # Check if this looks like an ID parameter
            if not self._is_id_param(param_name, param_value):
                continue

            original_id = str(param_value)
            test_ids = self._generate_test_ids(original_id)

            try:
                headers = target.get('headers', {})

                # Get baseline
                baseline_response = self._make_request(
                    http_client, method, url, params=params, headers=headers
                )
                if not baseline_response:
                    continue

                for test_id in test_ids:
                    test_params = params.copy()
                    test_params[param_name] = test_id

                    test_response = self._make_request(
                        http_client, method, url, params=test_params, headers=headers
                    )
                    if not test_response:
                        continue

                    is_vulnerable, evidence = self._check_bola_response(
                        baseline_response, test_response, original_id, test_id
                    )

                    if is_vulnerable:
                        result = self.create_result(
                            vulnerable=True,
                            url=url,
                            parameter=param_name,
                            payload=f"{param_name}={test_id} (was {original_id})",
                            evidence=evidence,
                            description=f"BOLA vulnerability in parameter '{param_name}'. "
                                      f"Accessing other users' resources by changing ID value.",
                            confidence=0.85
                        )
                        result['cwe'] = 'CWE-639'
                        result['owasp'] = 'API1:2023'
                        result['severity'] = 'critical'
                        results.append(result)
                        break  # One finding per param is enough

            except Exception as e:
                logger.debug(f"Error testing param BOLA: {e}")

        return results

    def _test_body_bola(self, url: str, method: str, body: Any,
                        http_client: Any, target: Dict) -> List[Dict[str, Any]]:
        """Test for BOLA in request body"""
        results = []

        if not isinstance(body, dict):
            return results

        for key, value in body.items():
            if not self._is_id_param(key, value):
                continue

            original_id = str(value)
            test_ids = self._generate_test_ids(original_id)

            try:
                headers = target.get('headers', {})
                headers['Content-Type'] = target.get('content_type', 'application/json')

                # Get baseline
                baseline_response = self._make_request(
                    http_client, method, url, json_body=body, headers=headers
                )
                if not baseline_response:
                    continue

                for test_id in test_ids:
                    test_body = body.copy()
                    test_body[key] = int(test_id) if original_id.isdigit() else test_id

                    test_response = self._make_request(
                        http_client, method, url, json_body=test_body, headers=headers
                    )
                    if not test_response:
                        continue

                    is_vulnerable, evidence = self._check_bola_response(
                        baseline_response, test_response, original_id, test_id
                    )

                    if is_vulnerable:
                        result = self.create_result(
                            vulnerable=True,
                            url=url,
                            parameter=f"body.{key}",
                            payload=f"{key}={test_id} (was {original_id})",
                            evidence=evidence,
                            description=f"BOLA vulnerability in request body field '{key}'. "
                                      f"Can access other users' resources via body manipulation.",
                            confidence=0.85
                        )
                        result['cwe'] = 'CWE-639'
                        result['owasp'] = 'API1:2023'
                        result['severity'] = 'critical'
                        results.append(result)
                        break

            except Exception as e:
                logger.debug(f"Error testing body BOLA: {e}")

        return results

    def _is_id_param(self, param_name: str, param_value: Any) -> bool:
        """Check if parameter looks like an ID"""
        name_lower = param_name.lower()

        # Check param name
        for id_name in self.ID_PARAM_NAMES:
            if id_name.lower() in name_lower:
                return True

        # Check if value is numeric
        if isinstance(param_value, int):
            return param_value > 0
        if isinstance(param_value, str) and param_value.isdigit():
            return int(param_value) > 0

        # Check for UUID format
        if isinstance(param_value, str):
            if re.match(r'^[a-f0-9-]{36}$', param_value, re.I):
                return True

        return False

    def _generate_test_ids(self, original_id: str) -> List[str]:
        """Generate alternative IDs to test"""
        test_ids = []

        if original_id.isdigit():
            orig_int = int(original_id)
            # Test adjacent IDs
            if orig_int > 1:
                test_ids.append(str(orig_int - 1))
            test_ids.append(str(orig_int + 1))
            test_ids.append(str(orig_int + 100))
            test_ids.append('1')  # Often admin/first user
            test_ids.append('0')
        elif re.match(r'^[a-f0-9-]{36}$', original_id, re.I):
            # UUID - try common test UUIDs
            test_ids.extend([
                '00000000-0000-0000-0000-000000000000',
                '00000000-0000-0000-0000-000000000001',
                'ffffffff-ffff-ffff-ffff-ffffffffffff'
            ])
        else:
            # Alphanumeric - try simple variations
            test_ids.extend(['1', '0', 'admin', 'test', 'guest'])

        return test_ids[:5]  # Limit to 5 tests

    def _make_request(self, http_client: Any, method: str, url: str,
                      params: Dict = None, json_body: Any = None,
                      headers: Dict = None) -> Optional[Any]:
        """Make HTTP request with error handling"""
        try:
            if method == 'GET':
                return http_client.get(url, params=params, headers=headers)
            elif method == 'POST':
                if json_body:
                    return http_client.post(url, json=json_body, headers=headers)
                return http_client.post(url, data=params, headers=headers)
            elif method == 'PUT':
                return http_client.put(url, json=json_body or params, headers=headers)
            elif method == 'PATCH':
                return http_client.patch(url, json=json_body or params, headers=headers)
            elif method == 'DELETE':
                return http_client.delete(url, params=params, headers=headers)
        except Exception as e:
            logger.debug(f"Request error: {e}")
        return None

    def _check_bola_response(self, baseline: Any, test: Any,
                             original_id: str, test_id: str) -> tuple:
        """
        Check if BOLA is likely based on response comparison

        IMPORTANT: Strong evidence required to avoid false positives!
        - Must have clear ID change in response
        - Must have meaningful data difference (not just timestamps/tokens)
        - Must not be an error response

        Returns:
            (is_vulnerable: bool, evidence: str)
        """
        # Both should return 200 OK for BOLA
        if test.status_code != 200:
            return False, ""

        # Also check baseline was successful
        if baseline.status_code != 200:
            return False, ""

        # Response should be different (different object data)
        baseline_text = baseline.text
        test_text = test.text

        # If responses are identical, not vulnerable (same object or error)
        if baseline_text == test_text:
            return False, ""

        # FP Prevention: Skip if response looks like an error
        error_indicators = [
            'not found', 'does not exist', 'invalid id', 'unauthorized',
            'forbidden', 'access denied', 'no permission', 'error',
            '"status":"error"', '"success":false', '"success": false'
        ]
        test_lower = test_text.lower()
        if any(err in test_lower for err in error_indicators):
            return False, ""

        # FP Prevention: Skip very short responses (likely errors)
        if len(test_text) < 50:
            return False, ""

        # Check for different object data in JSON response
        try:
            baseline_json = json.loads(baseline_text) if baseline_text and baseline_text.strip().startswith(('{', '[')) else None
            test_json = json.loads(test_text) if test_text and test_text.strip().startswith(('{', '[')) else None

            if baseline_json is None or test_json is None:
                return False, ""

            # Must be dict objects with ID fields
            if not isinstance(baseline_json, dict) or not isinstance(test_json, dict):
                # Could be array - check first item
                if isinstance(test_json, list) and len(test_json) > 0:
                    test_json = test_json[0]
                    baseline_json = baseline_json[0] if isinstance(baseline_json, list) and len(baseline_json) > 0 else {}
                else:
                    return False, ""

            # STRONG EVIDENCE: Check if returned ID matches the REQUESTED test ID
            id_fields = ['id', 'user_id', 'userId', '_id', 'ID', 'uuid', 'uid']
            for key in id_fields:
                if key in test_json and key in baseline_json:
                    returned_id = str(test_json[key])
                    original_returned_id = str(baseline_json[key])

                    # CONFIRMED BOLA: Requested ID X, got back object with ID X
                    if returned_id == test_id and original_returned_id == original_id:
                        # Additional check: Must have other different fields (not just ID)
                        diff_fields = []
                        for field in test_json:
                            if field not in baseline_json:
                                diff_fields.append(field)
                            elif test_json[field] != baseline_json[field]:
                                # Skip dynamic fields that change per-request
                                if field.lower() not in ['timestamp', 'created_at', 'updated_at',
                                                          'last_login', 'token', 'session', 'csrf']:
                                    diff_fields.append(field)

                        if len(diff_fields) >= 2:  # At least 2 different fields
                            evidence = f"**BOLA CONFIRMED** - Accessed different user's object!\n\n"
                            evidence += f"**Original Request ID:** {original_id}\n"
                            evidence += f"**Test Request ID:** {test_id}\n"
                            evidence += f"**Response returned ID:** {returned_id}\n\n"
                            evidence += f"**Different fields detected:** {', '.join(diff_fields[:5])}\n"
                            evidence += f"Original response: {len(baseline_text)} bytes\n"
                            evidence += f"Test response: {len(test_text)} bytes\n\n"
                            evidence += f"**Impact:** Unauthorized access to other users' data"
                            return True, evidence

        except (json.JSONDecodeError, KeyError, TypeError, IndexError):
            pass

        # FP Prevention: Don't report based on length difference alone
        # This caused too many false positives
        return False, ""


def get_module(module_path: str, payload_limit: int = None):
    """Create module instance"""
    return APIBOLAModule(module_path, payload_limit=payload_limit)
