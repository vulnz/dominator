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

        Returns:
            (is_vulnerable: bool, evidence: str)
        """
        # Both should return 200 OK for BOLA
        if test.status_code != 200:
            return False, ""

        # Response should be different (different object data)
        baseline_text = baseline.text
        test_text = test.text

        # If responses are identical, not vulnerable (same object or error)
        if baseline_text == test_text:
            return False, ""

        # Check for different object data
        try:
            # FIX: HTTPResponse doesn't have .json() method, use json.loads() instead
            baseline_json = json.loads(baseline_text) if baseline_text and baseline_text.strip().startswith(('{', '[')) else {}
            test_json = json.loads(test_text) if test_text and test_text.strip().startswith(('{', '[')) else {}

            # Look for ID fields that changed
            if isinstance(baseline_json, dict) and isinstance(test_json, dict):
                # Check if returned ID matches the requested ID
                for key in ['id', 'user_id', 'userId', '_id', 'ID']:
                    if key in test_json:
                        returned_id = str(test_json[key])
                        if returned_id == test_id or returned_id != original_id:
                            evidence = f"BOLA Confirmed!\n\n"
                            evidence += f"**Original ID:** {original_id}\n"
                            evidence += f"**Test ID:** {test_id}\n"
                            evidence += f"**Returned ID in response:** {returned_id}\n\n"
                            evidence += f"**Different data returned:**\n"
                            evidence += f"Original response: {len(baseline_text)} bytes\n"
                            evidence += f"Test response: {len(test_text)} bytes\n\n"
                            evidence += f"**Impact:** Unauthorized access to other users' data"
                            return True, evidence

        except json.JSONDecodeError:
            pass

        # Different response length might indicate different data
        len_diff = abs(len(baseline_text) - len(test_text))
        if len_diff > 50:  # Significant difference
            evidence = f"Possible BOLA - Different response data\n\n"
            evidence += f"**Original ID:** {original_id} ({len(baseline_text)} bytes)\n"
            evidence += f"**Test ID:** {test_id} ({len(test_text)} bytes)\n"
            evidence += f"**Difference:** {len_diff} bytes\n\n"
            evidence += f"Manual verification recommended."
            return True, evidence

        return False, ""


def get_module(module_path: str, payload_limit: int = None):
    """Create module instance"""
    return APIBOLAModule(module_path, payload_limit=payload_limit)
