"""
Race Condition Scanner

Detects race condition vulnerabilities by:
- Sending concurrent requests to sensitive endpoints
- Testing for double-spend/double-use on redemption endpoints
- Checking for Time-of-Check to Time-of-Use (TOCTOU) issues
"""

from typing import List, Dict, Any, Optional
from core.base_module import BaseModule
from core.logger import get_logger
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

logger = get_logger(__name__)


class RaceConditionModule(BaseModule):
    """Race Condition vulnerability scanner"""

    # Endpoints likely vulnerable to race conditions
    SENSITIVE_PATTERNS = [
        '/redeem', '/voucher', '/coupon', '/promo',
        '/transfer', '/send', '/pay', '/checkout',
        '/withdraw', '/claim', '/bonus', '/reward',
        '/vote', '/like', '/follow', '/register',
        '/apply', '/submit', '/create', '/order'
    ]

    # Number of concurrent requests
    CONCURRENT_REQUESTS = 10

    def __init__(self, module_path: str, payload_limit: int = None):
        super().__init__(module_path, payload_limit=payload_limit)
        logger.info("Race Condition module initialized")

    def scan(self, targets: List[Dict[str, Any]], http_client: Any) -> List[Dict[str, Any]]:
        """Scan for race condition vulnerabilities"""
        results = []

        logger.info(f"Starting Race Condition scan on {len(targets)} targets")

        for target in targets:
            url = target.get('url', '')
            method = target.get('method', 'GET').upper()
            params = target.get('params', {})
            body = target.get('body', {})
            headers = target.get('headers', {})

            # Only test sensitive endpoints
            if not self._is_sensitive_endpoint(url):
                continue

            # Only test state-changing methods
            if method not in ['POST', 'PUT', 'PATCH', 'DELETE']:
                continue

            # Test for race condition
            result = self._test_race_condition(url, method, params, body, headers, http_client)
            if result:
                results.append(result)

        logger.info(f"Race Condition scan complete: {len(results)} findings")
        return results

    def _is_sensitive_endpoint(self, url: str) -> bool:
        """Check if endpoint is likely sensitive to race conditions"""
        url_lower = url.lower()
        return any(pattern in url_lower for pattern in self.SENSITIVE_PATTERNS)

    def _test_race_condition(self, url: str, method: str, params: Dict,
                              body: Dict, headers: Dict, http_client: Any) -> Optional[Dict]:
        """Test endpoint for race condition vulnerability"""
        try:
            responses = []
            response_lock = threading.Lock()

            def make_request():
                """Make a single request"""
                try:
                    if method == 'POST':
                        resp = http_client.post(url, json=body, headers=headers)
                    elif method == 'PUT':
                        resp = http_client.put(url, json=body, headers=headers)
                    elif method == 'PATCH':
                        resp = http_client.patch(url, json=body, headers=headers)
                    elif method == 'DELETE':
                        resp = http_client.delete(url, headers=headers)
                    else:
                        resp = http_client.request(method, url, json=body, headers=headers)

                    with response_lock:
                        responses.append({
                            'status': resp.status_code if resp else 0,
                            'text': resp.text[:500] if resp else '',
                            'length': len(resp.text) if resp else 0
                        })
                except Exception as e:
                    logger.debug(f"Race request error: {e}")

            # Send concurrent requests
            with ThreadPoolExecutor(max_workers=self.CONCURRENT_REQUESTS) as executor:
                futures = [executor.submit(make_request) for _ in range(self.CONCURRENT_REQUESTS)]
                for future in as_completed(futures, timeout=30):
                    try:
                        future.result()
                    except Exception:
                        pass

            # Analyze responses for race condition indicators
            if len(responses) < 5:
                return None  # Not enough responses

            # Count successful responses
            success_count = sum(1 for r in responses if r['status'] in [200, 201, 204])
            error_count = sum(1 for r in responses if r['status'] in [400, 409, 429])

            # Race condition indicators:
            # 1. Multiple successes on single-use endpoint (e.g., voucher redeemed multiple times)
            # 2. Inconsistent responses (some succeed, some fail)
            # 3. All requests succeed when only one should

            if success_count >= 2:
                # Potential race - multiple successful requests
                # Check if responses suggest duplicate operations
                is_duplicate_operation = self._check_duplicate_operation(responses)

                if is_duplicate_operation or success_count > 3:
                    evidence = f"**Potential Race Condition Detected**\n\n"
                    evidence += f"**Endpoint:** {url}\n"
                    evidence += f"**Method:** {method}\n"
                    evidence += f"**Concurrent Requests:** {self.CONCURRENT_REQUESTS}\n\n"
                    evidence += f"**Results:**\n"
                    evidence += f"- Successful (2xx): {success_count}\n"
                    evidence += f"- Errors (4xx): {error_count}\n"
                    evidence += f"- Total responses: {len(responses)}\n\n"

                    if success_count > 5:
                        evidence += f"**HIGH RISK:** Multiple requests succeeded simultaneously.\n"
                        evidence += f"This may allow double-spend or duplicate operations.\n\n"
                        confidence = 0.85
                    else:
                        evidence += f"**MEDIUM RISK:** Some requests succeeded concurrently.\n"
                        evidence += f"Manual verification recommended.\n\n"
                        confidence = 0.70

                    evidence += f"**Impact:**\n"
                    evidence += f"- Voucher/coupon double-redemption\n"
                    evidence += f"- Balance manipulation\n"
                    evidence += f"- Vote/like inflation\n"
                    evidence += f"- Bypass usage limits\n\n"
                    evidence += f"**Recommendation:** Implement proper locking, transactions, or idempotency keys."

                    result = self.create_result(
                        vulnerable=True,
                        url=url,
                        parameter="Concurrent Requests",
                        payload=f"{self.CONCURRENT_REQUESTS} simultaneous {method} requests",
                        evidence=evidence,
                        description=f"Race condition: {success_count}/{len(responses)} concurrent requests succeeded",
                        confidence=confidence
                    )
                    result['cwe'] = 'CWE-362'
                    result['cwe_name'] = 'Concurrent Execution using Shared Resource with Improper Synchronization'
                    result['owasp'] = 'A04:2021'
                    result['owasp_name'] = 'Insecure Design'
                    result['severity'] = 'high' if success_count > 5 else 'medium'
                    return result

        except Exception as e:
            logger.debug(f"Race condition test error: {e}")

        return None

    def _check_duplicate_operation(self, responses: List[Dict]) -> bool:
        """Check if responses indicate duplicate successful operations"""
        success_responses = [r for r in responses if r['status'] in [200, 201]]

        if len(success_responses) < 2:
            return False

        # Check for common "success" patterns in response bodies
        success_indicators = [
            'success', 'redeemed', 'applied', 'created', 'completed',
            'transferred', 'claimed', 'submitted'
        ]

        matching_success = 0
        for resp in success_responses:
            text_lower = resp['text'].lower()
            if any(ind in text_lower for ind in success_indicators):
                matching_success += 1

        # If multiple responses contain success indicators, likely race condition
        return matching_success >= 2


def get_module(module_path: str, payload_limit: int = None):
    return RaceConditionModule(module_path, payload_limit=payload_limit)
