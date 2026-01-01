"""
Race Condition Scanner

Detects race condition vulnerabilities by:
- Sending concurrent requests to sensitive endpoints using barrier synchronization
- Testing for double-spend/double-use on redemption endpoints
- Checking for Time-of-Check to Time-of-Use (TOCTOU) issues
- Using threading barriers to ensure simultaneous request firing
"""

from typing import List, Dict, Any, Optional
from core.base_module import BaseModule
from core.logger import get_logger
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

logger = get_logger(__name__)


class RaceConditionModule(BaseModule):
    """Race Condition vulnerability scanner with barrier synchronization"""

    # Endpoints likely vulnerable to race conditions
    SENSITIVE_PATTERNS = [
        # Financial/transactional
        '/redeem', '/voucher', '/coupon', '/promo', '/discount',
        '/transfer', '/send', '/pay', '/checkout', '/purchase',
        '/withdraw', '/deposit', '/claim', '/bonus', '/reward',
        '/refund', '/cancel', '/reverse',
        # User actions
        '/vote', '/upvote', '/downvote', '/like', '/dislike',
        '/follow', '/unfollow', '/subscribe', '/register', '/signup',
        '/apply', '/submit', '/create', '/add', '/insert',
        '/order', '/book', '/reserve', '/schedule',
        # Resource limits
        '/download', '/export', '/generate', '/request',
        '/activate', '/enable', '/unlock', '/upgrade',
        # Tokens/codes
        '/token', '/code', '/invite', '/referral', '/gift'
    ]

    # Number of concurrent requests - increased for better detection
    CONCURRENT_REQUESTS = 20

    # Number of test rounds
    TEST_ROUNDS = 2

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
        """Test endpoint for race condition vulnerability using barrier synchronization"""
        try:
            all_responses = []

            # Run multiple test rounds for better detection
            for round_num in range(self.TEST_ROUNDS):
                responses = []
                response_lock = threading.Lock()
                request_times = []
                time_lock = threading.Lock()

                # Create barrier to synchronize all threads
                # All threads will wait at the barrier until everyone is ready
                barrier = threading.Barrier(self.CONCURRENT_REQUESTS, timeout=10)

                def make_synchronized_request(thread_id: int):
                    """Make a synchronized request - all threads fire at same time"""
                    try:
                        # Wait for all threads to be ready
                        barrier.wait()

                        # Record precise start time
                        start_time = time.perf_counter()

                        # Make the actual request
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

                        end_time = time.perf_counter()

                        with response_lock:
                            responses.append({
                                'status': resp.status_code if resp else 0,
                                'text': resp.text[:500] if resp else '',
                                'length': len(resp.text) if resp else 0,
                                'thread_id': thread_id,
                                'response_time': end_time - start_time
                            })

                        with time_lock:
                            request_times.append(start_time)

                    except threading.BrokenBarrierError:
                        logger.debug(f"Thread {thread_id}: Barrier broken/timeout")
                    except Exception as e:
                        logger.debug(f"Race request error (thread {thread_id}): {e}")

                # Send concurrent requests with barrier synchronization
                with ThreadPoolExecutor(max_workers=self.CONCURRENT_REQUESTS) as executor:
                    futures = [
                        executor.submit(make_synchronized_request, i)
                        for i in range(self.CONCURRENT_REQUESTS)
                    ]
                    for future in as_completed(futures, timeout=30):
                        try:
                            future.result()
                        except Exception:
                            pass

                all_responses.extend(responses)

                # Log timing spread (shows how synchronized the requests were)
                if request_times:
                    time_spread = max(request_times) - min(request_times)
                    logger.debug(f"Round {round_num + 1}: {len(responses)} responses, "
                               f"timing spread: {time_spread*1000:.2f}ms")

            # Analyze all responses for race condition indicators
            if len(all_responses) < 5:
                return None  # Not enough responses

            responses = all_responses

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
                    evidence += f"**Test Configuration:**\n"
                    evidence += f"- Concurrent Requests: {self.CONCURRENT_REQUESTS}\n"
                    evidence += f"- Test Rounds: {self.TEST_ROUNDS}\n"
                    evidence += f"- Total Requests Sent: {self.CONCURRENT_REQUESTS * self.TEST_ROUNDS}\n\n"
                    evidence += f"**Results:**\n"
                    evidence += f"- Successful (2xx): {success_count}\n"
                    evidence += f"- Errors (4xx): {error_count}\n"
                    evidence += f"- Total responses: {len(responses)}\n\n"

                    # Calculate success rate
                    success_rate = (success_count / len(responses)) * 100 if responses else 0

                    if success_count > 10 or success_rate > 50:
                        evidence += f"**CRITICAL RISK:** {success_count} requests succeeded simultaneously ({success_rate:.0f}%).\n"
                        evidence += f"This strongly indicates a race condition vulnerability.\n\n"
                        confidence = 0.95
                    elif success_count > 5:
                        evidence += f"**HIGH RISK:** Multiple requests succeeded simultaneously.\n"
                        evidence += f"This may allow double-spend or duplicate operations.\n\n"
                        confidence = 0.85
                    else:
                        evidence += f"**MEDIUM RISK:** Some requests succeeded concurrently.\n"
                        evidence += f"Manual verification recommended.\n\n"
                        confidence = 0.70

                    evidence += f"**Impact:**\n"
                    evidence += f"- Voucher/coupon double-redemption\n"
                    evidence += f"- Balance manipulation / double-spend\n"
                    evidence += f"- Vote/like inflation\n"
                    evidence += f"- Bypass usage limits / quotas\n"
                    evidence += f"- Resource exhaustion\n\n"
                    evidence += f"**Remediation:**\n"
                    evidence += f"- Implement database-level locking (SELECT FOR UPDATE)\n"
                    evidence += f"- Use atomic transactions\n"
                    evidence += f"- Implement idempotency keys\n"
                    evidence += f"- Add mutex/semaphore for critical operations\n"
                    evidence += f"- Use optimistic locking with version checks"

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
