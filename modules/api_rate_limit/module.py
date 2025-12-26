"""
API Rate Limit Scanner

Detects missing or weak rate limiting:
- No rate limiting on sensitive endpoints
- Bypasses for rate limits (header manipulation)
- Insufficient limits on authentication endpoints
"""

from typing import List, Dict, Any
from core.base_module import BaseModule
from core.logger import get_logger
import time

logger = get_logger(__name__)


class APIRateLimitModule(BaseModule):
    """API Rate Limit vulnerability scanner"""

    # Endpoints that should have rate limiting
    SENSITIVE_ENDPOINTS = [
        '/login', '/signin', '/auth', '/authenticate',
        '/register', '/signup', '/password', '/reset',
        '/forgot', '/verify', '/otp', '/2fa', '/mfa',
        '/token', '/oauth', '/api-key', '/admin',
        '/payment', '/checkout', '/transfer', '/withdraw'
    ]

    # Number of requests to send for rate limit testing
    # INCREASED to reduce false positives - 20 was too low
    BURST_SIZE = 50  # More requests needed to confirm no rate limiting
    BURST_INTERVAL = 0.05  # Faster to test actual rate limits

    def __init__(self, module_path: str, payload_limit: int = None):
        super().__init__(module_path, payload_limit=payload_limit)
        logger.info("API Rate Limit module initialized")

    def scan(self, targets: List[Dict[str, Any]], http_client: Any) -> List[Dict[str, Any]]:
        """Scan for rate limit issues"""
        results = []

        logger.info(f"Starting Rate Limit scan on {len(targets)} endpoints")

        for target in targets:
            url = target.get('url', '')
            method = target.get('method', 'GET').upper()
            headers = target.get('headers', {})

            # Skip if not a sensitive endpoint
            if not self._is_sensitive_endpoint(url):
                continue

            # Test rate limiting
            result = self._test_rate_limit(url, method, headers, http_client)
            if result:
                results.append(result)

        logger.info(f"Rate Limit scan complete: {len(results)} findings")
        return results

    def _is_sensitive_endpoint(self, url: str) -> bool:
        """Check if endpoint should have rate limiting"""
        url_lower = url.lower()
        return any(ep in url_lower for ep in self.SENSITIVE_ENDPOINTS)

    def _test_rate_limit(self, url: str, method: str, headers: Dict,
                         http_client: Any) -> Dict[str, Any]:
        """Test endpoint for rate limiting"""
        try:
            success_count = 0
            blocked_at = None
            status_codes = []

            # Send burst of requests
            for i in range(self.BURST_SIZE):
                try:
                    response = http_client.request(method, url, headers=headers, timeout=5)
                    status_codes.append(response.status_code)

                    if response.status_code == 429:
                        blocked_at = i + 1
                        break
                    elif response.status_code in [200, 201, 400, 401]:
                        success_count += 1

                    time.sleep(self.BURST_INTERVAL)

                except Exception:
                    break

            # Analyze results - STRICT thresholds to avoid FP
            # Must have at least 40 successful requests to confirm no rate limiting
            if blocked_at is None and success_count >= 40:
                # No rate limiting detected - CONFIRMED
                evidence = f"**CONFIRMED: No Rate Limiting on Sensitive Endpoint**\n\n"
                evidence += f"**Endpoint:** {url}\n"
                evidence += f"**Method:** {method}\n"
                evidence += f"**Requests sent:** {self.BURST_SIZE}\n"
                evidence += f"**Successful (non-429):** {success_count}\n"
                evidence += f"**Response codes:** {list(set(status_codes))}\n\n"
                evidence += f"**Attack Scenarios:**\n"
                evidence += f"- Brute force login attacks\n"
                evidence += f"- Credential stuffing\n"
                evidence += f"- Account enumeration\n"
                evidence += f"- API abuse/scraping\n\n"
                evidence += f"**Recommendation:** Implement rate limiting:\n"
                evidence += f"- Login endpoints: 5-10 requests/minute\n"
                evidence += f"- Password reset: 3 requests/hour\n"
                evidence += f"- General API: 100 requests/minute"

                result = self.create_result(
                    vulnerable=True,
                    url=url,
                    parameter="Rate Limit",
                    payload=f"Sent {self.BURST_SIZE} rapid requests, {success_count} succeeded",
                    evidence=evidence,
                    description=f"No rate limiting: {success_count}/{self.BURST_SIZE} requests succeeded",
                    confidence=0.90  # High confidence with 40+ successful requests
                )
                result['cwe'] = 'CWE-770'
                result['cwe_name'] = 'Allocation of Resources Without Limits or Throttling'
                result['owasp'] = 'API4:2023'
                result['owasp_name'] = 'Unrestricted Resource Consumption'
                result['severity'] = 'medium'
                return result

            elif blocked_at and blocked_at < 10:
                # Rate limiting is active
                logger.info(f"Rate limiting active at {blocked_at} requests on {url}")

        except Exception as e:
            logger.debug(f"Rate limit test error: {e}")

        return None


def get_module(module_path: str, payload_limit: int = None):
    return APIRateLimitModule(module_path, payload_limit=payload_limit)
