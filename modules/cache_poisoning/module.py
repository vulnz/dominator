"""
Web Cache Poisoning Scanner

Detects cache poisoning vulnerabilities by:
- Testing unkeyed headers that reflect in response
- Detecting cache deception via path confusion
- Testing X-Forwarded-* header poisoning
- Checking for cache key normalization issues
"""

from typing import List, Dict, Any, Optional
from core.base_module import BaseModule
from core.logger import get_logger
import random
import string
import time

logger = get_logger(__name__)


class CachePoisoningModule(BaseModule):
    """Web Cache Poisoning vulnerability scanner"""

    # Headers that might be unkeyed but reflected
    POISON_HEADERS = [
        ('X-Forwarded-Host', 'evil-{rand}.com'),
        ('X-Forwarded-Scheme', 'nothttps'),
        ('X-Forwarded-Proto', 'nothttps'),
        ('X-Original-URL', '/admin'),
        ('X-Rewrite-URL', '/admin'),
        ('X-Host', 'evil-{rand}.com'),
        ('X-Forwarded-Server', 'evil-{rand}.com'),
        ('X-HTTP-Host-Override', 'evil-{rand}.com'),
        ('Forwarded', 'host=evil-{rand}.com'),
        ('X-Custom-IP-Authorization', '127.0.0.1'),
    ]

    # Cache buster to ensure fresh responses
    CACHE_BUSTER_PARAM = '_cb'

    def __init__(self, module_path: str, payload_limit: int = None):
        super().__init__(module_path, payload_limit=payload_limit)
        logger.info("Cache Poisoning module initialized")

    def scan(self, targets: List[Dict[str, Any]], http_client: Any) -> List[Dict[str, Any]]:
        """Scan for cache poisoning vulnerabilities"""
        results = []
        tested_hosts = set()

        logger.info(f"Starting Cache Poisoning scan on {len(targets)} targets")

        for target in targets:
            url = target.get('url', '')
            if not url:
                continue

            # Only test one URL per host
            from urllib.parse import urlparse
            parsed = urlparse(url)
            host = parsed.netloc

            if host in tested_hosts:
                continue
            tested_hosts.add(host)

            # Test for cache poisoning
            result = self._test_cache_poisoning(url, http_client)
            if result:
                results.append(result)

            # Test for cache deception
            deception_result = self._test_cache_deception(url, http_client)
            if deception_result:
                results.append(deception_result)

        logger.info(f"Cache Poisoning scan complete: {len(results)} vulnerabilities found")
        return results

    def _test_cache_poisoning(self, url: str, http_client: Any) -> Optional[Dict]:
        """Test for unkeyed header reflection (cache poisoning)"""
        try:
            # Generate random marker
            rand_marker = ''.join(random.choices(string.ascii_lowercase, k=8))

            for header_name, header_template in self.POISON_HEADERS:
                header_value = header_template.replace('{rand}', rand_marker)

                # Add cache buster to get fresh response
                cache_buster = ''.join(random.choices(string.ascii_lowercase, k=6))
                test_url = self._add_cache_buster(url, cache_buster)

                # Send poisoned request
                poison_headers = {header_name: header_value}
                response1 = http_client.get(test_url, headers=poison_headers)

                if not response1 or response1.status_code != 200:
                    continue

                # Check if our marker is reflected
                if rand_marker in response1.text:
                    # Verify it's cached - request WITHOUT the header
                    time.sleep(0.2)
                    response2 = http_client.get(test_url)

                    if response2 and rand_marker in response2.text:
                        # CONFIRMED: Poisoned response was cached!
                        evidence = f"**CONFIRMED Web Cache Poisoning**\n\n"
                        evidence += f"**Vulnerable Header:** `{header_name}`\n"
                        evidence += f"**Injected Value:** `{header_value}`\n"
                        evidence += f"**Marker Found:** `{rand_marker}`\n\n"
                        evidence += f"**Attack Scenario:**\n"
                        evidence += f"1. Attacker sends request with malicious {header_name} header\n"
                        evidence += f"2. Server reflects the value in response\n"
                        evidence += f"3. Cache stores the poisoned response\n"
                        evidence += f"4. Victims receive the poisoned content\n\n"
                        evidence += f"**Impact:** XSS, Redirect, Defacement affecting all users"

                        return self.create_result(
                            vulnerable=True,
                            url=url,
                            parameter=header_name,
                            payload=header_value,
                            evidence=evidence,
                            description=f"Cache poisoning via unkeyed header: {header_name}",
                            confidence=0.95
                        )
                    else:
                        # Reflected but not cached - still interesting
                        evidence = f"**Potential Cache Poisoning**\n\n"
                        evidence += f"**Header:** `{header_name}` is reflected but may not be cached.\n"
                        evidence += f"**Value:** `{header_value}`\n"
                        evidence += f"**Note:** Manual verification needed."

                        return self.create_result(
                            vulnerable=True,
                            url=url,
                            parameter=header_name,
                            payload=header_value,
                            evidence=evidence,
                            description=f"Unkeyed header reflection: {header_name}",
                            confidence=0.70
                        )

        except Exception as e:
            logger.debug(f"Cache poisoning test error: {e}")

        return None

    def _test_cache_deception(self, url: str, http_client: Any) -> Optional[Dict]:
        """Test for cache deception (e.g., /account.css)"""
        try:
            # Common path confusion patterns
            deception_patterns = [
                '/.css',
                '/..%2f',
                '/;.js',
                '/.js',
                '/x.css',
            ]

            for pattern in deception_patterns:
                test_url = url.rstrip('/') + pattern

                response = http_client.get(test_url)
                if not response:
                    continue

                # Check for cache headers indicating it was cached
                cache_headers = ['x-cache', 'cf-cache-status', 'x-varnish', 'age']
                is_cached = any(h in response.headers.lower() for h in cache_headers)

                # Check if response contains sensitive-looking content
                if response.status_code == 200 and len(response.text) > 100:
                    # Look for sensitive content that shouldn't be cached
                    sensitive_indicators = [
                        'session', 'token', 'email', 'username', 'password',
                        'account', 'profile', 'settings', 'balance'
                    ]
                    text_lower = response.text.lower()

                    if any(ind in text_lower for ind in sensitive_indicators):
                        if is_cached or 'max-age' in response.headers.lower():
                            evidence = f"**Potential Cache Deception**\n\n"
                            evidence += f"**URL:** `{test_url}`\n"
                            evidence += f"**Pattern:** `{pattern}`\n"
                            evidence += f"**Response Size:** {len(response.text)} bytes\n\n"
                            evidence += f"**Indicators Found:** Sensitive content may be cached\n"
                            evidence += f"**Impact:** Attacker can trick cache into storing sensitive pages"

                            return self.create_result(
                                vulnerable=True,
                                url=test_url,
                                parameter="path",
                                payload=pattern,
                                evidence=evidence,
                                description=f"Cache deception via path confusion: {pattern}",
                                confidence=0.75
                            )

        except Exception as e:
            logger.debug(f"Cache deception test error: {e}")

        return None

    def _add_cache_buster(self, url: str, buster: str) -> str:
        """Add cache buster parameter to URL"""
        if '?' in url:
            return f"{url}&{self.CACHE_BUSTER_PARAM}={buster}"
        return f"{url}?{self.CACHE_BUSTER_PARAM}={buster}"


def get_module(module_path: str, payload_limit: int = None):
    return CachePoisoningModule(module_path, payload_limit=payload_limit)
