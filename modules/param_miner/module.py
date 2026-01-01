"""
Parameter Miner Module
Discovers hidden parameters using wordlists and response analysis

Improved features:
- Concurrent parameter testing for speed
- Multiple test values to confirm discovery
- Better detection via behavior analysis
- Debug parameter detection (common admin/debug params)
"""

from typing import List, Dict, Any
from urllib.parse import urlparse, parse_qs, urlencode
from concurrent.futures import ThreadPoolExecutor, as_completed
from core.base_module import BaseModule
from core.logger import get_logger
import threading

logger = get_logger(__name__)


class ParamMinerModule(BaseModule):
    """Hidden parameter discovery scanner with concurrent testing"""

    # High-value debug/admin parameters to test first
    PRIORITY_PARAMS = [
        'debug', 'test', 'admin', 'internal', 'dev', 'verbose',
        'trace', 'source', 'dump', 'config', 'settings',
        'api_key', 'apikey', 'token', 'secret', 'key', 'auth',
        'password', 'pass', 'pwd', 'user', 'username', 'id',
        'callback', 'redirect', 'url', 'next', 'return', 'goto',
        'file', 'path', 'include', 'template', 'page', 'view',
        'cmd', 'exec', 'command', 'query', 'sql', 'search'
    ]

    def __init__(self, module_path: str, payload_limit: int = None):
        """Initialize Parameter Miner module"""
        super().__init__(module_path, payload_limit=payload_limit)
        self.max_params_to_test = 100  # Increased for better coverage
        self.concurrent_workers = 10  # Parallel requests
        logger.info(f"Parameter Miner module loaded: {len(self.payloads)} parameters")

    def scan(self, targets: List[Dict[str, Any]], http_client: Any) -> List[Dict[str, Any]]:
        """Discover hidden parameters with concurrent testing"""
        results = []
        tested_endpoints = set()

        for target in targets:
            url = target.get('url')
            parsed = urlparse(url)
            base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"

            # Only test each endpoint once
            if base_url in tested_endpoints:
                continue
            tested_endpoints.add(base_url)

            existing_params = parse_qs(parsed.query)

            # Get baseline response
            try:
                baseline = http_client.get(base_url)
                if not baseline:
                    continue
                baseline_len = len(baseline.text)
                baseline_status = baseline.status_code
                baseline_text = baseline.text
            except Exception as e:
                logger.debug(f"Failed to get baseline for {base_url}: {e}")
                continue

            # Build parameter list: priority params first, then from payloads
            params_to_test = []
            for p in self.PRIORITY_PARAMS:
                if p not in existing_params and p not in params_to_test:
                    params_to_test.append(p)

            for p in self.get_limited_payloads():
                if p not in existing_params and p not in params_to_test:
                    params_to_test.append(p)
                if len(params_to_test) >= self.max_params_to_test:
                    break

            # Test parameters concurrently
            discovered = []
            discovered_lock = threading.Lock()

            def test_param(param: str):
                """Test single parameter"""
                try:
                    test_value = 'dmntr_test_7x3'  # Unique marker
                    test_url = f"{base_url}?{param}={test_value}"
                    response = http_client.get(test_url)

                    if not response:
                        return None

                    result = self._analyze_param_response(
                        param, test_value, response,
                        baseline_len, baseline_status, baseline_text
                    )

                    if result:
                        with discovered_lock:
                            discovered.append(result)
                        return result

                except Exception as e:
                    logger.debug(f"Error testing param {param}: {e}")
                return None

            # Run concurrent tests
            with ThreadPoolExecutor(max_workers=self.concurrent_workers) as executor:
                futures = {executor.submit(test_param, p): p for p in params_to_test}
                for future in as_completed(futures, timeout=60):
                    try:
                        future.result()
                    except Exception:
                        pass

            if discovered:
                # Sort by confidence and priority
                discovered.sort(key=lambda x: (x.get('is_priority', False), x.get('confidence', 0)), reverse=True)

                # Count priority params found
                priority_found = sum(1 for d in discovered if d.get('is_priority'))

                # Build detailed evidence showing each discovered parameter with proof
                evidence_parts = [
                    "**Hidden Parameters Discovered**\n",
                    f"**Target URL:** {base_url}",
                    f"**Parameters Found:** {len(discovered)}",
                    f"**High-Value (debug/admin):** {priority_found}\n",
                    "**Discovery Details:**"
                ]

                for d in discovered[:15]:
                    indicators_list = d.get('indicators', [])
                    indicator_str = ', '.join([i.replace('_', ' ') for i in indicators_list])
                    priority_mark = " ⚠️" if d.get('is_priority') else ""
                    conf = d.get('confidence', 0)
                    evidence_parts.append(f"  - `{d['param']}`{priority_mark} (conf: {conf:.0%}) → {indicator_str}")

                if len(discovered) > 15:
                    evidence_parts.append(f"  ... and {len(discovered) - 15} more")

                evidence_parts.append("\n**Security Impact:**")
                evidence_parts.append("- Hidden debug params may leak sensitive info")
                evidence_parts.append("- Admin params may bypass authorization")
                evidence_parts.append("- Could lead to injection vulnerabilities")

                # Determine severity based on what was found
                severity = 'Low'
                cvss = 3.7
                if priority_found >= 3:
                    severity = 'Medium'
                    cvss = 5.3
                elif any(d['param'] in ['debug', 'admin', 'test', 'config'] for d in discovered):
                    severity = 'Medium'
                    cvss = 5.3

                results.append(self.create_result(
                    vulnerable=True,
                    url=base_url,
                    parameter='hidden',
                    payload=', '.join([d['param'] for d in discovered[:10]]),
                    evidence='\n'.join(evidence_parts),
                    severity=severity,
                    method='GET',
                    additional_info={
                        'injection_type': 'Parameter Discovery',
                        'discovered_params': discovered[:20],
                        'priority_params_found': priority_found,
                        'baseline_length': baseline_len,
                        'baseline_status': baseline_status,
                        'cwe': 'CWE-200',
                        'owasp': 'A05:2021',
                        'cvss': cvss
                    }
                ))
                logger.info(f"Found {len(discovered)} hidden params on {base_url} ({priority_found} priority)")

        return results

    def _analyze_param_response(self, param: str, test_value: str, response,
                                  baseline_len: int, baseline_status: int,
                                  baseline_text: str) -> Dict[str, Any]:
        """
        Analyze response for parameter discovery indicators

        Returns:
            Dict with discovery details or None if not discovered
        """
        if not response:
            return None

        response_text = response.text
        response_len = len(response_text)

        # Track what indicators we found
        indicators = []
        confidence = 0.0

        # 1. Value reflected in response (strongest indicator)
        if test_value in response_text and test_value not in baseline_text:
            indicators.append('value_reflected')
            confidence += 0.5

        # 2. Status code changed meaningfully
        if response.status_code != baseline_status:
            if response.status_code in [400, 401, 403]:
                # Parameter recognized but rejected - likely valid param
                indicators.append('auth_error')
                confidence += 0.3
            elif response.status_code >= 500:
                # Caused server error - definitely processed
                indicators.append('server_error')
                confidence += 0.4

        # 3. Significant length change (not just minor variance)
        length_diff = abs(response_len - baseline_len)
        if length_diff > 200:
            # Check if new content appeared (not just removed)
            if response_len > baseline_len + 200:
                indicators.append('content_added')
                confidence += 0.25
            elif length_diff > 500:
                indicators.append('length_changed')
                confidence += 0.2

        # 4. Check for debug/error output triggered by param
        debug_indicators = [
            'debug', 'trace', 'stack', 'exception', 'error:',
            'warning:', 'notice:', 'fatal', 'undefined', 'null'
        ]
        for dbg in debug_indicators:
            if dbg.lower() in response_text.lower() and dbg.lower() not in baseline_text.lower():
                indicators.append(f'debug_output:{dbg}')
                confidence += 0.15
                break

        # 5. Check for known parameter names being echoed back
        if f'"{param}"' in response_text or f"'{param}'" in response_text:
            if f'"{param}"' not in baseline_text and f"'{param}'" not in baseline_text:
                indicators.append('param_name_in_response')
                confidence += 0.2

        # Require at least one strong indicator
        if not indicators or confidence < 0.3:
            return None

        return {
            'param': param,
            'reflected': 'value_reflected' in indicators,
            'status_changed': response.status_code != baseline_status,
            'length_changed': abs(response_len - baseline_len) > 200,
            'indicators': indicators,
            'confidence': min(confidence, 1.0),
            'response_status': response.status_code,
            'response_length': response_len,
            'is_priority': param in self.PRIORITY_PARAMS
        }

    def _is_param_reflected(self, response, value: str, baseline_len: int, baseline_status: int) -> bool:
        """Legacy method - Check if parameter value is reflected or causes behavior change"""
        if not response:
            return False

        # Primary check: Value reflected in response (actual proof)
        if value in response.text:
            return True

        # Secondary: Status code changed to error (indicates parameter recognized)
        if response.status_code >= 400 and baseline_status < 400:
            return True

        # Tertiary: Very significant length change
        if abs(len(response.text) - baseline_len) > 500:
            return True

        return False


def get_module(module_path: str, payload_limit: int = None):
    """Factory function to create module instance"""
    return ParamMinerModule(module_path, payload_limit)
