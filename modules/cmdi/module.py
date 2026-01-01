"""
Command Injection Scanner Module

Detects OS command injection vulnerabilities
"""

from typing import List, Dict, Any
from core.base_module import BaseModule
from detectors.base_detector import BaseDetector
from core.logger import get_logger
from utils.oob_detector import OOBDetector

logger = get_logger(__name__)


class CMDiModule(BaseModule):
    """Command Injection vulnerability scanner"""

    def __init__(self, module_path: str, payload_limit: int = None):
        """Initialize CMDi module"""
        super().__init__(module_path, payload_limit=payload_limit)

        # Initialize OOB detector for blind command injection
        self.oob_detector = OOBDetector()

        # Load patterns from TXT files
        self.linux_patterns = BaseDetector.load_patterns_from_file('cmdi/linux')
        self.windows_patterns = BaseDetector.load_patterns_from_file('cmdi/windows')
        self.all_patterns = self.linux_patterns + self.windows_patterns

        logger.info(f"CMDi module loaded: {len(self.linux_patterns)} Linux patterns, "
                   f"{len(self.windows_patterns)} Windows patterns")

    def scan(self, targets: List[Dict[str, Any]], http_client: Any) -> List[Dict[str, Any]]:
        """
        Scan for Command Injection vulnerabilities

        Args:
            targets: List of URLs with parameters
            http_client: HTTP client

        Returns:
            List of results
        """
        results = []

        logger.info(f"Starting CMDi scan on {len(targets)} targets")
        logger.info(f"Using {len(self.payloads)} payloads and {len(self.all_patterns)} detection patterns")

        for target in targets:
            url = target.get('url')
            params = target.get('params', {})
            method = target.get('method', 'GET').upper()

            logger.debug(f"Target URL: {url}, Params: {params}, Method: {method}")

            if not params:
                logger.debug(f"Skipping {url} - no parameters found")
                continue

            # Test each parameter
            for param_name in params:
                logger.debug(f"Testing CMDi in parameter: {param_name} via {method}")

                # CRITICAL: Get baseline response FIRST (without payload)
                baseline_text = self._get_baseline_response(url, params, param_name, method, http_client)

                # FIRST: Test Time-based Blind CMDi (sleep commands)
                time_result = self._test_time_based_cmdi(url, params, param_name, method, http_client)
                if time_result:
                    results.append(time_result)
                    logger.info(f"✓ Blind CMDi (Time-based) found in {url} (parameter: {param_name})")
                    continue  # Move to next parameter

                # SECOND: Test OOB (Blind Command Injection)
                oob_result = self._test_oob_cmdi(url, params, param_name, method, http_client)
                if oob_result:
                    results.append(oob_result)
                    logger.info(f"✓ Blind CMDi (OOB) found in {url} (parameter: {param_name})")
                    continue  # Move to next parameter

                # THIRD: Try regular payloads with BASELINE COMPARISON
                for payload in self.get_limited_payloads():  # Limit to 30 payloads
                    test_params = params.copy()
                    test_params[param_name] = str(params[param_name]) + payload

                    # Send request using appropriate method
                    if method == 'POST':
                        response = http_client.post(url, data=test_params)
                    else:
                        response = http_client.get(url, params=test_params)

                    if not response:
                        continue

                    # Detect command injection WITH BASELINE COMPARISON
                    detected, confidence, evidence = self._detect_cmdi(
                        payload, response, baseline_text
                    )

                    if detected:
                        response_text = getattr(response, 'text', '')[:5000]
                        result = self.create_result(
                            vulnerable=True,
                            url=url,
                            parameter=param_name,
                            payload=payload,
                            evidence=evidence,
                            description="OS Command Injection vulnerability detected. "
                                       "Server executes arbitrary system commands.",
                            confidence=confidence,
                            method=method,
                            response=response_text
                        )

                        # Add metadata from config
                        result['cwe'] = self.config.get('cwe', 'CWE-78')
                        result['owasp'] = self.config.get('owasp', 'A03:2021')
                        result['cvss'] = self.config.get('cvss', '9.8')

                        results.append(result)
                        logger.info(f"✓ CMDi found in {url} (parameter: {param_name}, confidence: {confidence:.2f})")

                        # Move to next parameter after finding vuln
                        break

        logger.info(f"CMDi scan complete: {len(results)} vulnerabilities found")
        return results

    def _get_baseline_response(self, url: str, params: Dict[str, Any], param_name: str,
                                method: str, http_client: Any) -> str:
        """
        Get baseline response without payload for comparison

        Args:
            url: Target URL
            params: Original parameters
            param_name: Parameter being tested
            method: HTTP method
            http_client: HTTP client

        Returns:
            Baseline response text
        """
        try:
            if method == 'POST':
                response = http_client.post(url, data=params)
            else:
                response = http_client.get(url, params=params)

            if response:
                return getattr(response, 'text', '')
        except Exception as e:
            logger.debug(f"Error getting baseline: {e}")

        return ""

    def _detect_cmdi(self, payload: str, response: Any, baseline_text: str = "") -> tuple:
        """
        Detect command injection WITH BASELINE COMPARISON AND REFLECTION FILTERING

        CRITICAL: Only report if indicators appear NEW (not in baseline)
        AND are NOT just the payload being reflected back.

        Args:
            payload: Injected payload
            response: HTTP response
            baseline_text: Response without payload (for comparison)

        Returns:
            (detected: bool, confidence: float, evidence: str)
        """
        # STAGE 1: Basic checks
        if response.status_code != 200:
            return False, 0.0, ""

        response_text = response.text
        response_lower = response_text.lower()
        payload_lower = payload.lower()

        # CRITICAL: Check for payload reflection - if payload is reflected, be MORE strict
        is_reflected = payload_lower in response_lower

        # STAGE 2: Check for STRONG indicators (definitive command output)
        strong_indicators = [
            'uid=',          # Linux id command output
            'gid=',          # Linux id command output
            'root:x:0:0:',   # /etc/passwd content
            'Linux version', # uname output
            'GNU/Linux',     # uname output
            'drwxr-xr-x',    # ls -la output
            '-rw-r--r--',    # ls -la output
            '/bin/bash',     # Shell path
            '/bin/sh',       # Shell path
        ]

        # Find strong indicators that appear NEW (not in baseline) AND NOT from reflection
        new_indicators = []
        for indicator in strong_indicators:
            if indicator in response_text:
                # CRITICAL: Check if this indicator is NEW (wasn't in baseline)
                if baseline_text and indicator in baseline_text:
                    logger.debug(f"CMDi indicator '{indicator}' already in baseline - skipping")
                    continue

                # CRITICAL: Check if indicator is OUTSIDE of reflected payload
                if is_reflected:
                    if not self._indicator_outside_reflection(indicator, response_text, payload):
                        logger.debug(f"CMDi indicator '{indicator}' is within reflected payload - skipping")
                        continue

                new_indicators.append(indicator)

        if new_indicators:
            # Strong indicator found and it's NEW - high confidence CMDi
            confidence = 0.85 + (0.05 * len(new_indicators))
            confidence = min(1.0, confidence)

            evidence = self._generate_strong_evidence(new_indicators, response_text, baseline_text)
            logger.debug(f"CMDi detected via strong NEW indicator: {new_indicators}")
            return True, confidence, evidence

        # STAGE 3: Check for WEAK indicators (require multiple + baseline comparison)
        weak_indicators = [
            'Windows',       # Only if genuinely new
            'win.ini',       # Only if genuinely new
            'C:\\',          # Only if genuinely new
            'Program Files', # Only if genuinely new
        ]

        # These are VERY prone to false positives - require STRICT validation
        new_weak = []
        for indicator in weak_indicators:
            if indicator in response_text:
                # MUST be new and not just reflected payload text
                if baseline_text and indicator not in baseline_text:
                    # Additional check: ensure it's not just our payload being echoed
                    if indicator not in payload:
                        new_weak.append(indicator)

        # Weak indicators alone are NOT enough - require at least 3
        if len(new_weak) >= 3:
            confidence = 0.55
            evidence = self._generate_weak_evidence(new_weak, response_text, baseline_text)
            logger.debug(f"CMDi detected via multiple weak NEW indicators: {new_weak}")
            return True, confidence, evidence

        # STAGE 4: Response length change detection (blind CMDi indicator)
        if baseline_text:
            len_diff = abs(len(response_text) - len(baseline_text))
            len_ratio = len(response_text) / max(1, len(baseline_text))

            # Significant response change might indicate command execution
            if len_ratio > 1.5 and len_diff > 200:
                # Look for ANY command output patterns in the new content
                if self._has_command_output_structure(response_text, baseline_text):
                    confidence = 0.60
                    evidence = f"Response length increased significantly ({len_diff} bytes). New content appears to contain command output structure."
                    logger.debug(f"CMDi detected via response length change")
                    return True, confidence, evidence

        return False, 0.0, ""

    def _indicator_outside_reflection(self, indicator: str, response_text: str, payload: str) -> bool:
        """
        Check if indicator appears OUTSIDE of reflected payload context

        CRITICAL: Prevents false positives when payload contains indicator-like strings
        and is simply reflected back.

        Args:
            indicator: CMDi indicator to check
            response_text: Response text
            payload: Original payload

        Returns:
            True if indicator appears outside of payload reflection
        """
        response_lower = response_text.lower()
        indicator_lower = indicator.lower()
        payload_lower = payload.lower()

        # Find all positions where payload appears
        payload_positions = []
        start = 0
        while True:
            pos = response_lower.find(payload_lower, start)
            if pos == -1:
                break
            payload_positions.append((pos, pos + len(payload_lower)))
            start = pos + 1

        if not payload_positions:
            return True  # Payload not reflected, indicator is genuine

        # Find all positions where indicator appears
        indicator_positions = []
        start = 0
        while True:
            pos = response_lower.find(indicator_lower, start)
            if pos == -1:
                break
            indicator_positions.append(pos)
            start = pos + 1

        # Check if ANY indicator position is OUTSIDE ALL payload ranges
        for ind_pos in indicator_positions:
            is_inside_payload = False
            for pay_start, pay_end in payload_positions:
                if pay_start <= ind_pos < pay_end:
                    is_inside_payload = True
                    break

            if not is_inside_payload:
                return True  # Found indicator outside of payload reflection

        return False  # All indicators within payload - FALSE POSITIVE

    def _has_command_output_structure(self, response_text: str, baseline_text: str) -> bool:
        """
        Check if response contains command output structure (not in baseline)

        Args:
            response_text: Response with payload
            baseline_text: Response without payload

        Returns:
            True if command output structure detected
        """
        # Patterns that indicate command output (not just webpage content)
        output_patterns = [
            r'drwx',           # Directory listing
            r'-rw-',           # File permissions
            r'total \d+',      # ls output header
            r'\d+:\d+',        # Time format in ls
            r'/home/',         # Linux paths
            r'/var/',          # Linux paths
            r'/usr/',          # Linux paths
            r'/etc/',          # Linux paths
            r'HKEY_',          # Windows registry
            r'\[\w+\].*=',     # INI file content
        ]

        import re
        for pattern in output_patterns:
            matches_in_response = len(re.findall(pattern, response_text))
            matches_in_baseline = len(re.findall(pattern, baseline_text)) if baseline_text else 0

            # Pattern count increased significantly
            if matches_in_response > matches_in_baseline + 2:
                return True

        return False

    def _generate_strong_evidence(self, indicators: List[str], response_text: str, baseline_text: str) -> str:
        """Generate evidence for strong CMDi indicators"""
        evidence_parts = []

        for indicator in indicators[:3]:
            snippet = BaseDetector.get_evidence(indicator, response_text, context_size=150)
            evidence_parts.append(snippet)

        evidence = f"CONFIRMED: Command execution output detected. "
        evidence += f"Strong indicators found: {', '.join(indicators[:5])}. "
        evidence += f"These indicators were NOT present in baseline response. "
        evidence += "Proof: " + " | ".join(evidence_parts[:2])

        return evidence

    def _generate_weak_evidence(self, indicators: List[str], response_text: str, baseline_text: str) -> str:
        """Generate evidence for weak CMDi indicators"""
        evidence = f"Possible command execution. "
        evidence += f"Multiple indicators appeared: {', '.join(indicators[:5])}. "
        evidence += f"These appeared in response but not in baseline. "
        evidence += "Manual verification recommended."

        return evidence

    def _validate_context(self, payload: str, response_text: str, matches: List[str]) -> bool:
        """
        Validate that patterns appear in proper context
        IMPROVED: More flexible to catch real command injection

        Args:
            payload: Injected payload
            response_text: Response text
            matches: Matched patterns

        Returns:
            True if context is valid
        """
        # Check 1: Very strong indicators (immediate pass)
        very_strong_indicators = [
            'uid=',
            'gid=',
            'root:x:0:0:',
            'Linux version',
            'GNU/Linux',
            'kernel',
        ]

        very_strong_found = sum(1 for ind in very_strong_indicators if ind in response_text)
        if very_strong_found >= 1:  # IMPROVED: Single very strong indicator is enough
            return True

        # Check 2: Multiple moderate indicators (at least 2)
        strong_indicators = [
            'uid=',
            'gid=',
            'groups=',
            'root:x:0:0:',
            'Linux version',
            'bin/',
            'usr/',
            '/etc/',
            '/var/',
            'total ',  # ls -la output
        ]

        strong_found = sum(1 for ind in strong_indicators if ind in response_text)
        if strong_found >= 2:
            return True

        # Check 3: Patterns should be near each other (within 800 chars)
        # IMPROVED: Relaxed from 500 to 800 for better detection
        if len(matches) >= 2:  # IMPROVED: Reduced from 3 to 2
            positions = []
            for match in matches[:3]:
                pos = response_text.find(match)
                if pos != -1:
                    positions.append(pos)

            if len(positions) >= 2:
                pos_range = max(positions) - min(positions)
                if pos_range < 800:  # IMPROVED: Increased from 500
                    return True

        # Check 4: Command output structure
        # Look for common command output patterns
        command_patterns = [
            'drwx',  # Directory listing
            '-rw-',  # File permissions
            'total ',  # ls output
            '/',  # Path separators (multiple)
        ]

        pattern_count = sum(1 for p in command_patterns if p in response_text)
        if pattern_count >= 2:
            return True

        return False

    def _generate_evidence(self, matches: List[str], response_text: str) -> str:
        """
        Generate evidence string from matches

        Args:
            matches: List of matched patterns
            response_text: Response text

        Returns:
            Evidence string
        """
        evidence_parts = []

        for pattern in matches[:3]:
            snippet = BaseDetector.get_evidence(pattern, response_text, context_size=100)
            evidence_parts.append(snippet)

        evidence = f"Found {len(matches)} CMDi indicators: {', '.join(matches[:5])}. "
        evidence += "Examples: " + " | ".join(evidence_parts[:2])

        return evidence

    def _test_time_based_cmdi(self, url: str, params: Dict[str, Any], param_name: str,
                              method: str, http_client: Any) -> Dict[str, Any]:
        """
        Test for Blind Command Injection using time-based detection (sleep commands)

        Args:
            url: Target URL
            params: Parameters dictionary
            param_name: Parameter name to test
            method: HTTP method (GET/POST)
            http_client: HTTP client

        Returns:
            Result dictionary if vulnerability found, None otherwise
        """
        import time

        # Time-based payloads for different OSes
        time_payloads = [
            # Linux sleep
            (';sleep 5', 5),
            ('|sleep 5', 5),
            ('`sleep 5`', 5),
            ('$(sleep 5)', 5),
            ('&&sleep 5', 5),
            ('\nsleep 5', 5),
            # Windows timeout/ping
            (';ping -n 6 127.0.0.1', 5),
            ('|ping -n 6 127.0.0.1', 5),
            ('&ping -n 6 127.0.0.1', 5),
            # Alternative separators
            (';sleep${IFS}5', 5),
            (';{sleep,5}', 5),
        ]

        logger.debug(f"Testing time-based blind CMDi with {len(time_payloads)} payloads")

        # Get baseline response time
        try:
            start = time.time()
            if method == 'POST':
                http_client.post(url, data=params, timeout=10)
            else:
                http_client.get(url, params=params, timeout=10)
            baseline_time = time.time() - start
        except Exception:
            baseline_time = 1.0  # Default if baseline fails

        for payload, expected_delay in time_payloads[:5]:  # Limit to first 5
            test_params = params.copy()
            original_value = str(params.get(param_name, ''))
            test_params[param_name] = original_value + payload

            try:
                start = time.time()
                if method == 'POST':
                    response = http_client.post(url, data=test_params, timeout=15)
                else:
                    response = http_client.get(url, params=test_params, timeout=15)
                elapsed = time.time() - start

                # Check if response took significantly longer (delay detected)
                # Allow for 1 second tolerance
                if elapsed >= expected_delay - 1 and elapsed > baseline_time + 3:
                    logger.info(f"Time-based CMDi detected: {elapsed:.2f}s (expected {expected_delay}s, baseline {baseline_time:.2f}s)")

                    result = self.create_result(
                        vulnerable=True,
                        url=url,
                        parameter=param_name,
                        payload=payload,
                        evidence=f"Blind Command Injection confirmed via time-based detection.\n\n"
                                f"**Payload:** {payload}\n"
                                f"**Expected delay:** {expected_delay} seconds\n"
                                f"**Actual response time:** {elapsed:.2f} seconds\n"
                                f"**Baseline response time:** {baseline_time:.2f} seconds\n\n"
                                f"The server executed the sleep/delay command, confirming RCE.",
                        description="Blind OS Command Injection vulnerability detected via time-based technique. "
                                  "The server executed a sleep command, confirming arbitrary command execution.",
                        confidence=0.90
                    )

                    result['cwe'] = self.config.get('cwe', 'CWE-78')
                    result['owasp'] = self.config.get('owasp', 'A03:2021')
                    result['cvss'] = self.config.get('cvss', '9.8')
                    result['detection_method'] = 'Time-based blind'

                    return result

            except Exception as e:
                # Timeout might also indicate sleep worked
                if 'timeout' in str(e).lower() or 'timed out' in str(e).lower():
                    result = self.create_result(
                        vulnerable=True,
                        url=url,
                        parameter=param_name,
                        payload=payload,
                        evidence=f"Blind Command Injection likely - request timed out.\n\n"
                                f"**Payload:** {payload}\n"
                                f"**Expected delay:** {expected_delay} seconds\n"
                                f"**Result:** Request timed out (likely sleep executed)\n\n"
                                f"Manual verification recommended.",
                        description="Possible Blind OS Command Injection - request timed out after injecting sleep command.",
                        confidence=0.75
                    )
                    result['cwe'] = 'CWE-78'
                    result['detection_method'] = 'Time-based (timeout)'
                    return result

                logger.debug(f"Time-based test error: {e}")

        return None

    def _test_oob_cmdi(self, url: str, params: Dict[str, Any], param_name: str,
                       method: str, http_client: Any) -> Dict[str, Any]:
        """
        Test for Blind Command Injection using OOB detection

        Args:
            url: Target URL
            params: Parameters dictionary
            param_name: Parameter name to test
            method: HTTP method (GET/POST)
            http_client: HTTP client

        Returns:
            Result dictionary if vulnerability found, None otherwise
        """
        try:
            # Generate OOB payloads for RCE/CMDi
            oob_payloads = self.oob_detector.get_callback_payloads('cmdi', url, param_name)

            logger.debug(f"Testing Blind CMDi (OOB) with {len(oob_payloads)} payloads")

            for payload_info in oob_payloads[:3]:  # Test first 3 OOB payloads
                payload = payload_info['payload']
                callback_id = payload_info['callback_id']

                # Append payload to parameter value
                test_params = params.copy()
                original_value = str(params.get(param_name, ''))

                # Try different injection points
                injection_variants = [
                    f"{original_value};{payload}",  # Command separator
                    f"{original_value}|{payload}",  # Pipe
                    f"{original_value}&&{payload}",  # AND
                    f"{original_value}`{payload}`",  # Backticks
                ]

                for variant in injection_variants:
                    test_params[param_name] = variant

                    # Send request
                    if method == 'POST':
                        response = http_client.post(url, data=test_params)
                    else:
                        response = http_client.get(url, params=test_params)

                    if not response:
                        continue

                    # Check for callback (wait 3 seconds)
                    detected, evidence = self.oob_detector.check_callback(callback_id, wait_time=3)

                    if detected:
                        # Blind CMDi confirmed via OOB callback
                        result = self.create_result(
                            vulnerable=True,
                            url=url,
                            parameter=param_name,
                            payload=variant,
                            evidence=f"Blind Command Injection confirmed via Out-of-Band callback. {evidence}",
                            description=f"Blind OS Command Injection vulnerability detected. "
                                      f"The server executed arbitrary system commands ({payload_info['type']} payload). "
                                      f"This was confirmed via out-of-band callback detection.",
                            confidence=0.95  # High confidence for OOB confirmation
                        )

                        # Add metadata
                        result['cwe'] = self.config.get('cwe', 'CWE-78')
                        result['owasp'] = self.config.get('owasp', 'A03:2021')
                        result['cvss'] = self.config.get('cvss', '9.8')
                        result['detection_method'] = 'Out-of-Band (OOB)'

                        return result

                    # Small delay between variants
                    import time
                    time.sleep(0.5)

        except Exception as e:
            logger.debug(f"Error in OOB CMDi testing: {e}")

        return None


def get_module(module_path: str, payload_limit: int = None):
    """Create module instance"""
    return CMDiModule(module_path, payload_limit=payload_limit)
