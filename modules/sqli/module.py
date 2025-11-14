"""
SQL Injection Scanner Module - IMPROVED

Improvements:
- Uses BaseDetector for common methods
- Patterns from TXT files (no hardcode!)
- Multi-stage detection
- Reduced false positives
- Confidence scoring
"""

from typing import List, Dict, Any
from core.base_module import BaseModule
from detectors.base_detector import BaseDetector
from core.logger import get_logger

logger = get_logger(__name__)


class SQLiModule(BaseModule):
    """Improved SQL Injection scanner module"""

    def __init__(self, module_path: str):
        """Initialize SQLi module"""
        super().__init__(module_path)

        # Load error patterns from TXT file (instead of hardcoding!)
        self.error_patterns = self._load_txt_file("error_patterns.txt")

        logger.info(f"SQLi module loaded: {len(self.payloads)} payloads, "
                   f"{len(self.error_patterns)} error patterns")

    def scan(self, targets: List[Dict[str, Any]], http_client: Any) -> List[Dict[str, Any]]:
        """
        Scan for SQL injection vulnerabilities

        Args:
            targets: List of URLs with parameters
            http_client: HTTP client

        Returns:
            List of results
        """
        results = []

        logger.info(f"Starting SQLi scan on {len(targets)} targets")

        # PRIORITIZE POST forms (SQLi is more common in forms)
        post_targets = [t for t in targets if t.get('method', 'GET').upper() == 'POST']
        get_targets = [t for t in targets if t.get('method', 'GET').upper() != 'POST']
        prioritized_targets = post_targets + get_targets

        logger.info(f"Prioritized {len(post_targets)} POST forms, {len(get_targets)} GET targets")

        for target in prioritized_targets:
            url = target.get('url')
            params = target.get('params', {})
            method = target.get('method', 'GET').upper()

            if not params:
                continue

            # Test each parameter
            for param_name in params:
                logger.debug(f"Testing SQLi in parameter: {param_name} via {method}")

                # Try payloads (limited)
                for payload in self.payloads[:50]:  # Limit to 50 for better detection
                    test_params = params.copy()
                    test_params[param_name] = payload

                    # DEBUG: Log what we're sending
                    logger.debug(f"Sending {method} request to: {url}")
                    logger.debug(f"POST data: {test_params}")

                    # Send request using appropriate method
                    if method == 'POST':
                        response = http_client.post(url, data=test_params)
                    else:
                        response = http_client.get(url, params=test_params)

                    if not response:
                        continue

                    # PASSIVE ANALYSIS: Check for path disclosure, DB errors in response
                    self.analyze_payload_response(response, url, payload)

                    # IMPROVED DETECTION
                    detected, confidence, evidence = self._detect_sqli_improved(
                        payload, response
                    )

                    if detected:
                        result = self.create_result(
                            vulnerable=True,
                            url=url,
                            parameter=param_name,
                            payload=payload,
                            evidence=evidence,
                            description="SQL Injection vulnerability detected. Database error messages exposed.",
                            confidence=confidence
                        )

                        # Add metadata
                        result['cwe'] = self.config.get('cwe', 'CWE-89')
                        result['owasp'] = self.config.get('owasp', 'A03:2021')
                        result['cvss'] = self.config.get('cvss', '9.8')

                        results.append(result)
                        logger.info(f"✓ SQLi found in {url} (parameter: {param_name}, confidence: {confidence:.2f})")

                        # Move to next parameter
                        break

        # BLIND SQLI DETECTION
        # Test for time-based blind SQL injection
        logger.info("Starting Blind SQLi (time-based) detection phase")
        blind_sqli_results = self._scan_blind_sqli(prioritized_targets, http_client)
        results.extend(blind_sqli_results)
        logger.info(f"Blind SQLi scan found {len(blind_sqli_results)} vulnerabilities")

        logger.info(f"SQLi scan complete: {len(results)} vulnerabilities found")
        return results

    def _detect_sqli_improved(self, payload: str, response: Any) -> tuple:
        """
        Improved SQLi detection with multi-stage validation

        Returns:
            (detected: bool, confidence: float, evidence: str)
        """
        # STAGE 1: Basic checks
        if response.status_code >= 500:
            # Server error может быть, но нужно больше подтверждений
            pass

        # STAGE 2: Check multiple error patterns (требуем минимум 1)
        response_text = getattr(response, 'text', '')

        # Debug logging
        logger.debug(f"Response status: {response.status_code}, text length: {len(response_text)}")
        logger.debug(f"Response preview: {response_text[:200]}")
        logger.debug(f"Checking {len(self.error_patterns)} patterns")

        detected, matches = BaseDetector.check_multiple_patterns(
            response_text,
            self.error_patterns,
            min_matches=1  # Minimum 1 SQL error pattern
        )

        logger.debug(f"Pattern check: detected={detected}, matches={matches[:3] if matches else []}")

        if not detected:
            # Try single strong pattern
            strong_patterns = [
                'You have an error in your SQL syntax',
                'Warning: mysql_',
                'mysqli_sql_exception',
                'Fatal error: Uncaught exception',
                'Unclosed quotation mark',
                'ORA-01756',
                'PostgreSQL query failed'
            ]

            for pattern in strong_patterns:
                if pattern in response.text:
                    detected = True
                    matches = [pattern]
                    break

        if not detected:
            return False, 0.0, ""

        # STAGE 3: Validate context
        context_valid = self._validate_sql_context(payload, response_text, matches)
        logger.debug(f"SQLi context validation: {context_valid}")
        if not context_valid:
            logger.debug(f"SQLi context validation failed for matches: {matches}")
            return False, 0.0, ""

        # STAGE 4: Check suspicious words
        has_suspicious = BaseDetector.has_suspicious_words(response_text)

        # STAGE 5: Calculate confidence
        # For SQLi, error patterns are VERY strong indicators - boost base confidence
        if len(matches) >= 1:
            confidence = 0.60  # Strong SQL error = high confidence
        else:
            confidence = BaseDetector.calculate_confidence(
                indicators_found=len(matches),
                response_length=len(response_text),
                has_suspicious_words=has_suspicious,
                payload_reflected=BaseDetector.is_payload_reflected(payload, response_text)
            )

        # Boost for multiple patterns
        if len(matches) >= 2:
            confidence += 0.15

        # Boost for suspicious words
        if has_suspicious:
            confidence += 0.10

        # Boost confidence if error is near payload
        if self._error_near_payload(payload, response_text, matches):
            confidence += 0.2
            confidence = min(1.0, confidence)

        if confidence < 0.35:  # Minimum threshold (lowered for better detection)
            logger.debug(f"SQLi confidence too low: {confidence:.2f}")
            return False, 0.0, ""

        # Generate evidence
        evidence = f"SQL errors detected: {', '.join(matches[:3])}. "
        evidence += BaseDetector.get_evidence(matches[0], response_text, context_size=150)

        return True, confidence, evidence

    def _validate_sql_context(self, payload: str, response_text: str, matches: List[str]) -> bool:
        """
        Validate SQL error context

        Args:
            payload: Injected payload
            response_text: Response text
            matches: Matched error patterns

        Returns:
            True if context is valid
        """
        # Check 1: Error should mention SQL syntax
        sql_keywords = ['select', 'from', 'where', 'syntax', 'query', 'statement']
        response_lower = response_text.lower()

        sql_mentions = sum(1 for keyword in sql_keywords if keyword in response_lower)
        if sql_mentions >= 2:
            return True

        # Check 2: Error shows actual SQL code
        if "'" in response_text and any(kw in response_lower for kw in ['select', 'from', 'where']):
            return True

        # Check 3: Database function names
        db_functions = ['mysql_', 'pg_', 'oci_', 'mssql_', 'sqlite_']
        if any(func in response_lower for func in db_functions):
            return True

        # Check 4: Multiple error patterns (already validated)
        if len(matches) >= 2:
            return True

        return False

    def _error_near_payload(self, payload: str, response_text: str, matches: List[str]) -> bool:
        """
        Check if SQL error appears near payload

        Args:
            payload: Payload
            response_text: Response
            matches: Matched patterns

        Returns:
            True if error is near payload
        """
        if not matches:
            return False

        # Find position of first error
        error_pos = response_text.find(matches[0])
        if error_pos == -1:
            return False

        # Find payload position
        payload_pos = response_text.find(payload)
        if payload_pos == -1:
            return False

        # Check if they're within 500 characters
        distance = abs(error_pos - payload_pos)
        return distance < 500

    def _scan_blind_sqli(self, targets: List[Dict[str, Any]], http_client: Any) -> List[Dict[str, Any]]:
        """
        Scan for Blind SQL Injection (time-based)

        Uses time delays (SLEEP, WAITFOR) to detect blind SQLi
        Detection: Measure response times with and without delay payloads

        Args:
            targets: List of URLs with parameters
            http_client: HTTP client

        Returns:
            List of blind SQLi results
        """
        results = []
        import time

        # Time-based blind SQLi payloads (5 second delays)
        # These work across multiple databases
        time_payloads = [
            "1' AND SLEEP(5)--",
            "1' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--",
            "1' OR IF(1=1,SLEEP(5),0)--",
            "1'; WAITFOR DELAY '0:0:5'--",
            "1' AND BENCHMARK(5000000,MD5('A'))--",
        ]

        # Test both GET and POST for blind SQLi
        # IMPROVED: Also test GET parameters (many blind SQLi are in GET)
        all_targets = targets

        # Prioritize POST, but test GET too
        post_targets = [t for t in all_targets if t.get('method', 'GET').upper() == 'POST']
        get_targets = [t for t in all_targets if t.get('method', 'GET').upper() == 'GET' and t.get('params')]

        # Test POST first, then GET
        test_targets = post_targets[:10] + get_targets[:10]

        # Limit testing to avoid very long scan times
        logger.info(f"Testing {len(test_targets)} targets for Blind SQLi (time-based): {len(post_targets[:10])} POST, {len(get_targets[:10])} GET")

        for target in test_targets:  # Limit to 20 total
            url = target.get('url')
            params = target.get('params', {})

            # Skip if already detected regular SQLi here
            # (Blind SQLi is for when no errors are shown)

            # Get method for this target
            method = target.get('method', 'GET').upper()

            # Test each parameter
            for param_name in params:
                logger.debug(f"Testing Blind SQLi in parameter: {param_name} via {method}")

                # STAGE 1: Get baseline response time (normal request)
                baseline_times = []
                for i in range(2):  # 2 baseline requests
                    test_params = params.copy()
                    test_params[param_name] = "1"

                    start_time = time.time()
                    if method == 'POST':
                        response = http_client.post(url, data=test_params)
                    else:
                        response = http_client.get(url, params=test_params)
                    elapsed = time.time() - start_time

                    if response:
                        baseline_times.append(elapsed)

                if len(baseline_times) < 2:
                    continue

                baseline_avg = sum(baseline_times) / len(baseline_times)
                logger.debug(f"Baseline response time: {baseline_avg:.2f}s")

                # STAGE 2: Test time-based payloads
                for payload in time_payloads[:3]:  # Test first 3 payloads
                    test_params = params.copy()
                    test_params[param_name] = payload

                    start_time = time.time()
                    if method == 'POST':
                        response = http_client.post(url, data=test_params)
                    else:
                        response = http_client.get(url, params=test_params)
                    elapsed = time.time() - start_time

                    if not response:
                        continue

                    # PASSIVE ANALYSIS: Check for path disclosure, DB errors in response
                    self.analyze_payload_response(response, url, payload)

                    logger.debug(f"Payload '{payload}' response time: {elapsed:.2f}s")

                    # STAGE 3: Check if response was delayed
                    # Expect ~5 second delay (allow 4-10 second range)
                    delay_diff = elapsed - baseline_avg

                    if delay_diff >= 4.0 and delay_diff <= 10.0:
                        # Likely blind SQLi detected!
                        # Verify with one more test to reduce false positives

                        # Verification test
                        start_time = time.time()
                        if method == 'POST':
                            verify_response = http_client.post(url, data=test_params)
                        else:
                            verify_response = http_client.get(url, params=test_params)
                        verify_elapsed = time.time() - start_time
                        verify_diff = verify_elapsed - baseline_avg

                        if verify_diff >= 4.0:
                            # Confirmed blind SQLi
                            confidence = 0.80

                            # Higher confidence if both tests showed similar delay
                            if abs(delay_diff - verify_diff) < 2.0:
                                confidence = 0.90

                            evidence = f"Time-based Blind SQLi detected. Baseline: {baseline_avg:.2f}s, "
                            evidence += f"With payload: {elapsed:.2f}s (delay: {delay_diff:.2f}s), "
                            evidence += f"Verification: {verify_elapsed:.2f}s (delay: {verify_diff:.2f}s). "
                            evidence += f"Payload caused consistent ~5 second delay indicating SLEEP() execution."

                            result = self.create_result(
                                vulnerable=True,
                                url=url,
                                parameter=param_name,
                                payload=payload,
                                evidence=evidence,
                                description="Blind SQL Injection (time-based) vulnerability detected. "
                                          "Database executes injected time-delay functions.",
                                confidence=confidence
                            )

                            result['cwe'] = 'CWE-89'
                            result['owasp'] = 'A03:2021'
                            result['cvss'] = '8.5'
                            result['sqli_type'] = 'blind_time'

                            results.append(result)
                            logger.info(f"✓ Blind SQLi found in {url} (parameter: {param_name}, confidence: {confidence:.2f})")

                            # Move to next parameter
                            break

        return results


def get_module(module_path: str):
    """Create module instance"""
    return SQLiModule(module_path)
