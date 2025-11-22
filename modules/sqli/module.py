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

    def __init__(self, module_path: str, payload_limit: int = None):
        """Initialize SQLi module"""
        super().__init__(module_path, payload_limit=payload_limit)

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

                # CRITICAL FIX: Get baseline response FIRST (without SQL payload)
                baseline_text = self._get_baseline_response(url, params, method, http_client)

                # Try payloads (limited)
                for payload in self.get_limited_payloads():  # Limit to 50 for better detection
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

                    # IMPROVED DETECTION WITH BASELINE COMPARISON
                    detected, confidence, evidence = self._detect_sqli_improved(
                        payload, response, baseline_text
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
        logger.info(f"Blind SQLi (time-based) scan found {len(blind_sqli_results)} vulnerabilities")

        # BOOLEAN-BASED BLIND SQLI DETECTION
        logger.info("Starting Boolean-based Blind SQLi detection phase")
        boolean_sqli_results = self._scan_boolean_blind_sqli(prioritized_targets, http_client)
        results.extend(boolean_sqli_results)
        logger.info(f"Boolean-based Blind SQLi scan found {len(boolean_sqli_results)} vulnerabilities")

        logger.info(f"SQLi scan complete: {len(results)} vulnerabilities found")
        return results

    def _get_baseline_response(self, url: str, params: dict, method: str, http_client: Any) -> str:
        """
        Get baseline response WITHOUT SQL payload for comparison

        CRITICAL: This allows us to detect if SQL errors are NEW (caused by payload)
        or pre-existing on the page.

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
            logger.debug(f"Error getting SQLi baseline: {e}")

        return ""

    def _detect_sqli_improved(self, payload: str, response: Any, baseline_text: str = "") -> tuple:
        """
        Improved SQLi detection with multi-stage validation AND BASELINE COMPARISON

        CRITICAL FIX: Verify SQL errors are NEW (not pre-existing on page)

        Returns:
            (detected: bool, confidence: float, evidence: str)
        """
        # STAGE 1: Basic checks
        if response.status_code >= 500:
            # Server error может быть, но нужно больше подтверждений
            pass

        # STAGE 2: Check multiple error patterns (требуем минимум 2 for reliability)
        response_text = getattr(response, 'text', '')

        # Debug logging
        logger.debug(f"Response status: {response.status_code}, text length: {len(response_text)}")
        logger.debug(f"Response preview: {response_text[:200]}")
        logger.debug(f"Checking {len(self.error_patterns)} patterns")

        detected, matches = BaseDetector.check_multiple_patterns(
            response_text,
            self.error_patterns,
            min_matches=2  # FIXED: Require 2+ patterns to reduce false positives
        )

        logger.debug(f"Pattern check: detected={detected}, matches={matches[:3] if matches else []}")

        # CRITICAL FIX: Filter out patterns that were already in baseline
        if detected and baseline_text:
            new_matches = []
            for match in matches:
                if match not in baseline_text:
                    new_matches.append(match)
                else:
                    logger.debug(f"SQLi pattern '{match}' already in baseline - skipping")

            if len(new_matches) < 2:
                logger.debug(f"Not enough NEW SQL errors (need 2, found {len(new_matches)})")
                detected = False
            else:
                matches = new_matches
                logger.debug(f"NEW SQL errors found: {matches[:3]}")

        if not detected:
            # Try single strong pattern (but ONLY if NEW - not in baseline)
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
                    # CRITICAL: Check if this strong pattern is NEW (not in baseline)
                    if baseline_text and pattern in baseline_text:
                        logger.debug(f"Strong SQL pattern '{pattern}' already in baseline - skipping")
                        continue
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
        IMPROVED: More flexible to catch real SQL errors

        Args:
            payload: Injected payload
            response_text: Response text
            matches: Matched error patterns

        Returns:
            True if context is valid
        """
        response_lower = response_text.lower()

        # Check 1: Strong SQL error indicators (immediate pass)
        strong_errors = [
            'you have an error in your sql syntax',
            'warning: mysql',
            'warning: mysqli',
            'unclosed quotation mark',
            'quoted string not properly terminated',
            'ora-01756',
            'postgresql query failed',
            'pg_query()',
            'pg_exec()',
        ]
        if any(err in response_lower for err in strong_errors):
            return True

        # Check 2: Error should mention SQL syntax (lowered threshold)
        sql_keywords = ['select', 'from', 'where', 'syntax', 'query', 'statement', 'database', 'table']
        sql_mentions = sum(1 for keyword in sql_keywords if keyword in response_lower)
        if sql_mentions >= 1:  # IMPROVED: Reduced from 2 to 1
            return True

        # Check 3: Error shows actual SQL code
        if "'" in response_text and any(kw in response_lower for kw in ['select', 'from', 'where', 'insert', 'update']):
            return True

        # Check 4: Database function names
        db_functions = ['mysql_', 'pg_', 'oci_', 'mssql_', 'sqlite_', 'mysqli_']
        if any(func in response_lower for func in db_functions):
            return True

        # Check 5: Multiple error patterns (already validated)
        if len(matches) >= 2:
            return True

        # Check 6: Single very strong match
        if len(matches) >= 1:
            for match in matches:
                if any(strong in match.lower() for strong in ['sql syntax', 'mysql', 'postgresql', 'oracle', 'mssql']):
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

        # Time-based blind SQLi payloads (3 second delays for faster scanning)
        # IMPROVED: Reduced from 5s to 3s for better performance
        time_payloads = [
            "1' AND SLEEP(3)--",
            "1' AND (SELECT * FROM (SELECT(SLEEP(3)))a)--",
            "1' OR IF(1=1,SLEEP(3),0)--",
            "1'; WAITFOR DELAY '0:0:3'--",
            "1' AND BENCHMARK(3000000,MD5('A'))--",
            # Also test without the leading value
            "' AND SLEEP(3)--",
            "' OR SLEEP(3)--",
            # PostgreSQL
            "1' AND pg_sleep(3)--",
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
                    # IMPROVED: Expect ~3 second delay (allow 2.5-8 second range for reliability)
                    delay_diff = elapsed - baseline_avg

                    if delay_diff >= 2.5 and delay_diff <= 8.0:
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

                        if verify_diff >= 2.5:
                            # Confirmed blind SQLi
                            confidence = 0.80

                            # Higher confidence if both tests showed similar delay
                            if abs(delay_diff - verify_diff) < 2.0:
                                confidence = 0.90

                            evidence = f"Time-based Blind SQLi detected. Baseline: {baseline_avg:.2f}s, "
                            evidence += f"With payload: {elapsed:.2f}s (delay: {delay_diff:.2f}s), "
                            evidence += f"Verification: {verify_elapsed:.2f}s (delay: {verify_diff:.2f}s). "
                            evidence += f"Payload caused consistent ~3 second delay indicating SLEEP() execution."

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

    def _scan_boolean_blind_sqli(self, targets: List[Dict[str, Any]], http_client: Any) -> List[Dict[str, Any]]:
        """
        Scan for Boolean-based Blind SQL Injection

        Uses boolean logic (true/false) to detect blind SQLi by comparing responses
        Detection: Compare TRUE condition vs FALSE condition response differences

        Args:
            targets: List of URLs with parameters
            http_client: HTTP client

        Returns:
            List of boolean-based blind SQLi results
        """
        results = []

        # Boolean-based blind SQLi payloads
        # Each tuple: (true_payload, false_payload, description)
        boolean_tests = [
            # MySQL/MariaDB
            ("1' AND '1'='1", "1' AND '1'='2", "String comparison"),
            ("1' OR '1'='1", "1' OR '1'='2", "OR string comparison"),
            ("1' AND 1=1--", "1' AND 1=2--", "Numeric comparison"),
            ("1' OR 1=1--", "1' OR 1=2--", "OR numeric comparison"),

            # Generic
            ("' OR 'a'='a", "' OR 'a'='b", "Generic string OR"),
            ("' AND 'a'='a", "' AND 'a'='b", "Generic string AND"),
        ]

        # Prioritize POST, then GET
        post_targets = [t for t in targets if t.get('method', 'GET').upper() == 'POST']
        get_targets = [t for t in targets if t.get('method', 'GET').upper() == 'GET' and t.get('params')]

        test_targets = post_targets[:8] + get_targets[:8]

        logger.info(f"Testing {len(test_targets)} targets for Boolean-based Blind SQLi")

        for target in test_targets:
            url = target.get('url')
            params = target.get('params', {})
            method = target.get('method', 'GET').upper()

            # Test each parameter
            for param_name in params:
                logger.debug(f"Testing Boolean Blind SQLi in parameter: {param_name} via {method}")

                # Get baseline response (normal request)
                baseline_params = params.copy()
                if method == 'POST':
                    baseline_response = http_client.post(url, data=baseline_params)
                else:
                    baseline_response = http_client.get(url, params=baseline_params)

                if not baseline_response:
                    continue

                baseline_text = getattr(baseline_response, 'text', '')
                baseline_length = len(baseline_text)

                # Test each boolean pair
                for true_payload, false_payload, description in boolean_tests:
                    # Send TRUE condition
                    true_params = params.copy()
                    true_params[param_name] = true_payload

                    if method == 'POST':
                        true_response = http_client.post(url, data=true_params)
                    else:
                        true_response = http_client.get(url, params=true_params)

                    if not true_response:
                        continue

                    # Send FALSE condition
                    false_params = params.copy()
                    false_params[param_name] = false_payload

                    if method == 'POST':
                        false_response = http_client.post(url, data=false_params)
                    else:
                        false_response = http_client.get(url, params=false_params)

                    if not false_response:
                        continue

                    # PASSIVE ANALYSIS on responses
                    self.analyze_payload_response(true_response, url, true_payload)
                    self.analyze_payload_response(false_response, url, false_payload)

                    # Compare responses
                    true_text = getattr(true_response, 'text', '')
                    false_text = getattr(false_response, 'text', '')

                    true_length = len(true_text)
                    false_length = len(false_text)

                    # Calculate response similarity
                    # TRUE should match baseline, FALSE should differ

                    # Check 1: Length difference
                    baseline_vs_true_diff = abs(baseline_length - true_length)
                    baseline_vs_false_diff = abs(baseline_length - false_length)
                    true_vs_false_diff = abs(true_length - false_length)

                    # Check 2: TRUE response should be similar to baseline
                    # FALSE response should differ from both

                    # If TRUE and FALSE responses are significantly different (>5% length diff)
                    if true_vs_false_diff > max(true_length, false_length) * 0.05:
                        # Check if TRUE is closer to baseline than FALSE
                        if baseline_vs_true_diff < baseline_vs_false_diff:
                            # Likely Boolean-based Blind SQLi
                            confidence = 0.70

                            # Higher confidence for larger differences
                            diff_ratio = true_vs_false_diff / max(true_length, false_length)
                            if diff_ratio > 0.2:
                                confidence = 0.80
                            if diff_ratio > 0.5:
                                confidence = 0.90

                            # Check content difference too
                            if true_text != false_text:
                                # Content differs - stronger indicator
                                confidence = min(0.95, confidence + 0.1)

                            evidence = f"Boolean-based Blind SQLi detected ({description}). "
                            evidence += f"Baseline length: {baseline_length}, "
                            evidence += f"TRUE payload ('{true_payload[:30]}...') length: {true_length}, "
                            evidence += f"FALSE payload ('{false_payload[:30]}...') length: {false_length}. "
                            evidence += f"Difference: {true_vs_false_diff} chars ({diff_ratio*100:.1f}%). "
                            evidence += f"TRUE condition response differs from FALSE, indicating SQL logic evaluation."

                            result = self.create_result(
                                vulnerable=True,
                                url=url,
                                parameter=param_name,
                                payload=f"TRUE: {true_payload}, FALSE: {false_payload}",
                                evidence=evidence,
                                description="Boolean-based Blind SQL Injection vulnerability detected. "
                                          "Database evaluates boolean logic in injected queries.",
                                confidence=confidence
                            )

                            result['cwe'] = 'CWE-89'
                            result['owasp'] = 'A03:2021'
                            result['cvss'] = '8.0'
                            result['sqli_type'] = 'blind_boolean'

                            results.append(result)
                            logger.info(f"✓ Boolean Blind SQLi found in {url} (parameter: {param_name}, confidence: {confidence:.2f})")

                            # Move to next parameter after finding
                            break

        return results


def get_module(module_path: str, payload_limit: int = None):
    """Create module instance"""
    return SQLiModule(module_path, payload_limit=payload_limit)
