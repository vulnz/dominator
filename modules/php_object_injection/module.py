"""
PHP Object Injection Scanner Module

Detects PHP Object Injection (Insecure Deserialization) vulnerabilities by:
1. Testing parameters with serialized PHP objects
2. Detecting error messages from unserialize()
3. Analyzing response changes indicating deserialization
4. Detecting magic method execution indicators
"""

from typing import List, Dict, Any
from core.base_module import BaseModule
from detectors.base_detector import BaseDetector
from core.logger import get_logger
import re

logger = get_logger(__name__)


class PHPObjectInjectionModule(BaseModule):
    """PHP Object Injection vulnerability scanner module"""

    def __init__(self, module_path: str, payload_limit: int = None):
        """Initialize PHP Object Injection module"""
        super().__init__(module_path, payload_limit=payload_limit)

        # PHP unserialize error patterns - STRICT patterns to avoid false positives
        # These MUST be actual PHP error messages, not generic text
        self.error_patterns = [
            # Actual PHP unserialize() error messages
            'unserialize(): Error at offset',
            'unserialize(): Unexpected end of serialized data',
            'unserialize(): Error at offset 0 of',
            'Notice: unserialize():',
            'Warning: unserialize():',
            'Fatal error: unserialize():',
            # Specific serialization errors
            'invalid serialization data',
            'unknown/corrupted data',
            'Function name must be a string',  # When object methods called incorrectly
        ]

        # HIGH confidence indicators - actual PHP debug output format
        self.high_confidence_indicators = [
            '__PHP_Incomplete_Class_Name',  # Very specific PHP indicator
            'object(stdClass)#',  # PHP var_dump output with object ID
            'object(__PHP_Incomplete_Class)#',
            'Cannot use object of type',  # PHP type error
        ]

        # MEDIUM confidence - need additional validation
        self.medium_confidence_indicators = [
            '__PHP_Incomplete_Class',  # Without the _Name suffix
            'allowed classes',  # PHP 7+ unserialize options
            'The requested class could not be found',
        ]

        # Magic method execution indicators - MUST be PHP context
        self.magic_method_indicators = [
            r'__wakeup\(\)\s*(?:called|failed|error)',
            r'__destruct\(\)\s*(?:called|failed|error)',
            r'__toString\(\)\s*must\s+return',
            r'Call\s+to\s+undefined\s+method.*::__\w+\(',
            r'Call\s+to\s+a\s+member\s+function.*on\s+(?:null|bool|int|string)',
        ]

        logger.info(f"PHP Object Injection module loaded: {len(self.payloads)} payloads, "
                   f"{len(self.error_patterns)} error patterns")

    def scan(self, targets: List[Dict[str, Any]], http_client: Any) -> List[Dict[str, Any]]:
        """
        Scan for PHP Object Injection vulnerabilities

        Args:
            targets: List of URLs with parameters
            http_client: HTTP client

        Returns:
            List of results
        """
        results = []

        logger.info(f"Starting PHP Object Injection scan on {len(targets)} targets")

        for target in targets:
            url = target.get('url')
            params = target.get('params', {})
            method = target.get('method', 'GET').upper()

            if not params:
                continue

            # Get baseline response
            if method == 'POST':
                baseline_response = http_client.post(url, data=params)
            else:
                baseline_response = http_client.get(url, params=params)

            if not baseline_response:
                continue

            baseline_text = getattr(baseline_response, 'text', '')
            baseline_length = len(baseline_text)

            # Test each parameter
            for param_name in params:
                logger.debug(f"Testing PHP Object Injection in parameter: {param_name} via {method}")

                # Try serialized payloads
                for payload in self.get_limited_payloads():  # Limit to 15 payloads
                    test_params = params.copy()
                    test_params[param_name] = payload

                    # Send request
                    if method == 'POST':
                        response = http_client.post(url, data=test_params)
                    else:
                        response = http_client.get(url, params=test_params)

                    if not response:
                        continue

                    # Detect PHP Object Injection
                    detected, confidence, evidence = self._detect_php_object_injection(
                        payload, response, baseline_text, baseline_length
                    )

                    if detected:
                        result = self.create_result(
                            vulnerable=True,
                            url=url,
                            parameter=param_name,
                            payload=payload,
                            evidence=evidence,
                            description="PHP Object Injection (Insecure Deserialization) vulnerability detected. "
                                      "Application uses unserialize() on user-controlled data.",
                            confidence=confidence
                        )

                        # Add metadata
                        result['cwe'] = self.config.get('cwe', 'CWE-502')
                        result['owasp'] = self.config.get('owasp', 'A08:2021')
                        result['cvss'] = self.config.get('cvss', '9.8')

                        results.append(result)
                        logger.info(f"✓ PHP Object Injection found in {url} "
                                  f"(parameter: {param_name}, confidence: {confidence:.2f})")

                        # Move to next parameter
                        break

        logger.info(f"PHP Object Injection scan complete: {len(results)} vulnerabilities found")
        return results

    def _detect_php_object_injection(self, payload: str, response: Any,
                                    baseline_text: str, baseline_length: int) -> tuple:
        """
        Detect PHP Object Injection vulnerability
        STRICT detection to minimize false positives

        Returns:
            (detected: bool, confidence: float, evidence: str)
        """
        response_text = getattr(response, 'text', '')
        response_lower = response_text.lower()
        baseline_lower = baseline_text.lower()

        # CRITICAL: Check if payload is just reflected back (common false positive)
        payload_reflected = payload in response_text or payload[:20] in response_text

        # Also check URL-encoded version
        import urllib.parse
        payload_encoded = urllib.parse.quote(payload)
        payload_reflected = payload_reflected or payload_encoded in response_text

        # METHOD 1: STRICT Error-based detection (MOST RELIABLE)
        # Only match actual PHP unserialize() error messages
        error_found = None

        for error_pattern in self.error_patterns:
            pattern_lower = error_pattern.lower()
            # Must be NEW in response (not in baseline)
            if pattern_lower in response_lower and pattern_lower not in baseline_lower:
                # Additional validation: check it's not just reflected payload
                if payload_reflected and error_pattern in payload:
                    continue
                error_found = error_pattern
                break

        if error_found:
            # High confidence for actual PHP error messages
            confidence = 0.90

            evidence = f"PHP unserialize() error detected: '{error_found}'. "
            evidence += "Application calls unserialize() on user-controlled input. "
            evidence += BaseDetector.get_evidence(error_found, response_text, context_size=150)

            return True, confidence, evidence

        # METHOD 2: HIGH confidence indicators (specific PHP debug output)
        for indicator in self.high_confidence_indicators:
            if indicator in response_text and indicator not in baseline_text:
                # Verify it's not just the payload being reflected
                if payload_reflected and indicator in payload:
                    continue

                confidence = 0.85
                evidence = f"PHP deserialization output detected: '{indicator}'. "
                evidence += "Response contains PHP object debug output indicating deserialization occurred. "
                evidence += BaseDetector.get_evidence(indicator, response_text, context_size=150)

                return True, confidence, evidence

        # METHOD 3: Magic method execution detection (regex-based)
        for pattern in self.magic_method_indicators:
            match = re.search(pattern, response_text, re.IGNORECASE)
            if match:
                matched_text = match.group(0)
                # Verify not in baseline
                if not re.search(pattern, baseline_text, re.IGNORECASE):
                    confidence = 0.85
                    evidence = f"PHP magic method execution detected: '{matched_text}'. "
                    evidence += "Indicates object was deserialized and magic method was triggered. "
                    evidence += BaseDetector.get_evidence(matched_text, response_text, context_size=150)

                    return True, confidence, evidence

        # METHOD 4: MEDIUM confidence indicators (require additional validation)
        # Only report if we have MULTIPLE indicators AND response changed significantly
        medium_found = []
        for indicator in self.medium_confidence_indicators:
            if indicator in response_text and indicator not in baseline_text:
                if not (payload_reflected and indicator in payload):
                    medium_found.append(indicator)

        if len(medium_found) >= 2:
            # Additional check: response should be significantly different
            length_diff = abs(len(response_text) - baseline_length)
            length_ratio = length_diff / max(baseline_length, 1)

            if length_ratio > 0.1:  # At least 10% size change
                confidence = 0.75
                evidence = f"Multiple deserialization indicators detected: {', '.join(medium_found)}. "
                evidence += f"Response size changed by {length_ratio*100:.1f}%. "
                evidence += "Possible PHP Object Injection - manual verification recommended. "
                evidence += BaseDetector.get_evidence(medium_found[0], response_text, context_size=150)

                return True, confidence, evidence

        # METHOD 5: Behavioral detection - serialization format disappeared
        # If we sent O:8:"stdClass" and response has object(stdClass)# without O:8:
        # This indicates actual deserialization occurred
        if 'O:' in payload and 'O:' not in response_text:
            # Check for PHP object output format
            object_output_match = re.search(r'object\((\w+)\)#\d+', response_text)
            if object_output_match and object_output_match.group(0) not in baseline_text:
                confidence = 0.80
                matched = object_output_match.group(0)
                evidence = f"Serialized payload was deserialized: '{matched}' found in response. "
                evidence += "Payload format 'O:' was converted to PHP object output. "
                evidence += BaseDetector.get_evidence(matched, response_text, context_size=150)

                return True, confidence, evidence

        return False, 0.0, ""

    def _is_valid_serialization(self, payload: str) -> bool:
        """
        Check if payload is valid PHP serialization format

        Args:
            payload: Payload to check

        Returns:
            True if valid serialization format
        """
        # Check for PHP serialization format markers
        serialization_patterns = [
            r'^O:\d+:',         # Object: O:8:"stdClass":...
            r'^a:\d+:',         # Array: a:2:{...}
            r'^s:\d+:',         # String: s:4:"test";
            r'^i:\d+;',         # Integer: i:123;
            r'^b:[01];',        # Boolean: b:1; or b:0;
            r'^N;',             # Null: N;
            r'^d:[\d.]+;',      # Float: d:3.14;
        ]

        for pattern in serialization_patterns:
            if re.match(pattern, payload):
                return True

        return False


def get_module(module_path: str, payload_limit: int = None):
    """Create module instance"""
    return PHPObjectInjectionModule(module_path, payload_limit=payload_limit)
