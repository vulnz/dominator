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

    def __init__(self, module_path: str):
        """Initialize PHP Object Injection module"""
        super().__init__(module_path)

        # PHP unserialize error patterns
        self.error_patterns = [
            'unserialize(',
            'Notice: unserialize',
            'Warning: unserialize',
            'Error: unserialize',
            'unexpected end of serialized data',
            'offset not contained in string',
            'Error at offset',
            'Failed to unserialize',
            '__wakeup',
            '__destruct called',
            '__toString called',
            'object(stdClass)',
            'serialization error',
        ]

        # Indicators that deserialization occurred
        self.deserialization_indicators = [
            'object(',
            'stdClass',
            '__PHP_Incomplete_Class',
            'Array to string conversion',
            'Object of class',
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
                for payload in self.payloads[:15]:  # Limit to 15 payloads
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

        Returns:
            (detected: bool, confidence: float, evidence: str)
        """
        response_text = getattr(response, 'text', '')
        response_length = len(response_text)

        # METHOD 1: Error-based detection
        # Check for unserialize errors
        error_found = None
        for error_pattern in self.error_patterns:
            if error_pattern in response_text and error_pattern not in baseline_text:
                error_found = error_pattern
                break

        if error_found:
            confidence = 0.90

            # Higher confidence if multiple error indicators
            error_count = sum(1 for err in self.error_patterns if err in response_text)
            if error_count >= 2:
                confidence = 0.90

            evidence = f"PHP unserialize() error detected: '{error_found}'. "
            evidence += "Application attempts to deserialize user input. "
            evidence += BaseDetector.get_evidence(error_found, response_text, context_size=200)

            return True, confidence, evidence

        # METHOD 2: Deserialization indicator detection
        # Check if response contains signs of deserialization
        indicators_found = []
        for indicator in self.deserialization_indicators:
            if indicator in response_text and indicator not in baseline_text:
                indicators_found.append(indicator)

        if len(indicators_found) >= 2:
            confidence = 0.85

            # Check if serialization format is reflected
            if 'O:' in payload and ('object(' in response_text or 'stdClass' in response_text):
                confidence = 0.85

            evidence = f"Deserialization indicators detected: {', '.join(indicators_found)}. "
            evidence += "Application may be deserializing user input without validation."

            return True, confidence, evidence

        # METHOD 3: DISABLED - Too many false positives
        # Behavior-based detection is unreliable for PHP Object Injection
        # Relying only on error-based (METHOD 1) and indicator-based (METHOD 2) detection

        # METHOD 4: Magic method execution detection
        # Check if magic methods like __wakeup, __destruct are triggered
        magic_method_patterns = [
            r'__wakeup.*called',
            r'__destruct.*called',
            r'__toString.*called',
            r'method __\w+ does not exist',
        ]

        for pattern in magic_method_patterns:
            if re.search(pattern, response_text, re.IGNORECASE):
                confidence = 0.85

                evidence = f"PHP magic method execution detected: {pattern}. "
                evidence += "Indicates successful object deserialization. "
                evidence += BaseDetector.get_evidence(pattern, response_text, context_size=200)

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


def get_module(module_path: str):
    """Create module instance"""
    return PHPObjectInjectionModule(module_path)
