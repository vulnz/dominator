"""
XPath Injection Scanner Module

Detects XPath injection vulnerabilities
Based on XVWA vulnerable code: XPath query with concatenated user input
"""

from typing import List, Dict, Any
from core.base_module import BaseModule
from detectors.base_detector import BaseDetector
from core.logger import get_logger

logger = get_logger(__name__)


class XPathModule(BaseModule):
    """XPath Injection scanner module"""

    def __init__(self, module_path: str, payload_limit: int = None):
        """Initialize XPath module"""
        super().__init__(module_path, payload_limit=payload_limit)

        # Load error patterns from TXT file
        self.error_patterns = self._load_txt_file("error_patterns.txt")

        logger.info(f"XPath module loaded: {len(self.payloads)} payloads, "
                   f"{len(self.error_patterns)} error patterns")

    def scan(self, targets: List[Dict[str, Any]], http_client: Any) -> List[Dict[str, Any]]:
        """
        Scan for XPath injection vulnerabilities

        Args:
            targets: List of URLs with parameters
            http_client: HTTP client

        Returns:
            List of results
        """
        results = []

        logger.info(f"Starting XPath scan on {len(targets)} targets")

        # PRIORITIZE POST forms
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
                logger.debug(f"Testing XPath in parameter: {param_name} via {method}")

                # Try payloads
                for payload in self.get_limited_payloads():  # Limit to 20
                    test_params = params.copy()
                    test_params[param_name] = payload

                    # Send request
                    if method == 'POST':
                        response = http_client.post(url, data=test_params)
                    else:
                        response = http_client.get(url, params=test_params)

                    if not response:
                        continue

                    # Detect XPath injection
                    detected, confidence, evidence = self._detect_xpath(
                        payload, response, baseline_text, baseline_length
                    )

                    if detected:
                        result = self.create_result(
                            vulnerable=True,
                            url=url,
                            parameter=param_name,
                            payload=payload,
                            evidence=evidence,
                            description="XPath Injection vulnerability detected. "
                                      "Application concatenates user input into XPath queries.",
                            confidence=confidence
                        )

                        # Add metadata
                        result['cwe'] = self.config.get('cwe', 'CWE-643')
                        result['owasp'] = self.config.get('owasp', 'A03:2021')
                        result['cvss'] = self.config.get('cvss', '8.5')

                        results.append(result)
                        logger.info(f"✓ XPath injection found in {url} "
                                  f"(parameter: {param_name}, confidence: {confidence:.2f})")

                        # Move to next parameter
                        break

        logger.info(f"XPath scan complete: {len(results)} vulnerabilities found")
        return results

    def _detect_xpath(self, payload: str, response: Any,
                     baseline_text: str, baseline_length: int) -> tuple:
        """
        Detect XPath injection with baseline comparison and reflection filtering

        CRITICAL: Prevents false positives from:
        1. Reflected payloads
        2. Pre-existing error messages
        3. Generic patterns

        Returns:
            (detected: bool, confidence: float, evidence: str)
        """
        response_text = getattr(response, 'text', '')
        response_length = len(response_text)

        # METHOD 1: Error-based detection with baseline comparison
        detected, matches = BaseDetector.check_multiple_patterns(
            response_text,
            self.error_patterns,
            min_matches=2  # CRITICAL: Require 2+ matches to reduce false positives
        )

        if detected and matches:
            # CRITICAL: Filter out matches that were in baseline
            new_matches = []
            for match in matches:
                if baseline_text and match in baseline_text:
                    continue  # Was already there - not from our injection
                # CRITICAL: Check if match is NOT just reflected payload
                if match in payload:
                    continue  # Match is part of our payload - reflection
                new_matches.append(match)

            # Still require 2+ NEW matches
            if len(new_matches) >= 2:
                confidence = 0.85

                # Validate matches are close together (actual error output)
                if self._matches_in_proximity(new_matches, response_text, max_distance=500):
                    confidence = 0.90

                evidence = f"XPath error detected (NEW - not in baseline): {', '.join(new_matches[:2])}. "
                evidence += f"These errors appeared AFTER injection.\n\n"
                evidence += BaseDetector.get_evidence(new_matches[0], response_text, context_size=150)

                return True, confidence, evidence

            # Single NEW match - lower confidence, require additional validation
            elif len(new_matches) == 1:
                # Only report if we also have significant response change
                len_diff = abs(response_length - baseline_length)
                if len_diff > 100:
                    confidence = 0.60
                    evidence = f"XPath error detected: {new_matches[0]}. "
                    evidence += f"Response changed by {len_diff} bytes. Manual verification recommended."
                    return True, confidence, evidence

        # METHOD 2: Boolean-based detection (data disclosure)
        if "' or '" in payload or "or 1=1" in payload:
            length_increase = response_length - baseline_length

            # Significant increase in data (at least 200 bytes)
            if length_increase > 200:
                # Check for NEW XML/data patterns (not in baseline)
                xml_patterns = ['<Coffee', '<Item', '<Record', '<User', '<Product', '<Node']

                new_xml_count = 0
                for p in xml_patterns:
                    in_response = response_text.count(p)
                    in_baseline = baseline_text.count(p) if baseline_text else 0
                    if in_response > in_baseline:
                        new_xml_count += (in_response - in_baseline)

                # Also check for structural data patterns
                structural_patterns = ['<td>', '<tr>', '</Item>', '</Record>']
                for p in structural_patterns:
                    in_response = response_text.count(p)
                    in_baseline = baseline_text.count(p) if baseline_text else 0
                    if in_response > in_baseline + 2:  # At least 3 more
                        new_xml_count += 1

                if new_xml_count > 0:
                    confidence = 0.70

                    # More NEW elements = higher confidence
                    if new_xml_count >= 3:
                        confidence = 0.85

                    evidence = f"Boolean-based XPath injection. Payload caused {length_increase} byte increase. "
                    evidence += f"Response contains {new_xml_count} NEW XML/data elements (not in baseline)."

                    return True, confidence, evidence

        return False, 0.0, ""

    def _matches_in_proximity(self, matches: List[str], text: str, max_distance: int = 500) -> bool:
        """Check if matches appear close to each other (indicates single error block)"""
        if len(matches) < 2:
            return True

        positions = []
        for match in matches[:3]:
            pos = text.find(match)
            if pos != -1:
                positions.append(pos)

        if len(positions) < 2:
            return True

        return (max(positions) - min(positions)) < max_distance


def get_module(module_path: str, payload_limit: int = None):
    """Create module instance"""
    return XPathModule(module_path, payload_limit=payload_limit)
