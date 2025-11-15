"""
SSTI (Server-Side Template Injection) Scanner Module

Detects SSTI vulnerabilities by testing template expression execution
Based on XVWA vulnerable code: Twig template with unsanitized user input
"""

from typing import List, Dict, Any
from core.base_module import BaseModule
from core.logger import get_logger
import re

logger = get_logger(__name__)


class SSTIModule(BaseModule):
    """SSTI Scanner Module"""

    def __init__(self, module_path: str):
        """Initialize SSTI module"""
        super().__init__(module_path)

        # Expected results for math payloads
        self.math_checks = {
            '{{7*7}}': '49',
            '${7*7}': '49',
            '#{7*7}': '49',
            '*{7*7}': '49',
            '@{7*7}': '49',
            '<%= 7*7 %>': '49',
        }

        # Template engine signatures
        self.engine_signatures = [
            'Twig', 'twig', 'Jinja2', 'jinja', 'Smarty',
            'Freemarker', 'freemarker', 'Velocity',
            'ERB', 'Mako', 'Handlebars'
        ]

        logger.info(f"SSTI module loaded: {len(self.payloads)} payloads")

    def scan(self, targets: List[Dict[str, Any]], http_client: Any) -> List[Dict[str, Any]]:
        """
        Scan for SSTI vulnerabilities

        Args:
            targets: List of URLs with parameters
            http_client: HTTP client

        Returns:
            List of results
        """
        results = []

        logger.info(f"Starting SSTI scan on {len(targets)} targets")

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

            # Test each parameter
            for param_name in params:
                logger.debug(f"Testing SSTI in parameter: {param_name} via {method}")

                # First, test with math expressions (safe detection)
                for payload, expected in self.math_checks.items():
                    test_params = params.copy()
                    test_params[param_name] = payload

                    # Send request
                    if method == 'POST':
                        response = http_client.post(url, data=test_params)
                    else:
                        response = http_client.get(url, params=test_params)

                    if not response:
                        continue

                    # PASSIVE ANALYSIS: Check for path disclosure, DB errors in response
                    self.analyze_payload_response(response, url, payload)

                    response_text = getattr(response, 'text', '')

                    # IMPROVED DETECTION: Reduce false positives
                    # Check if expression was evaluated
                    if expected in response_text and expected not in baseline_text:
                        # ANTI-FALSE-POSITIVE checks:

                        # 1. Check if payload is reflected but NOT evaluated
                        if payload in response_text:
                            # Payload is present in response
                            # Check if it appears OUTSIDE of template delimiters
                            # If payload appears as-is, it's just reflection, NOT execution

                            # Count occurrences
                            payload_count = response_text.count(payload)
                            result_count = response_text.count(expected)

                            # If result doesn't appear MORE than payload, it's reflection
                            if result_count <= payload_count:
                                logger.debug(f"SSTI false positive: payload reflected but not evaluated")
                                continue

                        # 2. Context validation - check if result appears in dangerous context
                        # For SSTI, we expect the RESULT (49) to appear where payload was
                        # Find where payload would be in response
                        if not self._validate_ssti_context(payload, expected, response_text, baseline_text):
                            logger.debug(f"SSTI false positive: result not in injection context")
                            continue

                        # 3. Check if "49" is just a random number (common in HTML)
                        # Look for patterns like: <td>49</td>, "count":49, etc.
                        # These are NOT SSTI - just normal data
                        if self._is_likely_false_positive(expected, response_text):
                            logger.debug(f"SSTI false positive: result appears in normal HTML/JSON context")
                            continue

                        # Passed all checks - likely real SSTI
                        confidence = 0.85

                        # Boost confidence if we can confirm evaluation
                        if not payload in response_text:
                            # Payload NOT in response, but result IS = clear evaluation
                            confidence = 0.95

                        evidence = f"Template injection detected. Payload '{payload}' evaluated to '{expected}' in response."
                        evidence += f"\n\nBaseline response did NOT contain '{expected}', but after injection it appears."
                        evidence += f"\n\nThis indicates server-side template evaluation of user input."

                        result = self.create_result(
                            vulnerable=True,
                            url=url,
                            parameter=param_name,
                            payload=payload,
                            evidence=evidence,
                            description="Server-Side Template Injection (SSTI) vulnerability detected. "
                                      "Application evaluates user input as template code.",
                            confidence=confidence
                        )

                        # Add metadata
                        result['cwe'] = self.config.get('cwe', 'CWE-94')
                        result['owasp'] = self.config.get('owasp', 'A03:2021')
                        result['cvss'] = self.config.get('cvss', '9.8')

                        results.append(result)
                        logger.info(f"✓ SSTI found in {url} "
                                  f"(parameter: {param_name}, confidence: {confidence:.2f})")

                        # Found SSTI in this parameter, move to next
                        break

                # If already found, skip other payloads for this param
                if any(r['parameter'] == param_name and r['url'] == url for r in results):
                    break

        logger.info(f"SSTI scan complete: {len(results)} vulnerabilities found")
        return results

    def _validate_ssti_context(self, payload: str, expected: str, response_text: str,
                               baseline_text: str) -> bool:
        """
        Validate that the result appears in the context where payload was injected
        IMPROVED: Better detection with fewer false negatives

        Returns True if this looks like real SSTI, False if false positive
        """
        # CRITICAL: If baseline didn't have the result but response does, likely SSTI
        expected_in_baseline = expected in baseline_text
        expected_in_response = expected in response_text

        if not expected_in_baseline and expected_in_response:
            # Result appeared ONLY after injection - strong indicator
            # But still check for obvious false positives

            # Count occurrences
            baseline_count = baseline_text.count(expected)
            response_count = response_text.count(expected)

            # If response has MORE occurrences than baseline, likely injection worked
            if response_count > baseline_count:
                return True

        # Find positions of expected result
        result_positions = [m.start() for m in re.finditer(re.escape(expected), response_text)]

        if not result_positions:
            return False

        # Check if result appears in user-controlled context
        # Look for the result appearing outside of common HTML/JSON structures
        valid_contexts = 0
        for pos in result_positions:
            # Extract context around result
            start = max(0, pos - 80)
            end = min(len(response_text), pos + 80)
            context = response_text[start:end]

            # Skip if result is in OBVIOUS data structures (strict matching only)
            false_positive_patterns = [
                r'<td[^>]*>\s*' + re.escape(expected) + r'\s*</td>',  # Table cell ONLY
                r'"count":\s*' + re.escape(expected),  # JSON count field
                r'"total":\s*' + re.escape(expected),  # JSON total field
                r'value="' + re.escape(expected) + '"',  # Exact input value
            ]

            is_false_positive = any(re.search(pattern, context) for pattern in false_positive_patterns)

            if not is_false_positive:
                # Result appears outside of obvious structures - likely SSTI
                valid_contexts += 1

        # If we found at least one valid context, consider it SSTI
        # IMPROVED: More lenient - if ANY occurrence looks valid, pass
        return valid_contexts > 0

    def _is_likely_false_positive(self, expected: str, response_text: str) -> bool:
        """
        Check if the expected result appears in contexts that indicate false positive

        Common false positives:
        - Pagination: "Page 49 of 100"
        - Counts: "49 items found"
        - Prices: "$49.99"
        - Dates: "2049"
        """
        # Patterns that indicate this is NOT SSTI
        false_positive_patterns = [
            r'\b' + re.escape(expected) + r'\s+(?:items|results|found|total|pages)',
            r'(?:page|item|product)\s+' + re.escape(expected),
            r'\$\s*' + re.escape(expected),  # Price
            r'\b20' + re.escape(expected),  # Year 2049
            r'<(?:td|th|li|span|div)[^>]*>\s*' + re.escape(expected) + r'\s*</(?:td|th|li|span|div)>',
        ]

        for pattern in false_positive_patterns:
            if re.search(pattern, response_text, re.IGNORECASE):
                return True

        return False


def get_module(module_path: str):
    """Create module instance"""
    return SSTIModule(module_path)
