"""
SSTI (Server-Side Template Injection) Scanner Module

Detects SSTI vulnerabilities by testing template expression execution
Based on XVWA vulnerable code: Twig template with unsanitized user input
"""

from typing import List, Dict, Any
from core.base_module import BaseModule
from core.logger import get_logger
import re
import urllib.parse

logger = get_logger(__name__)


class SSTIModule(BaseModule):
    """SSTI Scanner Module"""

    def __init__(self, module_path: str, payload_limit: int = None):
        """Initialize SSTI module"""
        super().__init__(module_path, payload_limit=payload_limit)

        import random
        import string

        # Generate UNIQUE random markers to avoid false positives
        # Use large numbers that are unlikely to appear naturally
        self.num1 = random.randint(10000, 99999)
        self.num2 = random.randint(10000, 99999)
        self.expected_math = str(self.num1 * self.num2)  # Large result like "123456789"

        # CRITICAL: For string tests, the expected result must NOT appear in the payload
        # BAD:  payload = {{"SSTItest"}} expected = "SSTItest" <- appears in payload!
        # GOOD: payload = {{7*191919}} expected = "1343433" <- only appears if evaluated
        self.marker = ''.join(random.choices(string.ascii_lowercase, k=10))

        # Math-only payloads - expected result NEVER appears in payload itself
        self.math_checks = {
            # Jinja2/Twig - {{num1*num2}}
            f'{{{{{self.num1}*{self.num2}}}}}': self.expected_math,
            # Freemarker/SpEL - ${num1*num2}
            f'${{{self.num1}*{self.num2}}}': self.expected_math,
            # Thymeleaf - #{num1*num2}
            f'#{{{self.num1}*{self.num2}}}': self.expected_math,
            # Velocity - *{num1*num2}
            f'*{{{self.num1}*{self.num2}}}': self.expected_math,
            # ERB - <%= num1*num2 %>
            f'<%= {self.num1}*{self.num2} %>': self.expected_math,
            # Mako - ${num1*num2}
            f'${{{self.num1}*{self.num2}}}': self.expected_math,
        }

        # Template engine error signatures (indicates template is being processed)
        self.error_signatures = [
            'Twig_Error', 'Twig\\Error', 'twig error',
            'jinja2.exceptions', 'jinja2.TemplateSyntaxError',
            'freemarker.core', 'FreeMarkerException',
            'org.apache.velocity', 'VelocityException',
            'ActionView::Template::Error',  # Rails ERB
            'mako.exceptions', 'MakoException',
            'TemplateSyntaxError', 'UndefinedError',
        ]

        logger.info(f"SSTI module loaded: {len(self.payloads)} payloads, math check: {self.num1}*{self.num2}={self.expected_math}")

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
                found_in_param = False

                # Test with math expressions (safe detection)
                for payload, expected in self.math_checks.items():
                    if found_in_param:
                        break

                    test_params = params.copy()
                    test_params[param_name] = payload

                    # Send request
                    if method == 'POST':
                        response = http_client.post(url, data=test_params)
                    else:
                        response = http_client.get(url, params=test_params)

                    if not response:
                        continue

                    # PASSIVE ANALYSIS
                    self.analyze_payload_response(response, url, payload)

                    response_text = getattr(response, 'text', '')

                    # STRICT DETECTION - the expected result should NEVER be in the payload
                    # So if expected is in response, it MUST have been computed

                    # Check 1: Expected result appears in response but NOT in baseline
                    if expected not in response_text:
                        continue

                    if expected in baseline_text:
                        # Result was already in baseline - not caused by our injection
                        continue

                    # Check 2: CRITICAL - Verify payload is NOT just reflected
                    # If payload appears in response (in error msg, etc), it's reflection
                    payload_reflected = self._is_payload_reflected(payload, response_text)

                    if payload_reflected:
                        logger.debug(f"SSTI: Payload reflected in response (error message?) - skipping")
                        continue

                    # Check 3: The expected number should not be part of normal page content
                    # Since we use large numbers like 123456789, this is unlikely
                    if self._is_likely_coincidence(expected, response_text):
                        logger.debug(f"SSTI: Result appears to be coincidental - skipping")
                        continue

                    # PASSED ALL CHECKS - This is real SSTI
                    confidence = 0.95  # High confidence since math was evaluated

                    evidence = f"Template expression evaluated!\n"
                    evidence += f"Payload: {payload}\n"
                    evidence += f"Expected result: {expected}\n"
                    evidence += f"The mathematical expression was computed server-side.\n"
                    evidence += f"Baseline did NOT contain '{expected}'."

                    result = self.create_result(
                        vulnerable=True,
                        url=url,
                        parameter=param_name,
                        payload=payload,
                        evidence=evidence,
                        description="Server-Side Template Injection (SSTI) vulnerability detected. "
                                  "Application evaluates user input as template code.",
                        confidence=confidence,
                        method=method,
                        response=response_text[:3000]
                    )

                    result['cwe'] = self.config.get('cwe', 'CWE-94')
                    result['owasp'] = self.config.get('owasp', 'A03:2021')
                    result['cvss'] = self.config.get('cvss', '9.8')

                    results.append(result)
                    logger.info(f"✓ SSTI found in {url} (parameter: {param_name})")
                    found_in_param = True
                    break

        logger.info(f"SSTI scan complete: {len(results)} vulnerabilities found")
        return results

    def _is_payload_reflected(self, payload: str, response_text: str) -> bool:
        """
        Check if the payload is reflected in the response (e.g., in error messages)

        This catches cases like:
        - SQL error: syntax error near '{{12345*67890}}'
        - Error: Invalid input '{{12345*67890}}'
        """
        # Check raw payload
        if payload in response_text:
            return True

        # Check URL-encoded payload
        if urllib.parse.quote(payload) in response_text:
            return True

        # Check HTML-encoded payload
        import html
        if html.escape(payload) in response_text:
            return True

        # Check partial payload (the distinctive parts)
        # For {{12345*67890}} check if "12345*67890" appears
        inner_match = re.search(r'[\{\$\#\*<][{\%=]?\s*(.+?)\s*[\}\%>]', payload)
        if inner_match:
            inner = inner_match.group(1)
            if inner in response_text:
                return True

        return False

    def _is_likely_coincidence(self, expected: str, response_text: str) -> bool:
        """
        Check if the expected result appearing is likely a coincidence

        For large numbers like 123456789, this is very unlikely
        """
        # Our expected results are 8-10 digit numbers from multiplication
        # These are extremely unlikely to appear by coincidence

        # Check if it appears in obvious data patterns
        patterns = [
            rf'id["\s:=]+{re.escape(expected)}',  # ID field
            rf'phone["\s:=]+.*{re.escape(expected)}',  # Phone number
            rf'\${re.escape(expected)}',  # Price
        ]

        for pattern in patterns:
            if re.search(pattern, response_text, re.IGNORECASE):
                return True

        return False


def get_module(module_path: str, payload_limit: int = None):
    """Create module instance"""
    return SSTIModule(module_path, payload_limit=payload_limit)
