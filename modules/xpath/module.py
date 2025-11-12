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

    def __init__(self, module_path: str):
        """Initialize XPath module"""
        super().__init__(module_path)

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
                for payload in self.payloads[:20]:  # Limit to 20
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
        Detect XPath injection

        Returns:
            (detected: bool, confidence: float, evidence: str)
        """
        response_text = getattr(response, 'text', '')
        response_length = len(response_text)

        # METHOD 1: Error-based detection
        detected, matches = BaseDetector.check_multiple_patterns(
            response_text,
            self.error_patterns,
            min_matches=1
        )

        if detected and matches:
            # XPath error found
            confidence = 0.85

            # Validate it's not reflected payload
            if payload in response_text and len(matches) == 1:
                confidence = 0.60

            evidence = f"XPath error detected: {', '.join(matches[:2])}. "
            evidence += BaseDetector.get_evidence(matches[0], response_text, context_size=150)

            return True, confidence, evidence

        # METHOD 2: Boolean-based detection (data disclosure)
        # Check if "always true" payloads return more data
        if "' or '" in payload or "or 1=1" in payload:
            length_increase = response_length - baseline_length

            # Significant increase in data
            if length_increase > 200:
                # Check for XML/data patterns
                xml_patterns = ['<Coffee', '<Item', '<Record', '<td>', '<tr>']
                xml_count = sum(1 for p in xml_patterns if p in response_text)

                if xml_count > 0:
                    confidence = 0.75

                    # More XML tags = higher confidence
                    if xml_count >= 3:
                        confidence = 0.90

                    evidence = f"Boolean-based XPath injection. Payload caused {length_increase} byte increase. "
                    evidence += f"Response contains {xml_count} XML/data elements indicating data disclosure."

                    return True, confidence, evidence

        return False, 0.0, ""


def get_module(module_path: str):
    """Create module instance"""
    return XPathModule(module_path)
