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

                    response_text = getattr(response, 'text', '')

                    # Check if expression was evaluated
                    if expected in response_text and expected not in baseline_text:
                        # Likely SSTI!
                        confidence = 0.90

                        # Check if payload is just reflected (not evaluated)
                        if payload in response_text:
                            # Both payload and result present = definitely SSTI
                            confidence = 0.95
                        else:
                            # Only result present = very likely SSTI
                            confidence = 0.85

                        evidence = f"Template injection detected. Payload '{payload}' evaluated to '{expected}' in response."

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


def get_module(module_path: str):
    """Create module instance"""
    return SSTIModule(module_path)
