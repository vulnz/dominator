"""
SQL Injection Scanner Module

Self-contained module:
- Payloads from payloads.txt
- Error patterns from error_patterns.txt
- NO hardcoded detection logic!
"""

from typing import List, Dict, Any
from core.base_module import BaseModule
from core.logger import get_logger

logger = get_logger(__name__)


class SQLiModule(BaseModule):
    """SQL Injection scanner module"""

    def __init__(self, module_path: str):
        """Initialize SQLi module"""
        super().__init__(module_path)

        # Load SQL error patterns
        self.error_patterns = self._load_txt_file("error_patterns.txt")
        logger.info(f"Loaded {len(self.error_patterns)} SQL error patterns")

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
        logger.info(f"Payloads: {len(self.payloads)}, Error patterns: {len(self.error_patterns)}")

        for target in targets:
            url = target.get('url')
            params = target.get('params', {})

            if not params:
                continue

            # Test each parameter
            for param_name in params:
                logger.debug(f"Testing SQLi in parameter: {param_name}")

                # Try each payload
                for payload in self.payloads:
                    test_params = params.copy()
                    test_params[param_name] = payload

                    # Send request
                    response = http_client.get(url, params=test_params)

                    if not response:
                        continue

                    # Detect SQLi using error patterns from TXT
                    detected, evidence = self._detect_sqli(response.text)

                    if detected:
                        result = self.create_result(
                            vulnerable=True,
                            url=url,
                            parameter=param_name,
                            payload=payload,
                            evidence=evidence,
                            description="SQL Injection vulnerability detected. Database error messages exposed."
                        )

                        results.append(result)
                        logger.info(f"✓ SQLi found in {url} (parameter: {param_name})")

                        # Move to next parameter
                        break

        logger.info(f"SQLi scan complete: {len(results)} vulnerabilities found")
        return results

    def _detect_sqli(self, response_text: str) -> tuple:
        """
        Detect SQL injection using error patterns from TXT

        Args:
            response_text: HTTP response

        Returns:
            (detected: bool, evidence: str)
        """
        response_lower = response_text.lower()

        # Check each error pattern
        for pattern in self.error_patterns:
            pattern_lower = pattern.lower()

            if pattern_lower in response_lower:
                evidence = f"SQL error pattern detected: {pattern}"
                logger.debug(evidence)
                return (True, evidence)

        return (False, "")


def get_module(module_path: str):
    """Create module instance"""
    return SQLiModule(module_path)
