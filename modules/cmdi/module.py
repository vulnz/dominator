"""
Command Injection Scanner Module

Detects OS command injection vulnerabilities
"""

from typing import List, Dict, Any
from core.base_module import BaseModule
from detectors.base_detector import BaseDetector
from core.logger import get_logger

logger = get_logger(__name__)


class CMDiModule(BaseModule):
    """Command Injection vulnerability scanner"""

    def __init__(self, module_path: str):
        """Initialize CMDi module"""
        super().__init__(module_path)

        # Load patterns from TXT files
        self.linux_patterns = BaseDetector.load_patterns_from_file('cmdi/linux')
        self.windows_patterns = BaseDetector.load_patterns_from_file('cmdi/windows')
        self.all_patterns = self.linux_patterns + self.windows_patterns

        logger.info(f"CMDi module loaded: {len(self.linux_patterns)} Linux patterns, "
                   f"{len(self.windows_patterns)} Windows patterns")

    def scan(self, targets: List[Dict[str, Any]], http_client: Any) -> List[Dict[str, Any]]:
        """
        Scan for Command Injection vulnerabilities

        Args:
            targets: List of URLs with parameters
            http_client: HTTP client

        Returns:
            List of results
        """
        results = []

        logger.info(f"Starting CMDi scan on {len(targets)} targets")
        logger.info(f"Using {len(self.payloads)} payloads and {len(self.all_patterns)} detection patterns")

        for target in targets:
            url = target.get('url')
            params = target.get('params', {})
            method = target.get('method', 'GET').upper()

            logger.debug(f"Target URL: {url}, Params: {params}, Method: {method}")

            if not params:
                logger.debug(f"Skipping {url} - no parameters found")
                continue

            # Test each parameter
            for param_name in params:
                logger.debug(f"Testing CMDi in parameter: {param_name} via {method}")

                # Try payloads
                for payload in self.payloads[:30]:  # Limit to 30 payloads
                    test_params = params.copy()
                    test_params[param_name] = str(params[param_name]) + payload

                    # Send request using appropriate method
                    if method == 'POST':
                        response = http_client.post(url, data=test_params)
                    else:
                        response = http_client.get(url, params=test_params)

                    if not response:
                        continue

                    # Detect command injection
                    detected, confidence, evidence = self._detect_cmdi(
                        payload, response
                    )

                    if detected:
                        result = self.create_result(
                            vulnerable=True,
                            url=url,
                            parameter=param_name,
                            payload=payload,
                            evidence=evidence,
                            description="OS Command Injection vulnerability detected. "
                                       "Server executes arbitrary system commands.",
                            confidence=confidence
                        )

                        # Add metadata from config
                        result['cwe'] = self.config.get('cwe', 'CWE-78')
                        result['owasp'] = self.config.get('owasp', 'A03:2021')
                        result['cvss'] = self.config.get('cvss', '9.8')

                        results.append(result)
                        logger.info(f"✓ CMDi found in {url} (parameter: {param_name}, confidence: {confidence:.2f})")

                        # Move to next parameter after finding vuln
                        break

        logger.info(f"CMDi scan complete: {len(results)} vulnerabilities found")
        return results

    def _detect_cmdi(self, payload: str, response: Any) -> tuple:
        """
        Detect command injection

        Returns:
            (detected: bool, confidence: float, evidence: str)
        """
        # STAGE 1: Basic checks
        if response.status_code != 200:
            return False, 0.0, ""

        # STAGE 2: Multi-pattern matching (require at least 2 patterns)
        detected, matches = BaseDetector.check_multiple_patterns(
            response.text,
            self.all_patterns,
            min_matches=2
        )

        logger.debug(f"CMDi Detection - Payload: {payload[:50]}, Matches: {len(matches)}, Patterns: {matches[:3] if matches else 'none'}")

        if not detected:
            # Try single strong pattern
            strong_patterns = [
                'uid=',
                'gid=',
                'groups=',
                'Linux version',
                'GNU/Linux'
            ]

            for pattern in strong_patterns:
                if pattern in response.text:
                    detected = True
                    matches = [pattern]
                    break

        if not detected:
            return False, 0.0, ""

        # STAGE 3: Context validation
        if not self._validate_context(payload, response.text, matches):
            logger.debug("CMDi context validation failed")
            return False, 0.0, ""

        # STAGE 4: Check for suspicious words
        has_suspicious = BaseDetector.has_suspicious_words(response.text)

        # STAGE 5: Calculate confidence
        confidence = BaseDetector.calculate_confidence(
            indicators_found=len(matches),
            response_length=len(response.text),
            has_suspicious_words=has_suspicious,
            payload_reflected=BaseDetector.is_payload_reflected(payload, response.text)
        )

        if confidence < 0.55:
            logger.debug(f"CMDi confidence too low: {confidence:.2f}")
            return False, 0.0, ""

        # Generate evidence
        evidence = self._generate_evidence(matches, response.text)

        logger.debug(f"CMDi detected with confidence {confidence:.2f}")
        return True, confidence, evidence

    def _validate_context(self, payload: str, response_text: str, matches: List[str]) -> bool:
        """
        Validate that patterns appear in proper context

        Args:
            payload: Injected payload
            response_text: Response text
            matches: Matched patterns

        Returns:
            True if context is valid
        """
        # Check 1: Multiple strong indicators (at least 2)
        strong_indicators = [
            'uid=',
            'gid=',
            'groups=',
            'root:x:0:0:',
            'Linux version'
        ]

        strong_found = sum(1 for ind in strong_indicators if ind in response_text)
        if strong_found >= 2:
            return True

        # Check 2: Patterns should be near each other (within 500 chars)
        if len(matches) >= 3:
            positions = []
            for match in matches[:3]:
                pos = response_text.find(match)
                if pos != -1:
                    positions.append(pos)

            if len(positions) >= 3:
                pos_range = max(positions) - min(positions)
                if pos_range < 500:  # Tightened from 1000
                    return True

        # Don't rely solely on line count - too generic
        return False

    def _generate_evidence(self, matches: List[str], response_text: str) -> str:
        """
        Generate evidence string from matches

        Args:
            matches: List of matched patterns
            response_text: Response text

        Returns:
            Evidence string
        """
        evidence_parts = []

        for pattern in matches[:3]:
            snippet = BaseDetector.get_evidence(pattern, response_text, context_size=100)
            evidence_parts.append(snippet)

        evidence = f"Found {len(matches)} CMDi indicators: {', '.join(matches[:5])}. "
        evidence += "Examples: " + " | ".join(evidence_parts[:2])

        return evidence


def get_module(module_path: str):
    """Create module instance"""
    return CMDiModule(module_path)
