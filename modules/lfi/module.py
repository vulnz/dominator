"""
LFI (Local File Inclusion) Scanner Module - IMPROVED

Improvements:
- Multi-stage detection (reduces false positives)
- Uses BaseDetector for common methods
- Patterns from TXT files
- Confidence scoring
- Context validation
"""

from typing import List, Dict, Any
from core.base_module import BaseModule
from detectors.base_detector import BaseDetector
from core.logger import get_logger

logger = get_logger(__name__)


class LFIModule(BaseModule):
    """Improved LFI vulnerability scanner"""

    def __init__(self, module_path: str):
        """Initialize LFI module"""
        super().__init__(module_path)

        # Load patterns from TXT files instead of hardcoding
        self.linux_patterns = BaseDetector.load_patterns_from_file('lfi/linux')
        self.windows_patterns = BaseDetector.load_patterns_from_file('lfi/windows')
        self.all_patterns = self.linux_patterns + self.windows_patterns

        logger.info(f"LFI module loaded: {len(self.linux_patterns)} Linux patterns, "
                   f"{len(self.windows_patterns)} Windows patterns")

    def scan(self, targets: List[Dict[str, Any]], http_client: Any) -> List[Dict[str, Any]]:
        """
        Scan for LFI vulnerabilities with improved detection

        Args:
            targets: List of URLs with parameters
            http_client: HTTP client

        Returns:
            List of results
        """
        results = []

        logger.info(f"Starting LFI scan on {len(targets)} targets")
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
                logger.debug(f"Testing LFI in parameter: {param_name} via {method}")

                # Try payloads (limited to avoid too many requests)
                for payload in self.payloads[:35]:  # Limit to 35 payloads for better detection
                    test_params = params.copy()
                    test_params[param_name] = payload

                    # Send request using appropriate method
                    if method == 'POST':
                        response = http_client.post(url, data=test_params)
                    else:
                        response = http_client.get(url, params=test_params)

                    if not response:
                        continue

                    # IMPROVED DETECTION with multi-stage validation
                    detected, confidence, evidence = self._detect_lfi_improved(
                        payload, response
                    )

                    if detected:
                        result = self.create_result(
                            vulnerable=True,
                            url=url,
                            parameter=param_name,
                            payload=payload,
                            evidence=evidence,
                            description="Local File Inclusion vulnerability detected. "
                                       "Server allows reading of arbitrary files.",
                            confidence=confidence
                        )

                        # Add CWE/OWASP info from config
                        result['cwe'] = self.config.get('cwe', 'CWE-22')
                        result['owasp'] = self.config.get('owasp', 'A03:2021')
                        result['cvss'] = self.config.get('cvss', '7.5')

                        results.append(result)
                        logger.info(f"✓ LFI found in {url} (parameter: {param_name}, confidence: {confidence:.2f})")

                        # Move to next parameter after finding vuln
                        break

        logger.info(f"LFI scan complete: {len(results)} vulnerabilities found")
        return results

    def _detect_lfi_improved(self, payload: str, response: Any) -> tuple:
        """
        Improved LFI detection with multi-stage validation

        Returns:
            (detected: bool, confidence: float, evidence: str)
        """
        # STAGE 1: Basic checks
        if response.status_code != 200:
            return False, 0.0, ""

        # STAGE 2: Length validation (lowered for better detection)
        # Skip length check - some valid LFI responses can be short
        # if not BaseDetector.validate_response_length(response.text, min_length=50):
        #     logger.debug("Response too short for LFI")
        #     return False, 0.0, ""

        # STAGE 3: Multi-pattern matching (требуем минимум 2 совпадения)
        detected, matches = BaseDetector.check_multiple_patterns(
            response.text,
            self.all_patterns,
            min_matches=2  # Minimum 2 patterns for better detection
        )

        logger.debug(f"LFI Detection - Payload: {payload[:50]}, Matches: {len(matches)}, Patterns: {matches[:3] if matches else 'none'}")

        if not detected:
            logger.debug(f"Insufficient pattern matches for LFI: {len(matches)}/2 required")
            return False, 0.0, ""

        # STAGE 4: Context validation
        if not self._validate_context(payload, response.text, matches):
            logger.debug("Context validation failed")
            return False, 0.0, ""

        # STAGE 5: Check for suspicious words (documentation, examples)
        has_suspicious = BaseDetector.has_suspicious_words(response.text)

        # STAGE 6: Calculate confidence
        confidence = BaseDetector.calculate_confidence(
            indicators_found=len(matches),
            response_length=len(response.text),
            has_suspicious_words=has_suspicious,
            payload_reflected=BaseDetector.is_payload_reflected(payload, response.text)
        )

        if confidence < 0.45:  # Minimum confidence threshold (lowered for better detection)
            logger.debug(f"Confidence too low: {confidence:.2f}")
            return False, 0.0, ""

        # Generate evidence
        evidence = self._generate_evidence(matches, response.text)

        logger.debug(f"LFI detected with confidence {confidence:.2f}")
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
        # Check 1: Multiple strong indicators
        strong_indicators = [
            'root:x:0:0:root:/root:',  # Complete /etc/passwd line
            '[boot loader]',            # Windows boot.ini
            'for 16-bit app support'    # Windows win.ini
        ]

        strong_found = sum(1 for ind in strong_indicators if ind in response_text)
        if strong_found >= 1:
            return True

        # Check 2: Patterns should be near each other (not scattered)
        # Find positions of first 3 matches
        if len(matches) >= 3:
            positions = []
            for match in matches[:3]:
                pos = response_text.find(match)
                if pos != -1:
                    positions.append(pos)

            if len(positions) >= 3:
                # Check if they're within 1000 characters of each other
                pos_range = max(positions) - min(positions)
                if pos_range < 1000:
                    return True

        # Check 3: Typical file structure
        # Real files have lines, not just random text
        lines = response_text.split('\n')
        if len(lines) > 10:  # Real file has multiple lines
            return True

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
        # Show first 3 matches
        evidence_parts = []

        for pattern in matches[:3]:
            snippet = BaseDetector.get_evidence(pattern, response_text, context_size=100)
            evidence_parts.append(snippet)

        evidence = f"Found {len(matches)} LFI indicators: {', '.join(matches[:5])}. "
        evidence += "Examples: " + " | ".join(evidence_parts[:2])

        return evidence


def get_module(module_path: str):
    """Create module instance"""
    return LFIModule(module_path)
