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

    def __init__(self, module_path: str, payload_limit: int = None):
        """Initialize LFI module"""
        super().__init__(module_path, payload_limit=payload_limit)

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

                # CRITICAL FIX: Get baseline response FIRST (without LFI payload)
                baseline_text = self._get_baseline_response(url, params, method, http_client)

                # Try payloads (limited to avoid too many requests)
                for payload in self.get_limited_payloads():  # Limit to 35 payloads for better detection
                    test_params = params.copy()
                    test_params[param_name] = payload

                    # Send request using appropriate method
                    if method == 'POST':
                        response = http_client.post(url, data=test_params)
                    else:
                        response = http_client.get(url, params=test_params)

                    if not response:
                        continue

                    # PASSIVE ANALYSIS: LFI often triggers path disclosure errors
                    self.analyze_payload_response(response, url, payload)

                    # IMPROVED DETECTION with multi-stage validation AND BASELINE COMPARISON
                    detected, confidence, evidence = self._detect_lfi_improved(
                        payload, response, baseline_text
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

    def _get_baseline_response(self, url: str, params: dict, method: str, http_client: Any) -> str:
        """
        Get baseline response WITHOUT LFI payload for comparison

        CRITICAL: This allows us to detect if file content is NEW (caused by payload)
        or pre-existing on the page.

        Returns:
            Baseline response text
        """
        try:
            if method == 'POST':
                response = http_client.post(url, data=params)
            else:
                response = http_client.get(url, params=params)

            if response:
                return getattr(response, 'text', '')
        except Exception as e:
            logger.debug(f"Error getting LFI baseline: {e}")

        return ""

    def _detect_lfi_improved(self, payload: str, response: Any, baseline_text: str = "") -> tuple:
        """
        Improved LFI detection with multi-stage validation AND BASELINE COMPARISON

        CRITICAL FIX: Verify file content is NEW (not pre-existing on page)

        Returns:
            (detected: bool, confidence: float, evidence: str)
        """
        # STAGE 1: Basic checks
        if response.status_code != 200:
            return False, 0.0, ""

        response_text = getattr(response, 'text', '')

        # STAGE 2: Check for very strong single indicators first
        very_strong_indicators = [
            'root:x:0:0:root:/root:',  # Complete /etc/passwd root line
            '[boot loader]',            # Windows boot.ini
            'for 16-bit app support',   # Windows win.ini
            '; for 16-bit app support', # Windows win.ini (full)
        ]

        for indicator in very_strong_indicators:
            if indicator in response_text:
                # CRITICAL: Check if this indicator is NEW (not already in baseline)
                if baseline_text and indicator in baseline_text:
                    logger.debug(f"LFI indicator '{indicator}' already in baseline - skipping")
                    continue

                # Single very strong indicator = immediate detection
                confidence = 0.95
                evidence = f"Very strong LFI indicator found (NEW - not in baseline): '{indicator}'. "
                evidence += BaseDetector.get_evidence(indicator, response_text, context_size=200)
                logger.debug(f"LFI detected via very strong indicator: {indicator}")
                return True, confidence, evidence

        # STAGE 3: Multi-pattern matching (require minimum 2 matches for reliability)
        detected, matches = BaseDetector.check_multiple_patterns(
            response_text,
            self.all_patterns,
            min_matches=2  # FIXED: Require 2+ patterns to reduce false positives
        )

        logger.debug(f"LFI Detection - Payload: {payload[:50]}, Matches: {len(matches)}, Patterns: {matches[:3] if matches else 'none'}")

        if not detected:
            logger.debug(f"No pattern matches for LFI")
            return False, 0.0, ""

        # CRITICAL FIX: Filter out patterns that were already in baseline
        if baseline_text:
            new_matches = []
            for match in matches:
                if match not in baseline_text:
                    new_matches.append(match)
                else:
                    logger.debug(f"LFI pattern '{match}' already in baseline - skipping")

            if len(new_matches) < 2:
                logger.debug(f"Not enough NEW LFI patterns (need 2, found {len(new_matches)})")
                return False, 0.0, ""

            matches = new_matches
            logger.debug(f"NEW LFI patterns found: {matches[:3]}")

        # Verify matches are strong (not generic like 'localhost')
        generic_patterns = ['localhost', '127.0.0.1', '[extensions]', '[fonts]', 'extension=']
        strong_matches = [m for m in matches if not any(g in m.lower() for g in generic_patterns)]

        if len(strong_matches) < 1 and len(matches) < 3:
            # All matches are generic, need at least 3 generic or 1 strong
            logger.debug(f"Only generic LFI patterns found - rejecting")
            return False, 0.0, ""

        # STAGE 4: Context validation
        if not self._validate_context(payload, response_text, matches):
            logger.debug("Context validation failed")
            return False, 0.0, ""

        # STAGE 6: Check for suspicious words (documentation, examples)
        has_suspicious = BaseDetector.has_suspicious_words(response.text)

        # STAGE 7: Calculate confidence
        confidence = BaseDetector.calculate_confidence(
            indicators_found=len(matches),
            response_length=len(response.text),
            has_suspicious_words=has_suspicious,
            payload_reflected=BaseDetector.is_payload_reflected(payload, response.text)
        )

        if confidence < 0.35:  # IMPROVED: Lowered from 0.45 to catch more real LFI
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


def get_module(module_path: str, payload_limit: int = None):
    """Create module instance"""
    return LFIModule(module_path, payload_limit=payload_limit)
