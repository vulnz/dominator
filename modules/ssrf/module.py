"""
SSRF (Server-Side Request Forgery) Scanner Module

Detects SSRF/XSPA vulnerabilities by testing internal/cloud endpoints
Based on XVWA vulnerable code: file_get_contents($_POST['img_url'])
"""

from typing import List, Dict, Any, Optional
from core.base_module import BaseModule
from detectors.base_detector import BaseDetector
from core.logger import get_logger
from utils.oob_detector import OOBDetector
import re

logger = get_logger(__name__)


class SSRFModule(BaseModule):
    """SSRF Scanner Module"""

    def __init__(self, module_path: str, payload_limit: int = None):
        """Initialize SSRF module"""
        super().__init__(module_path, payload_limit=payload_limit)

        # Initialize OOB detector for blind SSRF detection
        self.oob_detector = OOBDetector()

        # SSRF indicators in responses
        self.ssrf_indicators = [
            # Success indicators
            'root:x:0:0',  # /etc/passwd
            '[extensions]',  # win.ini
            'ami-id',  # AWS metadata
            'instance-id',
            'security-credentials',
            'computeMetadata',  # Google Cloud
            'metadata.google.internal',
            # Error indicators that confirm SSRF attempt
            'Connection refused',
            'Connection timed out',
            'No route to host',
            'Failed to connect',
            'Unable to connect',
            'Could not resolve host',
            # File protocol indicators (REMOVED 'file://' - too common in CSS)
            'file not found',
        ]

        logger.info(f"SSRF module loaded: {len(self.payloads)} payloads, "
                   f"{len(self.ssrf_indicators)} indicators")

    def scan(self, targets: List[Dict[str, Any]], http_client: Any) -> List[Dict[str, Any]]:
        """
        Scan for SSRF vulnerabilities

        Args:
            targets: List of URLs with parameters
            http_client: HTTP client

        Returns:
            List of results
        """
        results = []

        logger.info(f"Starting SSRF scan on {len(targets)} targets")

        # SSRF is more common in parameters that accept URLs
        url_params = ['url', 'uri', 'path', 'file', 'page', 'img', 'image',
                      'img_url', 'imageUrl', 'load', 'src', 'source', 'target']

        for target in targets:
            url = target.get('url')
            params = target.get('params', {})
            method = target.get('method', 'GET').upper()

            if not params:
                continue

            # Test each parameter (prioritize URL-like params)
            for param_name in params:
                # Skip if param doesn't look like URL parameter (optimization)
                param_lower = param_name.lower()
                is_url_param = any(keyword in param_lower for keyword in url_params)

                logger.debug(f"Testing SSRF in parameter: {param_name} via {method} "
                           f"(URL param: {is_url_param})")

                # FIRST: Test OOB (Blind SSRF) if parameter looks like URL parameter
                if is_url_param:
                    oob_result = self._test_oob_ssrf(url, params, param_name, method, http_client)
                    if oob_result:
                        results.append(oob_result)
                        logger.info(f"✓ Blind SSRF (OOB) found in {url} (parameter: {param_name})")
                        # Continue to test other parameters

                # Get baseline response for comparison
                baseline_text = self._get_baseline_response(url, params, method, http_client)

                # SECOND: Test regular SSRF with payloads
                # Limit payloads based on parameter name
                payload_limit = 15 if is_url_param else 5

                for payload in self.get_limited_payloads():
                    test_params = params.copy()
                    test_params[param_name] = payload

                    # Send request
                    if method == 'POST':
                        response = http_client.post(url, data=test_params)
                    else:
                        response = http_client.get(url, params=test_params)

                    if not response:
                        continue

                    # Detect SSRF WITH BASELINE COMPARISON
                    detected, confidence, evidence = self._detect_ssrf(
                        payload, response, param_name, baseline_text
                    )

                    if detected:
                        result = self.create_result(
                            vulnerable=True,
                            url=url,
                            parameter=param_name,
                            payload=payload,
                            evidence=evidence,
                            description="Server-Side Request Forgery (SSRF) vulnerability detected. "
                                      "Server makes requests to attacker-controlled URLs.",
                            confidence=confidence
                        )

                        # Add metadata
                        result['cwe'] = self.config.get('cwe', 'CWE-918')
                        result['owasp'] = self.config.get('owasp', 'A10:2021')
                        result['cvss'] = self.config.get('cvss', '8.6')

                        results.append(result)
                        logger.info(f"✓ SSRF found in {url} (parameter: {param_name}, "
                                  f"confidence: {confidence:.2f})")

                        # Move to next parameter
                        break

        logger.info(f"SSRF scan complete: {len(results)} vulnerabilities found")
        return results

    def _detect_ssrf(self, payload: str, response: Any, param_name: str, baseline_text: str = "") -> tuple:
        """
        Detect SSRF vulnerability WITH REFLECTION FILTERING

        CRITICAL: Verify indicator content is DIFFERENT from payload text
        (not just the payload being echoed back)

        Args:
            payload: SSRF payload sent
            response: HTTP response
            param_name: Parameter name tested
            baseline_text: Response without payload (for comparison)

        Returns:
            (detected: bool, confidence: float, evidence: str)
        """
        response_text = getattr(response, 'text', '')

        # STAGE 1: CRITICAL - Filter out payload reflection
        # If indicators are just parts of the reflected payload, it's NOT SSRF

        # Extract keywords from payload that might appear as "indicators"
        payload_keywords = self._extract_payload_keywords(payload)

        # STAGE 2: Check for GENUINE evidence of internal access
        # Indicators must NOT be part of the reflected payload
        genuine_indicators = []

        for indicator in self.ssrf_indicators:
            if indicator in response_text:
                # CRITICAL: Check if this indicator is just the payload being echoed
                indicator_is_from_payload = any(kw in indicator.lower() for kw in payload_keywords)

                if indicator_is_from_payload:
                    logger.debug(f"SSRF indicator '{indicator}' is from payload reflection - skipping")
                    continue

                # Check if indicator was already in baseline
                if baseline_text and indicator in baseline_text:
                    logger.debug(f"SSRF indicator '{indicator}' already in baseline - skipping")
                    continue

                # Check if indicator appears in ACTUAL content context (not URL/parameter)
                if self._is_indicator_in_content(indicator, response_text, payload):
                    genuine_indicators.append(indicator)

        if not genuine_indicators:
            return False, 0.0, ""

        # STAGE 3: Check for XSS confusion
        xss_patterns = ['<script', 'alert(', 'onerror=', 'onload=', 'javascript:']
        xss_count = sum(1 for pattern in xss_patterns if pattern in response_text.lower())

        if xss_count >= 2:
            logger.debug("SSRF detection skipped: looks like XSS vulnerability")
            return False, 0.0, ""

        # STAGE 4: Calculate confidence based on GENUINE indicators
        confidence = 0.5  # Base confidence

        # High-confidence indicators (file contents, not just error messages)
        high_confidence_patterns = [
            'root:x:0:0',      # /etc/passwd content
            '[extensions]',    # win.ini content
            'ami-id',          # AWS metadata
            'instance-id',     # AWS metadata
            'computeMetadata', # GCP metadata
            'privateKey',      # Credentials
            'accessKey',       # Credentials
        ]

        for pattern in high_confidence_patterns:
            if pattern in genuine_indicators:
                confidence = 0.90
                break

        # Error messages indicate attempted SSRF but not confirmed access
        error_patterns = ['Connection refused', 'Connection timed out', 'Could not resolve']
        only_errors = all(ind in error_patterns for ind in genuine_indicators)
        if only_errors:
            confidence = 0.55  # Lower confidence for error-only detection

        # Boost for URL parameter names
        url_param_keywords = ['url', 'uri', 'img', 'image', 'file', 'path', 'src']
        if any(kw in param_name.lower() for kw in url_param_keywords):
            confidence += 0.1

        confidence = min(1.0, confidence)

        if confidence < 0.50:
            logger.debug(f"SSRF confidence too low: {confidence:.2f}")
            return False, 0.0, ""

        # Generate detailed evidence
        evidence = self._generate_ssrf_evidence(genuine_indicators, response_text, payload)

        return True, confidence, evidence

    def _extract_payload_keywords(self, payload: str) -> List[str]:
        """
        Extract ALL keywords from payload that might falsely match as indicators

        CRITICAL: This must extract EVERY identifiable part of the payload URL
        to prevent reflection-based false positives.

        Args:
            payload: SSRF payload

        Returns:
            List of keywords to filter
        """
        keywords = []
        payload_lower = payload.lower()

        # Extract ALL path segments from the payload URL
        # e.g., "http://169.254.169.254/latest/meta-data/iam/security-credentials/"
        # should extract: ['169.254.169.254', 'latest', 'meta-data', 'iam', 'security-credentials']
        import re
        from urllib.parse import urlparse

        try:
            parsed = urlparse(payload)

            # Add host/domain parts
            if parsed.netloc:
                keywords.append(parsed.netloc.lower())
                # Also add IP octets
                for part in parsed.netloc.split('.'):
                    if part:
                        keywords.append(part.lower())

            # Add ALL path segments
            if parsed.path:
                path_parts = [p for p in parsed.path.split('/') if p]
                for part in path_parts:
                    keywords.append(part.lower())
                    # Also add hyphenated sub-parts
                    if '-' in part:
                        for subpart in part.split('-'):
                            if subpart:
                                keywords.append(subpart.lower())
        except:
            pass

        # Add common SSRF payload keywords as fallback
        common_terms = [
            'localhost', '127.0.0.1', '169.254', 'metadata',
            'security-credentials', 'computemetadata', 'internal',
            'aws', 'gcp', 'azure', 'admin', 'file:', 'gopher:',
            'dict:', 'ftp:', 'sftp:', 'ldap:', 'latest', 'meta-data',
            'user-data', 'instance-data', 'ami-id', 'instance-id',
            'iam', 'credentials', 'role'
        ]

        for term in common_terms:
            if term in payload_lower and term not in keywords:
                keywords.append(term)

        return keywords

    def _is_indicator_in_content(self, indicator: str, response_text: str, payload: str) -> bool:
        """
        STRICT check if indicator appears in GENUINE content (not reflection)

        CRITICAL FIX: Must verify indicator is NOT just the payload being echoed back.
        This prevents false positives where WHOIS/lookup services reflect input.

        Args:
            indicator: SSRF indicator found
            response_text: Response text
            payload: Original payload

        Returns:
            True ONLY if indicator is in genuine SSRF response content
        """
        response_lower = response_text.lower()
        indicator_lower = indicator.lower()
        payload_lower = payload.lower()

        # STEP 1: If the full payload appears in the response, it's likely reflection
        if payload_lower in response_lower:
            logger.debug(f"Payload reflected in response - checking if indicator is outside payload context")

            # Find ALL positions where payload appears
            payload_positions = []
            start = 0
            while True:
                pos = response_lower.find(payload_lower, start)
                if pos == -1:
                    break
                payload_positions.append((pos, pos + len(payload_lower)))
                start = pos + 1

            # Find ALL positions where indicator appears
            indicator_positions = []
            start = 0
            while True:
                pos = response_lower.find(indicator_lower, start)
                if pos == -1:
                    break
                indicator_positions.append(pos)
                start = pos + 1

            # Check if ANY indicator position is OUTSIDE ALL payload ranges
            for ind_pos in indicator_positions:
                is_inside_payload = False
                for pay_start, pay_end in payload_positions:
                    if pay_start <= ind_pos < pay_end:
                        is_inside_payload = True
                        break

                if not is_inside_payload:
                    # Found indicator OUTSIDE of payload reflection!
                    logger.debug(f"Indicator '{indicator}' found outside payload reflection at position {ind_pos}")
                    return True

            # All indicator occurrences are within payload - this is reflection, NOT SSRF
            logger.debug(f"All occurrences of '{indicator}' are within reflected payload - FALSE POSITIVE")
            return False

        # STEP 2: Payload NOT in response - check if indicator is part of URL that was reflected differently
        # e.g., URL-encoded payload might be reflected decoded
        import urllib.parse
        payload_variants = [
            payload_lower,
            urllib.parse.unquote(payload_lower),
            urllib.parse.quote(payload_lower),
        ]

        for variant in payload_variants:
            if variant in response_lower and indicator_lower in variant:
                logger.debug(f"Indicator '{indicator}' is part of reflected payload variant")
                return False

        # STEP 3: Check if indicator appears in likely reflection contexts
        # Common reflection patterns: error messages, form echoes, debug output
        reflection_patterns = [
            f'value="{indicator}',     # Form value
            f"value='{indicator}",
            f'>{payload}<',            # HTML element content
            f'>{indicator}<',
            f'error.*{indicator}',     # Error message
            f'{indicator}.*not found', # Not found error
            f'input.*{indicator}',     # Input reflection
        ]

        import re
        for pattern in reflection_patterns:
            if re.search(pattern, response_lower, re.IGNORECASE):
                logger.debug(f"Indicator appears in reflection context pattern: {pattern}")
                # Don't return False yet - might still be valid if also appears elsewhere
                pass

        # STEP 4: Indicator appears WITHOUT being part of reflected payload - likely genuine
        return True

    def _generate_ssrf_evidence(self, indicators: List[str], response_text: str, payload: str) -> str:
        """
        Generate detailed SSRF evidence

        Args:
            indicators: Genuine SSRF indicators found
            response_text: Response text
            payload: Original payload

        Returns:
            Evidence string
        """
        evidence_parts = []

        evidence_parts.append(f"SSRF indicators found (NOT from payload reflection): {', '.join(indicators[:3])}")

        # Get snippet of genuine indicator
        if indicators:
            snippet = BaseDetector.get_evidence(indicators[0], response_text, context_size=200)
            evidence_parts.append(f"Proof: {snippet}")

        # Determine SSRF type
        if 'root:x:' in response_text or 'win.ini' in response_text.lower():
            evidence_parts.append("Type: File access via SSRF")
        elif 'ami-id' in response_text or 'metadata' in response_text.lower():
            evidence_parts.append("Type: Cloud metadata access")
        elif any(err in response_text for err in ['Connection refused', 'timed out']):
            evidence_parts.append("Type: Internal port scanning (error-based)")

        return " | ".join(evidence_parts)

    def _get_baseline_response(self, url: str, params: Dict[str, Any],
                                method: str, http_client: Any) -> str:
        """
        Get baseline response without SSRF payload for comparison

        Args:
            url: Target URL
            params: Original parameters
            method: HTTP method
            http_client: HTTP client

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
            logger.debug(f"Error getting SSRF baseline: {e}")

        return ""

    def _test_oob_ssrf(self, url: str, params: Dict[str, Any], param_name: str,
                       method: str, http_client: Any) -> Dict[str, Any]:
        """
        Test for Blind SSRF using OOB detection

        Args:
            url: Target URL
            params: Parameters dictionary
            param_name: Parameter name to test
            method: HTTP method (GET/POST)
            http_client: HTTP client

        Returns:
            Result dictionary if vulnerability found, None otherwise
        """
        try:
            # Generate OOB payloads
            oob_payloads = self.oob_detector.get_callback_payloads('ssrf', url, param_name)

            logger.debug(f"Testing Blind SSRF (OOB) with {len(oob_payloads)} payloads")

            for payload_info in oob_payloads[:3]:  # Test first 3 OOB payloads
                payload = payload_info['payload']
                callback_id = payload_info['callback_id']

                # Send request with OOB payload
                test_params = params.copy()
                test_params[param_name] = payload

                if method == 'POST':
                    response = http_client.post(url, data=test_params)
                else:
                    response = http_client.get(url, params=test_params)

                if not response:
                    continue

                # Check for callback (wait 3 seconds)
                detected, evidence = self.oob_detector.check_callback(callback_id, wait_time=3)

                if detected:
                    # Blind SSRF confirmed via OOB callback
                    result = self.create_result(
                        vulnerable=True,
                        url=url,
                        parameter=param_name,
                        payload=payload,
                        evidence=f"Blind SSRF confirmed via Out-of-Band callback. {evidence}",
                        description=f"Blind Server-Side Request Forgery (SSRF) vulnerability detected. "
                                  f"The server made an external request to attacker-controlled URL ({payload_info['type']} payload). "
                                  f"This was confirmed via out-of-band callback detection.",
                        confidence=0.95  # High confidence for OOB confirmation
                    )

                    # Add metadata
                    result['cwe'] = self.config.get('cwe', 'CWE-918')
                    result['owasp'] = self.config.get('owasp', 'A10:2021')
                    result['cvss'] = self.config.get('cvss', '8.6')
                    result['detection_method'] = 'Out-of-Band (OOB)'

                    return result

        except Exception as e:
            logger.debug(f"Error in OOB SSRF testing: {e}")

        return None


def get_module(module_path: str, payload_limit: int = None):
    """Create module instance"""
    return SSRFModule(module_path, payload_limit=payload_limit)
