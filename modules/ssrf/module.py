"""
SSRF (Server-Side Request Forgery) Scanner Module

Detects SSRF/XSPA vulnerabilities by testing internal/cloud endpoints
Based on XVWA vulnerable code: file_get_contents($_POST['img_url'])
"""

from typing import List, Dict, Any
from core.base_module import BaseModule
from detectors.base_detector import BaseDetector
from core.logger import get_logger
import re

logger = get_logger(__name__)


class SSRFModule(BaseModule):
    """SSRF Scanner Module"""

    def __init__(self, module_path: str):
        """Initialize SSRF module"""
        super().__init__(module_path)

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

                # Limit payloads based on parameter name
                payload_limit = 15 if is_url_param else 5

                for payload in self.payloads[:payload_limit]:
                    test_params = params.copy()
                    test_params[param_name] = payload

                    # Send request
                    if method == 'POST':
                        response = http_client.post(url, data=test_params)
                    else:
                        response = http_client.get(url, params=test_params)

                    if not response:
                        continue

                    # Detect SSRF
                    detected, confidence, evidence = self._detect_ssrf(
                        payload, response, param_name
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

    def _detect_ssrf(self, payload: str, response: Any, param_name: str) -> tuple:
        """
        Detect SSRF vulnerability

        Returns:
            (detected: bool, confidence: float, evidence: str)
        """
        response_text = getattr(response, 'text', '')

        # STAGE 1: Check for direct evidence of internal access
        detected_indicators = []

        for indicator in self.ssrf_indicators:
            if indicator in response_text:
                detected_indicators.append(indicator)

        if not detected_indicators:
            return False, 0.0, ""

        # STAGE 2: Validate it's not a false positive (reflected payload)
        # If payload is just reflected without actual SSRF, skip it
        if payload in response_text and len(detected_indicators) == 0:
            return False, 0.0, ""

        # STAGE 3: Check for XSS confusion (avoid detecting XSS as SSRF)
        # If response contains script tags or alert(), it's probably XSS
        xss_patterns = ['<script', 'alert(', 'onerror=', 'onload=', 'javascript:']
        xss_count = sum(1 for pattern in xss_patterns if pattern in response_text.lower())

        if xss_count >= 2:
            logger.debug("SSRF detection skipped: looks like XSS vulnerability")
            return False, 0.0, ""

        # STAGE 4: Calculate confidence based on indicators
        confidence = 0.5  # Base confidence

        # High-confidence indicators
        high_confidence_patterns = [
            'root:x:0:0',  # /etc/passwd
            'ami-id',  # AWS metadata
            'instance-id',
            'computeMetadata'
        ]

        has_high_confidence = any(p in response_text for p in high_confidence_patterns)
        if has_high_confidence:
            confidence = 0.9

        # Check if parameter name suggests URL input
        url_param_keywords = ['url', 'uri', 'img', 'image', 'file', 'path']
        if any(kw in param_name.lower() for kw in url_param_keywords):
            confidence += 0.1

        # Check response length change (SSRF often returns different content)
        if len(response_text) > 500:  # Significant content returned
            confidence += 0.1

        confidence = min(1.0, confidence)

        if confidence < 0.55:
            logger.debug(f"SSRF confidence too low: {confidence:.2f}")
            return False, 0.0, ""

        # Generate evidence
        evidence = f"SSRF indicators detected: {', '.join(detected_indicators[:3])}. "
        evidence += BaseDetector.get_evidence(detected_indicators[0], response_text,
                                             context_size=200)

        return True, confidence, evidence


def get_module(module_path: str):
    """Create module instance"""
    return SSRFModule(module_path)
