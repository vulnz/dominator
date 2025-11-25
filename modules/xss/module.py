"""
XSS (Cross-Site Scripting) Scanner Module - IMPROVED

Improvements:
- Uses BaseDetector for common methods
- Multi-stage detection
- Context-aware validation
- Reduced false positives
- Confidence scoring
"""

from typing import List, Dict, Any
from core.base_module import BaseModule
from detectors.base_detector import BaseDetector
from core.logger import get_logger

logger = get_logger(__name__)


class XSSModule(BaseModule):
    """Improved XSS vulnerability scanner module"""

    def __init__(self, module_path: str, payload_limit: int = None, waf_mode: bool = False):
        """Initialize XSS module"""
        super().__init__(module_path, payload_limit=payload_limit)

        # Load XSS indicators from TXT file
        self.xss_indicators = BaseDetector.load_patterns_from_file('xss/indicators')

        # WAF bypass mode
        self.waf_mode = waf_mode
        self.waf_bypass_payloads = []

        if self.waf_mode:
            try:
                from utils.waf_bypass import WAFBypass
                self.waf_bypass_payloads = WAFBypass.get_xss_bypass_payloads()
                logger.info(f"WAF bypass mode enabled: {len(self.waf_bypass_payloads)} bypass payloads loaded")
            except ImportError:
                logger.warning("WAF bypass module not found, using standard payloads")

        logger.info(f"XSS module loaded: {len(self.payloads)} payloads, "
                   f"{len(self.xss_indicators)} indicators")

    def scan(self, targets: List[Dict[str, Any]], http_client: Any) -> List[Dict[str, Any]]:
        """
        Scan for XSS vulnerabilities

        Args:
            targets: List of URLs with parameters
            http_client: HTTP client for requests

        Returns:
            List of results
        """
        results = []

        logger.info(f"Starting XSS scan on {len(targets)} targets")

        for target in targets:
            url = target.get('url')
            params = target.get('params', {})
            method = target.get('method', 'GET').upper()

            if not params:
                logger.debug(f"Skipping {url} - no parameters")
                continue

            # Test each parameter
            for param_name in params:
                logger.debug(f"Testing XSS in parameter: {param_name} via {method}")

                # Get payloads - include WAF bypass payloads if enabled
                all_payloads = list(self.get_limited_payloads())
                if self.waf_mode and self.waf_bypass_payloads:
                    # Add WAF bypass payloads (prioritized at the end)
                    all_payloads.extend(self.waf_bypass_payloads)
                    logger.debug(f"Using {len(all_payloads)} payloads (including WAF bypass)")

                # Try each payload (limited)
                for payload in all_payloads:
                    # Create test parameters
                    test_params = params.copy()
                    test_params[param_name] = payload

                    # Send request using appropriate method
                    if method == 'POST':
                        response = http_client.post(url, data=test_params)
                    else:
                        response = http_client.get(url, params=test_params)

                    if not response:
                        continue

                    # PASSIVE ANALYSIS: Check for path disclosure, DB errors in response
                    self.analyze_payload_response(response, url, payload)

                    # IMPROVED DETECTION
                    detected, confidence, evidence = self._detect_xss_improved(
                        payload, response
                    )

                    if detected:
                        # Build full URL with payload for evidence
                        from urllib.parse import urlencode, urlparse, parse_qs
                        parsed = urlparse(url)
                        params = parse_qs(parsed.query) if parsed.query else {}
                        params[param_name] = [payload]
                        full_url_with_payload = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{urlencode(params, doseq=True)}"

                        # Prepend full URL to evidence
                        evidence_with_url = f"Vulnerable URL: {full_url_with_payload}\n\n{evidence}"

                        result = self.create_result(
                            vulnerable=True,
                            url=url,
                            parameter=param_name,
                            payload=payload,
                            evidence=evidence_with_url,
                            description="Reflected Cross-Site Scripting (XSS) vulnerability detected. "
                                       "User input is reflected in HTML output without proper sanitization.",
                            confidence=confidence
                        )

                        # Add metadata from config
                        result['cwe'] = self.config.get('cwe', 'CWE-79')
                        result['owasp'] = self.config.get('owasp', 'A03:2021')
                        result['cvss'] = self.config.get('cvss', '7.3')
                        result['xss_type'] = 'Reflected XSS'  # Specify XSS type

                        results.append(result)
                        logger.info(f"✓ Reflected XSS found in {url} (parameter: {param_name}, confidence: {confidence:.2f})")

                        # Move to next parameter after finding vuln
                        break

        # STORED XSS DETECTION
        # Test for stored XSS vulnerabilities (persistent XSS)
        logger.info("Starting Stored XSS detection phase")
        stored_xss_results = self._scan_stored_xss(targets, http_client)
        results.extend(stored_xss_results)
        logger.info(f"Stored XSS scan found {len(stored_xss_results)} vulnerabilities")

        logger.info(f"XSS scan complete: {len(results)} vulnerabilities found")
        return results

    def _detect_xss_improved(self, payload: str, response: Any) -> tuple:
        """
        Improved XSS detection with multi-stage validation

        CRITICAL: Checks for HTML encoding - if payload is encoded, XSS is BLOCKED

        Returns:
            (detected: bool, confidence: float, evidence: str)
        """
        response_text = response.text

        # STAGE 1: CRITICAL - Check if payload is reflected UNENCODED
        # If < becomes &lt; or > becomes &gt;, the XSS is BLOCKED
        if not BaseDetector.is_payload_reflected_unencoded(payload, response_text):
            # Check if it's HTML-encoded (blocked)
            if BaseDetector.is_html_encoded(payload, response_text):
                logger.debug(f"XSS blocked: payload is HTML-encoded in response")
                return False, 0.0, ""
            # Not reflected at all
            if not BaseDetector.is_payload_reflected(payload, response_text):
                return False, 0.0, ""

        # STAGE 2: Verify dangerous characters are UNENCODED
        # This is the most critical check for XSS
        dangerous_chars = ['<', '>', '"', "'"]
        has_unencoded_dangerous = False

        for char in dangerous_chars:
            if char in payload and char in response_text:
                # Check if the char near our payload context is unencoded
                if self._is_char_unencoded_in_context(payload, char, response_text):
                    has_unencoded_dangerous = True
                    break

        if not has_unencoded_dangerous:
            # Double-check: is the EXACT payload reflected?
            if payload not in response_text:
                logger.debug(f"XSS blocked: dangerous characters are encoded")
                return False, 0.0, ""

        # STAGE 3: Context validation - is payload in executable context?
        if not self._validate_xss_context(payload, response_text):
            logger.debug("XSS context validation failed")
            return False, 0.0, ""

        # STAGE 4: Calculate confidence
        confidence = 0.7  # Base confidence for unencoded reflection in dangerous context

        # Boost for very dangerous contexts
        if self._has_dangerous_context(payload, response_text):
            confidence = 0.90

        # Boost for exact payload match with script execution
        if '<script>' in payload.lower() and '<script>' in response_text.lower():
            confidence = 0.95

        # Check for suspicious words (might be documentation)
        if BaseDetector.has_suspicious_words(response_text):
            confidence -= 0.2

        if confidence < 0.50:
            logger.debug(f"XSS confidence too low: {confidence:.2f}")
            return False, 0.0, ""

        # Generate detailed evidence
        evidence = self._generate_xss_evidence(payload, response_text)

        return True, confidence, evidence

    def _is_char_unencoded_in_context(self, payload: str, char: str, response_text: str) -> bool:
        """
        Check if a dangerous character appears unencoded near payload context

        Args:
            payload: Original payload
            char: Dangerous character to check
            response_text: Response text

        Returns:
            True if char is unencoded in payload context
        """
        # Find payload position
        payload_pos = response_text.find(payload)
        if payload_pos == -1:
            # Try finding a unique part of the payload
            for part in [payload[:20], payload[-20:]]:
                if len(part) > 5 and part in response_text:
                    payload_pos = response_text.find(part)
                    break

        if payload_pos == -1:
            return False

        # Check 100 chars around payload position
        start = max(0, payload_pos - 50)
        end = min(len(response_text), payload_pos + len(payload) + 50)
        context = response_text[start:end]

        # Check if the char appears unencoded in this context
        return char in context

    def _generate_xss_evidence(self, payload: str, response_text: str) -> str:
        """
        Generate detailed XSS evidence

        Args:
            payload: XSS payload
            response_text: Response text

        Returns:
            Evidence string
        """
        evidence_parts = []

        # Show where payload is reflected
        snippet = BaseDetector.get_evidence(payload, response_text, context_size=200)
        evidence_parts.append(f"Payload reflected: {snippet}")

        # Determine XSS context
        context_type = "unknown"
        if '<script>' in payload.lower() and '<script>' in response_text.lower():
            context_type = "script tag injection"
        elif 'onerror=' in payload.lower() and 'onerror=' in response_text.lower():
            context_type = "event handler injection"
        elif '<img' in payload.lower() and '<img' in response_text.lower():
            context_type = "HTML tag injection (img)"
        elif '<svg' in payload.lower() and '<svg' in response_text.lower():
            context_type = "HTML tag injection (svg)"
        elif 'javascript:' in payload.lower() and 'javascript:' in response_text.lower():
            context_type = "javascript: URI injection"

        evidence_parts.append(f"XSS Type: {context_type}")
        evidence_parts.append("CONFIRMED: Payload is reflected UNENCODED (< and > are not HTML-escaped)")

        return " | ".join(evidence_parts)

    def _validate_xss_context(self, payload: str, response_text: str) -> bool:
        """
        Validate XSS context - payload should be in dangerous location
        IMPROVED: More flexible detection to reduce false negatives

        Args:
            payload: Injected payload
            response_text: Response text

        Returns:
            True if context is dangerous
        """
        response_lower = response_text.lower()
        payload_lower = payload.lower()

        # CRITICAL: If payload contains <script> and response has <script>, very likely XSS
        if '<script>' in payload_lower and '<script>' in response_lower:
            return True

        # Check 1: Payload in <script> tag (exact or with spaces)
        if f"<script>{payload}" in response_text or f"<script> {payload}" in response_text:
            return True

        # Check 2: Payload in event handler (more flexible)
        event_handlers = ['onerror=', 'onload=', 'onclick=', 'onmouseover=', 'onfocus=', 'onblur=']
        for handler in event_handlers:
            # Check various formats: onerror=payload, onerror="payload", onerror='payload'
            if handler in response_lower and payload_lower in response_lower:
                # Verify they're close together (within 50 chars)
                handler_pos = response_lower.find(handler)
                payload_pos = response_lower.find(payload_lower)
                if abs(handler_pos - payload_pos) < 50:
                    return True

        # Check 3: Payload breaks out of attribute or tag
        if f'>{payload}<' in response_text or f'">{payload}' in response_text or f"'>{payload}" in response_text:
            return True

        # Check 4: Payload in src/href attribute
        if f'src="{payload}"' in response_text or f"src='{payload}'" in response_text:
            return True
        if f'href="{payload}"' in response_text or f"href='{payload}'" in response_text:
            return True

        # Check 5: javascript: protocol
        if 'javascript:' in payload_lower and 'javascript:' in response_lower:
            return True

        # Check 6: IMPORTANT - If payload has <img and response reflects it
        if '<img' in payload_lower and '<img' in response_lower:
            # Check if img tag attributes are present (src, onerror, etc.)
            if 'src=' in response_lower or 'onerror=' in response_lower:
                return True

        # Check 7: SVG-based XSS
        if '<svg' in payload_lower and '<svg' in response_lower:
            return True

        # Check 8: HTML tag injection (payload contains < and >)
        if '<' in payload and '>' in payload:
            # If any HTML-like structure is reflected, consider it dangerous
            if payload in response_text:
                return True

        # Check 9: Alert function (strong XSS indicator)
        if 'alert(' in payload_lower and 'alert(' in response_lower:
            # Check if they're in executable context
            if '<script>' in response_lower or 'onerror=' in response_lower or 'onload=' in response_lower:
                return True

        return False

    def _has_dangerous_context(self, payload: str, response_text: str) -> bool:
        """
        Check if payload is in particularly dangerous context

        Args:
            payload: Payload
            response_text: Response

        Returns:
            True if context is very dangerous
        """
        dangerous_patterns = [
            '<script>alert',
            'onerror=alert',
            'javascript:alert',
            '<svg onload=',
            '<img src=x onerror='
        ]

        response_lower = response_text.lower()
        return any(pattern in response_lower for pattern in dangerous_patterns)

    def _scan_stored_xss(self, targets: List[Dict[str, Any]], http_client: Any) -> List[Dict[str, Any]]:
        """
        Scan for Stored XSS vulnerabilities

        Stored XSS is persistent - payload is saved and displayed to other users
        Detection: POST payload → GET page again → check if payload persists

        Args:
            targets: List of URLs with parameters
            http_client: HTTP client

        Returns:
            List of stored XSS results
        """
        results = []

        # Filter for POST forms that likely store data
        # Look for forms with 'stored', 'comment', 'message', 'post', 'add'
        storage_keywords = ['stored', 'comment', 'message', 'post', 'add', 'create', 'write', 'guest', 'forum']

        post_targets = []
        for target in targets:
            url = target.get('url', '').lower()
            method = target.get('method', 'GET').upper()
            params = target.get('params', {})

            # Check if this is a POST form with storage indicators
            if method == 'POST' and params:
                # Check URL for storage keywords (handles both 'stored' and 'stored_xss')
                if any(keyword in url for keyword in storage_keywords):
                    post_targets.append(target)
                    continue

                # Check parameter names for textarea/comment fields
                param_names_lower = [p.lower() for p in params.keys()]
                if any(keyword in ' '.join(param_names_lower) for keyword in ['comment', 'message', 'text', 'content', 'data', 'input']):
                    post_targets.append(target)
                    continue

                # IMPROVED: Test ALL POST forms, not just those with keywords
                # Many Stored XSS targets don't have obvious keywords
                # Add all POST forms to testing list (will be checked anyway)
                post_targets.append(target)

        logger.info(f"Found {len(post_targets)} POST targets for stored XSS testing")

        for target in post_targets:
            url = target.get('url')
            params = target.get('params', {})

            # Generate unique payload identifier
            import random
            unique_id = random.randint(100000, 999999)

            # Test each parameter with a unique payload
            for param_name in params:
                logger.debug(f"Testing Stored XSS in parameter: {param_name}")

                # Create unique payload that's easily identifiable
                payload = f"<script>alert('STORED_XSS_{unique_id}')</script>"

                # STAGE 1: POST the payload
                test_params = params.copy()
                test_params[param_name] = payload

                post_response = http_client.post(url, data=test_params)
                if not post_response:
                    continue

                # PASSIVE ANALYSIS: Check POST response for path disclosure, DB errors
                self.analyze_payload_response(post_response, url, payload)

                # STAGE 2: GET the same page to check if payload persists
                get_response = http_client.get(url)
                if not get_response:
                    continue

                # PASSIVE ANALYSIS: Check GET response too
                self.analyze_payload_response(get_response, url, payload)

                get_text = getattr(get_response, 'text', '')

                # STAGE 3: Check if our unique payload appears in the response
                if f"STORED_XSS_{unique_id}" in get_text:
                    # Payload persisted! Check if it's in dangerous context
                    if payload in get_text or f"<script>alert('STORED_XSS_{unique_id}')" in get_text:
                        confidence = 0.85  # High confidence - payload stored and reflected

                        # Check for dangerous context
                        if self._validate_xss_context(payload, get_text):
                            confidence = 0.95  # Very high - stored in executable context

                        evidence = f"Stored XSS detected. Unique payload 'STORED_XSS_{unique_id}' was stored after POST and retrieved in GET response. "
                        evidence += BaseDetector.get_evidence(f"STORED_XSS_{unique_id}", get_text, context_size=200)

                        result = self.create_result(
                            vulnerable=True,
                            url=url,
                            parameter=param_name,
                            payload=payload,
                            evidence=evidence,
                            description="Stored Cross-Site Scripting (XSS) vulnerability detected. "
                                      "User input is stored persistently and reflected without sanitization.",
                            confidence=confidence
                        )

                        result['cwe'] = 'CWE-79'
                        result['owasp'] = 'A03:2021'
                        result['cvss'] = '8.0'  # Higher CVSS for stored XSS
                        result['xss_type'] = 'Stored XSS'

                        results.append(result)
                        logger.info(f"✓ Stored XSS found in {url} (parameter: {param_name}, confidence: {confidence:.2f})")

                        # Move to next parameter
                        break

        return results


def get_module(module_path: str, payload_limit: int = None, waf_mode: bool = False):
    """
    Factory function to create module instance

    Args:
        module_path: Path to module directory
        payload_limit: Maximum payloads to use
        waf_mode: Enable WAF bypass payloads

    Returns:
        XSSModule instance
    """
    return XSSModule(module_path, payload_limit=payload_limit, waf_mode=waf_mode)
