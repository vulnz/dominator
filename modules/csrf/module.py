"""
CSRF (Cross-Site Request Forgery) Scanner Module

Detects missing CSRF protection in state-changing operations
Based on XVWA vulnerable code: Forms without anti-CSRF tokens
"""

from typing import List, Dict, Any
from core.base_module import BaseModule
from core.logger import get_logger
import re

logger = get_logger(__name__)


class CSRFModule(BaseModule):
    """CSRF Scanner Module"""

    def __init__(self, module_path: str):
        """Initialize CSRF module"""
        super().__init__(module_path)

        # Common CSRF token field names
        self.token_names = [
            'csrf', 'csrf_token', 'csrftoken', '_csrf', '_token',
            'authenticity_token', 'anti_csrf', 'xsrf', 'xsrf_token',
            'token', '__RequestVerificationToken', 'nonce'
        ]

        # State-changing operations (keywords in forms/URLs)
        self.state_changing_keywords = [
            'password', 'passwd', 'pass', 'pwd',
            'email', 'username', 'user',
            'delete', 'remove', 'change', 'update', 'modify',
            'create', 'add', 'new', 'register',
            'transfer', 'send', 'payment', 'purchase',
            'confirm'  # confirmation fields often indicate state changes
        ]

        logger.info(f"CSRF module loaded: {len(self.token_names)} token patterns")

    def scan(self, targets: List[Dict[str, Any]], http_client: Any) -> List[Dict[str, Any]]:
        """
        Scan for CSRF vulnerabilities

        Args:
            targets: List of URLs with parameters
            http_client: HTTP client

        Returns:
            List of results
        """
        results = []

        logger.info(f"Starting CSRF scan on {len(targets)} targets")

        # CSRF is relevant for forms with state-changing operations
        # GET forms with state-changing params are EVEN MORE VULNERABLE
        # Check both POST and GET forms
        form_targets = [t for t in targets if t.get('method', 'GET').upper() in ['POST', 'GET']]

        logger.info(f"Found {len(form_targets)} forms to check for CSRF protection")

        for target in form_targets:
            url = target.get('url')
            params = target.get('params', {})
            method = target.get('method', 'GET').upper()

            if not params:
                continue

            # Check if this form is state-changing
            is_state_changing = self._is_state_changing(url, params)

            if not is_state_changing:
                logger.debug(f"Skipping {url} - not state-changing")
                continue

            logger.debug(f"Checking CSRF protection for: {url}")

            # Check for CSRF token
            has_csrf_token = self._has_csrf_token(params)

            if not has_csrf_token:
                # Check if form accepts requests without referer/origin validation
                detected, confidence, evidence = self._detect_csrf(
                    url, params, method, http_client
                )

                if detected:
                    result = self.create_result(
                        vulnerable=True,
                        url=url,
                        parameter="",  # CSRF is form-level, not parameter-level
                        payload="",
                        evidence=evidence,
                        description="Cross-Site Request Forgery (CSRF) vulnerability detected. "
                                  "Form accepts state-changing requests without anti-CSRF tokens.",
                        confidence=confidence
                    )

                    # Add metadata
                    result['cwe'] = self.config.get('cwe', 'CWE-352')
                    result['owasp'] = self.config.get('owasp', 'A01:2021')
                    result['cvss'] = self.config.get('cvss', '6.5')

                    results.append(result)
                    logger.info(f"✓ CSRF vulnerability found in {url} "
                              f"(confidence: {confidence:.2f})")

        logger.info(f"CSRF scan complete: {len(results)} vulnerabilities found")
        return results

    def _is_state_changing(self, url: str, params: Dict[str, Any]) -> bool:
        """
        Check if form performs state-changing operation

        Args:
            url: Form URL
            params: Form parameters

        Returns:
            True if state-changing
        """
        # Check URL for state-changing keywords
        url_lower = url.lower()
        for keyword in self.state_changing_keywords:
            if keyword in url_lower:
                return True

        # Check parameter names for state-changing keywords
        for param_name in params.keys():
            param_lower = param_name.lower()
            for keyword in self.state_changing_keywords:
                if keyword in param_lower:
                    return True

        return False

    def _has_csrf_token(self, params: Dict[str, Any]) -> bool:
        """
        Check if form has CSRF token

        Args:
            params: Form parameters

        Returns:
            True if CSRF token present
        """
        for param_name in params.keys():
            param_lower = param_name.lower()
            for token_name in self.token_names:
                if token_name in param_lower:
                    logger.debug(f"CSRF token found: {param_name}")
                    return True

        return False

    def _detect_csrf(self, url: str, params: Dict[str, Any],
                    method: str, http_client: Any) -> tuple:
        """
        Detect CSRF vulnerability

        Returns:
            (detected: bool, confidence: float, evidence: str)
        """
        # STAGE 1: Send request without Referer header
        # (simulating cross-origin request)
        try:
            # Remove Referer/Origin headers if present
            headers = {
                'Referer': '',  # Empty referer
                'Origin': ''
            }

            # Send request using the form's method
            if method == 'POST':
                response = http_client.post(url, data=params, headers=headers)
            else:
                response = http_client.get(url, params=params, headers=headers)

            if not response:
                return False, 0.0, ""

            response_text = getattr(response, 'text', '')

        except Exception as e:
            logger.debug(f"CSRF test request failed: {e}")
            return False, 0.0, ""

        # STAGE 2: Check if request was accepted
        # Success indicators
        success_patterns = [
            'success',
            'changed',
            'updated',
            'saved',
            'completed',
            'thank you',
            'confirmed'
        ]

        response_lower = response_text.lower()
        success_count = sum(1 for pattern in success_patterns if pattern in response_lower)

        # If status is 200 and no error, likely accepted
        if response.status_code == 200:
            # Check for error messages (which would indicate rejection)
            error_patterns = ['error', 'invalid', 'failed', 'denied', 'forbidden']
            error_count = sum(1 for pattern in error_patterns if pattern in response_lower)

            if error_count == 0 or success_count > error_count:
                # Request was likely accepted without CSRF token
                confidence = 0.70

                # Higher confidence if we see success messages
                if success_count >= 2:
                    confidence = 0.85

                # Check if using GET method (very bad for state-changing)
                if method == 'GET' or 'passwd' in url.lower():
                    confidence = 0.90

                evidence = f"{method} form accepts state-changing requests without CSRF token. "
                if method == 'GET':
                    evidence += "CRITICAL: State-changing operation uses GET method! "
                evidence += f"Form has {len(params)} parameters: {', '.join(list(params.keys())[:5])}. "
                evidence += "No anti-CSRF token field found (checked: csrf, csrf_token, _token, etc). "

                if success_count > 0:
                    evidence += f"Request accepted (found {success_count} success indicators). "

                return True, confidence, evidence

        return False, 0.0, ""


def get_module(module_path: str):
    """Create module instance"""
    return CSRFModule(module_path)
