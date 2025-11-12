"""
Open Redirect Scanner Module

Detects Open Redirect vulnerabilities
"""

from typing import List, Dict, Any
from urllib.parse import urlparse
from core.base_module import BaseModule
from core.logger import get_logger

logger = get_logger(__name__)


class RedirectModule(BaseModule):
    """Open Redirect vulnerability scanner"""

    def __init__(self, module_path: str):
        """Initialize Redirect module"""
        super().__init__(module_path)
        logger.info(f"Redirect module loaded: {len(self.payloads)} payloads")

    def scan(self, targets: List[Dict[str, Any]], http_client: Any) -> List[Dict[str, Any]]:
        """
        Scan for Open Redirect vulnerabilities

        Args:
            targets: List of URLs with parameters
            http_client: HTTP client

        Returns:
            List of results
        """
        results = []

        logger.info(f"Starting Open Redirect scan on {len(targets)} targets")

        for target in targets:
            url = target.get('url')
            params = target.get('params', {})
            method = target.get('method', 'GET').upper()

            if not params:
                continue

            # Test each parameter
            for param_name in params:
                logger.debug(f"Testing Open Redirect in parameter: {param_name}")

                # Try payloads
                for payload in self.payloads[:20]:  # Limit to 20 payloads
                    test_params = params.copy()
                    test_params[param_name] = payload

                    # Send request
                    if method == 'POST':
                        response = http_client.post(url, data=test_params, allow_redirects=False)
                    else:
                        response = http_client.get(url, params=test_params, allow_redirects=False)

                    if not response:
                        continue

                    # Detect open redirect
                    detected, confidence, evidence = self._detect_redirect(
                        payload, response, url
                    )

                    if detected:
                        result = self.create_result(
                            vulnerable=True,
                            url=url,
                            parameter=param_name,
                            payload=payload,
                            evidence=evidence,
                            description="Open Redirect vulnerability detected. "
                                       "Application redirects to user-controlled URL.",
                            confidence=confidence
                        )

                        # Add metadata from config
                        result['cwe'] = self.config.get('cwe', 'CWE-601')
                        result['owasp'] = self.config.get('owasp', 'A01:2021')
                        result['cvss'] = self.config.get('cvss', '6.1')

                        results.append(result)
                        logger.info(f"✓ Open Redirect found in {url} (parameter: {param_name}, confidence: {confidence:.2f})")

                        # Move to next parameter after finding vuln
                        break

        logger.info(f"Open Redirect scan complete: {len(results)} vulnerabilities found")
        return results

    def _detect_redirect(self, payload: str, response: Any, original_url: str) -> tuple:
        """
        Detect open redirect

        Returns:
            (detected: bool, confidence: float, evidence: str)
        """
        # Check if response is a redirect
        if response.status_code not in [301, 302, 303, 307, 308]:
            return False, 0.0, ""

        # Get Location header
        location = response.headers.get('Location', '')
        if not location:
            return False, 0.0, ""

        logger.debug(f"Redirect detected: {response.status_code} → {location}")

        # Parse URLs
        try:
            original_domain = urlparse(original_url).netloc
            redirect_domain = urlparse(location).netloc if location.startswith('http') else None

            # If protocol-relative, extract domain
            if location.startswith('//'):
                redirect_domain = location.split('/')[2] if len(location.split('/')) > 2 else None

        except Exception as e:
            logger.debug(f"Error parsing URLs: {e}")
            return False, 0.0, ""

        # Check if redirecting to external domain
        if redirect_domain and redirect_domain != original_domain:
            # Check if redirect domain matches payload
            payload_domain = None
            try:
                if payload.startswith('http'):
                    payload_domain = urlparse(payload).netloc
                elif payload.startswith('//'):
                    payload_domain = payload.split('/')[2] if len(payload.split('/')) > 2 else None
                else:
                    payload_domain = payload.split('/')[0]
            except:
                pass

            if payload_domain and (payload_domain in location or redirect_domain == payload_domain):
                confidence = 0.95
                evidence = f"Redirects to external domain: {location}"
                return True, confidence, evidence

        # Check if Location header contains payload
        if payload in location:
            # Verify it's actually external
            if location.startswith('http') or location.startswith('//'):
                confidence = 0.80
                evidence = f"Location header contains payload: {location}"
                return True, confidence, evidence

        return False, 0.0, ""


def get_module(module_path: str):
    """Create module instance"""
    return RedirectModule(module_path)
