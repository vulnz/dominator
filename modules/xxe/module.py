"""
XXE (XML External Entity) Injection Scanner
Detects XXE vulnerabilities with error-based, file disclosure, and OOB detection
"""

import re
import time
from typing import Any, List, Dict
from core.base_module import BaseModule
from detectors.base_detector import BaseDetector
from utils.oob_detector import OOBDetector

import logging
logger = logging.getLogger(__name__)


class XXEModule(BaseModule):
    """XXE vulnerability scanner with multiple detection methods"""

    def __init__(self, module_path: str):
        super().__init__(module_path)

        # OOB detector for blind XXE
        self.oob_detector = OOBDetector()

        # Error patterns indicating XXE
        self.error_patterns = [
            # File disclosure patterns
            r'root:x:0:0:',  # /etc/passwd
            r'\[boot loader\]',  # Windows boot.ini
            r'\[fonts\]',  # Windows win.ini
            r'127\.0\.0\.1\s+localhost',  # /etc/hosts

            # XML parsing errors
            r'XML.*entity.*not defined',
            r'entity.*not.*declared',
            r'DOCTYPE.*not.*allowed',
            r'External entity.*disabled',
            r'XXE.*attack.*detected',

            # Java XXE errors
            r'javax\.xml\..*Exception',
            r'SAXParseException',
            r'java\.io\.FileNotFoundException',

            # PHP XXE errors
            r'simplexml_load',
            r'DOMDocument',
            r'XMLReader',

            # .NET XXE errors
            r'System\.Xml\..*Exception',
            r'XmlException',
        ]

    def scan(self, targets: List[Dict], http_client: Any) -> List[Dict]:
        """
        Scan targets for XXE vulnerabilities using OOB-only detection.

        OOB (Out-of-Band) is the ONLY reliable method for XXE detection because:
        - Error-based detection has too many false positives
        - File disclosure rarely works in modern apps
        - OOB proves the vulnerability definitively
        """
        results = []

        logger.info(f"Starting XXE scan (OOB-only) on {len(targets)} targets")
        logger.info("Using OOB callbacks for reliable blind XXE detection")

        for target in targets:
            url = target['url']
            method = target.get('method', 'GET')
            params = target.get('params', {})

            # Only test endpoints that accept XML or might process XML
            if not self._likely_accepts_xml(url, params):
                continue

            # Test each parameter with OOB payloads
            for param_name in params.keys():
                # OOB (Out-of-Band) detection for blind XXE
                if self.config.get('enable_oob', True):
                    # Generate OOB payloads using the new API
                    oob_payloads = self.oob_detector.get_callback_payloads('xxe', url, param_name)

                    if not oob_payloads:
                        logger.warning("OOB detector unavailable - XXE detection requires OOB!")
                        continue

                    # Get callback_id for verification
                    callback_id = oob_payloads[0]['callback_id']

                    try:
                        # Test each XXE OOB payload
                        for payload_dict in oob_payloads:
                            oob_payload = payload_dict['payload']

                            modified_params = params.copy()
                            modified_params[param_name] = oob_payload

                            response = self._send_request(http_client, url, method, modified_params)

                        # Check if callback received (after testing all payloads)
                        # Wait 5 seconds for blind XXE callback
                        detected_oob, oob_evidence = self.oob_detector.check_callback(
                            callback_id, wait_time=5
                        )

                        if detected_oob:
                            result = self.create_result(
                                vulnerable=True,
                                url=url,
                                parameter=param_name,
                                payload=oob_payload,
                                evidence=f"Blind XXE detected via OOB callback!\n\n{oob_evidence}",
                                description="Blind XXE vulnerability detected via out-of-band callback. "
                                          "Application processes external XML entities and makes outbound requests.",
                                confidence=1.0,
                                severity='critical',  # OOB confirms it's exploitable
                                method=method
                            )
                            results.append(result)
                            logger.info(f"XXE found via OOB: {url} (param: {param_name})")

                    except Exception as e:
                        logger.debug(f"Error testing OOB XXE on {url}: {e}")

        logger.info(f"XXE scan complete: {len(results)} vulnerabilities found")
        return results

    def _likely_accepts_xml(self, url: str, params: Dict) -> bool:
        """Check if endpoint likely accepts XML"""
        # Check URL for XML-related keywords
        xml_keywords = ['xml', 'soap', 'api', 'feed', 'rss', 'import', 'upload']

        url_lower = url.lower()
        for keyword in xml_keywords:
            if keyword in url_lower:
                return True

        # Check parameter names
        param_names = ' '.join(params.keys()).lower()
        for keyword in xml_keywords:
            if keyword in param_names:
                return True

        # Check for file upload parameters
        if any(name in param_names for name in ['file', 'upload', 'document']):
            return True

        return True  # Test all by default (can be made more strict)

    def _detect_xxe_error(self, payload: str, response: Any) -> tuple:
        """
        Detect XXE via error messages or file disclosure

        Returns:
            (detected, confidence, evidence)
        """
        response_text = getattr(response, 'text', '')

        # Check for file disclosure (highest confidence)
        if 'root:x:0:0:' in response_text:
            confidence = 1.0
            evidence = "File disclosure detected: /etc/passwd content found in response!\n\n"
            evidence += BaseDetector.get_evidence('root:x:0:0:', response_text, context_size=300)
            return True, confidence, evidence

        if '[boot loader]' in response_text or '[fonts]' in response_text:
            confidence = 1.0
            evidence = "File disclosure detected: Windows system file content found!\n\n"
            evidence += BaseDetector.get_evidence('[boot loader]', response_text, context_size=300)
            return True, confidence, evidence

        # Check for XXE error patterns
        for pattern in self.error_patterns:
            if re.search(pattern, response_text, re.IGNORECASE):
                confidence = 0.75

                # Higher confidence for specific errors
                if 'entity' in pattern.lower() or 'xxe' in pattern.lower():
                    confidence = 0.85

                evidence = f"XXE error pattern detected: '{pattern}'\n\n"
                evidence += BaseDetector.get_evidence(pattern, response_text, context_size=200)

                return True, confidence, evidence

        return False, 0.0, ""

    def _send_request(self, http_client: Any, url: str, method: str, params: Dict) -> Any:
        """Send HTTP request with XML content type"""
        headers = {
            'Content-Type': 'application/xml',
            'Accept': 'application/xml, text/xml, */*'
        }

        if method.upper() == 'POST':
            # For POST, send as XML body if payload looks like XML
            for param_name, param_value in params.items():
                if isinstance(param_value, str) and '<?xml' in param_value:
                    # Send XML as body
                    return http_client.post(url, data=param_value, headers=headers)

            # Otherwise POST as form data
            return http_client.post(url, data=params, headers=headers)
        else:
            return http_client.get(url, params=params, headers=headers)


def get_module(module_path: str):
    """Create module instance"""
    return XXEModule(module_path)
