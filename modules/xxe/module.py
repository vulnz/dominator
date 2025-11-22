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

    def __init__(self, module_path: str, payload_limit: int = None):
        super().__init__(module_path, payload_limit=payload_limit)

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
        Scan targets for XXE vulnerabilities using multi-stage detection:
        1. OOB (Out-of-Band) - Most reliable for blind XXE
        2. Error-based - Fallback for when OOB is disabled
        3. File disclosure - Definitive proof if file contents returned
        """
        results = []

        logger.info(f"Starting XXE scan on {len(targets)} targets")

        for target in targets:
            url = target['url']
            method = target.get('method', 'GET')
            params = target.get('params', {})

            # Only test endpoints that accept XML or might process XML
            if not self._likely_accepts_xml(url, params):
                continue

            # Get baseline response
            baseline_response = self._send_request(http_client, url, method, params)
            baseline_text = getattr(baseline_response, 'text', '') if baseline_response else ''

            # Test each parameter
            for param_name in params.keys():
                found_vuln = False

                # STAGE 1: OOB (Out-of-Band) detection for blind XXE
                if self.config.get('enable_oob', True):
                    oob_payloads = self.oob_detector.get_callback_payloads('xxe', url, param_name)

                    if oob_payloads:
                        callback_id = oob_payloads[0]['callback_id']

                        try:
                            for payload_dict in oob_payloads:
                                oob_payload = payload_dict['payload']
                                modified_params = params.copy()
                                modified_params[param_name] = oob_payload
                                self._send_request(http_client, url, method, modified_params)

                            # Check callback (wait 5 seconds)
                            detected_oob, oob_evidence = self.oob_detector.check_callback(
                                callback_id, wait_time=5
                            )

                            if detected_oob:
                                result = self.create_result(
                                    vulnerable=True,
                                    url=url,
                                    parameter=param_name,
                                    payload=oob_payload,
                                    evidence=f"Blind XXE CONFIRMED via OOB callback!\n\n{oob_evidence}",
                                    description="Blind XXE vulnerability detected via out-of-band callback. "
                                              "Application processes external XML entities.",
                                    confidence=1.0,
                                    severity='critical',
                                    method=method
                                )
                                results.append(result)
                                logger.info(f"XXE found via OOB: {url} (param: {param_name})")
                                found_vuln = True
                                break  # Move to next parameter

                        except Exception as e:
                            logger.debug(f"Error testing OOB XXE: {e}")

                if found_vuln:
                    continue

                # STAGE 2: Error-based and File disclosure detection (fallback)
                for payload in self.get_limited_payloads():
                    modified_params = params.copy()
                    modified_params[param_name] = payload

                    response = self._send_request(http_client, url, method, modified_params)
                    if not response:
                        continue

                    # Check for file disclosure or XXE errors
                    detected, confidence, evidence = self._detect_xxe_error(
                        payload, response, baseline_text
                    )

                    if detected:
                        result = self.create_result(
                            vulnerable=True,
                            url=url,
                            parameter=param_name,
                            payload=payload,
                            evidence=evidence,
                            description="XXE (XML External Entity) vulnerability detected. "
                                      "Application processes external XML entities.",
                            confidence=confidence,
                            severity='high' if confidence > 0.8 else 'medium',
                            method=method
                        )
                        results.append(result)
                        logger.info(f"XXE found: {url} (param: {param_name}, confidence: {confidence:.2f})")
                        found_vuln = True
                        break

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

    def _detect_xxe_error(self, payload: str, response: Any, baseline_text: str = "") -> tuple:
        """
        Detect XXE via error messages or file disclosure with baseline comparison

        CRITICAL: Only report if indicators are NEW (not in baseline) and NOT reflected payload

        Returns:
            (detected, confidence, evidence)
        """
        response_text = getattr(response, 'text', '')

        # Check for file disclosure (highest confidence) - MUST be NEW
        file_indicators = [
            ('root:x:0:0:', '/etc/passwd', 'Linux'),
            ('[boot loader]', 'boot.ini', 'Windows'),
            ('[fonts]', 'win.ini', 'Windows'),
            ('127.0.0.1\tlocalhost', '/etc/hosts', 'Linux'),
        ]

        for indicator, file_name, os_type in file_indicators:
            if indicator in response_text:
                # CRITICAL: Check if it's NEW (not in baseline)
                if baseline_text and indicator in baseline_text:
                    continue  # Was already there, not from our injection

                # CRITICAL: Check if indicator is NOT just reflected payload
                if indicator in payload:
                    continue  # Indicator is part of our payload - reflection

                confidence = 1.0
                evidence = f"File disclosure CONFIRMED: {file_name} ({os_type}) content found!\n\n"
                evidence += f"PROOF: Content '{indicator}' appeared AFTER injection (not in baseline).\n\n"
                evidence += BaseDetector.get_evidence(indicator, response_text, context_size=300)
                return True, confidence, evidence

        # Check for XXE error patterns - with baseline comparison
        matches_found = []
        for pattern in self.error_patterns:
            match = re.search(pattern, response_text, re.IGNORECASE)
            if match:
                matched_text = match.group(0)

                # CRITICAL: Check if it's NEW (not in baseline)
                if baseline_text and re.search(pattern, baseline_text, re.IGNORECASE):
                    continue  # Error was already there

                # CRITICAL: Skip if it looks like reflected payload
                if any(p in payload for p in [matched_text[:20]] if len(matched_text) >= 20):
                    continue

                matches_found.append((pattern, matched_text))

        # Require at least 1 NEW error pattern
        if matches_found:
            pattern, matched_text = matches_found[0]
            confidence = 0.75

            # Higher confidence for specific errors
            if 'entity' in pattern.lower() or 'xxe' in pattern.lower():
                confidence = 0.85

            # Boost for multiple matches
            if len(matches_found) >= 2:
                confidence = min(0.95, confidence + 0.1)

            evidence = f"XXE error pattern detected (NEW - not in baseline): '{matched_text}'\n\n"
            evidence += BaseDetector.get_evidence(matched_text, response_text, context_size=200)

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


def get_module(module_path: str, payload_limit: int = None):
    """Create module instance"""
    return XXEModule(module_path, payload_limit=payload_limit)
