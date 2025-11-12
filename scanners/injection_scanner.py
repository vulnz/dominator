"""
Scanner for injection vulnerabilities (XSS, SQLi, Command Injection, etc.)
"""

from typing import List, Dict, Any, Optional
from urllib.parse import urlencode, quote
from core.base_scanner import BaseScanner
from core.base_detector import DetectorResult, Severity
from core.logger import get_logger
from utils.payload_loader import PayloadLoader
from libs.false_positive_filter import FalsePositiveFilter

# Import detectors
try:
    from detectors.xss_detector import XSSDetector
    from detectors.sqli_detector import SQLiDetector
    from detectors.command_injection_detector import CommandInjectionDetector
    from detectors.ldap_injection_detector import LDAPInjectionDetector
    from detectors.nosql_injection_detector import NoSQLInjectionDetector
    from detectors.ssti_detector import SSTIDetector
    from detectors.xxe_detector import XXEDetector
    from detectors.crlf_detector import CRLFDetector
    from detectors.textinjection_detector import TextInjectionDetector
    from detectors.htmlinjection_detector import HTMLInjectionDetector
except ImportError as e:
    print(f"Warning: Could not import detector classes: {e}")
    # Create dummy classes
    XSSDetector = None
    SQLiDetector = None
    CommandInjectionDetector = None
    LDAPInjectionDetector = None
    NoSQLInjectionDetector = None
    SSTIDetector = None
    XXEDetector = None
    CRLFDetector = None
    TextInjectionDetector = None
    HTMLInjectionDetector = None

logger = get_logger(__name__)


class InjectionScanner(BaseScanner):
    """Scanner for injection vulnerabilities"""

    def __init__(self, http_client, config=None):
        """Initialize injection scanner"""
        super().__init__(http_client, config)
        self.payload_loader = PayloadLoader()
        self.fp_filter = FalsePositiveFilter()

        # Enabled modules (from config)
        self.enabled_modules = set()
        if config and hasattr(config, 'modules'):
            self.enabled_modules = set(config.modules)

    def scan(self, targets: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Scan for injection vulnerabilities

        Args:
            targets: List of URLs with parameters

        Returns:
            List of results
        """
        logger.info(f"Starting injection scanner on {len(targets)} targets")
        results = []

        # Scan for each type of injection
        if 'xss' in self.enabled_modules:
            results.extend(self._scan_xss(targets))
        if 'sqli' in self.enabled_modules:
            results.extend(self._scan_sqli(targets))
        if 'commandinjection' in self.enabled_modules:
            results.extend(self._scan_command_injection(targets))
        if 'ldapinjection' in self.enabled_modules:
            results.extend(self._scan_ldap_injection(targets))
        if 'nosqlinjection' in self.enabled_modules:
            results.extend(self._scan_nosql_injection(targets))
        if 'ssti' in self.enabled_modules:
            results.extend(self._scan_ssti(targets))
        if 'xxe' in self.enabled_modules:
            results.extend(self._scan_xxe(targets))
        if 'crlf' in self.enabled_modules:
            results.extend(self._scan_crlf(targets))
        if 'textinjection' in self.enabled_modules:
            results.extend(self._scan_text_injection(targets))
        if 'htmlinjection' in self.enabled_modules:
            results.extend(self._scan_html_injection(targets))

        logger.info(f"Injection scanner found {len(results)} results")
        return results

    def _scan_xss(self, targets: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Scan for XSS vulnerabilities"""
        if not XSSDetector:
            logger.warning("XSSDetector not available")
            return []

        logger.info("Scanning for XSS vulnerabilities")
        results = []
        payloads = self.payload_loader.load_payloads('xss')

        for target in targets:
            if self.should_stop():
                break

            url = target.get('url')
            params = target.get('params', {})

            for param_name in params:
                for payload in payloads[:20]:  # Limit payloads
                    if self.should_stop():
                        break

                    # Test parameter
                    test_params = params.copy()
                    test_params[param_name] = payload

                    response = self.http_client.get(url, params=test_params)
                    if not response:
                        continue

                    # Detect XSS
                    if XSSDetector.detect_reflected_xss(payload, response.text, response.status_code):
                        # Filter false positives
                        if self.fp_filter.is_false_positive('xss', {
                            'payload': payload,
                            'response': response.text,
                            'url': url,
                            'parameter': param_name
                        }):
                            continue

                        result = {
                            'vulnerability': True,
                            'type': 'XSS',
                            'severity': 'High',
                            'url': url,
                            'parameter': param_name,
                            'payload': payload,
                            'evidence': f'Payload reflected in response',
                            'description': 'Cross-Site Scripting vulnerability detected',
                            'scanner': self.name
                        }

                        # Add metadata
                        metadata = self.payload_loader.get_vulnerability_metadata('xss', 'High')
                        result.update(metadata)

                        results.append(result)
                        logger.info(f"XSS found: {url} (parameter: {param_name})")
                        break  # Move to next parameter

        return results

    def _scan_sqli(self, targets: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Scan for SQL injection vulnerabilities"""
        if not SQLiDetector:
            logger.warning("SQLiDetector not available")
            return []

        logger.info("Scanning for SQL injection vulnerabilities")
        results = []
        payloads = self.payload_loader.load_payloads('sqli')

        for target in targets:
            if self.should_stop():
                break

            url = target.get('url')
            params = target.get('params', {})

            for param_name in params:
                for payload in payloads[:20]:  # Limit payloads
                    if self.should_stop():
                        break

                    # Test parameter
                    test_params = params.copy()
                    test_params[param_name] = payload

                    response = self.http_client.get(url, params=test_params)
                    if not response:
                        continue

                    # Detect SQLi
                    detected, evidence = SQLiDetector.detect_error_based_sqli(
                        response.text, response.status_code
                    )

                    if detected:
                        # Filter false positives
                        if self.fp_filter.is_false_positive('sqli', {
                            'payload': payload,
                            'response': response.text,
                            'url': url,
                            'parameter': param_name
                        }):
                            continue

                        result = {
                            'vulnerability': True,
                            'type': 'SQLi',
                            'severity': 'Critical',
                            'url': url,
                            'parameter': param_name,
                            'payload': payload,
                            'evidence': evidence,
                            'description': 'SQL Injection vulnerability detected',
                            'scanner': self.name
                        }

                        # Add metadata
                        metadata = self.payload_loader.get_vulnerability_metadata('sqli', 'Critical')
                        result.update(metadata)

                        results.append(result)
                        logger.info(f"SQLi found: {url} (parameter: {param_name})")
                        break  # Move to next parameter

        return results

    def _scan_command_injection(self, targets: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Scan for command injection vulnerabilities"""
        if not CommandInjectionDetector:
            return []

        logger.info("Scanning for command injection vulnerabilities")
        results = []
        payloads = self.payload_loader.load_payloads('command_injection')

        for target in targets:
            if self.should_stop():
                break

            url = target.get('url')
            params = target.get('params', {})

            for param_name in params:
                for payload in payloads[:15]:  # Limit payloads
                    if self.should_stop():
                        break

                    test_params = params.copy()
                    test_params[param_name] = payload

                    response = self.http_client.get(url, params=test_params)
                    if not response:
                        continue

                    if CommandInjectionDetector.detect_command_injection(
                        response.text, response.status_code, payload
                    ):
                        result = {
                            'vulnerability': True,
                            'type': 'Command Injection',
                            'severity': 'Critical',
                            'url': url,
                            'parameter': param_name,
                            'payload': payload,
                            'evidence': CommandInjectionDetector.get_evidence(payload, response.text),
                            'description': 'Command Injection vulnerability detected',
                            'scanner': self.name
                        }

                        metadata = self.payload_loader.get_vulnerability_metadata('commandinjection', 'Critical')
                        result.update(metadata)

                        results.append(result)
                        logger.info(f"Command Injection found: {url} (parameter: {param_name})")
                        break

        return results

    def _scan_ldap_injection(self, targets: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Scan for LDAP injection"""
        if not LDAPInjectionDetector:
            return []
        logger.info("Scanning for LDAP injection vulnerabilities")
        return []  # Simplified for now

    def _scan_nosql_injection(self, targets: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Scan for NoSQL injection"""
        if not NoSQLInjectionDetector:
            return []
        logger.info("Scanning for NoSQL injection vulnerabilities")
        return []  # Simplified for now

    def _scan_ssti(self, targets: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Scan for Server-Side Template Injection"""
        if not SSTIDetector:
            return []
        logger.info("Scanning for SSTI vulnerabilities")
        return []  # Simplified for now

    def _scan_xxe(self, targets: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Scan for XXE"""
        if not XXEDetector:
            return []
        logger.info("Scanning for XXE vulnerabilities")
        return []  # Simplified for now

    def _scan_crlf(self, targets: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Scan for CRLF injection"""
        if not CRLFDetector:
            return []
        logger.info("Scanning for CRLF injection vulnerabilities")
        return []  # Simplified for now

    def _scan_text_injection(self, targets: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Scan for text injection"""
        if not TextInjectionDetector:
            return []
        logger.info("Scanning for text injection vulnerabilities")
        return []  # Simplified for now

    def _scan_html_injection(self, targets: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Scan for HTML injection"""
        if not HTMLInjectionDetector:
            return []
        logger.info("Scanning for HTML injection vulnerabilities")
        return []  # Simplified for now
