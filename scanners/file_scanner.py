"""
Scanner for file-related vulnerabilities (LFI, RFI, Path Traversal, etc.)
"""

from typing import List, Dict, Any
from core.base_scanner import BaseScanner
from core.logger import get_logger
from utils.payload_loader import PayloadLoader
from libs.false_positive_filter import FalsePositiveFilter

# Import detectors
try:
    from detectors.lfi_detector import LFIDetector
    from detectors.rfi_detector import RFIDetector
    from detectors.directory_traversal_detector import DirectoryTraversalDetector
    from detectors.path_traversal_detector import PathTraversalDetector
    from detectors.file_inclusion_detector import FileInclusionDetector
except ImportError as e:
    print(f"Warning: Could not import file detectors: {e}")
    LFIDetector = None
    RFIDetector = None
    DirectoryTraversalDetector = None
    PathTraversalDetector = None
    FileInclusionDetector = None

logger = get_logger(__name__)


class FileScanner(BaseScanner):
    """Scanner for file-related vulnerabilities"""

    def __init__(self, http_client, config=None):
        """Initialize file scanner"""
        super().__init__(http_client, config)
        self.payload_loader = PayloadLoader()
        self.fp_filter = FalsePositiveFilter()

        # Enabled modules
        self.enabled_modules = set()
        if config and hasattr(config, 'modules'):
            self.enabled_modules = set(config.modules)

    def scan(self, targets: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Scan for file vulnerabilities

        Args:
            targets: List of URLs with parameters

        Returns:
            List of results
        """
        logger.info(f"Starting file scanner on {len(targets)} targets")
        results = []

        # Scan for each type
        if 'lfi' in self.enabled_modules:
            results.extend(self._scan_lfi(targets))
        if 'rfi' in self.enabled_modules:
            results.extend(self._scan_rfi(targets))
        if 'dirtraversal' in self.enabled_modules or 'pathtraversal' in self.enabled_modules:
            results.extend(self._scan_path_traversal(targets))

        logger.info(f"File scanner found {len(results)} results")
        return results

    def _scan_lfi(self, targets: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Scan for Local File Inclusion"""
        if not LFIDetector:
            logger.warning("LFIDetector not available")
            return []

        logger.info("Scanning for LFI vulnerabilities")
        results = []
        payloads = self.payload_loader.load_payloads('lfi')

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

                    # Detect LFI
                    detected, evidence = LFIDetector.detect_lfi(
                        response.text, response.status_code
                    )

                    if detected:
                        # Filter false positives
                        if self.fp_filter.is_false_positive('lfi', {
                            'payload': payload,
                            'response': response.text,
                            'url': url,
                            'parameter': param_name
                        }):
                            continue

                        result = {
                            'vulnerability': True,
                            'type': 'LFI',
                            'severity': 'High',
                            'url': url,
                            'parameter': param_name,
                            'payload': payload,
                            'evidence': evidence,
                            'description': 'Local File Inclusion vulnerability detected',
                            'scanner': self.name
                        }

                        # Add metadata
                        metadata = self.payload_loader.get_vulnerability_metadata('lfi', 'High')
                        result.update(metadata)

                        results.append(result)
                        logger.info(f"LFI found: {url} (parameter: {param_name})")
                        break  # Move to next parameter

        return results

    def _scan_rfi(self, targets: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Scan for Remote File Inclusion"""
        if not RFIDetector:
            logger.warning("RFIDetector not available")
            return []

        logger.info("Scanning for RFI vulnerabilities")
        results = []
        payloads = self.payload_loader.load_payloads('rfi')

        for target in targets:
            if self.should_stop():
                break

            url = target.get('url')
            params = target.get('params', {})

            for param_name in params:
                for payload in payloads[:10]:  # Limit RFI payloads more strictly
                    if self.should_stop():
                        break

                    test_params = params.copy()
                    test_params[param_name] = payload

                    response = self.http_client.get(url, params=test_params)
                    if not response:
                        continue

                    if RFIDetector.detect_rfi(response.text, response.status_code, payload):
                        result = {
                            'vulnerability': True,
                            'type': 'RFI',
                            'severity': 'Critical',
                            'url': url,
                            'parameter': param_name,
                            'payload': payload,
                            'evidence': 'Remote file inclusion detected',
                            'description': 'Remote File Inclusion vulnerability detected',
                            'scanner': self.name
                        }

                        metadata = self.payload_loader.get_vulnerability_metadata('rfi', 'Critical')
                        result.update(metadata)

                        results.append(result)
                        logger.info(f"RFI found: {url} (parameter: {param_name})")
                        break

        return results

    def _scan_path_traversal(self, targets: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Scan for Path Traversal"""
        if not PathTraversalDetector and not DirectoryTraversalDetector:
            logger.warning("Path traversal detectors not available")
            return []

        logger.info("Scanning for path traversal vulnerabilities")
        results = []
        payloads = self.payload_loader.load_payloads('directory_traversal')

        for target in targets:
            if self.should_stop():
                break

            url = target.get('url')
            params = target.get('params', {})

            for param_name in params:
                for payload in payloads[:15]:
                    if self.should_stop():
                        break

                    test_params = params.copy()
                    test_params[param_name] = payload

                    response = self.http_client.get(url, params=test_params)
                    if not response:
                        continue

                    # Use whichever detector is available
                    detector = PathTraversalDetector or DirectoryTraversalDetector
                    detected = False

                    if PathTraversalDetector:
                        detected = PathTraversalDetector.detect_path_traversal(
                            response.text, response.status_code, payload
                        )
                    elif DirectoryTraversalDetector:
                        detected = DirectoryTraversalDetector.detect_directory_traversal(
                            response.text, response.status_code, payload
                        )

                    if detected:
                        result = {
                            'vulnerability': True,
                            'type': 'Path Traversal',
                            'severity': 'High',
                            'url': url,
                            'parameter': param_name,
                            'payload': payload,
                            'evidence': 'Path traversal indicators detected',
                            'description': 'Path Traversal vulnerability detected',
                            'scanner': self.name
                        }

                        metadata = self.payload_loader.get_vulnerability_metadata('pathtraversal', 'High')
                        result.update(metadata)

                        results.append(result)
                        logger.info(f"Path Traversal found: {url} (parameter: {param_name})")
                        break

        return results
