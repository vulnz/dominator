"""
Scanner for configuration and infrastructure issues (DirBrute, Git, PHPInfo, etc.)
"""

from typing import List, Dict, Any
from urllib.parse import urljoin
from core.base_scanner import BaseScanner
from core.logger import get_logger
from utils.payload_loader import PayloadLoader

# Import detectors
try:
    from detectors.dirbrute_detector import DirBruteDetector
    from detectors.real404_detector import Real404Detector
    from detectors.git_detector import GitDetector
    from detectors.env_detector import EnvDetector
    from detectors.phpinfo_detector import PHPInfoDetector
    from detectors.backup_finder_detector import BackupFinderDetector
    from detectors.security_headers_detector import SecurityHeadersDetector
    from detectors.ssl_tls_detector import SSLTLSDetector
except ImportError as e:
    print(f"Warning: Could not import config detectors: {e}")
    DirBruteDetector = None
    Real404Detector = None
    GitDetector = None
    EnvDetector = None
    PHPInfoDetector = None
    BackupFinderDetector = None
    SecurityHeadersDetector = None
    SSLTLSDetector = None

logger = get_logger(__name__)


class ConfigScanner(BaseScanner):
    """Scanner for configuration and infrastructure vulnerabilities"""

    def __init__(self, http_client, config=None):
        """Initialize config scanner"""
        super().__init__(http_client, config)
        self.payload_loader = PayloadLoader()

        # Enabled modules
        self.enabled_modules = set()
        if config and hasattr(config, 'modules'):
            self.enabled_modules = set(config.modules)

    def scan(self, targets: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Scan for configuration issues

        Args:
            targets: List of URLs

        Returns:
            List of results
        """
        logger.info(f"Starting config scanner on {len(targets)} targets")
        results = []

        # Extract base URLs from targets
        base_urls = list(set([self._get_base_url(t.get('url')) for t in targets if t.get('url')]))

        # Scan for each type
        if 'dirbrute' in self.enabled_modules:
            results.extend(self._scan_directories(base_urls))
        if 'git' in self.enabled_modules:
            results.extend(self._scan_git_exposure(base_urls))
        if 'phpinfo' in self.enabled_modules:
            results.extend(self._scan_phpinfo(base_urls))
        if 'secheaders' in self.enabled_modules:
            results.extend(self._scan_security_headers(base_urls))
        if 'ssltls' in self.enabled_modules:
            results.extend(self._scan_ssl_tls(base_urls))

        logger.info(f"Config scanner found {len(results)} results")
        return results

    def _get_base_url(self, url: str) -> str:
        """Extract base URL from full URL"""
        from urllib.parse import urlparse
        parsed = urlparse(url)
        return f"{parsed.scheme}://{parsed.netloc}"

    def _scan_directories(self, base_urls: List[str]) -> List[Dict[str, Any]]:
        """Scan for accessible directories"""
        if not DirBruteDetector or not Real404Detector:
            logger.warning("DirBruteDetector not available")
            return []

        logger.info("Scanning for accessible directories")
        results = []

        # Load directory wordlist
        wordlist = self.payload_loader.load_payloads('common_directories')
        if not wordlist:
            logger.warning("No directory wordlist available")
            return []

        for base_url in base_urls:
            if self.should_stop():
                break

            # Generate baseline 404
            baseline_404, baseline_size = Real404Detector.generate_baseline_404(
                base_url, session=self.http_client.session
            )

            # Test directories
            for directory in wordlist[:100]:  # Limit to first 100 directories
                if self.should_stop():
                    break

                test_url = urljoin(base_url, directory.strip('/') + '/')

                response = self.http_client.get(test_url, allow_redirects=False)
                if not response:
                    continue

                # Check if it's a valid response
                is_valid, reason = DirBruteDetector.is_valid_response(
                    response.text,
                    response.status_code,
                    response.content_length,
                    baseline_404,
                    baseline_size
                )

                if is_valid:
                    result = {
                        'vulnerability': True,
                        'type': 'Directory Listing',
                        'severity': 'Medium',
                        'url': test_url,
                        'evidence': reason,
                        'description': f'Accessible directory found: {directory}',
                        'scanner': self.name
                    }

                    metadata = self.payload_loader.get_vulnerability_metadata('dirbrute', 'Medium')
                    result.update(metadata)

                    results.append(result)
                    logger.info(f"Directory found: {test_url}")

        return results

    def _scan_git_exposure(self, base_urls: List[str]) -> List[Dict[str, Any]]:
        """Scan for exposed .git directories"""
        if not GitDetector:
            logger.warning("GitDetector not available")
            return []

        logger.info("Scanning for Git exposure")
        results = []

        git_paths = ['.git/', '.git/config', '.git/HEAD', '.git/index']

        for base_url in base_urls:
            if self.should_stop():
                break

            for git_path in git_paths:
                if self.should_stop():
                    break

                test_url = urljoin(base_url, git_path)

                response = self.http_client.get(test_url)
                if not response:
                    continue

                # Detect git exposure
                detected, evidence, severity = GitDetector.detect_git_exposure(
                    response.text, response.status_code, test_url
                )

                if detected:
                    result = {
                        'vulnerability': True,
                        'type': 'Git Exposure',
                        'severity': severity,
                        'url': test_url,
                        'evidence': evidence,
                        'description': 'Exposed .git directory allows source code disclosure',
                        'scanner': self.name
                    }

                    metadata = self.payload_loader.get_vulnerability_metadata('git', severity)
                    result.update(metadata)

                    results.append(result)
                    logger.info(f"Git exposure found: {test_url}")
                    break  # Don't test other paths if one is found

        return results

    def _scan_phpinfo(self, base_urls: List[str]) -> List[Dict[str, Any]]:
        """Scan for PHPInfo exposure"""
        if not PHPInfoDetector:
            logger.warning("PHPInfoDetector not available")
            return []

        logger.info("Scanning for PHPInfo exposure")
        results = []

        phpinfo_paths = ['phpinfo.php', 'info.php', 'test.php', 'php.php']

        for base_url in base_urls:
            if self.should_stop():
                break

            for path in phpinfo_paths:
                if self.should_stop():
                    break

                test_url = urljoin(base_url, path)

                response = self.http_client.get(test_url)
                if not response:
                    continue

                detected, evidence, severity = PHPInfoDetector.detect_phpinfo_exposure(
                    response.text, response.status_code, test_url
                )

                if detected:
                    result = {
                        'vulnerability': True,
                        'type': 'PHPInfo Exposure',
                        'severity': severity,
                        'url': test_url,
                        'evidence': evidence,
                        'description': 'PHPInfo page exposes sensitive server information',
                        'scanner': self.name
                    }

                    metadata = self.payload_loader.get_vulnerability_metadata('phpinfo', severity)
                    result.update(metadata)

                    results.append(result)
                    logger.info(f"PHPInfo found: {test_url}")
                    break

        return results

    def _scan_security_headers(self, base_urls: List[str]) -> List[Dict[str, Any]]:
        """Scan for missing security headers"""
        if not SecurityHeadersDetector:
            logger.warning("SecurityHeadersDetector not available")
            return []

        logger.info("Scanning for security headers")
        results = []

        for base_url in base_urls:
            if self.should_stop():
                break

            response = self.http_client.get(base_url)
            if not response:
                continue

            # Check for missing headers
            missing_headers = SecurityHeadersDetector.detect_missing_security_headers(response.headers)

            for header_info in missing_headers:
                result = {
                    'vulnerability': True,
                    'type': 'Missing Security Header',
                    'severity': header_info.get('severity', 'Low'),
                    'url': base_url,
                    'evidence': header_info.get('header', ''),
                    'description': header_info.get('description', 'Security header missing'),
                    'scanner': self.name
                }

                metadata = self.payload_loader.get_vulnerability_metadata('secheaders', 'Low')
                result.update(metadata)

                results.append(result)

            # Check for insecure cookies
            insecure_cookies = SecurityHeadersDetector.detect_insecure_cookies(response.headers)
            for cookie_info in insecure_cookies:
                result = {
                    'vulnerability': True,
                    'type': 'Insecure Cookie',
                    'severity': cookie_info.get('severity', 'Medium'),
                    'url': base_url,
                    'evidence': cookie_info.get('cookie', ''),
                    'description': cookie_info.get('description', 'Cookie missing security flags'),
                    'scanner': self.name
                }

                results.append(result)

        return results

    def _scan_ssl_tls(self, base_urls: List[str]) -> List[Dict[str, Any]]:
        """Scan for SSL/TLS issues"""
        if not SSLTLSDetector:
            logger.warning("SSLTLSDetector not available")
            return []

        logger.info("Scanning for SSL/TLS issues")
        results = []

        for base_url in base_urls:
            if self.should_stop():
                break

            # Only check HTTPS URLs
            if not base_url.startswith('https://'):
                continue

            detected, evidence, severity, details = SSLTLSDetector.detect_ssl_tls_implementation(base_url)

            if detected and severity != 'Info':
                result = {
                    'vulnerability': True,
                    'type': 'SSL/TLS Issue',
                    'severity': severity,
                    'url': base_url,
                    'evidence': evidence,
                    'description': 'SSL/TLS configuration issue detected',
                    'scanner': self.name,
                    'details': details
                }

                metadata = self.payload_loader.get_vulnerability_metadata('ssltls', severity)
                result.update(metadata)

                results.append(result)

        return results
