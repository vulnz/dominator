"""
Directory Brute Force Scanner Module

Discovers hidden directories and files through brute force by:
1. Extracting base URLs from discovered targets
2. Testing common directory and file names
3. Detecting interesting HTTP status codes (200, 301, 302, 401, 403)
4. Testing with common file extensions (.php, .txt, .bak, etc.)
5. Identifying sensitive files and backup files
"""

from typing import List, Dict, Any
from core.base_module import BaseModule
from core.logger import get_logger
from urllib.parse import urlparse, urljoin
import concurrent.futures
import time

logger = get_logger(__name__)


class DirectoryBruteForceModule(BaseModule):
    """Directory Brute Force scanner module"""

    def __init__(self, module_path: str):
        """Initialize Directory Brute Force module"""
        super().__init__(module_path)

        # Interesting status codes that indicate something exists
        self.interesting_codes = self.config.get('interesting_status_codes', [200, 301, 302, 401, 403])
        self.max_threads = self.config.get('max_threads', 10)
        self.interesting_extensions = self.config.get('interesting_extensions', ['', '.php', '.txt', '.bak'])

        logger.info(f"Directory Brute Force module loaded: {len(self.payloads)} paths, "
                   f"{len(self.interesting_extensions)} extensions")

    def scan(self, targets: List[Dict[str, Any]], http_client: Any) -> List[Dict[str, Any]]:
        """
        Scan for hidden directories and files

        Args:
            targets: List of URLs with parameters
            http_client: HTTP client

        Returns:
            List of results
        """
        results = []

        logger.info(f"Starting Directory Brute Force scan")

        # Extract unique base URLs
        base_urls = set()
        for target in targets:
            url = target.get('url')
            if not url:
                continue

            # Parse URL to get base
            parsed = urlparse(url)
            base_url = f"{parsed.scheme}://{parsed.netloc}/"
            base_urls.add(base_url)

            # Also add directory paths
            path_parts = parsed.path.rstrip('/').split('/')
            for i in range(1, len(path_parts)):
                dir_path = '/'.join(path_parts[:i+1]) + '/'
                dir_url = f"{parsed.scheme}://{parsed.netloc}{dir_path}"
                base_urls.add(dir_url)

        logger.info(f"Testing {len(base_urls)} base URLs")

        # Test each base URL
        for base_url in list(base_urls)[:10]:  # Limit to 10 base URLs
            logger.info(f"Brute forcing: {base_url}")

            # Test paths
            found_paths = self._brute_force_url(base_url, http_client)

            for path_info in found_paths:
                result = self.create_result(
                    vulnerable=True,
                    url=path_info['url'],
                    payload=path_info['path'],
                    evidence=path_info['evidence'],
                    description=path_info['description'],
                    confidence=path_info['confidence']
                )

                # Add metadata
                result['cwe'] = self.config.get('cwe', 'CWE-425')
                result['owasp'] = self.config.get('owasp', 'A01:2021')
                result['cvss'] = self.config.get('cvss', '5.3')
                result['status_code'] = path_info['status_code']

                results.append(result)

        logger.info(f"Directory Brute Force scan complete: {len(results)} paths found")
        return results

    def _brute_force_url(self, base_url: str, http_client: Any) -> List[Dict[str, Any]]:
        """
        Brute force a single base URL

        Args:
            base_url: Base URL to test
            http_client: HTTP client

        Returns:
            List of found paths with metadata
        """
        found_paths = []
        tested = 0
        start_time = time.time()

        # Limit paths to test (to avoid too many requests)
        paths_to_test = self.payloads[:100]  # Test first 100 paths

        logger.debug(f"Testing {len(paths_to_test)} paths against {base_url}")

        for path in paths_to_test:
            # Test with different extensions
            for ext in self.interesting_extensions[:5]:  # Limit extensions
                test_path = path + ext
                test_url = urljoin(base_url, test_path)

                tested += 1

                # Rate limiting - don't test too fast
                if tested % 10 == 0:
                    elapsed = time.time() - start_time
                    if elapsed < 1.0:
                        time.sleep(0.1)
                    start_time = time.time()

                try:
                    response = http_client.get(test_url, allow_redirects=False)

                    if not response:
                        continue

                    status_code = response.status_code

                    # Check if status code is interesting
                    if status_code in self.interesting_codes:
                        # Analyze the finding
                        confidence, severity, description = self._analyze_finding(
                            test_path, status_code, response
                        )

                        if confidence > 0.5:  # Only report if confidence is good
                            evidence = f"HTTP {status_code}: {test_path}"

                            # Add response size
                            response_size = len(getattr(response, 'text', ''))
                            evidence += f" ({response_size} bytes)"

                            # Check for redirects
                            if status_code in [301, 302]:
                                location = response.headers.get('Location', '')
                                if location:
                                    evidence += f" -> {location}"

                            found_paths.append({
                                'url': test_url,
                                'path': test_path,
                                'status_code': status_code,
                                'evidence': evidence,
                                'description': description,
                                'confidence': confidence,
                                'severity': severity
                            })

                            logger.info(f"✓ Found: {test_url} (HTTP {status_code})")

                except Exception as e:
                    logger.debug(f"Error testing {test_url}: {e}")
                    continue

        return found_paths

    def _analyze_finding(self, path: str, status_code: int, response: Any) -> tuple:
        """
        Analyze a found path to determine significance

        Args:
            path: Path found
            status_code: HTTP status code
            response: Response object

        Returns:
            (confidence: float, severity: str, description: str)
        """
        path_lower = path.lower()
        confidence = 0.6  # Base confidence
        severity = self.config.get('severity', 'Medium')
        description = f"Discovered path: {path}"

        # HIGH RISK PATHS
        high_risk_patterns = [
            'admin', 'administrator', 'cpanel', 'phpmyadmin', 'pma',
            '.git/', '.svn/', '.env', 'config.php', 'web.config',
            'backup', '.bak', '.old', '.sql', 'database',
            'shell', 'phpinfo', 'test.php', 'upload'
        ]

        for pattern in high_risk_patterns:
            if pattern in path_lower:
                confidence = 0.9
                severity = 'High'
                description = f"HIGH RISK: Discovered sensitive path '{path}'. "
                description += "This may expose administrative interfaces, configuration files, or backups."
                break

        # MEDIUM RISK PATHS
        medium_risk_patterns = [
            'login', 'auth', 'api', 'swagger', 'debug', 'dev',
            'staging', 'test', 'tmp', 'logs', 'backup'
        ]

        if confidence < 0.9:  # If not already high risk
            for pattern in medium_risk_patterns:
                if pattern in path_lower:
                    confidence = 0.8
                    severity = 'Medium'
                    description = f"Discovered potentially sensitive path '{path}'. "
                    description += "This may expose sensitive functionality or information."
                    break

        # Increase confidence based on status code
        if status_code == 200:
            confidence += 0.1
            description += " Path is accessible (HTTP 200)."
        elif status_code in [401, 403]:
            confidence += 0.05
            description += f" Path exists but access is restricted (HTTP {status_code})."
        elif status_code in [301, 302]:
            description += f" Path redirects (HTTP {status_code})."

        # Check response content for sensitive information
        if status_code == 200:
            response_text = getattr(response, 'text', '').lower()

            sensitive_indicators = [
                'password', 'username', 'mysql', 'root', 'admin',
                'phpinfo()', 'php version', 'sql error', 'stack trace'
            ]

            for indicator in sensitive_indicators:
                if indicator in response_text:
                    confidence = min(0.95, confidence + 0.1)
                    severity = 'High'
                    description += f" Response contains sensitive keyword: '{indicator}'."
                    break

        # Cap confidence
        confidence = min(1.0, confidence)

        return confidence, severity, description


def get_module(module_path: str):
    """Create module instance"""
    return DirectoryBruteForceModule(module_path)
