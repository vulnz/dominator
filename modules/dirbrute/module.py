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

        # Real 404 detection - cache baseline responses per base URL
        self.baseline_404_responses = {}  # {base_url: {'status': int, 'size': int, 'content_hash': str}}

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

            # Also add directory paths (but skip files)
            path = parsed.path.rstrip('/')
            if not path:
                continue

            path_parts = path.split('/')

            # Check if last part is a file (has extension like .php, .html, etc.)
            last_part = path_parts[-1] if path_parts else ''
            is_file = '.' in last_part and not last_part.startswith('.')

            # If it's a file, only add parent directories
            # If it's a directory, add it and all parent directories
            max_depth = len(path_parts) - 1 if is_file else len(path_parts)

            for i in range(1, max_depth + 1):
                dir_path = '/'.join(path_parts[:i]) + '/'
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

    def _establish_404_baseline(self, base_url: str, http_client: Any) -> Dict[str, Any]:
        """
        Establish baseline for fake 404 (Real 404) detection

        Tests multiple non-existent random paths to identify how the server responds to 404s.
        Some servers return 200 with same content for ALL paths (even non-existent).

        Args:
            base_url: Base URL to test
            http_client: HTTP client

        Returns:
            Baseline dictionary with status, size, and content hash
        """
        import hashlib
        import random
        import string

        # Generate 3 random non-existent paths
        random_paths = []
        for _ in range(3):
            random_str = ''.join(random.choices(string.ascii_lowercase + string.digits, k=32))
            random_paths.append(f"nonexistent_{random_str}.html")

        responses = []
        for random_path in random_paths:
            try:
                test_url = urljoin(base_url, random_path)
                response = http_client.get(test_url, allow_redirects=False)
                if response:
                    resp_text = getattr(response, 'text', '')
                    resp_hash = hashlib.md5(resp_text.encode()).hexdigest()
                    responses.append({
                        'status': response.status_code,
                        'size': len(resp_text),
                        'hash': resp_hash
                    })
            except Exception as e:
                logger.debug(f"Error establishing 404 baseline: {e}")
                continue

        if not responses:
            return None

        # Check if all responses are identical (classic sign of fake 404)
        first_resp = responses[0]
        all_identical = all(
            r['status'] == first_resp['status'] and
            r['size'] == first_resp['size'] and
            r['hash'] == first_resp['hash']
            for r in responses
        )

        if all_identical and first_resp['status'] == 200:
            logger.info(f"[REAL 404 DETECTED] {base_url} returns HTTP 200 for non-existent paths (size: {first_resp['size']} bytes)")
            return first_resp

        return None

    def _is_fake_404(self, response: Any, base_url: str) -> bool:
        """
        Check if response is a fake 404 (server returns 200 but page doesn't exist)

        Args:
            response: Response object
            base_url: Base URL being tested

        Returns:
            True if this is a fake 404, False if it's a real finding
        """
        import hashlib

        if base_url not in self.baseline_404_responses:
            return False

        baseline = self.baseline_404_responses[base_url]
        if not baseline:
            return False

        # Check if response matches the baseline
        resp_text = getattr(response, 'text', '')
        resp_hash = hashlib.md5(resp_text.encode()).hexdigest()
        resp_size = len(resp_text)

        # If status, size, and hash all match baseline, it's a fake 404
        if (response.status_code == baseline['status'] and
            resp_size == baseline['size'] and
            resp_hash == baseline['hash']):
            return True

        # Also check size similarity (within 5% tolerance for dynamic content)
        if response.status_code == baseline['status']:
            size_diff_percent = abs(resp_size - baseline['size']) / max(baseline['size'], 1) * 100
            if size_diff_percent < 5:
                return True

        return False

    def _brute_force_url(self, base_url: str, http_client: Any) -> List[Dict[str, Any]]:
        """
        Brute force a single base URL

        Args:
            base_url: Base URL to test
            http_client: HTTP client

        Returns:
            List of found paths with metadata
        """
        # Establish 404 baseline for this base URL
        baseline = self._establish_404_baseline(base_url, http_client)
        if baseline:
            self.baseline_404_responses[base_url] = baseline
        else:
            self.baseline_404_responses[base_url] = None

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
                        # CRITICAL: Check for fake 404 (Real 404 detection)
                        if self._is_fake_404(response, base_url):
                            logger.debug(f"✗ Fake 404: {test_path} (matches baseline)")
                            continue

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

        # ANTI-FALSE-POSITIVE: Filter invalid extension combinations for HTTP 403
        # .htaccess is Apache-only, .htaccess.php/.asp/.jsp are invalid combinations
        # Same for .htpasswd, web.config (IIS-only), etc.
        if status_code == 403:
            invalid_combinations = [
                # Apache files with wrong extensions
                ('.htaccess', ['.php', '.asp', '.aspx', '.jsp', '.html', '.txt']),
                ('.htpasswd', ['.php', '.asp', '.aspx', '.jsp', '.html', '.txt']),
                # IIS files with Apache extensions
                ('web.config', ['.php', '.bak', '.old']),
                # Git/SVN with extensions
                ('.git', ['.php', '.asp', '.aspx', '.jsp', '.html']),
                ('.svn', ['.php', '.asp', '.aspx', '.jsp', '.html']),
            ]

            for base_file, invalid_exts in invalid_combinations:
                if base_file in path_lower:
                    for invalid_ext in invalid_exts:
                        if path_lower.endswith(invalid_ext):
                            # This is likely a false positive - Apache returns 403 for ANY .htaccess* request
                            confidence = 0.3  # Very low confidence
                            logger.debug(f"[FALSE POSITIVE] Invalid combination: {base_file}{invalid_ext} (HTTP 403)")
                            break

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
