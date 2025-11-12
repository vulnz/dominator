"""
Git Repository Exposure Scanner Module

Detects exposed .git directories and files by:
1. Testing common .git paths (.git/config, .git/HEAD, etc.)
2. Analyzing HTTP status codes (200, 403, 301, 302)
3. Validating git file content patterns
4. Identifying git directory listings
5. Detecting sensitive git files (config, index, logs)
"""

from typing import List, Dict, Any
from core.base_module import BaseModule
from core.logger import get_logger
from detectors.git_detector import GitDetector
from urllib.parse import urljoin, urlparse

logger = get_logger(__name__)


class GitExposureModule(BaseModule):
    """Git repository exposure scanner module"""

    def __init__(self, module_path: str):
        """Initialize Git Exposure module"""
        super().__init__(module_path)

        # Use payloads from git detector if not loaded from file
        if not self.payloads:
            self.payloads = GitDetector.get_git_test_paths()

        logger.info(f"Git Exposure module loaded: {len(self.payloads)} git paths to test")

    def scan(self, targets: List[Dict[str, Any]], http_client: Any) -> List[Dict[str, Any]]:
        """
        Scan for exposed .git directories and files

        Args:
            targets: List of URLs with parameters
            http_client: HTTP client

        Returns:
            List of results
        """
        results = []

        logger.info(f"Starting Git Exposure scan")

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
            path = parsed.path.rstrip('/')
            if not path:
                continue

            path_parts = path.split('/')

            # Check if last part is a file (has extension)
            last_part = path_parts[-1] if path_parts else ''
            is_file = '.' in last_part and not last_part.startswith('.')

            # If it's a file, only add parent directories
            # If it's a directory, add it and all parent directories
            max_depth = len(path_parts) - 1 if is_file else len(path_parts)

            for i in range(1, max_depth + 1):
                dir_path = '/'.join(path_parts[:i]) + '/'
                dir_url = f"{parsed.scheme}://{parsed.netloc}{dir_path}"
                base_urls.add(dir_url)

        logger.info(f"Testing {len(base_urls)} base URLs for .git exposure")

        # Test each base URL
        for base_url in list(base_urls)[:10]:  # Limit to 10 base URLs
            logger.debug(f"Testing .git exposure: {base_url}")

            # Test git paths
            found_git_files = self._test_git_paths(base_url, http_client)

            for git_info in found_git_files:
                result = self.create_result(
                    vulnerable=True,
                    url=git_info['url'],
                    payload=git_info['path'],
                    evidence=git_info['evidence'],
                    description=git_info['description'],
                    confidence=git_info['confidence']
                )

                # Add metadata from config
                result['cwe'] = self.config.get('cwe', 'CWE-200')
                result['owasp'] = self.config.get('owasp', 'A01:2021')
                result['cvss'] = self.config.get('cvss', '7.5')
                result['severity'] = git_info['severity']
                result['status_code'] = git_info['status_code']
                result['remediation'] = self.config.get('remediation', '')

                results.append(result)

        logger.info(f"Git Exposure scan complete: {len(results)} exposed git files found")
        return results

    def _test_git_paths(self, base_url: str, http_client: Any) -> List[Dict[str, Any]]:
        """
        Test git paths for a single base URL

        Args:
            base_url: Base URL to test
            http_client: HTTP client

        Returns:
            List of found git files with metadata
        """
        found_git_files = []

        for git_path in self.payloads:
            test_url = urljoin(base_url, git_path)

            try:
                response = http_client.get(test_url, allow_redirects=False)

                if not response:
                    continue

                status_code = response.status_code
                response_text = getattr(response, 'text', '')

                # Use GitDetector to analyze response
                is_exposed, evidence, severity = GitDetector.detect_git_exposure(
                    response_text, status_code, test_url
                )

                if is_exposed:
                    # Get detailed evidence
                    detailed_evidence = GitDetector.get_evidence(git_path, response_text)

                    # Build description
                    description = f"Git repository file exposed: {git_path}. "

                    if status_code == 403:
                        description += "Access is forbidden but the file exists. "
                    elif status_code == 200:
                        description += "File is directly accessible. "

                    description += "This exposure can leak source code, credentials, commit history, and sensitive information."

                    # Determine confidence
                    confidence = 0.85  # Base confidence for git exposure

                    if status_code == 200:
                        confidence = 0.95  # Very high confidence for accessible files
                    elif status_code == 403:
                        confidence = 0.75  # Medium-high confidence for forbidden but existing files

                    # Add remediation advice
                    remediation = GitDetector.get_remediation_advice(git_path)

                    found_git_files.append({
                        'url': test_url,
                        'path': git_path,
                        'status_code': status_code,
                        'evidence': f"{detailed_evidence} | HTTP {status_code}",
                        'description': f"{description} {remediation}",
                        'confidence': confidence,
                        'severity': severity
                    })

                    logger.info(f"✓ Git exposure found: {test_url} (HTTP {status_code}, {severity})")

            except Exception as e:
                logger.debug(f"Error testing {test_url}: {e}")
                continue

        return found_git_files


def get_module(module_path: str):
    """Create module instance"""
    return GitExposureModule(module_path)
