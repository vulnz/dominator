"""
Backup Files Scanner Module (Nikto/Wapiti-style)

Discovers backup and sensitive files that may expose source code:
- Backup extensions: .bak, .old, .backup, .orig, ~, .copy
- Archive files: .zip, .tar, .gz, .7z, .rar
- Source control: .svn, .git, .hg
- IDE files: .swp, .swo, .swn (vim), .idea
- Configuration: .conf, .config, .ini, web.config.old
- Database dumps: .sql, .dump, .db

Based on Nikto and OWASP Testing Guide.
"""

from typing import List, Dict, Any
from core.base_module import BaseModule
from core.logger import get_logger
from detectors.real404_detector import Real404Detector
from urllib.parse import urlparse, urljoin
import os

logger = get_logger(__name__)


class BackupFilesModule(BaseModule):
    """Backup and sensitive files scanner"""

    # Backup extensions to test
    BACKUP_EXTENSIONS = [
        '.bak', '.backup', '.old', '.orig', '.save', '.saved',
        '.copy', '.tmp', '.temp', '~', '.1', '.2',
        '.bkp', '.bck', '.back', '_backup', '-backup',
        '.swp', '.swo', '.swn',  # Vim swap files
    ]

    # Archive extensions
    ARCHIVE_EXTENSIONS = [
        '.zip', '.tar', '.tar.gz', '.tgz', '.gz', '.bz2',
        '.rar', '.7z', '.cab', '.war', '.jar', '.ear',
    ]

    # Sensitive files to check directly
    SENSITIVE_FILES = [
        # Source control
        '/.git/config', '/.git/HEAD', '/.git/index',
        '/.svn/entries', '/.svn/wc.db',
        '/.hg/hgrc', '/.hg/store',
        '/.bzr/README', '/.bzr/branch-format',

        # Configuration files
        '/web.config', '/web.config.bak', '/web.config.old',
        '/wp-config.php', '/wp-config.php.bak',
        '/config.php', '/config.php.bak', '/config.inc.php',
        '/configuration.php', '/settings.php', '/database.php',
        '/.htaccess', '/.htpasswd',
        '/php.ini', '/php.ini.bak',
        '/.env', '/.env.local', '/.env.production', '/.env.backup',

        # Database dumps
        '/database.sql', '/db.sql', '/backup.sql', '/dump.sql',
        '/mysql.sql', '/data.sql', '/export.sql',
        '/database.db', '/database.sqlite', '/data.db',

        # IDE/Editor files
        '/.idea/workspace.xml', '/.vscode/settings.json',
        '/nbproject/project.properties',
        '/.project', '/.classpath',

        # Log files
        '/debug.log', '/error.log', '/access.log',
        '/app.log', '/application.log',

        # Backup archives
        '/backup.zip', '/backup.tar.gz', '/site.zip', '/www.zip',
        '/html.zip', '/public_html.zip', '/htdocs.zip',
        '/website.zip', '/webroot.zip', '/source.zip',
    ]

    def __init__(self, module_path: str, payload_limit: int = None):
        """Initialize Backup Files module"""
        super().__init__(module_path, payload_limit=payload_limit)
        # FIXED: Initialize Real404Detector to prevent false positives
        self.real404_detector = Real404Detector()
        logger.info("Backup Files module loaded")

    def scan(self, targets: List[Dict[str, Any]], http_client: Any) -> List[Dict[str, Any]]:
        """
        Scan targets for backup and sensitive files

        Args:
            targets: List of URLs to scan
            http_client: HTTP client

        Returns:
            List of findings
        """
        results = []
        scanned_hosts = set()
        scanned_paths = set()

        logger.info(f"Starting Backup Files scan on {len(targets)} targets")

        for target in targets:
            url = target.get('url', '')

            # Extract base URL and path
            parsed = urlparse(url)
            base_url = f"{parsed.scheme}://{parsed.netloc}"
            host = parsed.netloc

            # Scan host-level sensitive files once
            if host not in scanned_hosts:
                scanned_hosts.add(host)
                # FIXED: Generate 404 baseline to prevent false positives
                logger.debug(f"Generating 404 baseline for {base_url}")
                self.real404_detector.generate_baseline(base_url, http_client)

                sensitive_results = self._scan_sensitive_files(base_url, http_client)
                results.extend(sensitive_results)

            # Scan for backup versions of discovered files
            if parsed.path and parsed.path not in scanned_paths:
                scanned_paths.add(parsed.path)

                # Only check files with extensions (not directories)
                if '.' in os.path.basename(parsed.path):
                    backup_results = self._scan_backup_versions(base_url, parsed.path, http_client)
                    results.extend(backup_results)

        logger.info(f"Backup Files scan complete: {len(results)} files found")
        return results

    def _scan_sensitive_files(self, base_url: str, http_client: Any) -> List[Dict]:
        """Scan for sensitive files at the root and common paths"""
        results = []

        for sensitive_path in self.SENSITIVE_FILES:
            test_url = urljoin(base_url, sensitive_path)

            try:
                response = http_client.get(test_url)

                if response and self._is_file_found(response, sensitive_path):
                    severity = self._get_severity(sensitive_path)
                    result = self.create_result(
                        vulnerable=True,
                        url=test_url,
                        parameter='Sensitive File',
                        payload=sensitive_path,
                        evidence=self._generate_evidence(response, sensitive_path),
                        description=f"Sensitive file exposed: {sensitive_path}",
                        confidence=0.95
                    )
                    result['severity'] = severity
                    result['cwe'] = 'CWE-538'
                    result['owasp'] = 'A05:2021'
                    results.append(result)
                    logger.info(f"Found sensitive file: {test_url}")

            except Exception as e:
                logger.debug(f"Error checking {test_url}: {e}")

        return results

    def _scan_backup_versions(self, base_url: str, path: str, http_client: Any) -> List[Dict]:
        """Scan for backup versions of a specific file"""
        results = []

        # Generate backup file paths
        filename = os.path.basename(path)
        directory = os.path.dirname(path)

        backup_paths = []

        # Add backup extension variants
        for ext in self.BACKUP_EXTENSIONS:
            backup_paths.append(f"{path}{ext}")
            backup_paths.append(f"{directory}/{filename}{ext}")

            # Replace extension with backup extension
            if '.' in filename:
                name_without_ext = filename.rsplit('.', 1)[0]
                original_ext = filename.rsplit('.', 1)[1]
                backup_paths.append(f"{directory}/{name_without_ext}{ext}.{original_ext}")
                backup_paths.append(f"{directory}/{name_without_ext}.{original_ext}{ext}")

        # Add archive variants
        for ext in self.ARCHIVE_EXTENSIONS:
            backup_paths.append(f"{path}{ext}")

        # Test unique paths only
        for backup_path in set(backup_paths):
            test_url = urljoin(base_url, backup_path)

            try:
                response = http_client.get(test_url)

                if response and self._is_file_found(response, backup_path):
                    result = self.create_result(
                        vulnerable=True,
                        url=test_url,
                        parameter='Backup File',
                        payload=backup_path,
                        evidence=self._generate_evidence(response, backup_path),
                        description=f"Backup file exposed: {backup_path}",
                        confidence=0.90
                    )
                    result['severity'] = 'medium'
                    result['cwe'] = 'CWE-538'
                    result['owasp'] = 'A05:2021'
                    results.append(result)
                    logger.info(f"Found backup file: {test_url}")

            except Exception as e:
                logger.debug(f"Error checking {test_url}: {e}")

        return results

    def _is_file_found(self, response: Any, path: str) -> bool:
        """Check if response indicates a valid file"""
        if not response:
            return False

        # FIXED: Use Real404Detector instead of weak soft 404 detection
        # This provides multi-language support, baseline fingerprinting, and better accuracy
        if self.real404_detector.is_404(response, path):
            return False

        # Additional validation for specific file types
        response_text = getattr(response, 'text', '').lower()
        if path.endswith('.git/config'):
            return '[core]' in response_text or '[remote' in response_text
        if path.endswith('.env'):
            return '=' in response_text and not '<html' in response_text
        if path.endswith('.sql'):
            return 'insert into' in response_text or 'create table' in response_text
        if path.endswith('.htpasswd'):
            return ':' in response_text and len(response_text) < 10000

        return True

    def _get_severity(self, path: str) -> str:
        """Determine severity based on file type"""
        high_risk = ['.git', '.svn', '.env', 'config.php', 'wp-config', 'database', '.sql']
        medium_risk = ['.htaccess', '.htpasswd', '.bak', '.backup', 'web.config']

        path_lower = path.lower()

        for pattern in high_risk:
            if pattern in path_lower:
                return 'high'

        for pattern in medium_risk:
            if pattern in path_lower:
                return 'medium'

        return 'low'

    def _generate_evidence(self, response: Any, path: str) -> str:
        """Generate evidence string"""
        response_text = getattr(response, 'text', '')
        content_type = response.headers.get('Content-Type', 'unknown')

        evidence = f"Backup/Sensitive file found!\n\n"
        evidence += f"Path: {path}\n"
        evidence += f"Status: {response.status_code}\n"
        evidence += f"Content-Type: {content_type}\n"
        evidence += f"Content-Length: {len(response_text)} bytes\n\n"

        # Show preview (first 500 chars)
        preview = response_text[:500].replace('\n', '\\n')
        evidence += f"Preview:\n{preview}"

        if len(response_text) > 500:
            evidence += "\n... (truncated)"

        return evidence


def get_module(module_path: str, payload_limit: int = None):
    """Create module instance"""
    return BackupFilesModule(module_path, payload_limit=payload_limit)
