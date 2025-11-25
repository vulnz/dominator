"""
Robots.txt Information Disclosure Scanner
Analyzes robots.txt for sensitive paths and information leakage
"""

from core.base_module import BaseModule
from core.logger import get_logger
from typing import List, Dict, Any
from urllib.parse import urljoin, urlparse
import re

logger = get_logger(__name__)


class RobotsTxtScanner(BaseModule):
    """Scans and analyzes robots.txt for information disclosure"""

    def __init__(self, module_path: str, payload_limit: int = None):
        super().__init__(module_path, payload_limit=payload_limit)
        self.module_name = "Robots.txt Scanner"
        self.logger = logger

        # Sensitive patterns to look for in disallowed paths
        self.sensitive_patterns = [
            # Admin paths
            (r'/admin', 'Admin panel path', 'Medium'),
            (r'/administrator', 'Administrator path', 'Medium'),
            (r'/wp-admin', 'WordPress admin', 'Medium'),
            (r'/manager', 'Manager interface', 'Medium'),
            (r'/cpanel', 'cPanel path', 'Medium'),
            (r'/phpmyadmin', 'phpMyAdmin path', 'High'),
            (r'/adminer', 'Adminer database tool', 'High'),

            # Backup and config
            (r'/backup', 'Backup directory', 'High'),
            (r'/backups', 'Backups directory', 'High'),
            (r'\.bak', 'Backup files', 'High'),
            (r'\.sql', 'SQL files', 'Critical'),
            (r'\.zip', 'Archive files', 'Medium'),
            (r'\.tar', 'Archive files', 'Medium'),
            (r'/config', 'Configuration directory', 'High'),
            (r'/conf', 'Configuration directory', 'High'),
            (r'\.env', 'Environment file', 'Critical'),
            (r'\.git', 'Git repository', 'Critical'),
            (r'\.svn', 'SVN repository', 'High'),

            # API and data
            (r'/api', 'API endpoint', 'Low'),
            (r'/rest', 'REST API', 'Low'),
            (r'/graphql', 'GraphQL endpoint', 'Low'),
            (r'/v1', 'API version', 'Low'),
            (r'/v2', 'API version', 'Low'),
            (r'/data', 'Data directory', 'Medium'),
            (r'/export', 'Export functionality', 'Medium'),
            (r'/download', 'Download functionality', 'Low'),

            # User data
            (r'/user', 'User directory', 'Low'),
            (r'/users', 'Users directory', 'Low'),
            (r'/profile', 'Profile directory', 'Low'),
            (r'/account', 'Account directory', 'Low'),
            (r'/private', 'Private directory', 'Medium'),
            (r'/internal', 'Internal directory', 'Medium'),

            # Development
            (r'/dev', 'Development directory', 'Medium'),
            (r'/test', 'Test directory', 'Medium'),
            (r'/staging', 'Staging directory', 'Medium'),
            (r'/debug', 'Debug directory', 'High'),
            (r'/temp', 'Temporary directory', 'Medium'),
            (r'/tmp', 'Temporary directory', 'Medium'),

            # Logs and monitoring
            (r'/log', 'Log directory', 'High'),
            (r'/logs', 'Logs directory', 'High'),
            (r'\.log', 'Log files', 'High'),
            (r'/status', 'Status page', 'Low'),
            (r'/health', 'Health check', 'Low'),
            (r'/metrics', 'Metrics endpoint', 'Medium'),

            # CMS specific
            (r'/wp-content/uploads', 'WordPress uploads', 'Low'),
            (r'/wp-includes', 'WordPress includes', 'Low'),
            (r'/sites/default/files', 'Drupal files', 'Low'),
            (r'/storage', 'Storage directory', 'Medium'),
            (r'/uploads', 'Uploads directory', 'Low'),

            # Security
            (r'/cgi-bin', 'CGI directory', 'Medium'),
            (r'/scripts', 'Scripts directory', 'Medium'),
            (r'/includes', 'Includes directory', 'Medium'),
            (r'/install', 'Installation directory', 'High'),
            (r'/setup', 'Setup directory', 'High'),

            # Credentials
            (r'/password', 'Password related', 'High'),
            (r'/secret', 'Secret directory', 'High'),
            (r'/credential', 'Credentials', 'Critical'),
            (r'/key', 'Key files', 'High'),
            (r'/token', 'Token files', 'High'),
        ]

    def scan(self, targets: List[Dict[str, Any]], http_client: Any = None) -> List[Dict[str, Any]]:
        """Scan for robots.txt and analyze contents"""
        self.logger.info(f"Starting {self.module_name} scan on {len(targets)} targets")

        results = []
        tested_bases = set()

        for target in targets:
            url = target.get('url') if isinstance(target, dict) else target
            if not url:
                continue

            parsed = urlparse(url)
            base_url = f"{parsed.scheme}://{parsed.netloc}"

            if base_url in tested_bases:
                continue
            tested_bases.add(base_url)

            # Fetch and analyze robots.txt
            robots_url = urljoin(base_url, '/robots.txt')
            finding = self._analyze_robots(http_client, robots_url, base_url)
            if finding:
                results.extend(finding)

        self.logger.info(f"{self.module_name} scan complete: {len(results)} findings")
        return results

    def _analyze_robots(self, http_client, robots_url: str, base_url: str) -> List[Dict[str, Any]]:
        """Analyze robots.txt content"""
        results = []

        try:
            response = http_client.get(robots_url)
            if not response or response.status_code != 200:
                return results

            content = response.text
            if not content or len(content) < 10:
                return results

            # Parse robots.txt
            disallowed_paths = []
            sitemaps = []
            has_wildcard_disallow = False

            for line in content.split('\n'):
                line = line.strip()

                # Extract Disallow entries
                if line.lower().startswith('disallow:'):
                    path = line.split(':', 1)[1].strip()
                    if path:
                        disallowed_paths.append(path)
                        if path == '/' or path == '/*':
                            has_wildcard_disallow = True

                # Extract Sitemap entries
                elif line.lower().startswith('sitemap:'):
                    sitemap = line.split(':', 1)[1].strip()
                    if sitemap:
                        sitemaps.append(sitemap)

            # Create base finding for robots.txt existence
            if disallowed_paths or sitemaps:
                results.append(self.create_result(
                    vulnerable=True,
                    url=robots_url,
                    parameter='robots.txt',
                    payload='/robots.txt',
                    evidence=f"Found robots.txt with {len(disallowed_paths)} disallowed paths",
                    severity='Info',
                    method='GET',
                    additional_info={
                        'injection_type': 'Information Disclosure',
                        'disallowed_count': len(disallowed_paths),
                        'sitemap_count': len(sitemaps),
                        'sitemaps': sitemaps[:5],  # First 5 sitemaps
                        'cwe': 'CWE-200',
                        'owasp': 'A01:2021'
                    }
                ))

            # Analyze each disallowed path for sensitive content
            sensitive_findings = []
            for path in disallowed_paths:
                for pattern, desc, severity in self.sensitive_patterns:
                    if re.search(pattern, path, re.IGNORECASE):
                        sensitive_findings.append({
                            'path': path,
                            'type': desc,
                            'severity': severity
                        })
                        break

            # Group sensitive findings by severity
            critical_paths = [f for f in sensitive_findings if f['severity'] == 'Critical']
            high_paths = [f for f in sensitive_findings if f['severity'] == 'High']
            medium_paths = [f for f in sensitive_findings if f['severity'] == 'Medium']

            # Report critical/high findings
            if critical_paths:
                paths_list = [f"{f['path']} ({f['type']})" for f in critical_paths[:10]]
                results.append(self.create_result(
                    vulnerable=True,
                    url=robots_url,
                    parameter='robots.txt',
                    payload='Sensitive paths',
                    evidence=f"Critical paths in robots.txt: {', '.join(paths_list)}",
                    severity='High',
                    method='GET',
                    additional_info={
                        'injection_type': 'Sensitive Path Disclosure',
                        'paths': [f['path'] for f in critical_paths],
                        'description': 'Robots.txt reveals potentially sensitive paths',
                        'cwe': 'CWE-200',
                        'owasp': 'A01:2021',
                        'recommendation': 'Review disclosed paths and remove from robots.txt if sensitive'
                    }
                ))

            if high_paths:
                paths_list = [f"{f['path']} ({f['type']})" for f in high_paths[:10]]
                results.append(self.create_result(
                    vulnerable=True,
                    url=robots_url,
                    parameter='robots.txt',
                    payload='Sensitive paths',
                    evidence=f"High-risk paths in robots.txt: {', '.join(paths_list)}",
                    severity='Medium',
                    method='GET',
                    additional_info={
                        'injection_type': 'Sensitive Path Disclosure',
                        'paths': [f['path'] for f in high_paths],
                        'description': 'Robots.txt reveals potentially sensitive paths',
                        'cwe': 'CWE-200',
                        'owasp': 'A01:2021'
                    }
                ))

            # Check for sitemaps disclosure
            if sitemaps:
                results.append(self.create_result(
                    vulnerable=True,
                    url=robots_url,
                    parameter='robots.txt',
                    payload='Sitemap disclosure',
                    evidence=f"Sitemap(s) disclosed: {', '.join(sitemaps[:3])}",
                    severity='Info',
                    method='GET',
                    additional_info={
                        'injection_type': 'Sitemap Disclosure',
                        'sitemaps': sitemaps,
                        'description': 'Sitemap URLs found - can be used for enumeration',
                        'cwe': 'CWE-200',
                        'owasp': 'A01:2021'
                    }
                ))

        except Exception as e:
            self.logger.debug(f"Error analyzing {robots_url}: {e}")

        return results


def get_module(module_path: str, payload_limit: int = None):
    """Factory function to create module instance"""
    return RobotsTxtScanner(module_path, payload_limit=payload_limit)
