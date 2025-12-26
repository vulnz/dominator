"""
WPScan Plugin for Dominator

Integrates WPScan (WordPress Security Scanner) with automatic WordPress detection.
Runs only when WordPress is detected in the target profile.
"""

import json
import re
import logging
from typing import List, Dict, Any, Optional
from .base_plugin import BasePlugin, PluginResult

logger = logging.getLogger(__name__)


class WPScanPlugin(BasePlugin):
    """WPScan integration plugin for WordPress vulnerability scanning"""

    NAME = "wpscan"
    DISPLAY_NAME = "WPScan"
    VERSION = "1.0.0"
    AUTHOR = "Dominator Team"
    DESCRIPTION = "WordPress vulnerability scanner. Detects vulnerable plugins, themes, and core version issues."
    CATEGORY = "CMS Scanner"
    EXECUTABLE = "wpscan"

    # WordPress detection patterns
    WP_INDICATORS = [
        'wordpress', 'wp-content', 'wp-includes', 'wp-admin',
        'wp-json', 'xmlrpc.php', 'wp-login.php'
    ]

    # Severity mapping from WPScan to Dominator
    SEVERITY_MAP = {
        'critical': 'CRITICAL',
        'high': 'HIGH',
        'medium': 'MEDIUM',
        'low': 'LOW',
        'info': 'INFO',
        'informational': 'INFO'
    }

    def __init__(self, config: Dict[str, Any] = None):
        super().__init__(config)
        self.api_token = config.get('api_token', '') if config else ''

    def should_run(self, target_profile: Dict[str, Any]) -> bool:
        """Check if WordPress is detected in the target"""
        if not target_profile:
            return False

        # Check CMS field
        cms = target_profile.get('cms', '').lower()
        if 'wordpress' in cms or 'wp' in cms:
            logger.info("WordPress detected via CMS field")
            return True

        # Check technologies list
        technologies = target_profile.get('technologies', [])
        for tech in technologies:
            if isinstance(tech, dict):
                name = tech.get('name', '').lower()
            else:
                name = str(tech).lower()
            if 'wordpress' in name:
                logger.info("WordPress detected via technologies")
                return True

        # Check framework field
        framework = target_profile.get('framework', '').lower()
        if 'wordpress' in framework:
            return True

        # Check for WordPress indicators in interesting paths
        paths = target_profile.get('interesting_paths', [])
        for path in paths:
            path_lower = path.lower() if isinstance(path, str) else ''
            for indicator in self.WP_INDICATORS:
                if indicator in path_lower:
                    logger.info(f"WordPress detected via path: {path}")
                    return True

        return False

    def run(self, target: str, options: Dict[str, Any] = None) -> List[PluginResult]:
        """Run WPScan against the target"""
        if not self.is_available:
            logger.warning("WPScan is not installed or not in PATH")
            return []

        options = options or {}
        results = []

        # Build command
        cmd = [self.get_executable()]

        # Target URL
        cmd.extend(['--url', target])

        # Output format
        cmd.extend(['--format', 'json'])

        # API token for vulnerability data
        if self.api_token:
            cmd.extend(['--api-token', self.api_token])

        # Enumeration options
        enumerate_opts = options.get('enumerate', 'vp,vt,u,cb,dbe')
        cmd.extend(['--enumerate', enumerate_opts])

        # Random user agent
        cmd.append('--random-user-agent')

        # Don't show progress
        cmd.append('--no-banner')

        # Detection mode
        detection_mode = options.get('detection_mode', 'mixed')
        cmd.extend(['--detection-mode', detection_mode])

        # Throttle requests
        throttle = options.get('throttle', 100)
        cmd.extend(['--throttle', str(throttle)])

        # Timeout
        timeout = options.get('timeout', 600)

        logger.info(f"Running WPScan: {' '.join(cmd[:5])}...")

        stdout, stderr, returncode = self.run_command(cmd, timeout=timeout)

        if returncode != 0 and not stdout:
            logger.error(f"WPScan failed: {stderr}")
            self.errors.append(f"WPScan error: {stderr}")
            return []

        # Parse JSON output
        results = self.parse_output(stdout, target)

        logger.info(f"WPScan found {len(results)} findings")
        return results

    def parse_output(self, output: str, target: str) -> List[PluginResult]:
        """Parse WPScan JSON output into PluginResults"""
        results = []

        try:
            data = json.loads(output)
        except json.JSONDecodeError as e:
            logger.error(f"Failed to parse WPScan JSON: {e}")
            # Try to extract JSON from output
            json_match = re.search(r'\{.*\}', output, re.DOTALL)
            if json_match:
                try:
                    data = json.loads(json_match.group())
                except:
                    return results
            else:
                return results

        # Parse WordPress version
        if 'version' in data:
            version_data = data['version']
            if version_data:
                version = version_data.get('number', 'Unknown')
                status = version_data.get('status', '')

                if status == 'insecure':
                    results.append(PluginResult(
                        title=f"Outdated WordPress Version: {version}",
                        severity='HIGH',
                        url=target,
                        module='WordPress Core',
                        plugin_name=self.NAME,
                        description=f"WordPress version {version} is outdated and may contain known vulnerabilities.",
                        remediation="Update WordPress to the latest stable version.",
                        evidence=f"Detected version: {version}\nStatus: {status}",
                        cwe="CWE-1104",
                        cwe_name="Use of Unmaintained Third Party Components",
                        owasp="A06:2021",
                        owasp_name="Vulnerable and Outdated Components",
                        confidence="high",
                        tags=['wordpress', 'outdated', 'core'],
                        raw_finding=version_data
                    ))

                # Check for version vulnerabilities
                vulns = version_data.get('vulnerabilities', [])
                for vuln in vulns:
                    results.append(self._parse_vulnerability(vuln, target, 'WordPress Core'))

        # Parse themes
        if 'themes' in data and 'main_theme' in data:
            theme_data = data['main_theme']
            if theme_data:
                theme_name = theme_data.get('slug', 'Unknown')
                theme_version = theme_data.get('version', {}).get('number', 'Unknown')

                # Theme vulnerabilities
                vulns = theme_data.get('vulnerabilities', [])
                for vuln in vulns:
                    results.append(self._parse_vulnerability(vuln, target, f"Theme: {theme_name}"))

                # Outdated theme
                if theme_data.get('outdated', False):
                    results.append(PluginResult(
                        title=f"Outdated Theme: {theme_name}",
                        severity='MEDIUM',
                        url=target,
                        module=f'Theme: {theme_name}',
                        plugin_name=self.NAME,
                        description=f"Theme '{theme_name}' version {theme_version} is outdated.",
                        remediation=f"Update the {theme_name} theme to the latest version.",
                        evidence=f"Current version: {theme_version}",
                        cwe="CWE-1104",
                        owasp="A06:2021",
                        tags=['wordpress', 'theme', 'outdated'],
                        raw_finding=theme_data
                    ))

        # Parse plugins
        if 'plugins' in data:
            for plugin_slug, plugin_data in data['plugins'].items():
                plugin_version = plugin_data.get('version', {}).get('number', 'Unknown')

                # Plugin vulnerabilities
                vulns = plugin_data.get('vulnerabilities', [])
                for vuln in vulns:
                    results.append(self._parse_vulnerability(vuln, target, f"Plugin: {plugin_slug}"))

                # Outdated plugin
                if plugin_data.get('outdated', False):
                    results.append(PluginResult(
                        title=f"Outdated Plugin: {plugin_slug}",
                        severity='MEDIUM',
                        url=target,
                        module=f'Plugin: {plugin_slug}',
                        plugin_name=self.NAME,
                        description=f"Plugin '{plugin_slug}' version {plugin_version} is outdated.",
                        remediation=f"Update the {plugin_slug} plugin to the latest version.",
                        evidence=f"Current version: {plugin_version}",
                        cwe="CWE-1104",
                        owasp="A06:2021",
                        tags=['wordpress', 'plugin', 'outdated'],
                        raw_finding=plugin_data
                    ))

        # Parse users
        if 'users' in data:
            users = data['users']
            if users:
                user_list = list(users.keys())[:10]  # Limit to 10
                results.append(PluginResult(
                    title="WordPress User Enumeration",
                    severity='INFO',
                    url=target,
                    module='User Enumeration',
                    plugin_name=self.NAME,
                    description=f"Found {len(users)} WordPress users via enumeration.",
                    evidence=f"Users found: {', '.join(user_list)}",
                    remediation="Disable user enumeration by blocking ?author=N queries and wp-json/wp/v2/users endpoint.",
                    cwe="CWE-200",
                    cwe_name="Exposure of Sensitive Information",
                    owasp="A01:2021",
                    owasp_name="Broken Access Control",
                    tags=['wordpress', 'enumeration', 'users'],
                    raw_finding={'users': user_list}
                ))

        # Parse interesting findings
        if 'interesting_findings' in data:
            for finding in data['interesting_findings']:
                finding_type = finding.get('type', 'unknown')
                finding_url = finding.get('url', target)
                description = finding.get('to_s', '')

                # Map finding types to severities
                severity = 'INFO'
                if 'xmlrpc' in finding_type.lower():
                    severity = 'LOW'
                elif 'debug' in finding_type.lower():
                    severity = 'MEDIUM'
                elif 'backup' in finding_type.lower() or 'sensitive' in finding_type.lower():
                    severity = 'HIGH'

                results.append(PluginResult(
                    title=f"WordPress: {finding_type}",
                    severity=severity,
                    url=finding_url,
                    module='Interesting Finding',
                    plugin_name=self.NAME,
                    description=description,
                    confidence="high" if finding.get('confidence', 0) > 80 else "medium",
                    tags=['wordpress', finding_type.lower()],
                    raw_finding=finding
                ))

        # Parse config backups
        if 'config_backups' in data and data['config_backups']:
            for backup_url in data['config_backups']:
                results.append(PluginResult(
                    title="WordPress Config Backup Exposed",
                    severity='CRITICAL',
                    url=backup_url,
                    module='Config Backup',
                    plugin_name=self.NAME,
                    description="WordPress configuration backup file is publicly accessible. This may contain database credentials.",
                    remediation="Remove the backup file immediately and rotate all credentials.",
                    cwe="CWE-538",
                    cwe_name="Insertion of Sensitive Information into Externally-Accessible File",
                    owasp="A01:2021",
                    cvss="9.8",
                    tags=['wordpress', 'config', 'backup', 'credentials'],
                    raw_finding={'url': backup_url}
                ))

        return results

    def _parse_vulnerability(self, vuln: Dict[str, Any], target: str, component: str) -> PluginResult:
        """Parse a single vulnerability from WPScan output"""
        title = vuln.get('title', 'Unknown Vulnerability')
        vuln_type = vuln.get('vuln_type', '')

        # Determine severity
        severity = 'MEDIUM'
        if vuln.get('cvss', {}).get('score', 0) >= 9.0:
            severity = 'CRITICAL'
        elif vuln.get('cvss', {}).get('score', 0) >= 7.0:
            severity = 'HIGH'
        elif vuln.get('cvss', {}).get('score', 0) >= 4.0:
            severity = 'MEDIUM'
        else:
            severity = 'LOW'

        # Extract CVSS
        cvss_data = vuln.get('cvss', {})
        cvss_score = str(cvss_data.get('score', '')) if cvss_data else ''
        cvss_vector = cvss_data.get('vector', '') if cvss_data else ''

        # Get references
        refs = vuln.get('references', {})
        reference_list = []
        for ref_type, ref_urls in refs.items():
            if isinstance(ref_urls, list):
                reference_list.extend(ref_urls)
            elif isinstance(ref_urls, str):
                reference_list.append(ref_urls)

        # Get CVE if available
        cve_list = refs.get('cve', [])
        cwe = ''
        if cve_list:
            cwe = f"CVE-{cve_list[0]}" if cve_list[0] else ''

        return PluginResult(
            title=title,
            severity=severity,
            url=target,
            module=component,
            plugin_name=self.NAME,
            description=f"{vuln_type}: {title}" if vuln_type else title,
            evidence=f"Fixed in: {vuln.get('fixed_in', 'Unknown')}" if vuln.get('fixed_in') else "",
            remediation=f"Update {component} to version {vuln.get('fixed_in')} or later." if vuln.get('fixed_in') else f"Update {component} to the latest version.",
            cwe=cwe,
            cvss=cvss_score,
            cvss_vector=cvss_vector,
            references=reference_list,
            verified=True,
            tags=['wordpress', 'vulnerability', vuln_type.lower() if vuln_type else 'unknown'],
            raw_finding=vuln
        )
