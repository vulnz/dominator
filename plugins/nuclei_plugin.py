"""
Nuclei Plugin for Dominator

Integrates Nuclei (Template-based Vulnerability Scanner) with Dominator.
Nuclei runs by default for all targets and provides comprehensive template-based scanning.
"""

import json
import re
import logging
from typing import List, Dict, Any, Optional
from pathlib import Path
from .base_plugin import BasePlugin, PluginResult

logger = logging.getLogger(__name__)


class NucleiPlugin(BasePlugin):
    """Nuclei integration plugin for template-based vulnerability scanning"""

    NAME = "nuclei"
    DISPLAY_NAME = "Nuclei"
    VERSION = "1.0.0"
    AUTHOR = "Dominator Team"
    DESCRIPTION = "Fast template-based vulnerability scanner. Runs customizable YAML-based templates for CVEs, misconfigs, and exposures."
    CATEGORY = "Vulnerability Scanner"
    EXECUTABLE = "nuclei"

    # Severity mapping from Nuclei to Dominator
    SEVERITY_MAP = {
        'critical': 'CRITICAL',
        'high': 'HIGH',
        'medium': 'MEDIUM',
        'low': 'LOW',
        'info': 'INFO',
        'unknown': 'INFO'
    }

    # Default template tags to use
    DEFAULT_TAGS = ['cve', 'exposure', 'misconfiguration', 'takeover', 'default-login']

    def __init__(self, config: Dict[str, Any] = None):
        super().__init__(config)
        self.templates_path = config.get('templates_path', '') if config else ''
        self.custom_templates = config.get('custom_templates', []) if config else []
        self.excluded_tags = config.get('excluded_tags', ['dos', 'fuzz']) if config else ['dos', 'fuzz']

    def should_run(self, target_profile: Dict[str, Any]) -> bool:
        """Nuclei should run for all web targets"""
        # Always run nuclei for web targets unless explicitly disabled
        if not target_profile:
            return True

        # Check if it's a web target
        url = target_profile.get('url', '')
        if url.startswith('http://') or url.startswith('https://'):
            return True

        # Run if status code was obtained (indicates web server)
        if target_profile.get('status_code'):
            return True

        return True

    def run(self, target: str, options: Dict[str, Any] = None) -> List[PluginResult]:
        """Run Nuclei against the target"""
        if not self.is_available:
            logger.warning("Nuclei is not installed or not in PATH")
            return []

        options = options or {}
        results = []

        # Build command
        cmd = [self.get_executable()]

        # Target
        cmd.extend(['-u', target])

        # JSON output for parsing
        cmd.extend(['-jsonl'])

        # Severity filter
        severity = options.get('severity', 'critical,high,medium,low,info')
        cmd.extend(['-severity', severity])

        # Template tags
        tags = options.get('tags', ','.join(self.DEFAULT_TAGS))
        if tags:
            cmd.extend(['-tags', tags])

        # Exclude dangerous tags
        exclude_tags = options.get('exclude_tags', ','.join(self.excluded_tags))
        if exclude_tags:
            cmd.extend(['-exclude-tags', exclude_tags])

        # Custom templates path
        if self.templates_path and Path(self.templates_path).exists():
            cmd.extend(['-t', self.templates_path])

        # Rate limiting
        rate_limit = options.get('rate_limit', 150)
        cmd.extend(['-rate-limit', str(rate_limit)])

        # Concurrency
        concurrency = options.get('concurrency', 25)
        cmd.extend(['-c', str(concurrency)])

        # Timeout per request
        timeout_secs = options.get('timeout', 10)
        cmd.extend(['-timeout', str(timeout_secs)])

        # Retries
        retries = options.get('retries', 1)
        cmd.extend(['-retries', str(retries)])

        # Don't show banner/progress
        cmd.append('-silent')

        # Stats at end
        cmd.append('-stats')

        # Automatic template updates (disabled for speed)
        cmd.append('-disable-update-check')

        # Total timeout
        total_timeout = options.get('total_timeout', 600)

        logger.info(f"Running Nuclei: {' '.join(cmd[:5])}...")

        stdout, stderr, returncode = self.run_command(cmd, timeout=total_timeout)

        # Parse JSONL output (one JSON object per line)
        if stdout:
            results = self.parse_output(stdout, target)

        if stderr and 'error' in stderr.lower():
            logger.warning(f"Nuclei stderr: {stderr[:500]}")

        logger.info(f"Nuclei found {len(results)} findings")
        return results

    def parse_output(self, output: str, target: str) -> List[PluginResult]:
        """Parse Nuclei JSONL output into PluginResults"""
        results = []

        for line in output.strip().split('\n'):
            if not line.strip():
                continue

            try:
                finding = json.loads(line)
                result = self._parse_finding(finding, target)
                if result:
                    results.append(result)
            except json.JSONDecodeError:
                # Skip non-JSON lines (stats, progress, etc.)
                continue
            except Exception as e:
                logger.debug(f"Error parsing Nuclei finding: {e}")
                continue

        return results

    def _parse_finding(self, finding: Dict[str, Any], default_target: str) -> Optional[PluginResult]:
        """Parse a single Nuclei finding into PluginResult"""
        try:
            # Extract template info
            info = finding.get('info', {})
            template_id = finding.get('template-id', finding.get('templateID', 'unknown'))
            template_name = info.get('name', template_id)

            # Severity
            severity = info.get('severity', 'info').lower()
            severity = self.SEVERITY_MAP.get(severity, 'INFO')

            # URL
            url = finding.get('matched-at', finding.get('host', default_target))
            if not url:
                url = default_target

            # Description
            description = info.get('description', '')
            if not description:
                description = f"Nuclei template {template_id} matched"

            # Evidence
            matched_line = finding.get('matched-line', '')
            matcher_name = finding.get('matcher-name', '')
            extracted = finding.get('extracted-results', [])

            evidence_parts = []
            if matched_line:
                evidence_parts.append(f"Matched: {matched_line}")
            if matcher_name:
                evidence_parts.append(f"Matcher: {matcher_name}")
            if extracted:
                evidence_parts.append(f"Extracted: {', '.join(str(e) for e in extracted[:5])}")

            evidence = '\n'.join(evidence_parts)

            # HTTP details
            request_data = finding.get('request', '')
            response_data = finding.get('response', '')

            # Truncate large responses
            if len(response_data) > 5000:
                response_data = response_data[:5000] + '\n... [truncated]'

            # Classification
            classification = info.get('classification', {})
            cve_id = classification.get('cve-id', [])
            cwe_id = classification.get('cwe-id', [])
            cvss_score = classification.get('cvss-score', '')
            cvss_metrics = classification.get('cvss-metrics', '')

            # Get first CVE/CWE if available
            cve = f"CVE-{cve_id[0]}" if cve_id else ''
            cwe = f"CWE-{cwe_id[0]}" if cwe_id else ''

            # References
            references = info.get('reference', [])
            if isinstance(references, str):
                references = [references]

            # Tags
            tags = info.get('tags', [])
            if isinstance(tags, str):
                tags = tags.split(',')

            # Remediation
            remediation = info.get('remediation', '')

            # Author
            author = info.get('author', [])
            if isinstance(author, list):
                author = ', '.join(author)

            return PluginResult(
                title=template_name,
                severity=severity,
                url=url,
                module=template_id,
                plugin_name=self.NAME,
                description=description,
                evidence=evidence,
                remediation=remediation if remediation else f"Review the finding and apply appropriate fixes for {template_name}.",
                cwe=cwe,
                cvss=str(cvss_score) if cvss_score else '',
                cvss_vector=cvss_metrics if cvss_metrics else '',
                references=references,
                request=request_data,
                response=response_data,
                method=finding.get('type', 'http').upper(),
                confidence="high" if finding.get('matcher-status', True) else "medium",
                verified=True,
                tags=tags + ['nuclei', template_id],
                raw_finding=finding
            )

        except Exception as e:
            logger.error(f"Error parsing Nuclei finding: {e}")
            return None

    def run_with_templates(self, target: str, template_ids: List[str],
                           options: Dict[str, Any] = None) -> List[PluginResult]:
        """Run Nuclei with specific templates only"""
        if not self.is_available:
            return []

        options = options or {}

        cmd = [self.get_executable()]
        cmd.extend(['-u', target])
        cmd.extend(['-jsonl'])
        cmd.append('-silent')

        # Add specific templates
        for template_id in template_ids:
            cmd.extend(['-t', template_id])

        timeout = options.get('timeout', 300)
        stdout, stderr, returncode = self.run_command(cmd, timeout=timeout)

        if stdout:
            return self.parse_output(stdout, target)

        return []

    def run_cve_scan(self, target: str, options: Dict[str, Any] = None) -> List[PluginResult]:
        """Run Nuclei specifically for CVE detection"""
        options = options or {}
        options['tags'] = 'cve'
        options['severity'] = 'critical,high'
        return self.run(target, options)

    def run_exposure_scan(self, target: str, options: Dict[str, Any] = None) -> List[PluginResult]:
        """Run Nuclei for exposure and information disclosure"""
        options = options or {}
        options['tags'] = 'exposure,disclosure,config'
        return self.run(target, options)

    def run_takeover_scan(self, target: str, options: Dict[str, Any] = None) -> List[PluginResult]:
        """Run Nuclei for subdomain takeover detection"""
        options = options or {}
        options['tags'] = 'takeover'
        options['severity'] = 'critical,high'
        return self.run(target, options)

    def update_templates(self) -> bool:
        """Update Nuclei templates to latest version"""
        if not self.is_available:
            return False

        cmd = [self.get_executable(), '-update-templates']
        stdout, stderr, returncode = self.run_command(cmd, timeout=120)

        if returncode == 0:
            logger.info("Nuclei templates updated successfully")
            return True
        else:
            logger.error(f"Failed to update Nuclei templates: {stderr}")
            return False
