#!/usr/bin/env python3
"""
Scan Thread - Background thread for running vulnerability scans
"""

import sys
import subprocess
import re
import threading
from pathlib import Path

from PyQt5.QtCore import QThread, pyqtSignal


class ScanThread(QThread):
    """Background thread for running scans"""
    output_signal = pyqtSignal(str)
    finished_signal = pyqtSignal(int)
    progress_signal = pyqtSignal(int, str)
    vulnerability_signal = pyqtSignal(str, str)  # (severity, description)
    stats_signal = pyqtSignal(int, int, int)  # (total, modules_done, modules_total)
    resource_signal = pyqtSignal(str, str, str, str)  # (type, value, extra, source)
    scope_signal = pyqtSignal(str, str, str, str)  # (type, data1, data2, data3)
    report_signal = pyqtSignal(str)  # (report_filename) - emitted when report is saved

    def __init__(self, command, module_count=None):
        super().__init__()
        self.command = command
        self.process = None
        # Calculate total modules from command or use provided count
        if module_count is not None:
            self.total_modules = module_count
        elif "--all" in command:
            self.total_modules = 20  # All 20 modules
        elif "-m" in command:
            # Count modules from -m argument
            try:
                m_index = command.index("-m")
                if m_index + 1 < len(command):
                    module_str = command[m_index + 1]
                    self.total_modules = len(module_str.split(','))
            except:
                self.total_modules = 1
        else:
            self.total_modules = 1  # At least 1 module
        self.completed_modules = 0
        self.total_vulns = 0
        self.current_severity = 'MEDIUM'  # Track current severity section
        self.paused = False
        self._pause_event = threading.Event()
        self._pause_event.set()  # Not paused initially

    def pause(self):
        """Pause the scan"""
        self.paused = True
        self._pause_event.clear()

    def resume(self):
        """Resume the scan"""
        self.paused = False
        self._pause_event.set()

    def run(self):
        """Run the scan command"""
        try:
            # Get parent directory (where main.py and modules/ are)
            parent_dir = Path(__file__).parent.parent

            # Hide console window on Windows
            creation_flags = 0
            if sys.platform == 'win32':
                # CREATE_NO_WINDOW = 0x08000000
                creation_flags = getattr(subprocess, 'CREATE_NO_WINDOW', 0x08000000)

            self.process = subprocess.Popen(
                self.command,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1,
                universal_newlines=True,
                encoding='utf-8',
                errors='ignore',
                cwd=str(parent_dir),  # Set working directory to scanner root
                creationflags=creation_flags  # Hide console window
            )

            for line in iter(self.process.stdout.readline, ''):
                # Check for pause
                self._pause_event.wait()

                if line:
                    line_clean = line.strip()
                    self.output_signal.emit(line_clean)

                    # Parse different types of output
                    self.parse_scan_output(line_clean)

            self.process.wait()
            self.finished_signal.emit(self.process.returncode)

        except Exception as e:
            self.output_signal.emit(f"ERROR: {str(e)}")
            self.finished_signal.emit(-1)

    def parse_scan_output(self, line):
        """Parse scanner output for progress and findings"""
        # Strip ANSI color codes for easier parsing
        line_clean = line
        if '[' in line and 'm' in line:
            line_clean = re.sub(r'\x1b\[[0-9;]*m', '', line)

        # Detect resources (emails, phones, social media, leaked keys)
        self.detect_resources(line_clean)

        # Detect scope info (technologies, titles, IPs)
        self.detect_scope_info(line_clean)

        # Track module execution
        if 'Running module:' in line_clean:
            module_name = line_clean.split('Running module:')[-1].strip()
            self.progress_signal.emit(0, f"Testing: {module_name}")

        # Track module completion
        elif 'Module' in line_clean and 'completed' in line_clean:
            self.completed_modules += 1
            progress = int((self.completed_modules / self.total_modules) * 100)
            self.progress_signal.emit(progress, f"Completed {self.completed_modules}/{self.total_modules} modules")
            self.stats_signal.emit(self.total_vulns, self.completed_modules, self.total_modules)

        # Track crawling progress
        elif 'Crawling:' in line_clean or 'Found page:' in line_clean or 'Form discovered:' in line_clean:
            self.progress_signal.emit(0, "Crawling target...")

        # Track target discovery
        elif 'Page discovery complete:' in line_clean:
            try:
                targets = line_clean.split('Page discovery complete:')[-1].strip()
                self.progress_signal.emit(0, f"{targets}")
            except:
                pass

        # Track vulnerabilities found - FIXED: Only count actual vulnerabilities, not debug info
        # Filter out crawler/passive debug messages that start with "[CRAWLER]", "[PASSIVE]", etc.
        elif 'Found' in line_clean and not self._is_debug_message(line_clean):
            self.total_vulns += 1
            # Try to determine severity from context (will be updated by severity line)
            severity = 'MEDIUM'
            self.vulnerability_signal.emit(severity, line_clean)
            self.stats_signal.emit(self.total_vulns, self.completed_modules, self.total_modules)

        # Detect severity section headers (Critical Severity, High Severity, etc.)
        elif 'Severity (' in line_clean:
            # Extract count from "Critical Severity (5):" format
            try:
                if 'Critical' in line_clean:
                    self.current_severity = 'CRITICAL'
                elif 'High' in line_clean:
                    self.current_severity = 'HIGH'
                elif 'Medium' in line_clean:
                    self.current_severity = 'MEDIUM'
                elif 'Low' in line_clean:
                    self.current_severity = 'LOW'
            except:
                pass

        # Detect vulnerability type lines like "[SQL Injection]"
        elif line_clean.strip().startswith('[') and line_clean.strip().endswith(']'):
            vuln_type = line_clean.strip()
            # Skip empty brackets or brackets with only whitespace
            content = vuln_type[1:-1].strip()  # Remove brackets and check content
            # Also skip debug/summary messages (passive summary, crawler summary, etc.)
            content_lower = content.lower()
            is_summary = any(keyword in content_lower for keyword in [
                'summary', 'passive', 'crawler', 'total vulnerabilities'
            ])

            if content and len(content) > 0 and not is_summary:
                if hasattr(self, 'current_severity'):
                    severity = self.current_severity
                else:
                    severity = 'MEDIUM'
                self.vulnerability_signal.emit(severity, vuln_type)

        # Detect "Total vulnerabilities:" summary
        elif 'Total vulnerabilities:' in line_clean:
            try:
                count = int(line_clean.split('Total vulnerabilities:')[-1].strip())
                self.total_vulns = count
                self.stats_signal.emit(self.total_vulns, self.completed_modules, self.total_modules)
            except:
                pass

        # Track scan start
        elif 'Target:' in line_clean and 'http' in line_clean:
            target = line_clean.split('Target:')[-1].strip()
            self.progress_signal.emit(0, f"Scanning: {target}")

        # Detect report saved message - capture HTML report path
        elif 'report saved to' in line_clean.lower():
            try:
                # Extract filename from "HTML report saved to filename.html"
                parts = line_clean.split('saved to')
                if len(parts) >= 2:
                    report_file = parts[-1].strip()
                    # Extract just the filename if it includes "(mode: ...)"
                    if '(' in report_file:
                        report_file = report_file.split('(')[0].strip()
                    # Only emit for HTML reports
                    if report_file.endswith('.html'):
                        self.report_signal.emit(report_file)
            except:
                pass

    def detect_resources(self, line):
        """Detect emails, phones, social media, and leaked keys in output"""
        # Detect emails
        email_pattern = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
        emails = re.findall(email_pattern, line)
        for email in emails:
            email_type = "Personal" if any(d in email.lower() for d in ['gmail', 'yahoo', 'hotmail', 'outlook']) else "Business"
            self.resource_signal.emit("email", email, email_type, line[:100])

        # Detect phone numbers (international formats)
        phone_patterns = [
            r'\+?\d{1,3}[-.\s]?\(?\d{1,4}\)?[-.\s]?\d{1,4}[-.\s]?\d{1,9}',  # International
            r'\(\d{3}\)\s?\d{3}-\d{4}',  # (123) 456-7890
            r'\d{3}-\d{3}-\d{4}',  # 123-456-7890
        ]
        for pattern in phone_patterns:
            phones = re.findall(pattern, line)
            for phone in phones:
                if len(phone.replace('-', '').replace(' ', '').replace('(', '').replace(')', '').replace('+', '')) >= 10:
                    phone_format = "International" if '+' in phone else "US/Canada"
                    self.resource_signal.emit("phone", phone, phone_format, line[:100])

        # Detect social media links
        social_media_patterns = {
            'Facebook': r'(?:https?://)?(?:www\.)?facebook\.com/[A-Za-z0-9._-]+',
            'Twitter/X': r'(?:https?://)?(?:www\.)?(?:twitter|x)\.com/[A-Za-z0-9._-]+',
            'LinkedIn': r'(?:https?://)?(?:www\.)?linkedin\.com/(?:in|company)/[A-Za-z0-9._-]+',
            'Instagram': r'(?:https?://)?(?:www\.)?instagram\.com/[A-Za-z0-9._-]+',
            'GitHub': r'(?:https?://)?(?:www\.)?github\.com/[A-Za-z0-9._-]+',
            'YouTube': r'(?:https?://)?(?:www\.)?youtube\.com/(?:c|channel|user)/[A-Za-z0-9._-]+',
            'TikTok': r'(?:https?://)?(?:www\.)?tiktok\.com/@[A-Za-z0-9._-]+',
        }
        for platform, pattern in social_media_patterns.items():
            matches = re.findall(pattern, line, re.IGNORECASE)
            for match in matches:
                self.resource_signal.emit("social", match, platform, line[:100])

        # Detect leaked API keys and secrets
        leaked_key_patterns = {
            'AWS Access Key': r'AKIA[0-9A-Z]{16}',
            'AWS Secret Key': r'aws_secret_access_key\s*=\s*[\'"]([A-Za-z0-9/+=]{40})[\'"]',
            'Google API Key': r'AIza[0-9A-Za-z\-_]{35}',
            'GitHub Token': r'gh[ps]_[A-Za-z0-9]{36}',
            'Slack Token': r'xox[baprs]-[0-9]{10,12}-[0-9]{10,12}-[A-Za-z0-9]{24}',
            'Stripe API Key': r'sk_live_[0-9a-zA-Z]{24}',
            'PayPal Client ID': r'A[A-Z0-9]{80}',
            'JWT Token': r'eyJ[A-Za-z0-9-_=]+\.eyJ[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*',
            'Private Key': r'-----BEGIN (?:RSA |OPENSSH )?PRIVATE KEY-----',
            'Generic API Key': r'(?i)api[_-]?key["\']?\s*[:=]\s*["\']?([A-Za-z0-9_\-]{20,})["\']?',
        }
        for key_type, pattern in leaked_key_patterns.items():
            matches = re.findall(pattern, line)
            for match in matches:
                # Truncate key preview for security
                key_preview = str(match)[:20] + "..." if len(str(match)) > 20 else str(match)
                severity = "CRITICAL" if any(k in key_type for k in ['AWS', 'Private Key', 'Secret']) else "HIGH"
                self.resource_signal.emit("leaked_key", key_preview, f"{key_type}|{severity}", line[:100])

    def detect_scope_info(self, line):
        """Detect technologies, page titles, and IP information"""
        # Detect passive scanner technology detection output
        # Format: "[PASSIVE] Detected technologies: Nginx, Nginx, PHP"
        passive_tech_pattern = r'\[PASSIVE\]\s+Detected technologies:\s*(.+)'
        passive_match = re.search(passive_tech_pattern, line, re.IGNORECASE)
        if passive_match:
            techs = passive_match.group(1).split(',')
            seen_techs = set()  # Avoid duplicates
            for tech in techs:
                tech_name = tech.strip()
                if tech_name and tech_name not in seen_techs:
                    seen_techs.add(tech_name)
                    category = self._get_tech_category(tech_name)
                    self.scope_signal.emit("technology", tech_name, "", f"{category}|Passive Detection")

        # Also detect from summary line: "Detected Technologies: PHP, Nginx"
        summary_tech_pattern = r'^\s+Detected Technologies:\s*(.+)'
        summary_match = re.search(summary_tech_pattern, line)
        if summary_match:
            techs = summary_match.group(1).split(',')
            seen_techs = set()
            for tech in techs:
                tech_name = tech.strip()
                if tech_name and tech_name not in seen_techs:
                    seen_techs.add(tech_name)
                    category = self._get_tech_category(tech_name)
                    self.scope_signal.emit("technology", tech_name, "", f"{category}|Passive Summary")

        # Detect technologies from headers/responses
        tech_patterns = {
            'PHP': r'(?:X-Powered-By|Server).*PHP/([0-9.]+)',
            'Apache': r'Server.*Apache/([0-9.]+)',
            'Nginx': r'Server.*nginx/([0-9.]+)',
            'WordPress': r'(?:wp-content|wp-includes|WordPress/([0-9.]+))',
            'jQuery': r'jquery[.-]([0-9.]+)\.(?:min\.)?js',
            'React': r'react(?:-dom)?[.-]([0-9.]+)\.(?:min\.)?js',
            'Vue.js': r'vue[.-]([0-9.]+)\.(?:min\.)?js',
            'Angular': r'angular[.-]([0-9.]+)\.(?:min\.)?js',
            'Bootstrap': r'bootstrap[.-]([0-9.]+)\.(?:min\.)?(?:css|js)',
            'MySQL': r'MySQL/([0-9.]+)',
            'PostgreSQL': r'PostgreSQL/([0-9.]+)',
            'IIS': r'Server.*IIS/([0-9.]+)',
            'ASP.NET': r'X-AspNet-Version.*([0-9.]+)',
        }

        for tech_name, pattern in tech_patterns.items():
            matches = re.findall(pattern, line, re.IGNORECASE)
            for version in matches:
                category = self._get_tech_category(tech_name)
                self.scope_signal.emit("technology", tech_name, version, f"{category}|{line[:80]}")

        # Detect page titles
        title_pattern = r'<title>([^<]+)</title>'
        titles = re.findall(title_pattern, line, re.IGNORECASE)
        for title in titles:
            # Extract URL from line if present
            url_match = re.search(r'https?://[^\s]+', line)
            url = url_match.group(0) if url_match else "Unknown"
            self.scope_signal.emit("title", title.strip(), url, "")

        # Detect IP addresses and potential geo info
        ip_pattern = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
        ips = re.findall(ip_pattern, line)
        for ip in ips:
            # Skip private IPs
            if not (ip.startswith('192.168.') or ip.startswith('10.') or ip.startswith('172.') or ip.startswith('127.')):
                # Extract domain from line if present
                domain_match = re.search(r'(?:https?://)?([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})', line)
                domain = domain_match.group(1) if domain_match else ""
                self.scope_signal.emit("ip", ip, domain, line[:80])

    def _get_tech_category(self, tech_name):
        """Categorize technology"""
        categories = {
            'PHP': 'Language',
            'ASP.NET': 'Framework',
            'Apache': 'Web Server',
            'Nginx': 'Web Server',
            'IIS': 'Web Server',
            'WordPress': 'CMS',
            'jQuery': 'JavaScript Library',
            'React': 'Frontend Framework',
            'Vue.js': 'Frontend Framework',
            'Angular': 'Frontend Framework',
            'Bootstrap': 'CSS Framework',
            'MySQL': 'Database',
            'PostgreSQL': 'Database',
        }
        return categories.get(tech_name, 'Other')

    def _is_debug_message(self, line):
        """Check if line is a debug message that shouldn't be counted as finding

        Filters out:
        - Crawler stats: "Found X URLs", "Found X forms", "Found X AJAX endpoints"
        - Parsed parameters debug: "Parsed parameters: []"
        - Page discovery: "Found page with parameters"
        - Passive scanner stats: "Found X security header issues", "Found X cookie issues"
        - Form discovery: "Found form: POST/GET"
        - JavaScript files: "Found X JavaScript files"
        - Module INFO messages: "INFO - modules.xxx - Found X forms/targets/etc."

        Returns:
            bool: True if this is debug info, False if it's a real finding
        """
        line_lower = line.lower()

        # DEBUG patterns that should NOT be counted as findings
        debug_patterns = [
            # Module INFO messages - CRITICAL: Filter out all module informational logs
            r'info\s*-\s*modules\.',  # Matches "INFO - modules.xxx - ..."
            r'\[info\].*modules\.',  # Matches "[INFO] modules.xxx ..."
            r'found \d+ post forms',  # "Found 29 POST forms"
            r'found \d+ post targets',  # "Found 29 POST targets for stored XSS testing"
            r'found \d+ potential upload forms',  # "Found 30 potential upload forms"
            r'found \d+ potential login forms',  # "Found 23 potential login forms"
            r'found \d+ external js files',  # "Found 0 external JS files"
            r'found \d+ stateful',  # "Found X stateful GET forms"
            r'found \d+ get forms',  # "Found X GET forms"

            # Crawler debug messages - forms and parameters
            r'found form:\s*(get|post)',  # Matches "Found form: GET/POST..."
            r'parameters:\s*\[',  # Matches "Parameters: [...]"
            r'parsed parameters:',  # Matches "Parsed parameters: ..."
            r'found page with parameters',
            r'found page:',

            # Crawler stats (zero results)
            r'found 0 ajax endpoints',
            r'found 0 javascript files',
            r'found 0 urls',

            # Crawler summary messages (statistics)
            r'found \d+ javascript files',
            r'found \d+ urls to analyze',
            r'found \d+ pages with parameters',
            r'found \d+ forms',
            r'found \d+ ajax endpoints',

            # Passive scanner summary (should be aggregated, not per-page)
            r'found \d+ security header issues',
            r'found \d+ cookie security issues',
            r'found \d+ version disclosures',
            r'found \d+ api-related findings',
            r'found \d+ sensitive data leaks',

            # Empty messages or module summaries
            r'^\s*$',  # Empty lines
            r'module:\s*\w+\s*summary',  # "Module: PASSIVE SUMMARY"
        ]

        # Check if line matches any debug pattern
        import re
        for pattern in debug_patterns:
            if re.search(pattern, line_lower):
                return True

        return False

    def stop(self):
        """Stop the running scan"""
        if self.process:
            self.process.terminate()
