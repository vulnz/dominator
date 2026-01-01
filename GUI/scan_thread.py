#!/usr/bin/env python3
"""
Scan Thread - Background thread for running vulnerability scans
"""

import sys
import os
import subprocess
import re
import threading
import time
import json
from pathlib import Path

from PyQt5.QtCore import QThread, pyqtSignal, QTimer


class ScanThread(QThread):
    """Background thread for running scans"""
    output_signal = pyqtSignal(str)
    finished_signal = pyqtSignal(int)
    progress_signal = pyqtSignal(int, str)
    vulnerability_signal = pyqtSignal(str, str)  # (severity, description) - legacy
    vulnerability_data_signal = pyqtSignal(str, str, str, str, object)  # (severity, description, module, target, finding_data)
    stats_signal = pyqtSignal(int, int, int)  # (total, modules_done, modules_total)
    resource_signal = pyqtSignal(str, str, str, str)  # (type, value, extra, source)
    scope_signal = pyqtSignal(str, str, str, str)  # (type, data1, data2, data3)
    report_signal = pyqtSignal(str)  # (report_filename) - emitted when report is saved
    time_signal = pyqtSignal(int, int)  # (elapsed_seconds, remaining_seconds)
    profile_signal = pyqtSignal(object)  # (target_profile_dict) - target profiling data

    def __init__(self, command, module_count=None, max_time=None):
        super().__init__()
        self.command = command
        self.process = None
        self.max_time = max_time or 0  # Max time in minutes (0 = unlimited)
        self.start_time = None  # Will be set when scan starts

        # Calculate total modules from command or use provided count
        if module_count is not None:
            self.total_modules = module_count
        elif "--all" in command:
            # Count actual modules from modules/ directory
            self.total_modules = self._count_available_modules()
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
            # Default to all modules
            self.total_modules = self._count_available_modules()
        self.completed_modules = 0
        self.total_vulns = 0
        self.current_severity = 'MEDIUM'  # Track current severity section
        self.paused = False
        self._pause_event = threading.Event()
        self._pause_event.set()  # Not paused initially
        self._module_names = set()  # Track unique modules to avoid duplicate counting

    def _count_available_modules(self):
        """Count available modules from modules/ directory"""
        try:
            modules_dir = Path(__file__).parent.parent / "modules"
            if modules_dir.exists():
                count = 0
                for item in modules_dir.iterdir():
                    if item.is_dir() and not item.name.startswith('_'):
                        module_file = item / "module.py"
                        if module_file.exists() and item.name != 'oob_detection':
                            count += 1
                return max(count, 1)
        except:
            pass
        return 20  # Fallback

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
            # Record start time for time tracking
            self.start_time = time.time()
            self._last_time_emit = 0

            # Get parent directory (where main.py and modules/ are)
            parent_dir = Path(__file__).parent.parent

            # Hide console window on Windows - use multiple methods for reliability
            creation_flags = 0
            startupinfo = None

            if sys.platform == 'win32':
                # AGGRESSIVE window hiding for Windows - prevent ANY console window
                # CREATE_NO_WINDOW is the key flag that prevents console windows
                CREATE_NO_WINDOW = 0x08000000
                creation_flags = CREATE_NO_WINDOW

                # Configure STARTUPINFO for additional window hiding
                startupinfo = subprocess.STARTUPINFO()
                startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
                startupinfo.wShowWindow = 0  # SW_HIDE = 0

                # NOTE: Do NOT use pythonw.exe - it breaks stdout capture
                # CREATE_NO_WINDOW flag is sufficient and works with regular python.exe

            # Force Python to run unbuffered (-u flag) to ensure real-time output capture
            env = os.environ.copy()
            env['PYTHONUNBUFFERED'] = '1'

            # Insert -u flag after python to force unbuffered output
            command = list(self.command)
            if command and ('python' in command[0].lower()):
                # Add -u flag right after python executable if not already present
                if len(command) > 1 and command[1] != '-u':
                    command.insert(1, '-u')
            self.command = command

            self.process = subprocess.Popen(
                self.command,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=0,  # Unbuffered for real-time output
                universal_newlines=True,
                encoding='utf-8',
                errors='ignore',
                cwd=str(parent_dir),  # Set working directory to scanner root
                creationflags=creation_flags,  # Hide console window
                startupinfo=startupinfo,  # Additional window hiding
                env=env  # Use modified environment with unbuffered Python
            )

            for line in iter(self.process.stdout.readline, ''):
                # Check for pause
                self._pause_event.wait()

                if line:
                    line_clean = line.strip()
                    self.output_signal.emit(line_clean)

                    # Parse different types of output
                    self.parse_scan_output(line_clean)

                    # Emit time signal every second
                    self._emit_time_update()

            self.process.wait()
            self.finished_signal.emit(self.process.returncode)

        except Exception as e:
            self.output_signal.emit(f"ERROR: {str(e)}")
            self.finished_signal.emit(-1)

    def _emit_time_update(self):
        """Emit time elapsed and remaining signals"""
        if not self.start_time:
            return

        current_time = time.time()
        elapsed = int(current_time - self.start_time)

        # Only emit once per second to avoid flooding
        if elapsed == self._last_time_emit:
            return
        self._last_time_emit = elapsed

        # Calculate remaining time if max_time is set
        if self.max_time > 0:
            max_seconds = self.max_time * 60
            remaining = max(0, max_seconds - elapsed)
        else:
            remaining = -1  # Unlimited

        self.time_signal.emit(elapsed, remaining)

    def parse_scan_output(self, line):
        """Parse scanner output for progress and findings"""
        # Strip ALL ANSI color codes (more robust pattern)
        line_clean = re.sub(r'\x1b\[[0-9;]*[a-zA-Z]', '', line)
        line_clean = line_clean.strip()

        # Parse JSON findings from scanner (GUI_FINDING_JSON:{...})
        # This provides full finding data including request, response, evidence, remediation
        if line_clean.startswith('GUI_FINDING_JSON:'):
            try:
                json_str = line_clean[len('GUI_FINDING_JSON:'):]
                finding_data = json.loads(json_str)

                # Extract key fields
                severity = finding_data.get('severity', 'Medium').upper()
                vuln_type = finding_data.get('type', 'Unknown')
                module = finding_data.get('module', '')
                url = finding_data.get('url', '')
                description = finding_data.get('description', vuln_type)

                # Emit the full finding data signal
                self.vulnerability_data_signal.emit(
                    severity,
                    description,
                    module,
                    url,
                    finding_data  # Full data including request, response, evidence, remediation
                )

                # Don't emit regular vulnerability_signal - data signal covers it
                return  # Skip other parsing for this line

            except json.JSONDecodeError as e:
                # Fall through to normal parsing if JSON is invalid
                pass
            except Exception as e:
                pass

        # Parse target profile data (GUI_PROFILE_JSON:{...})
        # This provides pre-scan intelligence about the target
        if line_clean.startswith('GUI_PROFILE_JSON:'):
            try:
                json_str = line_clean[len('GUI_PROFILE_JSON:'):]
                profile_data = json.loads(json_str)
                self.profile_signal.emit(profile_data)
                return
            except json.JSONDecodeError:
                pass
            except Exception:
                pass

        # Detect resources (emails, phones, social media, leaked keys)
        self.detect_resources(line_clean)

        # Detect scope info (technologies, titles, IPs)
        self.detect_scope_info(line_clean)

        # Track module execution - "Running module: ModuleName"
        if 'Running module:' in line_clean:
            module_name = line_clean.split('Running module:')[-1].strip()
            # Calculate progress based on started modules
            current_progress = int((self.completed_modules / max(self.total_modules, 1)) * 100)
            self.progress_signal.emit(current_progress, f"Running: {module_name}")

        # Track module completion - "Module 'name' completed: X findings (Y vulnerabilities)"
        elif "completed:" in line_clean and ("Module" in line_clean or "module" in line_clean):
            # Extract module name and vulnerability count
            try:
                import re as regex
                # Extract module name
                name_match = regex.search(r"Module\s*'([^']+)'", line_clean, regex.IGNORECASE)
                if name_match:
                    module_name = name_match.group(1)
                    # Avoid double counting same module
                    if module_name not in self._module_names:
                        self._module_names.add(module_name)
                        self.completed_modules += 1

                        # Extract vulnerability count from "(Y vulnerabilities)"
                        vuln_match = regex.search(r'\((\d+)\s*vulnerabilit', line_clean, regex.IGNORECASE)
                        if vuln_match:
                            vuln_count = int(vuln_match.group(1))
                            if vuln_count > 0:
                                self.total_vulns += vuln_count
                                # Emit vulnerability signal for each module with findings
                                severity = 'MEDIUM'
                                if any(x in module_name.lower() for x in ['sqli', 'sql', 'rce', 'cmdi', 'command']):
                                    severity = 'CRITICAL'
                                elif any(x in module_name.lower() for x in ['xss', 'ssrf', 'xxe', 'ssti']):
                                    severity = 'HIGH'
                                elif any(x in module_name.lower() for x in ['info', 'disclosure', 'header']):
                                    severity = 'LOW'

                                self.vulnerability_signal.emit(severity, f"[{module_name}] {vuln_count} vulnerabilities found")
                else:
                    self.completed_modules += 1
            except:
                self.completed_modules += 1

            progress = int((self.completed_modules / max(self.total_modules, 1)) * 100)
            progress = min(progress, 99)  # Never show 100% until truly finished
            self.progress_signal.emit(progress, f"Completed {self.completed_modules}/{self.total_modules} modules")
            self.stats_signal.emit(self.total_vulns, self.completed_modules, self.total_modules)

        # Track crawling progress
        elif 'Crawling:' in line_clean or 'Form discovered:' in line_clean:
            self.progress_signal.emit(0, "Crawling target...")

        # Track target discovery
        elif 'Page discovery complete:' in line_clean:
            try:
                targets = line_clean.split('Page discovery complete:')[-1].strip()
                self.progress_signal.emit(0, f"{targets}")
            except:
                pass

        # NOTE: Vulnerability counting is done ONLY from module completion messages above
        # Format: "Module 'xxx' completed: X findings (Y vulnerabilities)"
        # This is the single source of truth for vulnerability counts

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

    # Technology category mappings (class-level constant)
    _TECH_CATEGORIES = {
        'PHP': 'Language', 'ASP.NET': 'Framework',
        'Apache': 'Web Server', 'Nginx': 'Web Server', 'IIS': 'Web Server',
        'WordPress': 'CMS', 'jQuery': 'JavaScript Library',
        'React': 'Frontend Framework', 'Vue.js': 'Frontend Framework', 'Angular': 'Frontend Framework',
        'Bootstrap': 'CSS Framework', 'MySQL': 'Database', 'PostgreSQL': 'Database',
    }

    def _get_tech_category(self, tech_name):
        """Categorize technology"""
        return self._TECH_CATEGORIES.get(tech_name, 'Other')

    # Pre-compiled debug patterns for _is_debug_message (class-level for performance)
    _DEBUG_PATTERNS = [re.compile(p) for p in [
        r'info\s*-\s*modules\.', r'\[info\].*modules\.',
        r'found \d+ post forms', r'found \d+ post targets',
        r'found \d+ potential upload forms', r'found \d+ potential login forms',
        r'found \d+ external js files', r'found \d+ stateful', r'found \d+ get forms',
        r'found form:\s*(get|post)', r'parameters:\s*\[', r'parsed parameters:',
        r'found page with parameters', r'found page:',
        r'found 0 ajax endpoints', r'found 0 javascript files', r'found 0 urls',
        r'found \d+ javascript files', r'found \d+ urls to analyze',
        r'found \d+ pages with parameters', r'found \d+ forms', r'found \d+ ajax endpoints',
        r'found \d+ security header issues', r'found \d+ cookie security issues',
        r'found \d+ version disclosures', r'found \d+ api-related findings',
        r'found \d+ sensitive data leaks', r'^\s*$', r'module:\s*\w+\s*summary',
    ]]

    def _is_debug_message(self, line):
        """Check if line is a debug message that shouldn't be counted as finding"""
        line_lower = line.lower()
        return any(pattern.search(line_lower) for pattern in self._DEBUG_PATTERNS)

    def stop(self):
        """Stop the running scan"""
        if self.process:
            self.process.terminate()

    def skip_module(self):
        """Skip the current module being executed

        Creates a signal file that the scanner checks to skip current module.
        """
        import os
        from pathlib import Path

        try:
            # Create signal file in scanner root directory
            signal_file = Path(__file__).parent.parent / ".skip_module"
            signal_file.write_text("skip", encoding='utf-8')
            return True
        except Exception as e:
            print(f"Error creating skip signal: {e}")
            return False
