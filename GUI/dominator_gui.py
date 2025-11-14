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
        QProgressBar, QListWidget, QSplitter, QScrollArea, QFrame
    )
    from PyQt5.QtCore import Qt, QThread, pyqtSignal, QTimer
    from PyQt5.QtGui import QFont, QColor, QPalette, QIcon, QTextCursor
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

    def __init__(self, command):
        super().__init__()
        self.command = command
        self.process = None
        self.total_modules = 20  # Total available modules
        self.completed_modules = 0
        self.total_vulns = 0

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
        # Track module execution
        if 'Running module:' in line:
            module_name = line.split('Running module:')[-1].strip()
            self.progress_signal.emit(0, f"🔍 Testing: {module_name}")

        # Track module completion
        elif 'Module' in line and 'completed' in line:
            self.completed_modules += 1
            progress = int((self.completed_modules / self.total_modules) * 100)
            self.progress_signal.emit(progress, f"✓ Completed {self.completed_modules}/{self.total_modules} modules")
            self.stats_signal.emit(self.total_vulns, self.completed_modules, self.total_modules)

        # Track crawling progress
        elif 'Crawling:' in line or 'Found page:' in line or 'Form discovered:' in line:
            self.progress_signal.emit(0, "🕷️ Crawling target...")

        # Track target discovery
        elif 'Page discovery complete:' in line:
            try:
                targets = line.split('Page discovery complete:')[-1].strip()
                self.progress_signal.emit(0, f"📍 {targets}")
            except:
                pass

        # Track vulnerabilities found
        elif 'Found vulnerability:' in line or '[HIGH]' in line or '[CRITICAL]' in line or '[MEDIUM]' in line:
            self.total_vulns += 1
            # Determine severity
            severity = 'MEDIUM'
            if '[CRITICAL]' in line or 'Critical' in line:
                severity = 'CRITICAL'
            elif '[HIGH]' in line or 'High' in line:
                severity = 'HIGH'
            elif '[MEDIUM]' in line or 'Medium' in line:
                severity = 'MEDIUM'

            self.vulnerability_signal.emit(severity, line)
            self.stats_signal.emit(self.total_vulns, self.completed_modules, self.total_modules)

        # Track scan start
        elif 'Target:' in line and 'http' in line:
            target = line.split('Target:')[-1].strip()
            self.progress_signal.emit(0, f"🎯 Scanning: {target}")

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
        self.setWindowTitle("🎯 Dominator Web Vulnerability Scanner")
        self.setGeometry(100, 100, 1400, 900)

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
        self.tabs.addTab(scan_tab, "🎯 Scan Configuration")

        # Advanced Options Tab
        advanced_tab = self.create_advanced_tab()
        self.tabs.addTab(advanced_tab, "⚙️ Advanced Options")

        # Output Tab
        output_tab = self.create_output_tab()
        self.tabs.addTab(output_tab, "📊 Scan Output")

        # Results Tab
        results_tab = self.create_results_tab()
        self.tabs.addTab(results_tab, "🔍 Results")

        main_layout.addWidget(self.tabs)

        # Status bar
        self.statusBar().showMessage("Ready to scan")
        self.statusBar().setStyleSheet("background-color: #2b2b2b; color: #00ff00; padding: 5px;")

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

        title = QLabel("🎯 DOMINATOR")
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
        target_group = QGroupBox("🎯 Target Configuration")
        target_layout = QGridLayout()

        # Target URL
        target_layout.addWidget(QLabel("Target URL:"), 0, 0)
        self.target_input = QLineEdit()
        self.target_input.setPlaceholderText("http://example.com or multiple URLs separated by commas")
        target_layout.addWidget(self.target_input, 0, 1, 1, 2)

        # Target File
        target_layout.addWidget(QLabel("Or Target File:"), 1, 0)
        self.target_file_input = QLineEdit()
        self.target_file_input.setPlaceholderText("Path to file with targets (one per line)")
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

        crawler_group.setLayout(crawler_layout)
        layout.addWidget(crawler_group)

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

    def build_command(self):
        """Build the scanner command"""
        # Get parent directory (where main.py is)
        parent_dir = Path(__file__).parent.parent
        main_script = parent_dir / "main.py"

        command = [sys.executable, str(main_script)]

        # Target
        if self.target_file_input.text():
            command.extend(["-f", self.target_file_input.text()])
        elif self.target_input.text():
            command.extend(["-t", self.target_input.text()])
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

        # HTTP config
        if self.cookies_input.text():
            command.extend(["-c", self.cookies_input.text()])

        # Crawler
        command.extend(["--max-crawl-pages", str(self.max_crawl_spin.value())])

        return command

    def start_scan(self):
        """Start the vulnerability scan"""
        command = self.build_command()
        if not command:
            self.output_console.append("ERROR: Please specify a target URL or file")
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
        self.tabs.tabBar().setTabTextColor(3, QColor('white'))

        # Start scan thread
        self.scan_thread = ScanThread(command)
        self.scan_thread.output_signal.connect(self.append_output)
        self.scan_thread.finished_signal.connect(self.scan_finished)
        self.scan_thread.progress_signal.connect(self.update_progress)
        self.scan_thread.vulnerability_signal.connect(self.add_vulnerability)
        self.scan_thread.stats_signal.connect(self.update_stats)
        self.scan_thread.start()

        # Switch to output tab to show progress
        self.tabs.setCurrentIndex(2)  # Switch to "Scan Output" tab

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
            self.tabs.setCurrentIndex(3)
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
        self.tabs.tabBar().setTabTextColor(3, QColor('#ff0000'))

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
