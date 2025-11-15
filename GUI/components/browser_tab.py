"""
Browser Integration Tab - Burp Suite-like functionality
Provides HTTP proxy, request interception, modification, and passive scanning
"""

from PyQt5.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QPushButton, QLabel,
    QTableWidget, QTableWidgetItem, QTextEdit, QSplitter,
    QCheckBox, QSpinBox, QGroupBox, QComboBox, QHeaderView,
    QMessageBox, QDialog, QDialogButtonBox, QTabWidget, QProgressDialog
)
from PyQt5.QtCore import Qt, pyqtSignal, QThread
from PyQt5.QtGui import QColor, QFont
import json
from datetime import datetime
from utils.chromium_manager import get_chromium_manager


class BrowserTab(QWidget):
    """Browser integration tab with proxy and interception"""

    # Signal to communicate with main scanner
    scan_page_requested = pyqtSignal(str, list)  # url, module_names

    def __init__(self, parent=None):
        super().__init__(parent)
        self.proxy = None
        self.selected_modules = []
        self.init_ui()

    def init_ui(self):
        """Initialize the browser tab UI"""
        layout = QVBoxLayout()

        # === Top Control Panel ===
        control_panel = self._create_control_panel()
        layout.addWidget(control_panel)

        # === Main Splitter (History + Details) ===
        splitter = QSplitter(Qt.Vertical)

        # Request History Table
        history_group = self._create_history_table()
        splitter.addWidget(history_group)

        # Request/Response Details
        details_group = self._create_details_panel()
        splitter.addWidget(details_group)

        # Set splitter sizes (60% history, 40% details)
        splitter.setSizes([600, 400])
        layout.addWidget(splitter)

        # === Bottom Findings Panel ===
        findings_group = self._create_findings_panel()
        layout.addWidget(findings_group)

        self.setLayout(layout)

    def _create_control_panel(self):
        """Create top control panel with proxy controls and browser launch"""
        group = QGroupBox("Browser & Proxy Controls")
        layout = QVBoxLayout()

        # Row 1: Proxy controls
        proxy_row = QHBoxLayout()

        self.proxy_status_label = QLabel("⚫ Proxy: Stopped")
        self.proxy_status_label.setStyleSheet("color: red; font-weight: bold;")
        proxy_row.addWidget(self.proxy_status_label)

        self.proxy_port_spin = QSpinBox()
        self.proxy_port_spin.setRange(1024, 65535)
        self.proxy_port_spin.setValue(8080)
        self.proxy_port_spin.setPrefix("Port: ")
        proxy_row.addWidget(self.proxy_port_spin)

        self.start_proxy_btn = QPushButton("▶ Start Proxy")
        self.start_proxy_btn.clicked.connect(self.toggle_proxy)
        self.start_proxy_btn.setStyleSheet("background-color: #4CAF50; color: white; font-weight: bold;")
        proxy_row.addWidget(self.start_proxy_btn)

        self.intercept_checkbox = QCheckBox("Enable Intercept")
        self.intercept_checkbox.setChecked(False)
        self.intercept_checkbox.stateChanged.connect(self.toggle_intercept)
        proxy_row.addWidget(self.intercept_checkbox)

        self.passive_scan_checkbox = QCheckBox("Passive Scanning")
        self.passive_scan_checkbox.setChecked(True)
        self.passive_scan_checkbox.stateChanged.connect(self.toggle_passive_scan)
        proxy_row.addWidget(self.passive_scan_checkbox)

        proxy_row.addStretch()
        layout.addLayout(proxy_row)

        # Row 2: Browser launch and scan controls
        browser_row = QHBoxLayout()

        self.launch_browser_btn = QPushButton("🌐 Launch Chrome Browser")
        self.launch_browser_btn.clicked.connect(self.launch_browser)
        self.launch_browser_btn.setEnabled(False)
        browser_row.addWidget(self.launch_browser_btn)

        browser_row.addWidget(QLabel("Scan Selected Page:"))

        self.scan_modules_combo = QComboBox()
        self.scan_modules_combo.addItems([
            "All Modules",
            "XSS Only",
            "SQLi Only",
            "LFI Only",
            "SSTI Only",
            "CMDi Only",
            "SSRF Only",
            "Critical Modules (XSS, SQLi, LFI)"
        ])
        browser_row.addWidget(self.scan_modules_combo)

        self.scan_page_btn = QPushButton("🔍 Scan This Page")
        self.scan_page_btn.clicked.connect(self.scan_selected_page)
        self.scan_page_btn.setEnabled(False)
        browser_row.addWidget(self.scan_page_btn)

        self.clear_history_btn = QPushButton("🗑 Clear History")
        self.clear_history_btn.clicked.connect(self.clear_history)
        browser_row.addWidget(self.clear_history_btn)

        browser_row.addStretch()
        layout.addLayout(browser_row)

        # Row 3: Proxy configuration instructions
        info_label = QLabel(
            "ℹ️ Configure your browser to use proxy: 127.0.0.1:" + str(self.proxy_port_spin.value()) +
            " | Click 'Launch Chrome' to auto-configure"
        )
        info_label.setStyleSheet("color: #666; font-size: 10pt;")
        layout.addWidget(info_label)

        group.setLayout(layout)
        return group

    def _create_history_table(self):
        """Create request history table"""
        group = QGroupBox("Request History")
        layout = QVBoxLayout()

        self.history_table = QTableWidget()
        self.history_table.setColumnCount(7)
        self.history_table.setHorizontalHeaderLabels([
            "#", "Time", "Method", "URL", "Status", "Length", "Notes"
        ])

        # Set column widths
        header = self.history_table.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.ResizeToContents)  # ID
        header.setSectionResizeMode(1, QHeaderView.ResizeToContents)  # Time
        header.setSectionResizeMode(2, QHeaderView.ResizeToContents)  # Method
        header.setSectionResizeMode(3, QHeaderView.Stretch)           # URL
        header.setSectionResizeMode(4, QHeaderView.ResizeToContents)  # Status
        header.setSectionResizeMode(5, QHeaderView.ResizeToContents)  # Length
        header.setSectionResizeMode(6, QHeaderView.ResizeToContents)  # Notes

        self.history_table.setSelectionBehavior(QTableWidget.SelectRows)
        self.history_table.setEditTriggers(QTableWidget.NoEditTriggers)
        self.history_table.itemSelectionChanged.connect(self.on_history_selection_changed)

        # Context menu for replay
        self.history_table.setContextMenuPolicy(Qt.ActionsContextMenu)

        layout.addWidget(self.history_table)

        # Stats row
        stats_row = QHBoxLayout()
        self.history_count_label = QLabel("Total Requests: 0")
        stats_row.addWidget(self.history_count_label)
        stats_row.addStretch()
        layout.addLayout(stats_row)

        group.setLayout(layout)
        return group

    def _create_details_panel(self):
        """Create request/response details panel"""
        group = QGroupBox("Request/Response Details")
        layout = QVBoxLayout()

        # Tabs for Request and Response
        self.details_tabs = QTabWidget()

        # Request tab
        self.request_text = QTextEdit()
        self.request_text.setReadOnly(True)
        self.request_text.setFont(QFont("Courier New", 9))
        self.details_tabs.addTab(self.request_text, "Request")

        # Response tab
        self.response_text = QTextEdit()
        self.response_text.setReadOnly(True)
        self.response_text.setFont(QFont("Courier New", 9))
        self.details_tabs.addTab(self.response_text, "Response")

        layout.addWidget(self.details_tabs)

        # Action buttons
        actions_row = QHBoxLayout()

        self.replay_btn = QPushButton("↻ Replay Request")
        self.replay_btn.clicked.connect(self.replay_selected_request)
        self.replay_btn.setEnabled(False)
        actions_row.addWidget(self.replay_btn)

        self.modify_replay_btn = QPushButton("✏ Modify & Replay")
        self.modify_replay_btn.clicked.connect(self.modify_and_replay)
        self.modify_replay_btn.setEnabled(False)
        actions_row.addWidget(self.modify_replay_btn)

        actions_row.addStretch()
        layout.addLayout(actions_row)

        group.setLayout(layout)
        return group

    def _create_findings_panel(self):
        """Create passive scan findings panel"""
        group = QGroupBox("Passive Scan Findings")
        layout = QVBoxLayout()

        self.findings_table = QTableWidget()
        self.findings_table.setColumnCount(5)
        self.findings_table.setHorizontalHeaderLabels([
            "Severity", "Type", "URL", "Evidence", "Description"
        ])
        self.findings_table.setMaximumHeight(150)

        # Set column widths
        header = self.findings_table.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.ResizeToContents)
        header.setSectionResizeMode(1, QHeaderView.ResizeToContents)
        header.setSectionResizeMode(2, QHeaderView.Stretch)
        header.setSectionResizeMode(3, QHeaderView.ResizeToContents)
        header.setSectionResizeMode(4, QHeaderView.Stretch)

        layout.addWidget(self.findings_table)

        # Stats
        self.findings_count_label = QLabel("Passive Findings: 0")
        layout.addWidget(self.findings_count_label)

        group.setLayout(layout)
        return group

    def toggle_proxy(self):
        """Start or stop the proxy server"""
        if self.proxy is None or not self.proxy.running:
            # Start proxy
            from utils.intercept_proxy import InterceptingProxy

            port = self.proxy_port_spin.value()
            self.proxy = InterceptingProxy(port=port)

            # Connect signals
            self.proxy.request_intercepted.connect(self.on_request_intercepted)
            self.proxy.response_received.connect(self.on_response_received)
            self.proxy.passive_finding.connect(self.on_passive_finding)

            # Start proxy
            message = self.proxy.start()

            # Update UI
            self.proxy_status_label.setText("🟢 Proxy: Running")
            self.proxy_status_label.setStyleSheet("color: green; font-weight: bold;")
            self.start_proxy_btn.setText("⏹ Stop Proxy")
            self.start_proxy_btn.setStyleSheet("background-color: #f44336; color: white; font-weight: bold;")
            self.launch_browser_btn.setEnabled(True)
            self.scan_page_btn.setEnabled(True)
            self.proxy_port_spin.setEnabled(False)

            QMessageBox.information(self, "Proxy Started", message)
        else:
            # Stop proxy
            self.proxy.stop()

            # Update UI
            self.proxy_status_label.setText("⚫ Proxy: Stopped")
            self.proxy_status_label.setStyleSheet("color: red; font-weight: bold;")
            self.start_proxy_btn.setText("▶ Start Proxy")
            self.start_proxy_btn.setStyleSheet("background-color: #4CAF50; color: white; font-weight: bold;")
            self.launch_browser_btn.setEnabled(False)
            self.scan_page_btn.setEnabled(False)
            self.proxy_port_spin.setEnabled(True)

            QMessageBox.information(self, "Proxy Stopped", "Proxy server has been stopped")

    def toggle_intercept(self, state):
        """Enable or disable request interception"""
        if self.proxy:
            self.proxy.intercept_enabled = (state == Qt.Checked)

    def toggle_passive_scan(self, state):
        """Enable or disable passive scanning"""
        if self.proxy:
            self.proxy.passive_scan_enabled = (state == Qt.Checked)

    def launch_browser(self):
        """Launch Chromium browser with proxy configuration"""
        port = self.proxy_port_spin.value()
        chromium_mgr = get_chromium_manager()

        # Check if Chromium is installed
        if not chromium_mgr.is_installed():
            # Ask user if they want to download
            reply = QMessageBox.question(
                self,
                "Download Chromium?",
                f"Portable Chromium not found.\n\n"
                f"Download size: ~{chromium_mgr.get_download_size_mb()} MB\n\n"
                f"Download now? (Or use system Chrome as fallback)",
                QMessageBox.Yes | QMessageBox.No | QMessageBox.Cancel,
                QMessageBox.Yes
            )

            if reply == QMessageBox.Yes:
                # Show progress dialog
                progress = QProgressDialog("Downloading Chromium...", "Cancel", 0, 100, self)
                progress.setWindowModality(Qt.WindowModal)
                progress.setAutoClose(True)
                progress.setAutoReset(True)

                def progress_callback(msg, percent):
                    progress.setLabelText(msg)
                    progress.setValue(percent)
                    QMessageBox.qApp.processEvents()

                try:
                    chromium_mgr.download(progress_callback=progress_callback)
                    progress.close()
                    QMessageBox.information(
                        self,
                        "Download Complete",
                        "Chromium downloaded successfully!"
                    )
                except Exception as e:
                    progress.close()
                    QMessageBox.critical(
                        self,
                        "Download Failed",
                        f"Failed to download Chromium:\n{str(e)}\n\n"
                        "Falling back to system Chrome..."
                    )

            elif reply == QMessageBox.Cancel:
                return

        # Launch browser
        try:
            chromium_mgr.launch_with_fallback(proxy_host='127.0.0.1', proxy_port=port)

            browser_type = "Chromium" if chromium_mgr.is_installed() else "Chrome"
            QMessageBox.information(
                self,
                "Browser Launched",
                f"{browser_type} launched with proxy: 127.0.0.1:{port}\n\n"
                "All requests will be intercepted and logged."
            )
        except Exception as e:
            QMessageBox.critical(
                self,
                "Launch Failed",
                f"Failed to launch browser:\n{str(e)}\n\n"
                "Please manually configure your browser:\n"
                f"Proxy: 127.0.0.1:{port}"
            )

    def on_request_intercepted(self, request_data):
        """Handle intercepted request - show intercept dialog"""
        dialog = InterceptDialog(request_data, self)
        result = dialog.exec_()

        request_id = request_data['id']

        if result == QDialog.Accepted:
            action = dialog.get_action()
            if action == 'forward':
                self.proxy.forward_request(request_id)
            elif action == 'drop':
                self.proxy.drop_request(request_id)
            elif action == 'modify':
                modified = dialog.get_modified_request()
                self.proxy.modify_and_forward(request_id, modified)
        else:
            # Dialog closed - forward by default
            self.proxy.forward_request(request_id)

    def on_response_received(self, data):
        """Handle received response - add to history"""
        request = data['request']
        response = data['response']

        # Add to history table
        row = self.history_table.rowCount()
        self.history_table.insertRow(row)

        # ID
        self.history_table.setItem(row, 0, QTableWidgetItem(str(request['id'])))

        # Time
        time_str = datetime.fromtimestamp(request['timestamp']).strftime('%H:%M:%S')
        self.history_table.setItem(row, 1, QTableWidgetItem(time_str))

        # Method
        method_item = QTableWidgetItem(request['method'])
        if request['method'] == 'POST':
            method_item.setBackground(QColor('#FFF3E0'))
        self.history_table.setItem(row, 2, method_item)

        # URL
        self.history_table.setItem(row, 3, QTableWidgetItem(request['url']))

        # Status
        status_item = QTableWidgetItem(str(response['status_code']))
        if 200 <= response['status_code'] < 300:
            status_item.setForeground(QColor('green'))
        elif 300 <= response['status_code'] < 400:
            status_item.setForeground(QColor('blue'))
        elif 400 <= response['status_code'] < 500:
            status_item.setForeground(QColor('orange'))
        else:
            status_item.setForeground(QColor('red'))
        self.history_table.setItem(row, 4, status_item)

        # Length
        length = len(response.get('body', b''))
        self.history_table.setItem(row, 5, QTableWidgetItem(f"{length} B"))

        # Notes
        self.history_table.setItem(row, 6, QTableWidgetItem(""))

        # Store full data in row
        self.history_table.item(row, 0).setData(Qt.UserRole, data)

        # Update count
        self.history_count_label.setText(f"Total Requests: {row + 1}")

        # Auto-scroll to bottom
        self.history_table.scrollToBottom()

    def on_passive_finding(self, finding):
        """Handle passive scan finding"""
        row = self.findings_table.rowCount()
        self.findings_table.insertRow(row)

        # Severity
        severity_item = QTableWidgetItem(finding['severity'])
        if finding['severity'] == 'Critical':
            severity_item.setBackground(QColor('#ff0000'))
            severity_item.setForeground(QColor('white'))
        elif finding['severity'] == 'High':
            severity_item.setBackground(QColor('#ff6600'))
            severity_item.setForeground(QColor('white'))
        elif finding['severity'] == 'Medium':
            severity_item.setBackground(QColor('#ffcc00'))
        elif finding['severity'] == 'Low':
            severity_item.setBackground(QColor('#ffff99'))
        else:
            severity_item.setBackground(QColor('#e0e0e0'))
        self.findings_table.setItem(row, 0, severity_item)

        # Type
        self.findings_table.setItem(row, 1, QTableWidgetItem(finding['type']))

        # URL
        self.findings_table.setItem(row, 2, QTableWidgetItem(finding['url']))

        # Evidence
        evidence = finding['evidence'][:100] + '...' if len(finding['evidence']) > 100 else finding['evidence']
        self.findings_table.setItem(row, 3, QTableWidgetItem(evidence))

        # Description
        self.findings_table.setItem(row, 4, QTableWidgetItem(finding['description']))

        # Update count
        self.findings_count_label.setText(f"Passive Findings: {row + 1}")

    def on_history_selection_changed(self):
        """Handle history table selection change"""
        selected = self.history_table.selectedItems()
        if not selected:
            self.replay_btn.setEnabled(False)
            self.modify_replay_btn.setEnabled(False)
            return

        row = selected[0].row()
        data = self.history_table.item(row, 0).data(Qt.UserRole)

        if data:
            # Show request
            request = data['request']
            request_text = f"{request['method']} {request['url']}\n"
            for header, value in request['headers'].items():
                request_text += f"{header}: {value}\n"
            request_text += f"\n{request['body']}"
            self.request_text.setPlainText(request_text)

            # Show response
            response = data['response']
            response_text = f"HTTP/1.1 {response['status_code']}\n"
            for header, value in response['headers'].items():
                response_text += f"{header}: {value}\n"
            response_text += f"\n{response.get('text', '')}"
            self.response_text.setPlainText(response_text)

            self.replay_btn.setEnabled(True)
            self.modify_replay_btn.setEnabled(True)

    def replay_selected_request(self):
        """Replay the selected request"""
        selected = self.history_table.selectedItems()
        if not selected:
            return

        row = selected[0].row()
        data = self.history_table.item(row, 0).data(Qt.UserRole)

        if data and self.proxy:
            request = data['request']
            response = self.proxy.replay_request(request)

            if 'error' in response:
                QMessageBox.critical(self, "Replay Failed", f"Error: {response['error']}")
            else:
                QMessageBox.information(
                    self,
                    "Request Replayed",
                    f"Status: {response['status_code']}\n"
                    f"Length: {len(response.get('body', b''))} bytes"
                )

    def modify_and_replay(self):
        """Open dialog to modify and replay request"""
        selected = self.history_table.selectedItems()
        if not selected:
            return

        row = selected[0].row()
        data = self.history_table.item(row, 0).data(Qt.UserRole)

        if data:
            request = data['request']
            dialog = ModifyRequestDialog(request, self)
            if dialog.exec_() == QDialog.Accepted:
                modified = dialog.get_modified_request()
                if self.proxy:
                    response = self.proxy.replay_request(modified)
                    if 'error' in response:
                        QMessageBox.critical(self, "Replay Failed", f"Error: {response['error']}")
                    else:
                        QMessageBox.information(
                            self,
                            "Modified Request Sent",
                            f"Status: {response['status_code']}\n"
                            f"Length: {len(response.get('body', b''))} bytes"
                        )

    def scan_selected_page(self):
        """Scan the currently selected page with chosen modules"""
        selected = self.history_table.selectedItems()
        if not selected:
            QMessageBox.warning(self, "No Selection", "Please select a request from history to scan")
            return

        row = selected[0].row()
        data = self.history_table.item(row, 0).data(Qt.UserRole)

        if data:
            url = data['request']['url']

            # Get module selection
            modules_choice = self.scan_modules_combo.currentText()
            if modules_choice == "All Modules":
                modules = []  # Empty means all
            elif modules_choice == "Critical Modules (XSS, SQLi, LFI)":
                modules = ['xss', 'sqli', 'lfi']
            else:
                module_name = modules_choice.split()[0].lower()
                modules = [module_name]

            # Emit signal to main GUI
            self.scan_page_requested.emit(url, modules)

            QMessageBox.information(
                self,
                "Scan Started",
                f"Starting scan of:\n{url}\n\nModules: {modules_choice}"
            )

    def clear_history(self):
        """Clear request history"""
        reply = QMessageBox.question(
            self,
            "Clear History",
            "Are you sure you want to clear all request history?",
            QMessageBox.Yes | QMessageBox.No
        )

        if reply == QMessageBox.Yes:
            self.history_table.setRowCount(0)
            self.history_count_label.setText("Total Requests: 0")

            if self.proxy:
                self.proxy.clear_history()


class InterceptDialog(QDialog):
    """Dialog for intercepting and modifying requests"""

    def __init__(self, request_data, parent=None):
        super().__init__(parent)
        self.request_data = request_data
        self.action = 'forward'
        self.init_ui()

    def init_ui(self):
        """Initialize intercept dialog UI"""
        self.setWindowTitle(f"Intercept Request #{self.request_data['id']}")
        self.resize(800, 600)

        # Set light theme for dialog
        self.setStyleSheet("""
            QDialog {
                background-color: #f0f0f0;
                color: black;
            }
            QLabel {
                color: black;
            }
            QTextEdit {
                background-color: white;
                color: black;
                border: 2px solid #cccccc;
                border-radius: 4px;
                padding: 5px;
            }
        """)

        layout = QVBoxLayout()

        # Request details
        info_label = QLabel(
            f"<b>Method:</b> {self.request_data['method']} | "
            f"<b>URL:</b> {self.request_data['url']}"
        )
        layout.addWidget(info_label)

        # Request editor
        self.request_edit = QTextEdit()
        request_text = f"{self.request_data['method']} {self.request_data['url']}\n"
        for header, value in self.request_data['headers'].items():
            request_text += f"{header}: {value}\n"
        request_text += f"\n{self.request_data['body']}"
        self.request_edit.setPlainText(request_text)
        self.request_edit.setFont(QFont("Courier New", 9))
        layout.addWidget(self.request_edit)

        # Buttons
        button_layout = QHBoxLayout()

        forward_btn = QPushButton("✓ Forward")
        forward_btn.clicked.connect(lambda: self.set_action('forward'))
        forward_btn.setStyleSheet("background-color: #4CAF50; color: white;")
        button_layout.addWidget(forward_btn)

        modify_btn = QPushButton("✏ Modify & Forward")
        modify_btn.clicked.connect(lambda: self.set_action('modify'))
        modify_btn.setStyleSheet("background-color: #2196F3; color: white;")
        button_layout.addWidget(modify_btn)

        drop_btn = QPushButton("✗ Drop")
        drop_btn.clicked.connect(lambda: self.set_action('drop'))
        drop_btn.setStyleSheet("background-color: #f44336; color: white;")
        button_layout.addWidget(drop_btn)

        layout.addLayout(button_layout)

        self.setLayout(layout)

    def set_action(self, action):
        """Set the action and close dialog"""
        self.action = action
        self.accept()

    def get_action(self):
        """Get the selected action"""
        return self.action

    def get_modified_request(self):
        """Get modified request data"""
        # Parse modified request text
        text = self.request_edit.toPlainText()
        lines = text.split('\n')

        # Parse first line (method and URL)
        first_line = lines[0].split()
        method = first_line[0] if len(first_line) > 0 else self.request_data['method']
        url = first_line[1] if len(first_line) > 1 else self.request_data['url']

        # Parse headers
        headers = {}
        body_start = 0
        for i, line in enumerate(lines[1:], 1):
            if not line.strip():
                body_start = i + 1
                break
            if ':' in line:
                key, value = line.split(':', 1)
                headers[key.strip()] = value.strip()

        # Parse body
        body = '\n'.join(lines[body_start:]) if body_start > 0 else ''

        # Create modified request
        modified = self.request_data.copy()
        modified['method'] = method
        modified['url'] = url
        modified['headers'] = headers
        modified['body'] = body
        modified['raw_body'] = body.encode('utf-8')

        return modified


class ModifyRequestDialog(QDialog):
    """Dialog for modifying a request before replay"""

    def __init__(self, request_data, parent=None):
        super().__init__(parent)
        self.request_data = request_data
        self.init_ui()

    def init_ui(self):
        """Initialize modify dialog UI"""
        self.setWindowTitle("Modify Request")
        self.resize(800, 600)

        # Set light theme for dialog
        self.setStyleSheet("""
            QDialog {
                background-color: #f0f0f0;
                color: black;
            }
            QLabel {
                color: black;
            }
            QTextEdit {
                background-color: white;
                color: black;
                border: 2px solid #cccccc;
                border-radius: 4px;
                padding: 5px;
            }
            QDialogButtonBox QPushButton {
                background-color: #e0e0e0;
                color: black;
                border: 2px solid #999999;
                border-radius: 4px;
                padding: 6px 15px;
            }
            QDialogButtonBox QPushButton:hover {
                background-color: #d0d0d0;
                border-color: #666666;
            }
        """)

        layout = QVBoxLayout()

        layout.addWidget(QLabel("Edit the request below and click Send:"))

        # Request editor
        self.request_edit = QTextEdit()
        request_text = f"{self.request_data['method']} {self.request_data['url']}\n"
        for header, value in self.request_data['headers'].items():
            request_text += f"{header}: {value}\n"
        request_text += f"\n{self.request_data['body']}"
        self.request_edit.setPlainText(request_text)
        self.request_edit.setFont(QFont("Courier New", 9))
        layout.addWidget(self.request_edit)

        # Buttons
        buttons = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)

        self.setLayout(layout)

    def get_modified_request(self):
        """Parse and return modified request"""
        text = self.request_edit.toPlainText()
        lines = text.split('\n')

        # Parse first line
        first_line = lines[0].split()
        method = first_line[0] if len(first_line) > 0 else self.request_data['method']
        url = first_line[1] if len(first_line) > 1 else self.request_data['url']

        # Parse headers
        headers = {}
        body_start = 0
        for i, line in enumerate(lines[1:], 1):
            if not line.strip():
                body_start = i + 1
                break
            if ':' in line:
                key, value = line.split(':', 1)
                headers[key.strip()] = value.strip()

        # Parse body
        body = '\n'.join(lines[body_start:]) if body_start > 0 else ''

        # Create modified request
        modified = self.request_data.copy()
        modified['method'] = method
        modified['url'] = url
        modified['headers'] = headers
        modified['body'] = body
        modified['raw_body'] = body.encode('utf-8')

        return modified
