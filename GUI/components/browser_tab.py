"""
Browser Integration Tab - Burp Suite-like functionality
Provides HTTP proxy, request interception, modification, and passive scanning
"""

from PyQt5.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QPushButton, QLabel,
    QTableWidget, QTableWidgetItem, QTextEdit, QSplitter,
    QCheckBox, QSpinBox, QGroupBox, QComboBox, QHeaderView,
    QMessageBox, QDialog, QDialogButtonBox, QTabWidget, QProgressDialog, QApplication,
    QMenu, QAction
)
from PyQt5.QtCore import Qt, pyqtSignal, QThread
from PyQt5.QtGui import QColor, QFont, QCursor
from GUI.components.browser_tab_dialogs import (
    ModifyRequestDialog, ScanConfigDialog
)
from GUI.components import InterceptPanel, OOBPanel
import json
from datetime import datetime
from utils.chromium_manager import get_chromium_manager
from GUI.components.repeater_tab_improved import RepeaterTabImproved as RepeaterTab


class BrowserTab(QWidget):
    """Browser integration tab with proxy and interception"""

    # Signal to communicate with main scanner
    scan_page_requested = pyqtSignal(str, dict)  # url, config (modules, cookies, headers)

    def __init__(self, main_gui=None, parent=None):
        super().__init__(parent)
        self.main_gui = main_gui  # Reference to main DominatorGUI
        self.proxy = None
        self.selected_modules = []
        self.repeater_tab = None  # Will be created in init_ui
        self.intercept_panel = None  # Will be created in init_ui

        # Performance optimization: batch UI updates
        self.pending_responses = []  # Queue for batching
        self.max_history_rows = 5000  # Auto-delete old rows beyond this
        self.max_queue_size = 1000  # CRITICAL: Max queue size to prevent crash
        self.auto_pause_threshold = 800  # Auto-pause at 80% of max
        self.logging_paused = False  # Pause/resume logging
        self.batch_timer = None  # Will be created in init_ui

        # Statistics for blocked requests
        self.blocked_requests_count = 0
        self.total_requests_count = 0

        self.init_ui()

    def init_ui(self):
        """Initialize the browser tab UI"""

        # Set light theme for entire tab
        self.setStyleSheet("""
            QWidget {
                background-color: white;
                color: black;
            }
            QGroupBox {
                background-color: #f5f5f5;
                color: black;
                border: 2px solid #cccccc;
                border-radius: 5px;
                margin-top: 10px;
                padding-top: 10px;
                font-weight: bold;
            }
            QGroupBox::title {
                color: black;
                subcontrol-origin: margin;
                left: 10px;
                padding: 0 5px;
            }
            QLabel {
                color: black;
                background-color: transparent;
            }
            QTableWidget {
                background-color: white;
                color: black;
                gridline-color: #cccccc;
                border: 1px solid #cccccc;
            }
            QTableWidget::item {
                color: black;
                background-color: white;
            }
            QTableWidget::item:selected {
                background-color: #e0e0ff;
                color: black;
            }
            QHeaderView::section {
                background-color: #e0e0e0;
                color: black;
                padding: 5px;
                border: 1px solid #cccccc;
                font-weight: bold;
            }
            QTextEdit {
                background-color: white;
                color: black;
                border: 1px solid #cccccc;
            }
            QPushButton {
                color: black;
            }
            QCheckBox {
                color: black;
                background-color: transparent;
            }
            QSpinBox {
                color: black;
                background-color: white;
            }
            QComboBox {
                color: black;
                background-color: white;
            }
        """)

        layout = QVBoxLayout()

        # Create sub-tabs for Proxy and Repeater
        self.sub_tabs = QTabWidget()
        self.sub_tabs.setStyleSheet("""
            QTabWidget::pane {
                border: 1px solid #cccccc;
                background-color: white;
            }
            QTabBar::tab {
                background-color: #e0e0e0;
                color: black;
                padding: 8px 20px;
                border: 1px solid #cccccc;
                border-bottom: none;
                margin-right: 2px;
            }
            QTabBar::tab:selected {
                background-color: white;
                color: black;
                font-weight: bold;
            }
            QTabBar::tab:hover {
                background-color: #d0d0d0;
            }
        """)

        # === Proxy Tab (main functionality) ===
        proxy_widget = QWidget()
        proxy_layout = QVBoxLayout()

        # Top Control Panel
        control_panel = self._create_control_panel()
        proxy_layout.addWidget(control_panel)

        # Intercept Panel (initially hidden, shown when requests are intercepted)
        self.intercept_panel = InterceptPanel()
        proxy_layout.addWidget(self.intercept_panel)

        # Main Splitter (History + Details)
        splitter = QSplitter(Qt.Vertical)

        # Request History Table
        history_group = self._create_history_table()
        history_group.setMinimumHeight(400)  # Ensure good visibility
        splitter.addWidget(history_group)

        # Request/Response Details
        details_group = self._create_details_panel()
        details_group.setMinimumHeight(200)
        splitter.addWidget(details_group)

        # Set splitter sizes (75% history, 25% details for better visibility)
        splitter.setSizes([750, 250])
        proxy_layout.addWidget(splitter)

        # Bottom Findings Panel
        findings_group = self._create_findings_panel()
        proxy_layout.addWidget(findings_group)

        proxy_widget.setLayout(proxy_layout)

        # === Repeater Tab ===
        self.repeater_tab = RepeaterTab()

        # === OOB Panel ===
        self.oob_panel = OOBPanel()

        # === WebSocket Tab ===
        websocket_widget = self._create_websocket_tab()

        # Add tabs
        self.sub_tabs.addTab(proxy_widget, "🌐 Proxy & Intercept")
        self.sub_tabs.addTab(self.repeater_tab, "🔁 Repeater")
        self.sub_tabs.addTab(websocket_widget, "🔌 WebSockets")
        self.sub_tabs.addTab(self.oob_panel, "📡 Out-of-Band")

        layout.addWidget(self.sub_tabs)

        self.setLayout(layout)

        # Initialize batch timer for performance optimization
        from PyQt5.QtCore import QTimer
        self.batch_timer = QTimer()
        self.batch_timer.timeout.connect(self._process_batch_updates)
        self.batch_timer.start(200)  # Process batches every 200ms

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

        self.block_analytics_checkbox = QCheckBox("Block Analytics/Telemetry")
        self.block_analytics_checkbox.setChecked(True)  # Enabled by default
        self.block_analytics_checkbox.stateChanged.connect(self.toggle_block_analytics)
        self.block_analytics_checkbox.setToolTip("Block 130+ analytics, telemetry, and tracking domains (Firefox, Chrome, Google, Yandex, etc.)")
        proxy_row.addWidget(self.block_analytics_checkbox)

        self.pause_logging_btn = QPushButton("⏸ Pause Logging")
        self.pause_logging_btn.clicked.connect(self.toggle_logging)
        self.pause_logging_btn.setEnabled(False)
        proxy_row.addWidget(self.pause_logging_btn)

        # Statistics label for blocked analytics
        self.analytics_stats_label = QLabel("🚫 Blocked: 0/0 (0%)")
        self.analytics_stats_label.setStyleSheet("color: #ff5722; font-weight: bold;")
        self.analytics_stats_label.setToolTip("Blocked analytics/telemetry requests vs total requests")
        proxy_row.addWidget(self.analytics_stats_label)

        proxy_row.addStretch()
        layout.addLayout(proxy_row)

        # Row 2: Browser launch and scan controls
        browser_row = QHBoxLayout()

        self.launch_browser_btn = QPushButton("🌐 Launch Chrome Browser")
        self.launch_browser_btn.clicked.connect(self.launch_browser)
        self.launch_browser_btn.setEnabled(False)
        browser_row.addWidget(self.launch_browser_btn)

        self.launch_firefox_btn = QPushButton("🦊 Launch Firefox")
        self.launch_firefox_btn.clicked.connect(self.launch_firefox)
        self.launch_firefox_btn.setEnabled(False)
        browser_row.addWidget(self.launch_firefox_btn)

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
        self.history_table.setSortingEnabled(True)
        self.history_table.setAlternatingRowColors(True)

        # Set column widths
        header = self.history_table.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.Interactive)  # ID
        header.setSectionResizeMode(1, QHeaderView.Interactive)  # Time
        header.setSectionResizeMode(2, QHeaderView.Interactive)  # Method
        header.setSectionResizeMode(3, QHeaderView.Stretch)      # URL
        header.setSectionResizeMode(4, QHeaderView.Interactive)  # Status
        header.setSectionResizeMode(5, QHeaderView.Interactive)  # Length
        header.setSectionResizeMode(6, QHeaderView.Interactive)  # Notes

        self.history_table.setSelectionBehavior(QTableWidget.SelectRows)
        self.history_table.setEditTriggers(QTableWidget.NoEditTriggers)
        self.history_table.itemSelectionChanged.connect(self.on_history_selection_changed)

        # Context menu for history table - right-click actions
        self.history_table.setContextMenuPolicy(Qt.CustomContextMenu)
        self.history_table.customContextMenuRequested.connect(self._show_history_context_menu)

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

        self.send_to_repeater_btn = QPushButton("🔁 Send to Repeater")
        self.send_to_repeater_btn.setStyleSheet("""
            QPushButton {
                background-color: #2196F3;
                color: white;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: #1976D2;
            }
            QPushButton:disabled {
                background-color: #cccccc;
                color: #666666;
            }
        """)
        self.send_to_repeater_btn.clicked.connect(self.send_to_repeater)
        self.send_to_repeater_btn.setEnabled(False)
        actions_row.addWidget(self.send_to_repeater_btn)

        self.send_to_scanner_btn = QPushButton("🔍 Send to Scanner")
        self.send_to_scanner_btn.setStyleSheet("""
            QPushButton {
                background-color: #FF9800;
                color: white;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: #F57C00;
            }
            QPushButton:disabled {
                background-color: #cccccc;
                color: #666666;
            }
        """)
        self.send_to_scanner_btn.clicked.connect(self.send_to_scanner)
        self.send_to_scanner_btn.setEnabled(False)
        actions_row.addWidget(self.send_to_scanner_btn)

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
        self.findings_table.setSortingEnabled(True)
        self.findings_table.setAlternatingRowColors(True)
        self.findings_table.setMaximumHeight(150)

        # Set column widths
        header = self.findings_table.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.Interactive)
        header.setSectionResizeMode(1, QHeaderView.Interactive)
        header.setSectionResizeMode(2, QHeaderView.Stretch)
        header.setSectionResizeMode(3, QHeaderView.Interactive)
        header.setSectionResizeMode(4, QHeaderView.Stretch)

        layout.addWidget(self.findings_table)

        # Stats
        self.findings_count_label = QLabel("Passive Findings: 0")
        layout.addWidget(self.findings_count_label)

        group.setLayout(layout)
        return group

    def _create_websocket_tab(self):
        """Create the WebSocket messages tab"""
        widget = QWidget()
        layout = QVBoxLayout(widget)

        # Header
        header_layout = QHBoxLayout()
        title_label = QLabel("🔌 WebSocket Messages")
        title_label.setFont(QFont("Segoe UI", 14, QFont.Bold))
        title_label.setStyleSheet("color: #9C27B0;")
        header_layout.addWidget(title_label)

        header_layout.addStretch()

        # Clear button
        clear_ws_btn = QPushButton("🗑️ Clear")
        clear_ws_btn.setStyleSheet("""
            QPushButton {
                background-color: #f44336;
                color: white;
                border: none;
                border-radius: 4px;
                padding: 6px 12px;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: #d32f2f;
            }
        """)
        clear_ws_btn.clicked.connect(self._clear_websocket_history)
        header_layout.addWidget(clear_ws_btn)

        layout.addLayout(header_layout)

        # Stats
        self.ws_stats_label = QLabel("Connections: 0 | Messages: 0 | Bytes: 0")
        self.ws_stats_label.setStyleSheet("color: #9C27B0; font-weight: bold; padding: 5px;")
        layout.addWidget(self.ws_stats_label)

        # WebSocket table
        self.websocket_table = QTableWidget()
        self.websocket_table.setColumnCount(6)
        self.websocket_table.setHorizontalHeaderLabels([
            "#", "Time", "URL", "Direction", "Type", "Data"
        ])
        self.websocket_table.setSortingEnabled(True)

        header = self.websocket_table.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.Interactive)  # ID
        header.setSectionResizeMode(1, QHeaderView.Interactive)  # Time
        header.setSectionResizeMode(2, QHeaderView.Stretch)      # URL
        header.setSectionResizeMode(3, QHeaderView.Interactive)  # Direction
        header.setSectionResizeMode(4, QHeaderView.Interactive)  # Type
        header.setSectionResizeMode(5, QHeaderView.Stretch)      # Data

        self.websocket_table.setSelectionBehavior(QTableWidget.SelectRows)
        self.websocket_table.setEditTriggers(QTableWidget.NoEditTriggers)
        self.websocket_table.setAlternatingRowColors(True)
        self.websocket_table.setStyleSheet("""
            QTableWidget {
                background-color: #ffffff;
                color: #333333;
                gridline-color: #e0e0e0;
                border: 1px solid #cccccc;
                border-radius: 4px;
            }
            QHeaderView::section {
                background-color: #9C27B0;
                color: white;
                padding: 8px;
                border: none;
                font-weight: bold;
            }
            QTableWidget::item {
                padding: 5px;
            }
            QTableWidget::item:selected {
                background-color: #E1BEE7;
                color: #333333;
            }
        """)

        layout.addWidget(self.websocket_table)

        # WebSocket message details
        details_group = QGroupBox("Message Details")
        details_layout = QVBoxLayout(details_group)

        self.ws_details_text = QTextEdit()
        self.ws_details_text.setReadOnly(True)
        self.ws_details_text.setFont(QFont("Courier New", 9))
        self.ws_details_text.setMaximumHeight(150)
        details_layout.addWidget(self.ws_details_text)

        layout.addWidget(details_group)

        # Connect selection change
        self.websocket_table.itemSelectionChanged.connect(self._on_websocket_selection_changed)

        # Initialize counters
        self.ws_connection_count = 0
        self.ws_message_count = 0
        self.ws_total_bytes = 0

        return widget

    def _on_websocket_selection_changed(self):
        """Handle WebSocket table selection change"""
        selected = self.websocket_table.selectedItems()
        if selected:
            row = selected[0].row()
            data_item = self.websocket_table.item(row, 5)
            if data_item:
                self.ws_details_text.setPlainText(data_item.text())

    def _clear_websocket_history(self):
        """Clear WebSocket history"""
        self.websocket_table.setRowCount(0)
        self.ws_connection_count = 0
        self.ws_message_count = 0
        self.ws_total_bytes = 0
        self._update_ws_stats()
        self.ws_details_text.clear()

    def _update_ws_stats(self):
        """Update WebSocket statistics label"""
        self.ws_stats_label.setText(
            f"Connections: {self.ws_connection_count} | Messages: {self.ws_message_count} | Bytes: {self.ws_total_bytes}"
        )

    def on_websocket_message(self, ws_data):
        """Handle incoming WebSocket message"""
        try:
            row = self.websocket_table.rowCount()
            self.websocket_table.insertRow(row)

            # ID
            id_item = QTableWidgetItem(str(row + 1))
            self.websocket_table.setItem(row, 0, id_item)

            # Time
            time_item = QTableWidgetItem(ws_data.get('timestamp', datetime.now().strftime('%H:%M:%S')))
            self.websocket_table.setItem(row, 1, time_item)

            # URL
            url_item = QTableWidgetItem(ws_data.get('url', 'Unknown'))
            self.websocket_table.setItem(row, 2, url_item)

            # Direction
            direction = ws_data.get('direction', 'Unknown')
            direction_item = QTableWidgetItem(direction)
            if direction == 'Outgoing':
                direction_item.setForeground(QColor('#2196F3'))
            elif direction == 'Incoming':
                direction_item.setForeground(QColor('#4CAF50'))
            else:
                direction_item.setForeground(QColor('#9C27B0'))
            self.websocket_table.setItem(row, 3, direction_item)

            # Type
            msg_type = ws_data.get('type', 'text')
            type_item = QTableWidgetItem(msg_type)
            self.websocket_table.setItem(row, 4, type_item)

            # Data
            data = ws_data.get('data', '')
            data_item = QTableWidgetItem(str(data)[:100] + ('...' if len(str(data)) > 100 else ''))
            data_item.setData(Qt.UserRole, data)  # Store full data
            self.websocket_table.setItem(row, 5, data_item)

            # Update stats
            if ws_data.get('type') == 'connection':
                self.ws_connection_count += 1
            else:
                self.ws_message_count += 1
                self.ws_total_bytes += len(str(data))

            self._update_ws_stats()

            # Auto-scroll
            self.websocket_table.scrollToBottom()

            # Flash WebSocket tab
            self.sub_tabs.tabBar().setTabTextColor(2, QColor('#9C27B0'))

        except Exception as e:
            print(f"[ERROR] Failed to add WebSocket message: {e}")

    def toggle_proxy(self):
        """Start or stop the proxy server"""
        if self.proxy is None or not self.proxy.running:
            try:
                print("[DEBUG] Starting proxy initialization...")

                # Start proxy with SSL interception ENABLED
                from utils.intercept_proxy import InterceptingProxy

                port = self.proxy_port_spin.value()
                print(f"[DEBUG] Creating InterceptingProxy on port {port}")
                # SSL interception ENABLED - shows actual HTTPS requests instead of CONNECT tunnels
                # Browsers need to trust the CA certificate for this to work
                self.proxy = InterceptingProxy(port=port, ssl_intercept_enabled=True)
                print("[DEBUG] InterceptingProxy created successfully")

                # Connect proxy to intercept panel
                self.intercept_panel.set_proxy(self.proxy)
                print("[DEBUG] Proxy connected to intercept panel")

                # Connect signals
                self.proxy.request_intercepted.connect(self.on_request_intercepted)
                self.proxy.response_received.connect(self.on_response_received)
                self.proxy.passive_finding.connect(self.on_passive_finding)
                self.proxy.statistics_updated.connect(self.on_statistics_updated)
                self.proxy.websocket_message.connect(self.on_websocket_message)
                print("[DEBUG] Signals connected (including statistics and WebSocket)")

                # Start proxy
                print("[DEBUG] Calling proxy.start()...")
                message = self.proxy.start()
                print(f"[DEBUG] Proxy started: {message}")

                # Update UI to reflect actual SSL interception status
                ssl_status = "✓ ENABLED" if self.proxy.ssl_intercept_enabled else "✗ DISABLED"
                self.proxy_status_label.setText(f"🟢 Proxy: Running - SSL Interception: {ssl_status}")
                self.proxy_status_label.setStyleSheet("color: green; font-weight: bold;")
                self.start_proxy_btn.setText("⏹ Stop Proxy")
                self.start_proxy_btn.setStyleSheet("background-color: #f44336; color: white; font-weight: bold;")
                self.launch_browser_btn.setEnabled(True)
                self.launch_firefox_btn.setEnabled(True)
                self.scan_page_btn.setEnabled(True)
                self.pause_logging_btn.setEnabled(True)
                self.proxy_port_spin.setEnabled(False)

                # Get CA cert path safely
                cert_path = "Certificate path not available"
                if self.proxy and self.proxy.cert_manager:
                    try:
                        cert_path = self.proxy.cert_manager.get_ca_cert_path()
                    except:
                        pass

                # Show SSL interception info
                QMessageBox.information(
                    self,
                    "Proxy Started - SSL Interception Enabled",
                    f"{message}\n\n"
                    "✓ SSL Interception: ENABLED\n"
                    "✓ HTTPS traffic will be decrypted and inspected\n"
                    "✓ Individual HTTPS requests visible in history\n"
                    "✓ Full request/response body inspection\n\n"
                    "CA certificate automatically generated at:\n"
                    f"{cert_path}"
                )

            except Exception as e:
                # Show detailed error message
                import traceback
                error_details = traceback.format_exc()
                QMessageBox.critical(
                    self,
                    "Proxy Start Error",
                    f"Failed to start proxy:\n\n{str(e)}\n\nDetails:\n{error_details}"
                )
                # Reset proxy state
                self.proxy = None
                return
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

    def toggle_logging(self):
        """Pause or resume request logging (performance optimization)"""
        self.logging_paused = not self.logging_paused
        if self.logging_paused:
            self.pause_logging_btn.setText("▶ Resume Logging")
            self.pause_logging_btn.setStyleSheet("background-color: #4CAF50;")
        else:
            self.pause_logging_btn.setText("⏸ Pause Logging")
            self.pause_logging_btn.setStyleSheet("")

    def toggle_block_analytics(self, state):
        """Enable or disable analytics/telemetry blocking"""
        if self.proxy:
            self.proxy.block_analytics_enabled = (state == Qt.Checked)
            print(f"[INFO] Analytics blocking {'enabled' if state == Qt.Checked else 'disabled'}")

    def on_statistics_updated(self, stats):
        """Update statistics display when proxy emits statistics_updated signal"""
        try:
            total = stats.get('total', 0)
            blocked = stats.get('blocked_analytics', 0)

            # Calculate percentage
            percentage = (blocked / total * 100) if total > 0 else 0

            # Update label
            self.analytics_stats_label.setText(f"🚫 Blocked: {blocked}/{total} ({percentage:.1f}%)")

            # Change color based on blocking effectiveness
            if percentage > 30:
                self.analytics_stats_label.setStyleSheet("color: #4CAF50; font-weight: bold;")  # Green - lots blocked
            elif percentage > 10:
                self.analytics_stats_label.setStyleSheet("color: #FF9800; font-weight: bold;")  # Orange - some blocked
            else:
                self.analytics_stats_label.setStyleSheet("color: #ff5722; font-weight: bold;")  # Red - few blocked

        except Exception as e:
            print(f"[ERROR] Failed to update statistics: {e}")

    def launch_browser(self):
        """Launch browser with proxy configuration - ALWAYS use portable Chromium"""
        port = self.proxy_port_spin.value()
        chromium_mgr = get_chromium_manager()

        try:
            # Check if portable Chromium is installed
            if chromium_mgr.is_installed():
                # Launch portable Chromium
                chromium_mgr.launch(proxy_host='127.0.0.1', proxy_port=port)

                QMessageBox.information(
                    self,
                    "Browser Launched",
                    f"Portable Chromium launched with proxy: 127.0.0.1:{port}\n\n"
                    "All HTTP requests will be intercepted and logged.\n"
                    "HTTPS requests will show as CONNECT tunnels (encrypted)."
                )
            else:
                # Portable Chromium not found - offer to download
                reply = QMessageBox.question(
                    self,
                    "Portable Chromium Required",
                    "Portable Chromium is not installed.\n\n"
                    "Dominator uses a clean portable browser to ensure:\n"
                    "• Isolated environment (no extensions/plugins)\n"
                    "• Proper proxy configuration\n"
                    "• Consistent certificate handling\n\n"
                    f"Download portable Chromium now? (~{chromium_mgr.get_download_size_mb()} MB)",
                    QMessageBox.Yes | QMessageBox.No,
                    QMessageBox.Yes
                )

                if reply == QMessageBox.Yes:
                    # Show progress dialog
                    progress = QProgressDialog("Downloading portable Chromium...", None, 0, 100, self)
                    progress.setWindowModality(Qt.WindowModal)
                    progress.setAutoClose(True)

                    def progress_callback(msg, percent):
                        progress.setLabelText(msg)
                        progress.setValue(percent)
                        QApplication.processEvents()

                    try:
                        chromium_mgr.download(progress_callback=progress_callback)
                        progress.close()

                        # Launch downloaded Chromium
                        chromium_mgr.launch(proxy_host='127.0.0.1', proxy_port=port)
                        # Success - no popup, user can see it launched
                    except Exception as e:
                        progress.close()
                        QMessageBox.critical(
                            self,
                            "Download Failed",
                            f"Failed to download Chromium:\n{str(e)}\n\n"
                            "You can manually configure any browser:\n"
                            f"Proxy: 127.0.0.1:{port}"
                        )
                # User declined - don't nag them with another popup

        except Exception as e:
            QMessageBox.critical(
                self,
                "Launch Failed",
                f"Failed to launch browser:\n{str(e)}\n\n"
                "You can manually configure any browser:\n"
                f"Proxy: 127.0.0.1:{port}"
            )

    def launch_firefox(self):
        """Launch Firefox with proxy configuration"""
        from utils.firefox_manager import get_firefox_manager

        port = self.proxy_port_spin.value()
        firefox_mgr = get_firefox_manager()

        try:
            if firefox_mgr.is_installed():
                # Launch Firefox with proxy
                firefox_mgr.launch(proxy_host='127.0.0.1', proxy_port=port, url="http://example.com")
                # Success - no popup, user can see it launched
            else:
                QMessageBox.warning(
                    self,
                    "Firefox Not Found",
                    "Firefox is not installed on this system.\n\n"
                    "Please install Firefox or use the Chrome browser option.\n\n"
                    "You can also manually configure any browser:\n"
                    f"HTTP Proxy: 127.0.0.1:{port}"
                )

        except Exception as e:
            QMessageBox.critical(
                self,
                "Launch Failed",
                f"Failed to launch Firefox:\n{str(e)}\n\n"
                "You can manually configure Firefox:\n"
                f"Proxy: 127.0.0.1:{port}"
            )

    def on_request_intercepted(self, request_data):
        """Handle intercepted request - add to intercept panel queue"""
        # Add request to the intercept panel's queue
        # The panel will handle display, navigation, and user actions
        self.intercept_panel.add_request(request_data)

    def on_response_received(self, data):
        """Handle received response - queue for batch processing (CRASH-SAFE)"""
        # Skip if logging is paused
        if self.logging_paused:
            return

        # CRITICAL: Check queue size to prevent memory overflow and crash
        queue_size = len(self.pending_responses)

        # Auto-pause if queue is getting too large (80% of max)
        if queue_size >= self.auto_pause_threshold and not self.logging_paused:
            print(f"[WARNING] Queue size {queue_size} exceeded threshold {self.auto_pause_threshold}, auto-pausing!")
            self.logging_paused = True
            self.pause_logging_btn.setText("▶ Resume (Auto-Paused)")
            self.pause_logging_btn.setStyleSheet("background-color: #ff9800;")  # Orange warning
            return

        # Hard limit: Drop oldest items if queue is full
        if queue_size >= self.max_queue_size:
            # Remove oldest 20% to make room
            drop_count = int(self.max_queue_size * 0.2)
            self.pending_responses = self.pending_responses[drop_count:]
            print(f"[WARNING] Queue full ({queue_size}), dropped {drop_count} oldest responses")

        # Add to pending queue instead of immediate UI update (performance optimization)
        self.pending_responses.append(data)

    def _process_batch_updates(self):
        """Process batched responses - called by timer (CRASH-SAFE with error handling)"""
        if not self.pending_responses or self.logging_paused:
            return

        try:
            # Take up to 50 responses per batch to avoid long blocking
            batch_size = min(50, len(self.pending_responses))
            batch = self.pending_responses[:batch_size]
            self.pending_responses = self.pending_responses[batch_size:]

            # Disable updates during bulk insert for better performance
            self.history_table.setUpdatesEnabled(False)

            for data in batch:
                try:
                    request = data['request']
                    response = data['response']

                    # Check row limit and remove oldest if exceeded
                    if self.history_table.rowCount() >= self.max_history_rows:
                        self.history_table.removeRow(0)  # Remove oldest

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

                    # Length - handle both bytes and string body
                    body = response.get('body', b'')
                    if isinstance(body, str):
                        length = len(body.encode('utf-8'))
                    elif isinstance(body, bytes):
                        length = len(body)
                    else:
                        length = 0

                    # Format length nicely
                    if length >= 1024 * 1024:
                        length_str = f"{length / (1024 * 1024):.2f} MB"
                    elif length >= 1024:
                        length_str = f"{length / 1024:.2f} KB"
                    else:
                        length_str = f"{length} B"

                    self.history_table.setItem(row, 5, QTableWidgetItem(length_str))

                    # Notes
                    self.history_table.setItem(row, 6, QTableWidgetItem(""))

                    # Store full data in row
                    self.history_table.item(row, 0).setData(Qt.UserRole, data)

                except Exception as e:
                    # Skip problematic items instead of crashing
                    print(f"[ERROR] Failed to add history item: {e}")
                    continue

            # Re-enable updates and refresh (performance optimization)
            self.history_table.setUpdatesEnabled(True)

            # Update count label with queue size indicator
            total = self.history_table.rowCount()
            queue_size = len(self.pending_responses)
            if queue_size > 0:
                self.history_count_label.setText(f"Total: {total} | Queue: {queue_size}")
            else:
                self.history_count_label.setText(f"Total Requests: {total}")

            # Auto-scroll to bottom
            self.history_table.scrollToBottom()

        except Exception as e:
            # Critical error - re-enable updates and log
            print(f"[CRITICAL ERROR] Batch processing failed: {e}")
            try:
                self.history_table.setUpdatesEnabled(True)
            except:
                pass

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
            self.send_to_repeater_btn.setEnabled(True)
            self.send_to_scanner_btn.setEnabled(True)

    def send_to_repeater(self):
        """Send selected request to Repeater tab"""
        selected = self.history_table.selectedItems()
        if not selected:
            return

        row = selected[0].row()
        data = self.history_table.item(row, 0).data(Qt.UserRole)

        if data:
            request = data['request']
            # Load request into Repeater
            if self.repeater_tab:
                self.repeater_tab.load_request(request)
                # Switch to Repeater tab (index 1)
                self.sub_tabs.setCurrentIndex(1)
                # Flash the tab to show it's active
                self.sub_tabs.tabBar().setTabTextColor(1, QColor('#4CAF50'))
            else:
                QMessageBox.warning(self, "Error", "Repeater tab not available")

    def send_to_scanner(self):
        """Send selected request to Scanner with auto-configured cookies and headers"""
        selected = self.history_table.selectedItems()
        if not selected:
            return

        row = selected[0].row()
        data = self.history_table.item(row, 0).data(Qt.UserRole)

        if not data:
            return

        request = data['request']

        # Extract cookies and headers from request
        cookies = {}
        custom_headers = {}

        for header, value in request.get('headers', {}).items():
            if header.lower() == 'cookie':
                # Parse cookie header
                for cookie_pair in value.split(';'):
                    if '=' in cookie_pair:
                        cookie_name, cookie_value = cookie_pair.strip().split('=', 1)
                        cookies[cookie_name] = cookie_value
            elif header.lower() not in ['host', 'content-length', 'connection']:
                # Add other important headers (skip standard ones)
                custom_headers[header] = value

        # Show scan configuration dialog
        dialog = ScanConfigDialog(request, cookies, custom_headers, self)
        result = dialog.exec_()

        if result == QDialog.Accepted:
            config = dialog.get_config()

            # Emit signal to start scan with configuration
            # The signal will be caught by the main GUI
            self.scan_page_requested.emit(request['url'], config)

            QMessageBox.information(
                self,
                "Scan Started",
                f"Scan configured for: {request['url']}\n\n"
                f"Modules: {', '.join(config['modules'])}\n"
                f"Cookies: {len(cookies)} cookie(s)\n"
                f"Custom Headers: {len(custom_headers)} header(s)\n\n"
                "Check the Scan Configuration tab to start the scan."
            )

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

    def _show_history_context_menu(self, position):
        """Show context menu for history table right-click"""
        # Check if there's a selected item
        selected = self.history_table.selectedItems()
        if not selected:
            return

        row = selected[0].row()
        data = self.history_table.item(row, 0).data(Qt.UserRole)
        if not data:
            return

        request = data.get('request', {})
        url = request.get('url', 'Unknown')

        # Create context menu
        menu = QMenu(self)

        # Send to Repeater action
        repeater_action = QAction("🔁 Send to Repeater", self)
        repeater_action.triggered.connect(self.send_to_repeater)
        menu.addAction(repeater_action)

        # Send to Scanner action
        scanner_action = QAction("🔍 Send to Scanner", self)
        scanner_action.triggered.connect(self.send_to_scanner)
        menu.addAction(scanner_action)

        menu.addSeparator()

        # Replay Request action
        replay_action = QAction("↻ Replay Request", self)
        replay_action.triggered.connect(self.replay_selected_request)
        menu.addAction(replay_action)

        # Modify & Replay action
        modify_action = QAction("✏ Modify & Replay", self)
        modify_action.triggered.connect(self.modify_and_replay)
        menu.addAction(modify_action)

        menu.addSeparator()

        # Copy URL action
        copy_url_action = QAction("📋 Copy URL", self)
        copy_url_action.triggered.connect(lambda: self._copy_to_clipboard(url))
        menu.addAction(copy_url_action)

        # Copy as cURL action
        copy_curl_action = QAction("📋 Copy as cURL", self)
        copy_curl_action.triggered.connect(lambda: self._copy_as_curl(request))
        menu.addAction(copy_curl_action)

        # Copy Request action
        copy_request_action = QAction("📋 Copy Request", self)
        copy_request_action.triggered.connect(lambda: self._copy_request(request))
        menu.addAction(copy_request_action)

        menu.addSeparator()

        # Open in Browser action
        open_browser_action = QAction("🌐 Open in Browser", self)
        open_browser_action.triggered.connect(lambda: self._open_in_browser(url))
        menu.addAction(open_browser_action)

        # Show menu at cursor position
        menu.exec_(QCursor.pos())

    def _copy_to_clipboard(self, text):
        """Copy text to clipboard"""
        clipboard = QApplication.clipboard()
        clipboard.setText(text)

    def _copy_as_curl(self, request):
        """Copy request as cURL command"""
        method = request.get('method', 'GET')
        url = request.get('url', '')
        headers = request.get('headers', {})

        curl_cmd = f"curl -X {method} '{url}'"

        for header, value in headers.items():
            if header.lower() not in ['content-length', 'host']:
                curl_cmd += f" \\\n  -H '{header}: {value}'"

        if method == 'POST' and request.get('body'):
            body = request.get('body', '')
            curl_cmd += f" \\\n  -d '{body}'"

        self._copy_to_clipboard(curl_cmd)
        QMessageBox.information(self, "Copied", "cURL command copied to clipboard")

    def _copy_request(self, request):
        """Copy full request to clipboard"""
        method = request.get('method', 'GET')
        url = request.get('url', '')
        headers = request.get('headers', {})

        from urllib.parse import urlparse
        parsed = urlparse(url)
        path = parsed.path or '/'
        if parsed.query:
            path += f"?{parsed.query}"

        request_text = f"{method} {path} HTTP/1.1\r\n"
        request_text += f"Host: {parsed.netloc}\r\n"

        for header, value in headers.items():
            if header.lower() != 'host':
                request_text += f"{header}: {value}\r\n"

        request_text += "\r\n"

        if request.get('body'):
            request_text += request.get('body', '')

        self._copy_to_clipboard(request_text)
        QMessageBox.information(self, "Copied", "Request copied to clipboard")

    def _open_in_browser(self, url):
        """Open URL in default browser"""
        import webbrowser
        webbrowser.open(url)

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

            # Create config dict (backward compatible format)
            config = {
                'modules': modules,
                'cookies': {},
                'custom_headers': {}
            }

            # Emit signal to main GUI
            self.scan_page_requested.emit(url, config)

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


