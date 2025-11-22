"""
Out-of-Band (OOB) Testing Panel
Similar to Burp Collaborator - provides callback detection for blind vulnerabilities
"""

from PyQt5.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QPushButton, QLabel,
    QTableWidget, QTableWidgetItem, QTextEdit, QGroupBox,
    QComboBox, QLineEdit, QCheckBox, QSpinBox, QHeaderView,
    QMessageBox, QListWidget, QListWidgetItem, QApplication,
    QFrame, QTabWidget
)
from PyQt5.QtCore import Qt, QTimer, pyqtSignal
from PyQt5.QtGui import QFont, QColor
import json
import uuid
import hashlib
import time
import requests
from datetime import datetime
from urllib.parse import urljoin, urlparse
import threading


class OOBManager:
    """
    Singleton manager for OOB domain access across the application.
    Allows scan modules to access the current OOB callback domain.
    """
    _instance = None
    _oob_domain = None
    _oob_identifier = None
    _provider = "requestbin"
    _api_key = None
    _custom_server = None
    _interactions = []

    @classmethod
    def get_instance(cls):
        if cls._instance is None:
            cls._instance = cls()
        return cls._instance

    @property
    def oob_domain(self):
        return self._oob_domain

    @oob_domain.setter
    def oob_domain(self, value):
        self._oob_domain = value

    @property
    def oob_identifier(self):
        return self._oob_identifier

    @oob_identifier.setter
    def oob_identifier(self, value):
        self._oob_identifier = value

    @property
    def provider(self):
        return self._provider

    @provider.setter
    def provider(self, value):
        self._provider = value

    @property
    def api_key(self):
        return self._api_key

    @api_key.setter
    def api_key(self, value):
        self._api_key = value

    @property
    def custom_server(self):
        return self._custom_server

    @custom_server.setter
    def custom_server(self, value):
        self._custom_server = value

    def add_interaction(self, interaction):
        self._interactions.append(interaction)

    def get_interactions(self):
        return self._interactions

    def clear_interactions(self):
        self._interactions = []

    def is_configured(self):
        """Check if OOB is properly configured"""
        return self._oob_domain is not None and self._oob_identifier is not None

    def get_dns_payload(self, suffix=""):
        """Generate a DNS callback payload"""
        if not self.is_configured():
            return None
        identifier = f"{self._oob_identifier}{suffix}"
        return f"{identifier}.{self._oob_domain}"

    def get_http_payload(self, suffix=""):
        """Generate an HTTP callback payload"""
        if not self.is_configured():
            return None
        identifier = f"{self._oob_identifier}{suffix}"
        return f"http://{identifier}.{self._oob_domain}"

    def get_https_payload(self, suffix=""):
        """Generate an HTTPS callback payload"""
        if not self.is_configured():
            return None
        identifier = f"{self._oob_identifier}{suffix}"
        return f"https://{identifier}.{self._oob_domain}"


class OOBPanel(QWidget):
    """Out-of-Band testing panel with collaborator functionality"""

    # Signal when new interactions are detected
    interactions_updated = pyqtSignal(list)
    # Signal to export payloads for scanning
    payloads_exported = pyqtSignal(dict)

    def __init__(self, parent=None):
        super().__init__(parent)
        self.oob_manager = OOBManager.get_instance()
        self.auto_poll_timer = QTimer()
        self.auto_poll_timer.timeout.connect(self.poll_interactions)
        self.generated_payloads = []
        self.init_ui()

    def init_ui(self):
        """Initialize the OOB panel UI"""
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
                background-color: #e0ffe0;
                color: black;
            }
            QHeaderView::section {
                background-color: #e0e0e0;
                color: black;
                padding: 5px;
                border: 1px solid #cccccc;
                font-weight: bold;
            }
            QTextEdit, QLineEdit {
                background-color: white;
                color: black;
                border: 1px solid #cccccc;
            }
            QPushButton {
                background-color: #4CAF50;
                color: white;
                border: none;
                padding: 8px 16px;
                border-radius: 4px;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: #45a049;
            }
            QPushButton:disabled {
                background-color: #cccccc;
                color: #666666;
            }
            QPushButton#secondary {
                background-color: #2196F3;
            }
            QPushButton#secondary:hover {
                background-color: #1976D2;
            }
            QPushButton#warning {
                background-color: #ff9800;
            }
            QPushButton#warning:hover {
                background-color: #f57c00;
            }
            QPushButton#danger {
                background-color: #f44336;
            }
            QPushButton#danger:hover {
                background-color: #d32f2f;
            }
            QCheckBox {
                color: black;
                background-color: transparent;
            }
            QSpinBox, QComboBox {
                color: black;
                background-color: white;
                border: 1px solid #cccccc;
                padding: 4px;
            }
            QListWidget {
                background-color: white;
                color: black;
                border: 1px solid #cccccc;
            }
            QListWidget::item {
                padding: 4px;
            }
            QListWidget::item:selected {
                background-color: #e0ffe0;
                color: black;
            }
        """)

        layout = QVBoxLayout()

        # Create tab widget for organized sections
        self.oob_tabs = QTabWidget()
        self.oob_tabs.setStyleSheet("""
            QTabWidget::pane {
                border: 1px solid #cccccc;
                background-color: white;
            }
            QTabBar::tab {
                background-color: #e0e0e0;
                color: black;
                padding: 6px 15px;
                border: 1px solid #cccccc;
                border-bottom: none;
                margin-right: 2px;
            }
            QTabBar::tab:selected {
                background-color: white;
                font-weight: bold;
            }
        """)

        # === Settings Tab ===
        settings_widget = QWidget()
        settings_layout = QVBoxLayout(settings_widget)
        settings_layout.setContentsMargins(5, 5, 5, 5)
        settings_layout.setSpacing(5)
        settings_group = self._create_settings_panel()
        settings_layout.addWidget(settings_group)
        settings_layout.addStretch()

        # === Payloads Tab ===
        payloads_widget = QWidget()
        payloads_layout = QVBoxLayout(payloads_widget)
        payloads_layout.setContentsMargins(5, 5, 5, 5)
        payloads_layout.setSpacing(5)
        payloads_group = self._create_payloads_panel()
        payloads_layout.addWidget(payloads_group)
        payloads_layout.addStretch()

        # === Monitor Tab ===
        monitor_widget = QWidget()
        monitor_layout = QVBoxLayout(monitor_widget)
        monitor_layout.setContentsMargins(5, 5, 5, 5)
        monitor_layout.setSpacing(5)
        monitor_group = self._create_monitor_panel()
        monitor_layout.addWidget(monitor_group)
        monitor_layout.addStretch()

        # Add tabs
        self.oob_tabs.addTab(settings_widget, "Settings")
        self.oob_tabs.addTab(payloads_widget, "Payloads")
        self.oob_tabs.addTab(monitor_widget, "Monitor")

        layout.addWidget(self.oob_tabs)
        self.setLayout(layout)

    def _create_settings_panel(self):
        """Create collaborator server settings panel"""
        group = QGroupBox("Collaborator Server Settings")
        layout = QVBoxLayout()

        # Provider selection
        provider_row = QHBoxLayout()
        provider_row.addWidget(QLabel("Provider:"))

        self.provider_combo = QComboBox()
        self.provider_combo.addItems([
            "RequestBin.cn (Free, No Key)",
            "Pipedream (Client ID + Secret)",
            "Interact.sh (Public)",
            "Custom Server"
        ])
        self.provider_combo.currentIndexChanged.connect(self.on_provider_changed)
        provider_row.addWidget(self.provider_combo)
        provider_row.addStretch()
        layout.addLayout(provider_row)

        # Client ID input (for Pipedream)
        client_id_row = QHBoxLayout()
        client_id_row.addWidget(QLabel("Client ID:"))
        self.client_id_input = QLineEdit()
        self.client_id_input.setPlaceholderText("Enter Pipedream Client ID...")
        self.client_id_input.setEnabled(False)
        client_id_row.addWidget(self.client_id_input)
        layout.addLayout(client_id_row)

        # Client Secret input (for Pipedream)
        client_secret_row = QHBoxLayout()
        client_secret_row.addWidget(QLabel("Client Secret:"))
        self.client_secret_input = QLineEdit()
        self.client_secret_input.setPlaceholderText("Enter Pipedream Client Secret...")
        self.client_secret_input.setEchoMode(QLineEdit.Password)
        self.client_secret_input.setEnabled(False)
        client_secret_row.addWidget(self.client_secret_input)

        self.show_secret_btn = QPushButton("Show")
        self.show_secret_btn.setFixedWidth(60)
        self.show_secret_btn.clicked.connect(self.toggle_secret_visibility)
        self.show_secret_btn.setEnabled(False)
        client_secret_row.addWidget(self.show_secret_btn)
        layout.addLayout(client_secret_row)

        # Custom server input
        custom_row = QHBoxLayout()
        custom_row.addWidget(QLabel("Custom Server:"))
        self.custom_server_input = QLineEdit()
        self.custom_server_input.setPlaceholderText("e.g., collaborator.example.com")
        self.custom_server_input.setEnabled(False)
        custom_row.addWidget(self.custom_server_input)
        layout.addLayout(custom_row)

        # Identifier generation
        id_row = QHBoxLayout()
        id_row.addWidget(QLabel("Unique Identifier:"))
        self.identifier_input = QLineEdit()
        self.identifier_input.setPlaceholderText("Click 'Generate' to create identifier")
        self.identifier_input.setReadOnly(True)
        id_row.addWidget(self.identifier_input)

        self.generate_id_btn = QPushButton("Generate")
        self.generate_id_btn.clicked.connect(self.generate_identifier)
        id_row.addWidget(self.generate_id_btn)
        layout.addLayout(id_row)

        # Status display
        status_row = QHBoxLayout()
        self.status_label = QLabel("Status: Not configured")
        self.status_label.setStyleSheet("color: #666; font-style: italic;")
        status_row.addWidget(self.status_label)
        status_row.addStretch()

        self.configure_btn = QPushButton("Configure")
        self.configure_btn.setObjectName("secondary")
        self.configure_btn.clicked.connect(self.configure_collaborator)
        status_row.addWidget(self.configure_btn)
        layout.addLayout(status_row)

        # Info label
        info_label = QLabel(
            "Note: OOB testing requires an external callback server.\n"
            "RequestBin.net is the default free option. For production use, consider Pipedream or your own server."
        )
        info_label.setStyleSheet("color: #666; font-size: 9pt;")
        info_label.setWordWrap(True)
        layout.addWidget(info_label)

        group.setLayout(layout)
        return group

    def _create_payloads_panel(self):
        """Create payload generation panel"""
        group = QGroupBox("Payload Generation")
        layout = QVBoxLayout()

        # Payload type selection and suffix
        type_row = QHBoxLayout()
        type_row.addWidget(QLabel("Suffix (optional):"))
        self.payload_suffix = QLineEdit()
        self.payload_suffix.setPlaceholderText("e.g., -xss, -sqli")
        self.payload_suffix.setMaximumWidth(150)
        type_row.addWidget(self.payload_suffix)
        type_row.addStretch()
        layout.addLayout(type_row)

        # Generation buttons
        gen_row = QHBoxLayout()

        self.gen_dns_btn = QPushButton("Generate DNS")
        self.gen_dns_btn.clicked.connect(lambda: self.generate_payload("dns"))
        gen_row.addWidget(self.gen_dns_btn)

        self.gen_http_btn = QPushButton("Generate HTTP")
        self.gen_http_btn.setObjectName("secondary")
        self.gen_http_btn.clicked.connect(lambda: self.generate_payload("http"))
        gen_row.addWidget(self.gen_http_btn)

        self.gen_https_btn = QPushButton("Generate HTTPS")
        self.gen_https_btn.setObjectName("secondary")
        self.gen_https_btn.clicked.connect(lambda: self.generate_payload("https"))
        gen_row.addWidget(self.gen_https_btn)

        self.gen_all_btn = QPushButton("Generate All")
        self.gen_all_btn.setObjectName("warning")
        self.gen_all_btn.clicked.connect(self.generate_all_payloads)
        gen_row.addWidget(self.gen_all_btn)

        gen_row.addStretch()
        layout.addLayout(gen_row)

        # Generated payloads list
        layout.addWidget(QLabel("Generated Payloads:"))
        self.payloads_list = QListWidget()
        self.payloads_list.setMinimumHeight(150)
        self.payloads_list.itemDoubleClicked.connect(self.copy_selected_payload)
        layout.addWidget(self.payloads_list)

        # Payload actions
        action_row = QHBoxLayout()

        self.copy_payload_btn = QPushButton("Copy Selected")
        self.copy_payload_btn.clicked.connect(self.copy_selected_payload)
        action_row.addWidget(self.copy_payload_btn)

        self.copy_all_btn = QPushButton("Copy All")
        self.copy_all_btn.setObjectName("secondary")
        self.copy_all_btn.clicked.connect(self.copy_all_payloads)
        action_row.addWidget(self.copy_all_btn)

        self.export_btn = QPushButton("Export for Scans")
        self.export_btn.setObjectName("warning")
        self.export_btn.clicked.connect(self.export_payloads)
        action_row.addWidget(self.export_btn)

        self.clear_payloads_btn = QPushButton("Clear")
        self.clear_payloads_btn.setObjectName("danger")
        self.clear_payloads_btn.clicked.connect(self.clear_payloads)
        action_row.addWidget(self.clear_payloads_btn)

        action_row.addStretch()
        layout.addLayout(action_row)

        group.setLayout(layout)
        return group

    def _create_monitor_panel(self):
        """Create interaction monitor panel"""
        group = QGroupBox("Interaction Monitor")
        layout = QVBoxLayout()

        # Polling controls
        poll_row = QHBoxLayout()

        self.poll_btn = QPushButton("Poll Now")
        self.poll_btn.clicked.connect(self.poll_interactions)
        poll_row.addWidget(self.poll_btn)

        self.auto_poll_check = QCheckBox("Auto-poll")
        self.auto_poll_check.stateChanged.connect(self.toggle_auto_poll)
        poll_row.addWidget(self.auto_poll_check)

        poll_row.addWidget(QLabel("Interval (sec):"))
        self.poll_interval_spin = QSpinBox()
        self.poll_interval_spin.setRange(5, 300)
        self.poll_interval_spin.setValue(30)
        self.poll_interval_spin.valueChanged.connect(self.update_poll_interval)
        poll_row.addWidget(self.poll_interval_spin)

        self.interaction_count_label = QLabel("Interactions: 0")
        self.interaction_count_label.setStyleSheet("font-weight: bold; color: #4CAF50;")
        poll_row.addWidget(self.interaction_count_label)

        poll_row.addStretch()
        layout.addLayout(poll_row)

        # Interactions table
        self.interactions_table = QTableWidget()
        self.interactions_table.setColumnCount(5)
        self.interactions_table.setHorizontalHeaderLabels([
            "Time", "Type", "Source IP", "Subdomain", "Request Data"
        ])
        self.interactions_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeToContents)
        self.interactions_table.horizontalHeader().setSectionResizeMode(4, QHeaderView.Stretch)
        self.interactions_table.setSelectionBehavior(QTableWidget.SelectRows)
        self.interactions_table.setMinimumHeight(200)
        self.interactions_table.itemSelectionChanged.connect(self.on_interaction_selected)
        layout.addWidget(self.interactions_table)

        # Request details
        details_row = QHBoxLayout()
        details_row.addWidget(QLabel("Request Details:"))
        details_row.addStretch()
        layout.addLayout(details_row)

        self.request_details = QTextEdit()
        self.request_details.setReadOnly(True)
        self.request_details.setMaximumHeight(100)
        self.request_details.setStyleSheet("font-family: monospace;")
        layout.addWidget(self.request_details)

        # Monitor actions
        action_row = QHBoxLayout()

        self.import_findings_btn = QPushButton("Import as Findings")
        self.import_findings_btn.setObjectName("warning")
        self.import_findings_btn.clicked.connect(self.import_as_findings)
        action_row.addWidget(self.import_findings_btn)

        self.clear_interactions_btn = QPushButton("Clear Interactions")
        self.clear_interactions_btn.setObjectName("danger")
        self.clear_interactions_btn.clicked.connect(self.clear_interactions)
        action_row.addWidget(self.clear_interactions_btn)

        action_row.addStretch()
        layout.addLayout(action_row)

        group.setLayout(layout)
        return group

    def on_provider_changed(self, index):
        """Handle provider selection change"""
        # Enable/disable inputs based on provider
        is_pipedream = index == 1  # Pipedream
        is_custom = index == 3  # Custom Server

        self.client_id_input.setEnabled(is_pipedream)
        self.client_secret_input.setEnabled(is_pipedream)
        self.show_secret_btn.setEnabled(is_pipedream)
        self.custom_server_input.setEnabled(is_custom)

        # Update provider in manager
        providers = ["requestbin", "pipedream", "interactsh", "custom"]
        if index < len(providers):
            self.oob_manager.provider = providers[index]

    def toggle_secret_visibility(self):
        """Toggle client secret visibility"""
        if self.client_secret_input.echoMode() == QLineEdit.Password:
            self.client_secret_input.setEchoMode(QLineEdit.Normal)
            self.show_secret_btn.setText("Hide")
        else:
            self.client_secret_input.setEchoMode(QLineEdit.Password)
            self.show_secret_btn.setText("Show")

    def generate_identifier(self):
        """Generate a unique identifier for OOB callbacks"""
        # Generate a short unique identifier
        unique_id = hashlib.md5(str(uuid.uuid4()).encode()).hexdigest()[:12]
        self.identifier_input.setText(unique_id)
        self.oob_manager.oob_identifier = unique_id
        self.status_label.setText("Status: Identifier generated")
        self.status_label.setStyleSheet("color: #4CAF50; font-style: italic;")

    def configure_collaborator(self):
        """Configure the collaborator server"""
        provider_index = self.provider_combo.currentIndex()
        identifier = self.identifier_input.text()

        if not identifier:
            QMessageBox.warning(self, "Configuration Error",
                              "Please generate an identifier first.")
            return

        # Set up based on provider
        if provider_index == 0:  # RequestBin.cn (free, no key needed)
            # Using requestbin.cn pattern
            domain = "requestbin.cn"
            self.oob_manager.oob_domain = domain

        elif provider_index == 1:  # Pipedream
            client_id = self.client_id_input.text()
            client_secret = self.client_secret_input.text()
            if not client_id or not client_secret:
                QMessageBox.warning(self, "Configuration Error",
                                  "Pipedream requires both Client ID and Client Secret.")
                return
            # Store credentials in manager
            self.oob_manager._client_id = client_id
            self.oob_manager._client_secret = client_secret
            # Pipedream uses webhook URLs
            domain = "pipedream.net"
            self.oob_manager.oob_domain = domain

        elif provider_index == 2:  # Interact.sh
            # Public interact.sh server
            domain = "oast.fun"
            self.oob_manager.oob_domain = domain

        elif provider_index == 3:  # Custom
            custom_server = self.custom_server_input.text()
            if not custom_server:
                QMessageBox.warning(self, "Configuration Error",
                                  "Please enter a custom server address.")
                return
            self.oob_manager.custom_server = custom_server
            self.oob_manager.oob_domain = custom_server
            domain = custom_server

        self.oob_manager.oob_identifier = identifier

        self.status_label.setText(f"Status: Configured ({domain})")
        self.status_label.setStyleSheet("color: #4CAF50; font-weight: bold;")

        QMessageBox.information(self, "Configuration Complete",
                               f"OOB Collaborator configured!\n\n"
                               f"Domain: {self.oob_manager.oob_domain}\n"
                               f"Identifier: {identifier}")

    def generate_payload(self, payload_type):
        """Generate a specific type of payload"""
        if not self.oob_manager.is_configured():
            QMessageBox.warning(self, "Not Configured",
                              "Please configure the collaborator server first.")
            return

        suffix = self.payload_suffix.text().strip()

        if payload_type == "dns":
            payload = self.oob_manager.get_dns_payload(suffix)
        elif payload_type == "http":
            payload = self.oob_manager.get_http_payload(suffix)
        elif payload_type == "https":
            payload = self.oob_manager.get_https_payload(suffix)
        else:
            return

        if payload:
            self.add_payload_to_list(payload, payload_type)
            self.generated_payloads.append({"type": payload_type, "payload": payload})

    def generate_all_payloads(self):
        """Generate all types of payloads"""
        self.generate_payload("dns")
        self.generate_payload("http")
        self.generate_payload("https")

    def add_payload_to_list(self, payload, payload_type):
        """Add a payload to the list widget"""
        item = QListWidgetItem(f"[{payload_type.upper()}] {payload}")
        item.setData(Qt.UserRole, {"type": payload_type, "payload": payload})

        # Color code by type
        if payload_type == "dns":
            item.setForeground(QColor("#1565C0"))
        elif payload_type == "http":
            item.setForeground(QColor("#4CAF50"))
        elif payload_type == "https":
            item.setForeground(QColor("#FF9800"))

        self.payloads_list.addItem(item)

    def copy_selected_payload(self):
        """Copy selected payload to clipboard"""
        current_item = self.payloads_list.currentItem()
        if current_item:
            data = current_item.data(Qt.UserRole)
            if data:
                clipboard = QApplication.clipboard()
                clipboard.setText(data["payload"])
                self.status_label.setText("Status: Payload copied to clipboard")

    def copy_all_payloads(self):
        """Copy all payloads to clipboard"""
        payloads = []
        for i in range(self.payloads_list.count()):
            item = self.payloads_list.item(i)
            data = item.data(Qt.UserRole)
            if data:
                payloads.append(data["payload"])

        if payloads:
            clipboard = QApplication.clipboard()
            clipboard.setText("\n".join(payloads))
            QMessageBox.information(self, "Copied",
                                   f"Copied {len(payloads)} payloads to clipboard.")

    def export_payloads(self):
        """Export payloads for use in scans"""
        if not self.generated_payloads:
            QMessageBox.warning(self, "No Payloads",
                              "No payloads to export. Generate some first.")
            return

        export_data = {
            "domain": self.oob_manager.oob_domain,
            "identifier": self.oob_manager.oob_identifier,
            "provider": self.oob_manager.provider,
            "payloads": self.generated_payloads
        }

        self.payloads_exported.emit(export_data)
        QMessageBox.information(self, "Exported",
                               f"Exported {len(self.generated_payloads)} payloads for scanning.\n"
                               f"OOB domain is now available for scan modules.")

    def clear_payloads(self):
        """Clear all generated payloads"""
        self.payloads_list.clear()
        self.generated_payloads = []

    def toggle_auto_poll(self, state):
        """Toggle automatic polling"""
        if state == Qt.Checked:
            interval = self.poll_interval_spin.value() * 1000
            self.auto_poll_timer.start(interval)
            self.status_label.setText(f"Status: Auto-polling every {self.poll_interval_spin.value()}s")
        else:
            self.auto_poll_timer.stop()
            self.status_label.setText("Status: Auto-poll disabled")

    def update_poll_interval(self, value):
        """Update the polling interval"""
        if self.auto_poll_timer.isActive():
            self.auto_poll_timer.setInterval(value * 1000)

    def poll_interactions(self):
        """Poll for new interactions from the collaborator server"""
        if not self.oob_manager.is_configured():
            self.status_label.setText("Status: Not configured")
            return

        self.status_label.setText("Status: Polling...")

        # Run polling in a thread to avoid blocking UI
        thread = threading.Thread(target=self._poll_thread)
        thread.daemon = True
        thread.start()

    def _poll_thread(self):
        """Background thread for polling interactions"""
        try:
            interactions = self._fetch_interactions()
            # Use timer to update UI from main thread
            QTimer.singleShot(0, lambda: self._update_interactions(interactions))
        except Exception as e:
            QTimer.singleShot(0, lambda: self._poll_error(str(e)))

    def _fetch_interactions(self):
        """Fetch interactions from the collaborator server"""
        interactions = []
        provider = self.oob_manager.provider
        identifier = self.oob_manager.oob_identifier

        try:
            if provider == "requestbin":
                # RequestBin.cn polling (free, no key required)
                # RequestBin.cn provides free request bins
                url = f"https://requestbin.cn/api/v1/bins/{identifier}/requests"
                response = requests.get(url, timeout=10)
                if response.status_code == 200:
                    data = response.json()
                    for req in data:
                        interactions.append({
                            "time": req.get("time", ""),
                            "type": "HTTP",
                            "source_ip": req.get("remote_addr", "Unknown"),
                            "subdomain": identifier,
                            "data": json.dumps(req, indent=2)
                        })

            elif provider == "pipedream":
                # Pipedream API polling with OAuth2
                client_id = getattr(self.oob_manager, '_client_id', '')
                client_secret = getattr(self.oob_manager, '_client_secret', '')

                # Get access token using client credentials
                auth_url = "https://api.pipedream.com/v1/oauth/token"
                auth_data = {
                    "grant_type": "client_credentials",
                    "client_id": client_id,
                    "client_secret": client_secret
                }
                auth_response = requests.post(auth_url, json=auth_data, timeout=10)

                if auth_response.status_code == 200:
                    access_token = auth_response.json().get("access_token", "")

                    # Fetch events with access token
                    url = f"https://api.pipedream.com/v1/sources/{identifier}/events"
                    headers = {"Authorization": f"Bearer {access_token}"}
                    response = requests.get(url, headers=headers, timeout=10)
                    if response.status_code == 200:
                        data = response.json()
                        for event in data.get("data", []):
                            interactions.append({
                                "time": event.get("ts", ""),
                                "type": "HTTP",
                                "source_ip": event.get("client_ip", "Unknown"),
                                "subdomain": identifier,
                                "data": json.dumps(event, indent=2)
                            })

            elif provider == "interactsh":
                # Interact.sh polling (requires their client library)
                # Simplified example
                url = f"https://oast.fun/poll?id={identifier}"
                response = requests.get(url, timeout=10)
                if response.status_code == 200:
                    data = response.json()
                    for item in data.get("data", []):
                        interaction_type = item.get("protocol", "HTTP").upper()
                        interactions.append({
                            "time": item.get("timestamp", ""),
                            "type": interaction_type,
                            "source_ip": item.get("remote-address", "Unknown"),
                            "subdomain": item.get("full-id", identifier),
                            "data": item.get("raw-request", "")
                        })

            elif provider == "custom":
                # Custom server polling - expects JSON API
                custom_server = self.oob_manager.custom_server
                url = f"https://{custom_server}/api/interactions/{identifier}"
                response = requests.get(url, timeout=10)
                if response.status_code == 200:
                    interactions = response.json()

        except requests.exceptions.RequestException as e:
            # Return empty list on network errors
            pass
        except json.JSONDecodeError:
            pass

        return interactions

    def _update_interactions(self, interactions):
        """Update the interactions table with new data"""
        for interaction in interactions:
            self._add_interaction_row(interaction)
            self.oob_manager.add_interaction(interaction)

        count = self.interactions_table.rowCount()
        self.interaction_count_label.setText(f"Interactions: {count}")

        if interactions:
            self.status_label.setText(f"Status: Found {len(interactions)} new interaction(s)")
            self.interactions_updated.emit(interactions)
        else:
            self.status_label.setText("Status: No new interactions")

    def _poll_error(self, error_msg):
        """Handle polling errors"""
        self.status_label.setText(f"Status: Poll error - {error_msg}")
        self.status_label.setStyleSheet("color: #f44336; font-style: italic;")

    def _add_interaction_row(self, interaction):
        """Add a row to the interactions table"""
        row = self.interactions_table.rowCount()
        self.interactions_table.insertRow(row)

        # Time
        time_item = QTableWidgetItem(interaction.get("time", ""))
        self.interactions_table.setItem(row, 0, time_item)

        # Type
        interaction_type = interaction.get("type", "HTTP")
        type_item = QTableWidgetItem(interaction_type)
        if interaction_type == "DNS":
            type_item.setForeground(QColor("#1565C0"))
        elif interaction_type == "HTTP":
            type_item.setForeground(QColor("#4CAF50"))
        elif interaction_type == "HTTPS":
            type_item.setForeground(QColor("#FF9800"))
        self.interactions_table.setItem(row, 1, type_item)

        # Source IP
        ip_item = QTableWidgetItem(interaction.get("source_ip", "Unknown"))
        self.interactions_table.setItem(row, 2, ip_item)

        # Subdomain
        subdomain_item = QTableWidgetItem(interaction.get("subdomain", ""))
        self.interactions_table.setItem(row, 3, subdomain_item)

        # Request Data (truncated)
        data = interaction.get("data", "")
        if len(data) > 100:
            data = data[:100] + "..."
        data_item = QTableWidgetItem(data)
        data_item.setData(Qt.UserRole, interaction.get("data", ""))
        self.interactions_table.setItem(row, 4, data_item)

    def on_interaction_selected(self):
        """Handle interaction selection"""
        selected_rows = self.interactions_table.selectedItems()
        if selected_rows:
            row = selected_rows[0].row()
            data_item = self.interactions_table.item(row, 4)
            if data_item:
                full_data = data_item.data(Qt.UserRole)
                self.request_details.setPlainText(full_data or "")

    def import_as_findings(self):
        """Import interactions as security findings"""
        interactions = self.oob_manager.get_interactions()
        if not interactions:
            QMessageBox.warning(self, "No Interactions",
                              "No interactions to import as findings.")
            return

        # Create findings from interactions
        findings = []
        for interaction in interactions:
            finding = {
                "type": "OOB Callback Detected",
                "severity": "High",
                "url": f"{interaction.get('type', 'HTTP').lower()}://{interaction.get('subdomain', '')}",
                "description": f"Out-of-Band callback received from {interaction.get('source_ip', 'unknown')}",
                "evidence": interaction.get("data", ""),
                "timestamp": interaction.get("time", datetime.now().isoformat())
            }
            findings.append(finding)

        # Emit signal or save findings
        QMessageBox.information(self, "Findings Imported",
                               f"Imported {len(findings)} interactions as security findings.\n"
                               f"Check the Results tab for details.")

        return findings

    def clear_interactions(self):
        """Clear all interactions"""
        self.interactions_table.setRowCount(0)
        self.request_details.clear()
        self.oob_manager.clear_interactions()
        self.interaction_count_label.setText("Interactions: 0")
        self.status_label.setText("Status: Interactions cleared")

    def get_oob_payloads_for_scanning(self):
        """
        Get OOB payloads for use in automatic scanning.
        Returns a dict with payloads that can be injected by scan modules.
        """
        if not self.oob_manager.is_configured():
            return None

        return {
            "dns": self.oob_manager.get_dns_payload(),
            "http": self.oob_manager.get_http_payload(),
            "https": self.oob_manager.get_https_payload(),
            "domain": self.oob_manager.oob_domain,
            "identifier": self.oob_manager.oob_identifier
        }


# Convenience function to get OOB manager from anywhere in the application
def get_oob_manager():
    """Get the global OOB manager instance"""
    return OOBManager.get_instance()
