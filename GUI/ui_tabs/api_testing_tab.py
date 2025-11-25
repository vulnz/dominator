#!/usr/bin/env python3
"""
API Testing Tab - Load and test API specifications
Supports: OpenAPI/Swagger, Postman, HAR, WADL, RAML, GraphQL
"""

import sys
import json
from pathlib import Path

from PyQt5.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton,
    QTextEdit, QComboBox, QGroupBox, QGridLayout, QFileDialog,
    QTableWidget, QTableWidgetItem, QHeaderView, QSplitter,
    QLineEdit, QCheckBox, QProgressBar, QTabWidget, QFrame,
    QMessageBox, QAbstractItemView, QDialog, QScrollArea, QDialogButtonBox
)
from PyQt5.QtCore import Qt, QThread, pyqtSignal
from PyQt5.QtGui import QFont, QColor


class ModuleSelectorDialog(QDialog):
    """Dialog for selecting specific modules to run"""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Select Modules")
        self.setMinimumWidth(600)
        self.setMinimumHeight(500)

        # Store selected modules
        self.selected_modules = []
        self.checkboxes = {}

        # Main layout
        layout = QVBoxLayout(self)

        # Instructions
        info_label = QLabel("Select the modules you want to run on the API endpoints:")
        info_label.setWordWrap(True)
        layout.addWidget(info_label)

        # Scroll area for modules
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll_content = QWidget()
        scroll_layout = QVBoxLayout(scroll_content)

        # Module categories
        categories = {
            "Injection Vulnerabilities": [
                ("sqli", "SQL Injection"),
                ("xss", "Cross-Site Scripting (XSS)"),
                ("cmdi", "Command Injection"),
                ("ssti", "Server-Side Template Injection"),
                ("xxe", "XML External Entity (XXE)"),
                ("nosql_injection", "NoSQL Injection"),
                ("ldap_injection", "LDAP Injection")
            ],
            "API Security": [
                ("api_security", "API Security Tests"),
                ("api_bola", "BOLA/IDOR"),
                ("api_mass_assignment", "Mass Assignment"),
                ("api_excessive_data", "Excessive Data Exposure"),
                ("api_rate_limit", "Rate Limiting"),
            ],
            "Authentication & Authorization": [
                ("jwt_analysis", "JWT Analysis"),
                ("csrf", "CSRF"),
                ("session", "Session Management"),
                ("weak_credentials", "Weak Credentials")
            ],
            "File & Path Vulnerabilities": [
                ("lfi", "Local File Inclusion"),
                ("rfi", "Remote File Inclusion"),
                ("file_upload", "File Upload"),
                ("backup_files", "Backup Files")
            ],
            "Information Disclosure": [
                ("sensitive_data", "Sensitive Data Exposure"),
                ("env_secrets", "Environment Secrets"),
                ("git", "Git Exposure")
            ],
            "Network & Infrastructure": [
                ("ssrf", "Server-Side Request Forgery"),
                ("http_smuggling", "HTTP Request Smuggling"),
                ("cors", "CORS Misconfiguration"),
                ("security_headers", "Security Headers")
            ]
        }

        # Create checkboxes by category
        for category, modules in categories.items():
            # Category header
            cat_label = QLabel(f"<b>{category}</b>")
            scroll_layout.addWidget(cat_label)

            # Module checkboxes
            for module_id, module_name in modules:
                cb = QCheckBox(module_name)
                cb.setProperty("module_id", module_id)
                self.checkboxes[module_id] = cb
                scroll_layout.addWidget(cb)

            # Spacer
            scroll_layout.addSpacing(10)

        scroll_layout.addStretch()
        scroll.setWidget(scroll_content)
        layout.addWidget(scroll)

        # Select All / Clear All buttons
        btn_layout = QHBoxLayout()
        select_all_btn = QPushButton("Select All")
        select_all_btn.clicked.connect(self._select_all)
        btn_layout.addWidget(select_all_btn)

        clear_all_btn = QPushButton("Clear All")
        clear_all_btn.clicked.connect(self._clear_all)
        btn_layout.addWidget(clear_all_btn)

        layout.addLayout(btn_layout)

        # Dialog buttons
        button_box = QDialogButtonBox(
            QDialogButtonBox.Ok | QDialogButtonBox.Cancel
        )
        button_box.accepted.connect(self._on_accept)
        button_box.rejected.connect(self.reject)
        layout.addWidget(button_box)

    def _select_all(self):
        """Select all modules"""
        for cb in self.checkboxes.values():
            cb.setChecked(True)

    def _clear_all(self):
        """Clear all selections"""
        for cb in self.checkboxes.values():
            cb.setChecked(False)

    def _on_accept(self):
        """Store selected modules and accept"""
        self.selected_modules = [
            cb.property("module_id")
            for cb in self.checkboxes.values()
            if cb.isChecked()
        ]
        if not self.selected_modules:
            QMessageBox.warning(
                self, "No Selection",
                "Please select at least one module to scan."
            )
            return
        self.accept()

    def get_selected_modules(self):
        """Return list of selected module IDs"""
        return self.selected_modules


class APIParserThread(QThread):
    """Background thread for parsing API specifications"""
    finished = pyqtSignal(list, dict)  # endpoints, summary
    error = pyqtSignal(str)
    progress = pyqtSignal(str)

    def __init__(self, source: str, format_type: str = 'auto', base_url: str = None):
        super().__init__()
        self.source = source
        self.format_type = format_type
        self.base_url = base_url

    def run(self):
        try:
            # Add parent path for imports
            parent_dir = Path(__file__).parent.parent.parent
            sys.path.insert(0, str(parent_dir))

            from utils.api_parser import APIParser

            self.progress.emit("Parsing API specification...")

            parser = APIParser()
            endpoints = parser.parse(
                self.source,
                format_type=self.format_type,
                base_url=self.base_url
            )

            summary = parser.get_summary()
            self.finished.emit(endpoints, summary)

        except Exception as e:
            self.error.emit(str(e))


class APIDiscoverThread(QThread):
    """Background thread for discovering API specs"""
    finished = pyqtSignal(str)  # spec URL or None
    error = pyqtSignal(str)
    progress = pyqtSignal(str)

    def __init__(self, target_url: str):
        super().__init__()
        self.target_url = target_url

    def run(self):
        try:
            parent_dir = Path(__file__).parent.parent.parent
            sys.path.insert(0, str(parent_dir))

            from utils.api_parser import fetch_swagger_url

            self.progress.emit("Searching for API specification...")

            spec_url = fetch_swagger_url(self.target_url)
            self.finished.emit(spec_url or "")

        except Exception as e:
            self.error.emit(str(e))


class APITestingTabBuilder:
    """Builder for API Testing tab"""

    def __init__(self, main_gui, collapsible_class=None):
        self.gui = main_gui
        self.CollapsibleBox = collapsible_class
        self.endpoints = []
        self.parser_thread = None
        self.discover_thread = None

    def build(self) -> QWidget:
        """Build the API Testing tab"""
        tab = QWidget()
        layout = QVBoxLayout(tab)
        layout.setSpacing(10)

        # Create splitter for left/right panels
        splitter = QSplitter(Qt.Horizontal)

        # Left panel - API Source
        left_panel = self._create_source_panel()
        splitter.addWidget(left_panel)

        # Right panel - Endpoints
        right_panel = self._create_endpoints_panel()
        splitter.addWidget(right_panel)

        # Set splitter sizes
        splitter.setSizes([400, 600])

        layout.addWidget(splitter)

        # Bottom panel - Actions
        bottom_panel = self._create_actions_panel()
        layout.addWidget(bottom_panel)

        return tab

    def _create_source_panel(self) -> QWidget:
        """Create API source input panel"""
        panel = QWidget()
        layout = QVBoxLayout(panel)

        # API Source Group
        source_group = QGroupBox("API Specification Source")
        source_layout = QVBoxLayout(source_group)

        # Source type
        type_layout = QHBoxLayout()
        type_layout.addWidget(QLabel("Source Type:"))
        self.gui.api_source_type = QComboBox()
        self.gui.api_source_type.addItems([
            "File", "URL", "Paste Content", "Auto-Discover"
        ])
        self.gui.api_source_type.currentTextChanged.connect(self._on_source_type_changed)
        type_layout.addWidget(self.gui.api_source_type)
        source_layout.addLayout(type_layout)

        # File input
        file_layout = QHBoxLayout()
        self.gui.api_file_input = QLineEdit()
        self.gui.api_file_input.setPlaceholderText("Path to API specification file...")
        file_layout.addWidget(self.gui.api_file_input)
        self.gui.api_browse_btn = QPushButton("Browse...")
        self.gui.api_browse_btn.clicked.connect(self._browse_api_file)
        file_layout.addWidget(self.gui.api_browse_btn)
        source_layout.addLayout(file_layout)

        # URL input (hidden by default)
        self.gui.api_url_input = QLineEdit()
        self.gui.api_url_input.setPlaceholderText("https://api.example.com/swagger.json")
        self.gui.api_url_input.hide()
        source_layout.addWidget(self.gui.api_url_input)

        # Content input (hidden by default)
        self.gui.api_content_input = QTextEdit()
        self.gui.api_content_input.setPlaceholderText("Paste API specification content here (JSON/YAML)...")
        self.gui.api_content_input.setMaximumHeight(150)
        self.gui.api_content_input.hide()
        source_layout.addWidget(self.gui.api_content_input)

        # Discover input (hidden by default)
        self.gui.api_discover_input = QLineEdit()
        self.gui.api_discover_input.setPlaceholderText("https://api.example.com")
        self.gui.api_discover_input.hide()
        source_layout.addWidget(self.gui.api_discover_input)

        # Format selection
        format_layout = QHBoxLayout()
        format_layout.addWidget(QLabel("Format:"))
        self.gui.api_format_combo = QComboBox()
        self.gui.api_format_combo.addItems([
            "Auto-Detect",
            "OpenAPI 3.x",
            "Swagger 2.0",
            "Postman Collection",
            "HAR (HTTP Archive)",
            "WADL",
            "RAML",
            "GraphQL Schema",
            "API Blueprint"
        ])
        format_layout.addWidget(self.gui.api_format_combo)
        source_layout.addLayout(format_layout)

        # Base URL override
        base_layout = QHBoxLayout()
        base_layout.addWidget(QLabel("Base URL (optional):"))
        self.gui.api_base_url = QLineEdit()
        self.gui.api_base_url.setPlaceholderText("Override base URL for endpoints...")
        base_layout.addWidget(self.gui.api_base_url)
        source_layout.addLayout(base_layout)

        # Parse button
        btn_layout = QHBoxLayout()
        self.gui.api_parse_btn = QPushButton("Parse API Specification")
        self.gui.api_parse_btn.setStyleSheet("""
            QPushButton {
                background-color: #2196F3;
                color: white;
                font-weight: bold;
                padding: 10px;
                border-radius: 4px;
            }
            QPushButton:hover {
                background-color: #1976D2;
            }
        """)
        self.gui.api_parse_btn.clicked.connect(self._parse_api_spec)
        btn_layout.addWidget(self.gui.api_parse_btn)
        source_layout.addLayout(btn_layout)

        # Progress bar
        self.gui.api_progress = QProgressBar()
        self.gui.api_progress.setTextVisible(False)
        self.gui.api_progress.hide()
        source_layout.addWidget(self.gui.api_progress)

        layout.addWidget(source_group)

        # Authentication Group
        auth_group = QGroupBox("API Authentication")
        auth_layout = QGridLayout(auth_group)

        auth_layout.addWidget(QLabel("Auth Type:"), 0, 0)
        self.gui.api_auth_type = QComboBox()
        self.gui.api_auth_type.addItems([
            "None", "Bearer Token", "API Key", "Basic Auth", "OAuth 2.0", "Custom Header"
        ])
        self.gui.api_auth_type.currentTextChanged.connect(self._on_auth_type_changed)
        auth_layout.addWidget(self.gui.api_auth_type, 0, 1)

        auth_layout.addWidget(QLabel("Token/Key:"), 1, 0)
        self.gui.api_auth_token = QLineEdit()
        self.gui.api_auth_token.setPlaceholderText("Enter token or API key...")
        self.gui.api_auth_token.setEchoMode(QLineEdit.Password)
        auth_layout.addWidget(self.gui.api_auth_token, 1, 1)

        auth_layout.addWidget(QLabel("Header Name:"), 2, 0)
        self.gui.api_auth_header_name = QLineEdit()
        self.gui.api_auth_header_name.setPlaceholderText("e.g., X-API-Key")
        self.gui.api_auth_header_name.hide()
        auth_layout.addWidget(self.gui.api_auth_header_name, 2, 1)

        self.gui.api_auth_header_label = auth_layout.itemAtPosition(2, 0).widget()
        self.gui.api_auth_header_label.hide()

        layout.addWidget(auth_group)

        # API Info (populated after parsing)
        info_group = QGroupBox("API Information")
        info_layout = QVBoxLayout(info_group)

        self.gui.api_info_label = QLabel("No API loaded")
        self.gui.api_info_label.setWordWrap(True)
        self.gui.api_info_label.setStyleSheet("color: #666; padding: 10px;")
        info_layout.addWidget(self.gui.api_info_label)

        layout.addWidget(info_group)

        layout.addStretch()

        return panel

    def _create_endpoints_panel(self) -> QWidget:
        """Create endpoints table panel"""
        panel = QWidget()
        layout = QVBoxLayout(panel)

        # Header
        header_layout = QHBoxLayout()
        header_layout.addWidget(QLabel("Discovered Endpoints"))

        self.gui.api_endpoint_count = QLabel("0 endpoints")
        self.gui.api_endpoint_count.setStyleSheet("color: #666;")
        header_layout.addStretch()
        header_layout.addWidget(self.gui.api_endpoint_count)

        # Filter
        self.gui.api_filter = QLineEdit()
        self.gui.api_filter.setPlaceholderText("Filter endpoints...")
        self.gui.api_filter.textChanged.connect(self._filter_endpoints)
        header_layout.addWidget(self.gui.api_filter)

        layout.addLayout(header_layout)

        # Endpoints table
        self.gui.api_endpoints_table = QTableWidget()
        self.gui.api_endpoints_table.setColumnCount(5)
        self.gui.api_endpoints_table.setHorizontalHeaderLabels([
            "Select", "Method", "Endpoint", "Parameters", "Description"
        ])
        self.gui.api_endpoints_table.horizontalHeader().setSectionResizeMode(2, QHeaderView.Stretch)
        self.gui.api_endpoints_table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.gui.api_endpoints_table.setAlternatingRowColors(True)
        layout.addWidget(self.gui.api_endpoints_table)

        # Selection buttons
        sel_layout = QHBoxLayout()
        select_all_btn = QPushButton("Select All")
        select_all_btn.clicked.connect(lambda: self._select_all_endpoints(True))
        sel_layout.addWidget(select_all_btn)

        deselect_all_btn = QPushButton("Deselect All")
        deselect_all_btn.clicked.connect(lambda: self._select_all_endpoints(False))
        sel_layout.addWidget(deselect_all_btn)

        sel_layout.addStretch()

        # Method filter checkboxes
        sel_layout.addWidget(QLabel("Methods:"))
        for method in ["GET", "POST", "PUT", "DELETE"]:
            cb = QCheckBox(method)
            cb.setChecked(True)
            cb.stateChanged.connect(self._filter_endpoints)
            setattr(self.gui, f'api_method_{method.lower()}', cb)
            sel_layout.addWidget(cb)

        layout.addLayout(sel_layout)

        return panel

    def _create_actions_panel(self) -> QWidget:
        """Create actions panel"""
        panel = QFrame()
        panel.setStyleSheet("background-color: #f5f5f5; border-radius: 4px; padding: 10px;")
        layout = QHBoxLayout(panel)

        # Scan options
        layout.addWidget(QLabel("Scan Selected Endpoints:"))

        self.gui.api_scan_modules = QComboBox()
        self.gui.api_scan_modules.addItems([
            "All Modules",
            "SQL Injection",
            "XSS",
            "API Security Only",
            "IDOR + Auth Bypass",
            "Injection Tests",
            "Custom Selection..."
        ])
        layout.addWidget(self.gui.api_scan_modules)

        layout.addStretch()

        # Action buttons
        self.gui.api_export_btn = QPushButton("Export Endpoints")
        self.gui.api_export_btn.clicked.connect(self._export_endpoints)
        layout.addWidget(self.gui.api_export_btn)

        self.gui.api_scan_btn = QPushButton("Scan Selected Endpoints")
        self.gui.api_scan_btn.setStyleSheet("""
            QPushButton {
                background-color: #4CAF50;
                color: white;
                font-weight: bold;
                padding: 10px 20px;
                border-radius: 4px;
            }
            QPushButton:hover {
                background-color: #45a049;
            }
        """)
        self.gui.api_scan_btn.clicked.connect(self._start_api_scan)
        layout.addWidget(self.gui.api_scan_btn)

        return panel

    def _on_source_type_changed(self, source_type: str):
        """Handle source type change"""
        # Hide all inputs
        self.gui.api_file_input.hide()
        self.gui.api_browse_btn.hide()
        self.gui.api_url_input.hide()
        self.gui.api_content_input.hide()
        self.gui.api_discover_input.hide()

        # Show relevant input
        if source_type == "File":
            self.gui.api_file_input.show()
            self.gui.api_browse_btn.show()
        elif source_type == "URL":
            self.gui.api_url_input.show()
        elif source_type == "Paste Content":
            self.gui.api_content_input.show()
        elif source_type == "Auto-Discover":
            self.gui.api_discover_input.show()

    def _on_auth_type_changed(self, auth_type: str):
        """Handle auth type change"""
        show_header = auth_type in ["API Key", "Custom Header"]
        self.gui.api_auth_header_name.setVisible(show_header)
        self.gui.api_auth_header_label.setVisible(show_header)

    def _browse_api_file(self):
        """Browse for API specification file"""
        file_filter = (
            "All API Specs (*.json *.yaml *.yml *.har *.wadl *.raml *.graphql *.gql *.apib);;"
            "OpenAPI/Swagger (*.json *.yaml *.yml);;"
            "Postman Collection (*.json);;"
            "HAR Files (*.har);;"
            "WADL Files (*.wadl);;"
            "RAML Files (*.raml);;"
            "GraphQL Schema (*.graphql *.gql);;"
            "API Blueprint (*.apib);;"
            "All Files (*.*)"
        )

        filename, _ = QFileDialog.getOpenFileName(
            self.gui, "Select API Specification", "", file_filter
        )
        if filename:
            self.gui.api_file_input.setText(filename)

    def _get_format_type(self) -> str:
        """Get format type from combo selection"""
        format_map = {
            "Auto-Detect": "auto",
            "OpenAPI 3.x": "openapi",
            "Swagger 2.0": "swagger",
            "Postman Collection": "postman",
            "HAR (HTTP Archive)": "har",
            "WADL": "wadl",
            "RAML": "raml",
            "GraphQL Schema": "graphql",
            "API Blueprint": "blueprint"
        }
        return format_map.get(self.gui.api_format_combo.currentText(), "auto")

    def _parse_api_spec(self):
        """Parse API specification"""
        source_type = self.gui.api_source_type.currentText()

        # Get source
        if source_type == "File":
            source = self.gui.api_file_input.text()
            if not source:
                QMessageBox.warning(self.gui, "Error", "Please select an API specification file")
                return
        elif source_type == "URL":
            source = self.gui.api_url_input.text()
            if not source:
                QMessageBox.warning(self.gui, "Error", "Please enter API specification URL")
                return
        elif source_type == "Paste Content":
            content = self.gui.api_content_input.toPlainText()
            if not content:
                QMessageBox.warning(self.gui, "Error", "Please paste API specification content")
                return
            # Save to temp file
            import tempfile
            with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
                f.write(content)
                source = f.name
        elif source_type == "Auto-Discover":
            target = self.gui.api_discover_input.text()
            if not target:
                QMessageBox.warning(self.gui, "Error", "Please enter target URL for discovery")
                return
            self._discover_api(target)
            return

        # Show progress
        self.gui.api_progress.show()
        self.gui.api_progress.setRange(0, 0)  # Indeterminate
        self.gui.api_parse_btn.setEnabled(False)

        # Start parser thread
        format_type = self._get_format_type()
        base_url = self.gui.api_base_url.text() or None

        self.parser_thread = APIParserThread(source, format_type, base_url)
        self.parser_thread.finished.connect(self._on_parse_finished)
        self.parser_thread.error.connect(self._on_parse_error)
        self.parser_thread.start()

    def _discover_api(self, target: str):
        """Auto-discover API specification"""
        self.gui.api_progress.show()
        self.gui.api_progress.setRange(0, 0)
        self.gui.api_parse_btn.setEnabled(False)

        self.discover_thread = APIDiscoverThread(target)
        self.discover_thread.finished.connect(self._on_discover_finished)
        self.discover_thread.error.connect(self._on_parse_error)
        self.discover_thread.start()

    def _on_discover_finished(self, spec_url: str):
        """Handle discovery completion"""
        self.gui.api_progress.hide()
        self.gui.api_parse_btn.setEnabled(True)

        if spec_url:
            self.gui.api_url_input.setText(spec_url)
            self.gui.api_source_type.setCurrentText("URL")
            self.gui.api_info_label.setText(f"Found API spec: {spec_url}\nClick 'Parse' to load endpoints.")
            QMessageBox.information(self.gui, "API Found", f"Found API specification:\n{spec_url}")
        else:
            QMessageBox.warning(self.gui, "Not Found",
                              "No API specification found at common endpoints.\n"
                              "Checked: /swagger.json, /openapi.json, /api-docs, etc.")

    def _on_parse_finished(self, endpoints: list, summary: dict):
        """Handle parse completion"""
        self.gui.api_progress.hide()
        self.gui.api_parse_btn.setEnabled(True)

        self.endpoints = endpoints

        # Get loaded file/URL for display
        source_type = self.gui.api_source_type.currentText()
        loaded_source = ""
        if source_type == "File":
            loaded_source = self.gui.api_file_input.text()
        elif source_type == "URL":
            loaded_source = self.gui.api_url_input.text()

        # Update info label with clear loaded file status
        info = summary.get('spec_info', {})
        info_text = f"<b style='color: #4CAF50;'>✓ API Loaded Successfully</b><br><br>"
        if loaded_source:
            # Truncate long paths
            display_source = loaded_source if len(loaded_source) < 50 else f"...{loaded_source[-47:]}"
            info_text += f"<b>Source:</b> {display_source}<br>"
        info_text += f"<b>API Name:</b> {info.get('title', 'Unknown API')}<br>"
        info_text += f"<b>Version:</b> {info.get('version', 'N/A')}<br>"
        info_text += f"<b>Base URL:</b> {summary.get('base_url', 'N/A')}<br>"
        info_text += f"<br><b>Endpoints:</b> {summary.get('total_endpoints', 0)}<br>"
        info_text += f"<b>Methods:</b> {summary.get('methods', {})}"

        # Auto-configure authentication from spec
        auth_info = summary.get('auth_info', {})
        if auth_info:
            auth_names = ', '.join(summary.get('auth_schemes', []))
            info_text += f"<br><br><b style='color: #2196F3;'>Authentication Required:</b> {auth_names}"

            # Auto-select auth type in dropdown based on spec
            for name, scheme in auth_info.items():
                # Use 'or' to handle None values
                auth_type = (scheme.get('type') or '').lower()
                auth_scheme = (scheme.get('scheme') or '').lower()

                if auth_type == 'http' and auth_scheme == 'bearer':
                    self.gui.api_auth_type.setCurrentText("Bearer Token")
                    info_text += f"<br><i>→ Enter your Bearer token below</i>"
                elif auth_type == 'oauth2':
                    self.gui.api_auth_type.setCurrentText("Bearer Token")
                    info_text += f"<br><i>→ Enter your OAuth2 access token below</i>"
                elif auth_type == 'apikey':
                    self.gui.api_auth_type.setCurrentText("API Key")
                    header_name = scheme.get('name') or 'X-API-Key'
                    self.gui.api_auth_header_name.setText(header_name)
                    self.gui.api_auth_header_name.show()
                    self.gui.api_auth_header_label.show()
                    info_text += f"<br><i>→ Enter API key for header: {header_name}</i>"
                elif auth_type == 'http' and auth_scheme == 'basic':
                    self.gui.api_auth_type.setCurrentText("Basic Auth")
                    info_text += f"<br><i>→ Enter Basic auth credentials</i>"
                break  # Use first auth scheme found
        else:
            info_text += f"<br><br><b style='color: #666;'>No authentication required</b>"

        self.gui.api_info_label.setText(info_text)

        # Populate endpoints table
        self._populate_endpoints_table(endpoints)

        # Update count
        self.gui.api_endpoint_count.setText(f"{len(endpoints)} endpoints")

    def _on_parse_error(self, error: str):
        """Handle parse error"""
        self.gui.api_progress.hide()
        self.gui.api_parse_btn.setEnabled(True)
        QMessageBox.critical(self.gui, "Parse Error", f"Failed to parse API specification:\n{error}")

    def _populate_endpoints_table(self, endpoints: list):
        """Populate endpoints table"""
        table = self.gui.api_endpoints_table
        table.setRowCount(len(endpoints))

        method_colors = {
            'GET': '#61affe',
            'POST': '#49cc90',
            'PUT': '#fca130',
            'DELETE': '#f93e3e',
            'PATCH': '#50e3c2',
            'HEAD': '#9012fe',
            'OPTIONS': '#0d5aa7'
        }

        for i, ep in enumerate(endpoints):
            # Checkbox
            checkbox = QCheckBox()
            checkbox.setChecked(True)
            table.setCellWidget(i, 0, checkbox)

            # Method
            method_item = QTableWidgetItem(ep.method)
            method_item.setBackground(QColor(method_colors.get(ep.method, '#666')))
            method_item.setForeground(QColor('white'))
            method_item.setTextAlignment(Qt.AlignCenter)
            table.setItem(i, 1, method_item)

            # URL
            table.setItem(i, 2, QTableWidgetItem(ep.url))

            # Parameters
            params = []
            if ep.params:
                params.extend(ep.params.keys())
            if ep.body and isinstance(ep.body, dict):
                params.extend(ep.body.keys())
            params_text = ', '.join(params[:5])
            if len(params) > 5:
                params_text += f" (+{len(params)-5})"
            table.setItem(i, 3, QTableWidgetItem(params_text))

            # Description
            table.setItem(i, 4, QTableWidgetItem(ep.description or ""))

        table.resizeRowsToContents()

    def _select_all_endpoints(self, select: bool):
        """Select or deselect all endpoints"""
        for i in range(self.gui.api_endpoints_table.rowCount()):
            checkbox = self.gui.api_endpoints_table.cellWidget(i, 0)
            if checkbox:
                checkbox.setChecked(select)

    def _filter_endpoints(self):
        """Filter endpoints by text and method"""
        filter_text = self.gui.api_filter.text().lower()
        allowed_methods = []

        for method in ["GET", "POST", "PUT", "DELETE"]:
            cb = getattr(self.gui, f'api_method_{method.lower()}', None)
            if cb and cb.isChecked():
                allowed_methods.append(method)

        table = self.gui.api_endpoints_table
        for i in range(table.rowCount()):
            method_item = table.item(i, 1)
            url_item = table.item(i, 2)

            method = method_item.text() if method_item else ""
            url = url_item.text().lower() if url_item else ""

            # Check method filter
            method_ok = method in allowed_methods or method not in ["GET", "POST", "PUT", "DELETE"]

            # Check text filter
            text_ok = not filter_text or filter_text in url

            table.setRowHidden(i, not (method_ok and text_ok))

    def _export_endpoints(self):
        """Export endpoints to file"""
        if not self.endpoints:
            QMessageBox.warning(self.gui, "No Endpoints", "Please load an API specification first")
            return

        filename, _ = QFileDialog.getSaveFileName(
            self.gui, "Export Endpoints",
            "api_endpoints.json",
            "JSON Files (*.json);;Text Files (*.txt)"
        )

        if not filename:
            return

        try:
            if filename.endswith('.json'):
                data = [ep.to_target() for ep in self.endpoints]
                with open(filename, 'w') as f:
                    json.dump(data, f, indent=2)
            else:
                with open(filename, 'w') as f:
                    for ep in self.endpoints:
                        f.write(f"{ep.method} {ep.url}\n")

            QMessageBox.information(self.gui, "Export Complete", f"Exported {len(self.endpoints)} endpoints to:\n{filename}")

        except Exception as e:
            QMessageBox.critical(self.gui, "Export Error", f"Failed to export:\n{e}")

    def _get_selected_endpoints(self) -> list:
        """Get list of selected endpoints"""
        selected = []
        for i in range(self.gui.api_endpoints_table.rowCount()):
            if self.gui.api_endpoints_table.isRowHidden(i):
                continue
            checkbox = self.gui.api_endpoints_table.cellWidget(i, 0)
            if checkbox and checkbox.isChecked():
                if i < len(self.endpoints):
                    selected.append(self.endpoints[i])
        return selected

    def _start_api_scan(self):
        """Start scanning selected endpoints"""
        selected = self._get_selected_endpoints()

        if not selected:
            QMessageBox.warning(self.gui, "No Selection", "Please select at least one endpoint to scan")
            return

        # Get auth headers
        auth_headers = {}
        auth_type = self.gui.api_auth_type.currentText()
        token = self.gui.api_auth_token.text()

        if token:
            if auth_type == "Bearer Token":
                auth_headers['Authorization'] = f'Bearer {token}'
            elif auth_type == "API Key":
                header_name = self.gui.api_auth_header_name.text() or 'X-API-Key'
                auth_headers[header_name] = token
            elif auth_type == "Custom Header":
                header_name = self.gui.api_auth_header_name.text()
                if header_name:
                    auth_headers[header_name] = token

        # Prepare targets for scanner
        targets = []
        for ep in selected:
            target = ep.to_target()
            target['headers'].update(auth_headers)
            targets.append(target)

        # Store targets and switch to scan tab
        self.gui.api_scan_targets = targets

        # Set first endpoint as main target
        if targets:
            first_url = targets[0]['url']
            self.gui.target_input.setPlainText(first_url)

        # Configure scan options
        scan_type = self.gui.api_scan_modules.currentText()
        custom_modules = None

        # Handle Custom Selection
        if scan_type == "Custom Selection...":
            dialog = ModuleSelectorDialog(self.gui)
            if dialog.exec_() == QDialog.Accepted:
                selected_modules = dialog.get_selected_modules()
                if selected_modules:
                    # Apply selected modules
                    self.gui.all_modules_cb.setChecked(False)
                    for name, cb in self.gui.module_checkboxes.items():
                        cb.setChecked(name in selected_modules)
                    custom_modules = selected_modules
                    scan_type = f"{len(selected_modules)} modules"
                else:
                    return  # No modules selected, abort
            else:
                return  # Dialog cancelled
        else:
            # Use preset module groups
            module_map = {
                "All Modules": None,  # All modules
                "SQL Injection": "sqli",
                "XSS": "xss",
                "API Security Only": "api_security",
                "IDOR + Auth Bypass": "idor,jwt_analysis",
                "Injection Tests": "sqli,xss,cmdi,ssti"
            }

            modules = module_map.get(scan_type)
            if modules:
                # Select specific modules
                self.gui.all_modules_cb.setChecked(False)
                for name, cb in self.gui.module_checkboxes.items():
                    cb.setChecked(name in modules.split(','))
            else:
                self.gui.all_modules_cb.setChecked(True)

        # Enable single-page mode (no crawling for API)
        self.gui.single_page_cb.setChecked(True)

        # Switch to scan tab
        self.gui.tabs.setCurrentIndex(0)

        # Show brief notification
        self.gui.statusBar().showMessage(
            f"Starting API scan on {len(selected)} endpoints with {scan_type}...",
            3000
        )

        # Enable output logging for API scans so user can see progress
        if hasattr(self.gui, 'output_enabled_cb'):
            self.gui.output_enabled_cb.setChecked(True)

        # Auto-start the scan immediately
        try:
            self.gui.start_scan()
        except Exception as e:
            from PyQt5.QtWidgets import QMessageBox
            QMessageBox.critical(
                self.gui,
                "Scan Error",
                f"Failed to start API scan:\n\n{str(e)}\n\n" +
                "Please check:\n" +
                "1. Endpoints are selected and valid\n" +
                "2. Modules are selected\n" +
                "3. Check output console for details"
            )
            import traceback
            traceback.print_exc()
