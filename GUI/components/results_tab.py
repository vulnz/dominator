"""
Enhanced Results Tab with detailed vulnerability display
"""

from PyQt5.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QTableWidget,
                             QTableWidgetItem, QPushButton, QLabel, QTextEdit,
                             QSplitter, QGroupBox, QComboBox, QLineEdit, QCheckBox,
                             QTabWidget, QHeaderView, QAbstractItemView)
from PyQt5.QtCore import Qt, pyqtSignal
from PyQt5.QtGui import QColor, QFont


class ResultsTab(QWidget):
    """Enhanced Results Tab with detailed vulnerability information"""

    export_requested = pyqtSignal()

    def __init__(self, parent=None):
        super().__init__(parent)
        self.vulnerabilities = []
        self.current_selected_vuln = None
        self.init_ui()

    def init_ui(self):
        """Initialize the UI components"""
        layout = QVBoxLayout(self)
        layout.setContentsMargins(10, 10, 10, 10)

        # Top controls
        controls_layout = self.create_controls()
        layout.addLayout(controls_layout)

        # Main splitter - Vuln list on left, details on right
        splitter = QSplitter(Qt.Horizontal)

        # Left: Vulnerabilities table
        left_widget = self.create_vulnerabilities_table()
        splitter.addWidget(left_widget)

        # Right: Detailed view
        right_widget = self.create_details_view()
        splitter.addWidget(right_widget)

        # Set splitter ratio (40% list, 60% details)
        splitter.setStretchFactor(0, 4)
        splitter.setStretchFactor(1, 6)

        layout.addWidget(splitter)

        # Bottom: Statistics
        stats_layout = self.create_statistics()
        layout.addLayout(stats_layout)

    def create_controls(self):
        """Create filter and control buttons"""
        layout = QHBoxLayout()

        # Severity filter
        severity_label = QLabel("Severity:")
        self.severity_filter = QComboBox()
        self.severity_filter.addItems(["All", "Critical", "High", "Medium", "Low", "Info"])
        self.severity_filter.currentTextChanged.connect(self.apply_filters)

        # Type filter
        type_label = QLabel("Type:")
        self.type_filter = QComboBox()
        self.type_filter.addItem("All Types")
        self.type_filter.currentTextChanged.connect(self.apply_filters)

        # Search
        search_label = QLabel("Search:")
        self.search_input = QLineEdit()
        self.search_input.setPlaceholderText("Search in URL, description...")
        self.search_input.textChanged.connect(self.apply_filters)

        # Show only verified
        self.verified_only_checkbox = QCheckBox("Verified only")
        self.verified_only_checkbox.stateChanged.connect(self.apply_filters)

        # Buttons
        self.export_btn = QPushButton("Export Results")
        self.export_btn.clicked.connect(self.export_requested.emit)

        self.clear_btn = QPushButton("Clear")
        self.clear_btn.clicked.connect(self.clear_results)

        # Add to layout
        layout.addWidget(severity_label)
        layout.addWidget(self.severity_filter)
        layout.addWidget(type_label)
        layout.addWidget(self.type_filter)
        layout.addWidget(search_label)
        layout.addWidget(self.search_input, 1)
        layout.addWidget(self.verified_only_checkbox)
        layout.addWidget(self.export_btn)
        layout.addWidget(self.clear_btn)

        return layout

    def create_vulnerabilities_table(self):
        """Create vulnerabilities list table"""
        group = QGroupBox("Vulnerabilities Found")
        layout = QVBoxLayout(group)

        self.vuln_table = QTableWidget(0, 5)
        self.vuln_table.setHorizontalHeaderLabels([
            "Severity", "Type", "URL", "Parameter", "Confidence"
        ])

        # Table settings
        self.vuln_table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.vuln_table.setSelectionMode(QAbstractItemView.SingleSelection)
        self.vuln_table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.vuln_table.setAlternatingRowColors(True)

        # Column widths
        header = self.vuln_table.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.ResizeToContents)  # Severity
        header.setSectionResizeMode(1, QHeaderView.ResizeToContents)  # Type
        header.setSectionResizeMode(2, QHeaderView.Stretch)           # URL
        header.setSectionResizeMode(3, QHeaderView.ResizeToContents)  # Parameter
        header.setSectionResizeMode(4, QHeaderView.ResizeToContents)  # Confidence

        # Selection change
        self.vuln_table.itemSelectionChanged.connect(self.on_vulnerability_selected)

        layout.addWidget(self.vuln_table)
        return group

    def create_details_view(self):
        """Create detailed vulnerability view"""
        group = QGroupBox("Vulnerability Details")
        layout = QVBoxLayout(group)

        # Tab widget for different detail sections
        self.details_tabs = QTabWidget()

        # Tab 1: Overview
        overview_tab = QWidget()
        overview_layout = QVBoxLayout(overview_tab)
        self.overview_text = QTextEdit()
        self.overview_text.setReadOnly(True)
        overview_layout.addWidget(self.overview_text)
        self.details_tabs.addTab(overview_tab, "Overview")

        # Tab 2: Request
        request_tab = QWidget()
        request_layout = QVBoxLayout(request_tab)

        # HTTP Request
        request_label = QLabel("HTTP Request:")
        request_label.setFont(QFont("Consolas", 10, QFont.Bold))
        self.request_text = QTextEdit()
        self.request_text.setReadOnly(True)
        self.request_text.setFont(QFont("Consolas", 9))

        # Copy request button
        copy_request_btn = QPushButton("Copy Request")
        copy_request_btn.clicked.connect(self.copy_request)

        request_layout.addWidget(request_label)
        request_layout.addWidget(self.request_text)
        request_layout.addWidget(copy_request_btn)
        self.details_tabs.addTab(request_tab, "Request")

        # Tab 3: Response
        response_tab = QWidget()
        response_layout = QVBoxLayout(response_tab)

        # HTTP Response
        response_label = QLabel("HTTP Response:")
        response_label.setFont(QFont("Consolas", 10, QFont.Bold))
        self.response_text = QTextEdit()
        self.response_text.setReadOnly(True)
        self.response_text.setFont(QFont("Consolas", 9))

        # Copy response button
        copy_response_btn = QPushButton("Copy Response")
        copy_response_btn.clicked.connect(self.copy_response)

        response_layout.addWidget(response_label)
        response_layout.addWidget(self.response_text)
        response_layout.addWidget(copy_response_btn)
        self.details_tabs.addTab(response_tab, "Response")

        # Tab 4: Evidence
        evidence_tab = QWidget()
        evidence_layout = QVBoxLayout(evidence_tab)
        self.evidence_text = QTextEdit()
        self.evidence_text.setReadOnly(True)
        evidence_layout.addWidget(self.evidence_text)
        self.details_tabs.addTab(evidence_tab, "Evidence")

        # Tab 5: Remediation
        remediation_tab = QWidget()
        remediation_layout = QVBoxLayout(remediation_tab)
        self.remediation_text = QTextEdit()
        self.remediation_text.setReadOnly(True)
        remediation_layout.addWidget(self.remediation_text)
        self.details_tabs.addTab(remediation_tab, "Remediation")

        # Tab 6: CURL Command
        curl_tab = QWidget()
        curl_layout = QVBoxLayout(curl_tab)

        curl_label = QLabel("CURL Command to reproduce:")
        curl_label.setFont(QFont("Consolas", 10, QFont.Bold))
        self.curl_text = QTextEdit()
        self.curl_text.setReadOnly(True)
        self.curl_text.setFont(QFont("Consolas", 9))

        copy_curl_btn = QPushButton("Copy CURL Command")
        copy_curl_btn.clicked.connect(self.copy_curl)

        curl_layout.addWidget(curl_label)
        curl_layout.addWidget(self.curl_text)
        curl_layout.addWidget(copy_curl_btn)
        self.details_tabs.addTab(curl_tab, "CURL")

        layout.addWidget(self.details_tabs)
        return group

    def create_statistics(self):
        """Create statistics labels"""
        layout = QHBoxLayout()

        self.total_label = QLabel("Total: 0")
        self.critical_label = QLabel("Critical: 0")
        self.high_label = QLabel("High: 0")
        self.medium_label = QLabel("Medium: 0")
        self.low_label = QLabel("Low: 0")
        self.info_label = QLabel("Info: 0")

        # Style labels
        font = QFont()
        font.setBold(True)

        for label in [self.total_label, self.critical_label, self.high_label,
                     self.medium_label, self.low_label, self.info_label]:
            label.setFont(font)

        layout.addWidget(self.total_label)
        layout.addWidget(QLabel("|"))
        layout.addWidget(self.critical_label)
        layout.addWidget(self.high_label)
        layout.addWidget(self.medium_label)
        layout.addWidget(self.low_label)
        layout.addWidget(self.info_label)
        layout.addStretch()

        return layout

    def add_vulnerability(self, vuln_data):
        """Add a vulnerability to the table"""
        self.vulnerabilities.append(vuln_data)

        # Update type filter
        vuln_type = vuln_data.get('vulnerability_type', 'Unknown')
        if self.type_filter.findText(vuln_type) == -1:
            self.type_filter.addItem(vuln_type)

        # Add to table if passes filters
        if self.passes_filters(vuln_data):
            self.add_to_table(vuln_data)

        # Update statistics
        self.update_statistics()

    def add_to_table(self, vuln_data):
        """Add vulnerability to table widget"""
        row = self.vuln_table.rowCount()
        self.vuln_table.insertRow(row)

        # Severity
        severity = vuln_data.get('severity', 'Unknown')
        severity_item = QTableWidgetItem(severity)
        severity_item.setData(Qt.UserRole, vuln_data)  # Store full data

        # Color code by severity
        color = self.get_severity_color(severity)
        severity_item.setForeground(color)
        font = QFont()
        font.setBold(True)
        severity_item.setFont(font)

        # Type
        vuln_type = vuln_data.get('vulnerability_type', 'Unknown')
        type_item = QTableWidgetItem(vuln_type)

        # URL
        url = vuln_data.get('url', 'N/A')
        url_item = QTableWidgetItem(url)

        # Parameter
        param = vuln_data.get('parameter', vuln_data.get('param', 'N/A'))
        param_item = QTableWidgetItem(param)

        # Confidence
        confidence = vuln_data.get('confidence', 'Medium')
        confidence_item = QTableWidgetItem(confidence)

        self.vuln_table.setItem(row, 0, severity_item)
        self.vuln_table.setItem(row, 1, type_item)
        self.vuln_table.setItem(row, 2, url_item)
        self.vuln_table.setItem(row, 3, param_item)
        self.vuln_table.setItem(row, 4, confidence_item)

    def get_severity_color(self, severity):
        """Get color for severity level"""
        colors = {
            'Critical': QColor(255, 0, 85),      # Red
            'High': QColor(255, 165, 0),         # Orange
            'Medium': QColor(255, 255, 0),       # Yellow
            'Low': QColor(0, 255, 136),          # Green
            'Info': QColor(0, 212, 255)          # Blue
        }
        return colors.get(severity, QColor(255, 255, 255))

    def on_vulnerability_selected(self):
        """Handle vulnerability selection"""
        selected = self.vuln_table.selectedItems()
        if not selected:
            return

        # Get vuln data from first column
        row = selected[0].row()
        severity_item = self.vuln_table.item(row, 0)
        vuln_data = severity_item.data(Qt.UserRole)

        self.current_selected_vuln = vuln_data
        self.display_vulnerability_details(vuln_data)

    def display_vulnerability_details(self, vuln_data):
        """Display detailed vulnerability information"""
        # Overview tab
        overview = f"""
<h2 style='color: {self.get_severity_color(vuln_data.get('severity', 'Unknown')).name()};'>
    {vuln_data.get('vulnerability_type', 'Unknown')} - {vuln_data.get('severity', 'Unknown')}
</h2>

<p><b>URL:</b> {vuln_data.get('url', 'N/A')}</p>
<p><b>Parameter:</b> {vuln_data.get('parameter', vuln_data.get('param', 'N/A'))}</p>
<p><b>Method:</b> {vuln_data.get('method', 'GET')}</p>
<p><b>Confidence:</b> {vuln_data.get('confidence', 'Medium')}</p>

<hr>

<h3>Description:</h3>
<p>{vuln_data.get('description', 'No description available.')}</p>

<hr>

<h3>Impact:</h3>
<p>{vuln_data.get('impact', 'See remediation for details.')}</p>

<hr>

<h3>Technical Details:</h3>
<p><b>CWE:</b> {vuln_data.get('cwe', 'N/A')}</p>
<p><b>OWASP:</b> {vuln_data.get('owasp', 'N/A')}</p>
<p><b>CVSS Score:</b> {vuln_data.get('cvss', 'N/A')}</p>
<p><b>Response Code:</b> {vuln_data.get('response_code', 'N/A')}</p>
        """
        self.overview_text.setHtml(overview)

        # Request tab
        request = vuln_data.get('request', 'No request data captured.')
        self.request_text.setPlainText(request)

        # Response tab
        response = vuln_data.get('response_body', vuln_data.get('response', 'No response data captured.'))
        # Highlight payload if present
        payload = vuln_data.get('payload', '')
        if payload and payload in response:
            # Simple highlight
            response = response.replace(payload, f'>>> {payload} <<<')
        self.response_text.setPlainText(response)

        # Evidence tab
        evidence = vuln_data.get('evidence', vuln_data.get('match', 'No evidence captured.'))
        if isinstance(evidence, list):
            evidence = '\n'.join([f"- {item}" for item in evidence])
        self.evidence_text.setPlainText(str(evidence))

        # Remediation tab
        remediation = vuln_data.get('remediation', 'No remediation information available.')
        self.remediation_text.setPlainText(remediation)

        # CURL tab
        curl_command = self.generate_curl_command(vuln_data)
        self.curl_text.setPlainText(curl_command)

    def generate_curl_command(self, vuln_data):
        """Generate CURL command to reproduce the vulnerability"""
        url = vuln_data.get('url', '')
        method = vuln_data.get('method', 'GET').upper()
        payload = vuln_data.get('payload', '')
        param = vuln_data.get('parameter', vuln_data.get('param', ''))

        curl = f"curl -X {method}"

        # Add URL
        if method == 'GET' and param and payload:
            # Append parameter
            separator = '&' if '?' in url else '?'
            curl += f" '{url}{separator}{param}={payload}'"
        else:
            curl += f" '{url}'"

        # Add headers
        headers = vuln_data.get('headers', {})
        for key, value in headers.items():
            curl += f" -H '{key}: {value}'"

        # Add POST data
        if method == 'POST':
            post_data = vuln_data.get('post_data', vuln_data.get('data', ''))
            if param and payload:
                curl += f" -d '{param}={payload}'"
            elif post_data:
                curl += f" -d '{post_data}'"

        # Add common options
        curl += " -i"  # Include headers
        curl += " -k"  # Ignore SSL errors
        curl += " -L"  # Follow redirects

        return curl

    def copy_request(self):
        """Copy HTTP request to clipboard"""
        from PyQt5.QtWidgets import QApplication
        QApplication.clipboard().setText(self.request_text.toPlainText())

    def copy_response(self):
        """Copy HTTP response to clipboard"""
        from PyQt5.QtWidgets import QApplication
        QApplication.clipboard().setText(self.response_text.toPlainText())

    def copy_curl(self):
        """Copy CURL command to clipboard"""
        from PyQt5.QtWidgets import QApplication
        QApplication.clipboard().setText(self.curl_text.toPlainText())

    def apply_filters(self):
        """Apply filters to vulnerability list"""
        # Clear table
        self.vuln_table.setRowCount(0)

        # Re-add matching vulnerabilities
        for vuln in self.vulnerabilities:
            if self.passes_filters(vuln):
                self.add_to_table(vuln)

    def passes_filters(self, vuln_data):
        """Check if vulnerability passes current filters"""
        # Severity filter
        severity_filter = self.severity_filter.currentText()
        if severity_filter != "All":
            if vuln_data.get('severity', '') != severity_filter:
                return False

        # Type filter
        type_filter = self.type_filter.currentText()
        if type_filter != "All Types":
            if vuln_data.get('vulnerability_type', '') != type_filter:
                return False

        # Search filter
        search_text = self.search_input.text().lower()
        if search_text:
            url = vuln_data.get('url', '').lower()
            desc = vuln_data.get('description', '').lower()
            vuln_type = vuln_data.get('vulnerability_type', '').lower()
            if search_text not in url and search_text not in desc and search_text not in vuln_type:
                return False

        # Verified only
        if self.verified_only_checkbox.isChecked():
            if vuln_data.get('confidence', 'Medium') != 'High':
                return False

        return True

    def update_statistics(self):
        """Update statistics labels"""
        stats = {'Critical': 0, 'High': 0, 'Medium': 0, 'Low': 0, 'Info': 0}

        for vuln in self.vulnerabilities:
            severity = vuln.get('severity', 'Unknown')
            if severity in stats:
                stats[severity] += 1

        total = len(self.vulnerabilities)

        self.total_label.setText(f"Total: {total}")
        self.critical_label.setText(f"Critical: {stats['Critical']}")
        self.high_label.setText(f"High: {stats['High']}")
        self.medium_label.setText(f"Medium: {stats['Medium']}")
        self.low_label.setText(f"Low: {stats['Low']}")
        self.info_label.setText(f"Info: {stats['Info']}")

        # Color code labels
        self.critical_label.setStyleSheet("color: #ff0055;")
        self.high_label.setStyleSheet("color: #ffa500;")
        self.medium_label.setStyleSheet("color: #ffff00;")
        self.low_label.setStyleSheet("color: #00ff88;")
        self.info_label.setStyleSheet("color: #00d4ff;")

    def clear_results(self):
        """Clear all results"""
        self.vulnerabilities = []
        self.vuln_table.setRowCount(0)
        self.overview_text.clear()
        self.request_text.clear()
        self.response_text.clear()
        self.evidence_text.clear()
        self.remediation_text.clear()
        self.curl_text.clear()
        self.update_statistics()
