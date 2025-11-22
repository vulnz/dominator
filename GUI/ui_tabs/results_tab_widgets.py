"""
Results Tab Widgets
Contains reusable widget classes for the Results tab.
"""

import json
from datetime import datetime
from PyQt5.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QGridLayout, QGroupBox,
    QLabel, QTextEdit, QFrame, QToolButton, QSizePolicy,
    QDialog, QDialogButtonBox, QTabWidget, QPushButton, QMenu,
    QAction, QFileDialog, QMessageBox
)
from PyQt5.QtCore import Qt
from PyQt5.QtGui import QColor, QFont, QPainter, QBrush, QPen


# Severity color constants
SEVERITY_COLORS = {
    'CRITICAL': '#f44336',
    'HIGH': '#FF9800',
    'MEDIUM': '#FFC107',
    'LOW': '#4CAF50',
    'INFO': '#2196F3'
}


class CollapsibleResourcesSection(QWidget):
    """A collapsible section widget for displaying discovered resources"""

    def __init__(self, title="Discovered Resources", parent=None):
        super().__init__(parent)
        self.is_collapsed = True
        self.setup_ui(title)

    def setup_ui(self, title):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)

        # Header button to toggle collapse
        self.toggle_button = QToolButton()
        self.toggle_button.setStyleSheet("""
            QToolButton {
                background-color: #f5f5f5;
                border: 1px solid #e0e0e0;
                border-radius: 4px;
                padding: 8px;
                text-align: left;
                font-weight: bold;
                color: #333333;
            }
            QToolButton:hover {
                background-color: #e8e8e8;
            }
        """)
        self.toggle_button.setToolButtonStyle(Qt.ToolButtonTextBesideIcon)
        self.toggle_button.setArrowType(Qt.RightArrow)
        self.toggle_button.setText(f" {title}")
        self.toggle_button.setCheckable(True)
        self.toggle_button.setChecked(False)
        self.toggle_button.clicked.connect(self.toggle_content)
        self.toggle_button.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)
        layout.addWidget(self.toggle_button)

        # Content area
        self.content_area = QFrame()
        self.content_area.setStyleSheet("""
            QFrame {
                background-color: #ffffff;
                border: 1px solid #e0e0e0;
                border-top: none;
                border-radius: 0px 0px 4px 4px;
            }
        """)
        self.content_area.setMaximumHeight(0)
        self.content_area.setMinimumHeight(0)

        self.content_layout = QVBoxLayout(self.content_area)
        self.content_layout.setContentsMargins(10, 10, 10, 10)
        self.content_layout.setSpacing(10)

        layout.addWidget(self.content_area)

    def toggle_content(self):
        """Toggle the collapsed state of the content area"""
        self.is_collapsed = not self.is_collapsed

        if self.is_collapsed:
            self.toggle_button.setArrowType(Qt.RightArrow)
            self.content_area.setMaximumHeight(0)
        else:
            self.toggle_button.setArrowType(Qt.DownArrow)
            # Set a reasonable max height for the content
            self.content_area.setMaximumHeight(400)

    def add_widget(self, widget):
        """Add a widget to the content area"""
        self.content_layout.addWidget(widget)

    def expand(self):
        """Expand the section"""
        if self.is_collapsed:
            self.toggle_button.setChecked(True)
            self.toggle_content()


class PieChartWidget(QWidget):
    """Custom widget to draw a pie chart for severity distribution"""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.data = {}
        self.setMinimumSize(150, 150)
        self.setMaximumSize(200, 200)

    def set_data(self, data):
        """Set pie chart data: dict of {label: count}"""
        self.data = data
        self.update()

    def paintEvent(self, event):
        if not self.data or sum(self.data.values()) == 0:
            return

        painter = QPainter(self)
        painter.setRenderHint(QPainter.Antialiasing)

        # Calculate total
        total = sum(self.data.values())
        if total == 0:
            return

        # Draw pie slices
        rect = self.rect().adjusted(10, 10, -10, -10)
        start_angle = 0

        colors = {
            'CRITICAL': QColor(SEVERITY_COLORS['CRITICAL']),
            'HIGH': QColor(SEVERITY_COLORS['HIGH']),
            'MEDIUM': QColor(SEVERITY_COLORS['MEDIUM']),
            'LOW': QColor(SEVERITY_COLORS['LOW']),
            'INFO': QColor(SEVERITY_COLORS['INFO'])
        }

        for label, count in self.data.items():
            if count == 0:
                continue
            span_angle = int((count / total) * 360 * 16)

            color = colors.get(label.upper(), QColor('#888888'))
            painter.setBrush(QBrush(color))
            painter.setPen(QPen(Qt.white, 1))
            painter.drawPie(rect, start_angle, span_angle)

            start_angle += span_angle


class TimelineWidget(QWidget):
    """Custom widget to draw a timeline bar chart of findings over time"""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.data = []  # List of (timestamp, severity) tuples
        self.setMinimumSize(200, 80)
        self.setMaximumHeight(100)

    def set_data(self, data):
        """Set timeline data: list of (timestamp, severity) tuples"""
        self.data = data
        self.update()

    def paintEvent(self, event):
        if not self.data:
            painter = QPainter(self)
            painter.setPen(QColor('#888888'))
            painter.drawText(self.rect(), Qt.AlignCenter, "No data yet")
            return

        painter = QPainter(self)
        painter.setRenderHint(QPainter.Antialiasing)

        # Group by minute buckets
        buckets = {}
        for timestamp, severity in self.data:
            minute = timestamp.replace(second=0, microsecond=0)
            if minute not in buckets:
                buckets[minute] = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0, 'INFO': 0}
            buckets[minute][severity] = buckets[minute].get(severity, 0) + 1

        if not buckets:
            return

        # Draw bars
        sorted_times = sorted(buckets.keys())
        bar_width = max(5, (self.width() - 20) // max(len(sorted_times), 1))
        max_count = max(sum(b.values()) for b in buckets.values()) if buckets else 1

        x = 10
        for time in sorted_times:
            bucket = buckets[time]
            y = self.height() - 10

            for severity in ['INFO', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL']:
                count = bucket.get(severity, 0)
                if count == 0:
                    continue

                height = int((count / max_count) * (self.height() - 20))
                color = QColor(SEVERITY_COLORS.get(severity, '#888888'))
                painter.setBrush(QBrush(color))
                painter.setPen(Qt.NoPen)
                painter.drawRect(x, y - height, bar_width - 2, height)
                y -= height

            x += bar_width


class StatsCard(QFrame):
    """A styled card widget for displaying statistics"""

    def __init__(self, title, value="0", color="#333333", parent=None):
        super().__init__(parent)
        self.setFrameShape(QFrame.StyledPanel)
        self.setStyleSheet(f"""
            QFrame {{
                background-color: #ffffff;
                border: 2px solid {color};
                border-radius: 8px;
                padding: 10px;
            }}
        """)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(10, 10, 10, 10)
        layout.setSpacing(5)

        self.title_label = QLabel(title)
        self.title_label.setStyleSheet(f"color: #666666; font-size: 11px; font-weight: bold;")
        self.title_label.setAlignment(Qt.AlignCenter)

        self.value_label = QLabel(value)
        self.value_label.setStyleSheet(f"color: {color}; font-size: 24px; font-weight: bold;")
        self.value_label.setAlignment(Qt.AlignCenter)

        layout.addWidget(self.title_label)
        layout.addWidget(self.value_label)

    def set_value(self, value):
        self.value_label.setText(str(value))


class FindingDetailDialog(QDialog):
    """Dialog to show detailed finding information"""

    def __init__(self, finding_data, parent=None):
        super().__init__(parent)
        self.finding = finding_data
        self.setWindowTitle("Finding Details")
        self.setMinimumSize(700, 600)
        self.setup_ui()

    def setup_ui(self):
        layout = QVBoxLayout(self)

        # Header with severity badge
        header = QHBoxLayout()

        severity = self.finding.get('severity', 'INFO')
        severity_label = QLabel(f"  {severity}  ")
        severity_label.setStyleSheet(f"""
            background-color: {SEVERITY_COLORS.get(severity, '#888888')};
            color: white;
            font-weight: bold;
            padding: 5px 10px;
            border-radius: 4px;
        """)
        header.addWidget(severity_label)

        title_label = QLabel(self.finding.get('title', 'Unknown Finding'))
        title_label.setStyleSheet("font-size: 16px; font-weight: bold; color: #333333;")
        header.addWidget(title_label)
        header.addStretch()

        layout.addLayout(header)

        # Tab widget for different sections
        tabs = QTabWidget()

        # Overview tab
        overview_tab = self._create_overview_tab()
        tabs.addTab(overview_tab, "Overview")

        # Technical Details tab
        technical_tab = self._create_technical_tab()
        tabs.addTab(technical_tab, "Technical Details")

        # Request/Response tab
        http_tab = self._create_http_tab()
        tabs.addTab(http_tab, "Request/Response")

        # Remediation tab
        remediation_tab = self._create_remediation_tab()
        tabs.addTab(remediation_tab, "Remediation")

        layout.addWidget(tabs)

        # Buttons
        button_box = QDialogButtonBox()

        # Export button with dropdown menu for TXT/HTML/JSON
        export_btn = QPushButton("📤 Export Finding")
        export_btn.setStyleSheet("""
            QPushButton {
                background-color: #4CAF50;
                color: white;
                padding: 6px 12px;
                border-radius: 4px;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: #45a049;
            }
            QPushButton::menu-indicator {
                image: none;
                width: 0px;
            }
        """)

        # Create menu for export formats
        export_menu = QMenu(export_btn)
        export_menu.setStyleSheet("""
            QMenu {
                background-color: white;
                border: 1px solid #ccc;
            }
            QMenu::item {
                padding: 6px 20px;
            }
            QMenu::item:selected {
                background-color: #4CAF50;
                color: white;
            }
        """)

        txt_action = QAction("📄 Export as TXT", self)
        txt_action.triggered.connect(lambda: self.export_finding('txt'))
        export_menu.addAction(txt_action)

        html_action = QAction("🌐 Export as HTML", self)
        html_action.triggered.connect(lambda: self.export_finding('html'))
        export_menu.addAction(html_action)

        json_action = QAction("📋 Export as JSON", self)
        json_action.triggered.connect(lambda: self.export_finding('json'))
        export_menu.addAction(json_action)

        export_btn.setMenu(export_menu)
        button_box.addButton(export_btn, QDialogButtonBox.ActionRole)

        close_btn = QPushButton("Close")
        close_btn.clicked.connect(self.accept)
        button_box.addButton(close_btn, QDialogButtonBox.AcceptRole)

        layout.addWidget(button_box)

    def _create_overview_tab(self):
        widget = QWidget()
        layout = QVBoxLayout(widget)

        # Info grid
        info_group = QGroupBox("Finding Information")
        info_layout = QGridLayout(info_group)

        info_layout.addWidget(QLabel("Module:"), 0, 0)
        info_layout.addWidget(QLabel(self.finding.get('module', 'N/A')), 0, 1)

        info_layout.addWidget(QLabel("Target:"), 1, 0)
        target_label = QLabel(self.finding.get('target', 'N/A'))
        target_label.setWordWrap(True)
        info_layout.addWidget(target_label, 1, 1)

        info_layout.addWidget(QLabel("Time:"), 2, 0)
        info_layout.addWidget(QLabel(self.finding.get('time', 'N/A')), 2, 1)

        # CVSS Score
        cvss = self.finding.get('cvss', 0)
        info_layout.addWidget(QLabel("CVSS Score:"), 3, 0)
        cvss_label = QLabel(f"{cvss}/10")
        if cvss >= 9:
            cvss_label.setStyleSheet("color: #f44336; font-weight: bold;")
        elif cvss >= 7:
            cvss_label.setStyleSheet("color: #FF9800; font-weight: bold;")
        elif cvss >= 4:
            cvss_label.setStyleSheet("color: #FFC107; font-weight: bold;")
        else:
            cvss_label.setStyleSheet("color: #4CAF50; font-weight: bold;")
        info_layout.addWidget(cvss_label, 3, 1)

        layout.addWidget(info_group)

        # References
        ref_group = QGroupBox("References")
        ref_layout = QVBoxLayout(ref_group)

        cwe = self.finding.get('cwe', '')
        if cwe:
            ref_layout.addWidget(QLabel(f"CWE: {cwe}"))

        owasp = self.finding.get('owasp', '')
        if owasp:
            ref_layout.addWidget(QLabel(f"OWASP: {owasp}"))

        if not cwe and not owasp:
            ref_layout.addWidget(QLabel("No references available"))

        layout.addWidget(ref_group)

        # Description
        desc_group = QGroupBox("Description")
        desc_layout = QVBoxLayout(desc_group)
        desc_text = QTextEdit()
        desc_text.setPlainText(self.finding.get('description', 'No description available'))
        desc_text.setReadOnly(True)
        desc_text.setMaximumHeight(150)
        desc_text.setFont(QFont("Consolas", 9))
        desc_layout.addWidget(desc_text)
        layout.addWidget(desc_group)

        layout.addStretch()
        return widget

    def _create_technical_tab(self):
        widget = QWidget()
        layout = QVBoxLayout(widget)

        # Proof/Evidence
        proof_group = QGroupBox("Proof of Concept / Evidence")
        proof_layout = QVBoxLayout(proof_group)
        proof_text = QTextEdit()
        proof_text.setPlainText(self.finding.get('proof', 'No proof available'))
        proof_text.setReadOnly(True)
        proof_text.setFont(QFont("Consolas", 9))
        proof_layout.addWidget(proof_text)
        layout.addWidget(proof_group)

        # Payload
        payload_group = QGroupBox("Payload Used")
        payload_layout = QVBoxLayout(payload_group)
        payload_text = QTextEdit()
        payload_text.setPlainText(self.finding.get('payload', 'N/A'))
        payload_text.setReadOnly(True)
        payload_text.setMaximumHeight(100)
        payload_text.setFont(QFont("Consolas", 9))
        payload_layout.addWidget(payload_text)
        layout.addWidget(payload_group)

        return widget

    def _create_http_tab(self):
        widget = QWidget()
        layout = QVBoxLayout(widget)

        # Request
        req_group = QGroupBox("HTTP Request")
        req_layout = QVBoxLayout(req_group)
        req_text = QTextEdit()
        req_text.setPlainText(self.finding.get('request', 'No request data available'))
        req_text.setReadOnly(True)
        req_text.setFont(QFont("Consolas", 9))
        req_layout.addWidget(req_text)
        layout.addWidget(req_group)

        # Response
        resp_group = QGroupBox("HTTP Response")
        resp_layout = QVBoxLayout(resp_group)
        resp_text = QTextEdit()
        resp_text.setPlainText(self.finding.get('response', 'No response data available'))
        resp_text.setReadOnly(True)
        resp_text.setFont(QFont("Consolas", 9))
        resp_layout.addWidget(resp_text)
        layout.addWidget(resp_group)

        return widget

    def _create_remediation_tab(self):
        widget = QWidget()
        layout = QVBoxLayout(widget)

        # Remediation advice
        rem_group = QGroupBox("Remediation Advice")
        rem_layout = QVBoxLayout(rem_group)
        rem_text = QTextEdit()
        rem_text.setPlainText(self.finding.get('remediation', 'No remediation advice available'))
        rem_text.setReadOnly(True)
        rem_text.setFont(QFont("Consolas", 9))
        rem_layout.addWidget(rem_text)
        layout.addWidget(rem_group)

        # Impact
        impact_group = QGroupBox("Potential Impact")
        impact_layout = QVBoxLayout(impact_group)
        impact_text = QTextEdit()
        impact_text.setPlainText(self.finding.get('impact', 'No impact assessment available'))
        impact_text.setReadOnly(True)
        impact_text.setMaximumHeight(150)
        impact_text.setFont(QFont("Consolas", 9))
        impact_layout.addWidget(impact_text)
        layout.addWidget(impact_group)

        layout.addStretch()
        return widget

    def export_finding(self, format_type='txt'):
        """Export single finding to file in TXT, HTML, or JSON format"""
        # Set default filename and filter based on format
        if format_type == 'html':
            default_filename = f"finding_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html"
            file_filter = "HTML Files (*.html)"
        elif format_type == 'json':
            default_filename = f"finding_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
            file_filter = "JSON Files (*.json)"
        else:  # txt
            default_filename = f"finding_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
            file_filter = "Text Files (*.txt)"

        filename, _ = QFileDialog.getSaveFileName(
            self, "Export Finding",
            default_filename,
            file_filter
        )

        if filename:
            try:
                if format_type == 'json':
                    # Export as JSON
                    with open(filename, 'w', encoding='utf-8') as f:
                        json.dump(self.finding, f, indent=2, default=str)

                elif format_type == 'html':
                    # Export as HTML with nice formatting
                    severity = self.finding.get('severity', 'N/A').upper()
                    severity_colors = {
                        'CRITICAL': '#f44336',
                        'HIGH': '#FF9800',
                        'MEDIUM': '#FFC107',
                        'LOW': '#4CAF50',
                        'INFO': '#2196F3'
                    }
                    severity_color = severity_colors.get(severity, '#888888')

                    html_content = f"""<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>Finding Report - {self.finding.get('title', 'N/A')}</title>
    <style>
        body {{
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            margin: 40px;
            background-color: #f5f5f5;
        }}
        .container {{
            max-width: 900px;
            margin: 0 auto;
            background-color: white;
            padding: 30px;
            border-radius: 8px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }}
        h1 {{
            color: #333;
            border-bottom: 3px solid {severity_color};
            padding-bottom: 10px;
        }}
        .severity-badge {{
            display: inline-block;
            background-color: {severity_color};
            color: white;
            padding: 8px 16px;
            border-radius: 4px;
            font-weight: bold;
            font-size: 14px;
            margin: 10px 0;
        }}
        .info-grid {{
            display: grid;
            grid-template-columns: 150px 1fr;
            gap: 10px;
            margin: 20px 0;
            background-color: #fafafa;
            padding: 15px;
            border-radius: 4px;
        }}
        .info-label {{
            font-weight: bold;
            color: #555;
        }}
        .info-value {{
            color: #333;
        }}
        .section {{
            margin: 30px 0;
        }}
        .section-title {{
            font-size: 20px;
            font-weight: bold;
            color: #1976D2;
            border-left: 4px solid #2196F3;
            padding-left: 10px;
            margin: 20px 0 10px 0;
        }}
        .content {{
            background-color: #f9f9f9;
            padding: 15px;
            border-radius: 4px;
            border: 1px solid #e0e0e0;
            white-space: pre-wrap;
            font-family: 'Consolas', 'Monaco', monospace;
            font-size: 13px;
            line-height: 1.6;
        }}
        .footer {{
            margin-top: 40px;
            padding-top: 20px;
            border-top: 1px solid #e0e0e0;
            text-align: center;
            color: #888;
            font-size: 12px;
        }}
    </style>
</head>
<body>
    <div class="container">
        <h1>{self.finding.get('title', 'N/A')}</h1>
        <div class="severity-badge">{severity}</div>

        <div class="info-grid">
            <div class="info-label">Module:</div>
            <div class="info-value">{self.finding.get('module', 'N/A')}</div>

            <div class="info-label">Target:</div>
            <div class="info-value">{self.finding.get('target', 'N/A')}</div>

            <div class="info-label">Time Discovered:</div>
            <div class="info-value">{self.finding.get('time', 'N/A')}</div>

            <div class="info-label">CVSS Score:</div>
            <div class="info-value">{self.finding.get('cvss', 'N/A')}</div>

            <div class="info-label">CWE:</div>
            <div class="info-value">{self.finding.get('cwe', 'N/A')}</div>

            <div class="info-label">OWASP:</div>
            <div class="info-value">{self.finding.get('owasp', 'N/A')}</div>
        </div>

        <div class="section">
            <div class="section-title">Description</div>
            <div class="content">{self.finding.get('description', 'N/A')}</div>
        </div>

        <div class="section">
            <div class="section-title">Proof of Concept</div>
            <div class="content">{self.finding.get('proof', 'N/A')}</div>
        </div>

        <div class="section">
            <div class="section-title">Impact</div>
            <div class="content">{self.finding.get('impact', 'N/A')}</div>
        </div>

        <div class="section">
            <div class="section-title">Remediation</div>
            <div class="content">{self.finding.get('remediation', 'N/A')}</div>
        </div>

        <div class="section">
            <div class="section-title">References</div>
            <div class="content">{self.finding.get('references', 'N/A')}</div>
        </div>

        <div class="footer">
            Report generated by Dominator Scanner on {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
        </div>
    </div>
</body>
</html>"""
                    with open(filename, 'w', encoding='utf-8') as f:
                        f.write(html_content)

                else:  # txt format
                    # Export as plain text
                    with open(filename, 'w', encoding='utf-8') as f:
                        f.write("=" * 80 + "\n")
                        f.write(f"FINDING REPORT\n")
                        f.write("=" * 80 + "\n\n")
                        f.write(f"Title:       {self.finding.get('title', 'N/A')}\n")
                        f.write(f"Severity:    {self.finding.get('severity', 'N/A')}\n")
                        f.write(f"Module:      {self.finding.get('module', 'N/A')}\n")
                        f.write(f"Target:      {self.finding.get('target', 'N/A')}\n")
                        f.write(f"Time:        {self.finding.get('time', 'N/A')}\n")
                        f.write(f"CVSS Score:  {self.finding.get('cvss', 'N/A')}\n")
                        f.write(f"CWE:         {self.finding.get('cwe', 'N/A')}\n")
                        f.write(f"OWASP:       {self.finding.get('owasp', 'N/A')}\n")
                        f.write("\n" + "-" * 80 + "\n")
                        f.write("DESCRIPTION\n")
                        f.write("-" * 80 + "\n")
                        f.write(f"{self.finding.get('description', 'N/A')}\n")
                        f.write("\n" + "-" * 80 + "\n")
                        f.write("PROOF OF CONCEPT\n")
                        f.write("-" * 80 + "\n")
                        f.write(f"{self.finding.get('proof', 'N/A')}\n")
                        f.write("\n" + "-" * 80 + "\n")
                        f.write("IMPACT\n")
                        f.write("-" * 80 + "\n")
                        f.write(f"{self.finding.get('impact', 'N/A')}\n")
                        f.write("\n" + "-" * 80 + "\n")
                        f.write("REMEDIATION\n")
                        f.write("-" * 80 + "\n")
                        f.write(f"{self.finding.get('remediation', 'N/A')}\n")
                        f.write("\n" + "-" * 80 + "\n")
                        f.write("REFERENCES\n")
                        f.write("-" * 80 + "\n")
                        f.write(f"{self.finding.get('references', 'N/A')}\n")
                        f.write("\n" + "=" * 80 + "\n")
                        f.write(f"Report generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                        f.write("=" * 80 + "\n")

                QMessageBox.information(self, "Success", f"Finding exported to:\n{filename}")
            except Exception as e:
                QMessageBox.critical(self, "Error", f"Failed to export:\n{e}")
