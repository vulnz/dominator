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
    QAction, QFileDialog, QMessageBox, QGraphicsDropShadowEffect
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
    """A styled card widget for displaying statistics - Modern dashboard style"""

    def __init__(self, title, value="0", color="#333333", parent=None):
        super().__init__(parent)
        self.color = color
        self._title = title  # Store original title
        self.setFrameShape(QFrame.NoFrame)

        # Set flexible size constraints - wide enough for labels
        self.setMinimumSize(100, 75)
        self.setMaximumSize(180, 120)
        self.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Preferred)

        # Modern card style with colored top border accent
        self.setStyleSheet(f"""
            StatsCard {{
                background-color: #ffffff;
                border: 1px solid #e5e7eb;
                border-top: 3px solid {color};
                border-radius: 6px;
            }}
        """)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(8, 10, 8, 8)
        layout.setSpacing(4)

        # Large number on top - FIXED: Ensure visible with explicit objectName
        self.value_label = QLabel(str(value))
        self.value_label.setObjectName("statsCardValue")
        # Use QFont for more reliable font rendering
        value_font = QFont("Segoe UI", 24, QFont.Bold)
        self.value_label.setFont(value_font)
        self.value_label.setStyleSheet(f"color: {color}; background: transparent;")
        self.value_label.setAlignment(Qt.AlignCenter)
        self.value_label.setMinimumWidth(80)
        self.value_label.setMinimumHeight(30)

        # Title below (uppercase, smaller)
        self.title_label = QLabel(title.upper())
        self.title_label.setObjectName("statsCardTitle")
        title_font = QFont("Segoe UI", 9, QFont.Bold)
        self.title_label.setFont(title_font)
        self.title_label.setStyleSheet("color: #6b7280; background: transparent;")
        self.title_label.setAlignment(Qt.AlignCenter)
        self.title_label.setMinimumWidth(80)
        self.title_label.setWordWrap(False)

        layout.addWidget(self.value_label)
        layout.addWidget(self.title_label)

    def set_value(self, value):
        """Update the displayed value"""
        self.value_label.setText(str(value))
        # Update color - always apply to ensure visibility
        self.value_label.setStyleSheet(f"color: {self.color}; background: transparent;")


class FindingDetailDialog(QDialog):
    """Dialog to show detailed finding information"""

    def __init__(self, finding_data, parent=None):
        super().__init__(parent)
        self.finding = finding_data if isinstance(finding_data, dict) else {}
        self.setWindowTitle("Finding Details")
        self.setMinimumSize(700, 600)
        try:
            self.setup_ui()
        except Exception as e:
            # Log error and show a minimal fallback UI
            from pathlib import Path
            log_file = Path(__file__).parent.parent.parent / "gui_debug.log"
            try:
                with open(log_file, 'a', encoding='utf-8') as f:
                    f.write(f"[{datetime.now().strftime('%H:%M:%S')}] ERROR in FindingDetailDialog.setup_ui: {e}\n")
                    import traceback
                    f.write(traceback.format_exc() + "\n")
            except:
                pass
            # Fallback UI
            layout = QVBoxLayout(self)
            layout.addWidget(QLabel(f"Error displaying finding details: {str(e)}"))

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

        # CVSS Score - handle string or numeric values safely
        cvss_raw = self.finding.get('cvss', 0)
        try:
            cvss = float(cvss_raw) if cvss_raw and cvss_raw != '-' and cvss_raw != 'N/A' else 0
        except (ValueError, TypeError):
            cvss = 0
        info_layout.addWidget(QLabel("CVSS Score:"), 3, 0)
        cvss_label = QLabel(f"{cvss}/10" if cvss > 0 else "N/A")
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

        # Evidence (check both 'evidence' and 'proof' for compatibility)
        evidence_group = QGroupBox("Evidence / Proof of Concept")
        evidence_layout = QVBoxLayout(evidence_group)
        evidence_text = QTextEdit()
        evidence = self.finding.get('evidence', '') or self.finding.get('proof', '')
        evidence_text.setPlainText(evidence if evidence else 'No evidence available')
        evidence_text.setReadOnly(True)
        evidence_text.setFont(QFont("Consolas", 9))
        evidence_layout.addWidget(evidence_text)
        layout.addWidget(evidence_group)

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

        # Response with HIGHLIGHTING of evidence/payload
        resp_group = QGroupBox("HTTP Response (Evidence Highlighted)")
        resp_layout = QVBoxLayout(resp_group)
        resp_text = QTextEdit()
        resp_text.setReadOnly(True)
        resp_text.setFont(QFont("Consolas", 9))

        # Get response and evidence to highlight
        response = self.finding.get('response', 'No response data available')
        evidence = self.finding.get('evidence', '')
        payload = self.finding.get('payload', '')

        # Build highlighted HTML response
        highlighted_response = self._highlight_evidence_in_response(response, evidence, payload)
        resp_text.setHtml(highlighted_response)

        resp_layout.addWidget(resp_text)
        layout.addWidget(resp_group)

        return widget

    def _highlight_evidence_in_response(self, response, evidence, payload):
        """Highlight evidence and payload in the response with HTML formatting"""
        import html

        if not response or response == 'No response data available':
            return '<pre style="font-family: Consolas; font-size: 9pt;">No response data available</pre>'

        # Escape HTML characters in response
        escaped_response = html.escape(response)

        # Create list of things to highlight
        highlights = []

        # Add evidence snippets to highlight (extract key parts from evidence)
        if evidence:
            # Extract quoted strings from evidence that might appear in response
            import re
            # Look for patterns like: 'text', "text", `text`
            quoted = re.findall(r"['\"`]([^'\"`]{5,100})['\"`]", evidence)
            for q in quoted:
                if len(q) > 5:  # Only highlight meaningful strings
                    highlights.append(q)

            # Also try to find the detector/indicator text
            # Common patterns: "detected:", "found:", "indicator:"
            indicator_patterns = [
                r'(?:detected|found|indicator|error|warning)[:\s]+([^\n]{10,80})',
                r'(?:unserialize|eval|exec|system)\([^)]+\)',
            ]
            for pattern in indicator_patterns:
                matches = re.findall(pattern, evidence, re.IGNORECASE)
                for m in matches:
                    if len(m) > 5:
                        highlights.append(m.strip())

        # Add payload to highlights
        if payload and len(payload) > 3:
            highlights.append(payload)

        # Remove duplicates while preserving order
        seen = set()
        unique_highlights = []
        for h in highlights:
            if h not in seen:
                seen.add(h)
                unique_highlights.append(h)

        # Apply highlighting with different colors
        result = escaped_response

        # Highlight payload in YELLOW
        if payload and len(payload) > 3:
            escaped_payload = html.escape(payload)
            if escaped_payload in result:
                result = result.replace(
                    escaped_payload,
                    f'<span style="background-color: #FFEB3B; color: #000; font-weight: bold; padding: 2px 4px; border-radius: 3px;">⚡ {escaped_payload}</span>'
                )

        # Highlight evidence snippets in RED/ORANGE
        highlight_colors = ['#FF5722', '#E91E63', '#9C27B0', '#673AB7']
        for i, highlight in enumerate(unique_highlights):
            if highlight == payload:  # Skip if already highlighted as payload
                continue
            escaped_highlight = html.escape(highlight)
            if escaped_highlight in result:
                color = highlight_colors[i % len(highlight_colors)]
                result = result.replace(
                    escaped_highlight,
                    f'<span style="background-color: {color}; color: white; font-weight: bold; padding: 2px 4px; border-radius: 3px;">🔍 {escaped_highlight}</span>',
                    1  # Only replace first occurrence to avoid over-highlighting
                )

        # Wrap in pre tag for proper formatting
        html_output = f'''
        <style>
            .response-content {{
                font-family: Consolas, Monaco, monospace;
                font-size: 9pt;
                line-height: 1.5;
                white-space: pre-wrap;
                word-wrap: break-word;
            }}
            .legend {{
                background-color: #f5f5f5;
                padding: 8px;
                margin-bottom: 10px;
                border-radius: 4px;
                font-size: 10pt;
            }}
        </style>
        <div class="legend">
            <b>Legend:</b>
            <span style="background-color: #FFEB3B; padding: 2px 6px; border-radius: 3px;">⚡ Payload</span>
            <span style="background-color: #FF5722; color: white; padding: 2px 6px; border-radius: 3px; margin-left: 10px;">🔍 Evidence/Indicator</span>
        </div>
        <div class="response-content">{result}</div>
        '''

        return html_output

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
