"""
Improved Repeater Tab - Multiple tabs support like Burp Suite
Allows managing multiple requests in separate tabs
"""

from PyQt5.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QPushButton, QLabel,
    QTextEdit, QSplitter, QTabWidget, QComboBox, QLineEdit,
    QGroupBox, QMessageBox, QSpinBox, QCheckBox, QApplication,
    QToolBar, QAction
)
from PyQt5.QtCore import Qt, pyqtSignal
from PyQt5.QtGui import QFont, QColor, QSyntaxHighlighter, QTextCharFormat, QIcon
import requests
from datetime import datetime
import re
import json


class HTTPSyntaxHighlighter(QSyntaxHighlighter):
    """Syntax highlighter for HTTP requests/responses"""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.highlighting_rules = []

        # HTTP methods
        method_format = QTextCharFormat()
        method_format.setForeground(QColor("#0000ff"))
        method_format.setFontWeight(QFont.Bold)
        methods = ["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD", "CONNECT"]
        for method in methods:
            self.highlighting_rules.append((f"^{method}\\b", method_format))

        # Headers
        header_format = QTextCharFormat()
        header_format.setForeground(QColor("#008000"))
        header_format.setFontWeight(QFont.Bold)
        self.highlighting_rules.append((r"^[\w-]+:", header_format))

        # URLs
        url_format = QTextCharFormat()
        url_format.setForeground(QColor("#0080ff"))
        url_format.setFontItalic(True)
        self.highlighting_rules.append((r"https?://[^\s]+", url_format))

        # Status codes
        status_format = QTextCharFormat()
        status_format.setForeground(QColor("#ff8000"))
        status_format.setFontWeight(QFont.Bold)
        self.highlighting_rules.append((r"HTTP/\d\.\d \d{3}", status_format))

    def highlightBlock(self, text):
        for pattern, format in self.highlighting_rules:
            expression = re.compile(pattern)
            for match in expression.finditer(text):
                self.setFormat(match.start(), match.end() - match.start(), format)


class SingleRepeaterWidget(QWidget):
    """Single repeater instance (one tab)"""

    def __init__(self, tab_name="Request 1", parent=None):
        super().__init__(parent)
        self.tab_name = tab_name
        self.request_history = []
        self.init_ui()

    def init_ui(self):
        """Initialize single repeater UI"""
        layout = QVBoxLayout()
        layout.setContentsMargins(0, 0, 0, 0)

        # Toolbar
        toolbar = self._create_toolbar()
        layout.addWidget(toolbar)

        # Main content
        splitter = QSplitter(Qt.Horizontal)

        # Request panel
        request_panel = self._create_request_panel()
        splitter.addWidget(request_panel)

        # Response panel
        response_panel = self._create_response_panel()
        splitter.addWidget(response_panel)

        splitter.setSizes([500, 500])
        layout.addWidget(splitter)

        # Status bar
        status_bar = self._create_status_bar()
        layout.addWidget(status_bar)

        self.setLayout(layout)

    def _create_toolbar(self):
        """Create toolbar with actions"""
        toolbar = QToolBar()
        toolbar.setStyleSheet("""
            QToolBar {
                background-color: #f0f0f0;
                border-bottom: 1px solid #cccccc;
                padding: 5px;
            }
            QPushButton {
                background-color: #e0e0e0;
                border: 1px solid #999999;
                border-radius: 3px;
                padding: 5px 10px;
                margin: 2px;
            }
            QPushButton:hover {
                background-color: #d0d0d0;
            }
        """)

        # Send button
        self.send_btn = QPushButton("▶ Send")
        self.send_btn.setStyleSheet("""
            QPushButton {
                background-color: #4CAF50;
                color: white;
                font-weight: bold;
                padding: 8px 20px;
            }
            QPushButton:hover {
                background-color: #45a049;
            }
        """)
        self.send_btn.clicked.connect(self.send_request)
        toolbar.addWidget(self.send_btn)

        toolbar.addSeparator()

        # Timeout
        toolbar.addWidget(QLabel("Timeout:"))
        self.timeout_spin = QSpinBox()
        self.timeout_spin.setRange(1, 120)
        self.timeout_spin.setValue(10)
        self.timeout_spin.setSuffix(" s")
        toolbar.addWidget(self.timeout_spin)

        # Follow redirects
        self.follow_redirects = QCheckBox("Follow Redirects")
        toolbar.addWidget(self.follow_redirects)

        toolbar.addSeparator()

        # Clear button
        clear_btn = QPushButton("🗑 Clear")
        clear_btn.clicked.connect(self.clear_request)
        toolbar.addWidget(clear_btn)

        return toolbar

    def _create_request_panel(self):
        """Create request editing panel"""
        group = QGroupBox("📤 Request")
        layout = QVBoxLayout()

        # URL bar
        url_row = QHBoxLayout()
        self.method_combo = QComboBox()
        self.method_combo.addItems(["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD"])
        url_row.addWidget(self.method_combo)

        self.url_input = QLineEdit()
        self.url_input.setPlaceholderText("https://example.com/api/endpoint")
        url_row.addWidget(self.url_input)
        layout.addLayout(url_row)

        # Request editor
        self.request_edit = QTextEdit()
        self.request_edit.setPlaceholderText(
            "GET /api/endpoint HTTP/1.1\n"
            "Host: example.com\n"
            "User-Agent: Dominator/1.0\n"
            "\nOptional body..."
        )
        self.request_edit.setFont(QFont("Courier New", 10))
        self.request_highlighter = HTTPSyntaxHighlighter(self.request_edit.document())
        layout.addWidget(self.request_edit)

        group.setLayout(layout)
        return group

    def _create_response_panel(self):
        """Create response display panel"""
        group = QGroupBox("📥 Response")
        layout = QVBoxLayout()

        # Response tabs
        self.response_tabs = QTabWidget()

        self.response_raw = QTextEdit()
        self.response_raw.setReadOnly(True)
        self.response_raw.setFont(QFont("Courier New", 10))
        self.response_highlighter = HTTPSyntaxHighlighter(self.response_raw.document())
        self.response_tabs.addTab(self.response_raw, "Raw")

        self.response_headers = QTextEdit()
        self.response_headers.setReadOnly(True)
        self.response_headers.setFont(QFont("Courier New", 10))
        self.response_tabs.addTab(self.response_headers, "Headers")

        self.response_body = QTextEdit()
        self.response_body.setReadOnly(True)
        self.response_body.setFont(QFont("Courier New", 10))
        self.response_tabs.addTab(self.response_body, "Body")

        layout.addWidget(self.response_tabs)

        # Metadata
        meta_row = QHBoxLayout()
        self.status_label = QLabel("Status: -")
        self.status_label.setStyleSheet("font-weight: bold;")
        meta_row.addWidget(self.status_label)

        self.size_label = QLabel("Size: -")
        meta_row.addWidget(self.size_label)

        self.time_label = QLabel("Time: -")
        meta_row.addWidget(self.time_label)

        meta_row.addStretch()
        layout.addLayout(meta_row)

        group.setLayout(layout)
        return group

    def _create_status_bar(self):
        """Create status bar"""
        widget = QWidget()
        layout = QHBoxLayout()
        layout.setContentsMargins(5, 2, 5, 2)

        self.status_message = QLabel("Ready")
        self.status_message.setStyleSheet("color: #666;")
        layout.addWidget(self.status_message)

        layout.addStretch()

        self.history_count = QLabel("History: 0")
        layout.addWidget(self.history_count)

        widget.setLayout(layout)
        return widget

    def load_request(self, request_data):
        """Load request into this repeater"""
        try:
            url = request_data.get('url', '')
            self.url_input.setText(url)

            method = request_data.get('method', 'GET')
            index = self.method_combo.findText(method)
            if index >= 0:
                self.method_combo.setCurrentIndex(index)

            raw_request = f"{method} {url} HTTP/1.1\n"
            headers = request_data.get('headers', {})
            for header, value in headers.items():
                raw_request += f"{header}: {value}\n"

            body = request_data.get('body', '')
            if body:
                raw_request += f"\n{body}"

            self.request_edit.setPlainText(raw_request)
            self.status_message.setText(f"✅ Loaded: {method} {url}")

        except Exception as e:
            QMessageBox.critical(self, "Load Error", f"Failed to load request:\n{str(e)}")

    def send_request(self):
        """Send the request"""
        try:
            raw_request = self.request_edit.toPlainText()
            if not raw_request.strip():
                QMessageBox.warning(self, "Empty Request", "Please enter a request")
                return

            lines = raw_request.split('\n')
            if not lines:
                return

            first_line = lines[0].strip().split()
            if len(first_line) < 2:
                QMessageBox.warning(self, "Invalid Request", "Invalid HTTP request format")
                return

            method = first_line[0]
            url = self.url_input.text() or first_line[1]

            headers = {}
            body_start = 0
            for i, line in enumerate(lines[1:], 1):
                if not line.strip():
                    body_start = i + 1
                    break
                if ':' in line:
                    key, value = line.split(':', 1)
                    headers[key.strip()] = value.strip()

            body = '\n'.join(lines[body_start:]) if body_start > 0 else ''

            self.status_message.setText(f"⏳ Sending {method} to {url}...")
            self.send_btn.setEnabled(False)
            QApplication.processEvents()

            import time
            start_time = time.time()

            response = requests.request(
                method=method,
                url=url,
                headers=headers,
                data=body.encode('utf-8') if body else None,
                timeout=self.timeout_spin.value(),
                allow_redirects=self.follow_redirects.isChecked(),
                verify=False
            )

            elapsed = time.time() - start_time

            self._display_response(response, elapsed)

            self.request_history.append({
                'timestamp': datetime.now(),
                'method': method,
                'url': url,
                'status': response.status_code,
                'time': elapsed
            })
            self.history_count.setText(f"History: {len(self.request_history)}")
            self.status_message.setText(f"✅ {response.status_code} ({elapsed:.2f}s)")

        except Exception as e:
            QMessageBox.critical(self, "Error", f"Request failed:\n{str(e)}")
            self.status_message.setText(f"❌ Error: {str(e)}")
        finally:
            self.send_btn.setEnabled(True)

    def _display_response(self, response, elapsed):
        """Display response"""
        # Raw
        raw = f"HTTP/1.1 {response.status_code} {response.reason}\n"
        for header, value in response.headers.items():
            raw += f"{header}: {value}\n"
        raw += f"\n{response.text}"
        self.response_raw.setPlainText(raw)

        # Headers
        headers_text = "\n".join([f"{h}: {v}" for h, v in response.headers.items()])
        self.response_headers.setPlainText(headers_text)

        # Body
        self.response_body.setPlainText(response.text)

        # Metadata
        status_code = response.status_code
        color = "green" if 200 <= status_code < 300 else "blue" if 300 <= status_code < 400 else "orange" if 400 <= status_code < 500 else "red"
        self.status_label.setText(f"Status: {status_code} {response.reason}")
        self.status_label.setStyleSheet(f"font-weight: bold; color: {color};")
        self.size_label.setText(f"Size: {len(response.content)} bytes")
        self.time_label.setText(f"Time: {elapsed:.3f}s")

    def clear_request(self):
        """Clear request"""
        self.request_edit.clear()
        self.url_input.clear()
        self.method_combo.setCurrentIndex(0)
        self.status_message.setText("Cleared")


class RepeaterTabImproved(QWidget):
    """Improved Repeater with multiple tabs support"""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.tab_counter = 1
        self.init_ui()

    def init_ui(self):
        """Initialize UI with tab management"""
        layout = QVBoxLayout()
        layout.setContentsMargins(0, 0, 0, 0)

        # Tab widget for multiple repeaters
        self.repeater_tabs = QTabWidget()
        self.repeater_tabs.setTabsClosable(True)
        self.repeater_tabs.tabCloseRequested.connect(self.close_tab)
        self.repeater_tabs.setStyleSheet("""
            QTabWidget::pane {
                border: 1px solid #cccccc;
            }
            QTabBar::tab {
                background-color: #e0e0e0;
                color: black;
                padding: 6px 15px;
                border: 1px solid #cccccc;
                border-bottom: none;
                margin-right: 1px;
            }
            QTabBar::tab:selected {
                background-color: white;
                font-weight: bold;
            }
            QTabBar::tab:hover {
                background-color: #d0d0d0;
            }
        """)

        # Add first tab
        self.add_new_tab()

        # Plus button to add new tabs
        plus_btn = QPushButton("➕ New Tab")
        plus_btn.setStyleSheet("""
            QPushButton {
                background-color: #2196F3;
                color: white;
                border: none;
                padding: 5px 15px;
                border-radius: 3px;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: #1976D2;
            }
        """)
        plus_btn.clicked.connect(self.add_new_tab)
        self.repeater_tabs.setCornerWidget(plus_btn, Qt.TopRightCorner)

        layout.addWidget(self.repeater_tabs)
        self.setLayout(layout)

    def add_new_tab(self, request_data=None):
        """Add a new repeater tab"""
        tab_name = f"Request {self.tab_counter}"
        self.tab_counter += 1

        repeater_widget = SingleRepeaterWidget(tab_name, self)

        if request_data:
            repeater_widget.load_request(request_data)

        self.repeater_tabs.addTab(repeater_widget, tab_name)
        self.repeater_tabs.setCurrentWidget(repeater_widget)

        return repeater_widget

    def close_tab(self, index):
        """Close a repeater tab"""
        if self.repeater_tabs.count() > 1:
            self.repeater_tabs.removeTab(index)
        else:
            QMessageBox.information(self, "Cannot Close", "Cannot close the last tab")

    def load_request(self, request_data):
        """Load request into current or new tab"""
        current = self.repeater_tabs.currentWidget()
        if current and isinstance(current, SingleRepeaterWidget):
            # If current tab is empty, load there
            if not current.url_input.text():
                current.load_request(request_data)
            else:
                # Otherwise create new tab
                self.add_new_tab(request_data)
        else:
            self.add_new_tab(request_data)
