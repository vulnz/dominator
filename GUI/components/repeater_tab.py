"""
Repeater Tab - Burp Suite-style request repeater
Allows manual editing and resending of HTTP requests
"""

from PyQt5.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QPushButton, QLabel,
    QTextEdit, QSplitter, QTabWidget, QComboBox, QLineEdit,
    QGroupBox, QMessageBox, QSpinBox, QCheckBox, QApplication
)
from PyQt5.QtCore import Qt, pyqtSignal, QThread
from PyQt5.QtGui import QFont, QColor, QSyntaxHighlighter, QTextCharFormat
import requests
from datetime import datetime
import re


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

        # Headers (name:)
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
        """Highlight a block of text"""
        for pattern, format in self.highlighting_rules:
            expression = re.compile(pattern)
            for match in expression.finditer(text):
                self.setFormat(match.start(), match.end() - match.start(), format)


class RepeaterTab(QWidget):
    """Repeater tab for manual request editing and sending"""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.current_request = None
        self.history = []
        self.init_ui()

    def init_ui(self):
        """Initialize the repeater UI"""

        # Light theme
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
            }
            QTextEdit {
                background-color: white;
                color: black;
                border: 1px solid #cccccc;
                font-family: 'Courier New', 'Consolas', monospace;
                font-size: 10pt;
            }
            QPushButton {
                background-color: #e0e0e0;
                color: black;
                border: 2px solid #999999;
                border-radius: 4px;
                padding: 8px 16px;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: #d0d0d0;
                border-color: #666666;
            }
            QPushButton:pressed {
                background-color: #c0c0c0;
            }
            QComboBox {
                background-color: white;
                color: black;
                border: 1px solid #cccccc;
                padding: 5px;
            }
            QLineEdit {
                background-color: white;
                color: black;
                border: 1px solid #cccccc;
                padding: 5px;
            }
            QSpinBox {
                background-color: white;
                color: black;
                border: 1px solid #cccccc;
            }
        """)

        layout = QVBoxLayout()

        # Top toolbar
        toolbar = self._create_toolbar()
        layout.addWidget(toolbar)

        # Main content - split between request and response
        splitter = QSplitter(Qt.Horizontal)

        # Request panel (left)
        request_panel = self._create_request_panel()
        splitter.addWidget(request_panel)

        # Response panel (right)
        response_panel = self._create_response_panel()
        splitter.addWidget(response_panel)

        # Equal split
        splitter.setSizes([500, 500])
        layout.addWidget(splitter)

        # Bottom status bar
        status_bar = self._create_status_bar()
        layout.addWidget(status_bar)

        self.setLayout(layout)

    def _create_toolbar(self):
        """Create top toolbar with action buttons"""
        group = QGroupBox("Request Controls")
        layout = QHBoxLayout()

        # Send button (main action)
        self.send_btn = QPushButton("▶ Send Request")
        self.send_btn.setStyleSheet("""
            QPushButton {
                background-color: #4CAF50;
                color: white;
                font-size: 12pt;
                padding: 10px 20px;
            }
            QPushButton:hover {
                background-color: #45a049;
            }
            QPushButton:disabled {
                background-color: #cccccc;
                color: #666666;
            }
        """)
        self.send_btn.clicked.connect(self.send_request)
        layout.addWidget(self.send_btn)

        # Clear button
        clear_btn = QPushButton("🗑 Clear")
        clear_btn.clicked.connect(self.clear_request)
        layout.addWidget(clear_btn)

        # Load from history
        load_btn = QPushButton("📁 Load from History")
        load_btn.clicked.connect(self.load_from_history)
        layout.addWidget(load_btn)

        # Timeout setting
        layout.addWidget(QLabel("Timeout:"))
        self.timeout_spin = QSpinBox()
        self.timeout_spin.setRange(1, 120)
        self.timeout_spin.setValue(10)
        self.timeout_spin.setSuffix(" sec")
        layout.addWidget(self.timeout_spin)

        # Follow redirects
        self.follow_redirects_check = QCheckBox("Follow Redirects")
        self.follow_redirects_check.setChecked(False)
        layout.addWidget(self.follow_redirects_check)

        layout.addStretch()
        group.setLayout(layout)
        return group

    def _create_request_panel(self):
        """Create left panel for request editing"""
        group = QGroupBox("📤 Request")
        layout = QVBoxLayout()

        # Quick URL bar
        url_row = QHBoxLayout()
        url_row.addWidget(QLabel("URL:"))

        self.url_input = QLineEdit()
        self.url_input.setPlaceholderText("https://example.com/api/endpoint")
        url_row.addWidget(self.url_input)

        self.method_combo = QComboBox()
        self.method_combo.addItems(["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD"])
        url_row.addWidget(self.method_combo)

        layout.addLayout(url_row)

        # Request editor (full raw HTTP)
        self.request_edit = QTextEdit()
        self.request_edit.setPlaceholderText(
            "Enter raw HTTP request:\n\n"
            "GET /api/endpoint HTTP/1.1\n"
            "Host: example.com\n"
            "User-Agent: Dominator/1.0\n"
            "Accept: */*\n"
            "\n"
            "Optional request body..."
        )
        self.request_edit.setFont(QFont("Courier New", 10))

        # Add syntax highlighting
        self.request_highlighter = HTTPSyntaxHighlighter(self.request_edit.document())

        layout.addWidget(self.request_edit)

        # Quick buttons for request
        req_buttons = QHBoxLayout()

        add_header_btn = QPushButton("+ Add Header")
        add_header_btn.clicked.connect(self.add_header)
        req_buttons.addWidget(add_header_btn)

        beautify_btn = QPushButton("✨ Beautify")
        beautify_btn.clicked.connect(self.beautify_request)
        req_buttons.addWidget(beautify_btn)

        req_buttons.addStretch()
        layout.addLayout(req_buttons)

        group.setLayout(layout)
        return group

    def _create_response_panel(self):
        """Create right panel for response display"""
        group = QGroupBox("📥 Response")
        layout = QVBoxLayout()

        # Response tabs (Raw, Headers, Body)
        self.response_tabs = QTabWidget()

        # Raw response
        self.response_raw = QTextEdit()
        self.response_raw.setReadOnly(True)
        self.response_raw.setFont(QFont("Courier New", 10))
        self.response_highlighter = HTTPSyntaxHighlighter(self.response_raw.document())
        self.response_tabs.addTab(self.response_raw, "Raw")

        # Headers only
        self.response_headers = QTextEdit()
        self.response_headers.setReadOnly(True)
        self.response_headers.setFont(QFont("Courier New", 10))
        self.response_tabs.addTab(self.response_headers, "Headers")

        # Body only
        self.response_body = QTextEdit()
        self.response_body.setReadOnly(True)
        self.response_body.setFont(QFont("Courier New", 10))
        self.response_tabs.addTab(self.response_body, "Body")

        layout.addWidget(self.response_tabs)

        # Response metadata
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
        """Create bottom status bar"""
        widget = QWidget()
        layout = QHBoxLayout()

        self.status_message = QLabel("Ready. Load a request or enter one manually.")
        self.status_message.setStyleSheet("color: #666; padding: 5px;")
        layout.addWidget(self.status_message)

        layout.addStretch()

        self.history_count = QLabel("History: 0 requests")
        layout.addWidget(self.history_count)

        widget.setLayout(layout)
        return widget

    def load_request(self, request_data):
        """Load a request from history into the repeater"""
        try:
            self.current_request = request_data

            # Set URL
            url = request_data.get('url', '')
            self.url_input.setText(url)

            # Set method
            method = request_data.get('method', 'GET')
            index = self.method_combo.findText(method)
            if index >= 0:
                self.method_combo.setCurrentIndex(index)

            # Build raw request
            raw_request = f"{method} {url} HTTP/1.1\n"

            headers = request_data.get('headers', {})
            for header, value in headers.items():
                raw_request += f"{header}: {value}\n"

            body = request_data.get('body', '')
            if body:
                raw_request += f"\n{body}"

            self.request_edit.setPlainText(raw_request)

            # Clear previous response
            self.response_raw.clear()
            self.response_headers.clear()
            self.response_body.clear()
            self.status_label.setText("Status: -")
            self.size_label.setText("Size: -")
            self.time_label.setText("Time: -")

            self.status_message.setText(f"✅ Loaded request: {method} {url}")

        except Exception as e:
            QMessageBox.critical(self, "Load Error", f"Failed to load request:\n{str(e)}")

    def send_request(self):
        """Send the current request"""
        try:
            # Parse request from text
            raw_request = self.request_edit.toPlainText()

            if not raw_request.strip():
                QMessageBox.warning(self, "Empty Request", "Please enter a request first.")
                return

            # Parse the request
            lines = raw_request.split('\n')
            if not lines:
                return

            # Parse first line (method, path, version)
            first_line = lines[0].strip().split()
            if len(first_line) < 2:
                QMessageBox.warning(self, "Invalid Request", "Invalid HTTP request format")
                return

            method = first_line[0]
            url = self.url_input.text() or first_line[1]

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

            # Update status
            self.status_message.setText(f"⏳ Sending {method} request to {url}...")
            self.send_btn.setEnabled(False)
            QApplication.processEvents()

            # Send request
            import time
            start_time = time.time()

            timeout = self.timeout_spin.value()
            follow_redirects = self.follow_redirects_check.isChecked()

            response = requests.request(
                method=method,
                url=url,
                headers=headers,
                data=body.encode('utf-8') if body else None,
                timeout=timeout,
                allow_redirects=follow_redirects,
                verify=False  # For testing purposes
            )

            elapsed = time.time() - start_time

            # Display response
            self._display_response(response, elapsed)

            # Add to history
            self.history.append({
                'timestamp': datetime.now(),
                'method': method,
                'url': url,
                'status': response.status_code,
                'time': elapsed
            })
            self.history_count.setText(f"History: {len(self.history)} requests")

            self.status_message.setText(f"✅ Response received: {response.status_code} ({elapsed:.2f}s)")

        except requests.exceptions.Timeout:
            QMessageBox.warning(self, "Timeout", f"Request timed out after {timeout} seconds")
            self.status_message.setText("❌ Request timed out")
        except requests.exceptions.ConnectionError as e:
            QMessageBox.critical(self, "Connection Error", f"Failed to connect:\n{str(e)}")
            self.status_message.setText("❌ Connection failed")
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Request failed:\n{str(e)}")
            self.status_message.setText(f"❌ Error: {str(e)}")
        finally:
            self.send_btn.setEnabled(True)

    def _display_response(self, response, elapsed):
        """Display the HTTP response"""
        # Raw response
        raw = f"HTTP/1.1 {response.status_code} {response.reason}\n"
        for header, value in response.headers.items():
            raw += f"{header}: {value}\n"
        raw += f"\n{response.text}"
        self.response_raw.setPlainText(raw)

        # Headers only
        headers_text = ""
        for header, value in response.headers.items():
            headers_text += f"{header}: {value}\n"
        self.response_headers.setPlainText(headers_text)

        # Body only
        self.response_body.setPlainText(response.text)

        # Metadata
        status_code = response.status_code
        if 200 <= status_code < 300:
            color = "green"
        elif 300 <= status_code < 400:
            color = "blue"
        elif 400 <= status_code < 500:
            color = "orange"
        else:
            color = "red"

        self.status_label.setText(f"Status: {status_code} {response.reason}")
        self.status_label.setStyleSheet(f"font-weight: bold; color: {color};")

        self.size_label.setText(f"Size: {len(response.content)} bytes")
        self.time_label.setText(f"Time: {elapsed:.3f}s")

    def clear_request(self):
        """Clear the request editor"""
        self.request_edit.clear()
        self.url_input.clear()
        self.method_combo.setCurrentIndex(0)
        self.status_message.setText("Cleared. Ready for new request.")

    def add_header(self):
        """Add a header template to request"""
        cursor = self.request_edit.textCursor()
        cursor.insertText("\nHeader-Name: value")

    def beautify_request(self):
        """Beautify/format the request"""
        # Simple beautification - ensure proper line breaks
        text = self.request_edit.toPlainText()
        # Could add JSON formatting for body, etc.
        self.status_message.setText("Request formatted")

    def load_from_history(self):
        """Show dialog to select from history"""
        if not self.history:
            QMessageBox.information(self, "Empty History", "No requests in history yet")
            return

        # Create history selection dialog
        from PyQt5.QtWidgets import QDialog, QListWidget, QListWidgetItem, QDialogButtonBox

        dialog = QDialog(self)
        dialog.setWindowTitle("Select Request from History")
        dialog.setMinimumWidth(500)
        dialog.setMinimumHeight(400)

        layout = QVBoxLayout(dialog)

        # History list
        history_list = QListWidget()
        for i, item in enumerate(self.history):
            method = item.get('method', 'GET')
            url = item.get('url', 'Unknown URL')
            status = item.get('status_code', 'N/A')
            timestamp = item.get('timestamp', '')
            list_item = QListWidgetItem(f"[{i+1}] {method} {url} - Status: {status} ({timestamp})")
            list_item.setData(Qt.UserRole, i)  # Store index
            history_list.addItem(list_item)

        layout.addWidget(QLabel("Select a request to load:"))
        layout.addWidget(history_list)

        # Buttons
        buttons = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        buttons.accepted.connect(dialog.accept)
        buttons.rejected.connect(dialog.reject)
        layout.addWidget(buttons)

        if dialog.exec_() == QDialog.Accepted and history_list.currentItem():
            idx = history_list.currentItem().data(Qt.UserRole)
            history_item = self.history[idx]

            # Load the request into the editor
            self.url_input.setText(history_item.get('url', ''))
            self.method_combo.setCurrentText(history_item.get('method', 'GET'))

            # Reconstruct request text
            request_text = f"{history_item.get('method', 'GET')} {history_item.get('url', '')} HTTP/1.1\n"
            for header, value in history_item.get('headers', {}).items():
                request_text += f"{header}: {value}\n"
            if history_item.get('body'):
                request_text += f"\n{history_item.get('body', '')}"

            self.request_edit.setPlainText(request_text)
            self.status_message.setText(f"Loaded request #{idx+1} from history")
