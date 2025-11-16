"""
Improved Repeater Tab - Multiple tabs support like Burp Suite
Allows managing multiple requests in separate tabs
"""

from PyQt5.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QPushButton, QLabel,
    QTextEdit, QSplitter, QTabWidget, QComboBox, QLineEdit,
    QGroupBox, QMessageBox, QSpinBox, QCheckBox, QApplication,
    QToolBar, QAction, QFileDialog, QProgressDialog, QShortcut, QMenu, QInputDialog
)
from PyQt5.QtCore import Qt, pyqtSignal, QTimer, QPoint
from PyQt5.QtGui import QFont, QColor, QSyntaxHighlighter, QTextCharFormat, QIcon, QKeySequence
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
        self.setup_shortcuts()

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

        # Auto-repeat controls
        toolbar.addWidget(QLabel("Repeat:"))
        self.repeat_count = QSpinBox()
        self.repeat_count.setRange(1, 100)
        self.repeat_count.setValue(1)
        self.repeat_count.setSuffix(" times")
        self.repeat_count.setToolTip("Number of times to send the request")
        toolbar.addWidget(self.repeat_count)

        self.auto_repeat_btn = QPushButton("🔄 Auto-Repeat")
        self.auto_repeat_btn.setStyleSheet("""
            QPushButton {
                background-color: #FF9800;
                color: white;
                font-weight: bold;
                padding: 8px 20px;
            }
            QPushButton:hover {
                background-color: #F57C00;
            }
        """)
        self.auto_repeat_btn.clicked.connect(self.auto_repeat_request)
        toolbar.addWidget(self.auto_repeat_btn)

        toolbar.addSeparator()

        # Clear button
        clear_btn = QPushButton("🗑 Clear")
        clear_btn.clicked.connect(self.clear_request)
        toolbar.addWidget(clear_btn)

        # Save/Load buttons
        save_btn = QPushButton("💾 Save")
        save_btn.clicked.connect(self.save_request)
        save_btn.setToolTip("Save request to file (Ctrl+S)")
        toolbar.addWidget(save_btn)

        load_btn = QPushButton("📂 Load")
        load_btn.clicked.connect(self.load_request_from_file)
        toolbar.addWidget(load_btn)

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

        # Search bar for request
        search_row = QHBoxLayout()
        search_row.addWidget(QLabel("🔍 Search:"))
        self.request_search_input = QLineEdit()
        self.request_search_input.setPlaceholderText("Search in request...")
        self.request_search_input.textChanged.connect(lambda: self.search_in_text(self.request_edit, self.request_search_input.text()))
        search_row.addWidget(self.request_search_input)

        self.request_search_prev = QPushButton("◀ Prev")
        self.request_search_prev.clicked.connect(lambda: self.find_prev(self.request_edit, self.request_search_input.text()))
        search_row.addWidget(self.request_search_prev)

        self.request_search_next = QPushButton("Next ▶")
        self.request_search_next.clicked.connect(lambda: self.find_next(self.request_edit, self.request_search_input.text()))
        search_row.addWidget(self.request_search_next)

        self.request_search_count = QLabel("0/0")
        search_row.addWidget(self.request_search_count)

        layout.addLayout(search_row)

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

        # Search bar for response
        search_row = QHBoxLayout()
        search_row.addWidget(QLabel("🔍 Search:"))
        self.response_search_input = QLineEdit()
        self.response_search_input.setPlaceholderText("Search in response...")
        self.response_search_input.textChanged.connect(self.search_in_response)
        search_row.addWidget(self.response_search_input)

        self.response_search_prev = QPushButton("◀ Prev")
        self.response_search_prev.clicked.connect(self.find_prev_in_response)
        search_row.addWidget(self.response_search_prev)

        self.response_search_next = QPushButton("Next ▶")
        self.response_search_next.clicked.connect(self.find_next_in_response)
        search_row.addWidget(self.response_search_next)

        self.response_search_count = QLabel("0/0")
        search_row.addWidget(self.response_search_count)

        layout.addLayout(search_row)

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

    def auto_repeat_request(self):
        """Send request multiple times"""
        repeat_count = self.repeat_count.value()

        if repeat_count == 1:
            self.send_request()
            return

        # Show progress dialog
        progress = QProgressDialog(f"Sending request {repeat_count} times...", "Cancel", 0, repeat_count, self)
        progress.setWindowModality(Qt.WindowModal)
        progress.setMinimumDuration(0)

        results = []

        try:
            for i in range(repeat_count):
                if progress.wasCanceled():
                    break

                progress.setValue(i)
                progress.setLabelText(f"Sending request {i+1}/{repeat_count}...")

                # Send request (reuse send_request logic)
                try:
                    raw_request = self.request_edit.toPlainText()
                    if not raw_request.strip():
                        continue

                    lines = raw_request.split('\n')
                    if not lines:
                        continue

                    first_line = lines[0].strip().split()
                    if len(first_line) < 2:
                        continue

                    method = first_line[0]
                    url = self.url_input.text() or first_line[1]

                    headers = {}
                    body_start = 0
                    for j, line in enumerate(lines[1:], 1):
                        if not line.strip():
                            body_start = j + 1
                            break
                        if ':' in line:
                            key, value = line.split(':', 1)
                            headers[key.strip()] = value.strip()

                    body = '\n'.join(lines[body_start:]) if body_start > 0 else ''

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

                    results.append({
                        'index': i + 1,
                        'status': response.status_code,
                        'time': elapsed,
                        'size': len(response.content)
                    })

                    # Update display with last response
                    if i == repeat_count - 1:
                        self._display_response(response, elapsed)

                    QApplication.processEvents()

                except Exception as e:
                    results.append({
                        'index': i + 1,
                        'error': str(e)
                    })

            progress.setValue(repeat_count)

            # Show summary
            summary = f"Auto-Repeat completed: {len(results)}/{repeat_count} requests\n\n"
            success_count = sum(1 for r in results if 'status' in r)
            error_count = len(results) - success_count

            if success_count > 0:
                avg_time = sum(r['time'] for r in results if 'time' in r) / success_count
                summary += f"✅ Successful: {success_count}\n"
                summary += f"⏱ Average time: {avg_time:.3f}s\n"

            if error_count > 0:
                summary += f"❌ Errors: {error_count}\n"

            # Status code distribution
            status_codes = {}
            for r in results:
                if 'status' in r:
                    code = r['status']
                    status_codes[code] = status_codes.get(code, 0) + 1

            if status_codes:
                summary += f"\n📊 Status codes:\n"
                for code, count in sorted(status_codes.items()):
                    summary += f"   {code}: {count} times\n"

            QMessageBox.information(self, "Auto-Repeat Results", summary)
            self.status_message.setText(f"✅ Auto-Repeat: {success_count}/{repeat_count} successful")

        except Exception as e:
            QMessageBox.critical(self, "Auto-Repeat Error", f"Failed:\n{str(e)}")
        finally:
            progress.close()

    def save_request(self):
        """Save current request to file"""
        filename, _ = QFileDialog.getSaveFileName(
            self,
            "Save Request",
            "",
            "HTTP Request Files (*.http);;Text Files (*.txt);;All Files (*)"
        )

        if filename:
            try:
                request_data = {
                    'url': self.url_input.text(),
                    'method': self.method_combo.currentText(),
                    'raw_request': self.request_edit.toPlainText(),
                    'timeout': self.timeout_spin.value(),
                    'follow_redirects': self.follow_redirects.isChecked(),
                    'saved_at': datetime.now().isoformat()
                }

                with open(filename, 'w', encoding='utf-8') as f:
                    json.dump(request_data, f, indent=2)

                self.status_message.setText(f"✅ Saved to {filename}")

            except Exception as e:
                QMessageBox.critical(self, "Save Error", f"Failed to save:\n{str(e)}")

    def load_request_from_file(self):
        """Load request from file"""
        filename, _ = QFileDialog.getOpenFileName(
            self,
            "Load Request",
            "",
            "HTTP Request Files (*.http);;Text Files (*.txt);;All Files (*)"
        )

        if filename:
            try:
                with open(filename, 'r', encoding='utf-8') as f:
                    request_data = json.load(f)

                self.url_input.setText(request_data.get('url', ''))

                method = request_data.get('method', 'GET')
                index = self.method_combo.findText(method)
                if index >= 0:
                    self.method_combo.setCurrentIndex(index)

                self.request_edit.setPlainText(request_data.get('raw_request', ''))
                self.timeout_spin.setValue(request_data.get('timeout', 10))
                self.follow_redirects.setChecked(request_data.get('follow_redirects', False))

                self.status_message.setText(f"✅ Loaded from {filename}")

            except Exception as e:
                QMessageBox.critical(self, "Load Error", f"Failed to load:\n{str(e)}")

    def setup_shortcuts(self):
        """Setup keyboard shortcuts"""
        # Ctrl+Enter - Send request
        send_shortcut = QShortcut(QKeySequence("Ctrl+Return"), self)
        send_shortcut.activated.connect(self.send_request)

        # Ctrl+L - Clear
        clear_shortcut = QShortcut(QKeySequence("Ctrl+L"), self)
        clear_shortcut.activated.connect(self.clear_request)

        # Ctrl+S - Save
        save_shortcut = QShortcut(QKeySequence("Ctrl+S"), self)
        save_shortcut.activated.connect(self.save_request)

        # Ctrl+F - Focus search in request
        search_shortcut = QShortcut(QKeySequence("Ctrl+F"), self)
        search_shortcut.activated.connect(lambda: self.request_search_input.setFocus())

    def search_in_text(self, text_edit, search_term):
        """Search and highlight all occurrences in text"""
        if not search_term:
            # Clear highlights
            cursor = text_edit.textCursor()
            cursor.select(cursor.Document)
            cursor.setCharFormat(QTextCharFormat())
            self.request_search_count.setText("0/0")
            return

        # Count occurrences
        text = text_edit.toPlainText()
        count = text.lower().count(search_term.lower())
        self.request_search_count.setText(f"0/{count}")

        # Highlight first occurrence
        if count > 0:
            self.find_next(text_edit, search_term)

    def find_next(self, text_edit, search_term):
        """Find next occurrence"""
        if not search_term:
            return

        cursor = text_edit.textCursor()
        found = text_edit.find(search_term)

        if not found:
            # Wrap around to beginning
            cursor.movePosition(cursor.Start)
            text_edit.setTextCursor(cursor)
            text_edit.find(search_term)

    def find_prev(self, text_edit, search_term):
        """Find previous occurrence"""
        if not search_term:
            return

        cursor = text_edit.textCursor()
        found = text_edit.find(search_term, text_edit.document().FindBackward)

        if not found:
            # Wrap around to end
            cursor.movePosition(cursor.End)
            text_edit.setTextCursor(cursor)
            text_edit.find(search_term, text_edit.document().FindBackward)

    def search_in_response(self):
        """Search in current response tab"""
        search_term = self.response_search_input.text()
        current_tab = self.response_tabs.currentWidget()

        if not search_term:
            self.response_search_count.setText("0/0")
            return

        # Count occurrences
        text = current_tab.toPlainText()
        count = text.lower().count(search_term.lower())
        self.response_search_count.setText(f"0/{count}")

        # Highlight first
        if count > 0:
            self.find_next_in_response()

    def find_next_in_response(self):
        """Find next in response"""
        search_term = self.response_search_input.text()
        current_tab = self.response_tabs.currentWidget()
        self.find_next(current_tab, search_term)

    def find_prev_in_response(self):
        """Find previous in response"""
        search_term = self.response_search_input.text()
        current_tab = self.response_tabs.currentWidget()
        self.find_prev(current_tab, search_term)


class RepeaterTabImproved(QWidget):
    """Improved Repeater with multiple tabs support"""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.tab_counter = 1
        self.favorite_tabs = set()  # Track favorite tabs
        self.init_ui()
        self.setup_global_shortcuts()

    def init_ui(self):
        """Initialize UI with tab management"""
        layout = QVBoxLayout()
        layout.setContentsMargins(0, 0, 0, 0)

        # Tab widget for multiple repeaters
        self.repeater_tabs = QTabWidget()
        self.repeater_tabs.setTabsClosable(True)
        self.repeater_tabs.tabCloseRequested.connect(self.close_tab)
        self.repeater_tabs.tabBar().setContextMenuPolicy(Qt.CustomContextMenu)
        self.repeater_tabs.tabBar().customContextMenuRequested.connect(self.show_tab_context_menu)
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

    def duplicate_current_tab(self):
        """Duplicate current tab"""
        current = self.repeater_tabs.currentWidget()
        if current and isinstance(current, SingleRepeaterWidget):
            # Get current tab data
            request_data = {
                'url': current.url_input.text(),
                'method': current.method_combo.currentText(),
                'headers': {},
                'body': ''
            }

            # Parse raw request for full data
            raw_request = current.request_edit.toPlainText()
            lines = raw_request.split('\n')

            body_start = 0
            for i, line in enumerate(lines[1:], 1):
                if not line.strip():
                    body_start = i + 1
                    break
                if ':' in line:
                    key, value = line.split(':', 1)
                    request_data['headers'][key.strip()] = value.strip()

            if body_start > 0:
                request_data['body'] = '\n'.join(lines[body_start:])

            # Create new tab with same data
            new_tab = self.add_new_tab(request_data)

    def setup_global_shortcuts(self):
        """Setup global keyboard shortcuts for tab management"""
        # Ctrl+D - Duplicate current tab
        duplicate_shortcut = QShortcut(QKeySequence("Ctrl+D"), self)
        duplicate_shortcut.activated.connect(self.duplicate_current_tab)

        # Ctrl+W - Close current tab
        close_shortcut = QShortcut(QKeySequence("Ctrl+W"), self)
        close_shortcut.activated.connect(lambda: self.close_tab(self.repeater_tabs.currentIndex()))

        # Ctrl+T - New tab
        new_tab_shortcut = QShortcut(QKeySequence("Ctrl+T"), self)
        new_tab_shortcut.activated.connect(lambda: self.add_new_tab())

    def show_tab_context_menu(self, position):
        """Show context menu for tab"""
        tab_bar = self.repeater_tabs.tabBar()
        tab_index = tab_bar.tabAt(position)

        if tab_index < 0:
            return

        menu = QMenu()

        # Rename action
        rename_action = menu.addAction("✏️ Rename Tab")
        rename_action.triggered.connect(lambda: self.rename_tab(tab_index))

        # Favorite action
        is_favorite = tab_index in self.favorite_tabs
        favorite_text = "⭐ Unfavorite" if is_favorite else "⭐ Add to Favorites"
        favorite_action = menu.addAction(favorite_text)
        favorite_action.triggered.connect(lambda: self.toggle_favorite(tab_index))

        menu.addSeparator()

        # Duplicate action
        duplicate_action = menu.addAction("📋 Duplicate Tab")
        duplicate_action.triggered.connect(self.duplicate_current_tab)

        menu.addSeparator()

        # Close action
        if self.repeater_tabs.count() > 1:
            close_action = menu.addAction("❌ Close Tab")
            close_action.triggered.connect(lambda: self.close_tab(tab_index))

            # Close other tabs
            close_others_action = menu.addAction("❌ Close Other Tabs")
            close_others_action.triggered.connect(lambda: self.close_other_tabs(tab_index))

        menu.exec_(tab_bar.mapToGlobal(position))

    def rename_tab(self, tab_index):
        """Rename a tab"""
        current_name = self.repeater_tabs.tabText(tab_index)
        # Remove favorite star if present
        current_name = current_name.replace("⭐ ", "")

        new_name, ok = QInputDialog.getText(
            self,
            "Rename Tab",
            "Enter new tab name:",
            QLineEdit.Normal,
            current_name
        )

        if ok and new_name:
            # Keep favorite star if tab is favorite
            if tab_index in self.favorite_tabs:
                new_name = f"⭐ {new_name}"
            self.repeater_tabs.setTabText(tab_index, new_name)

    def toggle_favorite(self, tab_index):
        """Toggle favorite status of tab"""
        current_name = self.repeater_tabs.tabText(tab_index)

        if tab_index in self.favorite_tabs:
            # Remove from favorites
            self.favorite_tabs.remove(tab_index)
            new_name = current_name.replace("⭐ ", "")
        else:
            # Add to favorites
            self.favorite_tabs.add(tab_index)
            if not current_name.startswith("⭐ "):
                new_name = f"⭐ {current_name}"
            else:
                new_name = current_name

        self.repeater_tabs.setTabText(tab_index, new_name)

    def close_other_tabs(self, keep_index):
        """Close all tabs except the specified one"""
        # Close tabs in reverse order to maintain indices
        for i in range(self.repeater_tabs.count() - 1, -1, -1):
            if i != keep_index:
                self.repeater_tabs.removeTab(i)
                # Update favorite_tabs set
                if i in self.favorite_tabs:
                    self.favorite_tabs.remove(i)
