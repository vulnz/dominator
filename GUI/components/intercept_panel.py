"""
Intercept Panel - Persistent panel for managing intercepted requests
Shows queued requests with navigation arrows instead of popup dialogs
"""

from PyQt5.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QPushButton, QLabel,
    QTextEdit, QFrame, QMessageBox
)
from PyQt5.QtCore import Qt, pyqtSignal
from PyQt5.QtGui import QFont, QColor, QSyntaxHighlighter, QTextCharFormat
from collections import deque
import re
from GUI.utils.message_box import show_information


class HTTPSyntaxHighlighter(QSyntaxHighlighter):
    """Syntax highlighter for HTTP requests/responses"""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.highlighting_rules = []

        # HTTP methods - blue and bold
        method_format = QTextCharFormat()
        method_format.setForeground(QColor("#1565C0"))
        method_format.setFontWeight(75)
        for method in ["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS", "TRACE", "CONNECT"]:
            self.highlighting_rules.append((f"^{method}\\b", method_format))

        # Headers - purple
        header_format = QTextCharFormat()
        header_format.setForeground(QColor("#6A1B9A"))
        self.highlighting_rules.append((r"^[\w-]+:", header_format))

        # URLs - cyan
        url_format = QTextCharFormat()
        url_format.setForeground(QColor("#00838F"))
        self.highlighting_rules.append((r"https?://[^\s]+", url_format))

        # Status codes - orange for errors, green for success
        status_format = QTextCharFormat()
        status_format.setForeground(QColor("#E65100"))
        self.highlighting_rules.append((r"HTTP/\d\.\d \d{3}", status_format))

        # Header values after colon - gray
        value_format = QTextCharFormat()
        value_format.setForeground(QColor("#455A64"))
        self.highlighting_rules.append((r":\s.*$", value_format))

    def highlightBlock(self, text):
        for pattern, fmt in self.highlighting_rules:
            for match in re.finditer(pattern, text, re.MULTILINE):
                self.setFormat(match.start(), match.end() - match.start(), fmt)


class InterceptPanel(QWidget):
    """Persistent panel for intercepting and managing requests"""

    # Signals
    request_forwarded = pyqtSignal(int)  # request_id
    request_dropped = pyqtSignal(int)  # request_id
    request_modified = pyqtSignal(int, dict)  # request_id, modified_data
    host_auto_allowed = pyqtSignal(str)  # host
    host_ignored = pyqtSignal(str)  # host - add to ignore list
    host_scoped = pyqtSignal(str)  # host - add to scope (only intercept this host)
    send_to_scanner = pyqtSignal(dict)  # request_data
    send_to_repeater = pyqtSignal(dict)  # request_data

    def __init__(self, parent=None):
        super().__init__(parent)
        self.request_queue = deque()  # Queue of intercepted requests
        self.current_index = 0
        self.proxy = None  # Will be set by parent
        self.init_ui()

    def set_proxy(self, proxy):
        """Set the proxy reference"""
        self.proxy = proxy

    def init_ui(self):
        """Initialize the intercept panel UI"""
        self.setStyleSheet("""
            QWidget {
                background-color: #fff3e0;
                border: 2px solid #ff9800;
                border-radius: 5px;
            }
            QLabel {
                color: black;
                background: transparent;
                border: none;
            }
            QTextEdit {
                background-color: white;
                color: black;
                border: 1px solid #cccccc;
                border-radius: 4px;
            }
            QPushButton {
                padding: 6px 12px;
                border-radius: 4px;
                font-weight: bold;
            }
        """)

        layout = QVBoxLayout()
        layout.setContentsMargins(10, 10, 10, 10)

        # Header with navigation
        header_layout = QHBoxLayout()

        # Intercept indicator
        self.intercept_label = QLabel("INTERCEPT")
        self.intercept_label.setStyleSheet("""
            QLabel {
                background-color: #ff9800;
                color: white;
                padding: 5px 10px;
                border-radius: 3px;
                font-weight: bold;
            }
        """)
        header_layout.addWidget(self.intercept_label)

        # Navigation arrows
        self.prev_btn = QPushButton("<")
        self.prev_btn.setFixedWidth(40)
        self.prev_btn.clicked.connect(self.show_previous)
        self.prev_btn.setStyleSheet("background-color: #e0e0e0; color: black;")
        header_layout.addWidget(self.prev_btn)

        self.queue_label = QLabel("0 / 0")
        self.queue_label.setStyleSheet("font-weight: bold; padding: 0 10px;")
        header_layout.addWidget(self.queue_label)

        self.next_btn = QPushButton(">")
        self.next_btn.setFixedWidth(40)
        self.next_btn.clicked.connect(self.show_next)
        self.next_btn.setStyleSheet("background-color: #e0e0e0; color: black;")
        header_layout.addWidget(self.next_btn)

        header_layout.addStretch()

        # Request info
        self.info_label = QLabel("No intercepted requests")
        self.info_label.setStyleSheet("color: #666;")
        header_layout.addWidget(self.info_label)

        layout.addLayout(header_layout)

        # Request editor
        self.request_edit = QTextEdit()
        self.request_edit.setFont(QFont("Consolas", 9))
        self.request_edit.setMinimumHeight(150)
        self.request_edit.setMaximumHeight(250)

        # Add syntax highlighting
        self.highlighter = HTTPSyntaxHighlighter(self.request_edit.document())

        layout.addWidget(self.request_edit)

        # Action buttons
        button_layout = QHBoxLayout()

        self.forward_btn = QPushButton("Forward")
        self.forward_btn.clicked.connect(self.forward_request)
        self.forward_btn.setStyleSheet("background-color: #4CAF50; color: white;")
        button_layout.addWidget(self.forward_btn)

        self.forward_all_btn = QPushButton("Forward All")
        self.forward_all_btn.clicked.connect(self.forward_all_requests)
        self.forward_all_btn.setStyleSheet("background-color: #8BC34A; color: white;")
        button_layout.addWidget(self.forward_all_btn)

        self.modify_btn = QPushButton("Modify & Forward")
        self.modify_btn.clicked.connect(self.modify_and_forward)
        self.modify_btn.setStyleSheet("background-color: #2196F3; color: white;")
        button_layout.addWidget(self.modify_btn)

        self.drop_btn = QPushButton("Drop")
        self.drop_btn.clicked.connect(self.drop_request)
        self.drop_btn.setStyleSheet("background-color: #f44336; color: white;")
        button_layout.addWidget(self.drop_btn)

        self.drop_all_btn = QPushButton("Drop All")
        self.drop_all_btn.clicked.connect(self.drop_all_requests)
        self.drop_all_btn.setStyleSheet("background-color: #d32f2f; color: white;")
        button_layout.addWidget(self.drop_all_btn)

        self.auto_allow_btn = QPushButton("Auto-Allow Host")
        self.auto_allow_btn.clicked.connect(self.auto_allow_host)
        self.auto_allow_btn.setStyleSheet("background-color: #FF9800; color: white;")
        button_layout.addWidget(self.auto_allow_btn)

        layout.addLayout(button_layout)

        # Send to Scanner/Repeater buttons
        send_layout = QHBoxLayout()

        self.send_to_repeater_btn = QPushButton("🔁 Send to Repeater")
        self.send_to_repeater_btn.clicked.connect(self.send_request_to_repeater)
        self.send_to_repeater_btn.setStyleSheet("background-color: #2196F3; color: white;")
        send_layout.addWidget(self.send_to_repeater_btn)

        self.send_to_scanner_btn = QPushButton("🔍 Send to Scanner")
        self.send_to_scanner_btn.clicked.connect(self.send_request_to_scanner)
        self.send_to_scanner_btn.setStyleSheet("background-color: #673AB7; color: white;")
        send_layout.addWidget(self.send_to_scanner_btn)

        send_layout.addStretch()
        layout.addLayout(send_layout)

        # Second row - Scope and Ignore buttons
        scope_layout = QHBoxLayout()

        self.ignore_host_btn = QPushButton("🚫 Ignore Host")
        self.ignore_host_btn.clicked.connect(self.ignore_host)
        self.ignore_host_btn.setStyleSheet("background-color: #9E9E9E; color: white;")
        self.ignore_host_btn.setToolTip("Add host to ignore list - requests won't be logged")
        scope_layout.addWidget(self.ignore_host_btn)

        self.scope_host_btn = QPushButton("🎯 Scope This Host Only")
        self.scope_host_btn.clicked.connect(self.scope_host_only)
        self.scope_host_btn.setStyleSheet("background-color: #673AB7; color: white;")
        self.scope_host_btn.setToolTip("Only intercept requests to this host")
        scope_layout.addWidget(self.scope_host_btn)

        self.add_to_scope_btn = QPushButton("➕ Add to Scope")
        self.add_to_scope_btn.clicked.connect(self.add_host_to_scope)
        self.add_to_scope_btn.setStyleSheet("background-color: #3F51B5; color: white;")
        self.add_to_scope_btn.setToolTip("Add this host to scope list")
        scope_layout.addWidget(self.add_to_scope_btn)

        scope_layout.addStretch()
        layout.addLayout(scope_layout)

        self.setLayout(layout)

        # Initially hidden
        self.hide()
        self.update_ui()

    def add_request(self, request_data):
        """Add a new intercepted request to the queue"""
        self.request_queue.append(request_data)

        # If this is the first request, show it
        if len(self.request_queue) == 1:
            self.current_index = 0
            self.show()
            self.update_ui()  # Full UI update for first request
        else:
            # For subsequent requests, only update counter (not full UI rebuild)
            # This prevents lag when many requests arrive rapidly
            self._update_counter_only()

    def _update_counter_only(self):
        """Fast update - only update the counter, not the entire UI"""
        count = len(self.request_queue)
        self.queue_label.setText(f"{self.current_index + 1} / {count}")
        self.next_btn.setEnabled(self.current_index < count - 1)

    def update_ui(self):
        """Update UI to reflect current state"""
        count = len(self.request_queue)

        if count == 0:
            self.queue_label.setText("0 / 0")
            self.info_label.setText("No intercepted requests")
            self.request_edit.clear()
            self.prev_btn.setEnabled(False)
            self.next_btn.setEnabled(False)
            self.forward_btn.setEnabled(False)
            self.forward_all_btn.setEnabled(False)
            self.modify_btn.setEnabled(False)
            self.drop_btn.setEnabled(False)
            self.drop_all_btn.setEnabled(False)
            self.auto_allow_btn.setEnabled(False)
            self.ignore_host_btn.setEnabled(False)
            self.scope_host_btn.setEnabled(False)
            self.add_to_scope_btn.setEnabled(False)
            self.send_to_repeater_btn.setEnabled(False)
            self.send_to_scanner_btn.setEnabled(False)
            return

        # Enable buttons
        self.forward_btn.setEnabled(True)
        self.forward_all_btn.setEnabled(True)
        self.modify_btn.setEnabled(True)
        self.drop_btn.setEnabled(True)
        self.drop_all_btn.setEnabled(True)
        self.auto_allow_btn.setEnabled(True)
        self.ignore_host_btn.setEnabled(True)
        self.scope_host_btn.setEnabled(True)
        self.add_to_scope_btn.setEnabled(True)
        self.send_to_repeater_btn.setEnabled(True)
        self.send_to_scanner_btn.setEnabled(True)

        # Update navigation
        self.queue_label.setText(f"{self.current_index + 1} / {count}")
        self.prev_btn.setEnabled(self.current_index > 0)
        self.next_btn.setEnabled(self.current_index < count - 1)

        # Show current request
        if 0 <= self.current_index < count:
            request = self.request_queue[self.current_index]
            self.display_request(request)

    def display_request(self, request_data):
        """Display a request in the editor"""
        # Update info label
        method = request_data.get('method', 'GET')
        url = request_data.get('url', '')
        req_id = request_data.get('id', 0)

        # Truncate URL for display
        display_url = url[:80] + '...' if len(url) > 80 else url
        self.info_label.setText(f"#{req_id} | {method} {display_url}")

        # Build request text
        request_text = f"{method} {url}\n"
        for header, value in request_data.get('headers', {}).items():
            request_text += f"{header}: {value}\n"
        request_text += f"\n{request_data.get('body', '')}"
        self.request_edit.setPlainText(request_text)

    def show_previous(self):
        """Show previous request in queue"""
        if self.current_index > 0:
            self.current_index -= 1
            self.update_ui()

    def show_next(self):
        """Show next request in queue"""
        if self.current_index < len(self.request_queue) - 1:
            self.current_index += 1
            self.update_ui()

    def get_current_request(self):
        """Get the currently displayed request"""
        if 0 <= self.current_index < len(self.request_queue):
            return self.request_queue[self.current_index]
        return None

    def remove_current_request(self):
        """Remove the current request from queue"""
        if 0 <= self.current_index < len(self.request_queue):
            del self.request_queue[self.current_index]

            # Adjust index
            if self.current_index >= len(self.request_queue):
                self.current_index = max(0, len(self.request_queue) - 1)

            # Hide if empty
            if len(self.request_queue) == 0:
                self.hide()

            self.update_ui()

    def forward_request(self):
        """Forward the current request"""
        request = self.get_current_request()
        if request and self.proxy:
            self.proxy.forward_request(request['id'])
            self.request_forwarded.emit(request['id'])
            self.remove_current_request()

    def forward_all_requests(self):
        """Forward all requests in queue"""
        if not self.proxy:
            return

        while len(self.request_queue) > 0:
            request = self.request_queue[0]
            self.proxy.forward_request(request['id'])
            self.request_forwarded.emit(request['id'])
            del self.request_queue[0]

        self.current_index = 0
        self.hide()
        self.update_ui()

    def drop_request(self):
        """Drop the current request"""
        request = self.get_current_request()
        if request and self.proxy:
            self.proxy.drop_request(request['id'])
            self.request_dropped.emit(request['id'])
            self.remove_current_request()

    def drop_all_requests(self):
        """Drop all requests in queue"""
        if not self.proxy:
            return

        while len(self.request_queue) > 0:
            request = self.request_queue[0]
            self.proxy.drop_request(request['id'])
            self.request_dropped.emit(request['id'])
            del self.request_queue[0]

        self.current_index = 0
        self.hide()
        self.update_ui()

    def modify_and_forward(self):
        """Modify and forward the current request"""
        request = self.get_current_request()
        if not request or not self.proxy:
            return

        # Parse modified request
        modified = self.parse_modified_request(request)
        self.proxy.modify_and_forward(request['id'], modified)
        self.request_modified.emit(request['id'], modified)
        self.remove_current_request()

    def parse_modified_request(self, original_request):
        """Parse the edited request text into a request dict"""
        text = self.request_edit.toPlainText()
        lines = text.split('\n')

        # Parse first line (method and URL)
        first_line = lines[0].split()
        method = first_line[0] if len(first_line) > 0 else original_request['method']
        url = first_line[1] if len(first_line) > 1 else original_request['url']

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
        modified = original_request.copy()
        modified['method'] = method
        modified['url'] = url
        modified['headers'] = headers
        modified['body'] = body
        modified['raw_body'] = body.encode('utf-8')

        return modified

    def auto_allow_host(self):
        """Auto-allow the host of the current request"""
        request = self.get_current_request()
        if not request or not self.proxy:
            return

        from urllib.parse import urlparse
        parsed = urlparse(request['url'])
        host = parsed.netloc or request.get('headers', {}).get('Host', '')

        if host:
            self.proxy.add_auto_allow_host(host)
            self.host_auto_allowed.emit(host)

            # Forward and remove
            self.proxy.forward_request(request['id'])
            self.remove_current_request()

            show_information(
                self,
                "Host Auto-Allowed",
                f"Host '{host}' added to auto-allow list.\n\n"
                "Future requests to this host will bypass interception.",
                setting_key="intercept_auto_allow_host"
            )

    def get_queue_count(self):
        """Get number of requests in queue"""
        return len(self.request_queue)

    def ignore_host(self):
        """Add host to ignore list - won't be logged"""
        request = self.get_current_request()
        if not request or not self.proxy:
            return

        from urllib.parse import urlparse
        parsed = urlparse(request['url'])
        host = parsed.netloc or request.get('headers', {}).get('Host', '')

        if host:
            # Add to ignore patterns
            pattern = f"^https?://{host.replace('.', '\\.')}/"
            self.proxy.add_ignore_pattern(pattern)
            self.host_ignored.emit(host)

            # Forward and remove
            self.proxy.forward_request(request['id'])
            self.remove_current_request()

            show_information(
                self,
                "Host Ignored",
                f"Host '{host}' added to ignore list.\n\n"
                "Future requests to this host won't be logged or intercepted.",
                setting_key="intercept_host_ignored"
            )

    def scope_host_only(self):
        """Set scope to only this host - ignore everything else"""
        request = self.get_current_request()
        if not request or not self.proxy:
            return

        from urllib.parse import urlparse
        parsed = urlparse(request['url'])
        host = parsed.netloc or request.get('headers', {}).get('Host', '')

        if host:
            # Clear existing scope and set to only this host
            self.proxy.in_scope_patterns = [f"^https?://{host.replace('.', '\\.')}"]
            self.proxy.scope_enabled = True
            self.host_scoped.emit(host)

            # Forward and remove
            self.proxy.forward_request(request['id'])
            self.remove_current_request()

            show_information(
                self,
                "Scope Set",
                f"Scope set to '{host}' only.\n\n"
                "Only requests to this host will be logged and can be intercepted.\n"
                "All other hosts will be ignored.",
                setting_key="intercept_scope_set"
            )

    def add_host_to_scope(self):
        """Add host to scope list"""
        request = self.get_current_request()
        if not request or not self.proxy:
            return

        from urllib.parse import urlparse
        parsed = urlparse(request['url'])
        host = parsed.netloc or request.get('headers', {}).get('Host', '')

        if host:
            # Add to scope patterns
            pattern = f"^https?://{host.replace('.', '\\.')}"
            if pattern not in self.proxy.in_scope_patterns:
                self.proxy.in_scope_patterns.append(pattern)
            self.proxy.scope_enabled = True
            self.host_scoped.emit(host)

            # Forward and remove
            self.proxy.forward_request(request['id'])
            self.remove_current_request()

            show_information(
                self,
                "Added to Scope",
                f"Host '{host}' added to scope.\n\n"
                f"Total hosts in scope: {len(self.proxy.in_scope_patterns)}",
                setting_key="intercept_added_to_scope"
            )

    def send_request_to_scanner(self):
        """Send current request to Scanner tab"""
        request = self.get_current_request()
        if request:
            self.send_to_scanner.emit(request)
            # Forward and remove
            if self.proxy:
                self.proxy.forward_request(request['id'])
            self.remove_current_request()

    def send_request_to_repeater(self):
        """Send current request to Repeater tab"""
        request = self.get_current_request()
        if request:
            self.send_to_repeater.emit(request)
            # Forward and remove
            if self.proxy:
                self.proxy.forward_request(request['id'])
            self.remove_current_request()
