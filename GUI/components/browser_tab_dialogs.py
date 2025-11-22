"""
Browser Tab Dialog Classes
Contains dialog classes for browser tab functionality.
"""

from PyQt5.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QPushButton, QLabel,
    QTextEdit, QCheckBox, QGroupBox, QHeaderView, QScrollArea,
    QMessageBox, QDialog, QDialogButtonBox, QGridLayout
)
from PyQt5.QtGui import QFont


class BulkScanConfigDialog(QDialog):
    """Dialog for configuring bulk scan from multiple requests"""

    AVAILABLE_MODULES = [
        'sqli', 'xss', 'xxe', 'ssti', 'cmdi', 'lfi', 'rfi',
        'ssrf', 'redirect', 'csrf', 'idor', 'xpath', 'dirbrute',
        'file_upload', 'weak_credentials', 'dom_xss', 'formula_injection',
        'php_object_injection', 'git', 'env_secrets', 'oob_detection'
    ]

    def __init__(self, urls, cookies, custom_headers, parent=None):
        super().__init__(parent)
        self.urls = urls
        self.cookies = cookies
        self.custom_headers = custom_headers
        self.module_checkboxes = {}
        self.url_checkboxes = {}
        self.init_ui()

    def init_ui(self):
        """Initialize bulk scan config dialog UI"""
        self.setWindowTitle("Configure Bulk Scan")
        self.resize(800, 700)

        self.setStyleSheet("""
            QDialog {
                background-color: #ffffff;
                color: #333333;
            }
            QLabel {
                color: #333333;
            }
            QCheckBox {
                color: #333333;
            }
            QGroupBox {
                background-color: #f8f8f8;
                border: 1px solid #e0e0e0;
                border-radius: 6px;
                margin-top: 10px;
                padding-top: 10px;
                font-weight: bold;
                color: #333333;
            }
            QGroupBox::title {
                subcontrol-origin: margin;
                left: 10px;
                padding: 0 5px;
                color: #4CAF50;
            }
            QListWidget {
                background-color: #ffffff;
                color: #333333;
                border: 1px solid #e0e0e0;
                border-radius: 4px;
            }
            QPushButton {
                background-color: #4CAF50;
                color: white;
                border: none;
                border-radius: 4px;
                padding: 8px 16px;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: #45a049;
            }
        """)

        layout = QVBoxLayout()

        # URLs selection
        urls_group = QGroupBox(f"URLs to Scan ({len(self.urls)} selected)")
        urls_layout = QVBoxLayout()

        # Select All / Deselect All
        url_btns = QHBoxLayout()
        select_all_urls = QPushButton("Select All")
        select_all_urls.clicked.connect(self.select_all_urls)
        url_btns.addWidget(select_all_urls)

        deselect_all_urls = QPushButton("Deselect All")
        deselect_all_urls.clicked.connect(self.deselect_all_urls)
        url_btns.addWidget(deselect_all_urls)
        url_btns.addStretch()
        urls_layout.addLayout(url_btns)

        # URL list with checkboxes
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setMaximumHeight(150)

        url_container = QWidget()
        url_container_layout = QVBoxLayout()

        for url in self.urls:
            cb = QCheckBox(url[:100] + ('...' if len(url) > 100 else ''))
            cb.setChecked(True)
            cb.setToolTip(url)
            self.url_checkboxes[url] = cb
            url_container_layout.addWidget(cb)

        url_container.setLayout(url_container_layout)
        scroll.setWidget(url_container)
        urls_layout.addWidget(scroll)

        urls_group.setLayout(urls_layout)
        layout.addWidget(urls_group)

        # Module selection
        module_group = QGroupBox("Select Scan Modules")
        module_layout = QVBoxLayout()

        # Module buttons
        mod_btns = QHBoxLayout()
        select_all_mods = QPushButton("Select All")
        select_all_mods.clicked.connect(self.select_all_modules)
        mod_btns.addWidget(select_all_mods)

        deselect_all_mods = QPushButton("Deselect All")
        deselect_all_mods.clicked.connect(self.deselect_all_modules)
        mod_btns.addWidget(deselect_all_mods)

        critical_only = QPushButton("Critical Only")
        critical_only.clicked.connect(self.select_critical_modules)
        mod_btns.addWidget(critical_only)

        mod_btns.addStretch()
        module_layout.addLayout(mod_btns)

        # Module checkboxes in grid
        grid = QGridLayout()
        row = 0
        col = 0

        for module in sorted(self.AVAILABLE_MODULES):
            checkbox = QCheckBox(module.upper().replace('_', ' '))
            checkbox.setChecked(True)
            self.module_checkboxes[module] = checkbox
            grid.addWidget(checkbox, row, col)
            col += 1
            if col >= 3:
                col = 0
                row += 1

        module_layout.addLayout(grid)
        module_group.setLayout(module_layout)
        layout.addWidget(module_group)

        # Extracted data info
        data_group = QGroupBox("Session Data (will be applied to all scans)")
        data_layout = QVBoxLayout()
        data_layout.addWidget(QLabel(f"<b>Cookies:</b> {len(self.cookies)} found"))
        data_layout.addWidget(QLabel(f"<b>Custom Headers:</b> {len(self.custom_headers)} found"))
        data_group.setLayout(data_layout)
        layout.addWidget(data_group)

        # Buttons
        button_box = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        button_box.accepted.connect(self.accept)
        button_box.rejected.connect(self.reject)
        layout.addWidget(button_box)

        self.setLayout(layout)

    def select_all_urls(self):
        for cb in self.url_checkboxes.values():
            cb.setChecked(True)

    def deselect_all_urls(self):
        for cb in self.url_checkboxes.values():
            cb.setChecked(False)

    def select_all_modules(self):
        for cb in self.module_checkboxes.values():
            cb.setChecked(True)

    def deselect_all_modules(self):
        for cb in self.module_checkboxes.values():
            cb.setChecked(False)

    def select_critical_modules(self):
        critical = ['sqli', 'xss', 'lfi', 'cmdi', 'ssti', 'xxe']
        for module, cb in self.module_checkboxes.items():
            cb.setChecked(module in critical)

    def get_config(self):
        """Get bulk scan configuration"""
        selected_urls = [url for url, cb in self.url_checkboxes.items() if cb.isChecked()]
        selected_modules = [module for module, cb in self.module_checkboxes.items() if cb.isChecked()]

        return {
            'urls': selected_urls,
            'modules': selected_modules,
            'cookies': self.cookies,
            'custom_headers': self.custom_headers
        }


class InterceptDialog(QDialog):
    """Dialog for intercepting and modifying requests"""

    def __init__(self, request_data, parent=None):
        super().__init__(parent)
        self.request_data = request_data
        self.action = 'forward'
        self.init_ui()

    def init_ui(self):
        """Initialize intercept dialog UI"""
        self.setWindowTitle(f"Intercept Request #{self.request_data['id']}")
        self.resize(800, 600)

        # Set light theme for dialog
        self.setStyleSheet("""
            QDialog {
                background-color: #ffffff;
                color: #333333;
            }
            QLabel {
                color: #333333;
            }
            QTextEdit {
                background-color: #f8f8f8;
                color: #333333;
                border: 1px solid #e0e0e0;
                border-radius: 4px;
                padding: 5px;
            }
            QPushButton {
                background-color: #4CAF50;
                color: white;
                border: none;
                border-radius: 4px;
                padding: 8px 16px;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: #45a049;
            }
        """)

        layout = QVBoxLayout()

        # Request details
        info_label = QLabel(
            f"<b>Method:</b> {self.request_data['method']} | "
            f"<b>URL:</b> {self.request_data['url']}"
        )
        layout.addWidget(info_label)

        # Request editor
        self.request_edit = QTextEdit()
        request_text = f"{self.request_data['method']} {self.request_data['url']}\n"
        for header, value in self.request_data['headers'].items():
            request_text += f"{header}: {value}\n"
        request_text += f"\n{self.request_data['body']}"
        self.request_edit.setPlainText(request_text)
        self.request_edit.setFont(QFont("Courier New", 9))
        layout.addWidget(self.request_edit)

        # Buttons
        button_layout = QHBoxLayout()

        forward_btn = QPushButton("Forward")
        forward_btn.clicked.connect(lambda: self.set_action('forward'))
        button_layout.addWidget(forward_btn)

        modify_btn = QPushButton("Modify & Forward")
        modify_btn.clicked.connect(lambda: self.set_action('modify'))
        modify_btn.setStyleSheet("""
            QPushButton {
                background-color: #2196F3;
                color: white;
                border: none;
                border-radius: 4px;
                padding: 8px 16px;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: #1976D2;
            }
        """)
        button_layout.addWidget(modify_btn)

        drop_btn = QPushButton("Drop")
        drop_btn.clicked.connect(lambda: self.set_action('drop'))
        drop_btn.setStyleSheet("""
            QPushButton {
                background-color: #f44336;
                color: white;
                border: none;
                border-radius: 4px;
                padding: 8px 16px;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: #d32f2f;
            }
        """)
        button_layout.addWidget(drop_btn)

        layout.addLayout(button_layout)

        # Send to Scanner/Repeater buttons
        send_layout = QHBoxLayout()

        send_to_repeater_btn = QPushButton("🔁 Send to Repeater")
        send_to_repeater_btn.clicked.connect(lambda: self.set_action('send_to_repeater'))
        send_to_repeater_btn.setStyleSheet("""
            QPushButton {
                background-color: #2196F3;
                color: white;
                border: none;
                border-radius: 4px;
                padding: 8px 16px;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: #1976D2;
            }
        """)
        send_layout.addWidget(send_to_repeater_btn)

        send_to_scanner_btn = QPushButton("🔍 Send to Scanner")
        send_to_scanner_btn.clicked.connect(lambda: self.set_action('send_to_scanner'))
        send_to_scanner_btn.setStyleSheet("""
            QPushButton {
                background-color: #FF9800;
                color: white;
                border: none;
                border-radius: 4px;
                padding: 8px 16px;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: #F57C00;
            }
        """)
        send_layout.addWidget(send_to_scanner_btn)

        send_layout.addStretch()
        layout.addLayout(send_layout)

        # Auto-allow button row
        auto_layout = QHBoxLayout()
        auto_allow_btn = QPushButton("Auto-Allow This Host (Bypass Interception)")
        auto_allow_btn.clicked.connect(lambda: self.set_action('auto_allow'))
        auto_allow_btn.setStyleSheet("""
            QPushButton {
                background-color: #FF9800;
                color: white;
                border: none;
                border-radius: 4px;
                padding: 8px 16px;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: #F57C00;
            }
        """)
        auto_layout.addWidget(auto_allow_btn)
        layout.addLayout(auto_layout)

        self.setLayout(layout)

    def set_action(self, action):
        """Set the action and close dialog"""
        self.action = action
        self.accept()

    def get_action(self):
        """Get the selected action"""
        return self.action

    def get_modified_request(self):
        """Get modified request data"""
        # Parse modified request text
        text = self.request_edit.toPlainText()
        lines = text.split('\n')

        # Parse first line (method and URL)
        first_line = lines[0].split()
        method = first_line[0] if len(first_line) > 0 else self.request_data['method']
        url = first_line[1] if len(first_line) > 1 else self.request_data['url']

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
        modified = self.request_data.copy()
        modified['method'] = method
        modified['url'] = url
        modified['headers'] = headers
        modified['body'] = body
        modified['raw_body'] = body.encode('utf-8')

        return modified


class ModifyRequestDialog(QDialog):
    """Dialog for modifying a request before replay"""

    def __init__(self, request_data, parent=None):
        super().__init__(parent)
        self.request_data = request_data
        self.init_ui()

    def init_ui(self):
        """Initialize modify dialog UI"""
        self.setWindowTitle("Modify Request")
        self.resize(800, 600)

        # Set light theme for dialog
        self.setStyleSheet("""
            QDialog {
                background-color: #ffffff;
                color: #333333;
            }
            QLabel {
                color: #333333;
            }
            QTextEdit {
                background-color: #f8f8f8;
                color: #333333;
                border: 1px solid #e0e0e0;
                border-radius: 4px;
                padding: 5px;
            }
            QDialogButtonBox QPushButton {
                background-color: #4CAF50;
                color: white;
                border: none;
                border-radius: 4px;
                padding: 8px 16px;
                font-weight: bold;
            }
            QDialogButtonBox QPushButton:hover {
                background-color: #45a049;
            }
        """)

        layout = QVBoxLayout()

        layout.addWidget(QLabel("Edit the request below and click Send:"))

        # Request editor
        self.request_edit = QTextEdit()
        request_text = f"{self.request_data['method']} {self.request_data['url']}\n"
        for header, value in self.request_data['headers'].items():
            request_text += f"{header}: {value}\n"
        request_text += f"\n{self.request_data['body']}"
        self.request_edit.setPlainText(request_text)
        self.request_edit.setFont(QFont("Courier New", 9))
        layout.addWidget(self.request_edit)

        # Buttons
        buttons = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)

        self.setLayout(layout)

    def get_modified_request(self):
        """Parse and return modified request"""
        text = self.request_edit.toPlainText()
        lines = text.split('\n')

        # Parse first line
        first_line = lines[0].split()
        method = first_line[0] if len(first_line) > 0 else self.request_data['method']
        url = first_line[1] if len(first_line) > 1 else self.request_data['url']

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
        modified = self.request_data.copy()
        modified['method'] = method
        modified['url'] = url
        modified['headers'] = headers
        modified['body'] = body
        modified['raw_body'] = body.encode('utf-8')

        return modified

class ScanConfigDialog(QDialog):
    """Dialog for configuring scan from intercepted request"""

    # Available scan modules
    AVAILABLE_MODULES = [
        'sqli', 'xss', 'xxe', 'ssti', 'cmdi', 'lfi', 'rfi',
        'ssrf', 'redirect', 'csrf', 'idor', 'xpath', 'dirbrute',
        'file_upload', 'weak_credentials', 'dom_xss', 'formula_injection',
        'php_object_injection', 'git', 'env_secrets', 'oob_detection'
    ]

    def __init__(self, request, cookies, custom_headers, parent=None):
        super().__init__(parent)
        self.request = request
        self.cookies = cookies
        self.custom_headers = custom_headers
        self.module_checkboxes = {}
        self.init_ui()

    def init_ui(self):
        """Initialize scan config dialog UI"""
        self.setWindowTitle("Configure Scan from Request")
        self.resize(700, 600)

        # Set light theme
        self.setStyleSheet("""
            QDialog {
                background-color: #ffffff;
                color: #333333;
            }
            QLabel {
                color: #333333;
            }
            QCheckBox {
                color: #333333;
            }
            QGroupBox {
                background-color: #f8f8f8;
                border: 1px solid #e0e0e0;
                border-radius: 6px;
                margin-top: 10px;
                padding-top: 10px;
                font-weight: bold;
                color: #333333;
            }
            QGroupBox::title {
                subcontrol-origin: margin;
                left: 10px;
                padding: 0 5px;
                color: #4CAF50;
            }
            QPushButton {
                background-color: #4CAF50;
                color: white;
                border: none;
                border-radius: 4px;
                padding: 8px 16px;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: #45a049;
            }
        """)

        layout = QVBoxLayout()

        # Request info
        info_group = QGroupBox("Request Information")
        info_layout = QVBoxLayout()
        info_layout.addWidget(QLabel(f"<b>URL:</b> {self.request['url']}"))
        info_layout.addWidget(QLabel(f"<b>Method:</b> {self.request['method']}"))
        info_layout.addWidget(QLabel(f"<b>Cookies:</b> {len(self.cookies)} found"))
        info_layout.addWidget(QLabel(f"<b>Custom Headers:</b> {len(self.custom_headers)} found"))
        info_group.setLayout(info_layout)
        layout.addWidget(info_group)

        # Module selection
        module_group = QGroupBox("Select Scan Modules")
        module_layout = QVBoxLayout()

        # Select All / Deselect All buttons
        select_buttons = QHBoxLayout()
        select_all_btn = QPushButton("Select All")
        select_all_btn.clicked.connect(self.select_all_modules)
        select_buttons.addWidget(select_all_btn)

        deselect_all_btn = QPushButton("Deselect All")
        deselect_all_btn.clicked.connect(self.deselect_all_modules)
        select_buttons.addWidget(deselect_all_btn)

        select_buttons.addStretch()
        module_layout.addLayout(select_buttons)

        # Module checkboxes in grid
        grid = QGridLayout()
        row = 0
        col = 0

        for module in sorted(self.AVAILABLE_MODULES):
            checkbox = QCheckBox(module.upper().replace('_', ' '))
            checkbox.setChecked(True)  # Default: all selected
            self.module_checkboxes[module] = checkbox
            grid.addWidget(checkbox, row, col)
            col += 1
            if col >= 3:  # 3 columns
                col = 0
                row += 1

        module_layout.addLayout(grid)
        module_group.setLayout(module_layout)
        layout.addWidget(module_group)

        # Extracted data preview
        data_group = QGroupBox("Extracted Data (will be auto-configured)")
        data_layout = QVBoxLayout()

        if self.cookies:
            cookies_text = QLabel(f"<b>Cookies ({len(self.cookies)}):</b>")
            data_layout.addWidget(cookies_text)
            cookie_list = ", ".join([f"{k}={v[:20]}..." if len(v) > 20 else f"{k}={v}"
                                     for k, v in list(self.cookies.items())[:5]])
            if len(self.cookies) > 5:
                cookie_list += f" ... and {len(self.cookies) - 5} more"
            data_layout.addWidget(QLabel(cookie_list))

        if self.custom_headers:
            headers_text = QLabel(f"<b>Custom Headers ({len(self.custom_headers)}):</b>")
            data_layout.addWidget(headers_text)
            header_list = ", ".join(list(self.custom_headers.keys())[:5])
            if len(self.custom_headers) > 5:
                header_list += f" ... and {len(self.custom_headers) - 5} more"
            data_layout.addWidget(QLabel(header_list))

        data_group.setLayout(data_layout)
        layout.addWidget(data_group)

        # Buttons
        button_box = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        button_box.accepted.connect(self.accept)
        button_box.rejected.connect(self.reject)
        layout.addWidget(button_box)

        self.setLayout(layout)

    def select_all_modules(self):
        """Select all module checkboxes"""
        for checkbox in self.module_checkboxes.values():
            checkbox.setChecked(True)

    def deselect_all_modules(self):
        """Deselect all module checkboxes"""
        for checkbox in self.module_checkboxes.values():
            checkbox.setChecked(False)

    def get_config(self):
        """Get scan configuration"""
        selected_modules = [
            module for module, checkbox in self.module_checkboxes.items()
            if checkbox.isChecked()
        ]

        return {
            'modules': selected_modules,
            'cookies': self.cookies,
            'custom_headers': self.custom_headers,
            'url': self.request['url'],
            'method': self.request['method']
        }
