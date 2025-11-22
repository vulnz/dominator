"""
Scan Wizard Dialog
A step-by-step wizard to guide users through configuring a scan.
"""

from PyQt5.QtWidgets import (
    QDialog, QVBoxLayout, QHBoxLayout, QLabel, QPushButton,
    QStackedWidget, QWidget, QLineEdit, QTextEdit, QCheckBox,
    QSpinBox, QComboBox, QGroupBox, QGridLayout, QFrame,
    QRadioButton, QButtonGroup, QProgressBar, QMessageBox,
    QScrollArea
)
from PyQt5.QtGui import QFont, QPixmap
from PyQt5.QtCore import Qt, pyqtSignal


class ScanWizard(QDialog):
    """Step-by-step scan configuration wizard"""

    # Signal emitted when wizard is completed with configuration
    scan_configured = pyqtSignal(dict)

    def __init__(self, parent=None):
        super().__init__(parent)
        self.config = {}
        self.current_step = 0
        self.total_steps = 7
        self.init_ui()

    def init_ui(self):
        """Initialize the wizard UI"""
        self.setWindowTitle("Scan Wizard - Dominator")
        self.setMinimumSize(700, 500)
        self.setStyleSheet("""
            QDialog {
                background-color: white;
            }
            QLabel {
                color: #333333;
                font-size: 11px;
            }
            QGroupBox {
                background-color: #f8f8f8;
                border: 1px solid #e0e0e0;
                border-radius: 5px;
                margin-top: 10px;
                padding-top: 10px;
                font-weight: bold;
                font-size: 12px;
            }
            QGroupBox::title {
                subcontrol-origin: margin;
                left: 10px;
                padding: 0 5px;
            }
            QCheckBox {
                font-size: 11px;
            }
            QComboBox {
                font-size: 11px;
            }
            QSpinBox {
                font-size: 11px;
            }
            QPushButton {
                font-size: 11px;
            }
        """)

        layout = QVBoxLayout(self)
        layout.setSpacing(15)

        # Header with progress
        header = self._create_header()
        layout.addWidget(header)

        # Stacked widget for wizard steps
        self.stack = QStackedWidget()

        # Create all steps
        self.stack.addWidget(self._create_step_welcome())      # Step 0
        self.stack.addWidget(self._create_step_target())       # Step 1
        self.stack.addWidget(self._create_step_scan_type())    # Step 2
        self.stack.addWidget(self._create_step_modules())      # Step 3
        self.stack.addWidget(self._create_step_headers())      # Step 4
        self.stack.addWidget(self._create_step_payloads())     # Step 5
        self.stack.addWidget(self._create_step_settings())     # Step 6
        self.stack.addWidget(self._create_step_confirm())      # Step 7

        layout.addWidget(self.stack)

        # Navigation buttons
        nav = self._create_navigation()
        layout.addWidget(nav)

        self.update_navigation()

    def _create_header(self):
        """Create header with title and progress bar"""
        header = QFrame()
        header.setStyleSheet("""
            QFrame {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
                    stop:0 #4CAF50, stop:1 #2196F3);
                border-radius: 8px;
                padding: 15px;
            }
        """)

        layout = QVBoxLayout(header)

        # Title
        self.step_title = QLabel("Welcome to Scan Wizard")
        self.step_title.setFont(QFont("Arial", 16, QFont.Bold))
        self.step_title.setStyleSheet("color: white;")
        layout.addWidget(self.step_title)

        # Subtitle
        self.step_subtitle = QLabel("Let's configure your scan step by step")
        self.step_subtitle.setStyleSheet("color: rgba(255, 255, 255, 0.8);")
        layout.addWidget(self.step_subtitle)

        # Progress bar
        self.progress = QProgressBar()
        self.progress.setRange(0, self.total_steps)
        self.progress.setValue(0)
        self.progress.setTextVisible(False)
        self.progress.setStyleSheet("""
            QProgressBar {
                background-color: rgba(255, 255, 255, 0.3);
                border-radius: 5px;
                height: 10px;
            }
            QProgressBar::chunk {
                background-color: white;
                border-radius: 5px;
            }
        """)
        layout.addWidget(self.progress)

        return header

    def _create_step_welcome(self):
        """Step 0: Welcome screen"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setAlignment(Qt.AlignCenter)

        # Icon/Logo
        icon = QLabel("🎯")
        icon.setFont(QFont("Segoe UI Emoji", 64))
        icon.setAlignment(Qt.AlignCenter)
        layout.addWidget(icon)

        # Welcome text
        welcome = QLabel("Welcome to Dominator Scan Wizard")
        welcome.setFont(QFont("Arial", 18, QFont.Bold))
        welcome.setAlignment(Qt.AlignCenter)
        layout.addWidget(welcome)

        desc = QLabel(
            "This wizard will guide you through setting up a vulnerability scan.\n\n"
            "You'll configure:\n"
            "• Target URL or IP\n"
            "• Scan type and intensity\n"
            "• Security modules to run\n"
            "• Performance settings"
        )
        desc.setAlignment(Qt.AlignCenter)
        desc.setStyleSheet("color: #666666; font-size: 12px;")
        layout.addWidget(desc)

        return widget

    def _create_step_target(self):
        """Step 1: Target configuration"""
        widget = QWidget()
        layout = QVBoxLayout(widget)

        # Single target
        single_group = QGroupBox("Target URL or IP")
        single_layout = QVBoxLayout()

        self.target_input = QLineEdit()
        self.target_input.setPlaceholderText("https://example.com or 192.168.1.1")
        self.target_input.setStyleSheet("""
            QLineEdit {
                padding: 10px;
                border: 1px solid #cccccc;
                border-radius: 5px;
                font-size: 14px;
            }
            QLineEdit:focus {
                border: 1px solid #4CAF50;
            }
        """)
        single_layout.addWidget(self.target_input)

        # Target type hints
        hints = QLabel(
            "Supported formats: URLs (http/https), domains, IP addresses, CIDR ranges"
        )
        hints.setStyleSheet("color: #888888; font-size: 11px;")
        single_layout.addWidget(hints)

        single_group.setLayout(single_layout)
        layout.addWidget(single_group)

        # Multiple targets
        multi_group = QGroupBox("Or Multiple Targets (one per line)")
        multi_layout = QVBoxLayout()

        self.multi_target_input = QTextEdit()
        self.multi_target_input.setPlaceholderText(
            "https://example.com\n"
            "https://api.example.com\n"
            "192.168.1.0/24"
        )
        self.multi_target_input.setMaximumHeight(100)
        self.multi_target_input.setStyleSheet("""
            QTextEdit {
                padding: 8px;
                border: 1px solid #cccccc;
                border-radius: 5px;
            }
        """)
        multi_layout.addWidget(self.multi_target_input)

        multi_group.setLayout(multi_layout)
        layout.addWidget(multi_group)

        layout.addStretch()

        return widget

    def _create_step_scan_type(self):
        """Step 2: Scan type selection"""
        widget = QWidget()
        layout = QVBoxLayout(widget)

        info = QLabel("Select the type of scan you want to perform:")
        info.setStyleSheet("font-size: 13px; color: #666666; margin-bottom: 10px;")
        layout.addWidget(info)

        # Scan type options
        self.scan_type_group = QButtonGroup()

        # Quick Scan
        quick = self._create_scan_type_card(
            "⚡", "Quick Scan",
            "Fast scan with essential security checks.\nBest for initial assessment.",
            "quick"
        )
        layout.addWidget(quick)

        # Standard Scan
        standard = self._create_scan_type_card(
            "🔍", "Standard Scan",
            "Comprehensive scan with all common vulnerability checks.\nRecommended for most cases.",
            "standard"
        )
        layout.addWidget(standard)

        # Full Scan
        full = self._create_scan_type_card(
            "🔬", "Full Scan",
            "Deep scan with all modules and extensive testing.\nMay take longer but very thorough.",
            "full"
        )
        layout.addWidget(full)

        # Custom Scan
        custom = self._create_scan_type_card(
            "⚙️", "Custom Scan",
            "Configure your own module selection and settings.\nFor advanced users.",
            "custom"
        )
        layout.addWidget(custom)

        layout.addStretch()

        return widget

    def _create_scan_type_card(self, icon, title, description, value):
        """Create a scan type selection card"""
        card = QFrame()
        card.setStyleSheet("""
            QFrame {
                background-color: #f8f8f8;
                border: 2px solid #e0e0e0;
                border-radius: 8px;
                padding: 10px;
            }
            QFrame:hover {
                border-color: #4CAF50;
                background-color: #f0f8f0;
            }
        """)

        layout = QHBoxLayout(card)

        # Radio button
        radio = QRadioButton()
        radio.setProperty("scan_type", value)
        self.scan_type_group.addButton(radio)
        if value == "standard":
            radio.setChecked(True)
        layout.addWidget(radio)

        # Icon
        icon_label = QLabel(icon)
        icon_label.setFont(QFont("Segoe UI Emoji", 24))
        layout.addWidget(icon_label)

        # Text
        text_layout = QVBoxLayout()
        title_label = QLabel(title)
        title_label.setFont(QFont("Arial", 12, QFont.Bold))
        text_layout.addWidget(title_label)

        desc_label = QLabel(description)
        desc_label.setStyleSheet("color: #666666; font-size: 11px;")
        text_layout.addWidget(desc_label)

        layout.addLayout(text_layout)
        layout.addStretch()

        return card

    def _create_step_modules(self):
        """Step 3: Module selection - All 25 modules"""
        widget = QWidget()
        layout = QVBoxLayout(widget)

        info = QLabel("Select the security modules to run (25 available):")
        info.setStyleSheet("font-size: 13px; color: #666666; margin-bottom: 10px;")
        layout.addWidget(info)

        # Create scroll area for modules
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setStyleSheet("""
            QScrollArea {
                border: none;
                background-color: transparent;
            }
        """)

        scroll_content = QWidget()
        scroll_layout = QVBoxLayout(scroll_content)

        # Module categories - All 25 modules
        categories = [
            ("Injection (6 modules)", [
                ("sqli", "SQL Injection", True),
                ("xss", "Cross-Site Scripting", True),
                ("cmdi", "Command Injection", True),
                ("ssti", "Server-Side Template Injection", True),
                ("xpath", "XPath Injection", False),
                ("xxe", "XML External Entity", False),
            ]),
            ("File & Path (4 modules)", [
                ("lfi", "Local File Inclusion", True),
                ("rfi", "Remote File Inclusion", True),
                ("file_upload", "File Upload Vulnerabilities", False),
                ("dirbrute", "Directory Bruteforce", False),
            ]),
            ("Access Control (4 modules)", [
                ("csrf", "Cross-Site Request Forgery", True),
                ("idor", "Insecure Direct Object Reference", True),
                ("ssrf", "Server-Side Request Forgery", True),
                ("redirect", "Open Redirect", True),
            ]),
            ("Information Disclosure (11 modules)", [
                ("git", "Git Repository Exposure", True),
                ("env_secrets", "Environment Secrets", True),
                ("db_exposure", "Database Exposure", True),
                ("backup_files", "Backup File Detection", True),
                ("config_files", "Configuration Files", True),
                ("svn_hg", "SVN/Mercurial Exposure", False),
                ("debug_pages", "Debug Pages Detection", False),
                ("api_docs", "API Documentation Exposure", False),
                ("dom_xss", "DOM-based XSS", False),
                ("weak_credentials", "Weak Credentials", False),
                ("php_object_injection", "PHP Object Injection", False),
            ]),
        ]

        self.module_checkboxes = {}

        for category_name, modules in categories:
            group = QGroupBox(category_name)
            group.setStyleSheet("""
                QGroupBox {
                    font-size: 12px;
                    font-weight: bold;
                }
            """)
            grid = QGridLayout()

            for i, (key, name, default) in enumerate(modules):
                cb = QCheckBox(name)
                cb.setChecked(default)
                cb.setStyleSheet("font-size: 11px;")
                self.module_checkboxes[key] = cb
                grid.addWidget(cb, i // 2, i % 2)

            group.setLayout(grid)
            scroll_layout.addWidget(group)

        scroll.setWidget(scroll_content)
        layout.addWidget(scroll)

        # Select all / none
        btn_layout = QHBoxLayout()

        select_all = QPushButton("Select All (25)")
        select_all.clicked.connect(lambda: self._toggle_all_modules(True))
        btn_layout.addWidget(select_all)

        select_none = QPushButton("Select None")
        select_none.clicked.connect(lambda: self._toggle_all_modules(False))
        btn_layout.addWidget(select_none)

        btn_layout.addStretch()

        # Module count label
        self.module_count_label = QLabel("Selected: 0/25")
        self.module_count_label.setStyleSheet("font-size: 11px; color: #666666;")
        btn_layout.addWidget(self.module_count_label)

        layout.addLayout(btn_layout)

        # Connect checkboxes to update count
        for cb in self.module_checkboxes.values():
            cb.stateChanged.connect(self._update_module_count)

        # Initial count update
        self._update_module_count()

        return widget

    def _update_module_count(self):
        """Update the selected module count label"""
        count = sum(1 for cb in self.module_checkboxes.values() if cb.isChecked())
        if hasattr(self, 'module_count_label'):
            self.module_count_label.setText(f"Selected: {count}/25")

    def _toggle_all_modules(self, checked):
        """Toggle all module checkboxes"""
        for cb in self.module_checkboxes.values():
            cb.setChecked(checked)
        self._update_module_count()

    def _create_step_headers(self):
        """Step 4: Headers, Cookies, and Authentication settings"""
        widget = QWidget()
        layout = QVBoxLayout(widget)

        info = QLabel("Configure custom headers, cookies, and authentication:")
        info.setStyleSheet("font-size: 13px; color: #666666; margin-bottom: 10px;")
        layout.addWidget(info)

        # Custom Headers
        headers_group = QGroupBox("Custom Headers")
        headers_layout = QVBoxLayout()

        self.headers_input = QTextEdit()
        self.headers_input.setPlaceholderText(
            "Header-Name: Header-Value\n"
            "Authorization: Bearer <token>\n"
            "X-Custom-Header: value"
        )
        self.headers_input.setMaximumHeight(80)
        self.headers_input.setStyleSheet("""
            QTextEdit {
                padding: 8px;
                border: 1px solid #cccccc;
                border-radius: 5px;
                font-size: 11px;
                font-family: 'Consolas', monospace;
            }
        """)
        headers_layout.addWidget(self.headers_input)

        headers_hint = QLabel("One header per line in 'Name: Value' format")
        headers_hint.setStyleSheet("color: #888888; font-size: 11px;")
        headers_layout.addWidget(headers_hint)

        headers_group.setLayout(headers_layout)
        layout.addWidget(headers_group)

        # Cookies
        cookies_group = QGroupBox("Cookies")
        cookies_layout = QVBoxLayout()

        self.cookies_input = QTextEdit()
        self.cookies_input.setPlaceholderText(
            "session=abc123; token=xyz789; user_id=12345"
        )
        self.cookies_input.setMaximumHeight(60)
        self.cookies_input.setStyleSheet("""
            QTextEdit {
                padding: 8px;
                border: 1px solid #cccccc;
                border-radius: 5px;
                font-size: 11px;
                font-family: 'Consolas', monospace;
            }
        """)
        cookies_layout.addWidget(self.cookies_input)

        cookies_hint = QLabel("Enter cookies in 'name=value; name2=value2' format")
        cookies_hint.setStyleSheet("color: #888888; font-size: 11px;")
        cookies_layout.addWidget(cookies_hint)

        cookies_group.setLayout(cookies_layout)
        layout.addWidget(cookies_group)

        # Authentication
        auth_group = QGroupBox("Authentication")
        auth_layout = QGridLayout()

        # Auth type
        auth_layout.addWidget(QLabel("Type:"), 0, 0)
        self.auth_type_combo = QComboBox()
        self.auth_type_combo.addItems(["None", "Basic Auth", "Bearer Token", "API Key"])
        self.auth_type_combo.setStyleSheet("font-size: 11px;")
        auth_layout.addWidget(self.auth_type_combo, 0, 1)

        # Username
        auth_layout.addWidget(QLabel("Username:"), 1, 0)
        self.auth_username = QLineEdit()
        self.auth_username.setPlaceholderText("Username or API key name")
        self.auth_username.setStyleSheet("font-size: 11px; padding: 5px;")
        auth_layout.addWidget(self.auth_username, 1, 1)

        # Password/Token
        auth_layout.addWidget(QLabel("Password/Token:"), 2, 0)
        self.auth_password = QLineEdit()
        self.auth_password.setPlaceholderText("Password or token value")
        self.auth_password.setEchoMode(QLineEdit.Password)
        self.auth_password.setStyleSheet("font-size: 11px; padding: 5px;")
        auth_layout.addWidget(self.auth_password, 2, 1)

        auth_group.setLayout(auth_layout)
        layout.addWidget(auth_group)

        layout.addStretch()

        return widget

    def _create_step_payloads(self):
        """Step 5: Super Advanced - Custom Payloads"""
        widget = QWidget()
        layout = QVBoxLayout(widget)

        info = QLabel("Super Advanced: Customize payloads for each module:")
        info.setStyleSheet("font-size: 13px; color: #666666; margin-bottom: 10px;")
        layout.addWidget(info)

        # Warning about advanced usage
        warning = QLabel(
            "Warning: Only modify payloads if you understand their purpose. "
            "Invalid payloads may cause scan failures or incomplete results."
        )
        warning.setStyleSheet("""
            color: #FF9800;
            background-color: #FFF3E0;
            padding: 8px;
            border-radius: 5px;
            font-size: 11px;
        """)
        warning.setWordWrap(True)
        layout.addWidget(warning)

        # Module selector
        selector_layout = QHBoxLayout()
        selector_layout.addWidget(QLabel("Select Module:"))

        self.payload_module_combo = QComboBox()
        self.payload_module_combo.addItems([
            "sqli - SQL Injection",
            "xss - Cross-Site Scripting",
            "cmdi - Command Injection",
            "ssti - Template Injection",
            "lfi - Local File Inclusion",
            "rfi - Remote File Inclusion",
            "ssrf - Server-Side Request Forgery",
            "xxe - XML External Entity",
        ])
        self.payload_module_combo.setStyleSheet("font-size: 11px;")
        selector_layout.addWidget(self.payload_module_combo)
        selector_layout.addStretch()

        layout.addLayout(selector_layout)

        # Payload editor
        payload_group = QGroupBox("Custom Payloads (one per line)")
        payload_layout = QVBoxLayout()

        self.payloads_input = QTextEdit()
        self.payloads_input.setPlaceholderText(
            "Enter custom payloads here, one per line.\n"
            "Leave empty to use default payloads.\n\n"
            "Example SQL Injection payloads:\n"
            "' OR '1'='1\n"
            "' UNION SELECT NULL--\n"
            "1; DROP TABLE users--"
        )
        self.payloads_input.setStyleSheet("""
            QTextEdit {
                padding: 8px;
                border: 1px solid #cccccc;
                border-radius: 5px;
                font-size: 11px;
                font-family: 'Consolas', monospace;
            }
        """)
        payload_layout.addWidget(self.payloads_input)

        payload_group.setLayout(payload_layout)
        layout.addWidget(payload_group)

        # Options
        options_layout = QHBoxLayout()

        self.append_payloads_cb = QCheckBox("Append to default payloads")
        self.append_payloads_cb.setChecked(True)
        self.append_payloads_cb.setStyleSheet("font-size: 11px;")
        options_layout.addWidget(self.append_payloads_cb)

        self.encode_payloads_cb = QCheckBox("URL encode payloads")
        self.encode_payloads_cb.setStyleSheet("font-size: 11px;")
        options_layout.addWidget(self.encode_payloads_cb)

        options_layout.addStretch()
        layout.addLayout(options_layout)

        return widget

    def _create_step_settings(self):
        """Step 6: Performance settings"""
        widget = QWidget()
        layout = QVBoxLayout(widget)

        # Threading
        thread_group = QGroupBox("Performance")
        thread_layout = QGridLayout()

        thread_layout.addWidget(QLabel("Threads:"), 0, 0)
        self.threads_spin = QSpinBox()
        self.threads_spin.setRange(1, 50)
        self.threads_spin.setValue(10)
        thread_layout.addWidget(self.threads_spin, 0, 1)

        thread_layout.addWidget(QLabel("Timeout (seconds):"), 0, 2)
        self.timeout_spin = QSpinBox()
        self.timeout_spin.setRange(5, 300)
        self.timeout_spin.setValue(15)
        thread_layout.addWidget(self.timeout_spin, 0, 3)

        thread_layout.addWidget(QLabel("Max Scan Time (min):"), 1, 0)
        self.max_time_spin = QSpinBox()
        self.max_time_spin.setRange(1, 300)
        self.max_time_spin.setValue(45)
        thread_layout.addWidget(self.max_time_spin, 1, 1)

        thread_group.setLayout(thread_layout)
        layout.addWidget(thread_group)

        # Output format
        output_group = QGroupBox("Output")
        output_layout = QHBoxLayout()

        output_layout.addWidget(QLabel("Report Format:"))
        self.format_combo = QComboBox()
        self.format_combo.addItems(["HTML", "JSON", "TXT", "All Formats"])
        self.format_combo.setCurrentIndex(3)
        output_layout.addWidget(self.format_combo)

        output_layout.addStretch()

        output_group.setLayout(output_layout)
        layout.addWidget(output_group)

        # Options
        options_group = QGroupBox("Options")
        options_layout = QVBoxLayout()

        self.verbose_cb = QCheckBox("Verbose output")
        options_layout.addWidget(self.verbose_cb)

        self.follow_redirects_cb = QCheckBox("Follow redirects")
        self.follow_redirects_cb.setChecked(True)
        options_layout.addWidget(self.follow_redirects_cb)

        options_group.setLayout(options_layout)
        layout.addWidget(options_group)

        layout.addStretch()

        return widget

    def _create_step_confirm(self):
        """Step 5: Confirmation"""
        widget = QWidget()
        layout = QVBoxLayout(widget)

        # Summary
        self.summary_label = QTextEdit()
        self.summary_label.setReadOnly(True)
        self.summary_label.setStyleSheet("""
            QTextEdit {
                background-color: #f8f8f8;
                border: 1px solid #e0e0e0;
                border-radius: 5px;
                padding: 15px;
                font-family: 'Consolas', monospace;
            }
        """)
        layout.addWidget(self.summary_label)

        # Schedule option
        schedule_group = QGroupBox("Schedule Option")
        schedule_layout = QVBoxLayout()

        self.schedule_instead_cb = QCheckBox("Schedule this scan instead of running now")
        self.schedule_instead_cb.setStyleSheet("font-size: 12px;")
        self.schedule_instead_cb.stateChanged.connect(self._toggle_schedule_options)
        schedule_layout.addWidget(self.schedule_instead_cb)

        # Schedule time picker (hidden by default)
        self.schedule_options_widget = QWidget()
        schedule_options_layout = QHBoxLayout(self.schedule_options_widget)
        schedule_options_layout.setContentsMargins(20, 5, 0, 5)

        schedule_options_layout.addWidget(QLabel("Schedule for:"))

        from PyQt5.QtWidgets import QDateTimeEdit
        from PyQt5.QtCore import QDateTime
        self.schedule_datetime = QDateTimeEdit()
        self.schedule_datetime.setDateTime(QDateTime.currentDateTime().addSecs(3600))
        self.schedule_datetime.setCalendarPopup(True)
        self.schedule_datetime.setStyleSheet("padding: 5px;")
        schedule_options_layout.addWidget(self.schedule_datetime)

        schedule_options_layout.addStretch()
        self.schedule_options_widget.setVisible(False)
        schedule_layout.addWidget(self.schedule_options_widget)

        schedule_group.setLayout(schedule_layout)
        layout.addWidget(schedule_group)

        # Warning
        warning = QLabel(
            "Important: Only scan targets you have permission to test. "
            "Unauthorized scanning may be illegal."
        )
        warning.setStyleSheet("""
            color: #FF9800;
            background-color: #FFF3E0;
            padding: 10px;
            border-radius: 5px;
            font-size: 11px;
        """)
        warning.setWordWrap(True)
        layout.addWidget(warning)

        return widget

    def _toggle_schedule_options(self, state):
        """Toggle visibility of schedule options"""
        self.schedule_options_widget.setVisible(state == Qt.Checked)
        if state == Qt.Checked:
            self.next_btn.setText("Schedule Scan")
        else:
            self.next_btn.setText("Start Scan")

    def _create_navigation(self):
        """Create navigation buttons"""
        nav = QFrame()
        nav.setStyleSheet("""
            QFrame {
                background-color: #f0f0f0;
                border-radius: 5px;
                padding: 10px;
            }
        """)

        layout = QHBoxLayout(nav)

        # Cancel button
        self.cancel_btn = QPushButton("Cancel")
        self.cancel_btn.clicked.connect(self.reject)
        layout.addWidget(self.cancel_btn)

        layout.addStretch()

        # Back button
        self.back_btn = QPushButton("◀ Back")
        self.back_btn.clicked.connect(self.go_back)
        layout.addWidget(self.back_btn)

        # Next button
        self.next_btn = QPushButton("Next ▶")
        self.next_btn.setStyleSheet("""
            QPushButton {
                background-color: #4CAF50;
                color: white;
                padding: 8px 20px;
                border-radius: 5px;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: #45a049;
            }
        """)
        self.next_btn.clicked.connect(self.go_next)
        layout.addWidget(self.next_btn)

        return nav

    def update_navigation(self):
        """Update navigation button states"""
        self.back_btn.setEnabled(self.current_step > 0)

        if self.current_step == self.total_steps:
            self.next_btn.setText("🚀 Start Scan")
        else:
            self.next_btn.setText("Next ▶")

        # Update progress
        self.progress.setValue(self.current_step)

        # Update header
        titles = [
            ("Welcome to Scan Wizard", "Let's configure your scan step by step"),
            ("Step 1: Target", "Enter the target URL or IP address to scan"),
            ("Step 2: Scan Type", "Choose the type of scan to perform"),
            ("Step 3: Modules", "Select security modules to run (25 available)"),
            ("Step 4: Headers & Auth", "Configure headers, cookies, and authentication"),
            ("Step 5: Custom Payloads", "Super Advanced - Add or modify payloads"),
            ("Step 6: Settings", "Configure performance and output settings"),
            ("Step 7: Confirm", "Review your configuration and start scanning"),
        ]

        if self.current_step < len(titles):
            self.step_title.setText(titles[self.current_step][0])
            self.step_subtitle.setText(titles[self.current_step][1])

    def go_back(self):
        """Go to previous step"""
        if self.current_step > 0:
            self.current_step -= 1
            self.stack.setCurrentIndex(self.current_step)
            self.update_navigation()

    def go_next(self):
        """Go to next step or finish"""
        # Validate current step
        if not self.validate_current_step():
            return

        if self.current_step < self.total_steps:
            self.current_step += 1
            self.stack.setCurrentIndex(self.current_step)
            self.update_navigation()

            # Update summary on last step
            if self.current_step == self.total_steps:
                self.update_summary()
        else:
            # Finish wizard
            self.finish_wizard()

    def validate_current_step(self):
        """Validate the current step"""
        if self.current_step == 1:  # Target step
            target = self.target_input.text().strip()
            multi = self.multi_target_input.toPlainText().strip()

            if not target and not multi:
                QMessageBox.warning(
                    self, "Validation Error",
                    "Please enter at least one target URL or IP address."
                )
                return False

        return True

    def update_summary(self):
        """Update the summary text"""
        target = self.target_input.text().strip()
        if not target:
            target = self.multi_target_input.toPlainText().strip().split('\n')[0]

        # Get scan type
        scan_type = "standard"
        for btn in self.scan_type_group.buttons():
            if btn.isChecked():
                scan_type = btn.property("scan_type")
                break

        # Get selected modules
        selected_modules = [
            name for name, cb in self.module_checkboxes.items()
            if cb.isChecked()
        ]

        # Check for custom headers
        has_headers = bool(self.headers_input.toPlainText().strip())
        has_cookies = bool(self.cookies_input.toPlainText().strip())
        has_auth = self.auth_type_combo.currentText() != "None"
        has_payloads = bool(self.payloads_input.toPlainText().strip())

        summary = f"""SCAN CONFIGURATION SUMMARY
{'='*40}

Target: {target}

Scan Type: {scan_type.upper()}

Modules ({len(selected_modules)}/25):
   {', '.join(selected_modules) if selected_modules else 'None selected'}

Authentication:
   - Custom Headers: {'Yes' if has_headers else 'No'}
   - Cookies: {'Yes' if has_cookies else 'No'}
   - Auth Type: {self.auth_type_combo.currentText()}

Advanced:
   - Custom Payloads: {'Yes' if has_payloads else 'No (using defaults)'}

Performance:
   - Threads: {self.threads_spin.value()}
   - Timeout: {self.timeout_spin.value()}s
   - Max Time: {self.max_time_spin.value()} min

Output Format: {self.format_combo.currentText()}

{'='*40}
Ready to start scan!
"""
        self.summary_label.setPlainText(summary)

    def finish_wizard(self):
        """Finish the wizard and emit configuration"""
        # Collect all configuration
        target = self.target_input.text().strip()
        multi_targets = self.multi_target_input.toPlainText().strip()

        scan_type = "standard"
        for btn in self.scan_type_group.buttons():
            if btn.isChecked():
                scan_type = btn.property("scan_type")
                break

        selected_modules = [
            name for name, cb in self.module_checkboxes.items()
            if cb.isChecked()
        ]

        # Parse custom headers
        headers = {}
        headers_text = self.headers_input.toPlainText().strip()
        if headers_text:
            for line in headers_text.split('\n'):
                if ':' in line:
                    key, value = line.split(':', 1)
                    headers[key.strip()] = value.strip()

        # Parse custom payloads
        custom_payloads = {}
        payloads_text = self.payloads_input.toPlainText().strip()
        if payloads_text:
            module_key = self.payload_module_combo.currentText().split(' - ')[0]
            custom_payloads[module_key] = payloads_text.split('\n')

        self.config = {
            'target': target if target else multi_targets.split('\n')[0],
            'targets': multi_targets.split('\n') if multi_targets else [target],
            'scan_type': scan_type,
            'modules': selected_modules,
            'threads': self.threads_spin.value(),
            'timeout': self.timeout_spin.value(),
            'max_time': self.max_time_spin.value(),
            'format': self.format_combo.currentText().lower(),
            'verbose': self.verbose_cb.isChecked(),
            'follow_redirects': self.follow_redirects_cb.isChecked(),
            # New options
            'custom_headers': headers,
            'cookies': self.cookies_input.toPlainText().strip(),
            'auth_type': self.auth_type_combo.currentText(),
            'auth_username': self.auth_username.text().strip(),
            'auth_password': self.auth_password.text(),
            'custom_payloads': custom_payloads,
            'append_payloads': self.append_payloads_cb.isChecked(),
            'encode_payloads': self.encode_payloads_cb.isChecked(),
        }

        # Check if user wants to schedule instead of run now
        if hasattr(self, 'schedule_instead_cb') and self.schedule_instead_cb.isChecked():
            self._create_scheduled_task()
            return

        self.scan_configured.emit(self.config)
        self.accept()

    def _create_scheduled_task(self):
        """Create a scheduled task from wizard configuration"""
        import uuid
        import json
        import os
        from pathlib import Path
        from datetime import datetime

        # Get schedule time
        schedule_dt = self.schedule_datetime.dateTime().toPyDateTime()

        # Create task data
        task = {
            'id': str(uuid.uuid4()),
            'name': f"Wizard Scan - {self.config['target'][:30]}",
            'target': self.config['target'],
            'project_path': '',
            'modules': self.config['modules'],
            'settings': {
                'threads': self.config['threads'],
                'timeout': self.config['timeout'],
                'max_time': self.config['max_time'],
                'format': self.config['format']
            },
            'schedule_type': 'once',
            'next_run': schedule_dt.isoformat(),
            'enabled': True,
            'created': datetime.now().isoformat(),
            'email_notification': False,
            'email_address': ''
        }

        # Load existing schedules
        schedules_file = str(Path.home() / ".dominator" / "schedules.json")
        schedules = []
        if os.path.exists(schedules_file):
            try:
                with open(schedules_file, 'r') as f:
                    schedules = json.load(f)
            except:
                pass

        # Add new task
        schedules.append(task)

        # Save schedules
        config_dir = Path.home() / ".dominator"
        config_dir.mkdir(exist_ok=True)
        try:
            with open(schedules_file, 'w') as f:
                json.dump(schedules, f, indent=2)

            QMessageBox.information(
                self, "Scan Scheduled",
                f"Scan has been scheduled for:\n{schedule_dt.strftime('%Y-%m-%d %H:%M')}\n\n"
                f"Target: {self.config['target']}\n"
                f"Modules: {len(self.config['modules'])}\n\n"
                "You can manage scheduled scans from Tools > Scheduler."
            )
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to save schedule: {str(e)}")
            return

        self.accept()

    def get_config(self):
        """Get the wizard configuration"""
        return self.config
