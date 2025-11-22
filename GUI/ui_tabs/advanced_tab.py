"""
Advanced Options Tab Builder
Handles authentication, HTTP configuration, and crawler settings.
"""

from PyQt5.QtWidgets import (
    QWidget, QVBoxLayout, QGridLayout,
    QGroupBox, QLabel, QLineEdit, QTextEdit,
    QCheckBox, QSpinBox, QComboBox
)


class AdvancedTabBuilder:
    """Builder class for creating the Advanced Options tab"""

    def __init__(self, gui, collapsible_box_class):
        """
        Initialize the builder with reference to main GUI

        Args:
            gui: Reference to DominatorGUI instance
            collapsible_box_class: The CollapsibleBox class (not used here but kept for consistency)
        """
        self.gui = gui
        self.CollapsibleBox = collapsible_box_class

    def build(self):
        """Create and return the advanced options tab widget"""
        widget = QWidget()
        layout = QVBoxLayout(widget)

        # ROTATION 9 Features
        rotation9_group = self._create_rotation9_group()
        layout.addWidget(rotation9_group)

        # Authentication
        auth_group = self._create_auth_group()
        layout.addWidget(auth_group)

        # HTTP Configuration
        http_group = self._create_http_group()
        layout.addWidget(http_group)

        # Crawler Settings
        crawler_group = self._create_crawler_group()
        layout.addWidget(crawler_group)

        layout.addStretch()
        return widget

    def _create_rotation9_group(self):
        """Create ROTATION 9 features group"""
        rotation9_group = QGroupBox("ROTATION 9 Features")
        rotation9_layout = QGridLayout()

        self.gui.recon_only_cb = QCheckBox("Recon Only Mode (Passive scanning only)")
        rotation9_layout.addWidget(self.gui.recon_only_cb, 0, 0, 1, 2)

        self.gui.rotate_agent_cb = QCheckBox("Rotate User-Agent (26 modern browsers)")
        rotation9_layout.addWidget(self.gui.rotate_agent_cb, 1, 0, 1, 2)

        self.gui.single_page_cb = QCheckBox("Single Page Mode (No crawling)")
        rotation9_layout.addWidget(self.gui.single_page_cb, 2, 0, 1, 2)

        rotation9_group.setLayout(rotation9_layout)
        return rotation9_group

    def _create_auth_group(self):
        """Create authentication group"""
        auth_group = QGroupBox("Authentication")
        auth_layout = QGridLayout()

        auth_layout.addWidget(QLabel("Auth Type:"), 0, 0)
        self.gui.auth_type_combo = QComboBox()
        self.gui.auth_type_combo.addItems([
            "None",
            "Basic Auth",
            "Digest Auth",
            "NTLM Auth",
            "Bearer Token",
            "API Key",
            "OAuth 2.0",
            "Custom Header"
        ])
        self.gui.auth_type_combo.currentTextChanged.connect(self.gui.on_auth_type_changed)
        auth_layout.addWidget(self.gui.auth_type_combo, 0, 1, 1, 3)

        # Username (for Basic, Digest, NTLM)
        self.gui.auth_username_label = QLabel("Username:")
        auth_layout.addWidget(self.gui.auth_username_label, 1, 0)
        self.gui.auth_username = QLineEdit()
        self.gui.auth_username.setPlaceholderText("Username for authentication")
        auth_layout.addWidget(self.gui.auth_username, 1, 1, 1, 3)

        # Password (for Basic, Digest, NTLM)
        self.gui.auth_password_label = QLabel("Password:")
        auth_layout.addWidget(self.gui.auth_password_label, 2, 0)
        self.gui.auth_password = QLineEdit()
        self.gui.auth_password.setPlaceholderText("Password for authentication")
        self.gui.auth_password.setEchoMode(QLineEdit.Password)
        auth_layout.addWidget(self.gui.auth_password, 2, 1, 1, 3)

        # Token/API Key (for Bearer, API Key, OAuth)
        self.gui.auth_token_label = QLabel("Token/Key:")
        auth_layout.addWidget(self.gui.auth_token_label, 3, 0)
        self.gui.auth_token = QLineEdit()
        self.gui.auth_token.setPlaceholderText("Bearer token, API key, or OAuth token")
        auth_layout.addWidget(self.gui.auth_token, 3, 1, 1, 3)

        # Custom header name (for API Key, Custom Header)
        self.gui.auth_header_name_label = QLabel("Header Name:")
        auth_layout.addWidget(self.gui.auth_header_name_label, 4, 0)
        self.gui.auth_header_name = QLineEdit()
        self.gui.auth_header_name.setPlaceholderText("e.g., X-API-Key, Authorization")
        auth_layout.addWidget(self.gui.auth_header_name, 4, 1, 1, 3)

        # Hide all fields initially
        self.gui.auth_username_label.hide()
        self.gui.auth_username.hide()
        self.gui.auth_password_label.hide()
        self.gui.auth_password.hide()
        self.gui.auth_token_label.hide()
        self.gui.auth_token.hide()
        self.gui.auth_header_name_label.hide()
        self.gui.auth_header_name.hide()

        auth_group.setLayout(auth_layout)
        return auth_group

    def _create_http_group(self):
        """Create HTTP configuration group"""
        http_group = QGroupBox("HTTP Configuration")
        http_layout = QGridLayout()

        http_layout.addWidget(QLabel("Custom Headers:"), 0, 0)
        self.gui.headers_input = QTextEdit()
        self.gui.headers_input.setPlaceholderText("Header1: Value1\nHeader2: Value2\nHeader3: Value3")
        self.gui.headers_input.setMinimumHeight(100)
        self.gui.headers_input.setMaximumHeight(150)
        # Stylesheet will be applied in apply_theme()
        http_layout.addWidget(self.gui.headers_input, 0, 1)

        http_layout.addWidget(QLabel("Cookies:"), 1, 0)
        self.gui.cookies_input = QLineEdit()
        self.gui.cookies_input.setPlaceholderText("session=abc123; token=xyz")
        # Stylesheet will be applied in apply_theme()
        http_layout.addWidget(self.gui.cookies_input, 1, 1)

        http_group.setLayout(http_layout)
        return http_group

    def _create_crawler_group(self):
        """Create crawler settings group"""
        crawler_group = QGroupBox("Crawler Settings")
        crawler_layout = QGridLayout()

        crawler_layout.addWidget(QLabel("Max Crawl Pages:"), 0, 0)
        self.gui.max_crawl_spin = QSpinBox()
        self.gui.max_crawl_spin.setRange(1, 1000)
        self.gui.max_crawl_spin.setValue(100)
        crawler_layout.addWidget(self.gui.max_crawl_spin, 0, 1)

        crawler_layout.addWidget(QLabel("Payload Limit:"), 0, 2)
        self.gui.payload_limit_spin = QSpinBox()
        self.gui.payload_limit_spin.setRange(1, 100)
        self.gui.payload_limit_spin.setValue(50)
        crawler_layout.addWidget(self.gui.payload_limit_spin, 0, 3)

        # Forbidden Paths
        crawler_layout.addWidget(QLabel("Forbidden Paths:"), 1, 0)
        self.gui.forbidden_paths_input = QLineEdit()
        self.gui.forbidden_paths_input.setPlaceholderText("/logout,/delete,/admin/critical (comma-separated)")
        self.gui.forbidden_paths_input.setToolTip("URLs/paths that should NOT be crawled or tested")
        crawler_layout.addWidget(self.gui.forbidden_paths_input, 1, 1, 1, 3)

        crawler_group.setLayout(crawler_layout)
        return crawler_group
