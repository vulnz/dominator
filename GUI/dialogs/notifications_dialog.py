#!/usr/bin/env python3
"""
Notifications Configuration Dialog
Configure Telegram, Email, and Slack notifications
"""

from PyQt5.QtWidgets import (
    QDialog, QVBoxLayout, QHBoxLayout, QGridLayout,
    QGroupBox, QLabel, QLineEdit, QPushButton,
    QCheckBox, QSpinBox, QTabWidget, QWidget,
    QMessageBox
)
from PyQt5.QtCore import Qt
from GUI.utils.notification_manager import get_notification_manager


class NotificationsDialog(QDialog):
    """Dialog for configuring notification settings"""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Notification Settings")
        self.resize(500, 500)
        self.notification_manager = get_notification_manager()
        self.init_ui()
        self.load_settings()

    def init_ui(self):
        """Initialize the dialog UI"""
        self.setStyleSheet("""
            QDialog {
                background-color: #ffffff;
            }
            QGroupBox {
                background-color: #f8f8f8;
                border: 1px solid #e0e0e0;
                border-radius: 6px;
                margin-top: 10px;
                padding-top: 15px;
                font-weight: bold;
            }
            QGroupBox::title {
                subcontrol-origin: margin;
                left: 10px;
                padding: 0 5px;
                color: #4CAF50;
            }
            QLabel {
                color: #333333;
            }
            QLineEdit, QSpinBox {
                background-color: #ffffff;
                border: 1px solid #cccccc;
                border-radius: 4px;
                padding: 6px;
                color: #333333;
            }
            QLineEdit:focus, QSpinBox:focus {
                border: 2px solid #4CAF50;
            }
            QCheckBox {
                color: #333333;
            }
        """)

        layout = QVBoxLayout(self)

        # Tabs for different providers
        tabs = QTabWidget()
        tabs.setStyleSheet("""
            QTabWidget::pane {
                border: 1px solid #e0e0e0;
                background-color: #ffffff;
            }
            QTabBar::tab {
                background-color: #f5f5f5;
                color: #333333;
                padding: 8px 16px;
                border: 1px solid #e0e0e0;
                border-bottom: none;
                margin-right: 2px;
            }
            QTabBar::tab:selected {
                background-color: #ffffff;
                color: #4CAF50;
                font-weight: bold;
            }
        """)

        # Telegram Tab
        telegram_tab = self._create_telegram_tab()
        tabs.addTab(telegram_tab, "Telegram")

        # Email Tab
        email_tab = self._create_email_tab()
        tabs.addTab(email_tab, "Email")

        # Slack Tab
        slack_tab = self._create_slack_tab()
        tabs.addTab(slack_tab, "Slack")

        layout.addWidget(tabs)

        # Buttons
        btn_layout = QHBoxLayout()
        btn_layout.addStretch()

        save_btn = QPushButton("Save")
        save_btn.setStyleSheet("""
            QPushButton {
                background-color: #4CAF50;
                color: white;
                padding: 8px 20px;
                border-radius: 4px;
                border: none;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: #45a049;
            }
        """)
        save_btn.clicked.connect(self.save_settings)
        btn_layout.addWidget(save_btn)

        cancel_btn = QPushButton("Cancel")
        cancel_btn.setStyleSheet("""
            QPushButton {
                background-color: #f5f5f5;
                color: #333333;
                padding: 8px 20px;
                border-radius: 4px;
                border: 1px solid #cccccc;
            }
            QPushButton:hover {
                background-color: #e0e0e0;
            }
        """)
        cancel_btn.clicked.connect(self.reject)
        btn_layout.addWidget(cancel_btn)

        layout.addLayout(btn_layout)

    def _create_telegram_tab(self):
        """Create Telegram configuration tab"""
        widget = QWidget()
        layout = QVBoxLayout(widget)

        # Enable checkbox
        self.telegram_enabled = QCheckBox("Enable Telegram Notifications")
        layout.addWidget(self.telegram_enabled)

        # Configuration group
        config_group = QGroupBox("Telegram Bot Configuration")
        config_layout = QGridLayout()

        # Bot Token
        config_layout.addWidget(QLabel("Bot Token:"), 0, 0)
        self.telegram_token = QLineEdit()
        self.telegram_token.setPlaceholderText("123456:ABC-DEF1234ghIkl-zyx57W2v1u123ew11")
        self.telegram_token.setEchoMode(QLineEdit.Password)
        config_layout.addWidget(self.telegram_token, 0, 1)

        # Show/Hide token
        show_token_btn = QPushButton("Show")
        show_token_btn.setFixedWidth(60)
        show_token_btn.clicked.connect(lambda: self._toggle_visibility(self.telegram_token, show_token_btn))
        config_layout.addWidget(show_token_btn, 0, 2)

        # Chat ID
        config_layout.addWidget(QLabel("Chat ID:"), 1, 0)
        self.telegram_chat_id = QLineEdit()
        self.telegram_chat_id.setPlaceholderText("-1001234567890 or @channelname")
        config_layout.addWidget(self.telegram_chat_id, 1, 1, 1, 2)

        # Help text
        help_label = QLabel(
            "How to get Bot Token:\n"
            "1. Message @BotFather on Telegram\n"
            "2. Send /newbot and follow instructions\n"
            "3. Copy the token provided\n\n"
            "How to get Chat ID:\n"
            "1. Add your bot to a group/channel\n"
            "2. Send a message to the group\n"
            "3. Visit: api.telegram.org/bot<TOKEN>/getUpdates"
        )
        help_label.setStyleSheet("color: #888888; font-size: 11px;")
        help_label.setWordWrap(True)
        config_layout.addWidget(help_label, 2, 0, 1, 3)

        config_group.setLayout(config_layout)
        layout.addWidget(config_group)

        # Test button
        test_btn = QPushButton("Test Telegram")
        test_btn.setStyleSheet("""
            QPushButton {
                background-color: #2196F3;
                color: white;
                padding: 8px 16px;
                border-radius: 4px;
                border: none;
            }
            QPushButton:hover {
                background-color: #1976D2;
            }
        """)
        test_btn.clicked.connect(self.test_telegram)
        layout.addWidget(test_btn)

        layout.addStretch()
        return widget

    def _create_email_tab(self):
        """Create Email configuration tab"""
        widget = QWidget()
        layout = QVBoxLayout(widget)

        # Enable checkbox
        self.email_enabled = QCheckBox("Enable Email Notifications")
        layout.addWidget(self.email_enabled)

        # SMTP Configuration
        smtp_group = QGroupBox("SMTP Configuration")
        smtp_layout = QGridLayout()

        # Server
        smtp_layout.addWidget(QLabel("SMTP Server:"), 0, 0)
        self.email_smtp_server = QLineEdit()
        self.email_smtp_server.setPlaceholderText("smtp.gmail.com")
        smtp_layout.addWidget(self.email_smtp_server, 0, 1)

        # Port
        smtp_layout.addWidget(QLabel("Port:"), 0, 2)
        self.email_smtp_port = QSpinBox()
        self.email_smtp_port.setRange(1, 65535)
        self.email_smtp_port.setValue(587)
        smtp_layout.addWidget(self.email_smtp_port, 0, 3)

        # Username
        smtp_layout.addWidget(QLabel("Username:"), 1, 0)
        self.email_username = QLineEdit()
        self.email_username.setPlaceholderText("your-email@gmail.com")
        smtp_layout.addWidget(self.email_username, 1, 1, 1, 3)

        # Password
        smtp_layout.addWidget(QLabel("Password:"), 2, 0)
        self.email_password = QLineEdit()
        self.email_password.setPlaceholderText("App password (not regular password)")
        self.email_password.setEchoMode(QLineEdit.Password)
        smtp_layout.addWidget(self.email_password, 2, 1, 1, 2)

        show_pass_btn = QPushButton("Show")
        show_pass_btn.setFixedWidth(60)
        show_pass_btn.clicked.connect(lambda: self._toggle_visibility(self.email_password, show_pass_btn))
        smtp_layout.addWidget(show_pass_btn, 2, 3)

        # To Email
        smtp_layout.addWidget(QLabel("Send To:"), 3, 0)
        self.email_to = QLineEdit()
        self.email_to.setPlaceholderText("recipient@example.com")
        smtp_layout.addWidget(self.email_to, 3, 1, 1, 3)

        smtp_group.setLayout(smtp_layout)
        layout.addWidget(smtp_group)

        # Test button
        test_btn = QPushButton("Test Email")
        test_btn.setStyleSheet("""
            QPushButton {
                background-color: #2196F3;
                color: white;
                padding: 8px 16px;
                border-radius: 4px;
                border: none;
            }
            QPushButton:hover {
                background-color: #1976D2;
            }
        """)
        test_btn.clicked.connect(self.test_email)
        layout.addWidget(test_btn)

        layout.addStretch()
        return widget

    def _create_slack_tab(self):
        """Create Slack configuration tab"""
        widget = QWidget()
        layout = QVBoxLayout(widget)

        # Enable checkbox
        self.slack_enabled = QCheckBox("Enable Slack Notifications")
        layout.addWidget(self.slack_enabled)

        # Configuration group
        config_group = QGroupBox("Slack Webhook Configuration")
        config_layout = QGridLayout()

        # Webhook URL
        config_layout.addWidget(QLabel("Webhook URL:"), 0, 0)
        self.slack_webhook = QLineEdit()
        self.slack_webhook.setPlaceholderText("https://hooks.slack.com/services/T00/B00/XXXX")
        config_layout.addWidget(self.slack_webhook, 0, 1)

        # Help text
        help_label = QLabel(
            "How to get Webhook URL:\n"
            "1. Go to api.slack.com/apps\n"
            "2. Create New App > From scratch\n"
            "3. Add 'Incoming Webhooks' feature\n"
            "4. Activate and add to channel\n"
            "5. Copy the Webhook URL"
        )
        help_label.setStyleSheet("color: #888888; font-size: 11px;")
        help_label.setWordWrap(True)
        config_layout.addWidget(help_label, 1, 0, 1, 2)

        config_group.setLayout(config_layout)
        layout.addWidget(config_group)

        # Test button
        test_btn = QPushButton("Test Slack")
        test_btn.setStyleSheet("""
            QPushButton {
                background-color: #2196F3;
                color: white;
                padding: 8px 16px;
                border-radius: 4px;
                border: none;
            }
            QPushButton:hover {
                background-color: #1976D2;
            }
        """)
        test_btn.clicked.connect(self.test_slack)
        layout.addWidget(test_btn)

        layout.addStretch()
        return widget

    def _toggle_visibility(self, line_edit, button):
        """Toggle password field visibility"""
        if line_edit.echoMode() == QLineEdit.Password:
            line_edit.setEchoMode(QLineEdit.Normal)
            button.setText("Hide")
        else:
            line_edit.setEchoMode(QLineEdit.Password)
            button.setText("Show")

    def load_settings(self):
        """Load current settings into UI"""
        settings = self.notification_manager.settings

        # Telegram
        self.telegram_enabled.setChecked(settings.get('telegram_enabled', False))
        self.telegram_token.setText(settings.get('telegram_bot_token', ''))
        self.telegram_chat_id.setText(settings.get('telegram_chat_id', ''))

        # Email
        self.email_enabled.setChecked(settings.get('email_enabled', False))
        self.email_smtp_server.setText(settings.get('email_smtp_server', ''))
        self.email_smtp_port.setValue(settings.get('email_smtp_port', 587))
        self.email_username.setText(settings.get('email_username', ''))
        self.email_password.setText(settings.get('email_password', ''))
        self.email_to.setText(settings.get('email_to', ''))

        # Slack
        self.slack_enabled.setChecked(settings.get('slack_enabled', False))
        self.slack_webhook.setText(settings.get('slack_webhook_url', ''))

    def save_settings(self):
        """Save settings and close dialog"""
        settings = {
            # Telegram
            'telegram_enabled': self.telegram_enabled.isChecked(),
            'telegram_bot_token': self.telegram_token.text(),
            'telegram_chat_id': self.telegram_chat_id.text(),

            # Email
            'email_enabled': self.email_enabled.isChecked(),
            'email_smtp_server': self.email_smtp_server.text(),
            'email_smtp_port': self.email_smtp_port.value(),
            'email_username': self.email_username.text(),
            'email_password': self.email_password.text(),
            'email_to': self.email_to.text(),

            # Slack
            'slack_enabled': self.slack_enabled.isChecked(),
            'slack_webhook_url': self.slack_webhook.text()
        }

        if self.notification_manager.save_settings(settings):
            QMessageBox.information(self, "Success", "Notification settings saved!")
            self.accept()
        else:
            QMessageBox.warning(self, "Error", "Failed to save settings")

    def test_telegram(self):
        """Test Telegram configuration"""
        # Temporarily save settings for testing
        self.notification_manager.settings['telegram_bot_token'] = self.telegram_token.text()
        self.notification_manager.settings['telegram_chat_id'] = self.telegram_chat_id.text()

        success, message = self.notification_manager.test_telegram()

        if success:
            QMessageBox.information(self, "Success", "Test message sent successfully!")
        else:
            QMessageBox.warning(self, "Error", f"Failed to send test message:\n{message}")

    def test_email(self):
        """Test Email configuration"""
        # Temporarily save settings for testing
        self.notification_manager.settings['email_smtp_server'] = self.email_smtp_server.text()
        self.notification_manager.settings['email_smtp_port'] = self.email_smtp_port.value()
        self.notification_manager.settings['email_username'] = self.email_username.text()
        self.notification_manager.settings['email_password'] = self.email_password.text()
        self.notification_manager.settings['email_to'] = self.email_to.text()

        success, message = self.notification_manager.test_email()

        if success:
            QMessageBox.information(self, "Success", "Test email sent successfully!")
        else:
            QMessageBox.warning(self, "Error", f"Failed to send test email:\n{message}")

    def test_slack(self):
        """Test Slack configuration"""
        # Temporarily save settings for testing
        self.notification_manager.settings['slack_webhook_url'] = self.slack_webhook.text()

        success, message = self.notification_manager.test_slack()

        if success:
            QMessageBox.information(self, "Success", "Test message sent successfully!")
        else:
            QMessageBox.warning(self, "Error", f"Failed to send test message:\n{message}")
