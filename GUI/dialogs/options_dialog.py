#!/usr/bin/env python3
"""
Options Dialog for Dominator GUI
Provides a centralized settings interface with multiple tabs
"""

import os
import json
from pathlib import Path

from PyQt5.QtWidgets import (
    QDialog, QVBoxLayout, QHBoxLayout, QTabWidget, QWidget,
    QLabel, QSpinBox, QCheckBox, QComboBox, QLineEdit,
    QPushButton, QGroupBox, QGridLayout, QListWidget,
    QListWidgetItem, QMessageBox, QFrame
)
from PyQt5.QtCore import Qt
from PyQt5.QtGui import QFont

from GUI.utils.message_box import reset_all_warnings, get_suppressed_warnings


# Settings file path
SETTINGS_FILE = Path(__file__).parent.parent.parent / "settings.json"


def get_default_settings():
    """Return default settings dictionary"""
    return {
        # General settings
        "default_threads": 10,
        "default_timeout": 30,
        "default_max_scan_time": 3600,
        "auto_save_results": True,
        "theme": "Light",

        # Proxy settings
        "default_proxy_port": 8080,
        "auto_install_ca_cert": False,
        "ssl_intercept_default": True,
        "ignore_ssl_errors": False,

        # Scan settings
        "default_modules": ["xss", "sqli", "csrf"],
        "follow_redirects": True,
        "max_redirects": 5,
        "user_agent": "Dominator/1.5.0 (Security Scanner)",

        # Notification settings
        "show_warnings": True,
        "sound_on_completion": False,
        "desktop_notifications": True
    }


def get_settings():
    """Load settings from JSON file, return defaults if not found"""
    try:
        if SETTINGS_FILE.exists():
            with open(SETTINGS_FILE, 'r', encoding='utf-8') as f:
                loaded = json.load(f)
                # Merge with defaults to ensure all keys exist
                defaults = get_default_settings()
                defaults.update(loaded)
                return defaults
    except Exception as e:
        print(f"Error loading settings: {e}")

    return get_default_settings()


def save_settings(settings):
    """Save settings to JSON file"""
    try:
        with open(SETTINGS_FILE, 'w', encoding='utf-8') as f:
            json.dump(settings, indent=2, fp=f)
        return True
    except Exception as e:
        print(f"Error saving settings: {e}")
        return False


class OptionsDialog(QDialog):
    """Options dialog with tabs for different setting categories"""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Options")
        self.setMinimumSize(600, 500)
        self.setModal(True)

        # Load current settings
        self.settings = get_settings()

        # Load available modules
        self.available_modules = self._load_available_modules()

        self.init_ui()
        self.apply_styling()
        self.load_settings_to_ui()

    def _load_available_modules(self):
        """Load list of available modules from modules directory"""
        modules = []
        modules_dir = Path(__file__).parent.parent.parent / "modules"

        if modules_dir.exists():
            for module_path in modules_dir.iterdir():
                if module_path.is_dir() and not module_path.name.startswith('_'):
                    config_file = module_path / "config.json"
                    if config_file.exists():
                        try:
                            with open(config_file, 'r', encoding='utf-8') as f:
                                config = json.load(f)
                                modules.append({
                                    'id': module_path.name,
                                    'name': config.get('name', module_path.name)
                                })
                        except:
                            modules.append({
                                'id': module_path.name,
                                'name': module_path.name
                            })

        return sorted(modules, key=lambda x: x['name'])

    def init_ui(self):
        """Initialize the user interface"""
        layout = QVBoxLayout(self)
        layout.setSpacing(10)
        layout.setContentsMargins(15, 15, 15, 15)

        # Create tab widget
        self.tabs = QTabWidget()

        # Create tabs
        self.tabs.addTab(self.create_general_tab(), "General")
        self.tabs.addTab(self.create_proxy_tab(), "Proxy")
        self.tabs.addTab(self.create_scan_tab(), "Scan")
        self.tabs.addTab(self.create_notifications_tab(), "Notifications")

        layout.addWidget(self.tabs)

        # Buttons
        button_layout = QHBoxLayout()
        button_layout.addStretch()

        self.save_btn = QPushButton("Save")
        self.save_btn.setFixedWidth(100)
        self.save_btn.clicked.connect(self.save_and_close)

        self.cancel_btn = QPushButton("Cancel")
        self.cancel_btn.setFixedWidth(100)
        self.cancel_btn.clicked.connect(self.reject)

        button_layout.addWidget(self.save_btn)
        button_layout.addWidget(self.cancel_btn)

        layout.addLayout(button_layout)

    def create_general_tab(self):
        """Create General settings tab"""
        tab = QWidget()
        layout = QVBoxLayout(tab)
        layout.setSpacing(15)

        # Performance group
        perf_group = QGroupBox("Performance")
        perf_layout = QGridLayout(perf_group)
        perf_layout.setSpacing(10)

        # Default threads
        perf_layout.addWidget(QLabel("Default Threads:"), 0, 0)
        self.threads_spin = QSpinBox()
        self.threads_spin.setRange(1, 50)
        self.threads_spin.setToolTip("Number of concurrent scanning threads (1-50)")
        perf_layout.addWidget(self.threads_spin, 0, 1)

        # Default timeout
        perf_layout.addWidget(QLabel("Default Timeout (seconds):"), 1, 0)
        self.timeout_spin = QSpinBox()
        self.timeout_spin.setRange(5, 300)
        self.timeout_spin.setToolTip("Request timeout in seconds (5-300)")
        perf_layout.addWidget(self.timeout_spin, 1, 1)

        # Max scan time
        perf_layout.addWidget(QLabel("Max Scan Time (seconds):"), 2, 0)
        self.max_scan_time_spin = QSpinBox()
        self.max_scan_time_spin.setRange(60, 86400)
        self.max_scan_time_spin.setToolTip("Maximum total scan time in seconds")
        perf_layout.addWidget(self.max_scan_time_spin, 2, 1)

        layout.addWidget(perf_group)

        # General options group
        options_group = QGroupBox("Options")
        options_layout = QVBoxLayout(options_group)
        options_layout.setSpacing(10)

        # Auto-save results
        self.auto_save_cb = QCheckBox("Auto-save results after scan completion")
        self.auto_save_cb.setToolTip("Automatically save scan results when finished")
        options_layout.addWidget(self.auto_save_cb)

        # Theme selection
        theme_layout = QHBoxLayout()
        theme_layout.addWidget(QLabel("Theme:"))
        self.theme_combo = QComboBox()
        self.theme_combo.addItems(["Light", "Dark"])
        self.theme_combo.setToolTip("Application color theme")
        theme_layout.addWidget(self.theme_combo)
        theme_layout.addStretch()
        options_layout.addLayout(theme_layout)

        layout.addWidget(options_group)
        layout.addStretch()

        return tab

    def create_proxy_tab(self):
        """Create Proxy settings tab"""
        tab = QWidget()
        layout = QVBoxLayout(tab)
        layout.setSpacing(15)

        # Proxy configuration group
        proxy_group = QGroupBox("Proxy Configuration")
        proxy_layout = QGridLayout(proxy_group)
        proxy_layout.setSpacing(10)

        # Default proxy port
        proxy_layout.addWidget(QLabel("Default Proxy Port:"), 0, 0)
        self.proxy_port_spin = QSpinBox()
        self.proxy_port_spin.setRange(1024, 65535)
        self.proxy_port_spin.setToolTip("Default port for the proxy server (1024-65535)")
        proxy_layout.addWidget(self.proxy_port_spin, 0, 1)

        layout.addWidget(proxy_group)

        # SSL options group
        ssl_group = QGroupBox("SSL/TLS Options")
        ssl_layout = QVBoxLayout(ssl_group)
        ssl_layout.setSpacing(10)

        # Auto-install CA certificate
        self.auto_install_cert_cb = QCheckBox("Auto-install CA certificate")
        self.auto_install_cert_cb.setToolTip("Automatically install the proxy CA certificate in browsers")
        ssl_layout.addWidget(self.auto_install_cert_cb)

        # SSL intercept by default
        self.ssl_intercept_cb = QCheckBox("Enable SSL interception by default")
        self.ssl_intercept_cb.setToolTip("Intercept HTTPS traffic for analysis")
        ssl_layout.addWidget(self.ssl_intercept_cb)

        # Ignore SSL errors
        self.ignore_ssl_errors_cb = QCheckBox("Ignore SSL certificate errors")
        self.ignore_ssl_errors_cb.setToolTip("Skip SSL verification for targets with invalid certificates")
        ssl_layout.addWidget(self.ignore_ssl_errors_cb)

        layout.addWidget(ssl_group)
        layout.addStretch()

        return tab

    def create_scan_tab(self):
        """Create Scan settings tab"""
        tab = QWidget()
        layout = QVBoxLayout(tab)
        layout.setSpacing(15)

        # Default modules group
        modules_group = QGroupBox("Default Modules to Enable")
        modules_layout = QVBoxLayout(modules_group)

        self.modules_list = QListWidget()
        self.modules_list.setMaximumHeight(150)
        self.modules_list.setToolTip("Select modules to enable by default for new scans")

        # Populate modules list
        for module in self.available_modules:
            item = QListWidgetItem(f"{module['name']} ({module['id']})")
            item.setData(Qt.UserRole, module['id'])
            item.setFlags(item.flags() | Qt.ItemIsUserCheckable)
            item.setCheckState(Qt.Unchecked)
            self.modules_list.addItem(item)

        modules_layout.addWidget(self.modules_list)

        # Quick select buttons
        btn_layout = QHBoxLayout()
        select_all_btn = QPushButton("Select All")
        select_all_btn.clicked.connect(self.select_all_modules)
        select_none_btn = QPushButton("Select None")
        select_none_btn.clicked.connect(self.select_no_modules)
        btn_layout.addWidget(select_all_btn)
        btn_layout.addWidget(select_none_btn)
        btn_layout.addStretch()
        modules_layout.addLayout(btn_layout)

        layout.addWidget(modules_group)

        # HTTP options group
        http_group = QGroupBox("HTTP Options")
        http_layout = QGridLayout(http_group)
        http_layout.setSpacing(10)

        # Follow redirects
        self.follow_redirects_cb = QCheckBox("Follow redirects")
        self.follow_redirects_cb.setToolTip("Automatically follow HTTP redirects")
        http_layout.addWidget(self.follow_redirects_cb, 0, 0, 1, 2)

        # Max redirects
        http_layout.addWidget(QLabel("Max Redirects:"), 1, 0)
        self.max_redirects_spin = QSpinBox()
        self.max_redirects_spin.setRange(0, 20)
        self.max_redirects_spin.setToolTip("Maximum number of redirects to follow (0-20)")
        http_layout.addWidget(self.max_redirects_spin, 1, 1)

        # User-Agent
        http_layout.addWidget(QLabel("User-Agent:"), 2, 0)
        self.user_agent_input = QLineEdit()
        self.user_agent_input.setToolTip("Custom User-Agent string for requests")
        http_layout.addWidget(self.user_agent_input, 2, 1)

        layout.addWidget(http_group)
        layout.addStretch()

        return tab

    def create_notifications_tab(self):
        """Create Notifications settings tab"""
        tab = QWidget()
        layout = QVBoxLayout(tab)
        layout.setSpacing(15)

        # Notifications group
        notif_group = QGroupBox("Notification Settings")
        notif_layout = QVBoxLayout(notif_group)
        notif_layout.setSpacing(10)

        # Show warnings
        self.show_warnings_cb = QCheckBox("Show warning dialogs")
        self.show_warnings_cb.setToolTip("Display warning messages for potentially dangerous operations")
        notif_layout.addWidget(self.show_warnings_cb)

        # Sound on completion
        self.sound_completion_cb = QCheckBox("Play sound on scan completion")
        self.sound_completion_cb.setToolTip("Play an audio notification when a scan finishes")
        notif_layout.addWidget(self.sound_completion_cb)

        # Desktop notifications
        self.desktop_notif_cb = QCheckBox("Show desktop notifications")
        self.desktop_notif_cb.setToolTip("Show system notifications for important events")
        notif_layout.addWidget(self.desktop_notif_cb)

        layout.addWidget(notif_group)

        # "Do not show again" warnings group
        warnings_group = QGroupBox("Hidden Warnings")
        warnings_layout = QVBoxLayout(warnings_group)
        warnings_layout.setSpacing(10)

        # Info label
        info_label = QLabel(
            "Some dialogs have 'Do not show again' checkboxes.\n"
            "Click the button below to reset all hidden warnings."
        )
        info_label.setStyleSheet("color: #666; font-size: 11px;")
        warnings_layout.addWidget(info_label)

        # Show count of suppressed warnings
        suppressed = get_suppressed_warnings()
        self.suppressed_count_label = QLabel(f"Currently hidden warnings: {len(suppressed)}")
        self.suppressed_count_label.setStyleSheet("font-weight: bold;")
        warnings_layout.addWidget(self.suppressed_count_label)

        # Reset button
        reset_btn_layout = QHBoxLayout()
        self.reset_warnings_btn = QPushButton("Reset All Warnings")
        self.reset_warnings_btn.setToolTip("Show all warnings that were hidden with 'Do not show again'")
        self.reset_warnings_btn.clicked.connect(self.reset_all_warnings_clicked)
        self.reset_warnings_btn.setStyleSheet("""
            QPushButton {
                background-color: #FF9800;
                color: white;
                border: none;
                padding: 8px 16px;
                border-radius: 4px;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: #F57C00;
            }
        """)
        reset_btn_layout.addWidget(self.reset_warnings_btn)
        reset_btn_layout.addStretch()
        warnings_layout.addLayout(reset_btn_layout)

        layout.addWidget(warnings_group)
        layout.addStretch()

        return tab

    def reset_all_warnings_clicked(self):
        """Reset all 'do not show again' preferences"""
        suppressed = get_suppressed_warnings()
        if not suppressed:
            QMessageBox.information(
                self, "No Hidden Warnings",
                "There are no hidden warnings to reset."
            )
            return

        reply = QMessageBox.question(
            self, "Reset All Warnings",
            f"This will reset {len(suppressed)} hidden warning(s).\n\n"
            "All dialogs will be shown again.\n\n"
            "Do you want to continue?",
            QMessageBox.Yes | QMessageBox.No,
            QMessageBox.No
        )

        if reply == QMessageBox.Yes:
            reset_all_warnings()
            self.suppressed_count_label.setText("Currently hidden warnings: 0")
            QMessageBox.information(
                self, "Warnings Reset",
                "All warning dialogs have been reset and will be shown again."
            )

    def apply_styling(self):
        """Apply light theme styling to the dialog"""
        self.setStyleSheet("""
            QDialog {
                background-color: #ffffff;
                color: #333333;
            }
            QTabWidget::pane {
                border: 1px solid #e0e0e0;
                background-color: #ffffff;
            }
            QTabBar::tab {
                background-color: #f5f5f5;
                color: #333333;
                padding: 8px 16px;
                margin-right: 2px;
                border: 1px solid #e0e0e0;
                border-bottom: none;
                border-top-left-radius: 4px;
                border-top-right-radius: 4px;
            }
            QTabBar::tab:selected {
                background-color: #ffffff;
                border-bottom: 2px solid #4CAF50;
            }
            QTabBar::tab:hover {
                background-color: #e8e8e8;
            }
            QGroupBox {
                font-weight: bold;
                border: 1px solid #e0e0e0;
                border-radius: 6px;
                margin-top: 12px;
                padding-top: 10px;
                background-color: #fafafa;
            }
            QGroupBox::title {
                subcontrol-origin: margin;
                subcontrol-position: top left;
                padding: 0 8px;
                color: #333333;
            }
            QLabel {
                color: #333333;
            }
            QSpinBox, QComboBox, QLineEdit {
                padding: 6px;
                border: 1px solid #cccccc;
                border-radius: 4px;
                background-color: #ffffff;
                color: #333333;
                min-width: 150px;
            }
            QSpinBox:focus, QComboBox:focus, QLineEdit:focus {
                border: 1px solid #4CAF50;
            }
            QCheckBox {
                color: #333333;
                spacing: 8px;
            }
            QCheckBox::indicator {
                width: 18px;
                height: 18px;
                border: 1px solid #cccccc;
                border-radius: 3px;
                background-color: #ffffff;
            }
            QCheckBox::indicator:checked {
                background-color: #4CAF50;
                border-color: #4CAF50;
            }
            QCheckBox::indicator:hover {
                border-color: #4CAF50;
            }
            QListWidget {
                border: 1px solid #cccccc;
                border-radius: 4px;
                background-color: #ffffff;
                color: #333333;
            }
            QListWidget::item {
                padding: 4px;
            }
            QListWidget::item:selected {
                background-color: #e8f5e9;
                color: #333333;
            }
            QListWidget::item:hover {
                background-color: #f0f0f0;
            }
            QPushButton {
                background-color: #4CAF50;
                color: white;
                border: none;
                padding: 8px 16px;
                border-radius: 4px;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: #45a049;
            }
            QPushButton:pressed {
                background-color: #3d8b40;
            }
            QPushButton[text="Cancel"] {
                background-color: #f5f5f5;
                color: #333333;
                border: 1px solid #cccccc;
            }
            QPushButton[text="Cancel"]:hover {
                background-color: #e8e8e8;
            }
        """)

    def load_settings_to_ui(self):
        """Load settings from dict to UI controls"""
        # General tab
        self.threads_spin.setValue(self.settings.get("default_threads", 10))
        self.timeout_spin.setValue(self.settings.get("default_timeout", 30))
        self.max_scan_time_spin.setValue(self.settings.get("default_max_scan_time", 3600))
        self.auto_save_cb.setChecked(self.settings.get("auto_save_results", True))

        theme = self.settings.get("theme", "Light")
        index = self.theme_combo.findText(theme)
        if index >= 0:
            self.theme_combo.setCurrentIndex(index)

        # Proxy tab
        self.proxy_port_spin.setValue(self.settings.get("default_proxy_port", 8080))
        self.auto_install_cert_cb.setChecked(self.settings.get("auto_install_ca_cert", False))
        self.ssl_intercept_cb.setChecked(self.settings.get("ssl_intercept_default", True))
        self.ignore_ssl_errors_cb.setChecked(self.settings.get("ignore_ssl_errors", False))

        # Scan tab
        default_modules = self.settings.get("default_modules", [])
        for i in range(self.modules_list.count()):
            item = self.modules_list.item(i)
            module_id = item.data(Qt.UserRole)
            if module_id in default_modules:
                item.setCheckState(Qt.Checked)

        self.follow_redirects_cb.setChecked(self.settings.get("follow_redirects", True))
        self.max_redirects_spin.setValue(self.settings.get("max_redirects", 5))
        self.user_agent_input.setText(self.settings.get("user_agent", "Dominator/1.5.0 (Security Scanner)"))

        # Notifications tab
        self.show_warnings_cb.setChecked(self.settings.get("show_warnings", True))
        self.sound_completion_cb.setChecked(self.settings.get("sound_on_completion", False))
        self.desktop_notif_cb.setChecked(self.settings.get("desktop_notifications", True))

    def save_settings_from_ui(self):
        """Save UI control values to settings dict"""
        # General tab
        self.settings["default_threads"] = self.threads_spin.value()
        self.settings["default_timeout"] = self.timeout_spin.value()
        self.settings["default_max_scan_time"] = self.max_scan_time_spin.value()
        self.settings["auto_save_results"] = self.auto_save_cb.isChecked()
        self.settings["theme"] = self.theme_combo.currentText()

        # Proxy tab
        self.settings["default_proxy_port"] = self.proxy_port_spin.value()
        self.settings["auto_install_ca_cert"] = self.auto_install_cert_cb.isChecked()
        self.settings["ssl_intercept_default"] = self.ssl_intercept_cb.isChecked()
        self.settings["ignore_ssl_errors"] = self.ignore_ssl_errors_cb.isChecked()

        # Scan tab
        selected_modules = []
        for i in range(self.modules_list.count()):
            item = self.modules_list.item(i)
            if item.checkState() == Qt.Checked:
                selected_modules.append(item.data(Qt.UserRole))
        self.settings["default_modules"] = selected_modules

        self.settings["follow_redirects"] = self.follow_redirects_cb.isChecked()
        self.settings["max_redirects"] = self.max_redirects_spin.value()
        self.settings["user_agent"] = self.user_agent_input.text()

        # Notifications tab
        self.settings["show_warnings"] = self.show_warnings_cb.isChecked()
        self.settings["sound_on_completion"] = self.sound_completion_cb.isChecked()
        self.settings["desktop_notifications"] = self.desktop_notif_cb.isChecked()

    def select_all_modules(self):
        """Select all modules in the list"""
        for i in range(self.modules_list.count()):
            self.modules_list.item(i).setCheckState(Qt.Checked)

    def select_no_modules(self):
        """Deselect all modules in the list"""
        for i in range(self.modules_list.count()):
            self.modules_list.item(i).setCheckState(Qt.Unchecked)

    def save_and_close(self):
        """Save settings and close dialog"""
        self.save_settings_from_ui()

        if save_settings(self.settings):
            QMessageBox.information(self, "Settings Saved",
                "Settings have been saved successfully.\n"
                "Some changes may require restarting the application.")
            self.accept()
        else:
            QMessageBox.critical(self, "Error",
                "Failed to save settings. Please check file permissions.")
