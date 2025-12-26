"""
Plugins Tab Builder
Handles the plugin management UI with list, details, and configuration.

Updated to use ThemeManager for consistent styling across themes.
"""

from PyQt5.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QGroupBox,
    QLabel, QLineEdit, QTextEdit, QPushButton,
    QTableWidget, QTableWidgetItem, QSplitter, QHeaderView,
    QCheckBox, QMessageBox, QFileDialog, QComboBox
)
from PyQt5.QtCore import Qt
from PyQt5.QtGui import QColor, QDesktopServices
from PyQt5.QtCore import QUrl
from pathlib import Path
import json
import zipfile
import shutil


class PluginsTabBuilder:
    """Builder class for creating the Plugins tab"""

    def __init__(self, gui, collapsible_box_class):
        """
        Initialize the builder with reference to main GUI

        Args:
            gui: Reference to DominatorGUI instance
            collapsible_box_class: The CollapsibleBox class (not used here but kept for consistency)
        """
        self.gui = gui
        self.CollapsibleBox = collapsible_box_class

        # Default plugins data - Third-party tools integration
        self.default_plugins = [
            {
                'name': 'WPScan',
                'description': 'WordPress vulnerability scanner. Automatically runs when WordPress is detected. Scans for vulnerable plugins, themes, core vulnerabilities, user enumeration, and config backups.',
                'version': '1.0.0',
                'author': 'Dominator Team',
                'enabled': True,
                'category': 'CMS Scanner',
                'executable': 'wpscan',
                'auto_detect': 'WordPress'
            },
            {
                'name': 'Nuclei',
                'description': 'Fast template-based vulnerability scanner. Runs YAML-based templates for CVEs, misconfigurations, exposures, and takeovers. Supports 8000+ community templates.',
                'version': '1.0.0',
                'author': 'Dominator Team',
                'enabled': True,
                'category': 'Vulnerability Scanner',
                'executable': 'nuclei',
                'auto_detect': 'All Web Targets'
            },
            {
                'name': 'Nmap Scanner',
                'description': 'Network exploration and security auditing tool. Performs port scanning, service detection, OS fingerprinting, and vulnerability scanning using NSE scripts.',
                'version': '1.0.0',
                'author': 'Dominator Team',
                'enabled': True,
                'category': 'Network',
                'executable': 'nmap',
                'auto_detect': 'IP/Host Targets'
            },
            {
                'name': 'SQLMap',
                'description': 'Automatic SQL injection and database takeover tool. Runs when SQL injection is suspected based on parameter analysis.',
                'version': '1.0.0',
                'author': 'Dominator Team',
                'enabled': False,
                'category': 'Exploitation',
                'executable': 'sqlmap',
                'auto_detect': 'SQL Injection Indicators'
            },
            {
                'name': 'Nikto',
                'description': 'Web server scanner that performs comprehensive tests against web servers for multiple items, including dangerous files/CGIs and outdated software.',
                'version': '1.0.0',
                'author': 'Dominator Team',
                'enabled': False,
                'category': 'Web Scanner',
                'executable': 'nikto',
                'auto_detect': 'All Web Targets'
            },
            {
                'name': 'Dirsearch',
                'description': 'Web path discovery tool. Brute-forces directories and files in web servers with extensive wordlists.',
                'version': '1.0.0',
                'author': 'Dominator Team',
                'enabled': False,
                'category': 'Discovery',
                'executable': 'dirsearch',
                'auto_detect': 'All Web Targets'
            }
        ]

    def _get_theme(self):
        """Get current theme from GUI or use default dark theme colors"""
        if hasattr(self.gui, 'current_theme') and self.gui.current_theme:
            return self.gui.current_theme
        # Default dark theme fallback
        return {
            "bg_main": "#1e1e1e",
            "bg_alt": "#252526",
            "bg_input": "#2d2d30",
            "bg_button": "#3c3c3c",
            "bg_button_hover": "#4a4a4a",
            "accent": "#0078d4",
            "accent_hover": "#1a8ae6",
            "text_primary": "#ffffff",
            "text_secondary": "#a0a0a0",
            "text_disabled": "#606060",
            "text_on_accent": "#ffffff",
            "border": "#3c3c3c",
            "success": "#4CAF50",
            "warning": "#FF9800",
            "error": "#f44336"
        }

    def build(self):
        """Create and return the plugins tab widget"""
        widget = QWidget()
        # Don't set local stylesheet - let theme manager handle it
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(5, 5, 5, 5)

        # Main horizontal splitter: Plugin list on left, details on right
        main_splitter = QSplitter(Qt.Horizontal)

        # Left Panel: Plugin List
        left_panel = self._create_left_panel()
        main_splitter.addWidget(left_panel)

        # Right Panel: Plugin Details/Configuration
        right_panel = self._create_right_panel()
        main_splitter.addWidget(right_panel)

        # Set splitter sizes: 400px for plugin list, rest for details
        main_splitter.setSizes([400, 600])
        layout.addWidget(main_splitter)

        # Load plugins list
        self._load_plugins_list()

        return widget

    def _create_left_panel(self):
        """Create left panel with plugin list and management buttons"""
        t = self._get_theme()
        left_panel = QWidget()
        left_layout = QVBoxLayout(left_panel)
        left_layout.setContentsMargins(0, 0, 0, 0)

        # Search/Filter bar
        search_layout = QHBoxLayout()
        search_label = QLabel("Search:")
        search_label.setStyleSheet(f"color: {t['accent']}; font-weight: bold;")
        search_layout.addWidget(search_label)

        self.gui.plugin_search = QLineEdit()
        self.gui.plugin_search.setPlaceholderText("Filter plugins...")
        # Let theme manager handle styling
        self.gui.plugin_search.textChanged.connect(self._filter_plugins)
        search_layout.addWidget(self.gui.plugin_search)

        left_layout.addLayout(search_layout)

        # Plugin count label
        self.gui.plugin_count_label = QLabel("Plugins: 0")
        self.gui.plugin_count_label.setStyleSheet(f"color: {t['text_secondary']}; font-size: 10px; padding: 5px;")
        left_layout.addWidget(self.gui.plugin_count_label)

        # Plugin table - let theme manager handle base styling
        self.gui.plugin_table = QTableWidget()
        self.gui.plugin_table.setColumnCount(4)
        self.gui.plugin_table.setHorizontalHeaderLabels(['Name', 'Version', 'Category', 'Status'])
        self.gui.plugin_table.horizontalHeader().setStretchLastSection(True)
        self.gui.plugin_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.Stretch)
        self.gui.plugin_table.setSelectionBehavior(QTableWidget.SelectRows)
        self.gui.plugin_table.setSelectionMode(QTableWidget.SingleSelection)
        self.gui.plugin_table.verticalHeader().setVisible(False)
        # Prevent text overflow - use ellipsis for long text
        self.gui.plugin_table.setWordWrap(False)
        self.gui.plugin_table.setTextElideMode(Qt.ElideRight)
        self.gui.plugin_table.itemSelectionChanged.connect(self._on_plugin_selected)
        left_layout.addWidget(self.gui.plugin_table)

        # Management buttons
        mgmt_group = QGroupBox("Plugin Management")
        mgmt_layout = QVBoxLayout()

        # First row of buttons
        btn_row1 = QHBoxLayout()

        install_btn = QPushButton("Install New Plugin")
        install_btn.setStyleSheet(f"""
            QPushButton {{
                background-color: {t['success']};
                color: {t['text_on_accent']};
                padding: 8px 16px;
                border-radius: 4px;
                font-weight: bold;
                border: none;
            }}
            QPushButton:hover {{
                background-color: #43a047;
            }}
        """)
        install_btn.clicked.connect(self._install_plugin)
        btn_row1.addWidget(install_btn)

        update_btn = QPushButton("Update Plugins")
        update_btn.setStyleSheet(f"""
            QPushButton {{
                background-color: {t['accent']};
                color: {t['text_on_accent']};
                padding: 8px 16px;
                border-radius: 4px;
                font-weight: bold;
                border: none;
            }}
            QPushButton:hover {{
                background-color: {t.get('accent_hover', t['accent'])};
            }}
        """)
        update_btn.clicked.connect(self._update_plugins)
        btn_row1.addWidget(update_btn)

        mgmt_layout.addLayout(btn_row1)

        # Second row - marketplace link
        btn_row2 = QHBoxLayout()

        marketplace_btn = QPushButton("Plugin Marketplace")
        marketplace_btn.setStyleSheet(f"""
            QPushButton {{
                background-color: {t['warning']};
                color: {t['text_on_accent']};
                padding: 8px 16px;
                border-radius: 4px;
                font-weight: bold;
                border: none;
            }}
            QPushButton:hover {{
                background-color: #F57C00;
            }}
        """)
        marketplace_btn.clicked.connect(self._open_marketplace)
        btn_row2.addWidget(marketplace_btn)

        refresh_btn = QPushButton("Refresh")
        refresh_btn.setStyleSheet(f"""
            QPushButton {{
                background-color: {t['bg_button']};
                color: {t['accent']};
                border: 1px solid {t['border']};
                border-radius: 4px;
                padding: 8px 16px;
                font-weight: bold;
            }}
            QPushButton:hover {{
                background-color: {t['bg_button_hover']};
                border-color: {t['accent']};
            }}
        """)
        refresh_btn.clicked.connect(self._load_plugins_list)
        btn_row2.addWidget(refresh_btn)

        mgmt_layout.addLayout(btn_row2)
        mgmt_group.setLayout(mgmt_layout)
        left_layout.addWidget(mgmt_group)

        return left_panel

    def _create_right_panel(self):
        """Create right panel with plugin details and configuration"""
        t = self._get_theme()
        right_panel = QWidget()
        right_layout = QVBoxLayout(right_panel)
        right_layout.setContentsMargins(0, 0, 0, 0)

        # Plugin Details Group
        details_group = QGroupBox("Plugin Details")
        details_layout = QVBoxLayout()

        # Plugin name
        name_layout = QHBoxLayout()
        name_label = QLabel("Name:")
        name_label.setStyleSheet(f"font-weight: bold; color: {t['accent']};")
        name_label.setFixedWidth(100)
        name_layout.addWidget(name_label)

        self.gui.plugin_name_label = QLabel("Select a plugin")
        self.gui.plugin_name_label.setStyleSheet(f"font-size: 14px; font-weight: bold; color: {t['text_primary']};")
        name_layout.addWidget(self.gui.plugin_name_label)
        name_layout.addStretch()
        details_layout.addLayout(name_layout)

        # Plugin version
        version_layout = QHBoxLayout()
        version_label = QLabel("Version:")
        version_label.setStyleSheet(f"font-weight: bold; color: {t['accent']};")
        version_label.setFixedWidth(100)
        version_layout.addWidget(version_label)

        self.gui.plugin_version_label = QLabel("-")
        version_layout.addWidget(self.gui.plugin_version_label)
        version_layout.addStretch()
        details_layout.addLayout(version_layout)

        # Plugin author
        author_layout = QHBoxLayout()
        author_label = QLabel("Author:")
        author_label.setStyleSheet(f"font-weight: bold; color: {t['accent']};")
        author_label.setFixedWidth(100)
        author_layout.addWidget(author_label)

        self.gui.plugin_author_label = QLabel("-")
        author_layout.addWidget(self.gui.plugin_author_label)
        author_layout.addStretch()
        details_layout.addLayout(author_layout)

        # Plugin category
        category_layout = QHBoxLayout()
        category_label = QLabel("Category:")
        category_label.setStyleSheet(f"font-weight: bold; color: {t['accent']};")
        category_label.setFixedWidth(100)
        category_layout.addWidget(category_label)

        self.gui.plugin_category_label = QLabel("-")
        category_layout.addWidget(self.gui.plugin_category_label)
        category_layout.addStretch()
        details_layout.addLayout(category_layout)

        # Plugin description
        desc_label = QLabel("Description:")
        desc_label.setStyleSheet(f"font-weight: bold; color: {t['accent']}; margin-top: 10px;")
        details_layout.addWidget(desc_label)

        self.gui.plugin_description_text = QTextEdit()
        self.gui.plugin_description_text.setReadOnly(True)
        self.gui.plugin_description_text.setMaximumHeight(100)
        # Let theme manager handle text edit styling
        details_layout.addWidget(self.gui.plugin_description_text)

        details_group.setLayout(details_layout)
        right_layout.addWidget(details_group)

        # Plugin Actions Group
        actions_group = QGroupBox("Plugin Actions")
        actions_layout = QVBoxLayout()

        # Enable/Disable toggle - let theme manager handle base checkbox styling
        enable_layout = QHBoxLayout()
        self.gui.plugin_enable_checkbox = QCheckBox("Enable Plugin")
        self.gui.plugin_enable_checkbox.setStyleSheet(f"""
            QCheckBox {{
                font-weight: bold;
                color: {t['text_primary']};
            }}
        """)
        self.gui.plugin_enable_checkbox.stateChanged.connect(self._toggle_plugin_enabled)
        enable_layout.addWidget(self.gui.plugin_enable_checkbox)
        enable_layout.addStretch()
        actions_layout.addLayout(enable_layout)

        # Action buttons
        action_btn_layout = QHBoxLayout()

        configure_btn = QPushButton("Configure")
        configure_btn.setStyleSheet(f"""
            QPushButton {{
                background-color: #9C27B0;
                color: white;
                padding: 10px 20px;
                border-radius: 4px;
                font-weight: bold;
                border: none;
            }}
            QPushButton:hover {{
                background-color: #7B1FA2;
            }}
        """)
        configure_btn.clicked.connect(self._configure_plugin)
        action_btn_layout.addWidget(configure_btn)

        run_btn = QPushButton("Run")
        run_btn.setStyleSheet(f"""
            QPushButton {{
                background-color: {t['success']};
                color: {t['text_on_accent']};
                padding: 10px 20px;
                border-radius: 4px;
                font-weight: bold;
                border: none;
            }}
            QPushButton:hover {{
                background-color: #43a047;
            }}
        """)
        run_btn.clicked.connect(self._run_plugin)
        action_btn_layout.addWidget(run_btn)

        actions_layout.addLayout(action_btn_layout)
        actions_group.setLayout(actions_layout)
        right_layout.addWidget(actions_group)

        # Plugin Configuration Group
        config_group = QGroupBox("Plugin Configuration")
        config_layout = QVBoxLayout()

        config_help = QLabel("Plugin-specific settings and parameters")
        config_help.setStyleSheet(f"color: {t['text_secondary']}; font-size: 10px;")
        config_layout.addWidget(config_help)

        self.gui.plugin_config_editor = QTextEdit()
        self.gui.plugin_config_editor.setStyleSheet(f"""
            QTextEdit {{
                background-color: {t['bg_input']};
                color: {t['accent']};
                font-family: 'Consolas', 'Courier New', monospace;
                font-size: 11px;
                border: 1px solid {t['border']};
                border-radius: 4px;
                padding: 8px;
            }}
        """)
        self.gui.plugin_config_editor.setPlaceholderText("Plugin configuration will appear here...")
        config_layout.addWidget(self.gui.plugin_config_editor)

        # Save config button
        save_btn_layout = QHBoxLayout()
        save_config_btn = QPushButton("Save Configuration")
        save_config_btn.setStyleSheet(f"""
            QPushButton {{
                background-color: {t['success']};
                color: {t['text_on_accent']};
                padding: 8px 16px;
                border-radius: 4px;
                font-weight: bold;
                border: none;
            }}
            QPushButton:hover {{
                background-color: #43a047;
            }}
        """)
        save_config_btn.clicked.connect(self._save_plugin_config)
        save_btn_layout.addWidget(save_config_btn)
        save_btn_layout.addStretch()
        config_layout.addLayout(save_btn_layout)

        config_group.setLayout(config_layout)
        right_layout.addWidget(config_group)

        return right_panel

    def _load_plugins_list(self):
        """Load and display all plugins in the table"""
        self.gui.plugin_table.setRowCount(0)

        for plugin in self.default_plugins:
            row = self.gui.plugin_table.rowCount()
            self.gui.plugin_table.insertRow(row)

            # Name
            name_item = QTableWidgetItem(plugin['name'])
            name_item.setData(Qt.UserRole, plugin)  # Store full plugin data
            self.gui.plugin_table.setItem(row, 0, name_item)

            # Version
            version_item = QTableWidgetItem(plugin['version'])
            self.gui.plugin_table.setItem(row, 1, version_item)

            # Category
            category_item = QTableWidgetItem(plugin['category'])
            self.gui.plugin_table.setItem(row, 2, category_item)

            # Status
            status_text = "Enabled" if plugin['enabled'] else "Disabled"
            status_item = QTableWidgetItem(status_text)
            if plugin['enabled']:
                status_item.setForeground(QColor('#4CAF50'))
            else:
                status_item.setForeground(QColor('#999999'))
            self.gui.plugin_table.setItem(row, 3, status_item)

        self.gui.plugin_count_label.setText(f"Plugins: {len(self.default_plugins)}")

        # Select first item if available
        if self.default_plugins:
            self.gui.plugin_table.selectRow(0)

    def _filter_plugins(self):
        """Filter plugins based on search text"""
        search_text = self.gui.plugin_search.text().lower()
        visible_count = 0

        for row in range(self.gui.plugin_table.rowCount()):
            name_item = self.gui.plugin_table.item(row, 0)
            category_item = self.gui.plugin_table.item(row, 2)

            name_match = search_text in name_item.text().lower()
            category_match = search_text in category_item.text().lower()

            if search_text == "" or name_match or category_match:
                self.gui.plugin_table.setRowHidden(row, False)
                visible_count += 1
            else:
                self.gui.plugin_table.setRowHidden(row, True)

        total = self.gui.plugin_table.rowCount()
        self.gui.plugin_count_label.setText(f"Plugins: {visible_count}/{total}")

    def _on_plugin_selected(self):
        """Handle plugin selection from table"""
        selected_items = self.gui.plugin_table.selectedItems()
        if not selected_items:
            return

        row = selected_items[0].row()
        name_item = self.gui.plugin_table.item(row, 0)
        plugin_data = name_item.data(Qt.UserRole)

        if plugin_data:
            self._display_plugin_details(plugin_data)

    def _display_plugin_details(self, plugin):
        """Display plugin details in the right panel"""
        self.gui.plugin_name_label.setText(plugin['name'])
        self.gui.plugin_version_label.setText(plugin['version'])
        self.gui.plugin_author_label.setText(plugin['author'])
        self.gui.plugin_category_label.setText(plugin['category'])
        self.gui.plugin_description_text.setPlainText(plugin['description'])
        self.gui.plugin_enable_checkbox.setChecked(plugin['enabled'])

        # Load plugin-specific configuration
        config_template = self._get_plugin_config_template(plugin['name'])
        self.gui.plugin_config_editor.setPlainText(config_template)

    def _get_plugin_config_template(self, plugin_name):
        """Get configuration template for a plugin"""
        templates = {
            'Nmap Scanner': '''{
    "target": "",
    "ports": "1-1000",
    "scan_type": "SYN",
    "service_detection": true,
    "os_detection": false,
    "scripts": ["vuln", "safe"],
    "timing": 4,
    "output_format": "xml"
}''',
            'Nuclei': '''{
    "target": "",
    "templates": ["cves", "vulnerabilities", "misconfigurations"],
    "severity": ["critical", "high", "medium"],
    "rate_limit": 150,
    "bulk_size": 25,
    "concurrency": 25,
    "timeout": 5
}''',
            'Custom Script Runner': '''{
    "script_path": "",
    "arguments": [],
    "working_directory": "",
    "timeout": 300,
    "capture_output": true,
    "environment": {}
}''',
            'Passive Scanner': '''{
    "analyze_headers": true,
    "detect_information_disclosure": true,
    "check_security_headers": true,
    "detect_sensitive_data": true,
    "check_cookies": true,
    "check_cors": true,
    "save_findings": true
}'''
        }
        return templates.get(plugin_name, '{\n    \n}')

    def _toggle_plugin_enabled(self, state):
        """Toggle plugin enabled state"""
        selected_items = self.gui.plugin_table.selectedItems()
        if not selected_items:
            return

        row = selected_items[0].row()
        name_item = self.gui.plugin_table.item(row, 0)
        plugin_data = name_item.data(Qt.UserRole)

        if plugin_data:
            enabled = state == Qt.Checked
            plugin_data['enabled'] = enabled

            # Update status in table
            status_item = self.gui.plugin_table.item(row, 3)
            status_item.setText("Enabled" if enabled else "Disabled")
            status_item.setForeground(QColor('#4CAF50') if enabled else QColor('#999999'))

            # Update in default_plugins list
            for plugin in self.default_plugins:
                if plugin['name'] == plugin_data['name']:
                    plugin['enabled'] = enabled
                    break

    def _configure_plugin(self):
        """Open plugin configuration dialog"""
        selected_items = self.gui.plugin_table.selectedItems()
        if not selected_items:
            QMessageBox.warning(self.gui, "No Plugin Selected", "Please select a plugin to configure.")
            return

        row = selected_items[0].row()
        name_item = self.gui.plugin_table.item(row, 0)
        plugin_name = name_item.text()

        QMessageBox.information(
            self.gui,
            "Configure Plugin",
            f"Configuration for '{plugin_name}' is available in the Plugin Configuration section below.\n\n"
            "Edit the JSON configuration and click 'Save Configuration' to apply changes."
        )

    def _run_plugin(self):
        """Run the selected plugin"""
        selected_items = self.gui.plugin_table.selectedItems()
        if not selected_items:
            QMessageBox.warning(self.gui, "No Plugin Selected", "Please select a plugin to run.")
            return

        row = selected_items[0].row()
        name_item = self.gui.plugin_table.item(row, 0)
        plugin_data = name_item.data(Qt.UserRole)

        if not plugin_data['enabled']:
            QMessageBox.warning(
                self.gui,
                "Plugin Disabled",
                f"The plugin '{plugin_data['name']}' is currently disabled.\n\n"
                "Enable it first to run."
            )
            return

        plugin_name = plugin_data['name']

        # Parse configuration
        config_text = self.gui.plugin_config_editor.toPlainText()
        try:
            config = json.loads(config_text)
        except json.JSONDecodeError as e:
            QMessageBox.critical(
                self.gui,
                "Invalid Configuration",
                f"The plugin configuration contains invalid JSON:\n\n{str(e)}"
            )
            return

        # Get target from main scan input or config
        target = config.get('target', '')
        if not target and hasattr(self.gui, 'target_input'):
            target = self.gui.target_input.toPlainText().strip().split('\n')[0]

        if not target:
            QMessageBox.warning(
                self.gui,
                "No Target",
                "Please specify a target in the configuration or Scan Configuration tab."
            )
            return

        # Handle different plugin types
        if plugin_name == 'Nmap Scanner':
            self._run_nmap_plugin(target, config)
        elif plugin_name == 'Nuclei':
            self._run_nuclei_plugin(target, config)
        elif plugin_name == 'Custom Script Runner':
            self._run_custom_script(config)
        elif plugin_name == 'Passive Scanner':
            self._run_passive_scanner(target, config)
        else:
            QMessageBox.information(
                self.gui,
                "Plugin Info",
                f"Plugin '{plugin_name}' requires custom implementation.\n\n"
                "Add a handler in _run_plugin() method."
            )

    def _run_nmap_plugin(self, target, config):
        """Run Nmap scanner plugin"""
        import subprocess
        import shutil

        # Check if nmap is available
        nmap_path = shutil.which('nmap')
        if not nmap_path:
            QMessageBox.critical(
                self.gui,
                "Nmap Not Found",
                "Nmap is not installed or not in PATH.\n\n"
                "Please install Nmap from: https://nmap.org/download.html"
            )
            return

        # Build nmap command
        ports = config.get('ports', '1-1000')
        scan_type = config.get('scan_type', 'SYN')
        timing = config.get('timing', 4)
        scripts = config.get('scripts', [])

        cmd = [nmap_path]

        # Add scan type
        scan_flags = {
            'SYN': '-sS', 'TCP': '-sT', 'UDP': '-sU',
            'ACK': '-sA', 'FIN': '-sF', 'Null': '-sN'
        }
        cmd.append(scan_flags.get(scan_type, '-sS'))

        # Add ports
        cmd.extend(['-p', ports])

        # Add timing
        cmd.append(f'-T{timing}')

        # Add service detection
        if config.get('service_detection', True):
            cmd.append('-sV')

        # Add OS detection
        if config.get('os_detection', False):
            cmd.append('-O')

        # Add scripts
        if scripts:
            cmd.append(f'--script={",".join(scripts)}')

        # Add target
        cmd.append(target)

        # Log command to output console
        if hasattr(self.gui, 'output_console'):
            self.gui.output_console.append(f"\n[Plugin] Running Nmap: {' '.join(cmd)}\n")

        # Run in background thread
        try:
            # Start subprocess
            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1
            )

            # Read output in real-time
            def read_output():
                for line in process.stdout:
                    if hasattr(self.gui, 'output_console'):
                        self.gui.output_console.append(f"[Nmap] {line.rstrip()}")
                process.wait()
                if hasattr(self.gui, 'output_console'):
                    self.gui.output_console.append(f"\n[Plugin] Nmap completed with exit code: {process.returncode}\n")

            import threading
            thread = threading.Thread(target=read_output, daemon=True)
            thread.start()

            QMessageBox.information(
                self.gui,
                "Nmap Started",
                f"Nmap scan started against: {target}\n\n"
                f"Ports: {ports}\n"
                f"Scan Type: {scan_type}\n\n"
                "Check the Scan Output tab for results."
            )

        except Exception as e:
            QMessageBox.critical(self.gui, "Error", f"Failed to run Nmap:\n{str(e)}")

    def _run_nuclei_plugin(self, target, config):
        """Run Nuclei scanner plugin"""
        import subprocess
        import shutil

        # Check if nuclei is available
        nuclei_path = shutil.which('nuclei')
        if not nuclei_path:
            QMessageBox.critical(
                self.gui,
                "Nuclei Not Found",
                "Nuclei is not installed or not in PATH.\n\n"
                "Install with: go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest\n"
                "Or download from: https://github.com/projectdiscovery/nuclei/releases"
            )
            return

        # Build nuclei command
        templates = config.get('templates', ['cves', 'vulnerabilities'])
        severity = config.get('severity', ['critical', 'high', 'medium'])
        rate_limit = config.get('rate_limit', 150)
        concurrency = config.get('concurrency', 25)

        cmd = [nuclei_path, '-u', target]

        # Add templates
        if templates:
            for t in templates:
                cmd.extend(['-t', t])

        # Add severity filter
        if severity:
            cmd.extend(['-severity', ','.join(severity)])

        # Add rate limit
        cmd.extend(['-rate-limit', str(rate_limit)])
        cmd.extend(['-c', str(concurrency)])

        # Add output options
        cmd.append('-silent')

        # Log command
        if hasattr(self.gui, 'output_console'):
            self.gui.output_console.append(f"\n[Plugin] Running Nuclei: {' '.join(cmd)}\n")

        try:
            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1
            )

            def read_output():
                for line in process.stdout:
                    if hasattr(self.gui, 'output_console'):
                        self.gui.output_console.append(f"[Nuclei] {line.rstrip()}")
                process.wait()
                if hasattr(self.gui, 'output_console'):
                    self.gui.output_console.append(f"\n[Plugin] Nuclei completed with exit code: {process.returncode}\n")

            import threading
            thread = threading.Thread(target=read_output, daemon=True)
            thread.start()

            QMessageBox.information(
                self.gui,
                "Nuclei Started",
                f"Nuclei scan started against: {target}\n\n"
                f"Templates: {', '.join(templates)}\n"
                f"Severity: {', '.join(severity)}\n\n"
                "Check the Scan Output tab for results."
            )

        except Exception as e:
            QMessageBox.critical(self.gui, "Error", f"Failed to run Nuclei:\n{str(e)}")

    def _run_custom_script(self, config):
        """Run custom Python script"""
        import subprocess
        import sys

        script_path = config.get('script_path', '')
        if not script_path:
            QMessageBox.warning(
                self.gui,
                "No Script",
                "Please specify a script path in the configuration."
            )
            return

        if not Path(script_path).exists():
            QMessageBox.critical(
                self.gui,
                "Script Not Found",
                f"Script not found: {script_path}"
            )
            return

        arguments = config.get('arguments', [])
        working_dir = config.get('working_directory', '') or str(Path(script_path).parent)
        timeout = config.get('timeout', 300)

        cmd = [sys.executable, script_path] + arguments

        if hasattr(self.gui, 'output_console'):
            self.gui.output_console.append(f"\n[Plugin] Running script: {' '.join(cmd)}\n")

        try:
            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1,
                cwd=working_dir
            )

            def read_output():
                for line in process.stdout:
                    if hasattr(self.gui, 'output_console'):
                        self.gui.output_console.append(f"[Script] {line.rstrip()}")
                process.wait()
                if hasattr(self.gui, 'output_console'):
                    self.gui.output_console.append(f"\n[Plugin] Script completed with exit code: {process.returncode}\n")

            import threading
            thread = threading.Thread(target=read_output, daemon=True)
            thread.start()

            QMessageBox.information(
                self.gui,
                "Script Started",
                f"Custom script started: {Path(script_path).name}\n\n"
                "Check the Scan Output tab for results."
            )

        except Exception as e:
            QMessageBox.critical(self.gui, "Error", f"Failed to run script:\n{str(e)}")

    def _run_passive_scanner(self, target, config):
        """Run passive scanner on captured traffic"""
        # This would analyze HTTP traffic captured by the interceptor
        if hasattr(self.gui, 'browser_tab') and hasattr(self.gui.browser_tab, 'request_history'):
            history = self.gui.browser_tab.request_history
            if not history:
                QMessageBox.warning(
                    self.gui,
                    "No Traffic",
                    "No HTTP traffic captured.\n\n"
                    "Start the Interceptor and browse the target to capture traffic."
                )
                return

            # Analyze captured requests
            findings = []
            for req in history:
                # Check for security issues
                headers = req.get('response_headers', {})

                # Check security headers
                if config.get('check_security_headers', True):
                    missing_headers = []
                    if 'X-Frame-Options' not in headers:
                        missing_headers.append('X-Frame-Options')
                    if 'X-Content-Type-Options' not in headers:
                        missing_headers.append('X-Content-Type-Options')
                    if 'Strict-Transport-Security' not in headers:
                        missing_headers.append('Strict-Transport-Security')

                    if missing_headers:
                        findings.append(f"Missing headers on {req.get('url', 'unknown')}: {', '.join(missing_headers)}")

                # Check cookies
                if config.get('check_cookies', True):
                    cookies = headers.get('Set-Cookie', '')
                    if cookies and 'HttpOnly' not in cookies:
                        findings.append(f"Cookie without HttpOnly on {req.get('url', 'unknown')}")
                    if cookies and 'Secure' not in cookies:
                        findings.append(f"Cookie without Secure on {req.get('url', 'unknown')}")

            # Display results
            if hasattr(self.gui, 'output_console'):
                self.gui.output_console.append(f"\n[Passive Scanner] Analyzed {len(history)} requests\n")
                for finding in findings:
                    self.gui.output_console.append(f"[Finding] {finding}")
                self.gui.output_console.append(f"\n[Passive Scanner] Found {len(findings)} issues\n")

            QMessageBox.information(
                self.gui,
                "Passive Scan Complete",
                f"Analyzed {len(history)} captured requests.\n\n"
                f"Found {len(findings)} potential issues.\n\n"
                "See Scan Output tab for details."
            )
        else:
            QMessageBox.warning(
                self.gui,
                "Interceptor Not Available",
                "The Passive Scanner requires the Interceptor tab.\n\n"
                "Capture some HTTP traffic first."
            )

    def _save_plugin_config(self):
        """Save plugin configuration"""
        selected_items = self.gui.plugin_table.selectedItems()
        if not selected_items:
            QMessageBox.warning(self.gui, "No Plugin Selected", "Please select a plugin first.")
            return

        row = selected_items[0].row()
        name_item = self.gui.plugin_table.item(row, 0)
        plugin_name = name_item.text()

        # Validate JSON
        import json
        config_text = self.gui.plugin_config_editor.toPlainText()
        try:
            json.loads(config_text)
            QMessageBox.information(
                self.gui,
                "Configuration Saved",
                f"Configuration for '{plugin_name}' has been saved successfully."
            )
        except json.JSONDecodeError as e:
            QMessageBox.critical(
                self.gui,
                "Invalid JSON",
                f"The configuration contains invalid JSON:\n\n{str(e)}"
            )

    def _install_plugin(self):
        """Install a new plugin into the modules folder"""
        filename, _ = QFileDialog.getOpenFileName(
            self.gui,
            "Select Plugin Package",
            "",
            "Plugin Files (*.zip *.py);;All Files (*)"
        )
        if not filename:
            return

        file_path = Path(filename)
        modules_dir = Path(__file__).parent.parent.parent / "modules"

        try:
            if filename.endswith('.zip'):
                # Install from ZIP package
                self._install_from_zip(file_path, modules_dir)
            elif filename.endswith('.py'):
                # Install from single Python file
                self._install_from_python(file_path, modules_dir)
            else:
                QMessageBox.warning(
                    self.gui,
                    "Invalid File Type",
                    "Please select a .zip package or .py module file."
                )
        except Exception as e:
            QMessageBox.critical(
                self.gui,
                "Installation Error",
                f"Failed to install plugin:\n\n{str(e)}"
            )

    def _install_from_zip(self, zip_path, modules_dir):
        """Install plugin from ZIP package"""
        with zipfile.ZipFile(zip_path, 'r') as zip_file:
            # Get plugin name from ZIP (first directory or from config)
            namelist = zip_file.namelist()

            # Look for config.json to get module name
            config_files = [n for n in namelist if n.endswith('config.json')]

            if config_files:
                # Read config to get module name
                with zip_file.open(config_files[0]) as f:
                    config = json.load(f)
                    plugin_name = config.get('module_name', '').lower()
                    if not plugin_name:
                        plugin_name = config.get('name', '').lower().replace(' ', '_')
            else:
                # Use first directory name or zip filename
                first_entry = namelist[0]
                if '/' in first_entry:
                    plugin_name = first_entry.split('/')[0].lower()
                else:
                    plugin_name = zip_path.stem.lower()

            if not plugin_name:
                raise ValueError("Could not determine plugin name from package")

            # Sanitize plugin name
            plugin_name = ''.join(c if c.isalnum() or c == '_' else '_' for c in plugin_name)
            plugin_dir = modules_dir / plugin_name

            # Check if already exists
            if plugin_dir.exists():
                reply = QMessageBox.question(
                    self.gui,
                    "Plugin Exists",
                    f"The plugin '{plugin_name}' already exists.\n\nOverwrite?",
                    QMessageBox.Yes | QMessageBox.No
                )
                if reply == QMessageBox.No:
                    return
                shutil.rmtree(plugin_dir)

            # Create plugin directory
            plugin_dir.mkdir(parents=True)

            # Extract files
            for name in namelist:
                # Skip directories
                if name.endswith('/'):
                    continue

                # Determine target path
                if '/' in name:
                    # File is in a subdirectory, strip first directory
                    parts = name.split('/', 1)
                    if len(parts) > 1:
                        relative_path = parts[1]
                    else:
                        relative_path = name
                else:
                    relative_path = name

                if relative_path:
                    target_path = plugin_dir / relative_path
                    target_path.parent.mkdir(parents=True, exist_ok=True)

                    with zip_file.open(name) as src, open(target_path, 'wb') as dst:
                        dst.write(src.read())

            # Ensure required files exist
            self._ensure_module_structure(plugin_dir, plugin_name)

            QMessageBox.information(
                self.gui,
                "Plugin Installed",
                f"Plugin '{plugin_name}' installed successfully to:\n\n"
                f"{plugin_dir}\n\n"
                "Refresh the Modules tab to see the new module."
            )

    def _install_from_python(self, py_path, modules_dir):
        """Install plugin from single Python file"""
        # Get plugin name from filename
        plugin_name = py_path.stem.lower()

        # Sanitize plugin name
        plugin_name = ''.join(c if c.isalnum() or c == '_' else '_' for c in plugin_name)
        plugin_dir = modules_dir / plugin_name

        # Check if already exists
        if plugin_dir.exists():
            reply = QMessageBox.question(
                self.gui,
                "Plugin Exists",
                f"The plugin '{plugin_name}' already exists.\n\nOverwrite?",
                QMessageBox.Yes | QMessageBox.No
            )
            if reply == QMessageBox.No:
                return
            shutil.rmtree(plugin_dir)

        # Create plugin directory
        plugin_dir.mkdir(parents=True)

        # Copy the Python file as module.py
        shutil.copy(py_path, plugin_dir / "module.py")

        # Create required files
        self._ensure_module_structure(plugin_dir, plugin_name)

        QMessageBox.information(
            self.gui,
            "Plugin Installed",
            f"Plugin '{plugin_name}' installed successfully to:\n\n"
            f"{plugin_dir}\n\n"
            "Refresh the Modules tab to see the new module."
        )

    def _ensure_module_structure(self, plugin_dir, plugin_name):
        """Ensure plugin has required module structure"""
        # Create config.json if not exists
        config_file = plugin_dir / "config.json"
        if not config_file.exists():
            config = {
                "name": plugin_name.upper().replace('_', ' '),
                "description": f"Custom {plugin_name} module",
                "severity": "Medium",
                "enabled": True,
                "max_payloads": 100,
                "timeout": 20
            }
            with open(config_file, 'w', encoding='utf-8') as f:
                json.dump(config, f, indent=2)

        # Create payloads.txt if not exists
        payloads_file = plugin_dir / "payloads.txt"
        if not payloads_file.exists():
            with open(payloads_file, 'w', encoding='utf-8') as f:
                f.write(f"# Payloads for {plugin_name}\n")
                f.write("# Add your payloads here, one per line\n")

        # Create patterns.txt if not exists
        patterns_file = plugin_dir / "patterns.txt"
        if not patterns_file.exists():
            with open(patterns_file, 'w', encoding='utf-8') as f:
                f.write(f"# Detection patterns for {plugin_name}\n")
                f.write("# Add regex patterns here, one per line\n")

        # Create module.py if not exists
        module_file = plugin_dir / "module.py"
        if not module_file.exists():
            template = f'''"""
{plugin_name.upper()} Module
Custom vulnerability scanner module
"""

from core.base_module import BaseModule


class {plugin_name.title().replace('_', '')}Module(BaseModule):
    """Custom {plugin_name} scanner module"""

    def scan(self, target: dict) -> dict:
        """
        Scan target for vulnerabilities

        Args:
            target: Target dictionary with 'url' and 'params'

        Returns:
            Scan results dictionary
        """
        results = {{
            'vulnerabilities': [],
            'info': [],
            'errors': []
        }}

        url = target.get('url', '')
        params = target.get('params', {{}})

        # Implement your scanning logic here
        for payload in self.payloads:
            # Test each payload
            pass

        return results
'''
            with open(module_file, 'w', encoding='utf-8') as f:
                f.write(template)

    def _update_plugins(self):
        """Update all plugins by checking GitHub releases or local updates"""
        reply = QMessageBox.question(
            self.gui,
            "Update Plugins",
            "Check for updates to all installed plugins?\n\n"
            "This will:\n"
            "• Check GitHub for new plugin versions\n"
            "• Check for local updates in the plugins folder\n"
            "• Download and install any available updates",
            QMessageBox.Yes | QMessageBox.No,
            QMessageBox.No
        )

        if reply != QMessageBox.Yes:
            return

        # Show progress
        from GUI.utils import LoadingDialog
        dialog = LoadingDialog(self.gui, "Checking for plugin updates...", cancellable=True)
        dialog.show()
        QApplication.processEvents()

        try:
            updates_found = []
            errors = []

            # Get list of installed plugins
            parent_dir = Path(__file__).parent.parent.parent
            plugins_dir = parent_dir / "plugins"

            if not plugins_dir.exists():
                dialog.close()
                QMessageBox.information(
                    self.gui,
                    "No Plugins",
                    "No plugins folder found. Create a 'plugins' folder and add plugins to it."
                )
                return

            # Check each plugin directory
            plugin_folders = [d for d in plugins_dir.iterdir() if d.is_dir()]

            for i, plugin_folder in enumerate(plugin_folders):
                if dialog.cancelled:
                    break

                plugin_name = plugin_folder.name
                dialog.update_progress(
                    int((i / len(plugin_folders)) * 100),
                    f"Checking {plugin_name}..."
                )

                # Check for plugin.json or config.json
                config_file = plugin_folder / "plugin.json"
                if not config_file.exists():
                    config_file = plugin_folder / "config.json"

                if config_file.exists():
                    try:
                        with open(config_file, 'r') as f:
                            config = json.load(f)

                        current_version = config.get('version', '0.0.0')
                        update_url = config.get('update_url', '')
                        github_repo = config.get('github_repo', '')

                        # Try to check for updates via GitHub API
                        if github_repo:
                            try:
                                import urllib.request
                                api_url = f"https://api.github.com/repos/{github_repo}/releases/latest"
                                req = urllib.request.Request(
                                    api_url,
                                    headers={'User-Agent': 'Dominator-Scanner/1.0'}
                                )
                                with urllib.request.urlopen(req, timeout=10) as response:
                                    release_data = json.loads(response.read().decode())
                                    latest_version = release_data.get('tag_name', '').lstrip('v')

                                    if latest_version and latest_version > current_version:
                                        updates_found.append({
                                            'name': plugin_name,
                                            'current': current_version,
                                            'latest': latest_version,
                                            'url': release_data.get('html_url', '')
                                        })
                            except Exception as e:
                                # GitHub check failed, continue
                                pass

                        # Check for local .update file (manual update indicator)
                        update_marker = plugin_folder / ".update_available"
                        if update_marker.exists():
                            try:
                                with open(update_marker, 'r') as f:
                                    update_info = f.read().strip()
                                updates_found.append({
                                    'name': plugin_name,
                                    'current': current_version,
                                    'latest': update_info or 'New version',
                                    'url': ''
                                })
                            except:
                                pass

                    except json.JSONDecodeError:
                        errors.append(f"Invalid config in {plugin_name}")

            dialog.close()

            if dialog.cancelled:
                return

            # Show results
            if updates_found:
                update_list = "\n".join([
                    f"• {u['name']}: {u['current']} → {u['latest']}"
                    for u in updates_found
                ])

                reply = QMessageBox.question(
                    self.gui,
                    "Updates Available",
                    f"Found {len(updates_found)} plugin update(s):\n\n{update_list}\n\n"
                    "Would you like to open the download page(s)?",
                    QMessageBox.Yes | QMessageBox.No
                )

                if reply == QMessageBox.Yes:
                    # Open update URLs
                    for update in updates_found:
                        if update['url']:
                            QDesktopServices.openUrl(QUrl(update['url']))
                        else:
                            # Open marketplace for plugins without direct URL
                            QDesktopServices.openUrl(QUrl("https://github.com/vulnz/dominator-plugins"))
                            break
            else:
                result_msg = "All plugins are up to date!"
                if errors:
                    result_msg += f"\n\nWarnings:\n" + "\n".join(errors)

                QMessageBox.information(
                    self.gui,
                    "Update Check Complete",
                    result_msg
                )

        except Exception as e:
            dialog.close()
            QMessageBox.critical(
                self.gui,
                "Update Error",
                f"Failed to check for updates:\n{str(e)}"
            )

    def _open_marketplace(self):
        """Open plugin marketplace in browser"""
        QDesktopServices.openUrl(QUrl("https://github.com/vulnz/dominator-plugins"))

    def apply_theme(self):
        """Update plugin tab styling when theme changes"""
        t = self._get_theme()

        # Update search label
        if hasattr(self.gui, 'plugin_search'):
            # Search label is recreated with build, so we just update plugin count
            pass

        # Update plugin count label
        if hasattr(self.gui, 'plugin_count_label'):
            self.gui.plugin_count_label.setStyleSheet(
                f"color: {t['text_secondary']}; font-size: 10px; padding: 5px;"
            )

        # Update plugin config editor
        if hasattr(self.gui, 'plugin_config_editor'):
            self.gui.plugin_config_editor.setStyleSheet(f"""
                QTextEdit {{
                    background-color: {t['bg_input']};
                    color: {t['accent']};
                    font-family: 'Consolas', 'Courier New', monospace;
                    font-size: 11px;
                    border: 1px solid {t['border']};
                    border-radius: 4px;
                    padding: 8px;
                }}
            """)

        # Update plugin name label
        if hasattr(self.gui, 'plugin_name_label'):
            self.gui.plugin_name_label.setStyleSheet(
                f"font-size: 14px; font-weight: bold; color: {t['text_primary']};"
            )

        # Update checkbox
        if hasattr(self.gui, 'plugin_enable_checkbox'):
            self.gui.plugin_enable_checkbox.setStyleSheet(f"""
                QCheckBox {{
                    font-weight: bold;
                    color: {t['text_primary']};
                }}
            """)
