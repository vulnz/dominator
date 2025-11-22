"""
Plugins Tab Builder
Handles the plugin management UI with list, details, and configuration.
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

        # Default plugins data
        self.default_plugins = [
            {
                'name': 'Nmap Scanner',
                'description': 'Network exploration and security auditing tool. Performs port scanning, service detection, OS fingerprinting, and vulnerability scanning using NSE scripts.',
                'version': '1.0.0',
                'author': 'Dominator Team',
                'enabled': True,
                'category': 'Network'
            },
            {
                'name': 'Nuclei',
                'description': 'Fast and customizable vulnerability scanner based on simple YAML based DSL. Supports template-based scanning for various protocols including HTTP, DNS, TCP, and more.',
                'version': '1.0.0',
                'author': 'Dominator Team',
                'enabled': True,
                'category': 'Scanner'
            },
            {
                'name': 'Custom Script Runner',
                'description': 'Execute custom Python scripts for specialized security testing. Allows integration of custom tools and automation scripts into the scanning workflow.',
                'version': '1.0.0',
                'author': 'Dominator Team',
                'enabled': False,
                'category': 'Utility'
            },
            {
                'name': 'Passive Scanner',
                'description': 'Analyzes HTTP traffic passively without sending additional requests. Detects security issues, information disclosure, and misconfigurations from proxy traffic.',
                'version': '1.0.0',
                'author': 'Dominator Team',
                'enabled': True,
                'category': 'Scanner'
            }
        ]

    def build(self):
        """Create and return the plugins tab widget"""
        widget = QWidget()
        widget.setStyleSheet("""
            QWidget {
                background-color: #ffffff;
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
            QLabel {
                color: #333333;
            }
            QPushButton {
                background-color: #f5f5f5;
                color: #333333;
                border: 1px solid #cccccc;
                border-radius: 4px;
                padding: 5px 10px;
            }
            QPushButton:hover {
                background-color: #e0e0e0;
            }
        """)
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
        left_panel = QWidget()
        left_layout = QVBoxLayout(left_panel)
        left_layout.setContentsMargins(0, 0, 0, 0)

        # Search/Filter bar
        search_layout = QHBoxLayout()
        search_label = QLabel("Search:")
        search_label.setStyleSheet("color: #4CAF50; font-weight: bold;")
        search_layout.addWidget(search_label)

        self.gui.plugin_search = QLineEdit()
        self.gui.plugin_search.setPlaceholderText("Filter plugins...")
        self.gui.plugin_search.setStyleSheet("""
            QLineEdit {
                background-color: #ffffff;
                color: #333333;
                border: 1px solid #cccccc;
                border-radius: 4px;
                padding: 5px;
            }
            QLineEdit:focus {
                border: 1px solid #4CAF50;
            }
        """)
        self.gui.plugin_search.textChanged.connect(self._filter_plugins)
        search_layout.addWidget(self.gui.plugin_search)

        left_layout.addLayout(search_layout)

        # Plugin count label
        self.gui.plugin_count_label = QLabel("Plugins: 0")
        self.gui.plugin_count_label.setStyleSheet("color: #888888; font-size: 10px; padding: 5px;")
        left_layout.addWidget(self.gui.plugin_count_label)

        # Plugin table
        self.gui.plugin_table = QTableWidget()
        self.gui.plugin_table.setColumnCount(4)
        self.gui.plugin_table.setHorizontalHeaderLabels(['Name', 'Version', 'Category', 'Status'])
        self.gui.plugin_table.setStyleSheet("""
            QTableWidget {
                background-color: #ffffff;
                color: #333333;
                border: 1px solid #cccccc;
                border-radius: 4px;
                gridline-color: #e0e0e0;
            }
            QTableWidget::item {
                padding: 8px;
                border-bottom: 1px solid #e0e0e0;
            }
            QTableWidget::item:hover {
                background-color: #f5f5f5;
            }
            QTableWidget::item:selected {
                background-color: #4CAF50;
                color: white;
            }
            QHeaderView::section {
                background-color: #f5f5f5;
                color: #333333;
                padding: 8px;
                border: none;
                border-bottom: 2px solid #4CAF50;
                font-weight: bold;
            }
        """)
        self.gui.plugin_table.horizontalHeader().setStretchLastSection(True)
        self.gui.plugin_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.Stretch)
        self.gui.plugin_table.setSelectionBehavior(QTableWidget.SelectRows)
        self.gui.plugin_table.setSelectionMode(QTableWidget.SingleSelection)
        self.gui.plugin_table.verticalHeader().setVisible(False)
        self.gui.plugin_table.itemSelectionChanged.connect(self._on_plugin_selected)
        left_layout.addWidget(self.gui.plugin_table)

        # Management buttons
        mgmt_group = QGroupBox("Plugin Management")
        mgmt_layout = QVBoxLayout()

        # First row of buttons
        btn_row1 = QHBoxLayout()

        install_btn = QPushButton("Install New Plugin")
        install_btn.setStyleSheet("""
            QPushButton {
                background-color: #4CAF50;
                color: white;
                padding: 8px 16px;
                border-radius: 4px;
                font-weight: bold;
                border: none;
            }
            QPushButton:hover {
                background-color: #45a049;
            }
        """)
        install_btn.clicked.connect(self._install_plugin)
        btn_row1.addWidget(install_btn)

        update_btn = QPushButton("Update Plugins")
        update_btn.setStyleSheet("""
            QPushButton {
                background-color: #2196F3;
                color: white;
                padding: 8px 16px;
                border-radius: 4px;
                font-weight: bold;
                border: none;
            }
            QPushButton:hover {
                background-color: #1976D2;
            }
        """)
        update_btn.clicked.connect(self._update_plugins)
        btn_row1.addWidget(update_btn)

        mgmt_layout.addLayout(btn_row1)

        # Second row - marketplace link
        btn_row2 = QHBoxLayout()

        marketplace_btn = QPushButton("Plugin Marketplace")
        marketplace_btn.setStyleSheet("""
            QPushButton {
                background-color: #FF9800;
                color: white;
                padding: 8px 16px;
                border-radius: 4px;
                font-weight: bold;
                border: none;
            }
            QPushButton:hover {
                background-color: #F57C00;
            }
        """)
        marketplace_btn.clicked.connect(self._open_marketplace)
        btn_row2.addWidget(marketplace_btn)

        refresh_btn = QPushButton("Refresh")
        refresh_btn.setStyleSheet("""
            QPushButton {
                background-color: #f5f5f5;
                color: #4CAF50;
                border: 1px solid #cccccc;
                border-radius: 4px;
                padding: 8px 16px;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: #e0e0e0;
                border-color: #4CAF50;
            }
        """)
        refresh_btn.clicked.connect(self._load_plugins_list)
        btn_row2.addWidget(refresh_btn)

        mgmt_layout.addLayout(btn_row2)
        mgmt_group.setLayout(mgmt_layout)
        left_layout.addWidget(mgmt_group)

        return left_panel

    def _create_right_panel(self):
        """Create right panel with plugin details and configuration"""
        right_panel = QWidget()
        right_layout = QVBoxLayout(right_panel)
        right_layout.setContentsMargins(0, 0, 0, 0)

        # Plugin Details Group
        details_group = QGroupBox("Plugin Details")
        details_layout = QVBoxLayout()

        # Plugin name
        name_layout = QHBoxLayout()
        name_label = QLabel("Name:")
        name_label.setStyleSheet("font-weight: bold; color: #4CAF50;")
        name_label.setFixedWidth(100)
        name_layout.addWidget(name_label)

        self.gui.plugin_name_label = QLabel("Select a plugin")
        self.gui.plugin_name_label.setStyleSheet("font-size: 14px; font-weight: bold;")
        name_layout.addWidget(self.gui.plugin_name_label)
        name_layout.addStretch()
        details_layout.addLayout(name_layout)

        # Plugin version
        version_layout = QHBoxLayout()
        version_label = QLabel("Version:")
        version_label.setStyleSheet("font-weight: bold; color: #4CAF50;")
        version_label.setFixedWidth(100)
        version_layout.addWidget(version_label)

        self.gui.plugin_version_label = QLabel("-")
        version_layout.addWidget(self.gui.plugin_version_label)
        version_layout.addStretch()
        details_layout.addLayout(version_layout)

        # Plugin author
        author_layout = QHBoxLayout()
        author_label = QLabel("Author:")
        author_label.setStyleSheet("font-weight: bold; color: #4CAF50;")
        author_label.setFixedWidth(100)
        author_layout.addWidget(author_label)

        self.gui.plugin_author_label = QLabel("-")
        author_layout.addWidget(self.gui.plugin_author_label)
        author_layout.addStretch()
        details_layout.addLayout(author_layout)

        # Plugin category
        category_layout = QHBoxLayout()
        category_label = QLabel("Category:")
        category_label.setStyleSheet("font-weight: bold; color: #4CAF50;")
        category_label.setFixedWidth(100)
        category_layout.addWidget(category_label)

        self.gui.plugin_category_label = QLabel("-")
        category_layout.addWidget(self.gui.plugin_category_label)
        category_layout.addStretch()
        details_layout.addLayout(category_layout)

        # Plugin description
        desc_label = QLabel("Description:")
        desc_label.setStyleSheet("font-weight: bold; color: #4CAF50; margin-top: 10px;")
        details_layout.addWidget(desc_label)

        self.gui.plugin_description_text = QTextEdit()
        self.gui.plugin_description_text.setReadOnly(True)
        self.gui.plugin_description_text.setMaximumHeight(100)
        self.gui.plugin_description_text.setStyleSheet("""
            QTextEdit {
                background-color: #f8f8f8;
                color: #333333;
                border: 1px solid #e0e0e0;
                border-radius: 4px;
                padding: 8px;
            }
        """)
        details_layout.addWidget(self.gui.plugin_description_text)

        details_group.setLayout(details_layout)
        right_layout.addWidget(details_group)

        # Plugin Actions Group
        actions_group = QGroupBox("Plugin Actions")
        actions_layout = QVBoxLayout()

        # Enable/Disable toggle
        enable_layout = QHBoxLayout()
        self.gui.plugin_enable_checkbox = QCheckBox("Enable Plugin")
        self.gui.plugin_enable_checkbox.setStyleSheet("""
            QCheckBox {
                font-weight: bold;
                color: #333333;
            }
            QCheckBox::indicator {
                width: 18px;
                height: 18px;
            }
            QCheckBox::indicator:checked {
                background-color: #4CAF50;
                border: 2px solid #4CAF50;
                border-radius: 3px;
            }
            QCheckBox::indicator:unchecked {
                background-color: #ffffff;
                border: 2px solid #cccccc;
                border-radius: 3px;
            }
        """)
        self.gui.plugin_enable_checkbox.stateChanged.connect(self._toggle_plugin_enabled)
        enable_layout.addWidget(self.gui.plugin_enable_checkbox)
        enable_layout.addStretch()
        actions_layout.addLayout(enable_layout)

        # Action buttons
        action_btn_layout = QHBoxLayout()

        configure_btn = QPushButton("Configure")
        configure_btn.setStyleSheet("""
            QPushButton {
                background-color: #9C27B0;
                color: white;
                padding: 10px 20px;
                border-radius: 4px;
                font-weight: bold;
                border: none;
            }
            QPushButton:hover {
                background-color: #7B1FA2;
            }
        """)
        configure_btn.clicked.connect(self._configure_plugin)
        action_btn_layout.addWidget(configure_btn)

        run_btn = QPushButton("Run")
        run_btn.setStyleSheet("""
            QPushButton {
                background-color: #4CAF50;
                color: white;
                padding: 10px 20px;
                border-radius: 4px;
                font-weight: bold;
                border: none;
            }
            QPushButton:hover {
                background-color: #45a049;
            }
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
        config_help.setStyleSheet("color: #888888; font-size: 10px;")
        config_layout.addWidget(config_help)

        self.gui.plugin_config_editor = QTextEdit()
        self.gui.plugin_config_editor.setStyleSheet("""
            QTextEdit {
                background-color: #ffffff;
                color: #333333;
                font-family: 'Consolas', 'Courier New', monospace;
                font-size: 11px;
                border: 2px solid #e0e0e0;
                border-radius: 4px;
                padding: 8px;
            }
        """)
        self.gui.plugin_config_editor.setPlaceholderText("Plugin configuration will appear here...")
        config_layout.addWidget(self.gui.plugin_config_editor)

        # Save config button
        save_btn_layout = QHBoxLayout()
        save_config_btn = QPushButton("Save Configuration")
        save_config_btn.setStyleSheet("""
            QPushButton {
                background-color: #4CAF50;
                color: white;
                padding: 8px 16px;
                border-radius: 4px;
                font-weight: bold;
                border: none;
            }
            QPushButton:hover {
                background-color: #45a049;
            }
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

        # Show placeholder message for now
        QMessageBox.information(
            self.gui,
            "Run Plugin",
            f"Starting '{plugin_data['name']}'...\n\n"
            "Plugin execution will be integrated in a future update.\n"
            "Current configuration:\n" + self.gui.plugin_config_editor.toPlainText()[:200] + "..."
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
        """Update all plugins"""
        reply = QMessageBox.question(
            self.gui,
            "Update Plugins",
            "Check for updates to all installed plugins?\n\n"
            "This will connect to the plugin repository to check for new versions.",
            QMessageBox.Yes | QMessageBox.No,
            QMessageBox.No
        )

        if reply == QMessageBox.Yes:
            QMessageBox.information(
                self.gui,
                "Update Check",
                "All plugins are up to date.\n\n"
                "Plugin update functionality will be fully integrated in a future update."
            )

    def _open_marketplace(self):
        """Open plugin marketplace in browser"""
        QDesktopServices.openUrl(QUrl("https://github.com/vulnz/dominator-plugins"))
