"""
Modules Tab Builder
Handles the module configuration and payload editing UI.
Enhanced with better visuals, descriptions, icons, and action buttons.
"""

from PyQt5.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QGroupBox,
    QLabel, QLineEdit, QTextEdit, QPushButton,
    QListWidget, QSplitter, QListWidgetItem, QFrame,
    QScrollArea, QGridLayout, QToolButton, QSizePolicy,
    QDialog, QFormLayout, QMessageBox, QCheckBox, QComboBox,
    QButtonGroup, QRadioButton
)
from PyQt5.QtCore import Qt, QSize
from PyQt5.QtGui import QFont, QColor, QIcon
from pathlib import Path
import json
import os
from datetime import datetime

# TOML support (Python 3.11+)
try:
    import tomllib
    HAS_TOML = True
except ImportError:
    HAS_TOML = False


class ModulesTabBuilder:
    """Builder class for creating the Modules tab

    Module descriptions are now loaded DYNAMICALLY from each module's config.json file.
    No hardcoded module list - the GUI auto-discovers all modules in the modules/ folder.
    """

    @staticmethod
    def load_all_module_configs():
        """Dynamically load all module configurations from config files.
        Prefers TOML over JSON format.
        Returns dict mapping module_folder -> config dict
        """
        parent_dir = Path(__file__).parent.parent.parent
        modules_dir = parent_dir / "modules"

        configs = {}
        if modules_dir.exists():
            for module_path in modules_dir.iterdir():
                if module_path.is_dir() and not module_path.name.startswith('_'):
                    toml_file = module_path / "config.toml"
                    json_file = module_path / "config.json"

                    config = None

                    # Try TOML first (preferred)
                    if HAS_TOML and toml_file.exists():
                        try:
                            with open(toml_file, 'rb') as f:
                                config = tomllib.load(f)
                        except Exception:
                            pass

                    # Fall back to JSON
                    if config is None and json_file.exists():
                        try:
                            with open(json_file, 'r', encoding='utf-8') as f:
                                config = json.load(f)
                        except Exception:
                            pass

                    # Store config or use fallback
                    if config:
                        configs[module_path.name] = config
                    else:
                        # Fallback for modules without valid config
                        configs[module_path.name] = {
                            'name': module_path.name.upper(),
                            'description': f'Module: {module_path.name}',
                            'enabled': True,
                            'severity': 'medium'
                        }
        return configs

    @staticmethod
    def get_module_description(module_folder):
        """Get description for a module from its config file (TOML preferred)"""
        parent_dir = Path(__file__).parent.parent.parent
        toml_file = parent_dir / "modules" / module_folder / "config.toml"
        json_file = parent_dir / "modules" / module_folder / "config.json"

        # Try TOML first
        if HAS_TOML and toml_file.exists():
            try:
                with open(toml_file, 'rb') as f:
                    config = tomllib.load(f)
                    return config.get('description', f'Module: {module_folder}')
            except:
                pass

        # Fall back to JSON
        if json_file.exists():
            try:
                with open(json_file, 'r', encoding='utf-8') as f:
                    config = json.load(f)
                    return config.get('description', f'Module: {module_folder}')
            except:
                pass

        return f'Module: {module_folder}'

    # Severity colors and icons
    SEVERITY_STYLES = {
        'Critical': {'color': '#dc3545', 'bg': '#fdf0f0', 'icon': '!!!'},
        'High': {'color': '#fd7e14', 'bg': '#fff5f0', 'icon': '!!'},
        'Medium': {'color': '#ffc107', 'bg': '#fffdf0', 'icon': '!'},
        'Low': {'color': '#28a745', 'bg': '#f0fdf4', 'icon': 'i'},
        'Info': {'color': '#17a2b8', 'bg': '#f0f9ff', 'icon': 'i'}
    }

    def __init__(self, gui, collapsible_box_class):
        """
        Initialize the builder with reference to main GUI

        Args:
            gui: Reference to DominatorGUI instance
            collapsible_box_class: The CollapsibleBox class (not used here but kept for consistency)
        """
        self.gui = gui
        self.CollapsibleBox = collapsible_box_class
        self.module_data_cache = {}  # Cache for module data

    def build(self):
        """Create and return the modules tab widget"""
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

        # Main horizontal splitter: Module list on left, details on right
        main_splitter = QSplitter(Qt.Horizontal)

        # Left Panel: Module List
        left_panel = self._create_left_panel()
        main_splitter.addWidget(left_panel)

        # Right Panel: Info panel and editors
        right_panel = self._create_right_panel()
        main_splitter.addWidget(right_panel)

        # Set splitter sizes: 350px for module list, rest for editors
        main_splitter.setSizes([350, 800])
        layout.addWidget(main_splitter)

        # Load modules list
        self.gui.load_modules_list()

        return widget

    def _create_left_panel(self):
        """Create left panel with enhanced module list"""
        left_panel = QWidget()
        left_layout = QVBoxLayout(left_panel)
        left_layout.setContentsMargins(0, 0, 0, 0)

        # Header with title and count
        header_layout = QHBoxLayout()
        title_label = QLabel("Security Modules")
        title_label.setStyleSheet("font-size: 14px; font-weight: bold; color: #4CAF50; padding: 5px;")
        header_layout.addWidget(title_label)
        header_layout.addStretch()
        left_layout.addLayout(header_layout)

        # Search/Filter bar
        search_layout = QHBoxLayout()
        search_label = QLabel("Search:")
        search_label.setStyleSheet("color: #4CAF50; font-weight: bold;")
        search_layout.addWidget(search_label)

        self.gui.module_search = QLineEdit()
        self.gui.module_search.setPlaceholderText("Filter modules...")
        self.gui.module_search.setStyleSheet("""
            QLineEdit {
                background-color: #ffffff;
                color: #333333;
                border: 1px solid #cccccc;
                border-radius: 4px;
                padding: 8px;
                font-size: 12px;
            }
            QLineEdit:focus {
                border: 2px solid #4CAF50;
            }
        """)
        self.gui.module_search.textChanged.connect(self._apply_filters)
        search_layout.addWidget(self.gui.module_search)

        refresh_btn = QPushButton("Refresh")
        refresh_btn.setStyleSheet("""
            QPushButton {
                background-color: #4CAF50;
                color: white;
                border: none;
                border-radius: 4px;
                padding: 8px 12px;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: #45a049;
            }
        """)
        refresh_btn.clicked.connect(self._refresh_modules)
        search_layout.addWidget(refresh_btn)

        left_layout.addLayout(search_layout)

        # Filter row: All / Active / Passive
        filter_layout = QHBoxLayout()
        filter_label = QLabel("Type:")
        filter_label.setStyleSheet("color: #666666; font-weight: bold; font-size: 11px;")
        filter_layout.addWidget(filter_label)

        # Store current filter state
        self.current_type_filter = "all"
        self.current_sort = "name"

        btn_style_inactive = """
            QPushButton {
                background-color: #f5f5f5;
                color: #666666;
                border: 1px solid #cccccc;
                border-radius: 4px;
                padding: 4px 10px;
                font-size: 10px;
            }
            QPushButton:hover {
                background-color: #e0e0e0;
            }
        """
        btn_style_active = """
            QPushButton {
                background-color: #4CAF50;
                color: white;
                border: 1px solid #4CAF50;
                border-radius: 4px;
                padding: 4px 10px;
                font-size: 10px;
                font-weight: bold;
            }
        """

        self.filter_all_btn = QPushButton("All")
        self.filter_all_btn.setStyleSheet(btn_style_active)
        self.filter_all_btn.clicked.connect(lambda: self._set_type_filter("all"))
        filter_layout.addWidget(self.filter_all_btn)

        self.filter_active_btn = QPushButton("Active")
        self.filter_active_btn.setStyleSheet(btn_style_inactive)
        self.filter_active_btn.clicked.connect(lambda: self._set_type_filter("active"))
        filter_layout.addWidget(self.filter_active_btn)

        self.filter_passive_btn = QPushButton("Passive")
        self.filter_passive_btn.setStyleSheet(btn_style_inactive)
        self.filter_passive_btn.clicked.connect(lambda: self._set_type_filter("passive"))
        filter_layout.addWidget(self.filter_passive_btn)

        filter_layout.addStretch()

        # Sort dropdown
        sort_label = QLabel("Sort:")
        sort_label.setStyleSheet("color: #666666; font-weight: bold; font-size: 11px;")
        filter_layout.addWidget(sort_label)

        self.sort_combo = QComboBox()
        self.sort_combo.addItems(["Name", "Payloads", "Modified", "Enabled", "Severity"])
        self.sort_combo.setStyleSheet("""
            QComboBox {
                background-color: #ffffff;
                color: #333333;
                border: 1px solid #cccccc;
                border-radius: 4px;
                padding: 4px 8px;
                font-size: 10px;
                min-width: 80px;
            }
            QComboBox::drop-down {
                border: none;
            }
            QComboBox QAbstractItemView {
                background-color: #ffffff;
                color: #333333;
                selection-background-color: #4CAF50;
            }
        """)
        self.sort_combo.currentTextChanged.connect(self._set_sort)
        filter_layout.addWidget(self.sort_combo)

        left_layout.addLayout(filter_layout)

        # Module count label
        self.gui.module_count_label = QLabel("Modules: 0")
        self.gui.module_count_label.setStyleSheet("color: #888888; font-size: 11px; padding: 5px;")
        left_layout.addWidget(self.gui.module_count_label)

        # Module list widget with enhanced styling
        self.gui.module_list = QListWidget()
        self.gui.module_list.setStyleSheet("""
            QListWidget {
                background-color: #ffffff;
                color: #333333;
                border: 1px solid #e0e0e0;
                border-radius: 6px;
                outline: none;
            }
            QListWidget::item {
                padding: 8px 12px;
                border-bottom: 1px solid #f0f0f0;
            }
            QListWidget::item:hover {
                background-color: #f5f5f5;
            }
            QListWidget::item:selected {
                background-color: #4CAF50;
                color: white;
            }
        """)
        self.gui.module_list.setSpacing(2)
        self.gui.module_list.itemClicked.connect(self.gui.on_module_selected)
        # Also connect currentItemChanged for arrow key navigation
        self.gui.module_list.currentItemChanged.connect(self._on_current_item_changed)
        left_layout.addWidget(self.gui.module_list)

        # Quick actions bar
        actions_layout = QHBoxLayout()

        enable_all_btn = QPushButton("Enable All")
        enable_all_btn.setStyleSheet("""
            QPushButton {
                background-color: #e8f5e9;
                color: #2e7d32;
                border: 1px solid #a5d6a7;
                border-radius: 4px;
                padding: 6px 10px;
                font-size: 11px;
            }
            QPushButton:hover {
                background-color: #c8e6c9;
            }
        """)
        enable_all_btn.clicked.connect(lambda: self._toggle_all_modules(True))
        actions_layout.addWidget(enable_all_btn)

        disable_all_btn = QPushButton("Disable All")
        disable_all_btn.setStyleSheet("""
            QPushButton {
                background-color: #ffebee;
                color: #c62828;
                border: 1px solid #ef9a9a;
                border-radius: 4px;
                padding: 6px 10px;
                font-size: 11px;
            }
            QPushButton:hover {
                background-color: #ffcdd2;
            }
        """)
        disable_all_btn.clicked.connect(lambda: self._toggle_all_modules(False))
        actions_layout.addWidget(disable_all_btn)

        actions_layout.addStretch()
        left_layout.addLayout(actions_layout)

        return left_panel

    def _create_right_panel(self):
        """Create right panel with info panel and editors"""
        right_widget = QWidget()
        right_layout = QVBoxLayout(right_widget)
        right_layout.setContentsMargins(0, 0, 0, 0)
        right_layout.setSpacing(8)

        # Module Info Panel (collapsible)
        info_panel = self._create_info_panel()
        right_layout.addWidget(info_panel)

        # Editors splitter
        editors_splitter = QSplitter(Qt.Horizontal)

        # Config Editor
        config_group = self._create_config_editor()
        editors_splitter.addWidget(config_group)

        # Payloads Editor
        payloads_group = self._create_payloads_editor()
        editors_splitter.addWidget(payloads_group)

        editors_splitter.setSizes([400, 400])
        right_layout.addWidget(editors_splitter)

        return right_widget

    def _create_info_panel(self):
        """Create the module information panel"""
        info_group = QGroupBox("Module Information")
        info_group.setStyleSheet("""
            QGroupBox {
                background-color: #f8f9fa;
                border: 1px solid #e0e0e0;
                border-radius: 8px;
                margin-top: 10px;
                padding: 15px;
                font-weight: bold;
            }
            QGroupBox::title {
                subcontrol-origin: margin;
                left: 10px;
                padding: 0 8px;
                color: #4CAF50;
                font-size: 13px;
            }
        """)

        info_layout = QVBoxLayout()
        info_layout.setSpacing(10)

        # Top row: Module name and quick actions
        top_row = QHBoxLayout()

        # Module name (large)
        self.gui.module_info_name = QLabel("Select a module")
        self.gui.module_info_name.setStyleSheet("""
            font-size: 18px;
            font-weight: bold;
            color: #333333;
        """)
        top_row.addWidget(self.gui.module_info_name)

        top_row.addStretch()

        # Quick action buttons
        self.gui.toggle_module_btn = QPushButton("Toggle")
        self.gui.toggle_module_btn.setStyleSheet("""
            QPushButton {
                background-color: #e3f2fd;
                color: #1565c0;
                border: 1px solid #90caf9;
                border-radius: 4px;
                padding: 6px 12px;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: #bbdefb;
            }
        """)
        self.gui.toggle_module_btn.clicked.connect(self._toggle_current_module)
        top_row.addWidget(self.gui.toggle_module_btn)

        self.gui.reset_module_btn = QPushButton("Reset Default")
        self.gui.reset_module_btn.setStyleSheet("""
            QPushButton {
                background-color: #fff3e0;
                color: #e65100;
                border: 1px solid #ffcc80;
                border-radius: 4px;
                padding: 6px 12px;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: #ffe0b2;
            }
        """)
        self.gui.reset_module_btn.clicked.connect(self._reset_current_module)
        top_row.addWidget(self.gui.reset_module_btn)

        info_layout.addLayout(top_row)

        # Description
        self.gui.module_info_desc = QLabel("Description will appear here")
        self.gui.module_info_desc.setWordWrap(True)
        self.gui.module_info_desc.setStyleSheet("""
            color: #555555;
            font-size: 12px;
            padding: 5px 0;
        """)
        info_layout.addWidget(self.gui.module_info_desc)

        # Badges row (severity, status, payload count)
        badges_layout = QHBoxLayout()

        # Severity badge
        self.gui.severity_badge = QLabel("SEVERITY")
        self.gui.severity_badge.setStyleSheet("""
            background-color: #dc3545;
            color: white;
            padding: 4px 10px;
            border-radius: 12px;
            font-size: 10px;
            font-weight: bold;
        """)
        badges_layout.addWidget(self.gui.severity_badge)

        # Status badge
        self.gui.status_badge = QLabel("ENABLED")
        self.gui.status_badge.setStyleSheet("""
            background-color: #28a745;
            color: white;
            padding: 4px 10px;
            border-radius: 12px;
            font-size: 10px;
            font-weight: bold;
        """)
        badges_layout.addWidget(self.gui.status_badge)

        # Payload count badge
        self.gui.payload_badge = QLabel("0 Payloads")
        self.gui.payload_badge.setStyleSheet("""
            background-color: #6c757d;
            color: white;
            padding: 4px 10px;
            border-radius: 12px;
            font-size: 10px;
            font-weight: bold;
        """)
        badges_layout.addWidget(self.gui.payload_badge)

        badges_layout.addStretch()
        info_layout.addLayout(badges_layout)

        # Details grid (CWE, OWASP, CVSS)
        details_frame = QFrame()
        details_frame.setStyleSheet("""
            QFrame {
                background-color: #ffffff;
                border: 1px solid #e0e0e0;
                border-radius: 6px;
                padding: 10px;
            }
        """)
        details_grid = QGridLayout(details_frame)
        details_grid.setSpacing(8)

        # CWE
        cwe_label = QLabel("CWE:")
        cwe_label.setStyleSheet("font-weight: bold; color: #666666;")
        details_grid.addWidget(cwe_label, 0, 0)
        self.gui.module_cwe = QLabel("N/A")
        self.gui.module_cwe.setStyleSheet("color: #333333;")
        details_grid.addWidget(self.gui.module_cwe, 0, 1)

        # OWASP
        owasp_label = QLabel("OWASP:")
        owasp_label.setStyleSheet("font-weight: bold; color: #666666;")
        details_grid.addWidget(owasp_label, 0, 2)
        self.gui.module_owasp = QLabel("N/A")
        self.gui.module_owasp.setStyleSheet("color: #333333;")
        details_grid.addWidget(self.gui.module_owasp, 0, 3)

        # CVSS
        cvss_label = QLabel("CVSS:")
        cvss_label.setStyleSheet("font-weight: bold; color: #666666;")
        details_grid.addWidget(cvss_label, 1, 0)
        self.gui.module_cvss = QLabel("N/A")
        self.gui.module_cvss.setStyleSheet("color: #333333;")
        details_grid.addWidget(self.gui.module_cvss, 1, 1)

        # Timeout
        timeout_label = QLabel("Timeout:")
        timeout_label.setStyleSheet("font-weight: bold; color: #666666;")
        details_grid.addWidget(timeout_label, 1, 2)
        self.gui.module_timeout = QLabel("N/A")
        self.gui.module_timeout.setStyleSheet("color: #333333;")
        details_grid.addWidget(self.gui.module_timeout, 1, 3)

        details_grid.setColumnStretch(1, 1)
        details_grid.setColumnStretch(3, 1)

        info_layout.addWidget(details_frame)

        # Example payloads section
        examples_label = QLabel("Example Payloads:")
        examples_label.setStyleSheet("font-weight: bold; color: #666666; margin-top: 5px;")
        info_layout.addWidget(examples_label)

        self.gui.example_payloads = QTextEdit()
        self.gui.example_payloads.setReadOnly(True)
        self.gui.example_payloads.setMaximumHeight(60)
        self.gui.example_payloads.setStyleSheet("""
            QTextEdit {
                background-color: #f5f5f5;
                color: #333333;
                font-family: 'Consolas', 'Courier New', monospace;
                font-size: 10px;
                border: 1px solid #e0e0e0;
                border-radius: 4px;
                padding: 5px;
            }
        """)
        info_layout.addWidget(self.gui.example_payloads)

        info_group.setLayout(info_layout)
        return info_group

    def _create_config_editor(self):
        """Create config editor group"""
        config_group = QGroupBox("Module Configuration (config.json)")
        config_group.setStyleSheet("""
            QGroupBox {
                background-color: #f8f9fa;
                border: 1px solid #e0e0e0;
                border-radius: 8px;
                margin-top: 10px;
                padding: 15px;
                font-weight: bold;
            }
            QGroupBox::title {
                subcontrol-origin: margin;
                left: 10px;
                padding: 0 8px;
                color: #4CAF50;
                font-size: 12px;
            }
        """)
        config_layout = QVBoxLayout()

        config_help = QLabel("Edit module settings (name, severity, CWE, OWASP, etc.)")
        config_help.setStyleSheet("color: #888888; font-size: 10px;")
        config_layout.addWidget(config_help)

        self.gui.module_config_editor = QTextEdit()
        self.gui.module_config_editor.setStyleSheet("""
            QTextEdit {
                background-color: #ffffff;
                color: #333333;
                font-family: 'Consolas', 'Courier New', monospace;
                font-size: 11px;
                border: 1px solid #e0e0e0;
                border-radius: 4px;
                padding: 8px;
            }
            QTextEdit:focus {
                border: 2px solid #4CAF50;
            }
        """)
        config_layout.addWidget(self.gui.module_config_editor)

        config_btn_layout = QHBoxLayout()
        save_config_btn = QPushButton("Save Config")
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
        save_config_btn.clicked.connect(self.gui.save_module_config)
        config_btn_layout.addWidget(save_config_btn)

        reload_config_btn = QPushButton("Reload")
        reload_config_btn.setStyleSheet("""
            QPushButton {
                background-color: #f5f5f5;
                color: #333333;
                padding: 8px 16px;
                border-radius: 4px;
                border: 1px solid #cccccc;
            }
            QPushButton:hover {
                background-color: #e0e0e0;
            }
        """)
        reload_config_btn.clicked.connect(self.gui.reload_current_module)
        config_btn_layout.addWidget(reload_config_btn)

        config_btn_layout.addStretch()
        config_layout.addLayout(config_btn_layout)

        config_group.setLayout(config_layout)
        return config_group

    def _create_payloads_editor(self):
        """Create payloads editor group"""
        payloads_group = QGroupBox("Module Payloads (payloads.txt)")
        payloads_group.setStyleSheet("""
            QGroupBox {
                background-color: #f8f9fa;
                border: 1px solid #e0e0e0;
                border-radius: 8px;
                margin-top: 10px;
                padding: 15px;
                font-weight: bold;
            }
            QGroupBox::title {
                subcontrol-origin: margin;
                left: 10px;
                padding: 0 8px;
                color: #4CAF50;
                font-size: 12px;
            }
        """)
        payloads_layout = QVBoxLayout()

        payloads_help = QLabel("Edit payloads used by this module (one per line)")
        payloads_help.setStyleSheet("color: #888888; font-size: 10px;")
        payloads_layout.addWidget(payloads_help)

        # Payload stats
        self.gui.payload_stats_label = QLabel("Payloads: 0 | Lines: 0")
        self.gui.payload_stats_label.setStyleSheet("color: #4CAF50; font-weight: bold; padding: 5px;")
        payloads_layout.addWidget(self.gui.payload_stats_label)

        self.gui.module_payloads_editor = QTextEdit()
        self.gui.module_payloads_editor.setStyleSheet("""
            QTextEdit {
                background-color: #ffffff;
                color: #333333;
                font-family: 'Consolas', 'Courier New', monospace;
                font-size: 11px;
                border: 1px solid #e0e0e0;
                border-radius: 4px;
                padding: 8px;
            }
            QTextEdit:focus {
                border: 2px solid #4CAF50;
            }
        """)
        self.gui.module_payloads_editor.textChanged.connect(self.gui.update_payload_stats)
        payloads_layout.addWidget(self.gui.module_payloads_editor)

        payload_btn_layout = QHBoxLayout()
        save_payloads_btn = QPushButton("Save Payloads")
        save_payloads_btn.setStyleSheet("""
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
        save_payloads_btn.clicked.connect(self.gui.save_module_payloads)
        payload_btn_layout.addWidget(save_payloads_btn)

        reload_payloads_btn = QPushButton("Reload")
        reload_payloads_btn.setStyleSheet("""
            QPushButton {
                background-color: #f5f5f5;
                color: #333333;
                padding: 8px 16px;
                border-radius: 4px;
                border: 1px solid #cccccc;
            }
            QPushButton:hover {
                background-color: #e0e0e0;
            }
        """)
        reload_payloads_btn.clicked.connect(self.gui.reload_current_module)
        payload_btn_layout.addWidget(reload_payloads_btn)

        export_payloads_btn = QPushButton("Export")
        export_payloads_btn.setStyleSheet("""
            QPushButton {
                background-color: #e3f2fd;
                color: #1565c0;
                padding: 8px 16px;
                border-radius: 4px;
                border: 1px solid #90caf9;
            }
            QPushButton:hover {
                background-color: #bbdefb;
            }
        """)
        export_payloads_btn.clicked.connect(self.gui.export_module_payloads)
        payload_btn_layout.addWidget(export_payloads_btn)

        # Add Custom Payload button
        add_custom_btn = QPushButton("+ Add Custom")
        add_custom_btn.setStyleSheet("""
            QPushButton {
                background-color: #fff3e0;
                color: #e65100;
                padding: 8px 16px;
                border-radius: 4px;
                border: 1px solid #ffcc80;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: #ffe0b2;
            }
        """)
        add_custom_btn.setToolTip("Add a custom payload with metadata (author, date, description)")
        add_custom_btn.clicked.connect(self._show_add_custom_payload_dialog)
        payload_btn_layout.addWidget(add_custom_btn)

        # View Custom Payloads button
        view_custom_btn = QPushButton("View Custom")
        view_custom_btn.setStyleSheet("""
            QPushButton {
                background-color: #e8f5e9;
                color: #2e7d32;
                padding: 8px 16px;
                border-radius: 4px;
                border: 1px solid #a5d6a7;
            }
            QPushButton:hover {
                background-color: #c8e6c9;
            }
        """)
        view_custom_btn.setToolTip("View all custom payloads with their metadata")
        view_custom_btn.clicked.connect(self._show_custom_payloads_list)
        payload_btn_layout.addWidget(view_custom_btn)

        payload_btn_layout.addStretch()
        payloads_layout.addLayout(payload_btn_layout)

        payloads_group.setLayout(payloads_layout)
        return payloads_group

    def _show_add_custom_payload_dialog(self):
        """Show dialog to add a custom payload with metadata"""
        current_item = self.gui.module_list.currentItem()
        if not current_item:
            QMessageBox.warning(self.gui, "No Module Selected", "Please select a module first")
            return

        module_folder = current_item.data(Qt.UserRole)
        dialog = AddCustomPayloadDialog(module_folder, self.gui)
        if dialog.exec_() == QDialog.Accepted:
            # Refresh the payloads editor
            self.gui.reload_current_module()

    def _show_custom_payloads_list(self):
        """Show list of all custom payloads for current module"""
        current_item = self.gui.module_list.currentItem()
        if not current_item:
            QMessageBox.warning(self.gui, "No Module Selected", "Please select a module first")
            return

        module_folder = current_item.data(Qt.UserRole)
        dialog = ViewCustomPayloadsDialog(module_folder, self.gui)
        dialog.exec_()

    def _toggle_all_modules(self, enable):
        """Enable or disable all modules"""
        parent_dir = Path(__file__).parent.parent.parent
        modules_dir = parent_dir / "modules"

        if not modules_dir.exists():
            return

        for module_path in modules_dir.iterdir():
            if module_path.is_dir() and not module_path.name.startswith('_'):
                config_file = module_path / "config.json"
                if config_file.exists():
                    try:
                        with open(config_file, 'r', encoding='utf-8') as f:
                            config = json.load(f)
                        config['enabled'] = enable
                        with open(config_file, 'w', encoding='utf-8') as f:
                            json.dump(config, f, indent=2)
                    except:
                        pass

        # Refresh the list
        self.gui.load_modules_list()

    def _toggle_current_module(self):
        """Toggle the current module's enabled status"""
        current_item = self.gui.module_list.currentItem()
        if not current_item:
            return

        module_folder = current_item.data(Qt.UserRole)
        parent_dir = Path(__file__).parent.parent.parent
        config_file = parent_dir / "modules" / module_folder / "config.json"

        if config_file.exists():
            try:
                with open(config_file, 'r', encoding='utf-8') as f:
                    config = json.load(f)
                config['enabled'] = not config.get('enabled', True)
                with open(config_file, 'w', encoding='utf-8') as f:
                    json.dump(config, f, indent=2)

                # Update the info panel
                self._update_info_panel(config)

                # Reload the module data in editor
                self.gui.load_module_data(module_folder)

                # Update status badge
                if config['enabled']:
                    self.gui.status_badge.setText("ENABLED")
                    self.gui.status_badge.setStyleSheet("""
                        background-color: #28a745;
                        color: white;
                        padding: 4px 10px;
                        border-radius: 12px;
                        font-size: 10px;
                        font-weight: bold;
                    """)
                else:
                    self.gui.status_badge.setText("DISABLED")
                    self.gui.status_badge.setStyleSheet("""
                        background-color: #dc3545;
                        color: white;
                        padding: 4px 10px;
                        border-radius: 12px;
                        font-size: 10px;
                        font-weight: bold;
                    """)
            except Exception as e:
                print(f"Error toggling module: {e}")

    def _reset_current_module(self):
        """Reset current module to default (placeholder - would need backup files)"""
        from PyQt5.QtWidgets import QMessageBox
        QMessageBox.information(
            self.gui, "Reset Module",
            "This would reset the module to its default configuration.\n"
            "Feature coming soon!"
        )

    def _on_current_item_changed(self, current, previous):
        """Handle arrow key navigation - update info panel when selection changes"""
        if current:
            module_folder = current.data(Qt.UserRole)
            if module_folder:
                # Update the info panel
                update_module_info_panel(self.gui, module_folder)
                # Load module data in editors
                self.gui.load_module_data(module_folder)

    def _set_type_filter(self, filter_type):
        """Set the type filter (all/active/passive)"""
        self.current_type_filter = filter_type

        # Update button styles
        btn_style_inactive = """
            QPushButton {
                background-color: #f5f5f5;
                color: #666666;
                border: 1px solid #cccccc;
                border-radius: 4px;
                padding: 4px 10px;
                font-size: 10px;
            }
            QPushButton:hover {
                background-color: #e0e0e0;
            }
        """
        btn_style_active = """
            QPushButton {
                background-color: #4CAF50;
                color: white;
                border: 1px solid #4CAF50;
                border-radius: 4px;
                padding: 4px 10px;
                font-size: 10px;
                font-weight: bold;
            }
        """

        self.filter_all_btn.setStyleSheet(btn_style_active if filter_type == "all" else btn_style_inactive)
        self.filter_active_btn.setStyleSheet(btn_style_active if filter_type == "active" else btn_style_inactive)
        self.filter_passive_btn.setStyleSheet(btn_style_active if filter_type == "passive" else btn_style_inactive)

        self._apply_filters()

    def _set_sort(self, sort_text):
        """Set the sort method"""
        self.current_sort = sort_text.lower()
        self._apply_filters()

    def _refresh_modules(self):
        """Refresh modules list and clear cache"""
        self.module_data_cache = {}
        self.gui.load_modules_list()
        self._apply_filters()

    def _get_all_module_data(self):
        """Get all module data with extended info for filtering/sorting"""
        parent_dir = Path(__file__).parent.parent.parent
        modules_dir = parent_dir / "modules"

        modules = []
        if not modules_dir.exists():
            return modules

        for module_path in modules_dir.iterdir():
            if module_path.is_dir() and not module_path.name.startswith('_'):
                config_file = module_path / "config.json"
                payloads_file = module_path / "payloads.txt"

                # Default values
                module_data = {
                    'folder': module_path.name,
                    'name': module_path.name.upper(),
                    'description': f'Module: {module_path.name}',
                    'enabled': True,
                    'passive': False,
                    'severity': 'medium',
                    'payload_count': 0,
                    'modified': 0
                }

                # Load config
                if config_file.exists():
                    try:
                        with open(config_file, 'r', encoding='utf-8') as f:
                            config = json.load(f)
                            module_data['name'] = config.get('name', module_data['name'])
                            module_data['description'] = config.get('description', module_data['description'])
                            module_data['enabled'] = config.get('enabled', True)
                            module_data['passive'] = config.get('passive', False)
                            module_data['severity'] = config.get('severity', 'medium')
                    except:
                        pass

                # Count payloads
                if payloads_file.exists():
                    try:
                        with open(payloads_file, 'r', encoding='utf-8') as f:
                            lines = f.readlines()
                            module_data['payload_count'] = len([l for l in lines if l.strip() and not l.strip().startswith('#')])
                        module_data['modified'] = os.path.getmtime(payloads_file)
                    except:
                        pass

                # Check config modification time as fallback
                if config_file.exists() and module_data['modified'] == 0:
                    try:
                        module_data['modified'] = os.path.getmtime(config_file)
                    except:
                        pass

                modules.append(module_data)

        return modules

    def _apply_filters(self):
        """Apply current filters and sorting to the module list"""
        modules = self._get_all_module_data()
        search_text = self.gui.module_search.text().lower() if hasattr(self.gui, 'module_search') else ""

        # Filter by type
        if self.current_type_filter == "active":
            modules = [m for m in modules if not m['passive']]
        elif self.current_type_filter == "passive":
            modules = [m for m in modules if m['passive']]

        # Filter by search text
        if search_text:
            modules = [m for m in modules if search_text in m['folder'].lower() or
                       search_text in m['name'].lower() or
                       search_text in m['description'].lower()]

        # Sort
        severity_order = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3, 'info': 4}

        if self.current_sort == "name":
            modules.sort(key=lambda x: x['folder'].lower())
        elif self.current_sort == "payloads":
            modules.sort(key=lambda x: x['payload_count'], reverse=True)
        elif self.current_sort == "modified":
            modules.sort(key=lambda x: x['modified'], reverse=True)
        elif self.current_sort == "enabled":
            modules.sort(key=lambda x: (0 if x['enabled'] else 1, x['folder'].lower()))
        elif self.current_sort == "severity":
            modules.sort(key=lambda x: severity_order.get(x['severity'].lower(), 5))

        # Update list widget
        self.gui.module_list.clear()

        for mod in modules:
            # Create item text with icons
            status_icon = "✓" if mod['enabled'] else "✗"
            passive_tag = " [P]" if mod['passive'] else ""
            payload_info = f" ({mod['payload_count']})" if mod['payload_count'] > 0 else ""

            item_text = f"{status_icon} {mod['folder']}{passive_tag}{payload_info}"

            item = QListWidgetItem(item_text)
            item.setData(Qt.UserRole, mod['folder'])

            # Color based on status
            if not mod['enabled']:
                item.setForeground(QColor('#999999'))

            self.gui.module_list.addItem(item)

        # Update count label
        total = len(self._get_all_module_data())
        shown = len(modules)
        passive_count = len([m for m in self._get_all_module_data() if m['passive']])
        active_count = total - passive_count

        self.gui.module_count_label.setText(
            f"Showing: {shown}/{total} | Active: {active_count} | Passive: {passive_count}"
        )

    def _update_info_panel(self, config):
        """Update the info panel with module configuration data"""
        # Update name
        self.gui.module_info_name.setText(config.get('name', 'Unknown Module'))

        # Update description
        self.gui.module_info_desc.setText(config.get('description', 'No description available'))

        # Update severity badge
        severity = config.get('severity', 'Info')
        severity_colors = {
            'Critical': '#dc3545',
            'High': '#fd7e14',
            'Medium': '#ffc107',
            'Low': '#28a745',
            'Info': '#17a2b8'
        }
        color = severity_colors.get(severity, '#6c757d')
        self.gui.severity_badge.setText(severity.upper())
        self.gui.severity_badge.setStyleSheet(f"""
            background-color: {color};
            color: white;
            padding: 4px 10px;
            border-radius: 12px;
            font-size: 10px;
            font-weight: bold;
        """)

        # Update status badge
        enabled = config.get('enabled', True)
        if enabled:
            self.gui.status_badge.setText("ENABLED")
            self.gui.status_badge.setStyleSheet("""
                background-color: #28a745;
                color: white;
                padding: 4px 10px;
                border-radius: 12px;
                font-size: 10px;
                font-weight: bold;
            """)
        else:
            self.gui.status_badge.setText("DISABLED")
            self.gui.status_badge.setStyleSheet("""
                background-color: #dc3545;
                color: white;
                padding: 4px 10px;
                border-radius: 12px;
                font-size: 10px;
                font-weight: bold;
            """)

        # Update CWE
        cwe = config.get('cwe', 'N/A')
        cwe_name = config.get('cwe_name', '')
        if cwe_name:
            self.gui.module_cwe.setText(f"{cwe} - {cwe_name}")
        else:
            self.gui.module_cwe.setText(cwe)

        # Update OWASP
        owasp = config.get('owasp', 'N/A')
        owasp_name = config.get('owasp_name', '')
        if owasp_name:
            self.gui.module_owasp.setText(f"{owasp} - {owasp_name}")
        else:
            self.gui.module_owasp.setText(owasp)

        # Update CVSS
        cvss = config.get('cvss', 'N/A')
        cvss_vector = config.get('cvss_vector', '')
        if cvss_vector:
            self.gui.module_cvss.setText(f"{cvss} ({cvss_vector[:20]}...)")
        else:
            self.gui.module_cvss.setText(str(cvss))

        # Update timeout
        timeout = config.get('timeout', 'Default')
        self.gui.module_timeout.setText(f"{timeout}s")


def update_module_info_panel(gui, module_folder):
    """Helper function to update the info panel when a module is selected"""
    parent_dir = Path(__file__).parent.parent.parent
    config_file = parent_dir / "modules" / module_folder / "config.json"
    payloads_file = parent_dir / "modules" / module_folder / "payloads.txt"

    # Load config
    config = {}
    if config_file.exists():
        try:
            with open(config_file, 'r', encoding='utf-8') as f:
                config = json.load(f)
        except:
            pass

    # Update name
    gui.module_info_name.setText(config.get('name', module_folder.upper()))

    # Update description
    gui.module_info_desc.setText(config.get('description', 'No description available'))

    # Update severity badge
    severity = config.get('severity', 'Info')
    severity_colors = {
        'Critical': '#dc3545',
        'High': '#fd7e14',
        'Medium': '#ffc107',
        'Low': '#28a745',
        'Info': '#17a2b8'
    }
    color = severity_colors.get(severity, '#6c757d')
    gui.severity_badge.setText(severity.upper())
    gui.severity_badge.setStyleSheet(f"""
        background-color: {color};
        color: white;
        padding: 4px 10px;
        border-radius: 12px;
        font-size: 10px;
        font-weight: bold;
    """)

    # Update status badge
    enabled = config.get('enabled', True)
    if enabled:
        gui.status_badge.setText("ENABLED")
        gui.status_badge.setStyleSheet("""
            background-color: #28a745;
            color: white;
            padding: 4px 10px;
            border-radius: 12px;
            font-size: 10px;
            font-weight: bold;
        """)
    else:
        gui.status_badge.setText("DISABLED")
        gui.status_badge.setStyleSheet("""
            background-color: #dc3545;
            color: white;
            padding: 4px 10px;
            border-radius: 12px;
            font-size: 10px;
            font-weight: bold;
        """)

    # Count payloads
    payload_count = 0
    if payloads_file.exists():
        try:
            with open(payloads_file, 'r', encoding='utf-8') as f:
                lines = f.readlines()
                payload_count = len([l for l in lines if l.strip() and not l.strip().startswith('#')])
        except:
            pass

    gui.payload_badge.setText(f"{payload_count} Payloads")

    # Update CWE
    cwe = config.get('cwe', 'N/A')
    cwe_name = config.get('cwe_name', '')
    if cwe_name:
        gui.module_cwe.setText(f"{cwe}")
        gui.module_cwe.setToolTip(cwe_name)
    else:
        gui.module_cwe.setText(cwe)

    # Update OWASP
    owasp = config.get('owasp', 'N/A')
    owasp_name = config.get('owasp_name', '')
    if owasp_name:
        gui.module_owasp.setText(f"{owasp}")
        gui.module_owasp.setToolTip(owasp_name)
    else:
        gui.module_owasp.setText(owasp)

    # Update CVSS
    cvss = config.get('cvss', 'N/A')
    gui.module_cvss.setText(str(cvss))
    if config.get('cvss_vector'):
        gui.module_cvss.setToolTip(config.get('cvss_vector', ''))

    # Update timeout
    timeout = config.get('timeout', 'Default')
    gui.module_timeout.setText(f"{timeout}s")

    # Show example payloads
    if payloads_file.exists():
        try:
            with open(payloads_file, 'r', encoding='utf-8') as f:
                lines = f.readlines()
                # Get first 5 non-comment payloads
                examples = []
                for line in lines:
                    line = line.strip()
                    if line and not line.startswith('#'):
                        examples.append(line)
                        if len(examples) >= 5:
                            break
                gui.example_payloads.setPlainText('\n'.join(examples))
        except:
            gui.example_payloads.setPlainText('Error loading payloads')
    else:
        gui.example_payloads.setPlainText('No payloads file found')


class AddCustomPayloadDialog(QDialog):
    """Dialog for adding a custom payload with metadata"""

    def __init__(self, module_folder, parent=None):
        super().__init__(parent)
        self.module_folder = module_folder
        self.setWindowTitle(f"Add Custom Payload - {module_folder}")
        self.resize(500, 400)
        self.init_ui()

    def init_ui(self):
        """Initialize the dialog UI"""
        self.setStyleSheet("""
            QDialog {
                background-color: #ffffff;
                color: #333333;
            }
            QLabel {
                color: #333333;
            }
            QLineEdit, QTextEdit {
                background-color: #ffffff;
                color: #333333;
                border: 1px solid #cccccc;
                border-radius: 4px;
                padding: 8px;
            }
            QLineEdit:focus, QTextEdit:focus {
                border: 2px solid #4CAF50;
            }
        """)

        layout = QVBoxLayout(self)

        # Form layout for metadata
        form_layout = QFormLayout()

        # Payload input
        self.payload_input = QTextEdit()
        self.payload_input.setPlaceholderText("Enter payload(s) - one per line")
        self.payload_input.setMaximumHeight(100)
        form_layout.addRow("Payload(s):", self.payload_input)

        # Author name
        self.author_input = QLineEdit()
        self.author_input.setPlaceholderText("Your name or alias")
        form_layout.addRow("Author:", self.author_input)

        # Description
        self.description_input = QLineEdit()
        self.description_input.setPlaceholderText("What this payload tests for")
        form_layout.addRow("Description:", self.description_input)

        # Tags/Category
        self.tags_input = QLineEdit()
        self.tags_input.setPlaceholderText("e.g., bypass, evasion, waf-bypass (comma-separated)")
        form_layout.addRow("Tags:", self.tags_input)

        # Source/Reference
        self.source_input = QLineEdit()
        self.source_input.setPlaceholderText("URL or reference (optional)")
        form_layout.addRow("Source:", self.source_input)

        layout.addLayout(form_layout)

        # Info label
        info_label = QLabel(
            "Custom payloads are tracked with metadata including date added.\n"
            "They will be appended to the module's payloads.txt file."
        )
        info_label.setStyleSheet("color: #888888; font-size: 11px; padding: 10px;")
        info_label.setWordWrap(True)
        layout.addWidget(info_label)

        # Buttons
        btn_layout = QHBoxLayout()
        btn_layout.addStretch()

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

        add_btn = QPushButton("Add Payload")
        add_btn.setStyleSheet("""
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
        add_btn.clicked.connect(self.add_payload)
        btn_layout.addWidget(add_btn)

        layout.addLayout(btn_layout)

    def add_payload(self):
        """Add the custom payload to the module"""
        payload_text = self.payload_input.toPlainText().strip()
        if not payload_text:
            QMessageBox.warning(self, "Missing Payload", "Please enter at least one payload")
            return

        author = self.author_input.text().strip() or "Anonymous"
        description = self.description_input.text().strip() or "Custom payload"
        tags = self.tags_input.text().strip()
        source = self.source_input.text().strip()

        # Get paths
        parent_dir = Path(__file__).parent.parent.parent
        module_path = parent_dir / "modules" / self.module_folder
        payloads_file = module_path / "payloads.txt"
        custom_meta_file = module_path / "custom_payloads.json"

        # Parse payloads (one per line)
        payloads = [p.strip() for p in payload_text.split('\n') if p.strip()]

        # Load existing custom payloads metadata
        custom_meta = []
        if custom_meta_file.exists():
            try:
                with open(custom_meta_file, 'r', encoding='utf-8') as f:
                    custom_meta = json.load(f)
            except:
                pass

        # Add to payloads.txt
        try:
            with open(payloads_file, 'a', encoding='utf-8') as f:
                f.write(f"\n# Custom payload by {author} - {datetime.now().strftime('%Y-%m-%d %H:%M')}\n")
                for payload in payloads:
                    f.write(f"{payload}\n")
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to add payload: {e}")
            return

        # Save metadata
        for payload in payloads:
            meta_entry = {
                "payload": payload,
                "author": author,
                "description": description,
                "tags": [t.strip() for t in tags.split(',') if t.strip()],
                "source": source,
                "date_added": datetime.now().isoformat(),
                "module": self.module_folder
            }
            custom_meta.append(meta_entry)

        try:
            with open(custom_meta_file, 'w', encoding='utf-8') as f:
                json.dump(custom_meta, f, indent=2)
        except Exception as e:
            # Non-critical - metadata save failed but payload was added
            print(f"Warning: Could not save metadata: {e}")

        QMessageBox.information(
            self, "Success",
            f"Added {len(payloads)} custom payload(s) to {self.module_folder}\n\n"
            f"Author: {author}\n"
            f"Date: {datetime.now().strftime('%Y-%m-%d %H:%M')}"
        )
        self.accept()


class ViewCustomPayloadsDialog(QDialog):
    """Dialog for viewing and managing custom payloads"""

    def __init__(self, module_folder, parent=None):
        super().__init__(parent)
        self.module_folder = module_folder
        self.setWindowTitle(f"Custom Payloads - {module_folder}")
        self.resize(700, 500)
        self.init_ui()
        self.load_custom_payloads()

    def init_ui(self):
        """Initialize the dialog UI"""
        self.setStyleSheet("""
            QDialog {
                background-color: #ffffff;
                color: #333333;
            }
            QLabel {
                color: #333333;
            }
            QListWidget {
                background-color: #ffffff;
                color: #333333;
                border: 1px solid #e0e0e0;
                border-radius: 4px;
            }
            QListWidget::item {
                padding: 8px;
                border-bottom: 1px solid #f0f0f0;
            }
            QListWidget::item:selected {
                background-color: #4CAF50;
                color: white;
            }
        """)

        layout = QVBoxLayout(self)

        # Header
        header = QLabel(f"Custom Payloads for {self.module_folder}")
        header.setStyleSheet("font-size: 16px; font-weight: bold; color: #4CAF50; padding: 10px;")
        layout.addWidget(header)

        # Payload list
        self.payload_list = QListWidget()
        self.payload_list.itemClicked.connect(self.show_payload_details)
        layout.addWidget(self.payload_list)

        # Details panel
        details_group = QGroupBox("Payload Details")
        details_group.setStyleSheet("""
            QGroupBox {
                background-color: #f8f8f8;
                border: 1px solid #e0e0e0;
                border-radius: 6px;
                margin-top: 10px;
                padding: 10px;
                font-weight: bold;
            }
            QGroupBox::title {
                color: #4CAF50;
            }
        """)
        details_layout = QVBoxLayout()

        self.details_text = QTextEdit()
        self.details_text.setReadOnly(True)
        self.details_text.setMaximumHeight(150)
        self.details_text.setStyleSheet("""
            QTextEdit {
                background-color: #ffffff;
                color: #333333;
                border: 1px solid #e0e0e0;
                border-radius: 4px;
                font-family: 'Consolas', monospace;
                font-size: 11px;
            }
        """)
        details_layout.addWidget(self.details_text)
        details_group.setLayout(details_layout)
        layout.addWidget(details_group)

        # Buttons
        btn_layout = QHBoxLayout()

        delete_btn = QPushButton("Delete Selected")
        delete_btn.setStyleSheet("""
            QPushButton {
                background-color: #ffebee;
                color: #c62828;
                padding: 8px 16px;
                border-radius: 4px;
                border: 1px solid #ef9a9a;
            }
            QPushButton:hover {
                background-color: #ffcdd2;
            }
        """)
        delete_btn.clicked.connect(self.delete_selected)
        btn_layout.addWidget(delete_btn)

        btn_layout.addStretch()

        close_btn = QPushButton("Close")
        close_btn.setStyleSheet("""
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
        close_btn.clicked.connect(self.accept)
        btn_layout.addWidget(close_btn)

        layout.addLayout(btn_layout)

    def load_custom_payloads(self):
        """Load custom payloads from metadata file"""
        parent_dir = Path(__file__).parent.parent.parent
        custom_meta_file = parent_dir / "modules" / self.module_folder / "custom_payloads.json"

        self.custom_payloads = []
        if custom_meta_file.exists():
            try:
                with open(custom_meta_file, 'r', encoding='utf-8') as f:
                    self.custom_payloads = json.load(f)
            except:
                pass

        self.payload_list.clear()
        if not self.custom_payloads:
            item = QListWidgetItem("No custom payloads found")
            item.setFlags(item.flags() & ~Qt.ItemIsSelectable)
            self.payload_list.addItem(item)
            return

        for i, payload_data in enumerate(self.custom_payloads):
            payload = payload_data.get('payload', '')[:50]
            author = payload_data.get('author', 'Unknown')
            date = payload_data.get('date_added', '')[:10]

            item_text = f"{payload}... | By: {author} | {date}"
            item = QListWidgetItem(item_text)
            item.setData(Qt.UserRole, i)
            self.payload_list.addItem(item)

    def show_payload_details(self, item):
        """Show details for selected payload"""
        index = item.data(Qt.UserRole)
        if index is None or index >= len(self.custom_payloads):
            return

        payload_data = self.custom_payloads[index]
        details = f"""Payload: {payload_data.get('payload', 'N/A')}

Author: {payload_data.get('author', 'Unknown')}
Date Added: {payload_data.get('date_added', 'N/A')}
Description: {payload_data.get('description', 'N/A')}
Tags: {', '.join(payload_data.get('tags', []))}
Source: {payload_data.get('source', 'N/A')}"""

        self.details_text.setPlainText(details)

    def delete_selected(self):
        """Delete selected custom payload"""
        current_item = self.payload_list.currentItem()
        if not current_item:
            return

        index = current_item.data(Qt.UserRole)
        if index is None or index >= len(self.custom_payloads):
            return

        payload = self.custom_payloads[index].get('payload', '')

        reply = QMessageBox.question(
            self, "Delete Custom Payload",
            f"Are you sure you want to delete this payload?\n\n{payload[:100]}",
            QMessageBox.Yes | QMessageBox.No
        )

        if reply == QMessageBox.Yes:
            # Remove from metadata
            del self.custom_payloads[index]

            # Save updated metadata
            parent_dir = Path(__file__).parent.parent.parent
            custom_meta_file = parent_dir / "modules" / self.module_folder / "custom_payloads.json"

            try:
                with open(custom_meta_file, 'w', encoding='utf-8') as f:
                    json.dump(self.custom_payloads, f, indent=2)
            except Exception as e:
                QMessageBox.warning(self, "Error", f"Failed to update metadata: {e}")

            # Note: We don't remove from payloads.txt as that would be complex
            # The metadata file is the source of truth for custom payloads

            # Reload list
            self.load_custom_payloads()
            self.details_text.clear()
