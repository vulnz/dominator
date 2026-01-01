"""
Scan Configuration Tab - Modern, Clean Design
Logical grouping with clear descriptions and large, readable fonts
"""

import json
import os
from pathlib import Path

from PyQt5.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QGridLayout,
    QGroupBox, QLabel, QLineEdit, QTextEdit, QPushButton,
    QCheckBox, QSpinBox, QComboBox, QScrollArea, QFrame
)
from PyQt5.QtCore import Qt


def load_modules_from_folder():
    """Dynamically load all modules from modules/ directory with categories"""
    modules = {}

    # Find modules directory
    script_dir = Path(__file__).parent.parent.parent  # Go up to dominator root
    modules_dir = script_dir / "modules"

    if not modules_dir.exists():
        return modules

    # Default icons by category/type
    DEFAULT_ICONS = {
        "injection": "💉", "xss": "🔥", "sqli": "💉", "cmdi": "⚡", "ssti": "📝",
        "xxe": "📄", "lfi": "📁", "rfi": "🌐", "ssrf": "🔗", "csrf": "🎭",
        "idor": "🔓", "redirect": "↪️", "upload": "📤", "file": "📁",
        "api": "🔌", "auth": "🔑", "crypto": "🔐", "recon": "🔍",
        "dir": "🗂️", "git": "📦", "backup": "💾", "config": "⚙️",
        "header": "📋", "ssl": "🔒", "cors": "🌐", "jwt": "🎫",
        "websocket": "🔌", "graphql": "📊", "subdomain": "🌍",
        "port": "🔌", "js": "📜", "dom": "💻", "session": "🍪",
        "security": "🛡️", "sensitive": "🔍", "default": "🔧"
    }

    # Category mappings for modules
    CATEGORY_MAP = {
        # Injection
        "sqli": "Injection", "xss": "Injection", "cmdi": "Injection", "ssti": "Injection",
        "xxe": "Injection", "xpath": "Injection", "nosql": "Injection", "ldap": "Injection",
        "ssi": "Injection", "formula": "Injection", "crlf": "Injection", "header_injection": "Injection",
        # File & Path
        "lfi": "File & Path", "rfi": "File & Path", "path": "File & Path", "file_upload": "File & Path",
        # Authentication & Session
        "csrf": "Auth & Session", "session": "Auth & Session", "jwt": "Auth & Session",
        "weak_credentials": "Auth & Session", "idor": "Auth & Session", "auth": "Auth & Session",
        # API Security
        "api": "API Security", "graphql": "API Security", "soap": "API Security", "websocket": "API Security",
        # Recon & Discovery
        "dirbrute": "Recon", "subdomain": "Recon", "port": "Recon", "param": "Recon",
        "favicon": "Recon", "robots": "Recon", "sensitive": "Recon",
        # Information Disclosure
        "git": "Info Disclosure", "env": "Info Disclosure", "backup": "Info Disclosure",
        "config": "Info Disclosure", "debug": "Info Disclosure", "package": "Info Disclosure",
        "phpinfo": "Info Disclosure", "db_exposure": "Info Disclosure", "base64": "Info Disclosure",
        # Server & Network
        "ssrf": "Server & Network", "redirect": "Server & Network", "smuggling": "Server & Network",
        "host_header": "Server & Network", "cors": "Server & Network", "http_methods": "Server & Network",
        "forbidden": "Server & Network", "cgi": "Server & Network", "iis": "Server & Network", "hpp": "Server & Network",
        # Security Headers & Config
        "ssl": "Security Config", "security_headers": "Security Config", "csp": "Security Config",
        "tabnabbing": "Security Config", "cspt": "Security Config",
        # Advanced Attacks
        "dom_xss": "Advanced", "prototype": "Advanced", "php_object": "Advanced",
        "type_juggling": "Advanced", "request_smuggling": "Advanced",
        # Cloud & Storage
        "cloud": "Cloud", "storage": "Cloud",
    }

    for module_path in sorted(modules_dir.iterdir()):
        if not module_path.is_dir() or module_path.name.startswith('_'):
            continue

        # Skip utility modules that don't have scanning capability
        if module_path.name in ['oob_detection']:
            continue

        config_file = module_path / "config.json"
        toml_file = module_path / "config.toml"

        # Default values
        module_id = module_path.name
        name = module_id.replace('_', ' ').title()
        desc = f"Module: {module_id}"
        passive = False
        enabled = True
        category = "Other"

        # Try to load config (prefer TOML, fallback to JSON)
        config = {}
        if toml_file.exists():
            try:
                import tomllib
                with open(toml_file, 'rb') as f:
                    config = tomllib.load(f)
            except:
                pass

        if not config and config_file.exists():
            try:
                with open(config_file, 'r', encoding='utf-8') as f:
                    config = json.load(f)
            except:
                pass

        if config:
            name = config.get('name', name)
            desc = config.get('description', desc)
            passive = config.get('passive', False)
            enabled = config.get('enabled', True)
            category = config.get('category', category)

        # Skip disabled modules
        if not enabled:
            continue

        # Auto-detect category from module name if not in config
        if category == "Other":
            module_lower = module_id.lower()
            for key, cat in CATEGORY_MAP.items():
                if key in module_lower:
                    category = cat
                    break

        # Determine icon based on module name
        icon = "🔧"
        module_lower = module_id.lower()
        for key, emoji in DEFAULT_ICONS.items():
            if key in module_lower:
                icon = emoji
                break

        # Truncate description if too long
        if len(desc) > 40:
            desc = desc[:37] + "..."

        modules[module_id] = {
            "name": name,
            "desc": desc,
            "active": not passive,
            "icon": icon,
            "category": category
        }

    return modules


class ScanTabBuilder:
    """Builder class for creating the Scan Configuration tab"""

    # Dynamically load modules from modules/ folder
    MODULE_INFO = load_modules_from_folder()

    # Legacy module descriptions for backwards compatibility
    MODULE_DESCRIPTIONS = {k: v["desc"] for k, v in MODULE_INFO.items()}
    MODULE_CATEGORIES = {}  # Not used in new design

    def __init__(self, gui, collapsible_box_class):
        """Initialize the builder"""
        self.gui = gui
        self.CollapsibleBox = collapsible_box_class

    def build(self):
        """Create and return the scan configuration tab"""
        widget = QWidget()
        main_layout = QVBoxLayout(widget)

        # Scroll area for content
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QScrollArea.NoFrame)

        scroll_content = QWidget()
        layout = QVBoxLayout(scroll_content)
        layout.setSpacing(15)

        # 1. Target + Scan Buttons
        target_group = self._create_target_section()
        layout.addWidget(target_group)

        # 2. Quick Presets
        presets_group = self._create_presets_section()
        layout.addWidget(presets_group)

        # 3. Module Selection (Active/Passive)
        modules_group = self._create_modules_section()
        layout.addWidget(modules_group)

        # 4. Scan Settings
        settings_group = self._create_settings_section()
        layout.addWidget(settings_group)

        # 5. Advanced Options (collapsed)
        advanced_group = self._create_advanced_section()
        layout.addWidget(advanced_group)

        layout.addStretch()

        scroll.setWidget(scroll_content)
        main_layout.addWidget(scroll)

        return widget

    def _create_target_section(self):
        """Target input + Scan buttons"""
        group = QGroupBox("🎯 Target & Scan Control")
        group.setStyleSheet("""
            QGroupBox {
                background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
                    stop:0 #ffffff, stop:1 #f8f9fa);
                border: 3px solid #4CAF50;
                border-radius: 12px;
                margin-top: 15px;
                padding: 20px 15px 15px 15px;
                font-size: 16px;
                font-weight: bold;
                color: #2e7d32;
            }
            QGroupBox::title {
                subcontrol-origin: margin;
                left: 20px;
                padding: 5px 15px;
                background-color: #ffffff;
                border-radius: 6px;
            }
        """)

        layout = QVBoxLayout()
        layout.setSpacing(12)

        # Target URL input
        target_label = QLabel("Enter Target URL(s), IP(s), or Domain(s):")
        target_label.setStyleSheet("font-size: 13px; color: #424242; font-weight: normal;")
        layout.addWidget(target_label)

        self.gui.target_input = QTextEdit()
        self.gui.target_input.setPlaceholderText(
            "One per line. Examples:\n\n"
            "• http://example.com/admin\n"
            "• 192.168.1.1\n"
            "• test.local\n"
            "• 192.168.1.0/24 (CIDR)\n"
            "• 192.168.1.1-50 (range)"
        )
        self.gui.target_input.setMinimumHeight(140)
        self.gui.target_input.setMaximumHeight(180)
        self.gui.target_input.setStyleSheet("""
            QTextEdit {
                background-color: #ffffff;
                color: #212121;
                border: 2px solid #e0e0e0;
                border-radius: 8px;
                padding: 10px;
                font-family: 'Consolas', 'Courier New', monospace;
                font-size: 13px;
                line-height: 1.5;
            }
            QTextEdit:focus {
                border: 2px solid #4CAF50;
                background-color: #f1f8e9;
            }
        """)
        layout.addWidget(self.gui.target_input)

        # File input (optional)
        file_layout = QHBoxLayout()
        file_label = QLabel("📄 Or load from file:")
        file_label.setStyleSheet("font-size: 13px; color: #424242; font-weight: normal;")
        file_layout.addWidget(file_label)

        self.gui.target_file_input = QLineEdit()
        self.gui.target_file_input.setPlaceholderText("targets.txt")
        self.gui.target_file_input.setStyleSheet("""
            QLineEdit {
                background-color: #ffffff;
                border: 2px solid #e0e0e0;
                border-radius: 6px;
                padding: 8px;
                color: #212121;
                font-size: 12px;
            }
            QLineEdit:focus {border: 2px solid #4CAF50;}
        """)
        file_layout.addWidget(self.gui.target_file_input)

        browse_btn = QPushButton("Browse...")
        browse_btn.setStyleSheet("""
            QPushButton {
                background-color: #4CAF50;
                color: white;
                border: none;
                border-radius: 6px;
                padding: 8px 20px;
                font-weight: bold;
                font-size: 12px;
            }
            QPushButton:hover {background-color: #45a049;}
            QPushButton:pressed {background-color: #3d8b40;}
        """)
        browse_btn.clicked.connect(self.gui.browse_target_file)
        file_layout.addWidget(browse_btn)
        layout.addLayout(file_layout)

        # SCAN BUTTONS - Right here under target!
        btn_layout = QHBoxLayout()
        btn_layout.setSpacing(10)

        # Start
        self.gui.start_btn = QPushButton("▶️  START SCAN")
        self.gui.start_btn.setStyleSheet("""
            QPushButton {
                background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
                    stop:0 #66BB6A, stop:1 #4CAF50);
                color: white;
                font-size: 14px;
                font-weight: bold;
                padding: 12px 30px;
                border-radius: 8px;
                border: none;
            }
            QPushButton:hover {
                background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
                    stop:0 #4CAF50, stop:1 #45a049);
            }
        """)
        self.gui.start_btn.clicked.connect(self.gui.start_scan)
        btn_layout.addWidget(self.gui.start_btn)

        # Pause
        self.gui.pause_btn = QPushButton("⏸️  Pause")
        self.gui.pause_btn.setStyleSheet("""
            QPushButton {
                background-color: #FF9800;
                color: white;
                font-size: 13px;
                font-weight: bold;
                padding: 10px 20px;
                border-radius: 6px;
            }
            QPushButton:hover {background-color: #F57C00;}
        """)
        self.gui.pause_btn.clicked.connect(self.gui.toggle_pause_scan)
        btn_layout.addWidget(self.gui.pause_btn)

        # Stop
        self.gui.stop_btn = QPushButton("⏹️  Stop")
        self.gui.stop_btn.setStyleSheet("""
            QPushButton {
                background-color: #f44336;
                color: white;
                font-size: 13px;
                font-weight: bold;
                padding: 10px 20px;
                border-radius: 6px;
            }
            QPushButton:hover {background-color: #d32f2f;}
        """)
        self.gui.stop_btn.clicked.connect(self.gui.stop_scan)
        btn_layout.addWidget(self.gui.stop_btn)

        # Wizard
        self.gui.wizard_btn = QPushButton("🧙  Wizard")
        self.gui.wizard_btn.setStyleSheet("""
            QPushButton {
                background-color: #2196F3;
                color: white;
                font-size: 13px;
                font-weight: bold;
                padding: 10px 20px;
                border-radius: 6px;
            }
            QPushButton:hover {background-color: #1976D2;}
        """)
        self.gui.wizard_btn.clicked.connect(self.gui.show_scan_wizard)
        btn_layout.addWidget(self.gui.wizard_btn)

        # Debug Toggle Button
        self.gui.debug_btn = QPushButton("🐛 Debug: OFF")
        self.gui.debug_btn.setCheckable(True)
        self.gui.debug_btn.setChecked(False)
        self._update_debug_btn_style(False)
        self.gui.debug_btn.clicked.connect(self._toggle_debug)
        btn_layout.addWidget(self.gui.debug_btn)

        # Raw Scan Toggle Button - shows ALL output without filtering
        self.gui.raw_scan_btn = QPushButton("📋 Raw Output: OFF")
        self.gui.raw_scan_btn.setCheckable(True)
        self.gui.raw_scan_btn.setChecked(False)
        self._update_raw_btn_style(False)
        self.gui.raw_scan_btn.clicked.connect(self._toggle_raw_scan)
        self.gui.raw_scan_btn.setToolTip("Show raw unfiltered scan output")
        btn_layout.addWidget(self.gui.raw_scan_btn)

        btn_layout.addStretch()
        layout.addLayout(btn_layout)

        group.setLayout(layout)
        return group

    def _update_toggle_btn_style(self, btn, is_on, on_color, on_hover):
        """Update toggle button style based on state"""
        bg_color = on_color if is_on else "#607D8B"
        hover_color = on_hover if is_on else "#455A64"
        btn.setStyleSheet(f"""
            QPushButton {{
                background-color: {bg_color}; color: white;
                font-size: 12px; font-weight: bold;
                padding: 10px 15px; border-radius: 6px;
            }}
            QPushButton:hover {{background-color: {hover_color};}}
        """)

    def _toggle_debug(self):
        """Toggle debug mode on/off"""
        is_on = self.gui.debug_btn.isChecked()
        self.gui.debug_mode = is_on
        self.gui.debug_btn.setText(f"🐛 Debug: {'ON' if is_on else 'OFF'}")
        self._update_toggle_btn_style(self.gui.debug_btn, is_on, "#9C27B0", "#7B1FA2")
        if hasattr(self.gui, 'debug_mode_action'):
            self.gui.debug_mode_action.setChecked(is_on)
        status = "enabled - verbose output" if is_on else "disabled - clean output"
        self.gui.statusBar().showMessage(f"Debug mode {status}", 3000)

    def _update_debug_btn_style(self, is_on):
        """Update debug button style based on state"""
        self._update_toggle_btn_style(self.gui.debug_btn, is_on, "#9C27B0", "#7B1FA2")

    def _toggle_raw_scan(self):
        """Toggle raw output mode on/off"""
        is_on = self.gui.raw_scan_btn.isChecked()
        self.gui.raw_output_mode = is_on
        self.gui.raw_scan_btn.setText(f"📋 Raw Output: {'ON' if is_on else 'OFF'}")
        self._update_toggle_btn_style(self.gui.raw_scan_btn, is_on, "#FF5722", "#E64A19")
        status = "enabled - all output shown" if is_on else "disabled - filtered output"
        self.gui.statusBar().showMessage(f"Raw output mode {status}", 3000)

    def _update_raw_btn_style(self, is_on):
        """Update raw output button style based on state"""
        self._update_toggle_btn_style(self.gui.raw_scan_btn, is_on, "#FF5722", "#E64A19")

    def _create_presets_section(self):
        """Quick scan presets with clear descriptions"""
        group = QGroupBox("⚡ Quick Scan Presets")
        group.setStyleSheet("""
            QGroupBox {
                background-color: #fafafa;
                border: 2px solid #e0e0e0;
                border-radius: 10px;
                margin-top: 12px;
                padding: 15px 10px 10px 10px;
                font-size: 15px;
                font-weight: bold;
                color: #424242;
            }
            QGroupBox::title {
                subcontrol-origin: margin;
                left: 15px;
                padding: 3px 10px;
                background-color: #ffffff;
                border-radius: 4px;
            }
        """)

        layout = QHBoxLayout()
        layout.setSpacing(10)

        # Fast Scan
        fast = self._preset_card(
            "🚀 Fast Scan",
            "Quick security check",
            "3 modules • 20 threads • ~15 min",
            lambda: self._apply_preset("fast")
        )
        layout.addWidget(fast)

        # Full Scan
        full = self._preset_card(
            "🔥 Full Scan",
            "Complete security audit",
            "All modules • 30 threads • ~60 min",
            lambda: self._apply_preset("full")
        )
        layout.addWidget(full)

        # Stealth Scan
        stealth = self._preset_card(
            "🥷 Stealth Scan",
            "Low and slow",
            "5 modules • 1 thread • ~2 hours",
            lambda: self._apply_preset("stealth")
        )
        layout.addWidget(stealth)

        # API Scan
        api = self._preset_card(
            "🔌 API Scan",
            "API endpoint testing",
            "5 modules • 15 threads • ~30 min",
            lambda: self._apply_preset("api")
        )
        layout.addWidget(api)

        group.setLayout(layout)
        return group

    def _preset_card(self, title, subtitle, desc, on_click):
        """Create preset card button with clean uniform design"""
        card = QPushButton()
        card.setText(f"{title}\n{subtitle}\n{desc}")
        card.setStyleSheet("""
            QPushButton {
                background-color: #ffffff;
                border: 1px solid #bdbdbd;
                border-radius: 8px;
                padding: 12px 10px;
                text-align: center;
                font-size: 11px;
                color: #424242;
                min-height: 70px;
                max-width: 200px;
            }
            QPushButton:hover {
                background-color: #e3f2fd;
                border: 2px solid #1976D2;
                color: #1565c0;
            }
            QPushButton:pressed {
                background-color: #bbdefb;
            }
        """)
        card.clicked.connect(on_click)
        return card

    def _create_modules_section(self):
        """Module selection with collapsible categories in clean grid layout"""
        group = QGroupBox("📦 Vulnerability Modules")
        group.setStyleSheet("""
            QGroupBox {
                background-color: #fafafa;
                border: 2px solid #e0e0e0;
                border-radius: 10px;
                margin-top: 12px;
                padding: 15px 10px 10px 10px;
                font-size: 15px;
                font-weight: bold;
                color: #424242;
            }
            QGroupBox::title {
                subcontrol-origin: margin;
                left: 15px;
                padding: 3px 10px;
                background-color: #ffffff;
                border-radius: 4px;
            }
        """)

        main_layout = QVBoxLayout()
        main_layout.setSpacing(10)

        # Select all checkbox
        all_layout = QHBoxLayout()
        module_count = len(self.MODULE_INFO)
        self.gui.all_modules_cb = QCheckBox(f"Select All ({module_count} modules)")
        self.gui.all_modules_cb.setChecked(True)
        self.gui.all_modules_cb.setStyleSheet("""
            QCheckBox {
                font-size: 13px;
                font-weight: bold;
                color: #1976D2;
                padding: 5px;
            }
            QCheckBox::indicator {
                width: 18px;
                height: 18px;
            }
        """)
        self.gui.all_modules_cb.toggled.connect(self.gui.toggle_module_selection)
        all_layout.addWidget(self.gui.all_modules_cb)
        all_layout.addStretch()
        main_layout.addLayout(all_layout)

        self.gui.module_checkboxes = {}
        self.gui.module_descriptions = self.MODULE_DESCRIPTIONS

        # Group modules by category
        categories = {}
        for mid, info in self.MODULE_INFO.items():
            cat = info.get("category", "Other")
            if cat not in categories:
                categories[cat] = []
            categories[cat].append((mid, info))

        # Sort categories by priority
        category_order = ["Injection", "File & Path", "Auth & Session", "API Security",
                         "Recon", "Info Disclosure", "Server & Network", "Security Config",
                         "Advanced", "Cloud", "Other"]

        # Grid layout for categories - 3 columns per row
        cat_grid = QGridLayout()
        cat_grid.setSpacing(8)
        cat_grid.setContentsMargins(5, 5, 5, 5)
        # Set column stretch to distribute space evenly
        for col in range(3):
            cat_grid.setColumnStretch(col, 1)
        cat_row, cat_col = 0, 0
        COLS = 3

        for cat_name in category_order:
            if cat_name not in categories:
                continue

            modules_in_cat = categories[cat_name]

            # Create collapsible box with clean, uniform styling
            cat_box = self.CollapsibleBox(f"{cat_name} ({len(modules_in_cat)})")
            cat_box.toggle_button.setStyleSheet("""
                QToolButton {
                    border: 1px solid #bdbdbd;
                    background-color: #ffffff;
                    color: #424242;
                    font-weight: bold;
                    font-size: 12px;
                    padding: 10px 12px;
                    text-align: left;
                    border-radius: 6px;
                    min-height: 32px;
                    min-width: 170px;
                }
                QToolButton:hover {
                    background-color: #e3f2fd;
                    border-color: #1976D2;
                    color: #1976D2;
                }
            """)
            # Set tooltip so full name is visible on hover
            cat_box.toggle_button.setToolTip(f"{cat_name} - {len(modules_in_cat)} modules")

            # Vertical list for modules in category
            cat_layout = QVBoxLayout()
            cat_layout.setSpacing(3)
            cat_layout.setContentsMargins(10, 8, 10, 8)

            for mid, info in sorted(modules_in_cat, key=lambda x: x[1]['name']):
                cb = QCheckBox(f"{info['icon']} {info['name']}")
                cb.setChecked(True)
                cb.setToolTip(f"{info['name']}\n{info['desc']}")
                cb.setStyleSheet("""
                    QCheckBox {
                        font-size: 11px;
                        color: #333333;
                        padding: 3px 2px;
                        min-height: 18px;
                    }
                    QCheckBox:hover {
                        background-color: #e8f5e9;
                        border-radius: 3px;
                    }
                    QCheckBox::indicator {
                        width: 14px;
                        height: 14px;
                    }
                """)
                cb.toggled.connect(lambda checked, cb_ref=cb: self._on_individual_module_toggled())
                self.gui.module_checkboxes[mid] = cb
                cat_layout.addWidget(cb)

            cat_box.setContentLayout(cat_layout)
            # Calculate height based on module count
            cat_box.setContentHeight(max(80, len(modules_in_cat) * 28 + 20))

            # Add to grid
            cat_grid.addWidget(cat_box, cat_row, cat_col)
            cat_col += 1
            if cat_col >= COLS:
                cat_col = 0
                cat_row += 1

        main_layout.addLayout(cat_grid)
        group.setLayout(main_layout)
        return group

    def _on_individual_module_toggled(self):
        """Called when an individual module checkbox is toggled"""
        # Check if all modules are selected
        all_selected = all(cb.isChecked() for cb in self.gui.module_checkboxes.values())
        # Update "select all" checkbox without triggering its signal
        self.gui.all_modules_cb.blockSignals(True)
        self.gui.all_modules_cb.setChecked(all_selected)
        self.gui.all_modules_cb.blockSignals(False)

    def _create_settings_section(self):
        """Scan settings"""
        group = QGroupBox("⚙️ Scan Settings")
        group.setStyleSheet("""
            QGroupBox {
                background-color: #fafafa;
                border: 2px solid #e0e0e0;
                border-radius: 10px;
                margin-top: 12px;
                padding: 15px 10px 10px 10px;
                font-size: 15px;
                font-weight: bold;
                color: #424242;
            }
            QGroupBox::title {
                subcontrol-origin: margin;
                left: 15px;
                padding: 3px 10px;
                background-color: #ffffff;
                border-radius: 4px;
            }
        """)

        layout = QGridLayout()
        layout.setSpacing(12)

        label_style = "font-size: 12px; color: #424242; font-weight: normal;"

        # Clean spinbox style
        spinbox_style = """
            QSpinBox {
                font-size: 13px;
                padding: 8px 12px;
                border: 1px solid #bdbdbd;
                border-radius: 6px;
                background-color: white;
                min-width: 80px;
                min-height: 32px;
            }
            QSpinBox:focus {
                border: 2px solid #1976D2;
            }
            QSpinBox::up-button, QSpinBox::down-button {
                width: 20px;
                background-color: #f5f5f5;
                border: none;
            }
            QSpinBox::up-button:hover, QSpinBox::down-button:hover {
                background-color: #e3f2fd;
            }
        """

        combo_style = """
            QComboBox {
                font-size: 13px;
                padding: 8px 12px;
                border: 1px solid #bdbdbd;
                border-radius: 6px;
                background-color: white;
                min-width: 100px;
                min-height: 32px;
            }
            QComboBox:focus {
                border: 2px solid #1976D2;
            }
            QComboBox::drop-down {
                width: 24px;
                border-left: 1px solid #e0e0e0;
                background-color: #f5f5f5;
                border-top-right-radius: 4px;
                border-bottom-right-radius: 4px;
            }
            QComboBox::drop-down:hover {
                background-color: #e3f2fd;
            }
        """

        # Threads
        lbl1 = QLabel("🧵 Concurrent Threads:")
        lbl1.setStyleSheet(label_style)
        layout.addWidget(lbl1, 0, 0)
        self.gui.threads_spin = QSpinBox()
        self.gui.threads_spin.setRange(1, 50)
        self.gui.threads_spin.setValue(10)
        self.gui.threads_spin.setStyleSheet(spinbox_style)
        self.gui.threads_spin.setToolTip("Higher = faster but noisier")
        layout.addWidget(self.gui.threads_spin, 0, 1)

        # Timeout
        lbl2 = QLabel("⏱️ Request Timeout (sec):")
        lbl2.setStyleSheet(label_style)
        layout.addWidget(lbl2, 0, 2)
        self.gui.timeout_spin = QSpinBox()
        self.gui.timeout_spin.setRange(5, 300)
        self.gui.timeout_spin.setValue(15)
        self.gui.timeout_spin.setStyleSheet(spinbox_style)
        layout.addWidget(self.gui.timeout_spin, 0, 3)

        # Max Time
        lbl3 = QLabel("⏰ Max Scan Duration (min):")
        lbl3.setStyleSheet(label_style)
        layout.addWidget(lbl3, 1, 0)
        self.gui.max_time_spin = QSpinBox()
        self.gui.max_time_spin.setRange(1, 300)
        self.gui.max_time_spin.setValue(45)
        self.gui.max_time_spin.setStyleSheet(spinbox_style)
        layout.addWidget(self.gui.max_time_spin, 1, 1)

        # Output Format
        lbl4 = QLabel("📄 Report Format:")
        lbl4.setStyleSheet(label_style)
        layout.addWidget(lbl4, 1, 2)
        self.gui.format_combo = QComboBox()
        self.gui.format_combo.addItems(["html", "json", "txt", "html,json,txt"])
        self.gui.format_combo.setCurrentText("html,json,txt")
        self.gui.format_combo.setStyleSheet(combo_style)
        layout.addWidget(self.gui.format_combo, 1, 3)

        group.setLayout(layout)
        return group

    def _create_advanced_section(self):
        """Advanced options (collapsed)"""
        from GUI.ui_tabs.advanced_tab import AdvancedTabBuilder

        box = self.CollapsibleBox("🔧 Advanced Options")
        content = QVBoxLayout()
        content.setSpacing(12)

        # Scan Mode
        mode_group = QGroupBox("🎚️ Scan Mode")
        mode_group.setStyleSheet("""
            QGroupBox {
                font-size: 12px;
                color: #212121;
                border: 1px solid #e0e0e0;
                border-radius: 6px;
                padding-top: 12px;
                margin-top: 8px;
                background-color: #fafafa;
            }
            QGroupBox::title {
                color: #1976D2;
                font-weight: bold;
                font-size: 13px;
            }
        """)
        mode_layout = QVBoxLayout()
        mode_layout.setSpacing(8)

        self.gui.recon_only_cb = QCheckBox("🔍 Passive Mode Only (no attacks, only reconnaissance)")
        self.gui.recon_only_cb.setStyleSheet("""
            font-size: 12px;
            color: #212121;
            spacing: 8px;
        """)
        mode_layout.addWidget(self.gui.recon_only_cb)

        self.gui.rotate_agent_cb = QCheckBox("🔄 Rotate User-Agent (cycle through 26 browsers)")
        self.gui.rotate_agent_cb.setStyleSheet("""
            font-size: 12px;
            color: #212121;
            spacing: 8px;
        """)
        mode_layout.addWidget(self.gui.rotate_agent_cb)

        self.gui.single_page_cb = QCheckBox("📄 Single Page Mode (don't crawl links)")
        self.gui.single_page_cb.setStyleSheet("""
            font-size: 12px;
            color: #212121;
            spacing: 8px;
        """)
        mode_layout.addWidget(self.gui.single_page_cb)

        mode_group.setLayout(mode_layout)
        content.addWidget(mode_group)

        # Auth, HTTP, Crawler from advanced tab
        builder = AdvancedTabBuilder(self.gui, self.CollapsibleBox)
        for group_func in [builder._create_auth_group, builder._create_http_group, builder._create_crawler_group]:
            grp = group_func()
            grp.setStyleSheet("""
                QGroupBox {
                    font-size: 12px;
                    color: #212121;
                    border: 1px solid #e0e0e0;
                    border-radius: 6px;
                    padding: 16px 12px 12px 12px;
                    margin-top: 8px;
                    background-color: #fafafa;
                }
                QGroupBox::title {
                    color: #1976D2;
                    font-weight: bold;
                    font-size: 13px;
                    padding: 0 6px;
                }
                QLabel {
                    font-size: 12px;
                    color: #212121;
                    font-weight: 600;
                    padding-right: 8px;
                }
                QLineEdit, QTextEdit, QComboBox, QSpinBox {
                    font-size: 12px;
                    color: #000000;
                    background-color: #ffffff;
                    border: 1px solid #9e9e9e;
                    border-radius: 4px;
                    padding: 5px 8px;
                    min-height: 24px;
                }
                QLineEdit::placeholder, QTextEdit::placeholder {
                    color: #757575;
                    font-style: italic;
                }
                QLineEdit:focus, QTextEdit:focus, QComboBox:focus, QSpinBox:focus {
                    border: 2px solid #2196F3;
                    padding: 4px 7px;
                }
                QComboBox::drop-down {
                    border: none;
                    width: 20px;
                }
                QComboBox::down-arrow {
                    image: none;
                    border-left: 4px solid transparent;
                    border-right: 4px solid transparent;
                    border-top: 5px solid #616161;
                    margin-right: 5px;
                }
                QCheckBox {
                    font-size: 12px;
                    color: #212121;
                    spacing: 8px;
                }
                QCheckBox::indicator {
                    width: 18px;
                    height: 18px;
                }
            """)
            content.addWidget(grp)

        box.setContentLayout(content)
        box.expand()  # Expand by default as requested
        return box

    def _apply_preset(self, preset_name):
        """Apply scan preset"""
        presets = {
            "fast": {
                "modules": ["xss", "sqli", "cmdi"],
                "threads": 20,
                "timeout": 10,
                "max_time": 15,
                "name": "🚀 Fast Scan"
            },
            "full": {
                "modules": "all",
                "threads": 30,
                "timeout": 20,
                "max_time": 60,
                "name": "🔥 Full Scan"
            },
            "stealth": {
                "modules": ["xss", "sqli", "cmdi", "lfi", "ssrf"],
                "threads": 1,
                "timeout": 30,
                "max_time": 120,
                "name": "🥷 Stealth Scan"
            },
            "api": {
                "modules": ["sqli", "ssrf", "xxe", "ssti", "idor"],
                "threads": 15,
                "timeout": 15,
                "max_time": 30,
                "name": "🔌 API Scan"
            }
        }

        if preset_name not in presets:
            return

        preset = presets[preset_name]

        # Apply modules
        if preset["modules"] == "all":
            self.gui.all_modules_cb.setChecked(True)
        else:
            self.gui.all_modules_cb.setChecked(False)
            for cb in self.gui.module_checkboxes.values():
                cb.setChecked(False)
            for module in preset["modules"]:
                if module in self.gui.module_checkboxes:
                    self.gui.module_checkboxes[module].setChecked(True)

        # Apply settings
        self.gui.threads_spin.setValue(preset["threads"])
        self.gui.timeout_spin.setValue(preset["timeout"])
        self.gui.max_time_spin.setValue(preset["max_time"])

        # Confirm
        self.gui.output_console.append(f"[+] ✓ Preset applied: {preset['name']}")
        self.gui.statusBar().showMessage(f"✓ {preset['name']} configured", 3000)

    # Legacy compatibility for control buttons
    def _create_control_buttons(self, layout):
        """Deprecated - buttons now in target section"""
        pass
