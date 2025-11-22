"""
Scan Configuration Tab - Modern, Clean Design
Logical grouping with clear descriptions and large, readable fonts
"""

from PyQt5.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QGridLayout,
    QGroupBox, QLabel, QLineEdit, QTextEdit, QPushButton,
    QCheckBox, QSpinBox, QComboBox, QScrollArea, QFrame
)
from PyQt5.QtCore import Qt


class ScanTabBuilder:
    """Builder class for creating the Scan Configuration tab"""

    # Module information with Active/Passive classification
    MODULE_INFO = {
        # ACTIVE Modules - send modified/malicious requests
        "sqli": {"name": "SQL Injection", "desc": "Database manipulation attacks", "active": True, "icon": "💉"},
        "xss": {"name": "Cross-Site Scripting", "desc": "JavaScript injection", "active": True, "icon": "🔥"},
        "cmdi": {"name": "Command Injection", "desc": "OS command execution", "active": True, "icon": "⚡"},
        "ssti": {"name": "Template Injection", "desc": "Server-side templates", "active": True, "icon": "📝"},
        "xpath": {"name": "XPath Injection", "desc": "XML query attacks", "active": True, "icon": "🔍"},
        "xxe": {"name": "XML External Entity", "desc": "XXE attacks", "active": True, "icon": "📄"},
        "lfi": {"name": "Local File Inclusion", "desc": "Read server files", "active": True, "icon": "📁"},
        "rfi": {"name": "Remote File Inclusion", "desc": "Include remote files", "active": True, "icon": "🌐"},
        "file_upload": {"name": "File Upload", "desc": "Malicious file upload", "active": True, "icon": "📤"},
        "ssrf": {"name": "Server-Side Request Forgery", "desc": "Force server requests", "active": True, "icon": "🔗"},
        "idor": {"name": "Insecure Direct Object Ref", "desc": "Access control bypass", "active": True, "icon": "🔓"},
        "csrf": {"name": "Cross-Site Request Forgery", "desc": "Forged requests", "active": True, "icon": "🎭"},
        "redirect": {"name": "Open Redirect", "desc": "URL redirection", "active": True, "icon": "↪️"},
        "dom_xss": {"name": "DOM XSS", "desc": "Client-side XSS", "active": True, "icon": "💻"},
        "weak_credentials": {"name": "Weak Credentials", "desc": "Default passwords", "active": True, "icon": "🔑"},
        "php_object_injection": {"name": "PHP Object Injection", "desc": "PHP unserialize", "active": True, "icon": "🐘"},

        # PASSIVE Modules - only observe, no attacks
        "dirbrute": {"name": "Directory Brute", "desc": "Find hidden paths", "active": False, "icon": "🗂️"},
        "git": {"name": "Git Exposure", "desc": "Exposed .git", "active": False, "icon": "📦"},
        "env_secrets": {"name": "Env Secrets", "desc": "Leaked .env", "active": False, "icon": "🔐"},
        "db_exposure": {"name": "DB Exposure", "desc": "Database files", "active": False, "icon": "🗄️"},
        "backup_files": {"name": "Backup Files", "desc": ".bak, .sql", "active": False, "icon": "💾"},
        "config_files": {"name": "Config Files", "desc": "Exposed configs", "active": False, "icon": "⚙️"},
        "svn_hg": {"name": "SVN/Mercurial", "desc": ".svn/.hg folders", "active": False, "icon": "📚"},
        "debug_pages": {"name": "Debug Pages", "desc": "phpinfo(), debug", "active": False, "icon": "🐛"},
        "api_docs": {"name": "API Docs", "desc": "Swagger/OpenAPI", "active": False, "icon": "📖"},
    }

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
        self.gui.target_input.setMaximumHeight(100)
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

        btn_layout.addStretch()
        layout.addLayout(btn_layout)

        group.setLayout(layout)
        return group

    def _create_presets_section(self):
        """Quick scan presets with clear descriptions"""
        group = QGroupBox("⚡ Quick Scan Presets")
        group.setStyleSheet("""
            QGroupBox {
                background-color: #f5f5f5;
                border: 2px solid #90CAF9;
                border-radius: 10px;
                margin-top: 12px;
                padding: 15px 10px 10px 10px;
                font-size: 15px;
                font-weight: bold;
                color: #1976D2;
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

        # Fast Scan
        fast = self._preset_card(
            "🚀 FAST SCAN",
            "Quick security check - 3 modules",
            "Modules: XSS, SQLi, Command Injection\n"
            "Threads: 20 | Timeout: 10s\n"
            "Duration: ~15 minutes\n\n"
            "Best for: Quick testing, CI/CD",
            "#2196F3",
            lambda: self._apply_preset("fast")
        )
        layout.addWidget(fast, 0, 0)

        # Full Scan
        full = self._preset_card(
            "🔥 FULL SCAN",
            "Complete security audit - ALL modules",
            "Modules: ALL 25 modules\n"
            "Threads: 30 | Timeout: 20s\n"
            "Duration: ~60 minutes\n\n"
            "Best for: Thorough testing",
            "#4CAF50",
            lambda: self._apply_preset("full")
        )
        layout.addWidget(full, 0, 1)

        # Stealth Scan
        stealth = self._preset_card(
            "🥷 STEALTH SCAN",
            "Low and slow - avoid detection",
            "Modules: 5 key modules\n"
            "Threads: 1 (single) | Timeout: 30s\n"
            "Duration: ~2 hours\n\n"
            "Best for: Avoiding IDS/WAF",
            "#9C27B0",
            lambda: self._apply_preset("stealth")
        )
        layout.addWidget(stealth, 0, 2)

        # API Scan
        api = self._preset_card(
            "🔌 API SCAN",
            "API endpoint testing - 5 modules",
            "Modules: SQLi, SSRF, XXE, SSTI, IDOR\n"
            "Threads: 15 | Timeout: 15s\n"
            "Duration: ~30 minutes\n\n"
            "Best for: REST/GraphQL APIs",
            "#FF9800",
            lambda: self._apply_preset("api")
        )
        layout.addWidget(api, 0, 3)

        group.setLayout(layout)
        return group

    def _preset_card(self, title, subtitle, desc, color, on_click):
        """Create preset card button"""
        card = QPushButton()
        card.setText(f"{title}\n{subtitle}\n\n{desc}")
        card.setStyleSheet(f"""
            QPushButton {{
                background-color: white;
                border: 3px solid {color};
                border-radius: 8px;
                padding: 12px;
                text-align: left;
                font-size: 11px;
                color: #424242;
            }}
            QPushButton:hover {{
                background-color: {color};
                color: white;
            }}
        """)
        card.setMinimumHeight(150)
        card.clicked.connect(on_click)
        return card

    def _create_modules_section(self):
        """Module selection - Active/Passive split"""
        group = QGroupBox("📦 Vulnerability Modules")
        group.setStyleSheet("""
            QGroupBox {
                background-color: #ffffff;
                border: 2px solid #9575CD;
                border-radius: 10px;
                margin-top: 12px;
                padding: 15px 10px 10px 10px;
                font-size: 15px;
                font-weight: bold;
                color: #6A1B9A;
            }
            QGroupBox::title {
                subcontrol-origin: margin;
                left: 15px;
                padding: 3px 10px;
                background-color: #ffffff;
                border-radius: 4px;
            }
        """)

        layout = QVBoxLayout()
        layout.setSpacing(12)

        # Select all
        all_layout = QHBoxLayout()
        self.gui.all_modules_cb = QCheckBox("✓ SELECT ALL MODULES (25 total)")
        self.gui.all_modules_cb.setChecked(True)
        self.gui.all_modules_cb.setStyleSheet("font-size: 13px; font-weight: bold; color: #6A1B9A;")
        self.gui.all_modules_cb.toggled.connect(self.gui.toggle_module_selection)
        all_layout.addWidget(self.gui.all_modules_cb)
        all_layout.addStretch()
        layout.addLayout(all_layout)

        self.gui.module_checkboxes = {}
        self.gui.module_descriptions = self.MODULE_DESCRIPTIONS

        # ACTIVE Modules
        active_label = QLabel("🔴 ACTIVE MODULES (send attack payloads, may trigger alerts)")
        active_label.setStyleSheet("font-size: 13px; font-weight: bold; color: #d32f2f; margin-top: 8px;")
        layout.addWidget(active_label)

        active_grid = QGridLayout()
        active_grid.setSpacing(6)
        row, col = 0, 0
        for mid, info in sorted(self.MODULE_INFO.items()):
            if info["active"]:
                cb = QCheckBox(f"{info['icon']} {info['name']}")
                cb.setChecked(True)  # Enable by default since "select all" is checked
                cb.setToolTip(f"{info['name']}\n{info['desc']}")
                cb.setStyleSheet("""
                    QCheckBox {
                        font-size: 12px;
                        color: #424242;
                        padding: 4px;
                    }
                    QCheckBox:hover {
                        background-color: #ffebee;
                        border-radius: 4px;
                    }
                """)
                # Connect individual checkbox to update "select all" state
                cb.toggled.connect(lambda checked, cb_ref=cb: self._on_individual_module_toggled())
                self.gui.module_checkboxes[mid] = cb
                active_grid.addWidget(cb, row, col)
                col += 1
                if col > 3:
                    col = 0
                    row += 1
        layout.addLayout(active_grid)

        # PASSIVE Modules
        passive_label = QLabel("🟢 PASSIVE MODULES (only observe, stealthy)")
        passive_label.setStyleSheet("font-size: 13px; font-weight: bold; color: #388E3C; margin-top: 12px;")
        layout.addWidget(passive_label)

        passive_grid = QGridLayout()
        passive_grid.setSpacing(6)
        row, col = 0, 0
        for mid, info in sorted(self.MODULE_INFO.items()):
            if not info["active"]:
                cb = QCheckBox(f"{info['icon']} {info['name']}")
                cb.setChecked(True)  # Enable by default since "select all" is checked
                cb.setToolTip(f"{info['name']}\n{info['desc']}")
                cb.setStyleSheet("""
                    QCheckBox {
                        font-size: 12px;
                        color: #424242;
                        padding: 4px;
                    }
                    QCheckBox:hover {
                        background-color: #e8f5e9;
                        border-radius: 4px;
                    }
                """)
                # Connect individual checkbox to update "select all" state
                cb.toggled.connect(lambda checked, cb_ref=cb: self._on_individual_module_toggled())
                self.gui.module_checkboxes[mid] = cb
                passive_grid.addWidget(cb, row, col)
                col += 1
                if col > 3:
                    col = 0
                    row += 1
        layout.addLayout(passive_grid)

        group.setLayout(layout)
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
                background-color: #fff3e0;
                border: 2px solid #FF9800;
                border-radius: 10px;
                margin-top: 12px;
                padding: 15px 10px 10px 10px;
                font-size: 15px;
                font-weight: bold;
                color: #E65100;
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
        input_style = "font-size: 12px; padding: 6px;"

        # Threads
        lbl1 = QLabel("🧵 Concurrent Threads:")
        lbl1.setStyleSheet(label_style)
        layout.addWidget(lbl1, 0, 0)
        self.gui.threads_spin = QSpinBox()
        self.gui.threads_spin.setRange(1, 50)
        self.gui.threads_spin.setValue(10)
        self.gui.threads_spin.setStyleSheet(input_style)
        self.gui.threads_spin.setToolTip("Higher = faster but noisier")
        layout.addWidget(self.gui.threads_spin, 0, 1)

        # Timeout
        lbl2 = QLabel("⏱️ Request Timeout (sec):")
        lbl2.setStyleSheet(label_style)
        layout.addWidget(lbl2, 0, 2)
        self.gui.timeout_spin = QSpinBox()
        self.gui.timeout_spin.setRange(5, 300)
        self.gui.timeout_spin.setValue(15)
        self.gui.timeout_spin.setStyleSheet(input_style)
        layout.addWidget(self.gui.timeout_spin, 0, 3)

        # Max Time
        lbl3 = QLabel("⏰ Max Scan Duration (min):")
        lbl3.setStyleSheet(label_style)
        layout.addWidget(lbl3, 1, 0)
        self.gui.max_time_spin = QSpinBox()
        self.gui.max_time_spin.setRange(1, 300)
        self.gui.max_time_spin.setValue(45)
        self.gui.max_time_spin.setStyleSheet(input_style)
        layout.addWidget(self.gui.max_time_spin, 1, 1)

        # Output Format
        lbl4 = QLabel("📄 Report Format:")
        lbl4.setStyleSheet(label_style)
        layout.addWidget(lbl4, 1, 2)
        self.gui.format_combo = QComboBox()
        self.gui.format_combo.addItems(["html", "json", "txt", "html,json,txt"])
        self.gui.format_combo.setCurrentText("html,json,txt")
        self.gui.format_combo.setStyleSheet(input_style)
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
