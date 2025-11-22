"""
Custom Payloads Tab Builder
Handles custom payload entry for different vulnerability modules.
"""

from PyQt5.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QGridLayout,
    QGroupBox, QLabel, QLineEdit, QTextEdit, QPushButton, QComboBox
)


class PayloadsTabBuilder:
    """Builder class for creating the Custom Payloads tab"""

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
        """Create and return the custom payloads tab widget"""
        widget = QWidget()
        layout = QVBoxLayout(widget)

        # Instructions
        info_label = QLabel("Provide custom payloads to override default payloads for specific modules. Select target module(s) below.")
        info_label.setStyleSheet("color: #4CAF50; padding: 10px; background-color: #f5f5f5; border-radius: 5px;")
        info_label.setWordWrap(True)
        layout.addWidget(info_label)

        # Module Selection for Custom Payloads
        module_select_group = self._create_module_select_group()
        layout.addWidget(module_select_group)

        # Custom Payloads File
        file_group = self._create_file_group()
        layout.addWidget(file_group)

        # Direct Payload Entry
        direct_group = self._create_direct_entry_group()
        layout.addWidget(direct_group)

        # Initialize with default examples
        self.gui.update_payload_examples("All Modules")

        layout.addStretch()
        return widget

    def _create_module_select_group(self):
        """Create module selection group"""
        module_select_group = QGroupBox("Target Module(s)")
        module_select_layout = QVBoxLayout()

        module_help = QLabel("Select which module(s) should use these custom payloads:")
        module_help.setStyleSheet("color: #888888; font-size: 10px;")
        module_select_layout.addWidget(module_help)

        # Module selector dropdown
        module_selector_layout = QHBoxLayout()
        module_selector_layout.addWidget(QLabel("Apply payloads to:"))

        self.gui.payload_target_module = QComboBox()
        self.gui.payload_target_module.addItems([
            "All Modules",
            "SQL Injection (sqli)",
            "Cross-Site Scripting (xss)",
            "Server-Side Template Injection (ssti)",
            "Command Injection (cmdi)",
            "LDAP Injection (ldap)",
            "XPath Injection (xpath)",
            "Local File Inclusion (lfi)",
            "Remote File Inclusion (rfi)",
            "XML External Entity (xxe)",
            "Server-Side Request Forgery (ssrf)",
            "PHP Object Injection (php_object_injection)"
        ])
        self.gui.payload_target_module.setStyleSheet("""
            QComboBox {
                background-color: #f5f5f5;
                color: #333333;
                border: 2px solid #e0e0e0;
                border-radius: 4px;
                padding: 6px;
                min-width: 300px;
            }
            QComboBox::drop-down {
                border: none;
                background-color: #e0e0e0;
            }
            QComboBox::down-arrow {
                image: none;
                border-left: 5px solid transparent;
                border-right: 5px solid transparent;
                border-top: 5px solid #333333;
            }
            QComboBox QAbstractItemView {
                background-color: #f5f5f5;
                color: #333333;
                selection-background-color: #4CAF50;
                selection-color: white;
            }
        """)
        module_selector_layout.addWidget(self.gui.payload_target_module)
        module_selector_layout.addStretch()

        module_select_layout.addLayout(module_selector_layout)
        module_select_group.setLayout(module_select_layout)
        return module_select_group

    def _create_file_group(self):
        """Create file loading group"""
        file_group = QGroupBox("Load Payloads from File")
        file_layout = QGridLayout()

        file_layout.addWidget(QLabel("Payloads File:"), 0, 0)
        self.gui.custom_payloads_file = QLineEdit()
        self.gui.custom_payloads_file.setPlaceholderText("Path to file with custom payloads (one per line)")
        file_layout.addWidget(self.gui.custom_payloads_file, 0, 1)

        browse_payloads_btn = QPushButton("Browse...")
        browse_payloads_btn.clicked.connect(self.gui.browse_payloads_file)
        file_layout.addWidget(browse_payloads_btn, 0, 2)

        file_group.setLayout(file_layout)
        return file_group

    def _create_direct_entry_group(self):
        """Create direct payload entry group"""
        direct_group = QGroupBox("Enter Payloads Directly")
        direct_layout = QVBoxLayout()

        help_text = QLabel("Enter custom payloads below (one per line). These will ONLY be used by the selected module above.")
        help_text.setStyleSheet("color: #888888; font-size: 10px;")
        help_text.setWordWrap(True)
        direct_layout.addWidget(help_text)

        # Dynamic help based on selected module
        self.gui.payload_example_label = QLabel()
        self.gui.payload_example_label.setStyleSheet("color: #4CAF50; font-size: 10px; padding: 5px; background-color: #ffffff; border-radius: 3px;")
        self.gui.payload_example_label.setWordWrap(True)
        direct_layout.addWidget(self.gui.payload_example_label)

        # Connect to update examples when module changes
        self.gui.payload_target_module.currentTextChanged.connect(self.gui.update_payload_examples)

        self.gui.custom_payloads_text = QTextEdit()
        self.gui.custom_payloads_text.setPlaceholderText(
            "Select a target module above to see example payloads...\n\n"
            "Your custom payloads will be used INSTEAD of the default payloads\n"
            "for the selected module during the scan.\n\n"
            "Examples:\n"
            "- SQL Injection: ' OR 1=1--, admin' --\n"
            "- XSS: <script>alert(1)</script>, <img src=x onerror=alert(1)>\n"
            "- SSTI: {{7*7}}, ${7*7}, {{config}}\n"
            "- Command Injection: ;whoami, `whoami`, $(whoami)"
        )
        self.gui.custom_payloads_text.setMinimumHeight(300)
        self.gui.custom_payloads_text.setStyleSheet("""
            QTextEdit {
                background-color: #ffffff;
                color: #333333;
                font-family: 'Consolas', 'Courier New', monospace;
                font-size: 18px;
                border: 2px solid #e0e0e0;
                border-radius: 4px;
                padding: 8px;
            }
        """)
        direct_layout.addWidget(self.gui.custom_payloads_text)

        # Payload count
        self.gui.payload_count_label = QLabel("Payloads: 0")
        self.gui.payload_count_label.setStyleSheet("color: #4CAF50; font-weight: bold;")
        direct_layout.addWidget(self.gui.payload_count_label)

        # Update count when text changes
        self.gui.custom_payloads_text.textChanged.connect(self.gui.update_payload_count)

        # Action buttons
        button_layout = self._create_action_buttons()
        direct_layout.addLayout(button_layout)

        direct_group.setLayout(direct_layout)
        return direct_group

    def _create_action_buttons(self):
        """Create action buttons layout"""
        button_layout = QHBoxLayout()

        clear_btn = QPushButton("Clear All")
        clear_btn.setStyleSheet("""
            QPushButton {
                background-color: #ff4444;
                color: #ffffff;
                padding: 8px 16px;
                border-radius: 4px;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: #cc0000;
            }
        """)
        clear_btn.clicked.connect(lambda: self.gui.custom_payloads_text.clear())
        button_layout.addWidget(clear_btn)

        save_btn = QPushButton("Save to File")
        save_btn.setStyleSheet("""
            QPushButton {
                background-color: #00ff88;
                color: black;
                padding: 8px 16px;
                border-radius: 4px;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: #00cc70;
            }
        """)
        save_btn.clicked.connect(self.gui.save_payloads_to_file)
        button_layout.addWidget(save_btn)

        view_existing_btn = QPushButton("View Existing Payloads")
        view_existing_btn.setStyleSheet("""
            QPushButton {
                background-color: #4a4aff;
                color: #ffffff;
                padding: 8px 16px;
                border-radius: 4px;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: #3838dd;
            }
        """)
        view_existing_btn.setToolTip("Open Modules tab to view/edit existing payloads for each module")
        view_existing_btn.clicked.connect(lambda: self.gui.tabs.setCurrentIndex(8))
        button_layout.addWidget(view_existing_btn)

        button_layout.addStretch()
        return button_layout
