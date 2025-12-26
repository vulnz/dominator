"""
Output Tab Builder
Handles scan output display with progress bar and console.
"""

from PyQt5.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QTextEdit, QPushButton, QProgressBar, QCheckBox
)
from PyQt5.QtGui import QFont


class OutputTabBuilder:
    """Builder class for creating the Scan Output tab"""

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
        """Create and return the output tab widget"""
        widget = QWidget()
        layout = QVBoxLayout(widget)

        # Progress bar
        self.gui.progress_bar = QProgressBar()
        self.gui.progress_bar.setStyleSheet("""
            QProgressBar {
                border: 2px solid #e0e0e0;
                border-radius: 5px;
                text-align: center;
                background-color: #ffffff;
                color: #333333;
            }
            QProgressBar::chunk {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
                    stop:0 #4CAF50, stop:1 #45a049);
            }
        """)
        layout.addWidget(self.gui.progress_bar)

        # Current module label
        self.gui.current_module_label = QLabel("Ready to start scan...")
        # Stylesheet will be applied in apply_theme()
        layout.addWidget(self.gui.current_module_label)

        # Time display row
        time_layout = QHBoxLayout()

        # Time elapsed label
        self.gui.time_elapsed_label = QLabel("⏱️ Elapsed: 00:00")
        self.gui.time_elapsed_label.setStyleSheet("""
            QLabel {
                color: #3b82f6;
                font-size: 12px;
                font-weight: bold;
                padding: 4px 10px;
                background-color: #f0f7ff;
                border-radius: 4px;
            }
        """)
        time_layout.addWidget(self.gui.time_elapsed_label)

        # Time remaining label
        self.gui.time_remaining_label = QLabel("⏳ Time Left: --:--")
        self.gui.time_remaining_label.setStyleSheet("""
            QLabel {
                color: #22c55e;
                font-size: 12px;
                font-weight: bold;
                padding: 4px 10px;
                background-color: #f0fdf4;
                border-radius: 4px;
            }
        """)
        time_layout.addWidget(self.gui.time_remaining_label)

        time_layout.addStretch()
        layout.addLayout(time_layout)

        # Toggle for enabling/disabling output logging
        output_control_layout = QHBoxLayout()

        self.gui.output_enabled_cb = QCheckBox("Enable Scan Output Logging")
        self.gui.output_enabled_cb.setChecked(True)  # FIXED: Enabled by default for better UX
        self.gui.output_enabled_cb.setStyleSheet("""
            QCheckBox {
                font-size: 12px;
                font-weight: bold;
                color: #3b82f6;
                padding: 4px;
            }
            QCheckBox::indicator {
                width: 18px;
                height: 18px;
            }
        """)
        self.gui.output_enabled_cb.stateChanged.connect(self._toggle_output_logging)
        output_control_layout.addWidget(self.gui.output_enabled_cb)

        output_control_layout.addStretch()

        layout.addLayout(output_control_layout)

        # Output console (create BEFORE clear button so it exists)
        self.gui.output_console = QTextEdit()
        self.gui.output_console.setReadOnly(True)
        self.gui.output_console.setFont(QFont("Consolas", 9))
        self.gui.output_console.setEnabled(True)  # FIXED: Enabled by default for better UX
        self.gui.output_console.setPlaceholderText("")

        # PERFORMANCE FIX: Limit output console to 5000 lines to prevent memory bloat
        # This prevents UI slowdown during long scans with verbose output
        self.gui.output_console.document().setMaximumBlockCount(5000)

        # Stylesheet will be applied in apply_theme()
        layout.addWidget(self.gui.output_console)

        # Clear button (create AFTER output_console)
        clear_layout = QHBoxLayout()
        clear_layout.addStretch()
        clear_btn = QPushButton("Clear Output")
        clear_btn.clicked.connect(self.gui.output_console.clear)
        clear_layout.addWidget(clear_btn)
        layout.addLayout(clear_layout)

        return widget

    def _toggle_output_logging(self, state):
        """Toggle output console logging on/off"""
        enabled = (state == 2)  # Qt.Checked == 2
        self.gui.output_console.setEnabled(enabled)

        if enabled:
            self.gui.output_console.setPlaceholderText("")
            self.gui.output_console.append("[*] Output logging enabled\n")
        else:
            self.gui.output_console.setPlaceholderText("Output logging is disabled. Enable checkbox above to see scan output.")
