"""
Output Tab Builder
Handles scan output display with progress bar and console.
"""

from PyQt5.QtWidgets import (
    QWidget, QVBoxLayout, QLabel, QTextEdit, QPushButton, QProgressBar
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

        # Output console
        self.gui.output_console = QTextEdit()
        self.gui.output_console.setReadOnly(True)
        self.gui.output_console.setFont(QFont("Consolas", 9))
        # Stylesheet will be applied in apply_theme()
        layout.addWidget(self.gui.output_console)

        # Clear button
        clear_btn = QPushButton("Clear Output")
        clear_btn.clicked.connect(self.gui.output_console.clear)
        layout.addWidget(clear_btn)

        return widget
