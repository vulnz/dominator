"""
Loading Dialog Utility for Dominator GUI

Provides loading indicators for long-running operations to improve UX.
"""

from PyQt5.QtWidgets import (
    QDialog, QVBoxLayout, QLabel, QProgressBar,
    QApplication, QPushButton, QHBoxLayout
)
from PyQt5.QtCore import Qt, QTimer
from PyQt5.QtGui import QFont


class LoadingDialog(QDialog):
    """
    A modal loading dialog that shows progress for long-running operations.

    Usage:
        with LoadingDialog(parent, "Loading data...") as dialog:
            # Long operation here
            dialog.update_progress(50, "Processing...")

        # Or manual control:
        dialog = LoadingDialog(parent, "Loading...")
        dialog.show()
        # ... do work ...
        dialog.close()
    """

    def __init__(self, parent=None, message="Please wait...", cancellable=False):
        """
        Initialize loading dialog.

        Args:
            parent: Parent widget
            message: Initial message to display
            cancellable: Whether to show a cancel button
        """
        super().__init__(parent)
        self.cancelled = False
        self._setup_ui(message, cancellable)

    def _setup_ui(self, message, cancellable):
        """Setup the dialog UI"""
        self.setWindowTitle("Loading")
        self.setModal(True)
        self.setFixedSize(350, 120)
        self.setWindowFlags(
            Qt.Dialog | Qt.CustomizeWindowHint | Qt.WindowTitleHint
        )

        layout = QVBoxLayout(self)
        layout.setSpacing(15)
        layout.setContentsMargins(20, 20, 20, 20)

        # Message label
        self.message_label = QLabel(message)
        self.message_label.setFont(QFont("Segoe UI", 10))
        self.message_label.setAlignment(Qt.AlignCenter)
        self.message_label.setWordWrap(True)
        layout.addWidget(self.message_label)

        # Progress bar
        self.progress_bar = QProgressBar()
        self.progress_bar.setRange(0, 0)  # Indeterminate by default
        self.progress_bar.setTextVisible(False)
        self.progress_bar.setStyleSheet("""
            QProgressBar {
                border: 1px solid #ddd;
                border-radius: 3px;
                background-color: #f5f5f5;
                height: 8px;
            }
            QProgressBar::chunk {
                background-color: #4CAF50;
                border-radius: 2px;
            }
        """)
        layout.addWidget(self.progress_bar)

        # Cancel button (optional)
        if cancellable:
            btn_layout = QHBoxLayout()
            btn_layout.addStretch()
            cancel_btn = QPushButton("Cancel")
            cancel_btn.clicked.connect(self._on_cancel)
            cancel_btn.setStyleSheet("""
                QPushButton {
                    background-color: #f44336;
                    color: white;
                    padding: 5px 20px;
                    border: none;
                    border-radius: 3px;
                }
                QPushButton:hover {
                    background-color: #d32f2f;
                }
            """)
            btn_layout.addWidget(cancel_btn)
            btn_layout.addStretch()
            layout.addLayout(btn_layout)

    def _on_cancel(self):
        """Handle cancel button click"""
        self.cancelled = True
        self.close()

    def update_message(self, message):
        """Update the displayed message"""
        self.message_label.setText(message)
        QApplication.processEvents()

    def update_progress(self, value, message=None):
        """
        Update progress bar and optionally the message.

        Args:
            value: Progress value (0-100) or -1 for indeterminate
            message: Optional new message to display
        """
        if value < 0:
            self.progress_bar.setRange(0, 0)  # Indeterminate
        else:
            self.progress_bar.setRange(0, 100)
            self.progress_bar.setValue(value)

        if message:
            self.message_label.setText(message)

        QApplication.processEvents()

    def set_determinate(self, max_value=100):
        """Switch to determinate progress mode"""
        self.progress_bar.setRange(0, max_value)
        self.progress_bar.setValue(0)

    def __enter__(self):
        """Context manager entry - show dialog"""
        self.show()
        QApplication.processEvents()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit - close dialog"""
        self.close()
        return False


class BusyIndicator:
    """
    Simple busy indicator that changes cursor and disables UI.

    Usage:
        with BusyIndicator(widget):
            # Long operation
            pass
    """

    def __init__(self, widget):
        """
        Initialize busy indicator.

        Args:
            widget: Widget to show busy state on
        """
        self.widget = widget

    def __enter__(self):
        """Start busy state"""
        QApplication.setOverrideCursor(Qt.WaitCursor)
        if self.widget:
            self.widget.setEnabled(False)
        QApplication.processEvents()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """End busy state"""
        QApplication.restoreOverrideCursor()
        if self.widget:
            self.widget.setEnabled(True)
        QApplication.processEvents()
        return False


def show_loading(parent, message="Loading...", operation=None):
    """
    Convenience function to show loading dialog during an operation.

    Args:
        parent: Parent widget
        message: Loading message
        operation: Callable to execute (optional)

    Returns:
        Result of operation if provided, otherwise the dialog instance
    """
    dialog = LoadingDialog(parent, message)

    if operation:
        dialog.show()
        QApplication.processEvents()
        try:
            result = operation()
            return result
        finally:
            dialog.close()
    else:
        return dialog
