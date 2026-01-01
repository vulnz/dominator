"""
Reusable GUI widgets for Dominator Scanner
"""

from PyQt5.QtWidgets import QWidget, QVBoxLayout, QToolButton, QSizePolicy
from PyQt5.QtCore import Qt


class CollapsibleBox(QWidget):
    """A collapsible box widget that can be expanded/collapsed"""

    def __init__(self, title="", parent=None):
        super().__init__(parent)

        self.toggle_button = QToolButton()
        self.toggle_button.setStyleSheet("""
            QToolButton {
                border: 1px solid #cccccc;
                background-color: #f5f5f5;
                color: #333333;
                font-weight: bold;
                font-size: 12px;
                padding: 8px;
                text-align: left;
            }
            QToolButton:hover {
                background-color: #e0e0e0;
            }
        """)
        self.toggle_button.setToolButtonStyle(Qt.ToolButtonTextBesideIcon)
        self.toggle_button.setArrowType(Qt.RightArrow)
        self.toggle_button.setText(title)
        self.toggle_button.setCheckable(True)
        self.toggle_button.setChecked(False)
        self.toggle_button.clicked.connect(self.on_toggle)

        # CRITICAL: Prevent text truncation - set size policy and minimum width
        self.toggle_button.setSizePolicy(QSizePolicy.Preferred, QSizePolicy.Fixed)
        self.toggle_button.setMinimumWidth(180)  # Ensure text fits
        self.toggle_button.setToolTip(title)  # Show full title on hover

        self.content_area = QWidget()
        self.content_area.setMaximumHeight(0)
        self.content_area.setMinimumHeight(0)
        self.content_area.setStyleSheet("background-color: #fafafa; border-radius: 4px;")

        self.content_layout = QVBoxLayout()
        self.content_layout.setContentsMargins(10, 10, 10, 10)
        self.content_area.setLayout(self.content_layout)

        main_layout = QVBoxLayout()
        main_layout.setSpacing(0)
        main_layout.setContentsMargins(0, 0, 0, 0)
        main_layout.addWidget(self.toggle_button)
        main_layout.addWidget(self.content_area)

        self.setLayout(main_layout)

        self._collapsed_height = 0
        self._content_height = 200  # Default height

    def on_toggle(self, checked):
        """Toggle the collapsible box"""
        if checked:
            self.toggle_button.setArrowType(Qt.DownArrow)
            self.content_area.setMaximumHeight(16777215)  # QWIDGETSIZE_MAX
            self.content_area.setMinimumHeight(self._content_height)
        else:
            self.toggle_button.setArrowType(Qt.RightArrow)
            self.content_area.setMaximumHeight(0)
            self.content_area.setMinimumHeight(0)

    def setContentLayout(self, layout):
        """Set the layout for the content area"""
        # Clear existing layout
        while self.content_layout.count():
            item = self.content_layout.takeAt(0)
            if item.widget():
                item.widget().setParent(None)

        # Create a container widget for the new layout
        container = QWidget()
        container.setLayout(layout)
        self.content_layout.addWidget(container)

        # Calculate content height
        self._content_height = layout.sizeHint().height() + 20
        if self._content_height < 100:
            self._content_height = 100

    def setContentHeight(self, height):
        """Set the content height when expanded"""
        self._content_height = height
        if self.toggle_button.isChecked():
            self.content_area.setMinimumHeight(height)

    def expand(self):
        """Expand the collapsible box by default"""
        self.toggle_button.setChecked(True)
        self.on_toggle(True)

    def collapse(self):
        """Collapse the collapsible box"""
        self.toggle_button.setChecked(False)
        self.on_toggle(False)
