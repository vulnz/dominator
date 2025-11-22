"""
Resources Tab Builder
Handles the resources tab UI including social media, emails, phones, and leaked keys.
"""

from PyQt5.QtWidgets import (
    QWidget, QVBoxLayout, QGroupBox, QLabel,
    QTableWidget, QAbstractItemView, QPushButton
)
from PyQt5.QtGui import QFont


class ResourcesTabBuilder:
    """Builder class for creating the Resources tab"""

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
        """Create and return the resources tab widget"""
        widget = QWidget()
        layout = QVBoxLayout(widget)

        # Resources summary header
        summary_label = QLabel("Discovered Resources")
        summary_label.setFont(QFont("Arial", 14, QFont.Bold))
        summary_label.setStyleSheet("color: #00ff88; padding: 10px;")
        layout.addWidget(summary_label)

        # Social Media section
        self.gui.social_group = self._create_social_media_section()
        layout.addWidget(self.gui.social_group)

        # Emails section
        self.gui.emails_group = self._create_emails_section()
        layout.addWidget(self.gui.emails_group)

        # Phone Numbers section
        self.gui.phones_group = self._create_phones_section()
        layout.addWidget(self.gui.phones_group)

        # Leaked Keys section
        self.gui.keys_group = self._create_leaked_keys_section()
        layout.addWidget(self.gui.keys_group)

        # Export button
        export_btn = QPushButton("Export Resources to File")
        export_btn.setStyleSheet("""
            QPushButton {
                background-color: #00ff88;
                color: black;
                padding: 10px;
                border-radius: 5px;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: #00cc70;
            }
        """)
        export_btn.clicked.connect(self.gui.config_handler.export_resources)
        layout.addWidget(export_btn)

        return widget

    def _create_social_media_section(self):
        """Create social media links section"""
        social_group = QGroupBox("Social Media Links")
        social_layout = QVBoxLayout()

        self.gui.social_media_table = QTableWidget()
        self.gui.social_media_table.setColumnCount(3)
        self.gui.social_media_table.setHorizontalHeaderLabels(["Platform", "URL", "Found On"])
        self.gui.social_media_table.horizontalHeader().setStretchLastSection(True)
        self.gui.social_media_table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.gui.social_media_table.setStyleSheet(self._get_table_stylesheet())
        social_layout.addWidget(self.gui.social_media_table)
        social_group.setLayout(social_layout)
        social_group.hide()  # Hide initially, show when data is added
        return social_group

    def _create_emails_section(self):
        """Create email addresses section"""
        emails_group = QGroupBox("Email Addresses")
        emails_layout = QVBoxLayout()

        self.gui.emails_table = QTableWidget()
        self.gui.emails_table.setColumnCount(3)
        self.gui.emails_table.setHorizontalHeaderLabels(["Email", "Type", "Found On"])
        self.gui.emails_table.horizontalHeader().setStretchLastSection(True)
        self.gui.emails_table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.gui.emails_table.setStyleSheet(self._get_table_stylesheet())
        emails_layout.addWidget(self.gui.emails_table)
        emails_group.setLayout(emails_layout)
        emails_group.hide()  # Hide initially, show when data is added
        return emails_group

    def _create_phones_section(self):
        """Create phone numbers section"""
        phones_group = QGroupBox("Phone Numbers")
        phones_layout = QVBoxLayout()

        self.gui.phones_table = QTableWidget()
        self.gui.phones_table.setColumnCount(3)
        self.gui.phones_table.setHorizontalHeaderLabels(["Phone Number", "Format", "Found On"])
        self.gui.phones_table.horizontalHeader().setStretchLastSection(True)
        self.gui.phones_table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.gui.phones_table.setStyleSheet(self._get_table_stylesheet())
        phones_layout.addWidget(self.gui.phones_table)
        phones_group.setLayout(phones_layout)
        phones_group.hide()  # Hide initially, show when data is added
        return phones_group

    def _create_leaked_keys_section(self):
        """Create leaked API keys section"""
        keys_group = QGroupBox("Leaked API Keys & Secrets")
        keys_layout = QVBoxLayout()

        self.gui.leaked_keys_table = QTableWidget()
        self.gui.leaked_keys_table.setColumnCount(4)
        self.gui.leaked_keys_table.setHorizontalHeaderLabels(["Key Type", "Key Preview", "Severity", "Found On"])
        self.gui.leaked_keys_table.horizontalHeader().setStretchLastSection(True)
        self.gui.leaked_keys_table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.gui.leaked_keys_table.setStyleSheet(self._get_table_stylesheet())
        keys_layout.addWidget(self.gui.leaked_keys_table)
        keys_group.setLayout(keys_layout)
        keys_group.hide()  # Hide initially, show when data is added
        return keys_group

    def _get_table_stylesheet(self):
        """Return common table stylesheet"""
        return """
            QTableWidget {
                background-color: #ffffff;
                color: #333333;
                gridline-color: #e0e0e0;
                border: 1px solid #cccccc;
                border-radius: 4px;
            }
            QHeaderView::section {
                background-color: #f5f5f5;
                color: #4CAF50;
                padding: 8px;
                border: 1px solid #e0e0e0;
                font-weight: bold;
            }
            QTableWidget::item {
                padding: 5px;
            }
            QTableWidget::item:selected {
                background-color: #4CAF50;
                color: white;
            }
        """
