"""
Scope Tab Builder
Handles the scope management UI including technology detection, IP info, and project description.
"""

from PyQt5.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QGroupBox, QLabel,
    QTextEdit, QTableWidget, QAbstractItemView, QPushButton,
    QFrame, QHeaderView, QLineEdit, QComboBox, QSpinBox
)
from PyQt5.QtGui import QFont
from PyQt5.QtCore import Qt


class ScopeTabBuilder:
    """Builder class for creating the Scope tab"""

    def __init__(self, gui, collapsible_box_class):
        """
        Initialize the builder with reference to main GUI

        Args:
            gui: Reference to DominatorGUI instance
            collapsible_box_class: The CollapsibleBox class for creating collapsible sections
        """
        self.gui = gui
        self.CollapsibleBox = collapsible_box_class

    def build(self):
        """Create and return the scope tab widget"""
        widget = QWidget()
        widget.setStyleSheet("""
            QWidget {
                background-color: white;
                color: black;
            }
            QGroupBox {
                background-color: #f8f8f8;
                border: 1px solid #e0e0e0;
                border-radius: 8px;
                margin-top: 12px;
                padding-top: 10px;
                font-weight: bold;
            }
            QGroupBox::title {
                color: #333333;
                subcontrol-origin: margin;
                left: 15px;
                padding: 0 8px;
            }
        """)

        layout = QVBoxLayout(widget)
        layout.setSpacing(12)

        # Stats Summary Card
        stats_card = self._create_stats_summary()
        layout.addWidget(stats_card)

        # Project Description - Collapsible
        desc_box = self.CollapsibleBox("📋 Project Information")
        desc_content = QVBoxLayout()
        desc_widget = self._create_project_description_content()
        desc_content.addWidget(desc_widget)
        desc_box.setContentLayout(desc_content)
        desc_box.setContentHeight(180)
        layout.addWidget(desc_box)

        # Scope Management - Collapsible
        scope_box = self.CollapsibleBox("🎯 Scan Scope")
        scope_content = QVBoxLayout()
        scope_widget = self._create_scope_management_content()
        scope_content.addWidget(scope_widget)
        scope_box.setContentLayout(scope_content)
        scope_box.setContentHeight(250)
        layout.addWidget(scope_box)

        # Technology Detection - Collapsible
        tech_box = self.CollapsibleBox("🔧 Detected Technologies")
        tech_content = QVBoxLayout()
        tech_widget = self._create_technology_detection_content()
        tech_content.addWidget(tech_widget)
        tech_box.setContentLayout(tech_content)
        tech_box.setContentHeight(200)
        layout.addWidget(tech_box)

        # IP Geolocation - Collapsible
        geo_box = self.CollapsibleBox("🌍 IP Geolocation")
        geo_content = QVBoxLayout()
        geo_widget = self._create_ip_geolocation_content()
        geo_content.addWidget(geo_widget)
        geo_box.setContentLayout(geo_content)
        geo_box.setContentHeight(200)
        layout.addWidget(geo_box)

        layout.addStretch()

        return widget

    def _create_stats_summary(self):
        """Create a fancy stats summary card at the top"""
        card = QFrame()
        card.setStyleSheet("""
            QFrame {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
                    stop:0 #4CAF50, stop:1 #2196F3);
                border-radius: 10px;
                padding: 15px;
            }
            QLabel {
                color: white;
                background: transparent;
            }
        """)

        layout = QHBoxLayout(card)

        # Targets stat
        targets_box = self._create_stat_box("🎯", "Targets", "0")
        self.gui.scope_stat_targets = targets_box['value_label']
        layout.addWidget(targets_box['widget'])

        # Technologies stat
        tech_box = self._create_stat_box("🔧", "Technologies", "0")
        self.gui.scope_stat_tech = tech_box['value_label']
        layout.addWidget(tech_box['widget'])

        # IPs stat
        ip_box = self._create_stat_box("🌐", "IP Addresses", "0")
        self.gui.scope_stat_ips = ip_box['value_label']
        layout.addWidget(ip_box['widget'])

        # Vulnerabilities Found stat
        vuln_box = self._create_stat_box("⚠️", "Findings", "0")
        self.gui.scope_stat_vulns = vuln_box['value_label']
        layout.addWidget(vuln_box['widget'])

        return card

    def _create_stat_box(self, icon, label, value):
        """Create a single stat box widget"""
        widget = QFrame()
        widget.setStyleSheet("""
            QFrame {
                background-color: rgba(255, 255, 255, 0.15);
                border-radius: 8px;
                padding: 10px;
            }
        """)

        layout = QVBoxLayout(widget)
        layout.setSpacing(5)
        layout.setContentsMargins(10, 8, 10, 8)

        # Icon and label row
        header = QHBoxLayout()
        icon_label = QLabel(icon)
        icon_label.setFont(QFont("Segoe UI Emoji", 16))
        header.addWidget(icon_label)

        text_label = QLabel(label)
        text_label.setFont(QFont("Arial", 9))
        text_label.setStyleSheet("color: rgba(255, 255, 255, 0.8);")
        header.addWidget(text_label)
        header.addStretch()
        layout.addLayout(header)

        # Value
        value_label = QLabel(value)
        value_label.setFont(QFont("Arial", 24, QFont.Bold))
        value_label.setAlignment(Qt.AlignCenter)
        layout.addWidget(value_label)

        return {'widget': widget, 'value_label': value_label}

    def _create_project_description_content(self):
        """Create project description content"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(5, 5, 5, 5)

        # Quick info row
        info_row = QHBoxLayout()

        # Project name
        info_row.addWidget(QLabel("Project:"))
        self.gui.project_name_input = QLineEdit()
        self.gui.project_name_input.setPlaceholderText("Project name...")
        self.gui.project_name_input.setMaximumWidth(200)
        info_row.addWidget(self.gui.project_name_input)

        # Client name
        info_row.addWidget(QLabel("Client:"))
        self.gui.client_name_input = QLineEdit()
        self.gui.client_name_input.setPlaceholderText("Client name...")
        self.gui.client_name_input.setMaximumWidth(200)
        info_row.addWidget(self.gui.client_name_input)

        info_row.addStretch()
        layout.addLayout(info_row)

        # Description text area
        desc_label = QLabel("Notes & Objectives:")
        desc_label.setStyleSheet("color: #4CAF50; font-weight: bold; margin-top: 8px;")
        layout.addWidget(desc_label)

        self.gui.project_description = QTextEdit()
        self.gui.project_description.setPlaceholderText(
            "Enter project details, scope notes, or testing objectives...\n\n"
            "Example:\n"
            "- Authorized by: John Doe (john@acme.com)\n"
            "- Testing window: Nov 14-18, 2025\n"
            "- Special notes: Avoid production database"
        )
        self.gui.project_description.setMaximumHeight(100)
        self.gui.project_description.setStyleSheet("""
            QTextEdit {
                background-color: #ffffff;
                color: #333333;
                border: 1px solid #cccccc;
                border-radius: 4px;
                padding: 8px;
                font-family: 'Consolas', 'Courier New', monospace;
            }
            QTextEdit:focus {
                border: 1px solid #4CAF50;
            }
        """)
        layout.addWidget(self.gui.project_description)

        return widget

    def _create_scope_management_content(self):
        """Create scope management content"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(10, 10, 10, 10)
        layout.setSpacing(15)

        # Header section with description
        header_frame = QFrame()
        header_frame.setStyleSheet("""
            QFrame {
                background-color: #f0f7ff;
                border-left: 4px solid #2196F3;
                border-radius: 6px;
                padding: 12px;
            }
        """)
        header_layout = QVBoxLayout(header_frame)

        header_title = QLabel("📋 Scope Configuration")
        header_title.setFont(QFont("Segoe UI", 13, QFont.Bold))
        header_title.setStyleSheet("color: #1976D2; background: transparent; border: none; padding: 0;")
        header_layout.addWidget(header_title)

        scope_info = QLabel(
            "Define which targets will be scanned. In-scope targets are actively tested, "
            "while out-of-scope URLs are ignored. Use patterns like *.example.com for wildcard matching."
        )
        scope_info.setFont(QFont("Segoe UI", 10))
        scope_info.setStyleSheet("color: #555555; background: transparent; border: none; padding: 0; margin-top: 4px;")
        scope_info.setWordWrap(True)
        header_layout.addWidget(scope_info)

        layout.addWidget(header_frame)

        # Quick actions card
        actions_card = QFrame()
        actions_card.setStyleSheet("""
            QFrame {
                background-color: #fafafa;
                border: 1px solid #e0e0e0;
                border-radius: 8px;
                padding: 12px;
            }
        """)
        actions_layout = QVBoxLayout(actions_card)
        actions_layout.setSpacing(10)

        actions_title = QLabel("⚡ Quick Actions")
        actions_title.setFont(QFont("Segoe UI", 11, QFont.Bold))
        actions_title.setStyleSheet("color: #424242; background: transparent; border: none; padding: 0;")
        actions_layout.addWidget(actions_title)

        # Buttons row
        buttons_row = QHBoxLayout()
        buttons_row.setSpacing(10)

        # Add target button - large and prominent
        add_btn = QPushButton("➕  Add Target URL/Domain")
        add_btn.setFont(QFont("Segoe UI", 10, QFont.Bold))
        add_btn.setMinimumHeight(40)
        add_btn.setStyleSheet("""
            QPushButton {
                background-color: #4CAF50;
                color: white;
                padding: 10px 20px;
                border-radius: 6px;
                border: none;
                font-size: 12px;
            }
            QPushButton:hover {
                background-color: #45a049;
            }
            QPushButton:pressed {
                background-color: #3d8b40;
            }
        """)
        buttons_row.addWidget(add_btn, 2)

        # Import button
        import_btn = QPushButton("📂  Import List")
        import_btn.setFont(QFont("Segoe UI", 10))
        import_btn.setMinimumHeight(40)
        import_btn.setStyleSheet("""
            QPushButton {
                background-color: #2196F3;
                color: white;
                padding: 10px 15px;
                border-radius: 6px;
                border: none;
                font-size: 11px;
            }
            QPushButton:hover {
                background-color: #1976D2;
            }
            QPushButton:pressed {
                background-color: #1565C0;
            }
        """)
        buttons_row.addWidget(import_btn, 1)

        # Export button
        export_btn = QPushButton("📤  Export")
        export_btn.setFont(QFont("Segoe UI", 10))
        export_btn.setMinimumHeight(40)
        export_btn.setStyleSheet("""
            QPushButton {
                background-color: #FF9800;
                color: white;
                padding: 10px 15px;
                border-radius: 6px;
                border: none;
                font-size: 11px;
            }
            QPushButton:hover {
                background-color: #F57C00;
            }
            QPushButton:pressed {
                background-color: #EF6C00;
            }
        """)
        buttons_row.addWidget(export_btn, 1)

        # Clear all button
        clear_btn = QPushButton("🗑️  Clear All")
        clear_btn.setFont(QFont("Segoe UI", 10))
        clear_btn.setMinimumHeight(40)
        clear_btn.setStyleSheet("""
            QPushButton {
                background-color: #f44336;
                color: white;
                padding: 10px 15px;
                border-radius: 6px;
                border: none;
                font-size: 11px;
            }
            QPushButton:hover {
                background-color: #d32f2f;
            }
            QPushButton:pressed {
                background-color: #c62828;
            }
        """)
        buttons_row.addWidget(clear_btn, 1)

        actions_layout.addLayout(buttons_row)
        layout.addWidget(actions_card)

        # Filter and view controls
        controls_row = QHBoxLayout()
        controls_row.setSpacing(12)

        # Filter label
        filter_label = QLabel("🔍 Filter:")
        filter_label.setFont(QFont("Segoe UI", 10, QFont.Bold))
        filter_label.setStyleSheet("color: #424242;")
        controls_row.addWidget(filter_label)

        # Filter dropdown - enhanced
        filter_combo = QComboBox()
        filter_combo.addItems([
            "📋 All Targets",
            "✅ In Scope Only",
            "❌ Out of Scope",
            "⚠️ With Vulnerabilities",
            "🔧 With Technologies"
        ])
        filter_combo.setFont(QFont("Segoe UI", 10))
        filter_combo.setMinimumHeight(32)
        filter_combo.setStyleSheet("""
            QComboBox {
                background-color: white;
                border: 2px solid #e0e0e0;
                border-radius: 6px;
                padding: 5px 10px;
                min-width: 180px;
                font-size: 11px;
            }
            QComboBox:hover {
                border: 2px solid #2196F3;
            }
            QComboBox::drop-down {
                border: none;
                width: 25px;
            }
            QComboBox::down-arrow {
                image: none;
                border-left: 5px solid transparent;
                border-right: 5px solid transparent;
                border-top: 6px solid #666;
                margin-right: 8px;
            }
        """)
        controls_row.addWidget(filter_combo)

        # Search box
        search_box = QLineEdit()
        search_box.setPlaceholderText("🔎 Search URLs, domains, or IPs...")
        search_box.setFont(QFont("Segoe UI", 10))
        search_box.setMinimumHeight(32)
        search_box.setStyleSheet("""
            QLineEdit {
                background-color: white;
                border: 2px solid #e0e0e0;
                border-radius: 6px;
                padding: 5px 12px;
                font-size: 11px;
            }
            QLineEdit:focus {
                border: 2px solid #2196F3;
            }
            QLineEdit::placeholder {
                color: #999999;
                font-style: italic;
            }
        """)
        controls_row.addWidget(search_box, 1)

        # View mode toggle
        view_label = QLabel("View:")
        view_label.setFont(QFont("Segoe UI", 10))
        view_label.setStyleSheet("color: #666666;")
        controls_row.addWidget(view_label)

        view_combo = QComboBox()
        view_combo.addItems(["📊 Table", "📇 Cards", "🌳 Tree"])
        view_combo.setFont(QFont("Segoe UI", 10))
        view_combo.setMinimumHeight(32)
        view_combo.setMaximumWidth(120)
        view_combo.setStyleSheet("""
            QComboBox {
                background-color: white;
                border: 2px solid #e0e0e0;
                border-radius: 6px;
                padding: 5px 8px;
                font-size: 10px;
            }
            QComboBox:hover {
                border: 2px solid #2196F3;
            }
        """)
        controls_row.addWidget(view_combo)

        layout.addLayout(controls_row)

        # Scope table with enhanced styling
        self.gui.scope_table = QTableWidget()
        self.gui.scope_table.setColumnCount(6)
        self.gui.scope_table.setHorizontalHeaderLabels([
            "✓ Status",
            "🌐 URL/Domain",
            "📄 Title",
            "🔧 Tech",
            "⚠️ Findings",
            "🔗 Actions"
        ])
        self.gui.scope_table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.gui.scope_table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.gui.scope_table.setSortingEnabled(True)
        self.gui.scope_table.setAlternatingRowColors(True)
        self.gui.scope_table.setFont(QFont("Segoe UI", 10))
        self.gui.scope_table.setMinimumHeight(300)
        # Prevent text overflow - use ellipsis for long text
        self.gui.scope_table.setWordWrap(False)
        self.gui.scope_table.setTextElideMode(Qt.ElideRight)

        # Column sizing
        header = self.gui.scope_table.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.Fixed)
        header.resizeSection(0, 80)  # Status
        header.setSectionResizeMode(1, QHeaderView.Stretch)  # URL
        header.setSectionResizeMode(2, QHeaderView.Interactive)
        header.resizeSection(2, 180)  # Title
        header.setSectionResizeMode(3, QHeaderView.Fixed)
        header.resizeSection(3, 100)  # Technologies
        header.setSectionResizeMode(4, QHeaderView.Fixed)
        header.resizeSection(4, 90)  # Findings
        header.setSectionResizeMode(5, QHeaderView.Fixed)
        header.resizeSection(5, 110)  # Actions

        self.gui.scope_table.setStyleSheet("""
            QTableWidget {
                background-color: #ffffff;
                color: #212121;
                gridline-color: #e8e8e8;
                border: 2px solid #e0e0e0;
                border-radius: 8px;
                font-size: 11px;
            }
            QHeaderView::section {
                background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
                    stop:0 #f5f5f5, stop:1 #e0e0e0);
                color: #2196F3;
                padding: 10px 8px;
                border: none;
                border-bottom: 2px solid #2196F3;
                border-right: 1px solid #d0d0d0;
                font-weight: bold;
                font-size: 11px;
            }
            QHeaderView::section:first {
                border-top-left-radius: 6px;
            }
            QHeaderView::section:last {
                border-top-right-radius: 6px;
                border-right: none;
            }
            QTableWidget::item {
                padding: 8px 6px;
                border-bottom: 1px solid #f0f0f0;
            }
            QTableWidget::item:selected {
                background-color: #e3f2fd;
                color: #1976D2;
            }
            QTableWidget::item:hover {
                background-color: #f5f5f5;
            }
            QTableWidget QTableCornerButton::section {
                background-color: #f5f5f5;
                border: none;
            }
        """)
        layout.addWidget(self.gui.scope_table)

        # Table footer with stats
        footer_row = QHBoxLayout()
        footer_row.setSpacing(15)

        stats_label = QLabel("📊 Showing: 0 targets | ✅ In Scope: 0 | ❌ Out of Scope: 0 | ⚠️ With Issues: 0")
        stats_label.setFont(QFont("Segoe UI", 9))
        stats_label.setStyleSheet("""
            color: #666666;
            padding: 8px;
            background-color: #fafafa;
            border-radius: 4px;
        """)
        footer_row.addWidget(stats_label)
        footer_row.addStretch()

        # Bulk actions
        bulk_label = QLabel("Bulk Actions:")
        bulk_label.setFont(QFont("Segoe UI", 9, QFont.Bold))
        bulk_label.setStyleSheet("color: #666666;")
        footer_row.addWidget(bulk_label)

        select_all_btn = QPushButton("Select All")
        select_all_btn.setStyleSheet("""
            QPushButton {
                background-color: #9E9E9E;
                color: white;
                padding: 5px 12px;
                border-radius: 4px;
                font-size: 9px;
            }
            QPushButton:hover {
                background-color: #757575;
            }
        """)
        footer_row.addWidget(select_all_btn)

        remove_selected_btn = QPushButton("Remove Selected")
        remove_selected_btn.setStyleSheet("""
            QPushButton {
                background-color: #f44336;
                color: white;
                padding: 5px 12px;
                border-radius: 4px;
                font-size: 9px;
            }
            QPushButton:hover {
                background-color: #d32f2f;
            }
        """)
        footer_row.addWidget(remove_selected_btn)

        layout.addLayout(footer_row)

        return widget

    def _create_technology_detection_content(self):
        """Create technology detection content"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(10, 10, 10, 10)
        layout.setSpacing(12)

        # Header frame with info
        header_frame = QFrame()
        header_frame.setStyleSheet("""
            QFrame {
                background-color: #f0f7ff;
                border-left: 4px solid #2196F3;
                border-radius: 6px;
                padding: 10px;
            }
        """)
        header_layout = QVBoxLayout(header_frame)

        header_title = QLabel("🔧 Technology Stack Detection")
        header_title.setFont(QFont("Segoe UI", 12, QFont.Bold))
        header_title.setStyleSheet("color: #1976D2; background: transparent; border: none; padding: 0;")
        header_layout.addWidget(header_title)

        tech_info = QLabel(
            "Detected technologies running on target servers including CMS, frameworks, "
            "JavaScript libraries, web servers, CDNs, and analytics platforms."
        )
        tech_info.setFont(QFont("Segoe UI", 9))
        tech_info.setStyleSheet("color: #555555; background: transparent; border: none; padding: 0; margin-top: 4px;")
        tech_info.setWordWrap(True)
        header_layout.addWidget(tech_info)

        layout.addWidget(header_frame)

        # Search and filter row with enhanced styling
        controls_frame = QFrame()
        controls_frame.setStyleSheet("""
            QFrame {
                background-color: #fafafa;
                border: 1px solid #e0e0e0;
                border-radius: 6px;
                padding: 8px;
            }
        """)
        controls_row = QHBoxLayout(controls_frame)
        controls_row.setSpacing(10)

        # Search label
        search_label = QLabel("🔍 Filter:")
        search_label.setFont(QFont("Segoe UI", 10, QFont.Bold))
        search_label.setStyleSheet("color: #424242; background: transparent; border: none;")
        controls_row.addWidget(search_label)

        # Search box with better styling
        search = QLineEdit()
        search.setPlaceholderText("Search by name or category...")
        search.setFont(QFont("Segoe UI", 10))
        search.setMinimumHeight(32)
        search.setStyleSheet("""
            QLineEdit {
                background-color: white;
                border: 2px solid #e0e0e0;
                border-radius: 6px;
                padding: 5px 12px;
                font-size: 11px;
            }
            QLineEdit:focus {
                border: 2px solid #2196F3;
            }
            QLineEdit::placeholder {
                color: #999999;
                font-style: italic;
            }
        """)
        controls_row.addWidget(search, 1)

        # Category label
        cat_label = QLabel("Category:")
        cat_label.setFont(QFont("Segoe UI", 10))
        cat_label.setStyleSheet("color: #666666; background: transparent; border: none;")
        controls_row.addWidget(cat_label)

        # Category filter with better styling
        cat_combo = QComboBox()
        cat_combo.addItems(["All Categories", "CMS", "Framework", "JavaScript", "Server", "CDN", "Analytics", "Database"])
        cat_combo.setFont(QFont("Segoe UI", 10))
        cat_combo.setMinimumHeight(32)
        cat_combo.setMaximumWidth(150)
        cat_combo.setStyleSheet("""
            QComboBox {
                background-color: white;
                border: 2px solid #e0e0e0;
                border-radius: 6px;
                padding: 5px 10px;
                font-size: 10px;
            }
            QComboBox:hover {
                border: 2px solid #2196F3;
            }
            QComboBox::drop-down {
                border: none;
                width: 20px;
            }
            QComboBox::down-arrow {
                image: none;
                border-left: 4px solid transparent;
                border-right: 4px solid transparent;
                border-top: 5px solid #666;
                margin-right: 5px;
            }
        """)
        controls_row.addWidget(cat_combo)

        layout.addWidget(controls_frame)

        # Tech table with enhanced styling
        self.gui.tech_table = QTableWidget()
        self.gui.tech_table.setColumnCount(5)
        self.gui.tech_table.setHorizontalHeaderLabels(["Technology", "Version", "Category", "Confidence", "Found On"])
        self.gui.tech_table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.gui.tech_table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.gui.tech_table.setSortingEnabled(True)
        self.gui.tech_table.setAlternatingRowColors(True)
        self.gui.tech_table.setFont(QFont("Segoe UI", 10))
        self.gui.tech_table.setMinimumHeight(200)
        # Prevent text overflow - use ellipsis for long text
        self.gui.tech_table.setWordWrap(False)
        self.gui.tech_table.setTextElideMode(Qt.ElideRight)

        # Column sizing
        header = self.gui.tech_table.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.Fixed)
        header.resizeSection(0, 150)  # Technology
        header.setSectionResizeMode(1, QHeaderView.Fixed)
        header.resizeSection(1, 100)  # Version
        header.setSectionResizeMode(2, QHeaderView.Fixed)
        header.resizeSection(2, 120)  # Category
        header.setSectionResizeMode(3, QHeaderView.Fixed)
        header.resizeSection(3, 100)  # Confidence
        header.setSectionResizeMode(4, QHeaderView.Stretch)  # Found On

        self.gui.tech_table.setStyleSheet("""
            QTableWidget {
                background-color: #ffffff;
                color: #212121;
                gridline-color: #e8e8e8;
                border: 2px solid #e0e0e0;
                border-radius: 8px;
                font-size: 11px;
            }
            QHeaderView::section {
                background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
                    stop:0 #f5f5f5, stop:1 #e0e0e0);
                color: #2196F3;
                padding: 10px 8px;
                border: none;
                border-bottom: 2px solid #2196F3;
                border-right: 1px solid #d0d0d0;
                font-weight: bold;
                font-size: 11px;
            }
            QHeaderView::section:last {
                border-right: none;
            }
            QTableWidget::item {
                padding: 8px 6px;
                border-bottom: 1px solid #f0f0f0;
            }
            QTableWidget::item:selected {
                background-color: #e3f2fd;
                color: #1976D2;
            }
            QTableWidget::item:hover {
                background-color: #f5f5f5;
            }
        """)
        layout.addWidget(self.gui.tech_table)

        # Footer stats
        footer_label = QLabel("📊 Total Technologies: 0 | CMS: 0 | Frameworks: 0 | Libraries: 0")
        footer_label.setFont(QFont("Segoe UI", 9))
        footer_label.setStyleSheet("""
            color: #666666;
            padding: 8px;
            background-color: #fafafa;
            border-radius: 4px;
        """)
        layout.addWidget(footer_label)

        return widget

    def _create_ip_geolocation_content(self):
        """Create IP geolocation content"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(10, 10, 10, 10)
        layout.setSpacing(12)

        # Header frame with info
        header_frame = QFrame()
        header_frame.setStyleSheet("""
            QFrame {
                background-color: #f0f7ff;
                border-left: 4px solid #9C27B0;
                border-radius: 6px;
                padding: 10px;
            }
        """)
        header_layout = QVBoxLayout(header_frame)

        header_title = QLabel("🌍 IP Geolocation & Network Information")
        header_title.setFont(QFont("Segoe UI", 12, QFont.Bold))
        header_title.setStyleSheet("color: #7B1FA2; background: transparent; border: none; padding: 0;")
        header_layout.addWidget(header_title)

        geo_info = QLabel(
            "Geographic and network details for discovered IP addresses including country, "
            "city, region, ISP provider, and associated domain names."
        )
        geo_info.setFont(QFont("Segoe UI", 9))
        geo_info.setStyleSheet("color: #555555; background: transparent; border: none; padding: 0; margin-top: 4px;")
        geo_info.setWordWrap(True)
        header_layout.addWidget(geo_info)

        layout.addWidget(header_frame)

        # Controls row with enhanced styling
        controls_frame = QFrame()
        controls_frame.setStyleSheet("""
            QFrame {
                background-color: #fafafa;
                border: 1px solid #e0e0e0;
                border-radius: 6px;
                padding: 8px;
            }
        """)
        controls_row = QHBoxLayout(controls_frame)
        controls_row.setSpacing(10)

        # Search label
        search_label = QLabel("🔍 Search:")
        search_label.setFont(QFont("Segoe UI", 10, QFont.Bold))
        search_label.setStyleSheet("color: #424242; background: transparent; border: none;")
        controls_row.addWidget(search_label)

        # Search box
        search = QLineEdit()
        search.setPlaceholderText("Filter by IP, country, city, or ISP...")
        search.setFont(QFont("Segoe UI", 10))
        search.setMinimumHeight(32)
        search.setStyleSheet("""
            QLineEdit {
                background-color: white;
                border: 2px solid #e0e0e0;
                border-radius: 6px;
                padding: 5px 12px;
                font-size: 11px;
            }
            QLineEdit:focus {
                border: 2px solid #9C27B0;
            }
            QLineEdit::placeholder {
                color: #999999;
                font-style: italic;
            }
        """)
        controls_row.addWidget(search, 1)

        controls_row.addStretch()

        # Refresh button with better styling
        refresh_btn = QPushButton("🔄 Refresh Data")
        refresh_btn.setFont(QFont("Segoe UI", 10, QFont.Bold))
        refresh_btn.setMinimumHeight(32)
        refresh_btn.setStyleSheet("""
            QPushButton {
                background-color: #FF9800;
                color: white;
                padding: 6px 16px;
                border-radius: 6px;
                border: none;
                font-size: 11px;
            }
            QPushButton:hover {
                background-color: #F57C00;
            }
            QPushButton:pressed {
                background-color: #EF6C00;
            }
        """)
        controls_row.addWidget(refresh_btn)

        # Map view button with better styling
        map_btn = QPushButton("🗺️ Map View")
        map_btn.setFont(QFont("Segoe UI", 10, QFont.Bold))
        map_btn.setMinimumHeight(32)
        map_btn.setStyleSheet("""
            QPushButton {
                background-color: #9C27B0;
                color: white;
                padding: 6px 16px;
                border-radius: 6px;
                border: none;
                font-size: 11px;
            }
            QPushButton:hover {
                background-color: #7B1FA2;
            }
            QPushButton:pressed {
                background-color: #6A1B9A;
            }
        """)
        controls_row.addWidget(map_btn)

        layout.addWidget(controls_frame)

        # Geo table with enhanced styling
        self.gui.geo_table = QTableWidget()
        self.gui.geo_table.setColumnCount(6)
        self.gui.geo_table.setHorizontalHeaderLabels(["IP Address", "Country", "City", "Region", "ISP", "Domain"])
        self.gui.geo_table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.gui.geo_table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.gui.geo_table.setSortingEnabled(True)
        self.gui.geo_table.setAlternatingRowColors(True)
        self.gui.geo_table.setFont(QFont("Segoe UI", 10))
        self.gui.geo_table.setMinimumHeight(200)
        # Prevent text overflow - use ellipsis for long text
        self.gui.geo_table.setWordWrap(False)
        self.gui.geo_table.setTextElideMode(Qt.ElideRight)

        # Column sizing
        header = self.gui.geo_table.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.Fixed)
        header.resizeSection(0, 140)  # IP
        header.setSectionResizeMode(1, QHeaderView.Fixed)
        header.resizeSection(1, 100)  # Country
        header.setSectionResizeMode(2, QHeaderView.Fixed)
        header.resizeSection(2, 120)  # City
        header.setSectionResizeMode(3, QHeaderView.Fixed)
        header.resizeSection(3, 100)  # Region
        header.setSectionResizeMode(4, QHeaderView.Fixed)
        header.resizeSection(4, 150)  # ISP
        header.setSectionResizeMode(5, QHeaderView.Stretch)  # Domain

        self.gui.geo_table.setStyleSheet("""
            QTableWidget {
                background-color: #ffffff;
                color: #212121;
                gridline-color: #e8e8e8;
                border: 2px solid #e0e0e0;
                border-radius: 8px;
                font-size: 11px;
            }
            QHeaderView::section {
                background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
                    stop:0 #f5f5f5, stop:1 #e0e0e0);
                color: #9C27B0;
                padding: 10px 8px;
                border: none;
                border-bottom: 2px solid #9C27B0;
                border-right: 1px solid #d0d0d0;
                font-weight: bold;
                font-size: 11px;
            }
            QHeaderView::section:last {
                border-right: none;
            }
            QTableWidget::item {
                padding: 8px 6px;
                border-bottom: 1px solid #f0f0f0;
            }
            QTableWidget::item:selected {
                background-color: #f3e5f5;
                color: #7B1FA2;
            }
            QTableWidget::item:hover {
                background-color: #f5f5f5;
            }
        """)
        layout.addWidget(self.gui.geo_table)

        # Footer stats
        footer_label = QLabel("📊 Total IPs: 0 | Countries: 0 | Unique ISPs: 0")
        footer_label.setFont(QFont("Segoe UI", 9))
        footer_label.setStyleSheet("""
            color: #666666;
            padding: 8px;
            background-color: #fafafa;
            border-radius: 4px;
        """)
        layout.addWidget(footer_label)

        return widget

    def _get_table_stylesheet(self):
        """Return common table stylesheet with light theme"""
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
                background-color: #e8f5e9;
                color: #333333;
            }
            QTableWidget::item:hover {
                background-color: #f5f5f5;
            }
        """
