"""
Results Tab Builder
Handles the results tab UI including vulnerability dashboard, filters, results table, and detail panel.
"""

import json
from datetime import datetime
from PyQt5.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QGridLayout, QGroupBox,
    QLabel, QListWidget, QPushButton, QFrame, QSplitter, QTableWidget,
    QTableWidgetItem, QHeaderView, QComboBox, QLineEdit, QTextEdit,
    QMenu, QAction, QFileDialog, QMessageBox, QScrollArea, QSizePolicy,
    QAbstractItemView, QDialog, QDialogButtonBox, QTabWidget, QToolButton,
    QTreeWidget, QTreeWidgetItem
)
from PyQt5.QtCore import Qt, pyqtSignal, QTimer, QPropertyAnimation, QEasingCurve
from PyQt5.QtGui import QColor, QFont, QPainter, QBrush, QPen
from GUI.dialogs.custom_report_dialog import CustomReportDialog
from GUI.ui_tabs.results_tab_widgets import (
    CollapsibleResourcesSection, PieChartWidget, TimelineWidget,
    StatsCard, FindingDetailDialog, SEVERITY_COLORS
)



class ResultsTabBuilder:
    """Builder class for creating the Results tab"""

    def __init__(self, gui, collapsible_box_class):
        """
        Initialize the builder with reference to main GUI

        Args:
            gui: Reference to DominatorGUI instance
            collapsible_box_class: The CollapsibleBox class
        """
        self.gui = gui
        self.CollapsibleBox = collapsible_box_class
        self.findings = []  # Store all findings data
        self.filtered_findings = []  # Store filtered findings
        self.timeline_data = []  # Timeline data for chart

    def build(self):
        """Create and return the results tab widget with subtabs"""
        from GUI.ui_tabs.progress_tab import ProgressTabBuilder

        widget = QWidget()
        main_layout = QVBoxLayout(widget)
        main_layout.setSpacing(0)
        main_layout.setContentsMargins(0, 0, 0, 0)

        # Create subtabs for Results and Progress
        self.results_subtabs = QTabWidget()
        self.results_subtabs.setStyleSheet("""
            QTabWidget::pane {
                border: 2px solid #e0e0e0;
                background-color: #ffffff;
                border-radius: 4px;
            }
            QTabBar::tab {
                background-color: #f5f5f5;
                color: #333333;
                padding: 12px 24px;
                border: 2px solid #e0e0e0;
                border-bottom: none;
                margin-right: 3px;
                border-radius: 6px 6px 0 0;
                font-weight: bold;
                font-size: 13px;
                min-width: 120px;
            }
            QTabBar::tab:selected {
                background-color: #ffffff;
                color: #4CAF50;
                border-bottom: 3px solid #4CAF50;
                padding-bottom: 11px;
            }
            QTabBar::tab:hover {
                background-color: #e8f5e9;
            }
        """)

        # === Results subtab ===
        results_content = QWidget()
        results_layout = QVBoxLayout(results_content)
        results_layout.setSpacing(10)
        results_layout.setContentsMargins(10, 10, 10, 10)

        # Dashboard header with stats
        dashboard = self._create_dashboard()
        results_layout.addWidget(dashboard)

        # Filters section
        filters = self._create_filters()
        results_layout.addWidget(filters)

        # Main content: Results table and detail panel
        splitter = QSplitter(Qt.Horizontal)

        # Left side: Results table
        results_widget = self._create_results_table()
        splitter.addWidget(results_widget)

        # Right side: Detail panel
        detail_widget = self._create_detail_panel()
        splitter.addWidget(detail_widget)

        splitter.setSizes([600, 400])
        results_layout.addWidget(splitter)

        # Discovered Resources collapsible section
        resources_section = self._create_resources_section()
        results_layout.addWidget(resources_section)

        # Export options bar
        export_bar = self._create_export_bar()
        results_layout.addWidget(export_bar)

        self.results_subtabs.addTab(results_content, "Findings")

        # === Scan Output subtab ===
        scan_output_content = self._create_scan_output_tab()
        self.results_subtabs.addTab(scan_output_content, "Scan Output")

        # === Progress subtab ===
        # Import and build the progress tab content
        progress_builder = ProgressTabBuilder(self.gui, self.CollapsibleBox)
        progress_content = progress_builder.build()
        self.gui.progress_tab_builder = progress_builder  # Store reference for updates

        self.results_subtabs.addTab(progress_content, "Progress")

        # === Debug subtab ===
        debug_content = self._create_debug_tab()
        self.results_subtabs.addTab(debug_content, "Debug")

        # === Site Tree subtab ===
        site_tree_content = self._create_site_tree_tab()
        self.results_subtabs.addTab(site_tree_content, "🌳 Site Tree")

        main_layout.addWidget(self.results_subtabs)

        return widget

    def _create_resources_section(self):
        """Create collapsible section for discovered resources"""
        self.gui.resources_section = CollapsibleResourcesSection("Discovered Resources (0)")

        # Create tab widget for different resource types
        resources_tabs = QTabWidget()
        resources_tabs.setStyleSheet("""
            QTabWidget::pane {
                border: 1px solid #e0e0e0;
                background-color: #ffffff;
                border-radius: 4px;
            }
            QTabBar::tab {
                background-color: #f5f5f5;
                color: #333333;
                padding: 6px 12px;
                border: 1px solid #e0e0e0;
                border-bottom: none;
                margin-right: 2px;
            }
            QTabBar::tab:selected {
                background-color: #ffffff;
                color: #4CAF50;
                font-weight: bold;
            }
            QTabBar::tab:hover {
                background-color: #e8e8e8;
            }
        """)

        # URLs/Endpoints tab
        urls_widget = QWidget()
        urls_layout = QVBoxLayout(urls_widget)
        urls_layout.setContentsMargins(5, 5, 5, 5)

        self.gui.resources_table = QTableWidget()
        self.gui.resources_table.setColumnCount(4)
        self.gui.resources_table.setHorizontalHeaderLabels(["Type", "URL/Path", "Parameters", "Status"])
        self.gui.resources_table.horizontalHeader().setStretchLastSection(True)
        self.gui.resources_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeToContents)
        self.gui.resources_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.Stretch)
        self.gui.resources_table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeToContents)
        self.gui.resources_table.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeToContents)
        self.gui.resources_table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.gui.resources_table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.gui.resources_table.setStyleSheet(self._get_resources_table_stylesheet())
        urls_layout.addWidget(self.gui.resources_table)

        resources_tabs.addTab(urls_widget, "URLs & Endpoints")

        # Social Media tab
        social_widget = QWidget()
        social_layout = QVBoxLayout(social_widget)
        social_layout.setContentsMargins(5, 5, 5, 5)

        self.gui.social_media_table = QTableWidget()
        self.gui.social_media_table.setColumnCount(3)
        self.gui.social_media_table.setHorizontalHeaderLabels(["Platform", "URL", "Found On"])
        self.gui.social_media_table.horizontalHeader().setStretchLastSection(True)
        self.gui.social_media_table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.gui.social_media_table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.gui.social_media_table.setStyleSheet(self._get_resources_table_stylesheet())
        social_layout.addWidget(self.gui.social_media_table)

        resources_tabs.addTab(social_widget, "Social Media")

        # Emails tab
        emails_widget = QWidget()
        emails_layout = QVBoxLayout(emails_widget)
        emails_layout.setContentsMargins(5, 5, 5, 5)

        self.gui.emails_table = QTableWidget()
        self.gui.emails_table.setColumnCount(3)
        self.gui.emails_table.setHorizontalHeaderLabels(["Email", "Type", "Found On"])
        self.gui.emails_table.horizontalHeader().setStretchLastSection(True)
        self.gui.emails_table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.gui.emails_table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.gui.emails_table.setStyleSheet(self._get_resources_table_stylesheet())
        emails_layout.addWidget(self.gui.emails_table)

        resources_tabs.addTab(emails_widget, "Emails")

        # Phones tab
        phones_widget = QWidget()
        phones_layout = QVBoxLayout(phones_widget)
        phones_layout.setContentsMargins(5, 5, 5, 5)

        self.gui.phones_table = QTableWidget()
        self.gui.phones_table.setColumnCount(3)
        self.gui.phones_table.setHorizontalHeaderLabels(["Phone Number", "Format", "Found On"])
        self.gui.phones_table.horizontalHeader().setStretchLastSection(True)
        self.gui.phones_table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.gui.phones_table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.gui.phones_table.setStyleSheet(self._get_resources_table_stylesheet())
        phones_layout.addWidget(self.gui.phones_table)

        resources_tabs.addTab(phones_widget, "Phones")

        # Leaked Keys tab
        keys_widget = QWidget()
        keys_layout = QVBoxLayout(keys_widget)
        keys_layout.setContentsMargins(5, 5, 5, 5)

        self.gui.leaked_keys_table = QTableWidget()
        self.gui.leaked_keys_table.setColumnCount(4)
        self.gui.leaked_keys_table.setHorizontalHeaderLabels(["Key Type", "Key Preview", "Severity", "Found On"])
        self.gui.leaked_keys_table.horizontalHeader().setStretchLastSection(True)
        self.gui.leaked_keys_table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.gui.leaked_keys_table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.gui.leaked_keys_table.setStyleSheet(self._get_resources_table_stylesheet())
        keys_layout.addWidget(self.gui.leaked_keys_table)

        resources_tabs.addTab(keys_widget, "Leaked Keys")

        # Add tabs to section
        self.gui.resources_section.add_widget(resources_tabs)

        # Export resources button
        export_resources_btn = QPushButton("Export Resources")
        export_resources_btn.setStyleSheet("""
            QPushButton {
                background-color: #4CAF50;
                color: white;
                border: none;
                border-radius: 4px;
                padding: 6px 12px;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: #388E3C;
            }
        """)
        export_resources_btn.clicked.connect(self._export_resources)
        self.gui.resources_section.add_widget(export_resources_btn)

        # Store reference for old code compatibility
        self.gui.social_group = QGroupBox()
        self.gui.social_group.hide()
        self.gui.emails_group = QGroupBox()
        self.gui.emails_group.hide()
        self.gui.phones_group = QGroupBox()
        self.gui.phones_group.hide()
        self.gui.keys_group = QGroupBox()
        self.gui.keys_group.hide()

        return self.gui.resources_section

    def _get_resources_table_stylesheet(self):
        """Return common table stylesheet for resources tables"""
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

    def _export_resources(self):
        """Export discovered resources to file"""
        # Collect all resources
        resources = {
            'urls_endpoints': [],
            'social_media': [],
            'emails': [],
            'phones': [],
            'leaked_keys': []
        }

        # URLs/Endpoints
        for row in range(self.gui.resources_table.rowCount()):
            resources['urls_endpoints'].append({
                'type': self.gui.resources_table.item(row, 0).text() if self.gui.resources_table.item(row, 0) else '',
                'url': self.gui.resources_table.item(row, 1).text() if self.gui.resources_table.item(row, 1) else '',
                'parameters': self.gui.resources_table.item(row, 2).text() if self.gui.resources_table.item(row, 2) else '',
                'status': self.gui.resources_table.item(row, 3).text() if self.gui.resources_table.item(row, 3) else ''
            })

        # Social Media
        for row in range(self.gui.social_media_table.rowCount()):
            resources['social_media'].append({
                'platform': self.gui.social_media_table.item(row, 0).text() if self.gui.social_media_table.item(row, 0) else '',
                'url': self.gui.social_media_table.item(row, 1).text() if self.gui.social_media_table.item(row, 1) else '',
                'found_on': self.gui.social_media_table.item(row, 2).text() if self.gui.social_media_table.item(row, 2) else ''
            })

        # Emails
        for row in range(self.gui.emails_table.rowCount()):
            resources['emails'].append({
                'email': self.gui.emails_table.item(row, 0).text() if self.gui.emails_table.item(row, 0) else '',
                'type': self.gui.emails_table.item(row, 1).text() if self.gui.emails_table.item(row, 1) else '',
                'found_on': self.gui.emails_table.item(row, 2).text() if self.gui.emails_table.item(row, 2) else ''
            })

        # Phones
        for row in range(self.gui.phones_table.rowCount()):
            resources['phones'].append({
                'phone': self.gui.phones_table.item(row, 0).text() if self.gui.phones_table.item(row, 0) else '',
                'format': self.gui.phones_table.item(row, 1).text() if self.gui.phones_table.item(row, 1) else '',
                'found_on': self.gui.phones_table.item(row, 2).text() if self.gui.phones_table.item(row, 2) else ''
            })

        # Leaked Keys
        for row in range(self.gui.leaked_keys_table.rowCount()):
            resources['leaked_keys'].append({
                'key_type': self.gui.leaked_keys_table.item(row, 0).text() if self.gui.leaked_keys_table.item(row, 0) else '',
                'key_preview': self.gui.leaked_keys_table.item(row, 1).text() if self.gui.leaked_keys_table.item(row, 1) else '',
                'severity': self.gui.leaked_keys_table.item(row, 2).text() if self.gui.leaked_keys_table.item(row, 2) else '',
                'found_on': self.gui.leaked_keys_table.item(row, 3).text() if self.gui.leaked_keys_table.item(row, 3) else ''
            })

        # Check if there's anything to export
        total_items = sum(len(v) for v in resources.values())
        if total_items == 0:
            QMessageBox.information(self.gui, "No Data", "No resources to export")
            return

        filename, _ = QFileDialog.getSaveFileName(
            self.gui, "Export Resources",
            f"resources_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json",
            "JSON Files (*.json);;Text Files (*.txt)"
        )

        if filename:
            try:
                if filename.endswith('.json'):
                    with open(filename, 'w', encoding='utf-8') as f:
                        json.dump(resources, f, indent=2)
                else:
                    with open(filename, 'w', encoding='utf-8') as f:
                        f.write("=== Discovered Resources ===\n\n")

                        if resources['urls_endpoints']:
                            f.write("--- URLs & Endpoints ---\n")
                            for item in resources['urls_endpoints']:
                                f.write(f"[{item['type']}] {item['url']}")
                                if item['parameters']:
                                    f.write(f" | Params: {item['parameters']}")
                                if item['status']:
                                    f.write(f" | Status: {item['status']}")
                                f.write("\n")
                            f.write("\n")

                        if resources['social_media']:
                            f.write("--- Social Media ---\n")
                            for item in resources['social_media']:
                                f.write(f"[{item['platform']}] {item['url']} (Found on: {item['found_on']})\n")
                            f.write("\n")

                        if resources['emails']:
                            f.write("--- Emails ---\n")
                            for item in resources['emails']:
                                f.write(f"{item['email']} [{item['type']}] (Found on: {item['found_on']})\n")
                            f.write("\n")

                        if resources['phones']:
                            f.write("--- Phone Numbers ---\n")
                            for item in resources['phones']:
                                f.write(f"{item['phone']} [{item['format']}] (Found on: {item['found_on']})\n")
                            f.write("\n")

                        if resources['leaked_keys']:
                            f.write("--- Leaked Keys ---\n")
                            for item in resources['leaked_keys']:
                                f.write(f"[{item['key_type']}] {item['key_preview']} | Severity: {item['severity']} (Found on: {item['found_on']})\n")

                QMessageBox.information(self.gui, "Success", f"Exported {total_items} resources to:\n{filename}")
            except Exception as e:
                QMessageBox.critical(self.gui, "Error", f"Failed to export:\n{e}")

    def _create_dashboard(self):
        """Create dashboard header with stats cards and charts"""
        dashboard = QFrame()
        dashboard.setStyleSheet("""
            QFrame {
                background-color: #f8f9fa;
                border: 1px solid #e0e0e0;
                border-radius: 8px;
                padding: 10px;
            }
        """)

        layout = QHBoxLayout(dashboard)
        layout.setSpacing(15)

        # Stats cards
        cards_layout = QVBoxLayout()

        # Total findings card
        self.gui.total_card = StatsCard("Total Findings", "0", "#333333")
        cards_layout.addWidget(self.gui.total_card)

        # Severity cards in a row
        severity_row = QHBoxLayout()

        self.gui.critical_card = StatsCard("Critical", "0", SEVERITY_COLORS['CRITICAL'])
        severity_row.addWidget(self.gui.critical_card)

        self.gui.high_card = StatsCard("High", "0", SEVERITY_COLORS['HIGH'])
        severity_row.addWidget(self.gui.high_card)

        self.gui.medium_card = StatsCard("Medium", "0", SEVERITY_COLORS['MEDIUM'])
        severity_row.addWidget(self.gui.medium_card)

        self.gui.low_card = StatsCard("Low", "0", SEVERITY_COLORS['LOW'])
        severity_row.addWidget(self.gui.low_card)

        cards_layout.addLayout(severity_row)
        layout.addLayout(cards_layout)

        # Charts section
        charts_layout = QVBoxLayout()

        # Pie chart
        pie_label = QLabel("Severity Distribution")
        pie_label.setStyleSheet("font-weight: bold; color: #333333;")
        pie_label.setAlignment(Qt.AlignCenter)
        charts_layout.addWidget(pie_label)

        self.gui.pie_chart = PieChartWidget()
        charts_layout.addWidget(self.gui.pie_chart, alignment=Qt.AlignCenter)

        layout.addLayout(charts_layout)

        # Timeline chart
        timeline_layout = QVBoxLayout()

        timeline_label = QLabel("Findings Timeline")
        timeline_label.setStyleSheet("font-weight: bold; color: #333333;")
        timeline_label.setAlignment(Qt.AlignCenter)
        timeline_layout.addWidget(timeline_label)

        self.gui.timeline_chart = TimelineWidget()
        timeline_layout.addWidget(self.gui.timeline_chart)

        layout.addLayout(timeline_layout)

        # Host statistics section
        host_stats_layout = QVBoxLayout()

        host_label = QLabel("Findings by Host")
        host_label.setStyleSheet("font-weight: bold; color: #333333;")
        host_label.setAlignment(Qt.AlignCenter)
        host_stats_layout.addWidget(host_label)

        # Host stats list (compact table showing top hosts)
        self.gui.host_stats_list = QListWidget()
        self.gui.host_stats_list.setMaximumHeight(120)
        self.gui.host_stats_list.setMaximumWidth(200)
        self.gui.host_stats_list.setStyleSheet("""
            QListWidget {
                background-color: #ffffff;
                border: 1px solid #e0e0e0;
                border-radius: 4px;
                font-size: 10px;
            }
            QListWidget::item {
                padding: 4px;
                border-bottom: 1px solid #f0f0f0;
            }
            QListWidget::item:selected {
                background-color: #e3f2fd;
                color: #333333;
            }
        """)
        self.gui.host_stats_list.itemClicked.connect(self._on_host_clicked)
        host_stats_layout.addWidget(self.gui.host_stats_list)

        layout.addLayout(host_stats_layout)

        # Legacy labels for compatibility
        self.gui.total_vulns_label = QLabel("Total Vulnerabilities: 0")
        self.gui.total_vulns_label.hide()
        self.gui.critical_label = QLabel("Critical: 0")
        self.gui.critical_label.hide()
        self.gui.high_label = QLabel("High: 0")
        self.gui.high_label.hide()
        self.gui.medium_label = QLabel("Medium: 0")
        self.gui.medium_label.hide()

        return dashboard

    def _create_filters(self):
        """Create filters section"""
        filters_frame = QFrame()
        filters_frame.setStyleSheet("""
            QFrame {
                background-color: #ffffff;
                border: 1px solid #e0e0e0;
                border-radius: 6px;
                padding: 8px;
            }
        """)

        layout = QHBoxLayout(filters_frame)
        layout.setSpacing(10)

        # Severity filter
        severity_label = QLabel("Severity:")
        severity_label.setStyleSheet("color: #333333; font-weight: bold;")
        layout.addWidget(severity_label)

        self.gui.severity_filter = QComboBox()
        self.gui.severity_filter.addItems(["All", "Critical", "High", "Medium", "Low", "Info"])
        self.gui.severity_filter.setStyleSheet("""
            QComboBox {
                background-color: #ffffff;
                border: 1px solid #cccccc;
                border-radius: 4px;
                padding: 5px;
                min-width: 100px;
            }
        """)
        self.gui.severity_filter.currentTextChanged.connect(self._apply_filters)
        layout.addWidget(self.gui.severity_filter)

        # Module filter
        module_label = QLabel("Module:")
        module_label.setStyleSheet("color: #333333; font-weight: bold;")
        layout.addWidget(module_label)

        self.gui.module_filter = QComboBox()
        self.gui.module_filter.addItem("All")
        self.gui.module_filter.setStyleSheet("""
            QComboBox {
                background-color: #ffffff;
                border: 1px solid #cccccc;
                border-radius: 4px;
                padding: 5px;
                min-width: 120px;
            }
        """)
        self.gui.module_filter.currentTextChanged.connect(self._apply_filters)
        layout.addWidget(self.gui.module_filter)

        # Target filter
        target_label = QLabel("Target:")
        target_label.setStyleSheet("color: #333333; font-weight: bold;")
        layout.addWidget(target_label)

        self.gui.target_filter = QComboBox()
        self.gui.target_filter.addItem("All")
        self.gui.target_filter.setStyleSheet("""
            QComboBox {
                background-color: #ffffff;
                border: 1px solid #cccccc;
                border-radius: 4px;
                padding: 5px;
                min-width: 150px;
            }
        """)
        self.gui.target_filter.currentTextChanged.connect(self._apply_filters)
        layout.addWidget(self.gui.target_filter)

        # Search box
        search_label = QLabel("Search:")
        search_label.setStyleSheet("color: #333333; font-weight: bold;")
        layout.addWidget(search_label)

        self.gui.results_search = QLineEdit()
        self.gui.results_search.setPlaceholderText("Search findings...")
        self.gui.results_search.setStyleSheet("""
            QLineEdit {
                background-color: #ffffff;
                border: 1px solid #cccccc;
                border-radius: 4px;
                padding: 5px;
                min-width: 150px;
            }
        """)
        self.gui.results_search.textChanged.connect(self._apply_filters)
        layout.addWidget(self.gui.results_search)

        # Clear filters button
        clear_btn = QPushButton("Clear Filters")
        clear_btn.setStyleSheet("""
            QPushButton {
                background-color: #f0f0f0;
                color: #333333;
                border: 1px solid #cccccc;
                border-radius: 4px;
                padding: 5px 15px;
            }
            QPushButton:hover {
                background-color: #e0e0e0;
            }
        """)
        clear_btn.clicked.connect(self._clear_filters)
        layout.addWidget(clear_btn)

        # Group by target checkbox
        self.gui.group_by_target = QPushButton("Group by Target")
        self.gui.group_by_target.setCheckable(True)
        self.gui.group_by_target.setStyleSheet("""
            QPushButton {
                background-color: #f0f0f0;
                color: #333333;
                border: 1px solid #cccccc;
                border-radius: 4px;
                padding: 5px 15px;
            }
            QPushButton:checked {
                background-color: #2196F3;
                color: white;
            }
            QPushButton:hover {
                background-color: #e0e0e0;
            }
            QPushButton:checked:hover {
                background-color: #1976D2;
            }
        """)
        self.gui.group_by_target.clicked.connect(self._toggle_group_by_target)
        layout.addWidget(self.gui.group_by_target)

        layout.addStretch()

        return filters_frame

    def _create_results_table(self):
        """Create the results table widget"""
        container = QWidget()
        layout = QVBoxLayout(container)
        layout.setContentsMargins(0, 0, 0, 0)

        # Table label
        label = QLabel("Findings")
        label.setStyleSheet("font-size: 14px; font-weight: bold; color: #333333; padding: 5px;")
        layout.addWidget(label)

        # Results table
        self.gui.results_table = QTableWidget()
        self.gui.results_table.setColumnCount(6)
        self.gui.results_table.setHorizontalHeaderLabels(["#", "Severity", "Module", "Title", "Target", "Time"])

        # Style the table
        self.gui.results_table.setStyleSheet("""
            QTableWidget {
                background-color: #ffffff;
                border: 1px solid #e0e0e0;
                border-radius: 4px;
                gridline-color: #f0f0f0;
            }
            QTableWidget::item {
                padding: 8px;
                color: #333333;
            }
            QTableWidget::item:selected {
                background-color: #e3f2fd;
                color: #333333;
            }
            QHeaderView::section {
                background-color: #f5f5f5;
                color: #333333;
                padding: 8px;
                border: none;
                border-bottom: 2px solid #e0e0e0;
                font-weight: bold;
            }
        """)

        # Configure table
        header = self.gui.results_table.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.Fixed)
        header.setSectionResizeMode(1, QHeaderView.Fixed)
        header.setSectionResizeMode(2, QHeaderView.ResizeToContents)
        header.setSectionResizeMode(3, QHeaderView.Stretch)
        header.setSectionResizeMode(4, QHeaderView.ResizeToContents)
        header.setSectionResizeMode(5, QHeaderView.ResizeToContents)

        self.gui.results_table.setColumnWidth(0, 40)
        self.gui.results_table.setColumnWidth(1, 80)

        self.gui.results_table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.gui.results_table.setSelectionMode(QAbstractItemView.ExtendedSelection)
        self.gui.results_table.setSortingEnabled(True)
        self.gui.results_table.setContextMenuPolicy(Qt.CustomContextMenu)

        # Connect signals
        self.gui.results_table.doubleClicked.connect(self._on_row_double_clicked)
        self.gui.results_table.customContextMenuRequested.connect(self._show_context_menu)
        self.gui.results_table.itemSelectionChanged.connect(self._on_selection_changed)

        layout.addWidget(self.gui.results_table)

        # Legacy vulns_list for compatibility
        self.gui.vulns_list = QListWidget()
        self.gui.vulns_list.hide()

        return container

    def _create_detail_panel(self):
        """Create the detail panel for showing selected finding details"""
        container = QWidget()
        layout = QVBoxLayout(container)
        layout.setContentsMargins(0, 0, 0, 0)

        # Panel label
        label = QLabel("Finding Details")
        label.setStyleSheet("font-size: 14px; font-weight: bold; color: #333333; padding: 5px;")
        layout.addWidget(label)

        # Scroll area for details
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setStyleSheet("""
            QScrollArea {
                background-color: #ffffff;
                border: 1px solid #e0e0e0;
                border-radius: 4px;
            }
        """)

        # Detail content widget
        self.gui.detail_content = QWidget()
        detail_layout = QVBoxLayout(self.gui.detail_content)
        detail_layout.setSpacing(10)

        # Severity badge
        self.gui.detail_severity = QLabel("No finding selected")
        self.gui.detail_severity.setAlignment(Qt.AlignCenter)
        self.gui.detail_severity.setStyleSheet("""
            background-color: #f0f0f0;
            color: #666666;
            padding: 10px;
            border-radius: 4px;
            font-weight: bold;
        """)
        detail_layout.addWidget(self.gui.detail_severity)

        # Title
        self.gui.detail_title = QLabel("")
        self.gui.detail_title.setStyleSheet("font-size: 14px; font-weight: bold; color: #333333;")
        self.gui.detail_title.setWordWrap(True)
        detail_layout.addWidget(self.gui.detail_title)

        # Info section
        info_group = QGroupBox("Information")
        info_group.setStyleSheet("QGroupBox { font-weight: bold; color: #333333; }")
        info_layout = QGridLayout(info_group)

        info_layout.addWidget(QLabel("Module:"), 0, 0)
        self.gui.detail_module = QLabel("-")
        self.gui.detail_module.setStyleSheet("color: #333333;")
        info_layout.addWidget(self.gui.detail_module, 0, 1)

        info_layout.addWidget(QLabel("Target:"), 1, 0)
        self.gui.detail_target = QLabel("-")
        self.gui.detail_target.setStyleSheet("color: #333333;")
        self.gui.detail_target.setWordWrap(True)
        info_layout.addWidget(self.gui.detail_target, 1, 1)

        info_layout.addWidget(QLabel("Time:"), 2, 0)
        self.gui.detail_time = QLabel("-")
        self.gui.detail_time.setStyleSheet("color: #333333;")
        info_layout.addWidget(self.gui.detail_time, 2, 1)

        info_layout.addWidget(QLabel("CVSS:"), 3, 0)
        self.gui.detail_cvss = QLabel("-")
        self.gui.detail_cvss.setStyleSheet("color: #333333; font-weight: bold;")
        info_layout.addWidget(self.gui.detail_cvss, 3, 1)

        detail_layout.addWidget(info_group)

        # References section
        ref_group = QGroupBox("References")
        ref_group.setStyleSheet("QGroupBox { font-weight: bold; color: #333333; }")
        ref_layout = QVBoxLayout(ref_group)

        self.gui.detail_cwe = QLabel("CWE: -")
        self.gui.detail_cwe.setStyleSheet("color: #333333;")
        ref_layout.addWidget(self.gui.detail_cwe)

        self.gui.detail_owasp = QLabel("OWASP: -")
        self.gui.detail_owasp.setStyleSheet("color: #333333;")
        ref_layout.addWidget(self.gui.detail_owasp)

        detail_layout.addWidget(ref_group)

        # Description section
        desc_group = QGroupBox("Description")
        desc_group.setStyleSheet("QGroupBox { font-weight: bold; color: #333333; }")
        desc_layout = QVBoxLayout(desc_group)

        self.gui.detail_description = QTextEdit()
        self.gui.detail_description.setReadOnly(True)
        self.gui.detail_description.setMaximumHeight(100)
        self.gui.detail_description.setFont(QFont("Consolas", 9))
        self.gui.detail_description.setStyleSheet("""
            QTextEdit {
                background-color: #f8f9fa;
                border: 1px solid #e0e0e0;
                border-radius: 4px;
                color: #333333;
            }
        """)
        desc_layout.addWidget(self.gui.detail_description)

        detail_layout.addWidget(desc_group)

        # View full details button
        view_full_btn = QPushButton("View Full Details")
        view_full_btn.setStyleSheet("""
            QPushButton {
                background-color: #2196F3;
                color: white;
                border: none;
                border-radius: 4px;
                padding: 8px 16px;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: #1976D2;
            }
        """)
        view_full_btn.clicked.connect(self._show_full_details)
        detail_layout.addWidget(view_full_btn)

        detail_layout.addStretch()

        scroll.setWidget(self.gui.detail_content)
        layout.addWidget(scroll)

        return container

    def _create_export_bar(self):
        """Create export options bar"""
        export_frame = QFrame()
        export_frame.setStyleSheet("""
            QFrame {
                background-color: #f8f9fa;
                border: 1px solid #e0e0e0;
                border-radius: 6px;
                padding: 8px;
            }
        """)

        layout = QHBoxLayout(export_frame)

        # Open report button
        open_report_btn = QPushButton("Open HTML Report")
        open_report_btn.setStyleSheet("""
            QPushButton {
                background-color: #4CAF50;
                color: white;
                border: none;
                border-radius: 4px;
                padding: 8px 16px;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: #388E3C;
            }
        """)
        open_report_btn.clicked.connect(self.gui.results_handler.open_report)
        layout.addWidget(open_report_btn)

        # Generate Live Report button
        live_report_btn = QPushButton("Generate Live Report")
        live_report_btn.setStyleSheet("""
            QPushButton {
                background-color: #00BCD4;
                color: white;
                border: none;
                border-radius: 4px;
                padding: 8px 16px;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: #00ACC1;
            }
        """)
        live_report_btn.setToolTip("Generate report from current findings (works during or after scan)")
        live_report_btn.clicked.connect(self._generate_live_report)
        layout.addWidget(live_report_btn)

        # Custom Report button
        custom_report_btn = QPushButton("Custom Report")
        custom_report_btn.setStyleSheet("""
            QPushButton {
                background-color: #673AB7;
                color: white;
                border: none;
                border-radius: 4px;
                padding: 8px 16px;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: #512DA8;
            }
        """)
        custom_report_btn.clicked.connect(self._open_custom_report_dialog)
        layout.addWidget(custom_report_btn)

        layout.addStretch()

        # Export buttons
        export_filtered_btn = QPushButton("Export Filtered")
        export_filtered_btn.setStyleSheet("""
            QPushButton {
                background-color: #2196F3;
                color: white;
                border: none;
                border-radius: 4px;
                padding: 8px 16px;
            }
            QPushButton:hover {
                background-color: #1976D2;
            }
        """)
        export_filtered_btn.clicked.connect(lambda: self._export_results('filtered'))
        layout.addWidget(export_filtered_btn)

        export_selected_btn = QPushButton("Export Selected")
        export_selected_btn.setStyleSheet("""
            QPushButton {
                background-color: #FF9800;
                color: white;
                border: none;
                border-radius: 4px;
                padding: 8px 16px;
            }
            QPushButton:hover {
                background-color: #F57C00;
            }
        """)
        export_selected_btn.clicked.connect(lambda: self._export_results('selected'))
        layout.addWidget(export_selected_btn)

        export_all_btn = QPushButton("Export All")
        export_all_btn.setStyleSheet("""
            QPushButton {
                background-color: #9C27B0;
                color: white;
                border: none;
                border-radius: 4px;
                padding: 8px 16px;
            }
            QPushButton:hover {
                background-color: #7B1FA2;
            }
        """)
        export_all_btn.clicked.connect(lambda: self._export_results('all'))
        layout.addWidget(export_all_btn)

        return export_frame

    def _create_scan_output_tab(self):
        """Create the scan output tab with search and colored table view"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(10, 10, 10, 10)
        layout.setSpacing(10)

        # Header with title and export button
        header_layout = QHBoxLayout()

        title_label = QLabel("📄 Raw Scan Output")
        title_label.setFont(QFont("Segoe UI", 14, QFont.Bold))
        title_label.setStyleSheet("color: #1976D2;")
        header_layout.addWidget(title_label)

        header_layout.addStretch()

        # Export raw data button
        export_raw_btn = QPushButton("📤 Export Raw Data")
        export_raw_btn.setStyleSheet("""
            QPushButton {
                background-color: #4CAF50;
                color: white;
                border: none;
                border-radius: 6px;
                padding: 10px 20px;
                font-size: 12px;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: #45a049;
            }
        """)
        export_raw_btn.clicked.connect(self._export_raw_scan_output)
        header_layout.addWidget(export_raw_btn)

        layout.addLayout(header_layout)

        # Search bar
        search_layout = QHBoxLayout()

        search_label = QLabel("🔍 Search:")
        search_label.setFont(QFont("Segoe UI", 10, QFont.Bold))
        search_layout.addWidget(search_label)

        self.gui.scan_output_search = QLineEdit()
        self.gui.scan_output_search.setPlaceholderText("Search scan output (keywords, URLs, modules)...")
        self.gui.scan_output_search.setFont(QFont("Segoe UI", 10))
        self.gui.scan_output_search.setMinimumHeight(32)
        self.gui.scan_output_search.setStyleSheet("""
            QLineEdit {
                background-color: white;
                border: 2px solid #e0e0e0;
                border-radius: 6px;
                padding: 6px 12px;
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
        self.gui.scan_output_search.textChanged.connect(self._filter_scan_output)
        search_layout.addWidget(self.gui.scan_output_search, 1)

        # Clear search button
        clear_search_btn = QPushButton("✖ Clear")
        clear_search_btn.setStyleSheet("""
            QPushButton {
                background-color: #9E9E9E;
                color: white;
                border: none;
                border-radius: 4px;
                padding: 6px 12px;
                font-size: 10px;
            }
            QPushButton:hover {
                background-color: #757575;
            }
        """)
        clear_search_btn.clicked.connect(lambda: self.gui.scan_output_search.clear())
        search_layout.addWidget(clear_search_btn)

        layout.addLayout(search_layout)

        # Info bar showing statistics
        info_bar = QFrame()
        info_bar.setStyleSheet("""
            QFrame {
                background-color: #f0f7ff;
                border-left: 4px solid #2196F3;
                border-radius: 4px;
                padding: 8px;
            }
        """)
        info_layout = QHBoxLayout(info_bar)

        self.gui.scan_output_stats = QLabel("Total Lines: 0 | Errors: 0 | Warnings: 0 | Info: 0")
        self.gui.scan_output_stats.setFont(QFont("Segoe UI", 9))
        self.gui.scan_output_stats.setStyleSheet("color: #1976D2; background: transparent; border: none;")
        info_layout.addWidget(self.gui.scan_output_stats)
        info_layout.addStretch()

        layout.addWidget(info_bar)

        # Table widget for scan output
        self.gui.scan_output_table = QTableWidget()
        self.gui.scan_output_table.setColumnCount(4)
        self.gui.scan_output_table.setHorizontalHeaderLabels([
            "# Line",
            "Level",
            "Module",
            "Message"
        ])

        # Column sizing
        header = self.gui.scan_output_table.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.Fixed)
        header.resizeSection(0, 70)  # Line number
        header.setSectionResizeMode(1, QHeaderView.Fixed)
        header.resizeSection(1, 90)  # Level
        header.setSectionResizeMode(2, QHeaderView.Fixed)
        header.resizeSection(2, 150)  # Module
        header.setSectionResizeMode(3, QHeaderView.Stretch)  # Message

        self.gui.scan_output_table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.gui.scan_output_table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.gui.scan_output_table.setAlternatingRowColors(True)
        self.gui.scan_output_table.setFont(QFont("Consolas", 9))
        self.gui.scan_output_table.setStyleSheet("""
            QTableWidget {
                background-color: #ffffff;
                color: #212121;
                gridline-color: #e8e8e8;
                border: 2px solid #e0e0e0;
                border-radius: 6px;
            }
            QHeaderView::section {
                background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
                    stop:0 #f5f5f5, stop:1 #e0e0e0);
                color: #2196F3;
                padding: 8px;
                border: none;
                border-bottom: 2px solid #2196F3;
                border-right: 1px solid #d0d0d0;
                font-weight: bold;
                font-size: 10px;
            }
            QHeaderView::section:last {
                border-right: none;
            }
            QTableWidget::item {
                padding: 6px;
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

        layout.addWidget(self.gui.scan_output_table)

        # Store all scan output lines for filtering
        self.gui.scan_output_lines = []

        return widget

    def _create_debug_tab(self):
        """Create the debug messages tab for INFO/DEBUG output"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(10, 10, 10, 10)
        layout.setSpacing(10)

        # Header with title and controls
        header_layout = QHBoxLayout()

        title_label = QLabel("🔧 Debug Messages")
        title_label.setFont(QFont("Segoe UI", 14, QFont.Bold))
        title_label.setStyleSheet("color: #9E9E9E;")
        header_layout.addWidget(title_label)

        header_layout.addStretch()

        # Clear debug button
        clear_debug_btn = QPushButton("Clear Debug")
        clear_debug_btn.setStyleSheet("""
            QPushButton {
                background-color: #f44336;
                color: white;
                border: none;
                border-radius: 6px;
                padding: 8px 16px;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: #d32f2f;
            }
        """)
        clear_debug_btn.clicked.connect(self._clear_debug_messages)
        header_layout.addWidget(clear_debug_btn)

        layout.addLayout(header_layout)

        # Search bar
        search_layout = QHBoxLayout()

        search_label = QLabel("🔍 Search:")
        search_label.setFont(QFont("Segoe UI", 10, QFont.Bold))
        search_layout.addWidget(search_label)

        self.gui.debug_search = QLineEdit()
        self.gui.debug_search.setPlaceholderText("Search debug messages...")
        self.gui.debug_search.setMinimumHeight(32)
        self.gui.debug_search.setStyleSheet("""
            QLineEdit {
                background-color: white;
                border: 2px solid #e0e0e0;
                border-radius: 6px;
                padding: 6px 12px;
            }
            QLineEdit:focus {
                border: 2px solid #9E9E9E;
            }
        """)
        self.gui.debug_search.textChanged.connect(self._filter_debug_messages)
        search_layout.addWidget(self.gui.debug_search, 1)

        layout.addLayout(search_layout)

        # Debug stats
        self.gui.debug_stats = QLabel("Debug Messages: 0 | INFO: 0 | DEBUG: 0 | Forms: 0 | URLs: 0")
        self.gui.debug_stats.setFont(QFont("Segoe UI", 9))
        self.gui.debug_stats.setStyleSheet("color: #9E9E9E; padding: 5px;")
        layout.addWidget(self.gui.debug_stats)

        # Debug table
        self.gui.debug_table = QTableWidget()
        self.gui.debug_table.setColumnCount(4)
        self.gui.debug_table.setHorizontalHeaderLabels([
            "# Line", "Type", "Source", "Message"
        ])

        header = self.gui.debug_table.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.Fixed)
        header.resizeSection(0, 60)
        header.setSectionResizeMode(1, QHeaderView.Fixed)
        header.resizeSection(1, 80)
        header.setSectionResizeMode(2, QHeaderView.Fixed)
        header.resizeSection(2, 150)
        header.setSectionResizeMode(3, QHeaderView.Stretch)

        self.gui.debug_table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.gui.debug_table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.gui.debug_table.setAlternatingRowColors(True)
        self.gui.debug_table.setFont(QFont("Consolas", 9))
        self.gui.debug_table.setStyleSheet("""
            QTableWidget {
                background-color: #fafafa;
                color: #666666;
                gridline-color: #e8e8e8;
                border: 2px solid #e0e0e0;
                border-radius: 6px;
            }
            QHeaderView::section {
                background: #f0f0f0;
                color: #9E9E9E;
                padding: 8px;
                border: none;
                border-bottom: 2px solid #9E9E9E;
                font-weight: bold;
            }
            QTableWidget::item {
                padding: 4px;
            }
            QTableWidget::item:selected {
                background-color: #e0e0e0;
                color: #666666;
            }
        """)

        layout.addWidget(self.gui.debug_table)

        # Store debug messages list
        self.gui.debug_messages = []

        return widget

    def add_debug_message(self, message, msg_type="INFO", source=""):
        """Add a debug message to the debug tab"""
        if not hasattr(self.gui, 'debug_table'):
            return

        # Store message
        line_num = len(self.gui.debug_messages) + 1
        msg_data = {
            'line': line_num,
            'type': msg_type,
            'source': source,
            'message': message
        }
        self.gui.debug_messages.append(msg_data)

        # Add to table
        row = self.gui.debug_table.rowCount()
        self.gui.debug_table.insertRow(row)

        # Line number
        line_item = QTableWidgetItem(str(line_num))
        line_item.setForeground(QColor('#999999'))
        self.gui.debug_table.setItem(row, 0, line_item)

        # Type with color
        type_item = QTableWidgetItem(msg_type)
        type_item.setFont(QFont("Consolas", 9, QFont.Bold))
        if msg_type == "DEBUG":
            type_item.setForeground(QColor('#9E9E9E'))
        elif msg_type == "INFO":
            type_item.setForeground(QColor('#2196F3'))
        elif msg_type == "FORM":
            type_item.setForeground(QColor('#4CAF50'))
        elif msg_type == "URL":
            type_item.setForeground(QColor('#FF9800'))
        self.gui.debug_table.setItem(row, 1, type_item)

        # Source
        source_item = QTableWidgetItem(source)
        source_item.setForeground(QColor('#1976D2'))
        self.gui.debug_table.setItem(row, 2, source_item)

        # Message
        msg_item = QTableWidgetItem(message)
        self.gui.debug_table.setItem(row, 3, msg_item)

        # Auto-scroll
        self.gui.debug_table.scrollToBottom()

        # Update stats
        self._update_debug_stats()

    def _update_debug_stats(self):
        """Update debug statistics label"""
        if not hasattr(self.gui, 'debug_messages') or not hasattr(self.gui, 'debug_stats'):
            return

        total = len(self.gui.debug_messages)
        info_count = sum(1 for m in self.gui.debug_messages if m['type'] == 'INFO')
        debug_count = sum(1 for m in self.gui.debug_messages if m['type'] == 'DEBUG')
        form_count = sum(1 for m in self.gui.debug_messages if m['type'] == 'FORM')
        url_count = sum(1 for m in self.gui.debug_messages if m['type'] == 'URL')

        self.gui.debug_stats.setText(
            f"Debug Messages: {total} | INFO: {info_count} | DEBUG: {debug_count} | Forms: {form_count} | URLs: {url_count}"
        )

    def _filter_debug_messages(self):
        """Filter debug table based on search text"""
        if not hasattr(self.gui, 'debug_table') or not hasattr(self.gui, 'debug_search'):
            return

        search_text = self.gui.debug_search.text().lower()

        for row in range(self.gui.debug_table.rowCount()):
            match_found = not search_text  # Show all if empty search
            for col in range(self.gui.debug_table.columnCount()):
                item = self.gui.debug_table.item(row, col)
                if item and search_text in item.text().lower():
                    match_found = True
                    break
            self.gui.debug_table.setRowHidden(row, not match_found)

    def _clear_debug_messages(self):
        """Clear all debug messages"""
        if hasattr(self.gui, 'debug_table'):
            self.gui.debug_table.setRowCount(0)
        if hasattr(self.gui, 'debug_messages'):
            self.gui.debug_messages = []
        self._update_debug_stats()

    def _create_site_tree_tab(self):
        """Create the Site Tree tab showing website structure like Acunetix"""
        from urllib.parse import urlparse

        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(10, 10, 10, 10)
        layout.setSpacing(10)

        # Header with title and controls
        header_layout = QHBoxLayout()

        title_label = QLabel("🌳 Website Structure")
        title_label.setFont(QFont("Segoe UI", 14, QFont.Bold))
        title_label.setStyleSheet("color: #2E7D32;")
        header_layout.addWidget(title_label)

        header_layout.addStretch()

        # Expand All button
        expand_btn = QPushButton("➕ Expand All")
        expand_btn.setStyleSheet("""
            QPushButton {
                background-color: #4CAF50;
                color: white;
                border: none;
                border-radius: 6px;
                padding: 8px 16px;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: #45a049;
            }
        """)
        expand_btn.clicked.connect(self._expand_all_tree)
        header_layout.addWidget(expand_btn)

        # Collapse All button
        collapse_btn = QPushButton("➖ Collapse All")
        collapse_btn.setStyleSheet("""
            QPushButton {
                background-color: #2196F3;
                color: white;
                border: none;
                border-radius: 6px;
                padding: 8px 16px;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: #1976D2;
            }
        """)
        collapse_btn.clicked.connect(self._collapse_all_tree)
        header_layout.addWidget(collapse_btn)

        # Clear button
        clear_tree_btn = QPushButton("🗑️ Clear")
        clear_tree_btn.setStyleSheet("""
            QPushButton {
                background-color: #f44336;
                color: white;
                border: none;
                border-radius: 6px;
                padding: 8px 16px;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: #d32f2f;
            }
        """)
        clear_tree_btn.clicked.connect(self._clear_site_tree)
        header_layout.addWidget(clear_tree_btn)

        layout.addLayout(header_layout)

        # Stats bar
        stats_frame = QFrame()
        stats_frame.setStyleSheet("""
            QFrame {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
                    stop:0 #4CAF50, stop:1 #2196F3);
                border-radius: 8px;
                padding: 10px;
            }
            QLabel {
                color: white;
                background: transparent;
            }
        """)
        stats_layout = QHBoxLayout(stats_frame)

        self.gui.tree_urls_count = QLabel("📄 URLs: 0")
        self.gui.tree_urls_count.setFont(QFont("Segoe UI", 11, QFont.Bold))
        stats_layout.addWidget(self.gui.tree_urls_count)

        self.gui.tree_dirs_count = QLabel("📁 Directories: 0")
        self.gui.tree_dirs_count.setFont(QFont("Segoe UI", 11, QFont.Bold))
        stats_layout.addWidget(self.gui.tree_dirs_count)

        self.gui.tree_params_count = QLabel("🔧 Parameters: 0")
        self.gui.tree_params_count.setFont(QFont("Segoe UI", 11, QFont.Bold))
        stats_layout.addWidget(self.gui.tree_params_count)

        self.gui.tree_vulns_count = QLabel("⚠️ Vulnerabilities: 0")
        self.gui.tree_vulns_count.setFont(QFont("Segoe UI", 11, QFont.Bold))
        stats_layout.addWidget(self.gui.tree_vulns_count)

        stats_layout.addStretch()
        layout.addWidget(stats_frame)

        # Search bar
        search_layout = QHBoxLayout()
        search_label = QLabel("🔍 Filter:")
        search_label.setFont(QFont("Segoe UI", 10, QFont.Bold))
        search_layout.addWidget(search_label)

        self.gui.tree_search = QLineEdit()
        self.gui.tree_search.setPlaceholderText("Filter URLs (e.g., 'login', '.php', 'admin')...")
        self.gui.tree_search.setMinimumHeight(32)
        self.gui.tree_search.setStyleSheet("""
            QLineEdit {
                background-color: white;
                border: 2px solid #e0e0e0;
                border-radius: 6px;
                padding: 6px 12px;
            }
            QLineEdit:focus {
                border: 2px solid #4CAF50;
            }
        """)
        self.gui.tree_search.textChanged.connect(self._filter_site_tree)
        search_layout.addWidget(self.gui.tree_search, 1)

        layout.addLayout(search_layout)

        # Site Tree Widget
        self.gui.site_tree = QTreeWidget()
        self.gui.site_tree.setHeaderLabels(["URL / Path", "Type", "Parameters", "Vulnerabilities"])
        self.gui.site_tree.setColumnWidth(0, 400)
        self.gui.site_tree.setColumnWidth(1, 100)
        self.gui.site_tree.setColumnWidth(2, 150)
        self.gui.site_tree.setColumnWidth(3, 120)
        self.gui.site_tree.setAlternatingRowColors(True)
        self.gui.site_tree.setAnimated(True)
        self.gui.site_tree.setExpandsOnDoubleClick(True)
        self.gui.site_tree.setStyleSheet("""
            QTreeWidget {
                background-color: #fafafa;
                color: #333333;
                border: 2px solid #e0e0e0;
                border-radius: 6px;
                font-family: 'Consolas', 'Courier New', monospace;
                font-size: 10pt;
            }
            QTreeWidget::item {
                padding: 4px;
                border-bottom: 1px solid #f0f0f0;
            }
            QTreeWidget::item:selected {
                background-color: #e8f5e9;
                color: #2E7D32;
            }
            QTreeWidget::item:hover {
                background-color: #f5f5f5;
            }
            QHeaderView::section {
                background-color: #4CAF50;
                color: white;
                padding: 8px;
                border: none;
                font-weight: bold;
            }
            QTreeWidget::branch:has-children:!has-siblings:closed,
            QTreeWidget::branch:closed:has-children:has-siblings {
                border-image: none;
                image: url(:/icons/branch-closed.png);
            }
            QTreeWidget::branch:open:has-children:!has-siblings,
            QTreeWidget::branch:open:has-children:has-siblings {
                border-image: none;
                image: url(:/icons/branch-open.png);
            }
        """)

        # Context menu for tree items
        self.gui.site_tree.setContextMenuPolicy(Qt.CustomContextMenu)
        self.gui.site_tree.customContextMenuRequested.connect(self._show_tree_context_menu)

        layout.addWidget(self.gui.site_tree)

        # Store tree data
        self.gui.site_tree_data = {}  # {url: {params: [], vulns: [], type: 'page/dir/file'}}
        self.gui.site_tree_nodes = {}  # {path: QTreeWidgetItem}

        return widget

    def add_url_to_tree(self, url, params=None, vuln_info=None):
        """Add a URL to the site tree, building the path hierarchy"""
        from urllib.parse import urlparse, parse_qs

        if not hasattr(self.gui, 'site_tree'):
            return

        parsed = urlparse(url)
        base_url = f"{parsed.scheme}://{parsed.netloc}"

        # Get or create root node for this domain
        if base_url not in self.gui.site_tree_nodes:
            root_item = QTreeWidgetItem(self.gui.site_tree)
            root_item.setText(0, f"🌐 {parsed.netloc}")
            root_item.setText(1, "Domain")
            root_item.setFont(0, QFont("Segoe UI", 10, QFont.Bold))
            root_item.setForeground(0, QColor('#1976D2'))
            root_item.setExpanded(True)
            self.gui.site_tree_nodes[base_url] = root_item
            self.gui.site_tree_data[base_url] = {'type': 'domain', 'params': [], 'vulns': []}

        root_item = self.gui.site_tree_nodes[base_url]

        # Build path hierarchy
        path_parts = [p for p in parsed.path.split('/') if p]
        current_path = base_url
        parent_item = root_item

        for i, part in enumerate(path_parts):
            current_path = f"{current_path}/{part}"

            if current_path not in self.gui.site_tree_nodes:
                item = QTreeWidgetItem(parent_item)

                # Determine type and icon
                is_file = '.' in part
                is_last = (i == len(path_parts) - 1)

                if is_file:
                    icon = self._get_file_icon(part)
                    item_type = "File"
                else:
                    icon = "📁"
                    item_type = "Directory"

                item.setText(0, f"{icon} {part}")
                item.setText(1, item_type)
                item.setForeground(0, QColor('#333333'))

                self.gui.site_tree_nodes[current_path] = item
                self.gui.site_tree_data[current_path] = {'type': item_type.lower(), 'params': [], 'vulns': []}

            parent_item = self.gui.site_tree_nodes[current_path]

        # Add parameters if present
        final_path = current_path if path_parts else base_url
        if params:
            if isinstance(params, dict):
                param_names = list(params.keys())
            elif isinstance(params, list):
                param_names = params
            else:
                param_names = [str(params)]

            if final_path in self.gui.site_tree_data:
                for p in param_names:
                    if p not in self.gui.site_tree_data[final_path]['params']:
                        self.gui.site_tree_data[final_path]['params'].append(p)

                # Update tree item
                item = self.gui.site_tree_nodes.get(final_path)
                if item:
                    param_str = ', '.join(self.gui.site_tree_data[final_path]['params'][:5])
                    if len(self.gui.site_tree_data[final_path]['params']) > 5:
                        param_str += f" (+{len(self.gui.site_tree_data[final_path]['params'])-5})"
                    item.setText(2, param_str)
                    item.setForeground(2, QColor('#FF9800'))

        # Add vulnerability info if present
        if vuln_info:
            if final_path in self.gui.site_tree_data:
                self.gui.site_tree_data[final_path]['vulns'].append(vuln_info)

                item = self.gui.site_tree_nodes.get(final_path)
                if item:
                    vuln_count = len(self.gui.site_tree_data[final_path]['vulns'])
                    item.setText(3, f"⚠️ {vuln_count}")
                    item.setForeground(3, QColor('#f44336'))
                    item.setBackground(0, QColor('#ffebee'))

        # Update stats
        self._update_tree_stats()

    def _get_file_icon(self, filename):
        """Get appropriate icon for file type"""
        ext = filename.split('.')[-1].lower() if '.' in filename else ''
        icons = {
            'php': '🐘',
            'html': '🌐',
            'htm': '🌐',
            'js': '📜',
            'css': '🎨',
            'json': '📋',
            'xml': '📄',
            'txt': '📝',
            'pdf': '📕',
            'jpg': '🖼️',
            'jpeg': '🖼️',
            'png': '🖼️',
            'gif': '🖼️',
            'svg': '🖼️',
            'zip': '📦',
            'asp': '🔷',
            'aspx': '🔷',
            'jsp': '☕',
            'py': '🐍',
            'rb': '💎',
            'sql': '🗄️',
            'bak': '💾',
            'config': '⚙️',
            'env': '🔐',
        }
        return icons.get(ext, '📄')

    def _update_tree_stats(self):
        """Update the site tree statistics"""
        if not hasattr(self.gui, 'site_tree_data'):
            return

        urls = 0
        dirs = 0
        params = 0
        vulns = 0

        for path, data in self.gui.site_tree_data.items():
            if data['type'] == 'file' or data['type'] == 'page':
                urls += 1
            elif data['type'] == 'directory':
                dirs += 1
            params += len(data['params'])
            vulns += len(data['vulns'])

        # Count domains as dirs
        dirs += sum(1 for d in self.gui.site_tree_data.values() if d['type'] == 'domain')

        self.gui.tree_urls_count.setText(f"📄 URLs: {urls}")
        self.gui.tree_dirs_count.setText(f"📁 Directories: {dirs}")
        self.gui.tree_params_count.setText(f"🔧 Parameters: {params}")
        self.gui.tree_vulns_count.setText(f"⚠️ Vulnerabilities: {vulns}")

    def _expand_all_tree(self):
        """Expand all tree nodes"""
        if hasattr(self.gui, 'site_tree'):
            self.gui.site_tree.expandAll()

    def _collapse_all_tree(self):
        """Collapse all tree nodes"""
        if hasattr(self.gui, 'site_tree'):
            self.gui.site_tree.collapseAll()

    def _clear_site_tree(self):
        """Clear the site tree"""
        if hasattr(self.gui, 'site_tree'):
            self.gui.site_tree.clear()
        if hasattr(self.gui, 'site_tree_data'):
            self.gui.site_tree_data = {}
        if hasattr(self.gui, 'site_tree_nodes'):
            self.gui.site_tree_nodes = {}
        self._update_tree_stats()

    def _filter_site_tree(self):
        """Filter tree items based on search text"""
        if not hasattr(self.gui, 'site_tree') or not hasattr(self.gui, 'tree_search'):
            return

        search_text = self.gui.tree_search.text().lower()

        def set_item_visibility(item, visible):
            item.setHidden(not visible)
            # If visible, also show all parents
            if visible:
                parent = item.parent()
                while parent:
                    parent.setHidden(False)
                    parent.setExpanded(True)
                    parent = parent.parent()

        def search_item(item):
            """Recursively search and show/hide items"""
            text = item.text(0).lower()
            params = item.text(2).lower()

            matches = not search_text or search_text in text or search_text in params

            # Check children
            child_matches = False
            for i in range(item.childCount()):
                if search_item(item.child(i)):
                    child_matches = True

            visible = matches or child_matches
            set_item_visibility(item, visible)
            return visible

        # Search all root items
        for i in range(self.gui.site_tree.topLevelItemCount()):
            search_item(self.gui.site_tree.topLevelItem(i))

    def _show_tree_context_menu(self, position):
        """Show context menu for tree items"""
        item = self.gui.site_tree.itemAt(position)
        if not item:
            return

        menu = QMenu()
        menu.setStyleSheet("""
            QMenu {
                background-color: white;
                border: 1px solid #ccc;
            }
            QMenu::item {
                padding: 8px 20px;
            }
            QMenu::item:selected {
                background-color: #4CAF50;
                color: white;
            }
        """)

        # Copy URL action
        copy_action = QAction("📋 Copy URL", self.gui)
        copy_action.triggered.connect(lambda: self._copy_tree_url(item))
        menu.addAction(copy_action)

        # Open in browser
        open_action = QAction("🌐 Open in Browser", self.gui)
        open_action.triggered.connect(lambda: self._open_tree_url(item))
        menu.addAction(open_action)

        menu.addSeparator()

        # Scan this URL
        scan_action = QAction("🔍 Scan This URL", self.gui)
        scan_action.triggered.connect(lambda: self._scan_tree_url(item))
        menu.addAction(scan_action)

        menu.exec_(self.gui.site_tree.viewport().mapToGlobal(position))

    def _copy_tree_url(self, item):
        """Copy URL from tree item to clipboard"""
        from PyQt5.QtWidgets import QApplication

        # Reconstruct URL from tree path
        path_parts = []
        current = item
        while current:
            text = current.text(0)
            # Remove icon
            if ' ' in text:
                text = text.split(' ', 1)[1]
            path_parts.insert(0, text)
            current = current.parent()

        if path_parts:
            url = '/'.join(path_parts)
            if not url.startswith('http'):
                url = 'http://' + url
            QApplication.clipboard().setText(url)

    def _open_tree_url(self, item):
        """Open URL in browser"""
        import webbrowser

        path_parts = []
        current = item
        while current:
            text = current.text(0)
            if ' ' in text:
                text = text.split(' ', 1)[1]
            path_parts.insert(0, text)
            current = current.parent()

        if path_parts:
            url = '/'.join(path_parts)
            if not url.startswith('http'):
                url = 'http://' + url
            webbrowser.open(url)

    def _scan_tree_url(self, item):
        """Set this URL as target and prepare for scan"""
        path_parts = []
        current = item
        while current:
            text = current.text(0)
            if ' ' in text:
                text = text.split(' ', 1)[1]
            path_parts.insert(0, text)
            current = current.parent()

        if path_parts:
            url = '/'.join(path_parts)
            if not url.startswith('http'):
                url = 'http://' + url

            # Set as target in GUI
            if hasattr(self.gui, 'target_input'):
                self.gui.target_input.setText(url)
                self.gui.tabs.setCurrentIndex(0)  # Switch to Scan Configuration tab
                QMessageBox.information(self.gui, "Target Set",
                    f"Target URL set to:\n{url}\n\nClick 'Start' to begin scanning.")

    def _apply_filters(self):
        """Apply all filters to results table"""
        if not hasattr(self.gui, 'results_table'):
            return

        severity_filter = self.gui.severity_filter.currentText().upper()
        module_filter = self.gui.module_filter.currentText()
        target_filter = self.gui.target_filter.currentText()
        search_text = self.gui.results_search.text().lower()

        for row in range(self.gui.results_table.rowCount()):
            show_row = True

            # Check severity filter
            if severity_filter != "ALL":
                severity_item = self.gui.results_table.item(row, 1)
                if severity_item and severity_item.text().upper() != severity_filter:
                    show_row = False

            # Check module filter
            if show_row and module_filter != "All":
                module_item = self.gui.results_table.item(row, 2)
                if module_item and module_item.text() != module_filter:
                    show_row = False

            # Check target filter
            if show_row and target_filter != "All":
                target_item = self.gui.results_table.item(row, 4)
                if target_item and target_filter not in target_item.text():
                    show_row = False

            # Check search text
            if show_row and search_text:
                row_text = ""
                for col in range(self.gui.results_table.columnCount()):
                    item = self.gui.results_table.item(row, col)
                    if item:
                        row_text += item.text().lower() + " "
                if search_text not in row_text:
                    show_row = False

            self.gui.results_table.setRowHidden(row, not show_row)

    def _clear_filters(self):
        """Clear all filters"""
        self.gui.severity_filter.setCurrentIndex(0)
        self.gui.module_filter.setCurrentIndex(0)
        self.gui.target_filter.setCurrentIndex(0)
        self.gui.results_search.clear()

        # Show all rows
        for row in range(self.gui.results_table.rowCount()):
            self.gui.results_table.setRowHidden(row, False)

    def _toggle_group_by_target(self):
        """Toggle grouping results by target"""
        # This would re-organize the table by target
        # For now, just sort by target column
        if self.gui.group_by_target.isChecked():
            self.gui.results_table.sortItems(4, Qt.AscendingOrder)  # Sort by Target column
        else:
            self.gui.results_table.sortItems(0, Qt.AscendingOrder)  # Sort by # column

    def _on_host_clicked(self, item):
        """Handle click on a host in the stats list to filter results"""
        if not item:
            return

        # Extract host from item text (format: "hostname (count)")
        text = item.text()
        if ' (' in text:
            host = text.rsplit(' (', 1)[0]

            # Set target filter to this host
            index = self.gui.target_filter.findText(host)
            if index >= 0:
                self.gui.target_filter.setCurrentIndex(index)
            else:
                # If exact match not found, search for partial match
                for i in range(self.gui.target_filter.count()):
                    if host in self.gui.target_filter.itemText(i):
                        self.gui.target_filter.setCurrentIndex(i)
                        break

    def _on_row_double_clicked(self, index):
        """Handle double-click on a row to show full details"""
        self._show_full_details()

    def _on_selection_changed(self):
        """Handle selection change to update detail panel"""
        selected = self.gui.results_table.selectedItems()
        if not selected:
            return

        row = selected[0].row()

        # Get finding data from row
        severity = self.gui.results_table.item(row, 1).text() if self.gui.results_table.item(row, 1) else "INFO"
        module = self.gui.results_table.item(row, 2).text() if self.gui.results_table.item(row, 2) else "-"
        title = self.gui.results_table.item(row, 3).text() if self.gui.results_table.item(row, 3) else "-"
        target = self.gui.results_table.item(row, 4).text() if self.gui.results_table.item(row, 4) else "-"
        time = self.gui.results_table.item(row, 5).text() if self.gui.results_table.item(row, 5) else "-"

        # Update detail panel
        self.gui.detail_severity.setText(severity)
        color = SEVERITY_COLORS.get(severity.upper(), '#888888')
        self.gui.detail_severity.setStyleSheet(f"""
            background-color: {color};
            color: white;
            padding: 10px;
            border-radius: 4px;
            font-weight: bold;
            font-size: 14px;
        """)

        self.gui.detail_title.setText(title)
        self.gui.detail_module.setText(module)
        self.gui.detail_target.setText(target)
        self.gui.detail_time.setText(time)

        # Get stored finding data if available
        finding_data = self.gui.results_table.item(row, 0).data(Qt.UserRole) if self.gui.results_table.item(row, 0) else {}

        if finding_data:
            self.gui.detail_cvss.setText(f"{finding_data.get('cvss', 0)}/10")
            self.gui.detail_cwe.setText(f"CWE: {finding_data.get('cwe', 'N/A')}")
            self.gui.detail_owasp.setText(f"OWASP: {finding_data.get('owasp', 'N/A')}")
            self.gui.detail_description.setPlainText(finding_data.get('description', 'No description available'))
        else:
            self.gui.detail_cvss.setText("-")
            self.gui.detail_cwe.setText("CWE: -")
            self.gui.detail_owasp.setText("OWASP: -")
            self.gui.detail_description.setPlainText(title)

    def _show_context_menu(self, position):
        """Show context menu for results table"""
        menu = QMenu()

        # Copy actions
        copy_action = QAction("Copy Finding", self.gui)
        copy_action.triggered.connect(self._copy_selected)
        menu.addAction(copy_action)

        copy_target_action = QAction("Copy Target URL", self.gui)
        copy_target_action.triggered.connect(self._copy_target)
        menu.addAction(copy_target_action)

        menu.addSeparator()

        # View details
        details_action = QAction("View Full Details", self.gui)
        details_action.triggered.connect(self._show_full_details)
        menu.addAction(details_action)

        menu.addSeparator()

        # Export selected
        export_action = QAction("Export Selected", self.gui)
        export_action.triggered.connect(lambda: self._export_results('selected'))
        menu.addAction(export_action)

        menu.addSeparator()

        # Delete
        delete_action = QAction("Delete Finding", self.gui)
        delete_action.triggered.connect(self._delete_selected)
        menu.addAction(delete_action)

        menu.exec_(self.gui.results_table.mapToGlobal(position))

    def _copy_selected(self):
        """Copy selected finding to clipboard"""
        selected = self.gui.results_table.selectedItems()
        if not selected:
            return

        row = selected[0].row()
        text = []
        for col in range(self.gui.results_table.columnCount()):
            item = self.gui.results_table.item(row, col)
            if item:
                text.append(item.text())

        from PyQt5.QtWidgets import QApplication
        QApplication.clipboard().setText(" | ".join(text))

    def _copy_target(self):
        """Copy target URL to clipboard"""
        selected = self.gui.results_table.selectedItems()
        if not selected:
            return

        row = selected[0].row()
        target_item = self.gui.results_table.item(row, 4)
        if target_item:
            from PyQt5.QtWidgets import QApplication
            QApplication.clipboard().setText(target_item.text())

    def _show_full_details(self):
        """Show full details dialog for selected finding"""
        selected = self.gui.results_table.selectedItems()
        if not selected:
            QMessageBox.information(self.gui, "No Selection", "Please select a finding to view details")
            return

        row = selected[0].row()

        # Get finding data
        finding_data = self.gui.results_table.item(row, 0).data(Qt.UserRole) if self.gui.results_table.item(row, 0) else {}

        # If no stored data, create from table
        if not finding_data:
            finding_data = {
                'severity': self.gui.results_table.item(row, 1).text() if self.gui.results_table.item(row, 1) else "INFO",
                'module': self.gui.results_table.item(row, 2).text() if self.gui.results_table.item(row, 2) else "-",
                'title': self.gui.results_table.item(row, 3).text() if self.gui.results_table.item(row, 3) else "-",
                'target': self.gui.results_table.item(row, 4).text() if self.gui.results_table.item(row, 4) else "-",
                'time': self.gui.results_table.item(row, 5).text() if self.gui.results_table.item(row, 5) else "-",
            }

        dialog = FindingDetailDialog(finding_data, self.gui)
        dialog.exec_()

    def _delete_selected(self):
        """Delete selected findings"""
        selected_rows = set()
        for item in self.gui.results_table.selectedItems():
            selected_rows.add(item.row())

        if not selected_rows:
            return

        reply = QMessageBox.question(
            self.gui, "Delete Findings",
            f"Are you sure you want to delete {len(selected_rows)} finding(s)?",
            QMessageBox.Yes | QMessageBox.No,
            QMessageBox.No
        )

        if reply == QMessageBox.Yes:
            # Delete rows in reverse order to maintain indices
            for row in sorted(selected_rows, reverse=True):
                self.gui.results_table.removeRow(row)

            # Update counts
            self._update_stats()

    def _export_results(self, export_type):
        """Export results based on type"""
        findings_to_export = []

        if export_type == 'all':
            for row in range(self.gui.results_table.rowCount()):
                findings_to_export.append(self._get_finding_from_row(row))
        elif export_type == 'filtered':
            for row in range(self.gui.results_table.rowCount()):
                if not self.gui.results_table.isRowHidden(row):
                    findings_to_export.append(self._get_finding_from_row(row))
        elif export_type == 'selected':
            selected_rows = set()
            for item in self.gui.results_table.selectedItems():
                selected_rows.add(item.row())
            for row in selected_rows:
                findings_to_export.append(self._get_finding_from_row(row))

        if not findings_to_export:
            QMessageBox.information(self.gui, "No Data", "No findings to export")
            return

        filename, _ = QFileDialog.getSaveFileName(
            self.gui, "Export Results",
            f"findings_{export_type}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json",
            "JSON Files (*.json);;CSV Files (*.csv);;Text Files (*.txt)"
        )

        if filename:
            try:
                if filename.endswith('.json'):
                    with open(filename, 'w', encoding='utf-8') as f:
                        json.dump(findings_to_export, f, indent=2, default=str)
                elif filename.endswith('.csv'):
                    import csv
                    with open(filename, 'w', newline='', encoding='utf-8') as f:
                        writer = csv.writer(f)
                        writer.writerow(['#', 'Severity', 'Module', 'Title', 'Target', 'Time'])
                        for finding in findings_to_export:
                            writer.writerow([
                                finding.get('id', ''),
                                finding.get('severity', ''),
                                finding.get('module', ''),
                                finding.get('title', ''),
                                finding.get('target', ''),
                                finding.get('time', '')
                            ])
                else:
                    with open(filename, 'w', encoding='utf-8') as f:
                        for finding in findings_to_export:
                            f.write(f"[{finding.get('severity', 'INFO')}] {finding.get('title', 'N/A')}\n")
                            f.write(f"  Module: {finding.get('module', 'N/A')}\n")
                            f.write(f"  Target: {finding.get('target', 'N/A')}\n")
                            f.write(f"  Time: {finding.get('time', 'N/A')}\n\n")

                QMessageBox.information(self.gui, "Success", f"Exported {len(findings_to_export)} findings to:\n{filename}")
            except Exception as e:
                QMessageBox.critical(self.gui, "Error", f"Failed to export:\n{e}")

    def _generate_live_report(self):
        """Generate and open a live HTML report from current findings"""
        import os
        import platform
        import subprocess
        import tempfile
        from pathlib import Path

        # Collect all findings from results table
        findings = []
        for row in range(self.gui.results_table.rowCount()):
            finding = self._get_finding_from_row(row)
            findings.append(finding)

        if not findings:
            QMessageBox.information(self.gui, "No Findings", "No findings to generate report from.\nStart a scan or wait for results.")
            return

        # Count severities
        severity_counts = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0, 'INFO': 0}
        for f in findings:
            sev = f.get('severity', '').upper()
            if sev in severity_counts:
                severity_counts[sev] += 1

        # Generate HTML
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        html = f"""<!DOCTYPE html>
<html>
<head>
    <title>Dominator Live Report - {timestamp}</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; background: #f5f5f5; }}
        .header {{ background: #4CAF50; color: white; padding: 20px; border-radius: 8px; margin-bottom: 20px; }}
        .header h1 {{ margin: 0; }}
        .stats {{ display: flex; gap: 15px; margin-bottom: 20px; }}
        .stat-card {{ background: white; padding: 15px; border-radius: 6px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); text-align: center; min-width: 100px; }}
        .stat-card .number {{ font-size: 24px; font-weight: bold; }}
        .stat-card.critical .number {{ color: #f44336; }}
        .stat-card.high .number {{ color: #FF9800; }}
        .stat-card.medium .number {{ color: #FFC107; }}
        .stat-card.low .number {{ color: #4CAF50; }}
        .finding {{ background: white; padding: 15px; margin-bottom: 10px; border-radius: 6px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); border-left: 4px solid #ccc; }}
        .finding.critical {{ border-left-color: #f44336; }}
        .finding.high {{ border-left-color: #FF9800; }}
        .finding.medium {{ border-left-color: #FFC107; }}
        .finding.low {{ border-left-color: #4CAF50; }}
        .finding .title {{ font-weight: bold; margin-bottom: 5px; }}
        .finding .meta {{ color: #666; font-size: 12px; }}
        .live-badge {{ background: #00BCD4; color: white; padding: 4px 8px; border-radius: 4px; font-size: 12px; }}
    </style>
</head>
<body>
    <div class="header">
        <h1>Dominator Scan Report <span class="live-badge">LIVE</span></h1>
        <p>Generated: {timestamp}</p>
        <p>Total Findings: {len(findings)}</p>
    </div>

    <div class="stats">
        <div class="stat-card critical">
            <div class="number">{severity_counts['CRITICAL']}</div>
            <div>Critical</div>
        </div>
        <div class="stat-card high">
            <div class="number">{severity_counts['HIGH']}</div>
            <div>High</div>
        </div>
        <div class="stat-card medium">
            <div class="number">{severity_counts['MEDIUM']}</div>
            <div>Medium</div>
        </div>
        <div class="stat-card low">
            <div class="number">{severity_counts['LOW']}</div>
            <div>Low</div>
        </div>
    </div>

    <h2>Findings</h2>
"""

        # Add findings
        for f in findings:
            sev = f.get('severity', '').lower()
            html += f"""
    <div class="finding {sev}">
        <div class="title">[{f.get('severity', 'N/A')}] {f.get('title', 'N/A')}</div>
        <div class="meta">
            Module: {f.get('module', 'N/A')} |
            Target: {f.get('target', 'N/A')} |
            Time: {f.get('time', 'N/A')}
        </div>
    </div>
"""

        html += """
    <p style="color: #888; margin-top: 30px; text-align: center;">
        Generated by Dominator Web Vulnerability Scanner
    </p>
</body>
</html>
"""

        # Save to temp file and open
        try:
            # Create temp file with .html extension
            with tempfile.NamedTemporaryFile(mode='w', suffix='.html', delete=False, encoding='utf-8') as f:
                f.write(html)
                temp_path = f.name

            # Open in browser
            if platform.system() == 'Windows':
                os.startfile(temp_path)
            elif platform.system() == 'Darwin':
                subprocess.run(['open', temp_path])
            else:
                subprocess.run(['xdg-open', temp_path])

            self.gui.output_console.append(f"[+] Live report generated: {temp_path}")

        except Exception as e:
            QMessageBox.critical(self.gui, "Error", f"Failed to generate live report:\n{e}")

    def _open_custom_report_dialog(self):
        """Open custom report configuration dialog"""
        # Collect all findings from results table
        findings = []
        for row in range(self.gui.results_table.rowCount()):
            finding = self._get_finding_from_row(row)
            findings.append(finding)

        # Create results data structure for the dialog
        results_data = {
            'findings': findings,
            'scan_info': {
                'start_time': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                'target_count': len(set(f.get('target', '') for f in findings)),
                'module_count': len(set(f.get('module', '') for f in findings))
            }
        }

        # Open dialog
        dialog = CustomReportDialog(results_data=results_data, parent=self.gui)
        dialog.exec_()

    def _get_finding_from_row(self, row):
        """Get finding data from a table row"""
        finding = {
            'id': self.gui.results_table.item(row, 0).text() if self.gui.results_table.item(row, 0) else "",
            'severity': self.gui.results_table.item(row, 1).text() if self.gui.results_table.item(row, 1) else "",
            'module': self.gui.results_table.item(row, 2).text() if self.gui.results_table.item(row, 2) else "",
            'title': self.gui.results_table.item(row, 3).text() if self.gui.results_table.item(row, 3) else "",
            'target': self.gui.results_table.item(row, 4).text() if self.gui.results_table.item(row, 4) else "",
            'time': self.gui.results_table.item(row, 5).text() if self.gui.results_table.item(row, 5) else "",
        }

        # Add stored data if available
        stored_data = self.gui.results_table.item(row, 0).data(Qt.UserRole) if self.gui.results_table.item(row, 0) else {}
        if stored_data:
            finding.update(stored_data)

        return finding

    def _update_stats(self):
        """Update statistics cards and charts"""
        counts = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0, 'INFO': 0}

        for row in range(self.gui.results_table.rowCount()):
            severity_item = self.gui.results_table.item(row, 1)
            if severity_item:
                severity = severity_item.text().upper()
                if severity in counts:
                    counts[severity] += 1

        total = sum(counts.values())

        # Update cards
        self.gui.total_card.set_value(total)
        self.gui.critical_card.set_value(counts['CRITICAL'])
        self.gui.high_card.set_value(counts['HIGH'])
        self.gui.medium_card.set_value(counts['MEDIUM'])
        self.gui.low_card.set_value(counts['LOW'])

        # Update pie chart
        self.gui.pie_chart.set_data(counts)

        # Update legacy labels
        self.gui.total_vulns_label.setText(f"Total Vulnerabilities: {total}")
        self.gui.critical_label.setText(f"Critical: {counts['CRITICAL']}")
        self.gui.high_label.setText(f"High: {counts['HIGH']}")
        self.gui.medium_label.setText(f"Medium: {counts['MEDIUM']}")

    def add_scan_output_line(self, line_text):
        """Add a line to the scan output table with color coding"""
        if not hasattr(self.gui, 'scan_output_table'):
            return

        # Parse the line to extract level, module, and message
        level = "INFO"
        module = ""
        message = line_text.strip()

        # Detect log level from line
        if "[ERROR]" in message or "[CRITICAL]" in message or "ERROR" in message[:20]:
            level = "ERROR"
        elif "[WARNING]" in message or "[WARN]" in message or "WARNING" in message[:20]:
            level = "WARNING"
        elif "[INFO]" in message or "INFO:" in message[:20]:
            level = "INFO"
        elif "[DEBUG]" in message or "DEBUG:" in message[:20]:
            level = "DEBUG"
        elif "[SUCCESS]" in message or "SUCCESS:" in message[:20]:
            level = "SUCCESS"

        # Try to extract module name
        if "Module:" in message:
            try:
                module = message.split("Module:")[1].split("|")[0].strip()
            except:
                pass

        # Store the full line data
        line_data = {
            'line_number': len(self.gui.scan_output_lines) + 1,
            'level': level,
            'module': module,
            'message': message,
            'raw_text': line_text
        }
        self.gui.scan_output_lines.append(line_data)

        # Add to table
        row = self.gui.scan_output_table.rowCount()
        self.gui.scan_output_table.insertRow(row)

        # Line number
        line_num_item = QTableWidgetItem(str(line_data['line_number']))
        line_num_item.setFont(QFont("Consolas", 9))
        line_num_item.setForeground(QColor('#666666'))
        self.gui.scan_output_table.setItem(row, 0, line_num_item)

        # Level with color coding
        level_item = QTableWidgetItem(level)
        level_item.setFont(QFont("Consolas", 9, QFont.Bold))
        if level == "ERROR" or level == "CRITICAL":
            level_item.setBackground(QColor('#f44336'))
            level_item.setForeground(QColor('white'))
        elif level == "WARNING":
            level_item.setBackground(QColor('#FF9800'))
            level_item.setForeground(QColor('white'))
        elif level == "SUCCESS":
            level_item.setBackground(QColor('#4CAF50'))
            level_item.setForeground(QColor('white'))
        elif level == "DEBUG":
            level_item.setForeground(QColor('#9E9E9E'))
        else:  # INFO
            level_item.setForeground(QColor('#2196F3'))
        self.gui.scan_output_table.setItem(row, 1, level_item)

        # Module
        module_item = QTableWidgetItem(module)
        module_item.setFont(QFont("Consolas", 9))
        module_item.setForeground(QColor('#1976D2'))
        self.gui.scan_output_table.setItem(row, 2, module_item)

        # Message
        message_item = QTableWidgetItem(message)
        message_item.setFont(QFont("Consolas", 9))
        self.gui.scan_output_table.setItem(row, 3, message_item)

        # Auto-scroll to bottom
        self.gui.scan_output_table.scrollToBottom()

        # Update statistics
        self._update_scan_output_stats()

        # Also add to Debug tab if it's an INFO/DEBUG message or contains debug patterns
        debug_patterns = ['found', 'testing', 'checking', 'scanning', 'crawl', 'parameters', 'form']
        is_debug_msg = level in ['INFO', 'DEBUG'] or any(p in message.lower() for p in debug_patterns)

        if is_debug_msg and hasattr(self.gui, 'debug_table'):
            # Determine debug type
            msg_lower = message.lower()
            if 'form' in msg_lower:
                debug_type = "FORM"
            elif 'url' in msg_lower or 'page' in msg_lower or 'endpoint' in msg_lower:
                debug_type = "URL"
            elif level == 'DEBUG':
                debug_type = "DEBUG"
            else:
                debug_type = "INFO"

            # Extract source from message
            source = module if module else ""
            if ' - ' in message:
                parts = message.split(' - ')
                if len(parts) >= 2:
                    source = parts[1].strip() if not source else source

            self.add_debug_message(message, debug_type, source)

    def _update_scan_output_stats(self):
        """Update the scan output statistics bar"""
        if not hasattr(self.gui, 'scan_output_lines') or not hasattr(self.gui, 'scan_output_stats'):
            return

        total = len(self.gui.scan_output_lines)
        errors = sum(1 for line in self.gui.scan_output_lines if line['level'] in ['ERROR', 'CRITICAL'])
        warnings = sum(1 for line in self.gui.scan_output_lines if line['level'] == 'WARNING')
        info = sum(1 for line in self.gui.scan_output_lines if line['level'] == 'INFO')

        self.gui.scan_output_stats.setText(
            f"Total Lines: {total} | Errors: {errors} | Warnings: {warnings} | Info: {info}"
        )

    def _filter_scan_output(self):
        """Filter scan output table based on search text"""
        if not hasattr(self.gui, 'scan_output_table') or not hasattr(self.gui, 'scan_output_search'):
            return

        search_text = self.gui.scan_output_search.text().lower()

        for row in range(self.gui.scan_output_table.rowCount()):
            # Check all columns for match
            match_found = False
            for col in range(self.gui.scan_output_table.columnCount()):
                item = self.gui.scan_output_table.item(row, col)
                if item and search_text in item.text().lower():
                    match_found = True
                    break

            # Show/hide row based on match
            self.gui.scan_output_table.setRowHidden(row, not match_found)

    def _export_raw_scan_output(self):
        """Export raw scan output to file"""
        if not hasattr(self.gui, 'scan_output_lines'):
            QMessageBox.information(self.gui, "No Data", "No scan output to export.")
            return

        filename, _ = QFileDialog.getSaveFileName(
            self.gui, "Export Raw Scan Output",
            f"scan_output_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt",
            "Text Files (*.txt);;CSV Files (*.csv);;JSON Files (*.json)"
        )

        if filename:
            try:
                if filename.endswith('.json'):
                    # Export as JSON
                    with open(filename, 'w', encoding='utf-8') as f:
                        json.dump(self.gui.scan_output_lines, f, indent=2)
                elif filename.endswith('.csv'):
                    # Export as CSV
                    import csv
                    with open(filename, 'w', newline='', encoding='utf-8') as f:
                        writer = csv.writer(f)
                        writer.writerow(['Line', 'Level', 'Module', 'Message'])
                        for line in self.gui.scan_output_lines:
                            writer.writerow([
                                line['line_number'],
                                line['level'],
                                line['module'],
                                line['message']
                            ])
                else:
                    # Export as plain text
                    with open(filename, 'w', encoding='utf-8') as f:
                        for line in self.gui.scan_output_lines:
                            f.write(line['raw_text'] + '\n')

                QMessageBox.information(
                    self.gui, "Success",
                    f"Exported {len(self.gui.scan_output_lines)} lines to:\n{filename}"
                )
            except Exception as e:
                QMessageBox.critical(self.gui, "Error", f"Failed to export:\n{e}")


# Helper function to add a finding to the results table (to be called from results_handler)
def add_finding_to_table(gui, severity, description, module="", target="", finding_data=None):
    """
    Add a finding to the results table

    Args:
        gui: The main GUI instance
        severity: Severity level (CRITICAL, HIGH, MEDIUM, LOW, INFO)
        description: Finding title/description
        module: Module that found the vulnerability
        target: Target URL
        finding_data: Additional finding data (dict with cvss, cwe, owasp, etc.)
    """
    if not hasattr(gui, 'results_table'):
        return

    row = gui.results_table.rowCount()
    gui.results_table.insertRow(row)

    # Row number
    num_item = QTableWidgetItem(str(row + 1))
    num_item.setTextAlignment(Qt.AlignCenter)
    if finding_data:
        num_item.setData(Qt.UserRole, finding_data)
    gui.results_table.setItem(row, 0, num_item)

    # Severity with color
    severity_item = QTableWidgetItem(severity.upper())
    severity_item.setTextAlignment(Qt.AlignCenter)
    color = SEVERITY_COLORS.get(severity.upper(), '#888888')
    severity_item.setForeground(QColor(color))
    severity_item.setFont(QFont("Arial", 9, QFont.Bold))
    gui.results_table.setItem(row, 1, severity_item)

    # Module
    module_item = QTableWidgetItem(module)
    gui.results_table.setItem(row, 2, module_item)

    # Title
    title_item = QTableWidgetItem(description)
    gui.results_table.setItem(row, 3, title_item)

    # Target
    target_item = QTableWidgetItem(target)
    gui.results_table.setItem(row, 4, target_item)

    # Time
    time_item = QTableWidgetItem(datetime.now().strftime("%H:%M:%S"))
    time_item.setTextAlignment(Qt.AlignCenter)
    gui.results_table.setItem(row, 5, time_item)

    # Update filters
    if hasattr(gui, 'module_filter') and module:
        # Add module to filter if not already there
        items = [gui.module_filter.itemText(i) for i in range(gui.module_filter.count())]
        if module not in items:
            gui.module_filter.addItem(module)

    if hasattr(gui, 'target_filter') and target:
        # Extract host from target
        try:
            from urllib.parse import urlparse
            host = urlparse(target).netloc
            if host:
                items = [gui.target_filter.itemText(i) for i in range(gui.target_filter.count())]
                if host not in items:
                    gui.target_filter.addItem(host)
        except:
            pass

    # Update stats
    if hasattr(gui, 'total_card'):
        counts = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0, 'INFO': 0}
        for r in range(gui.results_table.rowCount()):
            sev_item = gui.results_table.item(r, 1)
            if sev_item:
                sev = sev_item.text().upper()
                if sev in counts:
                    counts[sev] += 1

        total = sum(counts.values())
        gui.total_card.set_value(total)
        gui.critical_card.set_value(counts['CRITICAL'])
        gui.high_card.set_value(counts['HIGH'])
        gui.medium_card.set_value(counts['MEDIUM'])
        gui.low_card.set_value(counts['LOW'])
        gui.pie_chart.set_data(counts)

        # Update timeline
        if hasattr(gui, 'timeline_chart'):
            if not hasattr(gui, '_timeline_data'):
                gui._timeline_data = []
            gui._timeline_data.append((datetime.now(), severity.upper()))
            gui.timeline_chart.set_data(gui._timeline_data)

        # Update host stats list
        if hasattr(gui, 'host_stats_list'):
            # Count findings per host
            host_counts = {}
            for r in range(gui.results_table.rowCount()):
                target_item = gui.results_table.item(r, 4)
                if target_item:
                    target_url = target_item.text()
                    try:
                        from urllib.parse import urlparse
                        host = urlparse(target_url).netloc
                        if host:
                            host_counts[host] = host_counts.get(host, 0) + 1
                    except:
                        pass

            # Update the list widget
            gui.host_stats_list.clear()
            # Sort hosts by count (descending)
            sorted_hosts = sorted(host_counts.items(), key=lambda x: x[1], reverse=True)
            for host, count in sorted_hosts[:10]:  # Show top 10 hosts
                from PyQt5.QtWidgets import QListWidgetItem
                item = QListWidgetItem(f"{host} ({count})")
                gui.host_stats_list.addItem(item)

        # Update legacy labels
        gui.total_vulns_label.setText(f"Total Vulnerabilities: {total}")
        gui.critical_label.setText(f"Critical: {counts['CRITICAL']}")
        gui.high_label.setText(f"High: {counts['HIGH']}")
        gui.medium_label.setText(f"Medium: {counts['MEDIUM']}")


def add_resource_to_table(gui, resource_type, url, parameters="", status=""):
    """
    Add a resource to the resources table

    Args:
        gui: The main GUI instance
        resource_type: Type of resource (URL, Form, API, Endpoint, etc.)
        url: The URL/Path of the resource
        parameters: Any parameters found
        status: Status code or state
    """
    if not hasattr(gui, 'resources_table'):
        return

    row = gui.resources_table.rowCount()
    gui.resources_table.insertRow(row)

    # Type
    type_item = QTableWidgetItem(resource_type)
    gui.resources_table.setItem(row, 0, type_item)

    # URL/Path
    url_item = QTableWidgetItem(url)
    gui.resources_table.setItem(row, 1, url_item)

    # Parameters
    params_item = QTableWidgetItem(parameters)
    gui.resources_table.setItem(row, 2, params_item)

    # Status
    status_item = QTableWidgetItem(status)
    gui.resources_table.setItem(row, 3, status_item)

    # Update the resources section title with count
    _update_resources_count(gui)


def add_social_media_to_table(gui, platform, url, found_on):
    """
    Add a social media link to the social media table

    Args:
        gui: The main GUI instance
        platform: Social media platform name
        url: The URL
        found_on: Where it was found
    """
    if not hasattr(gui, 'social_media_table'):
        return

    row = gui.social_media_table.rowCount()
    gui.social_media_table.insertRow(row)

    gui.social_media_table.setItem(row, 0, QTableWidgetItem(platform))
    gui.social_media_table.setItem(row, 1, QTableWidgetItem(url))
    gui.social_media_table.setItem(row, 2, QTableWidgetItem(found_on))

    _update_resources_count(gui)


def add_email_to_table(gui, email, email_type, found_on):
    """
    Add an email to the emails table

    Args:
        gui: The main GUI instance
        email: The email address
        email_type: Type of email (personal, corporate, etc.)
        found_on: Where it was found
    """
    if not hasattr(gui, 'emails_table'):
        return

    row = gui.emails_table.rowCount()
    gui.emails_table.insertRow(row)

    gui.emails_table.setItem(row, 0, QTableWidgetItem(email))
    gui.emails_table.setItem(row, 1, QTableWidgetItem(email_type))
    gui.emails_table.setItem(row, 2, QTableWidgetItem(found_on))

    _update_resources_count(gui)


def add_phone_to_table(gui, phone, phone_format, found_on):
    """
    Add a phone number to the phones table

    Args:
        gui: The main GUI instance
        phone: The phone number
        phone_format: Format of the phone number
        found_on: Where it was found
    """
    if not hasattr(gui, 'phones_table'):
        return

    row = gui.phones_table.rowCount()
    gui.phones_table.insertRow(row)

    gui.phones_table.setItem(row, 0, QTableWidgetItem(phone))
    gui.phones_table.setItem(row, 1, QTableWidgetItem(phone_format))
    gui.phones_table.setItem(row, 2, QTableWidgetItem(found_on))

    _update_resources_count(gui)


def add_leaked_key_to_table(gui, key_type, key_preview, severity, found_on):
    """
    Add a leaked key to the leaked keys table

    Args:
        gui: The main GUI instance
        key_type: Type of key (API Key, AWS Key, etc.)
        key_preview: Preview of the key (truncated for security)
        severity: Severity level
        found_on: Where it was found
    """
    if not hasattr(gui, 'leaked_keys_table'):
        return

    row = gui.leaked_keys_table.rowCount()
    gui.leaked_keys_table.insertRow(row)

    gui.leaked_keys_table.setItem(row, 0, QTableWidgetItem(key_type))
    gui.leaked_keys_table.setItem(row, 1, QTableWidgetItem(key_preview))

    # Color code severity
    severity_item = QTableWidgetItem(severity)
    if severity.upper() == 'CRITICAL':
        severity_item.setForeground(QColor('#f44336'))
    elif severity.upper() == 'HIGH':
        severity_item.setForeground(QColor('#FF9800'))
    elif severity.upper() == 'MEDIUM':
        severity_item.setForeground(QColor('#FFC107'))
    gui.leaked_keys_table.setItem(row, 2, severity_item)

    gui.leaked_keys_table.setItem(row, 3, QTableWidgetItem(found_on))

    _update_resources_count(gui)


def _update_resources_count(gui):
    """Update the resources section title with total count"""
    if not hasattr(gui, 'resources_section'):
        return

    total = 0
    if hasattr(gui, 'resources_table'):
        total += gui.resources_table.rowCount()
    if hasattr(gui, 'social_media_table'):
        total += gui.social_media_table.rowCount()
    if hasattr(gui, 'emails_table'):
        total += gui.emails_table.rowCount()
    if hasattr(gui, 'phones_table'):
        total += gui.phones_table.rowCount()
    if hasattr(gui, 'leaked_keys_table'):
        total += gui.leaked_keys_table.rowCount()

    gui.resources_section.toggle_button.setText(f" Discovered Resources ({total})")

    # Auto-expand if there are resources
    if total > 0 and gui.resources_section.is_collapsed:
        gui.resources_section.expand()
