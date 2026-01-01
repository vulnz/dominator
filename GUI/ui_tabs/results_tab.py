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
    QTreeWidget, QTreeWidgetItem, QProgressBar
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

        # Create subtabs for Results and Progress - Light theme
        self.results_subtabs = QTabWidget()
        self.results_subtabs.setStyleSheet("""
            QTabWidget::pane {
                border: 2px solid #d1d5db;
                background-color: #ffffff;
                border-radius: 8px;
            }
            QTabBar::tab {
                background-color: #f3f4f6;
                color: #4b5563;
                padding: 12px 24px;
                border: 2px solid #d1d5db;
                border-bottom: none;
                margin-right: 3px;
                border-radius: 6px 6px 0 0;
                font-weight: bold;
                font-size: 13px;
                min-width: 120px;
            }
            QTabBar::tab:selected {
                background-color: #ffffff;
                color: #6366f1;
                border-bottom: 3px solid #6366f1;
                padding-bottom: 11px;
            }
            QTabBar::tab:hover {
                background-color: #e5e7eb;
                color: #1f2937;
            }
        """)

        # === Results subtab ===
        results_content = QWidget()
        results_content.setStyleSheet("background-color: #f9fafb;")
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

        # === Scan Output subtab (combined with Debug) ===
        scan_output_content = self._create_combined_output_tab()
        self.results_subtabs.addTab(scan_output_content, "Scan Output")

        # === Progress subtab ===
        # Import and build the progress tab content
        progress_builder = ProgressTabBuilder(self.gui, self.CollapsibleBox)
        progress_content = progress_builder.build()
        self.gui.progress_tab_builder = progress_builder  # Store reference for updates

        self.results_subtabs.addTab(progress_content, "Progress")

        # === Site Tree subtab ===
        site_tree_content = self._create_site_tree_tab()
        self.results_subtabs.addTab(site_tree_content, "🌳 Site Tree")

        # === Target Profile subtab ===
        target_profile_content = self._create_target_profile_tab()
        self.results_subtabs.addTab(target_profile_content, "🎯 Target Profile")

        main_layout.addWidget(self.results_subtabs)

        return widget

    def _create_resources_section(self):
        """Create collapsible section for discovered resources"""
        self.gui.resources_section = CollapsibleResourcesSection("Discovered Resources (0)")

        # Create tab widget for different resource types
        resources_tabs = QTabWidget()
        resources_tabs.setStyleSheet("""
            QTabWidget::pane {
                border: 1px solid #d1d5db;
                background-color: #ffffff;
                border-radius: 4px;
            }
            QTabBar::tab {
                background-color: #f3f4f6;
                color: #6b7280;
                padding: 6px 12px;
                border: 1px solid #d1d5db;
                border-bottom: none;
                margin-right: 2px;
            }
            QTabBar::tab:selected {
                background-color: #f9fafb;
                color: #6366f1;
                font-weight: bold;
            }
            QTabBar::tab:hover {
                background-color: #e5e7eb;
            }
        """)

        # URLs/Endpoints tab
        urls_widget = QWidget()
        urls_layout = QVBoxLayout(urls_widget)
        urls_layout.setContentsMargins(5, 5, 5, 5)

        self.gui.resources_table = QTableWidget()
        self.gui.resources_table.setColumnCount(4)
        self.gui.resources_table.setHorizontalHeaderLabels(["Type", "URL/Path", "Parameters", "Status"])
        self.gui.resources_table.setSortingEnabled(True)
        self.gui.resources_table.setAlternatingRowColors(True)
        self.gui.resources_table.horizontalHeader().setStretchLastSection(True)
        self.gui.resources_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.Interactive)
        self.gui.resources_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.Stretch)
        self.gui.resources_table.horizontalHeader().setSectionResizeMode(2, QHeaderView.Interactive)
        self.gui.resources_table.horizontalHeader().setSectionResizeMode(3, QHeaderView.Interactive)
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
        self.gui.social_media_table.setSortingEnabled(True)
        self.gui.social_media_table.setAlternatingRowColors(True)
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
        self.gui.emails_table.setSortingEnabled(True)
        self.gui.emails_table.setAlternatingRowColors(True)
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
        self.gui.phones_table.setSortingEnabled(True)
        self.gui.phones_table.setAlternatingRowColors(True)
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
        self.gui.leaked_keys_table.setSortingEnabled(True)
        self.gui.leaked_keys_table.setAlternatingRowColors(True)
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
                color: #1f2937;
                gridline-color: #d1d5db;
                border: 1px solid #d1d5db;
                border-radius: 4px;
            }
            QHeaderView::section {
                background-color: #f3f4f6;
                color: #6366f1;
                padding: 8px;
                border: 1px solid #d1d5db;
                font-weight: bold;
            }
            QTableWidget::item {
                padding: 5px;
            }
            QTableWidget::item:selected {
                background-color: #6366f1;
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
        """Create dashboard header with stats cards and charts - Dark theme"""
        dashboard = QFrame()
        dashboard.setStyleSheet("""
            QFrame {
                background: linear-gradient(135deg, #f3f4f6 0%, #1e1e35 100%);
                border: 2px solid #d1d5db;
                border-radius: 12px;
                padding: 15px;
            }
            QLabel {
                color: #1f2937;
            }
        """)

        layout = QHBoxLayout(dashboard)
        layout.setSpacing(15)

        # Stats cards - all in one row for better layout
        cards_layout = QHBoxLayout()
        cards_layout.setSpacing(10)

        # Total findings card (first)
        self.gui.total_card = StatsCard("Total Findings", "0", "#6366f1")
        cards_layout.addWidget(self.gui.total_card)

        # Severity cards
        self.gui.critical_card = StatsCard("Critical", "0", SEVERITY_COLORS['CRITICAL'])
        cards_layout.addWidget(self.gui.critical_card)

        self.gui.high_card = StatsCard("High", "0", SEVERITY_COLORS['HIGH'])
        cards_layout.addWidget(self.gui.high_card)

        self.gui.medium_card = StatsCard("Medium", "0", SEVERITY_COLORS['MEDIUM'])
        cards_layout.addWidget(self.gui.medium_card)

        self.gui.low_card = StatsCard("Low", "0", SEVERITY_COLORS['LOW'])
        cards_layout.addWidget(self.gui.low_card)

        # Add stretch at end to prevent cards from stretching
        cards_layout.addStretch()
        layout.addLayout(cards_layout)

        # Charts section
        charts_layout = QVBoxLayout()

        # Pie chart
        pie_label = QLabel("Severity Distribution")
        pie_label.setStyleSheet("font-weight: bold; color: #1f2937;")
        pie_label.setAlignment(Qt.AlignCenter)
        charts_layout.addWidget(pie_label)

        self.gui.pie_chart = PieChartWidget()
        charts_layout.addWidget(self.gui.pie_chart, alignment=Qt.AlignCenter)

        layout.addLayout(charts_layout)

        # Timeline chart
        timeline_layout = QVBoxLayout()

        timeline_label = QLabel("Findings Timeline")
        timeline_label.setStyleSheet("font-weight: bold; color: #1f2937;")
        timeline_label.setAlignment(Qt.AlignCenter)
        timeline_layout.addWidget(timeline_label)

        self.gui.timeline_chart = TimelineWidget()
        timeline_layout.addWidget(self.gui.timeline_chart)

        layout.addLayout(timeline_layout)

        # Host statistics section
        host_stats_layout = QVBoxLayout()

        host_label = QLabel("Findings by Host")
        host_label.setStyleSheet("font-weight: bold; color: #1f2937;")
        host_label.setAlignment(Qt.AlignCenter)
        host_stats_layout.addWidget(host_label)

        # Host stats list (compact table showing top hosts)
        self.gui.host_stats_list = QListWidget()
        self.gui.host_stats_list.setMaximumHeight(120)
        self.gui.host_stats_list.setMaximumWidth(200)
        self.gui.host_stats_list.setStyleSheet("""
            QListWidget {
                background-color: #ffffff;
                border: 1px solid #d1d5db;
                border-radius: 4px;
                font-size: 10px;
                color: #1f2937;
            }
            QListWidget::item {
                padding: 4px;
                border-bottom: 1px solid #e5e7eb;
            }
            QListWidget::item:selected {
                background-color: #d1d5db;
                color: #ffffff;
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
                border: 1px solid #d1d5db;
                border-radius: 6px;
                padding: 8px;
            }
        """)

        layout = QHBoxLayout(filters_frame)
        layout.setSpacing(10)

        # Severity filter
        severity_label = QLabel("Severity:")
        severity_label.setStyleSheet("color: #1f2937; font-weight: bold;")
        layout.addWidget(severity_label)

        self.gui.severity_filter = QComboBox()
        self.gui.severity_filter.addItems(["All", "Critical", "High", "Medium", "Low", "Info"])
        self.gui.severity_filter.setStyleSheet("""
            QComboBox {
                background-color: #f3f4f6;
                color: #1f2937;
                border: 1px solid #d1d5db;
                border-radius: 4px;
                padding: 5px;
                min-width: 100px;
            }
            QComboBox:hover { border-color: #6366f1; }
            QComboBox::drop-down { border: none; }
            QComboBox QAbstractItemView { background-color: #f3f4f6; color: #1f2937; selection-background-color: #6366f1; }
        """)
        self.gui.severity_filter.currentTextChanged.connect(self._apply_filters)
        layout.addWidget(self.gui.severity_filter)

        # Module filter
        module_label = QLabel("Module:")
        module_label.setStyleSheet("color: #1f2937; font-weight: bold;")
        layout.addWidget(module_label)

        self.gui.module_filter = QComboBox()
        self.gui.module_filter.addItem("All")
        self.gui.module_filter.setStyleSheet("""
            QComboBox {
                background-color: #f3f4f6;
                color: #1f2937;
                border: 1px solid #d1d5db;
                border-radius: 4px;
                padding: 5px;
                min-width: 120px;
            }
            QComboBox:hover { border-color: #6366f1; }
            QComboBox::drop-down { border: none; }
            QComboBox QAbstractItemView { background-color: #f3f4f6; color: #1f2937; selection-background-color: #6366f1; }
        """)
        self.gui.module_filter.currentTextChanged.connect(self._apply_filters)
        layout.addWidget(self.gui.module_filter)

        # Target filter
        target_label = QLabel("Target:")
        target_label.setStyleSheet("color: #1f2937; font-weight: bold;")
        layout.addWidget(target_label)

        self.gui.target_filter = QComboBox()
        self.gui.target_filter.addItem("All")
        self.gui.target_filter.setStyleSheet("""
            QComboBox {
                background-color: #f3f4f6;
                color: #1f2937;
                border: 1px solid #d1d5db;
                border-radius: 4px;
                padding: 5px;
                min-width: 150px;
            }
            QComboBox:hover { border-color: #6366f1; }
            QComboBox::drop-down { border: none; }
            QComboBox QAbstractItemView { background-color: #f3f4f6; color: #1f2937; selection-background-color: #6366f1; }
        """)
        self.gui.target_filter.currentTextChanged.connect(self._apply_filters)
        layout.addWidget(self.gui.target_filter)

        # Status Code filter
        status_label = QLabel("Status:")
        status_label.setStyleSheet("color: #1f2937; font-weight: bold;")
        layout.addWidget(status_label)

        self.gui.status_filter = QComboBox()
        self.gui.status_filter.addItems(["All", "2xx", "3xx", "4xx", "5xx", "200", "301", "302", "400", "401", "403", "404", "500"])
        self.gui.status_filter.setStyleSheet("""
            QComboBox {
                background-color: #f3f4f6;
                color: #1f2937;
                border: 1px solid #d1d5db;
                border-radius: 4px;
                padding: 5px;
                min-width: 70px;
            }
            QComboBox:hover { border-color: #6366f1; }
            QComboBox::drop-down { border: none; }
            QComboBox QAbstractItemView { background-color: #f3f4f6; color: #1f2937; selection-background-color: #6366f1; }
        """)
        self.gui.status_filter.currentTextChanged.connect(self._apply_filters)
        layout.addWidget(self.gui.status_filter)

        # Extension filter
        ext_label = QLabel("Extension:")
        ext_label.setStyleSheet("color: #1f2937; font-weight: bold;")
        layout.addWidget(ext_label)

        self.gui.extension_filter = QComboBox()
        self.gui.extension_filter.addItems(["All", ".php", ".asp", ".aspx", ".jsp", ".html", ".js", ".json", ".xml", "No ext"])
        self.gui.extension_filter.setStyleSheet("""
            QComboBox {
                background-color: #f3f4f6;
                color: #1f2937;
                border: 1px solid #d1d5db;
                border-radius: 4px;
                padding: 5px;
                min-width: 80px;
            }
            QComboBox:hover { border-color: #6366f1; }
            QComboBox::drop-down { border: none; }
            QComboBox QAbstractItemView { background-color: #f3f4f6; color: #1f2937; selection-background-color: #6366f1; }
        """)
        self.gui.extension_filter.currentTextChanged.connect(self._apply_filters)
        layout.addWidget(self.gui.extension_filter)

        # Search box
        search_label = QLabel("Search:")
        search_label.setStyleSheet("color: #1f2937; font-weight: bold;")
        layout.addWidget(search_label)

        self.gui.results_search = QLineEdit()
        self.gui.results_search.setPlaceholderText("Search findings...")
        self.gui.results_search.setStyleSheet("""
            QLineEdit {
                background-color: #f3f4f6;
                color: #1f2937;
                border: 1px solid #d1d5db;
                border-radius: 4px;
                padding: 5px;
                min-width: 120px;
            }
            QLineEdit:focus { border-color: #6366f1; }
        """)
        self.gui.results_search.textChanged.connect(self._apply_filters)
        layout.addWidget(self.gui.results_search)

        # Clear filters button
        clear_btn = QPushButton("Clear Filters")
        clear_btn.setStyleSheet("""
            QPushButton {
                background-color: #f3f4f6;
                color: #1f2937;
                border: 1px solid #d1d5db;
                border-radius: 4px;
                padding: 5px 15px;
            }
            QPushButton:hover {
                background-color: #d1d5db;
                border-color: #6366f1;
            }
        """)
        clear_btn.clicked.connect(self._clear_filters)
        layout.addWidget(clear_btn)

        # Group by target checkbox
        self.gui.group_by_target = QPushButton("Group by Target")
        self.gui.group_by_target.setCheckable(True)
        self.gui.group_by_target.setStyleSheet("""
            QPushButton {
                background-color: #f3f4f6;
                color: #1f2937;
                border: 1px solid #d1d5db;
                border-radius: 4px;
                padding: 5px 15px;
            }
            QPushButton:checked {
                background-color: #6366f1;
                color: white;
            }
            QPushButton:hover {
                background-color: #d1d5db;
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
        """Create a modern, clean results table with essential columns only"""
        container = QWidget()
        layout = QVBoxLayout(container)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(8)

        # Header with title, count and quick actions
        header_frame = QFrame()
        header_frame.setStyleSheet("""
            QFrame {
                background-color: #f8fafc;
                border: 1px solid #e2e8f0;
                border-radius: 8px;
                padding: 8px;
            }
        """)
        header_layout = QHBoxLayout(header_frame)
        header_layout.setContentsMargins(12, 8, 12, 8)

        # Title with icon
        title_label = QLabel("Vulnerability Findings")
        title_label.setFont(QFont("Segoe UI", 14, QFont.Bold))
        title_label.setStyleSheet("color: #1e293b; background: transparent; border: none;")
        header_layout.addWidget(title_label)

        # Count badge
        self.gui.findings_count_label = QLabel("0")
        self.gui.findings_count_label.setFont(QFont("Segoe UI", 11, QFont.Bold))
        self.gui.findings_count_label.setStyleSheet("""
            background-color: #3b82f6;
            color: white;
            padding: 4px 12px;
            border-radius: 12px;
            border: none;
        """)
        header_layout.addWidget(self.gui.findings_count_label)

        header_layout.addStretch()

        # Severity filter chips
        filter_label = QLabel("Filter:")
        filter_label.setStyleSheet("color: #64748b; background: transparent; border: none;")
        header_layout.addWidget(filter_label)

        self.gui.severity_filter = QComboBox()
        self.gui.severity_filter.addItems(["All", "Critical", "High", "Medium", "Low", "Info"])
        self.gui.severity_filter.setStyleSheet("""
            QComboBox {
                background-color: white;
                border: 1px solid #cbd5e1;
                border-radius: 4px;
                padding: 4px 24px 4px 8px;
                min-width: 80px;
                font-size: 11px;
            }
            QComboBox:hover { border-color: #3b82f6; }
            QComboBox::drop-down { border: none; width: 20px; }
        """)
        self.gui.severity_filter.currentTextChanged.connect(self._filter_findings_by_severity)
        header_layout.addWidget(self.gui.severity_filter)

        layout.addWidget(header_frame)

        # Modern results table - simplified columns
        self.gui.results_table = QTableWidget()
        self.gui.results_table.setColumnCount(6)
        self.gui.results_table.setHorizontalHeaderLabels([
            "Severity", "Vulnerability Type", "Target URL", "Parameter", "Evidence", "CVSS"
        ])

        # Modern clean table style
        self.gui.results_table.setStyleSheet("""
            QTableWidget {
                background-color: #ffffff;
                alternate-background-color: #f8fafc;
                border: 1px solid #e2e8f0;
                border-radius: 8px;
                gridline-color: #f1f5f9;
                color: #1e293b;
                font-size: 12px;
                selection-background-color: #dbeafe;
                selection-color: #1e40af;
            }
            QTableWidget::item {
                padding: 10px 8px;
                border-bottom: 1px solid #f1f5f9;
            }
            QTableWidget::item:selected {
                background-color: #dbeafe;
                color: #1e40af;
            }
            QTableWidget::item:hover {
                background-color: #f1f5f9;
            }
            QHeaderView::section {
                background-color: #f8fafc;
                color: #475569;
                padding: 12px 8px;
                border: none;
                border-bottom: 2px solid #3b82f6;
                border-right: 1px solid #e2e8f0;
                font-weight: 600;
                font-size: 11px;
                text-transform: uppercase;
            }
            QHeaderView::section:last {
                border-right: none;
            }
            QHeaderView::section:hover {
                background-color: #f1f5f9;
                color: #1e293b;
            }
            QScrollBar:vertical {
                background: #f8fafc;
                width: 8px;
                border-radius: 4px;
            }
            QScrollBar::handle:vertical {
                background: #cbd5e1;
                border-radius: 4px;
                min-height: 30px;
            }
            QScrollBar::handle:vertical:hover {
                background: #94a3b8;
            }
            QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {
                height: 0px;
            }
        """)

        # Configure column widths
        header = self.gui.results_table.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.Fixed)       # Severity
        header.setSectionResizeMode(1, QHeaderView.Interactive) # Vulnerability Type
        header.setSectionResizeMode(2, QHeaderView.Stretch)     # URL (stretch)
        header.setSectionResizeMode(3, QHeaderView.Fixed)       # Parameter
        header.setSectionResizeMode(4, QHeaderView.Interactive) # Evidence
        header.setSectionResizeMode(5, QHeaderView.Fixed)       # CVSS

        self.gui.results_table.setColumnWidth(0, 90)   # Severity
        self.gui.results_table.setColumnWidth(1, 180)  # Vulnerability Type
        self.gui.results_table.setColumnWidth(3, 100)  # Parameter
        self.gui.results_table.setColumnWidth(4, 200)  # Evidence
        self.gui.results_table.setColumnWidth(5, 60)   # CVSS

        self.gui.results_table.setAlternatingRowColors(True)
        self.gui.results_table.verticalHeader().setVisible(False)  # Hide row numbers
        self.gui.results_table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.gui.results_table.setSelectionMode(QAbstractItemView.ExtendedSelection)
        self.gui.results_table.setSortingEnabled(True)
        self.gui.results_table.setContextMenuPolicy(Qt.CustomContextMenu)
        self.gui.results_table.setWordWrap(False)
        self.gui.results_table.setTextElideMode(Qt.ElideMiddle)
        self.gui.results_table.setShowGrid(False)  # Cleaner look

        # Connect signals
        self.gui.results_table.doubleClicked.connect(self._on_row_double_clicked)
        self.gui.results_table.customContextMenuRequested.connect(self._show_context_menu)
        self.gui.results_table.itemSelectionChanged.connect(self._on_selection_changed)
        self.gui.results_table.clicked.connect(self._on_row_clicked)

        layout.addWidget(self.gui.results_table)

        # Legacy vulns_list for compatibility
        self.gui.vulns_list = QListWidget()
        self.gui.vulns_list.hide()

        return container

    def _filter_findings_by_severity(self, severity_text):
        """Filter findings table by severity"""
        if not hasattr(self.gui, 'results_table'):
            return

        for row in range(self.gui.results_table.rowCount()):
            if severity_text == "All":
                self.gui.results_table.setRowHidden(row, False)
            else:
                severity_item = self.gui.results_table.item(row, 0)
                if severity_item:
                    row_severity = severity_item.text().upper()
                    self.gui.results_table.setRowHidden(row, severity_text.upper() not in row_severity)

    def _create_detail_panel(self):
        """Create the detail panel for showing selected finding details with ALL data"""
        container = QWidget()
        layout = QVBoxLayout(container)
        layout.setContentsMargins(0, 0, 0, 0)

        # Panel label
        label = QLabel("📋 Finding Details")
        label.setStyleSheet("font-size: 16px; font-weight: bold; color: #1976D2; padding: 5px;")
        layout.addWidget(label)

        # Scroll area for details with dark theme
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setStyleSheet("""
            QScrollArea {
                background-color: #f9fafb;
                border: 2px solid #d1d5db;
                border-radius: 8px;
            }
            QScrollBar:vertical {
                background: #f9fafb;
                width: 10px;
            }
            QScrollBar::handle:vertical {
                background: #4a4a7a;
                border-radius: 5px;
            }
        """)

        # Detail content widget with dark theme
        self.gui.detail_content = QWidget()
        self.gui.detail_content.setStyleSheet("background-color: #f9fafb;")
        detail_layout = QVBoxLayout(self.gui.detail_content)
        detail_layout.setSpacing(12)
        detail_layout.setContentsMargins(15, 15, 15, 15)

        # Severity badge
        self.gui.detail_severity = QLabel("Select a finding to view details")
        self.gui.detail_severity.setAlignment(Qt.AlignCenter)
        self.gui.detail_severity.setStyleSheet("""
            background-color: #d1d5db;
            color: #6b7280;
            padding: 15px;
            border-radius: 8px;
            font-weight: bold;
            font-size: 14px;
        """)
        detail_layout.addWidget(self.gui.detail_severity)

        # Title
        self.gui.detail_title = QLabel("")
        self.gui.detail_title.setStyleSheet("font-size: 16px; font-weight: bold; color: #f0f0f0;")
        self.gui.detail_title.setWordWrap(True)
        detail_layout.addWidget(self.gui.detail_title)

        # === BASIC INFO SECTION ===
        info_group = QGroupBox("📌 Basic Information")
        info_group.setStyleSheet("""
            QGroupBox {
                font-weight: bold;
                color: #60a5fa;
                border: 1px solid #d1d5db;
                border-radius: 6px;
                margin-top: 10px;
                padding-top: 10px;
            }
            QGroupBox::title {
                subcontrol-origin: margin;
                left: 10px;
                padding: 0 5px;
            }
            QLabel { color: #1f2937; }
        """)
        info_layout = QGridLayout(info_group)
        info_layout.setSpacing(8)

        # Labels with styling
        label_style = "color: #6b7280; font-weight: bold;"
        value_style = "color: #1f2937;"

        for row_idx, (label_text, attr_name) in enumerate([
            ("Module:", "detail_module"),
            ("Target URL:", "detail_target"),
            ("Parameter:", "detail_parameter"),
            ("Time:", "detail_time"),
        ]):
            lbl = QLabel(label_text)
            lbl.setStyleSheet(label_style)
            info_layout.addWidget(lbl, row_idx, 0)

            value_lbl = QLabel("-")
            value_lbl.setStyleSheet(value_style)
            value_lbl.setWordWrap(True)
            value_lbl.setTextInteractionFlags(Qt.TextSelectableByMouse)
            setattr(self.gui, attr_name, value_lbl)
            info_layout.addWidget(value_lbl, row_idx, 1)

        detail_layout.addWidget(info_group)

        # === CLASSIFICATION SECTION ===
        class_group = QGroupBox("🏷️ Classification")
        class_group.setStyleSheet(info_group.styleSheet().replace('#60a5fa', '#a78bfa'))
        class_layout = QGridLayout(class_group)
        class_layout.setSpacing(8)

        for row_idx, (label_text, attr_name) in enumerate([
            ("CVSS Score:", "detail_cvss"),
            ("CWE:", "detail_cwe"),
            ("OWASP:", "detail_owasp"),
        ]):
            lbl = QLabel(label_text)
            lbl.setStyleSheet(label_style)
            class_layout.addWidget(lbl, row_idx, 0)

            value_lbl = QLabel("-")
            value_lbl.setStyleSheet("color: #fbbf24; font-weight: bold;")
            value_lbl.setWordWrap(True)
            setattr(self.gui, attr_name, value_lbl)
            class_layout.addWidget(value_lbl, row_idx, 1)

        detail_layout.addWidget(class_group)

        # === PAYLOAD SECTION ===
        payload_group = QGroupBox("💉 Payload")
        payload_group.setStyleSheet(info_group.styleSheet().replace('#60a5fa', '#f87171'))
        payload_layout = QVBoxLayout(payload_group)

        self.gui.detail_payload = QTextEdit()
        self.gui.detail_payload.setReadOnly(True)
        self.gui.detail_payload.setMaximumHeight(80)
        self.gui.detail_payload.setFont(QFont("Consolas", 10))
        self.gui.detail_payload.setStyleSheet("""
            QTextEdit {
                background-color: #e5e7eb;
                border: 1px solid #4a4a7a;
                border-radius: 4px;
                color: #f87171;
                padding: 8px;
            }
        """)
        payload_layout.addWidget(self.gui.detail_payload)
        detail_layout.addWidget(payload_group)

        # === EVIDENCE SECTION ===
        evidence_group = QGroupBox("🔍 Evidence")
        evidence_group.setStyleSheet(info_group.styleSheet().replace('#60a5fa', '#22c55e'))
        evidence_layout = QVBoxLayout(evidence_group)

        self.gui.detail_evidence = QTextEdit()
        self.gui.detail_evidence.setReadOnly(True)
        self.gui.detail_evidence.setMaximumHeight(100)
        self.gui.detail_evidence.setFont(QFont("Consolas", 9))
        self.gui.detail_evidence.setStyleSheet("""
            QTextEdit {
                background-color: #e5e7eb;
                border: 1px solid #4a4a7a;
                border-radius: 4px;
                color: #22c55e;
                padding: 8px;
            }
        """)
        evidence_layout.addWidget(self.gui.detail_evidence)
        detail_layout.addWidget(evidence_group)

        # === DESCRIPTION SECTION ===
        desc_group = QGroupBox("📝 Description")
        desc_group.setStyleSheet(info_group.styleSheet())
        desc_layout = QVBoxLayout(desc_group)

        self.gui.detail_description = QTextEdit()
        self.gui.detail_description.setReadOnly(True)
        self.gui.detail_description.setMaximumHeight(80)
        self.gui.detail_description.setFont(QFont("Arial", 10))
        self.gui.detail_description.setStyleSheet("""
            QTextEdit {
                background-color: #e5e7eb;
                border: 1px solid #4a4a7a;
                border-radius: 4px;
                color: #1f2937;
                padding: 8px;
            }
        """)
        desc_layout.addWidget(self.gui.detail_description)
        detail_layout.addWidget(desc_group)

        # === REMEDIATION SECTION ===
        remed_group = QGroupBox("🛡️ Remediation")
        remed_group.setStyleSheet(info_group.styleSheet().replace('#60a5fa', '#fbbf24'))
        remed_layout = QVBoxLayout(remed_group)

        self.gui.detail_remediation = QTextEdit()
        self.gui.detail_remediation.setReadOnly(True)
        self.gui.detail_remediation.setMaximumHeight(80)
        self.gui.detail_remediation.setFont(QFont("Arial", 10))
        self.gui.detail_remediation.setStyleSheet("""
            QTextEdit {
                background-color: #e5e7eb;
                border: 1px solid #4a4a7a;
                border-radius: 4px;
                color: #fbbf24;
                padding: 8px;
            }
        """)
        remed_layout.addWidget(self.gui.detail_remediation)
        detail_layout.addWidget(remed_group)

        # === HTTP REQUEST SECTION ===
        request_group = QGroupBox("📤 HTTP Request")
        request_group.setStyleSheet(info_group.styleSheet().replace('#60a5fa', '#a78bfa'))
        request_layout = QVBoxLayout(request_group)

        self.gui.detail_request = QTextEdit()
        self.gui.detail_request.setReadOnly(True)
        self.gui.detail_request.setMaximumHeight(100)
        self.gui.detail_request.setFont(QFont("Consolas", 9))
        self.gui.detail_request.setStyleSheet("""
            QTextEdit {
                background-color: #1e1e2e;
                border: 1px solid #4a4a7a;
                border-radius: 4px;
                color: #a78bfa;
                padding: 8px;
            }
        """)
        request_layout.addWidget(self.gui.detail_request)
        detail_layout.addWidget(request_group)

        # === HTTP RESPONSE SECTION ===
        response_group = QGroupBox("📥 HTTP Response")
        response_group.setStyleSheet(info_group.styleSheet().replace('#60a5fa', '#60a5fa'))
        response_layout = QVBoxLayout(response_group)

        self.gui.detail_response = QTextEdit()
        self.gui.detail_response.setReadOnly(True)
        self.gui.detail_response.setMaximumHeight(100)
        self.gui.detail_response.setFont(QFont("Consolas", 9))
        self.gui.detail_response.setStyleSheet("""
            QTextEdit {
                background-color: #1e1e2e;
                border: 1px solid #4a4a7a;
                border-radius: 4px;
                color: #60a5fa;
                padding: 8px;
            }
        """)
        response_layout.addWidget(self.gui.detail_response)
        detail_layout.addWidget(response_group)

        # View full details button
        view_full_btn = QPushButton("🔎 View Full Details")
        view_full_btn.setStyleSheet("""
            QPushButton {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
                    stop:0 #6366f1, stop:1 #8b5cf6);
                color: white;
                border: none;
                border-radius: 8px;
                padding: 12px 24px;
                font-weight: bold;
                font-size: 13px;
            }
            QPushButton:hover {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
                    stop:0 #4f46e5, stop:1 #7c3aed);
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
                background-color: #ffffff;
                border: 1px solid #d1d5db;
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

    def _create_combined_output_tab(self):
        """Create the combined scan output tab with progress display and all output messages"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(10, 10, 10, 10)
        layout.setSpacing(8)

        # === Progress Section at Top ===
        progress_frame = QFrame()
        progress_frame.setStyleSheet("""
            QFrame {
                background-color: #f8fafc;
                border: 2px solid #e2e8f0;
                border-radius: 8px;
                padding: 10px;
            }
        """)
        progress_layout = QVBoxLayout(progress_frame)
        progress_layout.setSpacing(8)

        # Progress bar with percentage
        progress_row = QHBoxLayout()

        self.gui.output_progress_bar = QProgressBar()
        self.gui.output_progress_bar.setMinimum(0)
        self.gui.output_progress_bar.setMaximum(100)
        self.gui.output_progress_bar.setValue(0)
        self.gui.output_progress_bar.setMinimumHeight(24)
        self.gui.output_progress_bar.setStyleSheet("""
            QProgressBar {
                border: 2px solid #cbd5e1;
                border-radius: 6px;
                text-align: center;
                background-color: #f1f5f9;
                color: #1e293b;
                font-weight: bold;
                font-size: 11px;
            }
            QProgressBar::chunk {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
                    stop:0 #22c55e, stop:0.5 #16a34a, stop:1 #15803d);
                border-radius: 4px;
            }
        """)
        progress_row.addWidget(self.gui.output_progress_bar, 1)

        progress_layout.addLayout(progress_row)

        # Status info row
        status_row = QHBoxLayout()

        # Current module label
        self.gui.output_current_module = QLabel("Ready to scan...")
        self.gui.output_current_module.setFont(QFont("Segoe UI", 10, QFont.Bold))
        self.gui.output_current_module.setStyleSheet("color: #3b82f6; background: transparent; border: none;")
        status_row.addWidget(self.gui.output_current_module)

        status_row.addStretch()

        # Time elapsed
        self.gui.output_time_elapsed = QLabel("Elapsed: --:--")
        self.gui.output_time_elapsed.setFont(QFont("Segoe UI", 9))
        self.gui.output_time_elapsed.setStyleSheet("""
            color: #64748b;
            background-color: #f1f5f9;
            padding: 4px 8px;
            border-radius: 4px;
            border: none;
        """)
        status_row.addWidget(self.gui.output_time_elapsed)

        # Time remaining
        self.gui.output_time_remaining = QLabel("Remaining: --:--")
        self.gui.output_time_remaining.setFont(QFont("Segoe UI", 9))
        self.gui.output_time_remaining.setStyleSheet("""
            color: #64748b;
            background-color: #f1f5f9;
            padding: 4px 8px;
            border-radius: 4px;
            border: none;
        """)
        status_row.addWidget(self.gui.output_time_remaining)

        progress_layout.addLayout(status_row)
        layout.addWidget(progress_frame)

        # === Header with title, filters and export ===
        header_layout = QHBoxLayout()

        title_label = QLabel("Scan Output")
        title_label.setFont(QFont("Segoe UI", 12, QFont.Bold))
        title_label.setStyleSheet("color: #1e293b;")
        header_layout.addWidget(title_label)

        header_layout.addStretch()

        # Filter dropdown
        filter_label = QLabel("Filter:")
        filter_label.setFont(QFont("Segoe UI", 9))
        header_layout.addWidget(filter_label)

        self.gui.output_filter_combo = QComboBox()
        self.gui.output_filter_combo.addItems(["All", "Errors", "Warnings", "Info", "Modules", "Findings"])
        self.gui.output_filter_combo.setMinimumWidth(100)
        self.gui.output_filter_combo.setStyleSheet("""
            QComboBox {
                background-color: white;
                border: 1px solid #cbd5e1;
                border-radius: 4px;
                padding: 4px 8px;
                font-size: 10px;
            }
            QComboBox:hover {
                border-color: #3b82f6;
            }
            QComboBox::drop-down {
                border: none;
                padding-right: 8px;
            }
        """)
        self.gui.output_filter_combo.currentTextChanged.connect(self._filter_combined_output)
        header_layout.addWidget(self.gui.output_filter_combo)

        # Clear button
        clear_btn = QPushButton("Clear")
        clear_btn.setStyleSheet("""
            QPushButton {
                background-color: #ef4444;
                color: white;
                border: none;
                border-radius: 4px;
                padding: 6px 12px;
                font-size: 10px;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: #dc2626;
            }
        """)
        clear_btn.clicked.connect(self._clear_combined_output)
        header_layout.addWidget(clear_btn)

        # Export button
        export_btn = QPushButton("Export")
        export_btn.setStyleSheet("""
            QPushButton {
                background-color: #22c55e;
                color: white;
                border: none;
                border-radius: 4px;
                padding: 6px 12px;
                font-size: 10px;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: #16a34a;
            }
        """)
        export_btn.clicked.connect(self._export_raw_scan_output)
        header_layout.addWidget(export_btn)

        layout.addLayout(header_layout)

        # === Search bar ===
        search_layout = QHBoxLayout()

        self.gui.scan_output_search = QLineEdit()
        self.gui.scan_output_search.setPlaceholderText("Search output (URLs, modules, messages)...")
        self.gui.scan_output_search.setMinimumHeight(32)
        self.gui.scan_output_search.setStyleSheet("""
            QLineEdit {
                background-color: white;
                border: 2px solid #e2e8f0;
                border-radius: 6px;
                padding: 6px 12px;
                font-size: 11px;
            }
            QLineEdit:focus {
                border: 2px solid #3b82f6;
            }
            QLineEdit::placeholder {
                color: #94a3b8;
            }
        """)
        self.gui.scan_output_search.textChanged.connect(self._filter_combined_output)
        search_layout.addWidget(self.gui.scan_output_search)

        layout.addLayout(search_layout)

        # === Stats bar ===
        stats_frame = QFrame()
        stats_frame.setStyleSheet("""
            QFrame {
                background-color: #f1f5f9;
                border-radius: 4px;
                padding: 4px;
            }
        """)
        stats_layout = QHBoxLayout(stats_frame)
        stats_layout.setContentsMargins(8, 4, 8, 4)

        self.gui.scan_output_stats = QLabel("Lines: 0 | Errors: 0 | Warnings: 0 | Modules: 0 | Findings: 0")
        self.gui.scan_output_stats.setFont(QFont("Segoe UI", 9))
        self.gui.scan_output_stats.setStyleSheet("color: #475569; background: transparent; border: none;")
        stats_layout.addWidget(self.gui.scan_output_stats)
        stats_layout.addStretch()

        layout.addWidget(stats_frame)

        # === Output Table ===
        self.gui.scan_output_table = QTableWidget()
        self.gui.scan_output_table.setColumnCount(4)
        self.gui.scan_output_table.setHorizontalHeaderLabels([
            "#", "Level", "Source", "Message"
        ])
        self.gui.scan_output_table.setSortingEnabled(True)
        self.gui.scan_output_table.setMinimumHeight(300)
        self.gui.scan_output_table.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)

        # Column sizing
        header = self.gui.scan_output_table.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.Interactive)
        header.resizeSection(0, 50)
        header.setSectionResizeMode(1, QHeaderView.Interactive)
        header.resizeSection(1, 80)
        header.setSectionResizeMode(2, QHeaderView.Interactive)
        header.resizeSection(2, 120)
        header.setSectionResizeMode(3, QHeaderView.Stretch)

        self.gui.scan_output_table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.gui.scan_output_table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.gui.scan_output_table.setAlternatingRowColors(True)
        self.gui.scan_output_table.setFont(QFont("Consolas", 9))
        self.gui.scan_output_table.setStyleSheet("""
            QTableWidget {
                background-color: #ffffff;
                color: #1e293b;
                gridline-color: #e2e8f0;
                border: 1px solid #e2e8f0;
                border-radius: 6px;
            }
            QHeaderView::section {
                background: #f8fafc;
                color: #475569;
                padding: 8px;
                border: none;
                border-bottom: 2px solid #3b82f6;
                border-right: 1px solid #e2e8f0;
                font-weight: bold;
                font-size: 10px;
            }
            QHeaderView::section:last {
                border-right: none;
            }
            QTableWidget::item {
                padding: 4px;
                border-bottom: 1px solid #f1f5f9;
            }
            QTableWidget::item:selected {
                background-color: #dbeafe;
                color: #1e40af;
            }
            QTableWidget::item:hover {
                background-color: #f8fafc;
            }
        """)

        layout.addWidget(self.gui.scan_output_table)

        # Store all output lines for filtering
        self.gui.scan_output_lines = []
        # Also store debug messages for compatibility
        self.gui.debug_messages = []
        self.gui.debug_table = self.gui.scan_output_table  # Alias for compatibility

        return widget

    def _filter_combined_output(self):
        """Filter the combined output table based on search and filter dropdown"""
        if not hasattr(self.gui, 'scan_output_table'):
            return

        search_text = self.gui.scan_output_search.text().lower() if hasattr(self.gui, 'scan_output_search') else ""
        filter_type = self.gui.output_filter_combo.currentText() if hasattr(self.gui, 'output_filter_combo') else "All"

        for row in range(self.gui.scan_output_table.rowCount()):
            show_row = True

            # Get level from column 1
            level_item = self.gui.scan_output_table.item(row, 1)
            level = level_item.text().upper() if level_item else ""

            # Apply filter type
            if filter_type != "All":
                if filter_type == "Errors" and "ERROR" not in level:
                    show_row = False
                elif filter_type == "Warnings" and "WARN" not in level:
                    show_row = False
                elif filter_type == "Info" and level not in ["INFO", "DEBUG"]:
                    show_row = False
                elif filter_type == "Modules" and "MODULE" not in level:
                    show_row = False
                elif filter_type == "Findings" and "FINDING" not in level and "VULN" not in level:
                    show_row = False

            # Apply search filter
            if show_row and search_text:
                match_found = False
                for col in range(self.gui.scan_output_table.columnCount()):
                    item = self.gui.scan_output_table.item(row, col)
                    if item and search_text in item.text().lower():
                        match_found = True
                        break
                show_row = match_found

            self.gui.scan_output_table.setRowHidden(row, not show_row)

    def _clear_combined_output(self):
        """Clear all output from the combined output table"""
        if hasattr(self.gui, 'scan_output_table'):
            self.gui.scan_output_table.setRowCount(0)
        if hasattr(self.gui, 'scan_output_lines'):
            self.gui.scan_output_lines = []
        if hasattr(self.gui, 'debug_messages'):
            self.gui.debug_messages = []
        self._update_combined_output_stats()

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
                border: 2px solid #1f2937;
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
        self.gui.debug_table.setSortingEnabled(True)
        self.gui.debug_table.setMinimumHeight(300)
        self.gui.debug_table.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)

        header = self.gui.debug_table.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.Interactive)
        header.resizeSection(0, 60)
        header.setSectionResizeMode(1, QHeaderView.Interactive)
        header.resizeSection(1, 80)
        header.setSectionResizeMode(2, QHeaderView.Interactive)
        header.resizeSection(2, 150)
        header.setSectionResizeMode(3, QHeaderView.Stretch)

        self.gui.debug_table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.gui.debug_table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.gui.debug_table.setAlternatingRowColors(True)
        self.gui.debug_table.setFont(QFont("Consolas", 9))
        self.gui.debug_table.setStyleSheet("""
            QTableWidget {
                background-color: #ffffff;
                color: #6b7280;
                gridline-color: #d1d5db;
                border: 2px solid #d1d5db;
                border-radius: 6px;
            }
            QHeaderView::section {
                background: #f3f4f6;
                color: #6366f1;
                padding: 8px;
                border: none;
                border-bottom: 2px solid #6366f1;
                font-weight: bold;
            }
            QTableWidget::item {
                padding: 4px;
            }
            QTableWidget::item:selected {
                background-color: #d1d5db;
                color: #1f2937;
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
                border: 2px solid #1f2937;
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
        self.gui.site_tree.setMinimumHeight(300)
        self.gui.site_tree.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)
        self.gui.site_tree.setAlternatingRowColors(True)
        self.gui.site_tree.setAnimated(True)
        self.gui.site_tree.setExpandsOnDoubleClick(True)
        self.gui.site_tree.setStyleSheet("""
            QTreeWidget {
                background-color: #ffffff;
                color: #1f2937;
                border: 2px solid #d1d5db;
                border-radius: 6px;
                font-family: 'Consolas', 'Courier New', monospace;
                font-size: 10pt;
            }
            QTreeWidget::item {
                padding: 4px;
                border-bottom: 1px solid #e5e7eb;
            }
            QTreeWidget::item:selected {
                background-color: #d1d5db;
                color: #ffffff;
            }
            QTreeWidget::item:hover {
                background-color: #f3f4f6;
            }
            QHeaderView::section {
                background-color: #6366f1;
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

    def _create_target_profile_tab(self):
        """Create the Target Profile tab showing pre-scan intelligence"""
        from GUI.components.target_profile_panel import TargetProfilePanel

        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(10, 10, 10, 10)
        layout.setSpacing(10)

        # Header with title and controls
        header_layout = QHBoxLayout()

        title_label = QLabel("🎯 Target Intelligence Profile")
        title_label.setFont(QFont("Segoe UI", 14, QFont.Bold))
        title_label.setStyleSheet("color: #4CAF50;")
        header_layout.addWidget(title_label)

        header_layout.addStretch()

        # Refresh button
        refresh_btn = QPushButton("🔄 Refresh Profile")
        refresh_btn.setStyleSheet("""
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
        refresh_btn.clicked.connect(self._refresh_target_profile)
        header_layout.addWidget(refresh_btn)

        # Clear button
        clear_btn = QPushButton("🗑️ Clear")
        clear_btn.setStyleSheet("""
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
        clear_btn.clicked.connect(self._clear_target_profile)
        header_layout.addWidget(clear_btn)

        layout.addLayout(header_layout)

        # Info banner
        info_frame = QFrame()
        info_frame.setStyleSheet("""
            QFrame {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
                    stop:0 #2196F3, stop:1 #4CAF50);
                border-radius: 8px;
                padding: 10px;
            }
            QLabel {
                color: white;
                background: transparent;
            }
        """)
        info_layout = QHBoxLayout(info_frame)

        info_text = QLabel(
            "📊 Pre-scan intelligence about your target including technology stack, "
            "WAF detection, security headers, SSL info, and geolocation."
        )
        info_text.setFont(QFont("Segoe UI", 10))
        info_text.setWordWrap(True)
        info_layout.addWidget(info_text)

        layout.addWidget(info_frame)

        # Target Profile Panel
        self.gui.target_profile_panel = TargetProfilePanel()
        layout.addWidget(self.gui.target_profile_panel)

        # Store profile data
        self.gui.current_target_profile = None

        return widget

    def _refresh_target_profile(self):
        """Refresh the target profile by re-running profiling"""
        if not hasattr(self.gui, 'target_input'):
            return

        target = self.gui.target_input.toPlainText().strip().split('\n')[0]
        if not target:
            QMessageBox.warning(self.gui, "No Target",
                "Please enter a target URL in the Scan Config tab first.")
            return

        # Run profiling in background
        from threading import Thread

        def run_profile():
            try:
                from core.target_profiler import TargetProfiler
                from core.http_client import HTTPClient

                http_client = HTTPClient(timeout=15)
                profiler = TargetProfiler(http_client)
                profile = profiler.profile(target)

                # Update GUI in main thread
                from PyQt5.QtCore import QMetaObject, Qt, Q_ARG

                if hasattr(self.gui, 'target_profile_panel'):
                    self.gui.current_target_profile = profile.to_dict()
                    self.gui.target_profile_panel.update_profile(profile.to_dict())

            except Exception as e:
                print(f"Profile refresh error: {e}")

        thread = Thread(target=run_profile, daemon=True)
        thread.start()

    def _clear_target_profile(self):
        """Clear the target profile panel"""
        if hasattr(self.gui, 'target_profile_panel'):
            self.gui.target_profile_panel.clear()
        self.gui.current_target_profile = None

    def update_target_profile(self, profile_dict):
        """Update the target profile panel with new data"""
        if hasattr(self.gui, 'target_profile_panel'):
            self.gui.current_target_profile = profile_dict
            self.gui.target_profile_panel.update_profile(profile_dict)

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
                item.setForeground(0, QColor('#1f2937'))

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
                from GUI.dominator_gui import DominatorGUI
                self.gui.target_input.setText(url)
                self.gui.tabs.setCurrentIndex(DominatorGUI.TAB_SCAN_CONFIG)
                QMessageBox.information(self.gui, "Target Set",
                    f"Target URL set to:\n{url}\n\nClick 'Start' to begin scanning.")

    def _apply_filters(self):
        """Apply all filters to results table"""
        if not hasattr(self.gui, 'results_table'):
            return

        severity_filter = self.gui.severity_filter.currentText().upper()
        module_filter = self.gui.module_filter.currentText()
        target_filter = self.gui.target_filter.currentText()
        status_filter = self.gui.status_filter.currentText() if hasattr(self.gui, 'status_filter') else "All"
        extension_filter = self.gui.extension_filter.currentText() if hasattr(self.gui, 'extension_filter') else "All"
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

            # Check status code filter (column 7)
            if show_row and status_filter != "All":
                status_item = self.gui.results_table.item(row, 7)
                if status_item:
                    status_text = status_item.text()
                    if status_filter.endswith("xx"):
                        # Check status range (e.g., 2xx, 4xx)
                        prefix = status_filter[0]
                        if not status_text.startswith(prefix):
                            show_row = False
                    else:
                        # Exact status code match
                        if status_text != status_filter:
                            show_row = False
                else:
                    # No status code - hide if specific filter selected
                    show_row = False

            # Check extension filter (from URL column 4)
            if show_row and extension_filter != "All":
                url_item = self.gui.results_table.item(row, 4)
                if url_item:
                    url_text = url_item.text().lower()
                    # Extract path from URL (remove query string)
                    path = url_text.split('?')[0]
                    if extension_filter == "No ext":
                        # Check for no extension
                        if '.' in path.split('/')[-1]:
                            show_row = False
                    else:
                        # Check for specific extension
                        if not path.endswith(extension_filter.lower()):
                            show_row = False
                else:
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
        if hasattr(self.gui, 'status_filter'):
            self.gui.status_filter.setCurrentIndex(0)
        if hasattr(self.gui, 'extension_filter'):
            self.gui.extension_filter.setCurrentIndex(0)
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
        try:
            self._show_full_details()
        except Exception as e:
            # Log error to debug file
            from pathlib import Path
            from datetime import datetime
            log_file = Path(__file__).parent.parent.parent / "gui_debug.log"
            try:
                with open(log_file, 'a', encoding='utf-8') as f:
                    f.write(f"[{datetime.now().strftime('%H:%M:%S')}] ERROR in _on_row_double_clicked: {e}\n")
                    import traceback
                    f.write(traceback.format_exc() + "\n")
            except:
                pass

    def _on_row_clicked(self, index):
        """Handle single-click on a row - updates detail panel and enables 'View Details' button"""
        # The selection change handler already updates the detail panel
        # This just ensures the "View Details" button is enabled
        if hasattr(self.gui, 'view_details_btn'):
            self.gui.view_details_btn.setEnabled(True)

    def _on_selection_changed(self):
        """Handle selection change to update detail panel with ALL data"""
        try:
            # Early exit if table doesn't exist or is not properly initialized
            if not hasattr(self.gui, 'results_table') or self.gui.results_table is None:
                return

            selected = self.gui.results_table.selectedItems()
            if not selected:
                return

            row = selected[0].row()

            # Validate row is within bounds
            if row < 0 or row >= self.gui.results_table.rowCount():
                return

            # Get finding data from row (column order: #, Severity, Module, Title, URL, Parameter, Payload, Status, CVSS, Time)
            severity = self.gui.results_table.item(row, 1).text() if self.gui.results_table.item(row, 1) else "INFO"
            module = self.gui.results_table.item(row, 2).text() if self.gui.results_table.item(row, 2) else "-"
            title = self.gui.results_table.item(row, 3).text() if self.gui.results_table.item(row, 3) else "-"
            target = self.gui.results_table.item(row, 4).text() if self.gui.results_table.item(row, 4) else "-"
            parameter = self.gui.results_table.item(row, 5).text() if self.gui.results_table.item(row, 5) else "-"
            payload = self.gui.results_table.item(row, 6).text() if self.gui.results_table.item(row, 6) else "-"
            status_code = self.gui.results_table.item(row, 7).text() if self.gui.results_table.item(row, 7) else "-"
            cvss_display = self.gui.results_table.item(row, 8).text() if self.gui.results_table.item(row, 8) else "-"
            time = self.gui.results_table.item(row, 9).text() if self.gui.results_table.item(row, 9) else "-"

            # Update severity badge - check if widget exists
            if not hasattr(self.gui, 'detail_severity') or self.gui.detail_severity is None:
                return

            self.gui.detail_severity.setText(f"⚠️  {severity}  ⚠️")
            color = SEVERITY_COLORS.get(severity.upper(), '#888888')
            self.gui.detail_severity.setStyleSheet(f"""
                background-color: {color};
                color: white;
                padding: 15px;
                border-radius: 8px;
                font-weight: bold;
                font-size: 16px;
            """)

            # Update basic info
            if hasattr(self.gui, 'detail_title'):
                self.gui.detail_title.setText(title)
            if hasattr(self.gui, 'detail_module'):
                self.gui.detail_module.setText(module)
            if hasattr(self.gui, 'detail_target'):
                self.gui.detail_target.setText(target)
            if hasattr(self.gui, 'detail_parameter'):
                self.gui.detail_parameter.setText(parameter)
            if hasattr(self.gui, 'detail_time'):
                self.gui.detail_time.setText(time)

            # Get stored finding data for extended info
            finding_data = self.gui.results_table.item(row, 0).data(Qt.UserRole) if self.gui.results_table.item(row, 0) else {}
            data = finding_data or {}

            # Classification
            cvss = data.get('cvss', cvss_display)
            cwe = data.get('cwe', 'N/A')
            cwe_name = data.get('cwe_name', '')
            owasp = data.get('owasp', 'N/A')
            owasp_name = data.get('owasp_name', '')

            if hasattr(self.gui, 'detail_cvss'):
                self.gui.detail_cvss.setText(f"{cvss}/10" if cvss and cvss != '-' else "-")
            if hasattr(self.gui, 'detail_cwe'):
                self.gui.detail_cwe.setText(f"{cwe}" + (f" - {cwe_name}" if cwe_name else ""))
            if hasattr(self.gui, 'detail_owasp'):
                self.gui.detail_owasp.setText(f"{owasp}" + (f" - {owasp_name}" if owasp_name else ""))

            # Payload - get from stored data (may be longer than displayed)
            full_payload = data.get('payload', payload)
            if hasattr(self.gui, 'detail_payload'):
                self.gui.detail_payload.setPlainText(full_payload if full_payload else "No payload")

            # Evidence
            evidence = data.get('evidence', '')
            if hasattr(self.gui, 'detail_evidence'):
                self.gui.detail_evidence.setPlainText(evidence if evidence else "No evidence captured")

            # Description
            description = data.get('description', title)
            if hasattr(self.gui, 'detail_description'):
                self.gui.detail_description.setPlainText(description if description else "No description available")

            # Remediation
            remediation = data.get('remediation', '')
            if hasattr(self.gui, 'detail_remediation'):
                self.gui.detail_remediation.setPlainText(remediation if remediation else "No remediation advice available")

            # HTTP Request
            request = data.get('request', '')
            if hasattr(self.gui, 'detail_request'):
                self.gui.detail_request.setPlainText(request if request else "No request data available")

            # HTTP Response
            response = data.get('response', '')
            if hasattr(self.gui, 'detail_response'):
                # Truncate response for display if too long
                if len(response) > 2000:
                    response = response[:2000] + "\n\n... [Response truncated, view full details for complete response]"
                self.gui.detail_response.setPlainText(response if response else "No response data available")

        except Exception as e:
            # Log error to debug file
            from pathlib import Path
            from datetime import datetime
            log_file = Path(__file__).parent.parent.parent / "gui_debug.log"
            try:
                with open(log_file, 'a', encoding='utf-8') as f:
                    f.write(f"[{datetime.now().strftime('%H:%M:%S')}] ERROR in _on_selection_changed: {e}\n")
                    import traceback
                    f.write(traceback.format_exc() + "\n")
            except:
                pass

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
        try:
            # Early exit if table doesn't exist or is not properly initialized
            if not hasattr(self.gui, 'results_table') or self.gui.results_table is None:
                return

            selected = self.gui.results_table.selectedItems()
            if not selected:
                QMessageBox.information(self.gui, "No Selection", "Please select a finding to view details")
                return

            row = selected[0].row()

            # Validate row is within bounds
            if row < 0 or row >= self.gui.results_table.rowCount():
                return

            # Get finding data
            finding_data = self.gui.results_table.item(row, 0).data(Qt.UserRole) if self.gui.results_table.item(row, 0) else {}

            # If no stored data, create from table (column order: #, Severity, Module, Title, URL, Parameter, Payload, Status, CVSS, Time)
            if not finding_data:
                finding_data = {
                    'severity': self.gui.results_table.item(row, 1).text() if self.gui.results_table.item(row, 1) else "INFO",
                    'module': self.gui.results_table.item(row, 2).text() if self.gui.results_table.item(row, 2) else "-",
                    'title': self.gui.results_table.item(row, 3).text() if self.gui.results_table.item(row, 3) else "-",
                    'target': self.gui.results_table.item(row, 4).text() if self.gui.results_table.item(row, 4) else "-",
                    'parameter': self.gui.results_table.item(row, 5).text() if self.gui.results_table.item(row, 5) else "-",
                    'payload': self.gui.results_table.item(row, 6).text() if self.gui.results_table.item(row, 6) else "-",
                    'status_code': self.gui.results_table.item(row, 7).text() if self.gui.results_table.item(row, 7) else "-",
                    'cvss': self.gui.results_table.item(row, 8).text() if self.gui.results_table.item(row, 8) else "-",
                    'time': self.gui.results_table.item(row, 9).text() if self.gui.results_table.item(row, 9) else "-",
                }

            dialog = FindingDetailDialog(finding_data, self.gui)
            dialog.exec_()
        except Exception as e:
            # Log error to debug file
            from pathlib import Path
            from datetime import datetime
            log_file = Path(__file__).parent.parent.parent / "gui_debug.log"
            try:
                with open(log_file, 'a', encoding='utf-8') as f:
                    f.write(f"[{datetime.now().strftime('%H:%M:%S')}] ERROR in _show_full_details: {e}\n")
                    import traceback
                    f.write(traceback.format_exc() + "\n")
            except:
                pass
            QMessageBox.critical(self.gui, "Error", f"Error showing details: {str(e)}")

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

        # Generate HTML with professional dark theme
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        html = f"""<!DOCTYPE html>
<html>
<head>
    <title>Dominator Live Report - {timestamp}</title>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <style>
        * {{ box-sizing: border-box; margin: 0; padding: 0; }}
        body {{
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #ffffff 0%, #16213e 100%);
            color: #1f2937;
            min-height: 100vh;
            padding: 30px;
        }}
        .container {{ max-width: 1400px; margin: 0 auto; }}

        /* Header */
        .header {{
            background: linear-gradient(135deg, #6366f1 0%, #8b5cf6 100%);
            padding: 30px;
            border-radius: 16px;
            margin-bottom: 30px;
            box-shadow: 0 10px 40px rgba(99, 102, 241, 0.3);
        }}
        .header h1 {{
            font-size: 2.5em;
            margin-bottom: 10px;
            display: flex;
            align-items: center;
            gap: 15px;
        }}
        .header .subtitle {{
            opacity: 0.9;
            font-size: 1.1em;
        }}
        .live-badge {{
            background: #22c55e;
            color: white;
            padding: 6px 16px;
            border-radius: 20px;
            font-size: 14px;
            font-weight: bold;
            animation: pulse 2s infinite;
        }}
        @keyframes pulse {{
            0%, 100% {{ opacity: 1; }}
            50% {{ opacity: 0.7; }}
        }}

        /* Stats Grid */
        .stats {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }}
        .stat-card {{
            background: linear-gradient(135deg, #f3f4f6 0%, #1e1e35 100%);
            padding: 25px;
            border-radius: 12px;
            text-align: center;
            border: 1px solid #d1d5db;
            transition: transform 0.3s, box-shadow 0.3s;
        }}
        .stat-card:hover {{
            transform: translateY(-5px);
            box-shadow: 0 10px 30px rgba(0,0,0,0.3);
        }}
        .stat-card .number {{
            font-size: 3em;
            font-weight: bold;
            line-height: 1;
        }}
        .stat-card .label {{
            font-size: 0.9em;
            opacity: 0.8;
            margin-top: 8px;
            text-transform: uppercase;
            letter-spacing: 1px;
        }}
        .stat-card.total .number {{ color: #60a5fa; }}
        .stat-card.critical .number {{ color: #ef4444; }}
        .stat-card.high .number {{ color: #f97316; }}
        .stat-card.medium .number {{ color: #eab308; }}
        .stat-card.low .number {{ color: #22c55e; }}
        .stat-card.info .number {{ color: #3b82f6; }}

        /* Findings Section */
        .section-title {{
            font-size: 1.5em;
            margin: 30px 0 20px 0;
            padding-bottom: 10px;
            border-bottom: 2px solid #6366f1;
            display: flex;
            align-items: center;
            gap: 10px;
        }}

        /* Finding Cards */
        .finding {{
            background: linear-gradient(135deg, #f3f4f6 0%, #1e1e35 100%);
            padding: 20px;
            margin-bottom: 15px;
            border-radius: 12px;
            border-left: 5px solid #d1d5db;
            transition: transform 0.2s, box-shadow 0.2s;
        }}
        .finding:hover {{
            transform: translateX(5px);
            box-shadow: 0 5px 20px rgba(0,0,0,0.2);
        }}
        .finding.critical {{ border-left-color: #ef4444; }}
        .finding.high {{ border-left-color: #f97316; }}
        .finding.medium {{ border-left-color: #eab308; }}
        .finding.low {{ border-left-color: #22c55e; }}
        .finding.info {{ border-left-color: #3b82f6; }}

        .finding .title {{
            font-size: 1.2em;
            font-weight: bold;
            margin-bottom: 10px;
            display: flex;
            align-items: center;
            gap: 10px;
        }}
        .severity-badge {{
            padding: 4px 12px;
            border-radius: 6px;
            font-size: 0.75em;
            font-weight: bold;
            text-transform: uppercase;
        }}
        .severity-badge.critical {{ background: #ef4444; color: white; }}
        .severity-badge.high {{ background: #f97316; color: white; }}
        .severity-badge.medium {{ background: #eab308; color: #000; }}
        .severity-badge.low {{ background: #22c55e; color: white; }}
        .severity-badge.info {{ background: #3b82f6; color: white; }}

        .finding .meta {{
            display: flex;
            flex-wrap: wrap;
            gap: 20px;
            font-size: 0.9em;
            opacity: 0.8;
            margin-bottom: 15px;
        }}
        .finding .meta-item {{
            display: flex;
            align-items: center;
            gap: 6px;
        }}
        .finding .meta a {{
            color: #60a5fa;
            text-decoration: none;
        }}
        .finding .meta a:hover {{ text-decoration: underline; }}

        /* Details Grid */
        .details-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 15px;
            margin-top: 15px;
        }}
        .detail-item {{
            background: #ffffff;
            padding: 12px;
            border-radius: 8px;
            border: 1px solid #d1d5db;
        }}
        .detail-item .label {{
            font-size: 0.8em;
            color: #6b7280;
            text-transform: uppercase;
            letter-spacing: 0.5px;
            margin-bottom: 5px;
        }}
        .detail-item .value {{
            font-family: 'Consolas', 'Monaco', monospace;
            word-break: break-all;
        }}
        .detail-item .value.param {{ color: #fbbf24; }}
        .detail-item .value.payload {{ color: #f87171; }}
        .detail-item .value.cvss {{ color: #22c55e; font-size: 1.3em; font-weight: bold; }}
        .detail-item .value.cwe {{ color: #a78bfa; }}
        .detail-item .value.owasp {{ color: #fb923c; }}

        /* Collapsible Sections */
        details {{
            margin-top: 10px;
            background: #ffffff;
            border-radius: 8px;
            border: 1px solid #d1d5db;
        }}
        summary {{
            padding: 12px;
            cursor: pointer;
            font-weight: bold;
            color: #60a5fa;
            user-select: none;
        }}
        summary:hover {{ background: rgba(99, 102, 241, 0.1); border-radius: 8px 8px 0 0; }}
        details[open] summary {{ border-bottom: 1px solid #d1d5db; }}

        pre {{
            background: #0f0f1a;
            color: #aed581;
            padding: 15px;
            border-radius: 0 0 8px 8px;
            overflow-x: auto;
            font-size: 12px;
            max-height: 300px;
            margin: 0;
        }}

        /* Footer */
        .footer {{
            text-align: center;
            margin-top: 50px;
            padding: 20px;
            opacity: 0.6;
            font-size: 0.9em;
        }}

        /* Print Styles */
        @media print {{
            body {{ background: white; color: black; }}
            .finding {{ page-break-inside: avoid; }}
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>
                <span>DOMINATOR</span>
                <span class="live-badge">LIVE</span>
            </h1>
            <p class="subtitle">Web Vulnerability Scan Report - Generated: {timestamp}</p>
        </div>

        <div class="stats">
            <div class="stat-card total">
                <div class="number">{len(findings)}</div>
                <div class="label">Total Findings</div>
            </div>
            <div class="stat-card critical">
                <div class="number">{severity_counts['CRITICAL']}</div>
                <div class="label">Critical</div>
            </div>
            <div class="stat-card high">
                <div class="number">{severity_counts['HIGH']}</div>
                <div class="label">High</div>
            </div>
            <div class="stat-card medium">
                <div class="number">{severity_counts['MEDIUM']}</div>
                <div class="label">Medium</div>
            </div>
            <div class="stat-card low">
                <div class="number">{severity_counts['LOW']}</div>
                <div class="label">Low</div>
            </div>
            <div class="stat-card info">
                <div class="number">{severity_counts['INFO']}</div>
                <div class="label">Info</div>
            </div>
        </div>
"""

        # Add Target Profile section if available
        if hasattr(self.gui, 'current_target_profile') and self.gui.current_target_profile:
            profile = self.gui.current_target_profile
            profile_html = """
        <h2 class="section-title">🎯 Target Profile</h2>
        <div class="finding" style="border-left-color: #6366f1;">
            <div class="details-grid">
"""
            if profile.get('url'):
                profile_html += f'''
                <div class="detail-item">
                    <div class="label">Target URL</div>
                    <div class="value" style="color: #60a5fa;">{profile.get('url')}</div>
                </div>'''
            if profile.get('ip_address'):
                profile_html += f'''
                <div class="detail-item">
                    <div class="label">IP Address</div>
                    <div class="value">{profile.get('ip_address')}</div>
                </div>'''
            if profile.get('web_server'):
                profile_html += f'''
                <div class="detail-item">
                    <div class="label">Web Server</div>
                    <div class="value" style="color: #22c55e;">{profile.get('web_server')}</div>
                </div>'''
            if profile.get('programming_language'):
                profile_html += f'''
                <div class="detail-item">
                    <div class="label">Language</div>
                    <div class="value" style="color: #a78bfa;">{profile.get('programming_language')}</div>
                </div>'''
            if profile.get('framework'):
                profile_html += f'''
                <div class="detail-item">
                    <div class="label">Framework</div>
                    <div class="value" style="color: #fb923c;">{profile.get('framework')}</div>
                </div>'''
            if profile.get('cms'):
                profile_html += f'''
                <div class="detail-item">
                    <div class="label">CMS</div>
                    <div class="value" style="color: #ec4899;">{profile.get('cms')}</div>
                </div>'''
            if profile.get('waf_detected'):
                profile_html += f'''
                <div class="detail-item">
                    <div class="label">WAF Detected</div>
                    <div class="value" style="color: #ef4444; font-weight: bold;">⚠️ {profile.get('waf_detected')}</div>
                </div>'''
            if profile.get('country'):
                profile_html += f'''
                <div class="detail-item">
                    <div class="label">Country</div>
                    <div class="value">{profile.get('country')} ({profile.get('country_code', '')})</div>
                </div>'''
            if profile.get('ssl_enabled'):
                ssl_grade = profile.get('ssl_grade', 'N/A')
                grade_color = '#22c55e' if ssl_grade in ['A+', 'A'] else '#eab308' if ssl_grade in ['B', 'C'] else '#ef4444'
                profile_html += f'''
                <div class="detail-item">
                    <div class="label">SSL/TLS</div>
                    <div class="value" style="color: {grade_color};">Grade: {ssl_grade}</div>
                </div>'''
            missing_headers = profile.get('missing_security_headers', [])
            if missing_headers:
                profile_html += f'''
                <div class="detail-item">
                    <div class="label">Missing Headers</div>
                    <div class="value" style="color: #f97316;">{', '.join(missing_headers[:5])}</div>
                </div>'''

            profile_html += """
            </div>
        </div>
"""
            html += profile_html

        html += """
        <h2 class="section-title">🔍 Vulnerability Findings</h2>
"""

        # Add findings with full details - grouped by severity
        severity_order = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']
        for sev_level in severity_order:
            sev_findings = [f for f in findings if f.get('severity', '').upper() == sev_level]
            if not sev_findings:
                continue

            for f in sev_findings:
                sev = f.get('severity', '').lower()

                # Build details grid
                details_html = '<div class="details-grid">'

                if f.get('parameter'):
                    details_html += f'''
                    <div class="detail-item">
                        <div class="label">Parameter</div>
                        <div class="value param">{f.get('parameter')}</div>
                    </div>'''

                if f.get('payload'):
                    payload = str(f.get('payload', ''))
                    payload_display = payload[:100] + '...' if len(payload) > 100 else payload
                    details_html += f'''
                    <div class="detail-item">
                        <div class="label">Payload</div>
                        <div class="value payload" title="{payload}">{payload_display}</div>
                    </div>'''

                if f.get('cvss'):
                    details_html += f'''
                    <div class="detail-item">
                        <div class="label">CVSS Score</div>
                        <div class="value cvss">{f.get('cvss')}/10</div>
                    </div>'''

                if f.get('cwe'):
                    cwe_name = f.get('cwe_name', '')
                    details_html += f'''
                    <div class="detail-item">
                        <div class="label">CWE</div>
                        <div class="value cwe">{f.get('cwe')}{' - ' + cwe_name if cwe_name else ''}</div>
                    </div>'''

                if f.get('owasp'):
                    owasp_name = f.get('owasp_name', '')
                    details_html += f'''
                    <div class="detail-item">
                        <div class="label">OWASP</div>
                        <div class="value owasp">{f.get('owasp')}{' - ' + owasp_name if owasp_name else ''}</div>
                    </div>'''

                if f.get('cvss_vector'):
                    details_html += f'''
                    <div class="detail-item">
                        <div class="label">CVSS Vector</div>
                        <div class="value" style="font-size: 0.85em; color: #9ca3af;">{f.get('cvss_vector')}</div>
                    </div>'''

                if f.get('method'):
                    details_html += f'''
                    <div class="detail-item">
                        <div class="label">HTTP Method</div>
                        <div class="value" style="color: #818cf8;">{f.get('method')}</div>
                    </div>'''

                if f.get('confidence'):
                    conf = f.get('confidence', '')
                    conf_color = '#22c55e' if conf.lower() == 'high' else '#eab308' if conf.lower() == 'medium' else '#94a3b8'
                    details_html += f'''
                    <div class="detail-item">
                        <div class="label">Confidence</div>
                        <div class="value" style="color: {conf_color}; font-weight: bold;">{conf}</div>
                    </div>'''

                details_html += '</div>'

                # Description section (full vulnerability description)
                if f.get('description'):
                    details_html += f'''
                    <details open>
                        <summary>📝 Description</summary>
                        <pre style="color: #e2e8f0; white-space: pre-wrap;">{f.get('description')}</pre>
                    </details>'''

                # Evidence section
                if f.get('evidence'):
                    evidence = str(f.get('evidence', ''))[:500]
                    details_html += f'''
                    <details>
                        <summary>Evidence</summary>
                        <pre>{evidence}</pre>
                    </details>'''

                # Request/Response
                if f.get('request'):
                    req = str(f.get('request', ''))[:1000]
                    details_html += f'''
                    <details>
                        <summary>HTTP Request</summary>
                        <pre>{req}</pre>
                    </details>'''

                if f.get('response'):
                    resp = str(f.get('response', ''))[:1000]
                    details_html += f'''
                    <details>
                        <summary>HTTP Response</summary>
                        <pre>{resp}</pre>
                    </details>'''

                # Remediation
                if f.get('remediation'):
                    details_html += f'''
                    <details>
                        <summary>🛡️ Remediation</summary>
                        <pre style="color: #22c55e; white-space: pre-wrap;">{f.get('remediation')}</pre>
                    </details>'''

                # References
                refs = f.get('references', [])
                if refs:
                    if isinstance(refs, str):
                        refs = [refs]
                    refs_html = '<ul style="margin: 10px; padding-left: 20px;">'
                    for ref in refs[:10]:  # Limit to 10 references
                        refs_html += f'<li><a href="{ref}" target="_blank" style="color: #60a5fa;">{ref}</a></li>'
                    refs_html += '</ul>'
                    details_html += f'''
                    <details>
                        <summary>📚 References</summary>
                        <div style="background: #0f0f1a; padding: 10px; border-radius: 0 0 8px 8px;">
                            {refs_html}
                        </div>
                    </details>'''

                # Impact
                if f.get('impact'):
                    details_html += f'''
                    <details>
                        <summary>💥 Impact</summary>
                        <pre style="color: #f97316; white-space: pre-wrap;">{f.get('impact')}</pre>
                    </details>'''

                html += f'''
        <div class="finding {sev}">
            <div class="title">
                <span class="severity-badge {sev}">{f.get('severity', 'N/A')}</span>
                <span>{f.get('title', 'N/A')}</span>
            </div>
            <div class="meta">
                <span class="meta-item"><strong>Module:</strong> {f.get('module', 'N/A')}</span>
                <span class="meta-item"><strong>Target:</strong> <a href="{f.get('target', '#')}" target="_blank">{f.get('target', 'N/A')}</a></span>
                <span class="meta-item"><strong>Time:</strong> {f.get('time', 'N/A')}</span>
            </div>
            {details_html}
        </div>
'''

        html += """
        <div class="footer">
            <p>Generated by Dominator Web Vulnerability Scanner</p>
            <p>https://github.com/dominator-scanner</p>
        </div>
    </div>
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
        """Get finding data from a table row (9-column structure)

        Extracts all available data including stored full finding data from Qt.UserRole.
        This ensures live reports contain all fields: evidence, request, response,
        remediation, CWE, OWASP, description, references, etc.
        """
        # Columns: 0=#, 1=Severity, 2=Module, 3=Vulnerability, 4=URL, 5=Parameter, 6=Payload, 7=CVSS, 8=Time
        finding = {
            'id': self.gui.results_table.item(row, 0).text() if self.gui.results_table.item(row, 0) else "",
            'severity': self.gui.results_table.item(row, 1).text() if self.gui.results_table.item(row, 1) else "",
            'module': self.gui.results_table.item(row, 2).text() if self.gui.results_table.item(row, 2) else "",
            'title': self.gui.results_table.item(row, 3).text() if self.gui.results_table.item(row, 3) else "",
            'target': self.gui.results_table.item(row, 4).text() if self.gui.results_table.item(row, 4) else "",
            'parameter': self.gui.results_table.item(row, 5).text() if self.gui.results_table.item(row, 5) else "",
            'payload': self.gui.results_table.item(row, 6).text() if self.gui.results_table.item(row, 6) else "",
            'cvss': self.gui.results_table.item(row, 7).text() if self.gui.results_table.item(row, 7) else "",
            'time': self.gui.results_table.item(row, 8).text() if self.gui.results_table.item(row, 8) else "",
        }

        # Add stored data if available (contains full payload, evidence, CWE, OWASP, etc.)
        stored_data = self.gui.results_table.item(row, 0).data(Qt.UserRole) if self.gui.results_table.item(row, 0) else {}
        if stored_data and isinstance(stored_data, dict):
            # Merge stored data, preserving existing values if stored ones are empty
            for key, value in stored_data.items():
                if value and (key not in finding or not finding.get(key)):
                    finding[key] = value
                elif value and key not in finding:
                    finding[key] = value

            # Ensure all important fields are extracted from stored data
            important_fields = [
                'description', 'evidence', 'request', 'response', 'remediation',
                'cwe', 'cwe_name', 'owasp', 'owasp_name', 'cvss_vector',
                'references', 'confidence', 'method', 'type', 'category',
                'impact', 'likelihood', 'risk_rating', 'false_positive',
                'verified', 'tags', 'screenshots', 'raw_response'
            ]
            for field in important_fields:
                if field in stored_data and stored_data[field]:
                    finding[field] = stored_data[field]

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
        """Add a line to the combined scan output table with color coding and level detection"""
        if not hasattr(self.gui, 'scan_output_table'):
            return

        # Parse the line to extract level, source/module, and message
        level = "INFO"
        source = ""
        message = line_text.strip()

        # Skip empty lines
        if not message:
            return

        # Detect log level from line content
        msg_upper = message.upper()
        if "[ERROR]" in msg_upper or "[CRITICAL]" in msg_upper or "ERROR:" in msg_upper[:30] or "FAILED" in msg_upper[:30]:
            level = "ERROR"
        elif "[WARNING]" in msg_upper or "[WARN]" in msg_upper or "WARNING:" in msg_upper[:30]:
            level = "WARNING"
        elif "VULNERABILITY" in msg_upper or "VULN" in msg_upper[:20] or "[HIGH]" in msg_upper or "[CRITICAL]" in msg_upper or "[MEDIUM]" in msg_upper:
            level = "FINDING"
        elif "Running module:" in message:
            level = "MODULE"
        elif "Module" in message and "completed" in message:
            level = "MODULE"
        elif "[INFO]" in msg_upper or "INFO:" in msg_upper[:20]:
            level = "INFO"
        elif "[DEBUG]" in msg_upper or "DEBUG:" in msg_upper[:20]:
            level = "DEBUG"
        elif "[SUCCESS]" in msg_upper or "SUCCESS:" in msg_upper[:20]:
            level = "SUCCESS"

        # Try to extract source/module name
        if "Running module:" in message:
            try:
                source = message.split("Running module:")[-1].strip()
            except:
                pass
        elif "Module '" in message:
            try:
                import re
                match = re.search(r"Module\s*'([^']+)'", message)
                if match:
                    source = match.group(1)
            except:
                pass
        elif "modules." in message.lower():
            try:
                import re
                match = re.search(r'modules\.(\w+)', message, re.IGNORECASE)
                if match:
                    source = match.group(1)
            except:
                pass

        # Store the full line data
        line_data = {
            'line_number': len(self.gui.scan_output_lines) + 1,
            'level': level,
            'source': source,
            'message': message,
            'raw_text': line_text
        }
        self.gui.scan_output_lines.append(line_data)

        # Limit table rows to prevent memory issues (keep last 5000 lines)
        max_rows = 5000
        if self.gui.scan_output_table.rowCount() >= max_rows:
            self.gui.scan_output_table.removeRow(0)

        # Add to table
        row = self.gui.scan_output_table.rowCount()
        self.gui.scan_output_table.insertRow(row)

        # Line number
        line_num_item = QTableWidgetItem(str(line_data['line_number']))
        line_num_item.setFont(QFont("Consolas", 9))
        line_num_item.setForeground(QColor('#94a3b8'))
        self.gui.scan_output_table.setItem(row, 0, line_num_item)

        # Level with color coding
        level_item = QTableWidgetItem(level)
        level_item.setFont(QFont("Consolas", 9, QFont.Bold))
        if level == "ERROR":
            level_item.setBackground(QColor('#ef4444'))
            level_item.setForeground(QColor('white'))
        elif level == "WARNING":
            level_item.setBackground(QColor('#f59e0b'))
            level_item.setForeground(QColor('white'))
        elif level == "FINDING":
            level_item.setBackground(QColor('#8b5cf6'))
            level_item.setForeground(QColor('white'))
        elif level == "MODULE":
            level_item.setBackground(QColor('#3b82f6'))
            level_item.setForeground(QColor('white'))
        elif level == "SUCCESS":
            level_item.setBackground(QColor('#22c55e'))
            level_item.setForeground(QColor('white'))
        elif level == "DEBUG":
            level_item.setForeground(QColor('#94a3b8'))
        else:  # INFO
            level_item.setForeground(QColor('#0ea5e9'))
        self.gui.scan_output_table.setItem(row, 1, level_item)

        # Source/Module
        source_item = QTableWidgetItem(source)
        source_item.setFont(QFont("Consolas", 9))
        source_item.setForeground(QColor('#6366f1'))
        self.gui.scan_output_table.setItem(row, 2, source_item)

        # Message
        message_item = QTableWidgetItem(message)
        message_item.setFont(QFont("Consolas", 9))
        # Color message based on level
        if level == "ERROR":
            message_item.setForeground(QColor('#dc2626'))
        elif level == "WARNING":
            message_item.setForeground(QColor('#d97706'))
        elif level == "FINDING":
            message_item.setForeground(QColor('#7c3aed'))
        self.gui.scan_output_table.setItem(row, 3, message_item)

        # Auto-scroll to bottom
        self.gui.scan_output_table.scrollToBottom()

        # Update statistics
        self._update_combined_output_stats()

    def _update_combined_output_stats(self):
        """Update the combined output statistics bar"""
        if not hasattr(self.gui, 'scan_output_lines') or not hasattr(self.gui, 'scan_output_stats'):
            return

        total = len(self.gui.scan_output_lines)
        errors = sum(1 for line in self.gui.scan_output_lines if line['level'] == 'ERROR')
        warnings = sum(1 for line in self.gui.scan_output_lines if line['level'] == 'WARNING')
        modules = sum(1 for line in self.gui.scan_output_lines if line['level'] == 'MODULE')
        findings = sum(1 for line in self.gui.scan_output_lines if line['level'] == 'FINDING')

        self.gui.scan_output_stats.setText(
            f"Lines: {total} | Errors: {errors} | Warnings: {warnings} | Modules: {modules} | Findings: {findings}"
        )

    def _update_scan_output_stats(self):
        """Alias for backwards compatibility"""
        self._update_combined_output_stats()

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
    Add a finding to the results table with clean, essential data

    New Column Structure (6 columns):
    0: Severity - Color-coded severity badge
    1: Vulnerability Type - Module/type of vulnerability
    2: Target URL - The affected URL
    3: Parameter - Vulnerable parameter
    4: Evidence - Short evidence snippet
    5: CVSS - Score if available

    Args:
        gui: The main GUI instance
        severity: Severity level (CRITICAL, HIGH, MEDIUM, LOW, INFO)
        description: Finding title/description
        module: Module that found the vulnerability
        target: Target URL
        finding_data: Additional finding data (dict with cvss, cwe, owasp, parameter, payload, etc.)
    """
    if not hasattr(gui, 'results_table'):
        return

    row = gui.results_table.rowCount()
    gui.results_table.insertRow(row)
    gui.results_table.setRowHeight(row, 40)

    # Extract data from finding_data
    data = finding_data or {}
    parameter = data.get('parameter', '')
    payload = data.get('payload', '')
    cvss = data.get('cvss', '')
    evidence = data.get('evidence', '') or data.get('description', '') or description

    # Create vulnerability type display - combine module and type info
    vuln_type = description or data.get('type', '') or module
    if module and module.lower() not in vuln_type.lower():
        vuln_type = f"{module}: {vuln_type}" if vuln_type else module

    # Truncate evidence for display
    if len(evidence) > 80:
        evidence_display = evidence[:77] + "..."
    else:
        evidence_display = evidence

    # Column 0: Severity with colored background (store full data here)
    severity_upper = severity.upper()
    severity_item = QTableWidgetItem(severity_upper)
    severity_item.setTextAlignment(Qt.AlignCenter)
    severity_item.setData(Qt.UserRole, finding_data)  # Store full data for detail panel
    color = SEVERITY_COLORS.get(severity_upper, '#64748b')
    severity_item.setForeground(QColor('#ffffff'))
    severity_item.setBackground(QColor(color))
    severity_item.setFont(QFont("Segoe UI", 10, QFont.Bold))
    gui.results_table.setItem(row, 0, severity_item)

    # Column 1: Vulnerability Type - purple for visibility
    vuln_item = QTableWidgetItem(vuln_type)
    vuln_item.setFont(QFont("Segoe UI", 10))
    vuln_item.setForeground(QColor('#7c3aed'))
    vuln_item.setToolTip(description or vuln_type)
    gui.results_table.setItem(row, 1, vuln_item)

    # Column 2: Target URL - blue link style
    target_item = QTableWidgetItem(target)
    target_item.setToolTip(target)
    target_item.setForeground(QColor('#2563eb'))
    target_item.setFont(QFont("Segoe UI", 10))
    gui.results_table.setItem(row, 2, target_item)

    # Column 3: Parameter - amber/orange, monospace
    param_display = parameter if parameter else "-"
    param_item = QTableWidgetItem(param_display)
    param_item.setForeground(QColor('#d97706'))
    param_item.setFont(QFont("Consolas", 10))
    if payload:
        param_item.setToolTip(f"Payload: {payload}")
    gui.results_table.setItem(row, 3, param_item)

    # Column 4: Evidence - truncated with full in tooltip
    evidence_item = QTableWidgetItem(evidence_display)
    evidence_item.setForeground(QColor('#475569'))
    evidence_item.setFont(QFont("Segoe UI", 9))
    evidence_item.setToolTip(evidence)  # Full evidence on hover
    gui.results_table.setItem(row, 4, evidence_item)

    # Column 5: CVSS Score with color coding
    cvss_display = str(cvss) if cvss else "-"
    cvss_item = QTableWidgetItem(cvss_display)
    cvss_item.setTextAlignment(Qt.AlignCenter)
    cvss_item.setFont(QFont("Segoe UI", 10, QFont.Bold))
    # Color CVSS based on score
    try:
        cvss_val = float(cvss) if cvss else 0
        if cvss_val >= 9.0:
            cvss_item.setForeground(QColor('#dc2626'))  # Red for Critical
        elif cvss_val >= 7.0:
            cvss_item.setForeground(QColor('#ea580c'))  # Orange for High
        elif cvss_val >= 4.0:
            cvss_item.setForeground(QColor('#ca8a04'))  # Yellow for Medium
        elif cvss_val > 0:
            cvss_item.setForeground(QColor('#16a34a'))  # Green for Low
        else:
            cvss_item.setForeground(QColor('#64748b'))  # Gray for none
    except:
        cvss_item.setForeground(QColor('#64748b'))
    gui.results_table.setItem(row, 5, cvss_item)

    # Update findings count badge
    if hasattr(gui, 'findings_count_label'):
        count = gui.results_table.rowCount()
        gui.findings_count_label.setText(str(count))

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
            sev_item = gui.results_table.item(r, 0)  # Column 0 is now Severity
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
