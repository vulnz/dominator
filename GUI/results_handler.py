#!/usr/bin/env python3
"""
Results Handler - Handles vulnerability results and statistics for Dominator GUI
Extracted from dominator_gui.py to reduce file size
"""

import os
from pathlib import Path

from PyQt5.QtWidgets import QListWidgetItem, QTableWidgetItem, QMessageBox
from PyQt5.QtGui import QColor

from GUI.ui_tabs.results_tab import add_finding_to_table
from GUI.utils.message_box import show_question


class ResultsHandler:
    """Handles vulnerability results display and statistics"""

    def __init__(self, gui):
        """
        Initialize ResultsHandler with GUI instance

        Args:
            gui: DominatorGUI instance
        """
        self.gui = gui
        self.current_report_file = None  # Track current scan's report file

    def add_vulnerability_with_data(self, severity, description, module, target, finding_data):
        """
        Add vulnerability with full finding data (request, response, evidence, remediation)

        This is called when the scanner emits JSON finding data via GUI_FINDING_JSON.

        Args:
            severity: Severity level (CRITICAL, HIGH, MEDIUM, LOW)
            description: Vulnerability description
            module: Module that found the vulnerability
            target: Target URL
            finding_data: Full finding dictionary with all fields
        """
        # Call the regular add_vulnerability with the full finding_data
        self.add_vulnerability(severity, description, module, target, finding_data)

    def add_vulnerability(self, severity, description, module="", target="", finding_data=None):
        """Add vulnerability to the results list and table"""
        # Update counters (thread-safe)
        if hasattr(self.gui, 'increment_vuln_count'):
            self.gui.increment_vuln_count(severity)
        elif severity in self.gui.vuln_counts:
            self.gui.vuln_counts[severity] += 1

        # Update display
        self.update_vuln_display()

        # Update progress tab builder with vulnerability count
        if hasattr(self.gui, 'progress_tab_builder'):
            total_vulns = self.gui.get_total_vulns() if hasattr(self.gui, 'get_total_vulns') else sum(self.gui.vuln_counts.values())
            self.gui.progress_tab_builder.update_dashboard_stats(vulns=total_vulns)

            # Log the finding
            log_level = "error" if severity in ['CRITICAL', 'HIGH'] else "warning"
            short_desc = description[:80] + "..." if len(description) > 80 else description
            self.gui.progress_tab_builder.add_activity_log(f"[{severity}] {short_desc}", log_level)

        # Parse description for module and target if not provided
        # Format might be: "[MODULE] Description - Target URL"
        parsed_module = module
        parsed_target = target
        parsed_description = description

        if not module and '[' in description and ']' in description:
            # Try to extract module from description
            start = description.find('[')
            end = description.find(']')
            if start >= 0 and end > start:
                parsed_module = description[start+1:end]
                parsed_description = description[end+1:].strip()
                if parsed_description.startswith('-'):
                    parsed_description = parsed_description[1:].strip()

        if not target and ' - http' in description:
            # Try to extract target URL
            parts = description.rsplit(' - http', 1)
            if len(parts) == 2:
                parsed_description = parts[0]
                parsed_target = 'http' + parts[1]
        elif not target and ' http' in description:
            # Alternative format
            parts = description.rsplit(' http', 1)
            if len(parts) == 2:
                parsed_target = 'http' + parts[1].split()[0] if parts[1] else ''

        # Add to new results table
        add_finding_to_table(
            self.gui,
            severity,
            parsed_description,
            parsed_module,
            parsed_target,
            finding_data
        )

        # Also add to legacy list for backward compatibility
        color = '#ff0000' if severity == 'CRITICAL' else '#ff8800' if severity == 'HIGH' else '#ffff00'
        item = QListWidgetItem(f"[{severity}] {description}")
        item.setForeground(QColor(color))
        if hasattr(self.gui, 'vulns_list'):
            self.gui.vulns_list.addItem(item)

        # Add to Site Tree with vulnerability info
        if parsed_target and hasattr(self.gui, 'results_tab_builder'):
            vuln_info = {
                'severity': severity,
                'module': parsed_module,
                'description': parsed_description[:50]
            }
            # Extract params from finding_data if available
            params = None
            if finding_data and 'parameter' in finding_data:
                params = [finding_data['parameter']]
            self.gui.results_tab_builder.add_url_to_tree(parsed_target, params, vuln_info)

        # Flash results tab to show new finding
        from GUI.dominator_gui import DominatorGUI
        self.gui.tabs.tabBar().setTabTextColor(DominatorGUI.TAB_RESULTS, QColor('#ff0000'))

    def update_vuln_display(self):
        """Update vulnerability count displays"""
        total = sum(self.gui.vuln_counts.values())
        self.gui.total_vulns_label.setText(f"Total Vulnerabilities: {total}")
        self.gui.critical_label.setText(f"Critical: {self.gui.vuln_counts['CRITICAL']}")
        self.gui.high_label.setText(f"High: {self.gui.vuln_counts['HIGH']}")
        self.gui.medium_label.setText(f"Medium: {self.gui.vuln_counts['MEDIUM']}")

    def update_stats(self, total_vulns, modules_done, modules_total):
        """Update scan statistics"""
        # Update status bar
        self.gui.statusBar().showMessage(f"Scan running... | {modules_done}/{modules_total} modules | {total_vulns} vulnerabilities")

    def set_current_report(self, report_filename):
        """Set the current scan's report file path

        Args:
            report_filename: The filename of the generated report
        """
        parent_dir = Path(__file__).parent.parent
        self.current_report_file = parent_dir / report_filename
        self.gui.output_console.append(f"[+] Report generated: {report_filename}")

    def open_report(self):
        """Open the generated HTML report"""
        import platform
        import subprocess

        # First, try to open the current scan's report
        if self.current_report_file and self.current_report_file.exists():
            report_path = self.current_report_file
        else:
            # Fall back to looking for latest HTML report
            parent_dir = Path(__file__).parent.parent
            reports = list(parent_dir.glob("scan_report_*.html"))

            if not reports:
                self.gui.output_console.append("[!] No reports found")
                return

            # Get latest report
            report_path = max(reports, key=lambda p: p.stat().st_mtime)

        # Open report with default browser (cross-platform)
        try:
            if platform.system() == 'Windows':
                os.startfile(str(report_path))
            elif platform.system() == 'Darwin':  # macOS
                subprocess.run(['open', str(report_path)])
            else:  # Linux
                subprocess.run(['xdg-open', str(report_path)])

            self.gui.output_console.append(f"[*] Opening report: {report_path.name}")
        except Exception as e:
            self.gui.output_console.append(f"[!] Error opening report: {e}")

    def add_resource(self, resource_type, value, extra, source):
        """Add discovered resource to appropriate table"""
        if resource_type == "email":
            # Check if already exists
            for row in range(self.gui.emails_table.rowCount()):
                if self.gui.emails_table.item(row, 0) and self.gui.emails_table.item(row, 0).text() == value:
                    return  # Already added

            row = self.gui.emails_table.rowCount()
            self.gui.emails_table.insertRow(row)
            self.gui.emails_table.setItem(row, 0, QTableWidgetItem(value))
            self.gui.emails_table.setItem(row, 1, QTableWidgetItem(extra))  # Type (Personal/Business)
            self.gui.emails_table.setItem(row, 2, QTableWidgetItem(source))
            self.gui.emails_group.show()  # Show group when data is added

        elif resource_type == "phone":
            # Check if already exists
            for row in range(self.gui.phones_table.rowCount()):
                if self.gui.phones_table.item(row, 0) and self.gui.phones_table.item(row, 0).text() == value:
                    return

            row = self.gui.phones_table.rowCount()
            self.gui.phones_table.insertRow(row)
            self.gui.phones_table.setItem(row, 0, QTableWidgetItem(value))
            self.gui.phones_table.setItem(row, 1, QTableWidgetItem(extra))  # Format
            self.gui.phones_table.setItem(row, 2, QTableWidgetItem(source))
            self.gui.phones_group.show()  # Show group when data is added

        elif resource_type == "social":
            # Check if already exists
            for row in range(self.gui.social_media_table.rowCount()):
                if self.gui.social_media_table.item(row, 1) and self.gui.social_media_table.item(row, 1).text() == value:
                    return

            row = self.gui.social_media_table.rowCount()
            self.gui.social_media_table.insertRow(row)
            self.gui.social_media_table.setItem(row, 0, QTableWidgetItem(extra))  # Platform
            self.gui.social_media_table.setItem(row, 1, QTableWidgetItem(value))  # URL
            self.gui.social_media_table.setItem(row, 2, QTableWidgetItem(source))
            self.gui.social_group.show()  # Show group when data is added

        elif resource_type == "leaked_key":
            # Check if already exists
            for row in range(self.gui.leaked_keys_table.rowCount()):
                if self.gui.leaked_keys_table.item(row, 1) and self.gui.leaked_keys_table.item(row, 1).text() == value:
                    return

            row = self.gui.leaked_keys_table.rowCount()
            self.gui.leaked_keys_table.insertRow(row)

            # Parse extra: "KeyType|Severity"
            parts = extra.split('|')
            key_type = parts[0] if len(parts) > 0 else "Unknown"
            severity = parts[1] if len(parts) > 1 else "HIGH"

            self.gui.leaked_keys_table.setItem(row, 0, QTableWidgetItem(key_type))
            self.gui.leaked_keys_table.setItem(row, 1, QTableWidgetItem(value))

            # Color-code severity
            severity_item = QTableWidgetItem(severity)
            if severity == "CRITICAL":
                severity_item.setForeground(QColor('#ff0000'))
            elif severity == "HIGH":
                severity_item.setForeground(QColor('#ff8800'))
            self.gui.leaked_keys_table.setItem(row, 2, severity_item)

            self.gui.leaked_keys_table.setItem(row, 3, QTableWidgetItem(source))
            self.gui.keys_group.show()  # Show group when data is added

    def add_scope_info(self, info_type, data1, data2, data3):
        """Add scope information (technologies, titles, IPs) to appropriate tables"""
        if info_type == "technology":
            # Check if already exists
            for row in range(self.gui.tech_table.rowCount()):
                if (self.gui.tech_table.item(row, 0) and self.gui.tech_table.item(row, 0).text() == data1 and
                    self.gui.tech_table.item(row, 1) and self.gui.tech_table.item(row, 1).text() == data2):
                    return

            row = self.gui.tech_table.rowCount()
            self.gui.tech_table.insertRow(row)

            # data1 = tech_name, data2 = version, data3 = "category|source"
            parts = data3.split('|', 1)
            category = parts[0] if len(parts) > 0 else "Other"
            source = parts[1] if len(parts) > 1 else ""

            self.gui.tech_table.setItem(row, 0, QTableWidgetItem(data1))  # Technology
            self.gui.tech_table.setItem(row, 1, QTableWidgetItem(data2))  # Version
            self.gui.tech_table.setItem(row, 2, QTableWidgetItem(category))  # Category
            self.gui.tech_table.setItem(row, 3, QTableWidgetItem(source))  # Found On

        elif info_type == "title":
            # Check if already exists - FIXED: Check correct columns (URL is now column 1, Title is column 2)
            for row in range(self.gui.scope_table.rowCount()):
                if (self.gui.scope_table.item(row, 1) and self.gui.scope_table.item(row, 1).text() == data2 and
                    self.gui.scope_table.item(row, 2) and self.gui.scope_table.item(row, 2).text() == data1):
                    return

            row = self.gui.scope_table.rowCount()
            self.gui.scope_table.insertRow(row)

            # data1 = title, data2 = url, data3 = unused
            # FIXED: Correct column mapping - Status, URL, Title, Tech, Findings, Actions
            self.gui.scope_table.setItem(row, 0, QTableWidgetItem("In Scope"))  # Status
            self.gui.scope_table.setItem(row, 1, QTableWidgetItem(data2))  # URL
            self.gui.scope_table.setItem(row, 2, QTableWidgetItem(data1))  # Title
            self.gui.scope_table.setItem(row, 3, QTableWidgetItem(""))  # Technologies (will be updated)
            self.gui.scope_table.setItem(row, 4, QTableWidgetItem("0"))  # Findings count
            self.gui.scope_table.setItem(row, 5, QTableWidgetItem(""))  # Actions (buttons will be added)

            # Add to Site Tree
            if data2 and hasattr(self.gui, 'results_tab_builder'):
                self.gui.results_tab_builder.add_url_to_tree(data2)

        elif info_type == "ip":
            # Check if already exists
            for row in range(self.gui.geo_table.rowCount()):
                if self.gui.geo_table.item(row, 0) and self.gui.geo_table.item(row, 0).text() == data1:
                    return

            row = self.gui.geo_table.rowCount()
            self.gui.geo_table.insertRow(row)

            # data1 = IP, data2 = domain, data3 = source
            # For now, we don't have actual geo lookup, so we'll mark as "Pending"
            self.gui.geo_table.setItem(row, 0, QTableWidgetItem(data1))  # IP
            self.gui.geo_table.setItem(row, 1, QTableWidgetItem("Lookup Pending"))  # Country (placeholder)
            self.gui.geo_table.setItem(row, 2, QTableWidgetItem("-"))  # City (placeholder)
            self.gui.geo_table.setItem(row, 3, QTableWidgetItem("-"))  # ISP (placeholder)
            self.gui.geo_table.setItem(row, 4, QTableWidgetItem(data2))  # Domain

    def clear_results(self):
        """Clear all scan results"""
        reply = show_question(
            self.gui, "Clear Results",
            "Are you sure you want to clear all results?",
            QMessageBox.Yes | QMessageBox.No,
            QMessageBox.No
        )
        if reply == QMessageBox.Yes:
            # Clear legacy list
            if hasattr(self.gui, 'vulns_list'):
                self.gui.vulns_list.clear()

            # Clear new results table
            if hasattr(self.gui, 'results_table'):
                self.gui.results_table.setRowCount(0)

            # Clear filters
            if hasattr(self.gui, 'module_filter'):
                self.gui.module_filter.clear()
                self.gui.module_filter.addItem("All")
            if hasattr(self.gui, 'target_filter'):
                self.gui.target_filter.clear()
                self.gui.target_filter.addItem("All")

            # Clear timeline data
            if hasattr(self.gui, '_timeline_data'):
                self.gui._timeline_data = []
            if hasattr(self.gui, 'timeline_chart'):
                self.gui.timeline_chart.set_data([])

            # Reset counters
            self.gui.vuln_counts = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0}
            self.update_vuln_display()

            # Update stats cards
            if hasattr(self.gui, 'total_card'):
                self.gui.total_card.set_value(0)
                self.gui.critical_card.set_value(0)
                self.gui.high_card.set_value(0)
                self.gui.medium_card.set_value(0)
                self.gui.low_card.set_value(0)

            # Clear pie chart
            if hasattr(self.gui, 'pie_chart'):
                self.gui.pie_chart.set_data({})

            self.gui.output_console.append("[*] Results cleared")
