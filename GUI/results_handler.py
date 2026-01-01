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

    def _log_error(self, method_name, error):
        """Log error to debug file"""
        from datetime import datetime
        log_file = Path(__file__).parent.parent / "gui_debug.log"
        try:
            with open(log_file, 'a', encoding='utf-8') as f:
                f.write(f"[{datetime.now().strftime('%H:%M:%S')}] ERROR in ResultsHandler.{method_name}: {error}\n")
                import traceback
                f.write(traceback.format_exc() + "\n")
        except:
            pass

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
        try:
            # Call the regular add_vulnerability with the full finding_data
            self.add_vulnerability(severity, description, module, target, finding_data)
        except Exception as e:
            self._log_error("add_vulnerability_with_data", e)

    def add_vulnerability(self, severity, description, module="", target="", finding_data=None):
        """Add vulnerability to the results list and table"""
        try:
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
        except Exception as e:
            self._log_error("add_vulnerability", e)

    def update_vuln_display(self):
        """Update vulnerability count displays"""
        try:
            total = sum(self.gui.vuln_counts.values())
            self.gui.total_vulns_label.setText(f"Total Vulnerabilities: {total}")
            self.gui.critical_label.setText(f"Critical: {self.gui.vuln_counts['CRITICAL']}")
            self.gui.high_label.setText(f"High: {self.gui.vuln_counts['HIGH']}")
            self.gui.medium_label.setText(f"Medium: {self.gui.vuln_counts['MEDIUM']}")
        except Exception as e:
            self._log_error("update_vuln_display", e)

    def update_stats(self, total_vulns, modules_done, modules_total):
        """Update scan statistics"""
        try:
            # Update status bar
            self.gui.statusBar().showMessage(f"Scan running... | {modules_done}/{modules_total} modules | {total_vulns} vulnerabilities")
        except Exception as e:
            self._log_error("update_stats", e)

    def set_current_report(self, report_filename):
        """Set the current scan's report file path

        Args:
            report_filename: The filename of the generated report
        """
        try:
            parent_dir = Path(__file__).parent.parent
            self.current_report_file = parent_dir / report_filename
            self.gui.output_console.append(f"[+] Report generated: {report_filename}")
        except Exception as e:
            self._log_error("set_current_report", e)

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
        try:
            self._add_resource_impl(resource_type, value, extra, source)
        except Exception as e:
            self._log_error("add_resource", e)

    def _table_has_value(self, table, check_col, value):
        """Check if table already contains a value in specified column"""
        return any(
            table.item(row, check_col) and table.item(row, check_col).text() == value
            for row in range(table.rowCount())
        )

    def _add_table_row(self, table, items, group=None):
        """Add a row to table with items and optionally show group"""
        row = table.rowCount()
        table.insertRow(row)
        for col, item in enumerate(items):
            table.setItem(row, col, item if isinstance(item, QTableWidgetItem) else QTableWidgetItem(item))
        if group:
            group.show()

    def _add_resource_impl(self, resource_type, value, extra, source):
        """Implementation of add_resource"""
        if resource_type == "email":
            if self._table_has_value(self.gui.emails_table, 0, value):
                return
            self._add_table_row(self.gui.emails_table, [value, extra, source], self.gui.emails_group)

        elif resource_type == "phone":
            if self._table_has_value(self.gui.phones_table, 0, value):
                return
            self._add_table_row(self.gui.phones_table, [value, extra, source], self.gui.phones_group)

        elif resource_type == "social":
            if self._table_has_value(self.gui.social_media_table, 1, value):
                return
            self._add_table_row(self.gui.social_media_table, [extra, value, source], self.gui.social_group)

        elif resource_type == "leaked_key":
            if self._table_has_value(self.gui.leaked_keys_table, 1, value):
                return
            parts = extra.split('|')
            key_type, severity = parts[0] if parts else "Unknown", parts[1] if len(parts) > 1 else "HIGH"
            severity_item = QTableWidgetItem(severity)
            severity_colors = {"CRITICAL": '#ff0000', "HIGH": '#ff8800'}
            if severity in severity_colors:
                severity_item.setForeground(QColor(severity_colors[severity]))
            self._add_table_row(self.gui.leaked_keys_table, [key_type, value, severity_item, source], self.gui.keys_group)

    def add_scope_info(self, info_type, data1, data2, data3):
        """Add scope information (technologies, titles, IPs) to appropriate tables"""
        try:
            self._add_scope_info_impl(info_type, data1, data2, data3)
        except Exception as e:
            self._log_error("add_scope_info", e)

    def _add_scope_info_impl(self, info_type, data1, data2, data3):
        """Implementation of add_scope_info"""
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
            self.gui.geo_table.setItem(row, 0, QTableWidgetItem(data1))  # IP
            self.gui.geo_table.setItem(row, 1, QTableWidgetItem("Looking up..."))  # Country
            self.gui.geo_table.setItem(row, 2, QTableWidgetItem("-"))  # City
            self.gui.geo_table.setItem(row, 3, QTableWidgetItem("-"))  # ISP
            self.gui.geo_table.setItem(row, 4, QTableWidgetItem(data2))  # Domain

            # Start async geo lookup
            self._lookup_geo_ip(data1, row)

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

    def _lookup_geo_ip(self, ip_address, table_row):
        """
        Perform async geo-IP lookup using free ip-api.com service
        Uses threading instead of QThread to avoid garbage collection issues.

        Args:
            ip_address: IP address to lookup
            table_row: Row index in geo_table to update
        """
        import threading
        from PyQt5.QtCore import QTimer

        def do_lookup():
            try:
                import urllib.request
                import json

                # Use ip-api.com (free, no API key required, 45 req/min limit)
                url = f"http://ip-api.com/json/{ip_address}?fields=status,country,city,isp,org,as"
                req = urllib.request.Request(url, headers={'User-Agent': 'DominatorScanner/1.0'})

                with urllib.request.urlopen(req, timeout=5) as response:
                    data = json.loads(response.read().decode('utf-8'))

                if data.get('status') == 'success':
                    result = {
                        'country': data.get('country', 'Unknown'),
                        'city': data.get('city', '-'),
                        'isp': data.get('isp', data.get('org', '-')),
                    }
                else:
                    result = {'country': 'Lookup Failed', 'city': '-', 'isp': '-'}

            except Exception as e:
                result = {'country': f'Error: {str(e)[:20]}', 'city': '-', 'isp': '-'}

            # Update UI from main thread using QTimer
            QTimer.singleShot(0, lambda: self._update_geo_table(table_row, result))

        # Run in background thread
        thread = threading.Thread(target=do_lookup, daemon=True)
        thread.start()

    def _update_geo_table(self, row, data):
        """Update geo table with lookup results (called from main thread)"""
        try:
            if hasattr(self.gui, 'geo_table') and row < self.gui.geo_table.rowCount():
                self.gui.geo_table.setItem(row, 1, QTableWidgetItem(data.get('country', '-')))
                self.gui.geo_table.setItem(row, 2, QTableWidgetItem(data.get('city', '-')))
                self.gui.geo_table.setItem(row, 3, QTableWidgetItem(data.get('isp', '-')))
        except Exception as e:
            self._log_error('_update_geo_table', e)
