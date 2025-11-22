#!/usr/bin/env python3
"""
Config Handler - Handles configuration file operations for Dominator GUI
Extracted from dominator_gui.py to reduce file size
"""

import json
from datetime import datetime
from pathlib import Path

from PyQt5.QtWidgets import QFileDialog, QMessageBox
from GUI.utils.message_box import show_information


class ConfigHandler:
    """Handles configuration file loading, saving, and exporting"""

    def __init__(self, gui):
        """
        Initialize ConfigHandler with GUI instance

        Args:
            gui: DominatorGUI instance
        """
        self.gui = gui

    def load_configuration(self):
        """Load scan configuration from JSON file"""
        filename, _ = QFileDialog.getOpenFileName(
            self.gui, "Load Project", "", "Dominator Projects (*.json);;All Files (*)"
        )
        if filename:
            try:
                with open(filename, 'r', encoding='utf-8') as f:
                    config = json.load(f)

                # Load target settings
                if 'target' in config:
                    self.gui.target_input.setPlainText(config['target'])
                if 'target_file' in config:
                    self.gui.target_file_input.setText(config['target_file'])

                # Load scan settings
                if 'threads' in config:
                    self.gui.threads_spin.setValue(config['threads'])
                if 'timeout' in config:
                    self.gui.timeout_spin.setValue(config['timeout'])
                if 'max_time' in config:
                    self.gui.max_time_spin.setValue(config['max_time'])
                if 'format' in config:
                    self.gui.format_combo.setCurrentText(config['format'])

                # Load modules
                if 'all_modules' in config:
                    self.gui.all_modules_cb.setChecked(config['all_modules'])
                if 'modules' in config and not config.get('all_modules', True):
                    self.gui.all_modules_cb.setChecked(False)
                    for module in config['modules']:
                        if module in self.gui.module_checkboxes:
                            self.gui.module_checkboxes[module].setChecked(True)

                # Load advanced options
                if 'recon_only' in config:
                    self.gui.recon_only_cb.setChecked(config['recon_only'])
                if 'rotate_agent' in config:
                    self.gui.rotate_agent_cb.setChecked(config['rotate_agent'])
                if 'single_page' in config:
                    self.gui.single_page_cb.setChecked(config['single_page'])

                # Load HTTP configuration
                if 'custom_headers' in config:
                    self.gui.headers_input.setPlainText(config['custom_headers'])
                if 'cookies' in config:
                    self.gui.cookies_input.setText(config['cookies'])

                # Load custom payloads
                if 'custom_payloads' in config:
                    self.gui.custom_payloads_text.setPlainText(config['custom_payloads'])
                if 'payload_target_module' in config:
                    index = self.gui.payload_target_module.findText(config['payload_target_module'])
                    if index >= 0:
                        self.gui.payload_target_module.setCurrentIndex(index)

                # Store current project file
                self.gui.current_project_file = filename
                self.gui.setWindowTitle(f"DOMINATOR Web Scanner - {Path(filename).name}")

                show_information(self.gui, "Success", f"Project loaded from:\n{filename}", setting_key="info_project_loaded")
            except Exception as e:
                QMessageBox.critical(self.gui, "Error", f"Failed to load project:\n{e}")

    def save_configuration(self):
        """Save current scan configuration to JSON file"""
        filename, _ = QFileDialog.getSaveFileName(
            self.gui, "Save Project", "dominator_project.json", "Dominator Projects (*.json);;All Files (*)"
        )
        if filename:
            try:
                config = {
                    # Target settings
                    'target': self.gui.target_input.toPlainText(),
                    'target_file': self.gui.target_file_input.text(),

                    # Scan settings
                    'threads': self.gui.threads_spin.value(),
                    'timeout': self.gui.timeout_spin.value(),
                    'max_time': self.gui.max_time_spin.value(),
                    'format': self.gui.format_combo.currentText(),

                    # Module selection
                    'modules': [name for name, cb in self.gui.module_checkboxes.items() if cb.isChecked()],
                    'all_modules': self.gui.all_modules_cb.isChecked(),

                    # Advanced options
                    'recon_only': self.gui.recon_only_cb.isChecked(),
                    'rotate_agent': self.gui.rotate_agent_cb.isChecked(),
                    'single_page': self.gui.single_page_cb.isChecked(),

                    # HTTP configuration
                    'custom_headers': self.gui.headers_input.toPlainText(),
                    'cookies': self.gui.cookies_input.text(),

                    # Custom payloads
                    'custom_payloads': self.gui.custom_payloads_text.toPlainText(),
                    'payload_target_module': self.gui.payload_target_module.currentText(),

                    # Metadata
                    'saved_at': datetime.now().isoformat(),
                    'version': '1.0'
                }

                with open(filename, 'w', encoding='utf-8') as f:
                    json.dump(config, f, indent=2)

                # Store current project file
                self.gui.current_project_file = filename
                self.gui.setWindowTitle(f"DOMINATOR Web Scanner - {Path(filename).name}")

                show_information(self.gui, "Success", f"Project saved to:\n{filename}", setting_key="info_project_saved")
            except Exception as e:
                QMessageBox.critical(self.gui, "Error", f"Failed to save project:\n{e}")

    def export_results(self):
        """Export scan results to CSV"""
        if not self.gui.vulns_list.count():
            QMessageBox.information(self.gui, "No Results", "No vulnerabilities to export!")
            return

        filename, _ = QFileDialog.getSaveFileName(
            self.gui, "Export Results", "vulnerabilities.txt", "Text Files (*.txt);;CSV Files (*.csv);;All Files (*)"
        )
        if filename:
            try:
                with open(filename, 'w', encoding='utf-8') as f:
                    f.write("DOMINATOR SCAN RESULTS\n")
                    f.write("=" * 80 + "\n\n")
                    f.write(f"Total Vulnerabilities: {self.gui.vulns_list.count()}\n")
                    f.write(f"Critical: {self.gui.vuln_counts['CRITICAL']}\n")
                    f.write(f"High: {self.gui.vuln_counts['HIGH']}\n")
                    f.write(f"Medium: {self.gui.vuln_counts['MEDIUM']}\n\n")
                    f.write("=" * 80 + "\n\n")

                    for i in range(self.gui.vulns_list.count()):
                        item = self.gui.vulns_list.item(i)
                        f.write(f"{item.text()}\n")

                show_information(self.gui, "Success", f"Results exported to:\n{filename}", setting_key="info_results_exported")
            except Exception as e:
                QMessageBox.critical(self.gui, "Error", f"Failed to export results:\n{e}")

    def export_resources(self):
        """Export discovered resources to a file"""
        if (self.gui.social_media_table.rowCount() == 0 and
            self.gui.emails_table.rowCount() == 0 and
            self.gui.phones_table.rowCount() == 0 and
            self.gui.leaked_keys_table.rowCount() == 0):
            QMessageBox.information(self.gui, "No Resources", "No resources to export!")
            return

        filename, _ = QFileDialog.getSaveFileName(
            self.gui, "Export Resources", "resources_report.txt", "Text Files (*.txt);;CSV Files (*.csv);;All Files (*)"
        )
        if filename:
            try:
                with open(filename, 'w', encoding='utf-8') as f:
                    f.write("="*80 + "\n")
                    f.write(" DOMINATOR - DISCOVERED RESOURCES REPORT\n")
                    f.write("="*80 + "\n\n")

                    # Social Media
                    if self.gui.social_media_table.rowCount() > 0:
                        f.write(f"\n SOCIAL MEDIA LINKS ({self.gui.social_media_table.rowCount()})\n")
                        f.write("-"*80 + "\n")
                        for row in range(self.gui.social_media_table.rowCount()):
                            platform = self.gui.social_media_table.item(row, 0).text()
                            url = self.gui.social_media_table.item(row, 1).text()
                            source = self.gui.social_media_table.item(row, 2).text()
                            f.write(f"  {platform:15s} | {url}\n")
                            f.write(f"  Found on: {source}\n\n")

                    # Emails
                    if self.gui.emails_table.rowCount() > 0:
                        f.write(f"\n EMAIL ADDRESSES ({self.gui.emails_table.rowCount()})\n")
                        f.write("-"*80 + "\n")
                        for row in range(self.gui.emails_table.rowCount()):
                            email = self.gui.emails_table.item(row, 0).text()
                            email_type = self.gui.emails_table.item(row, 1).text()
                            source = self.gui.emails_table.item(row, 2).text()
                            f.write(f"  {email:30s} | Type: {email_type}\n")
                            f.write(f"  Found on: {source}\n\n")

                    # Phones
                    if self.gui.phones_table.rowCount() > 0:
                        f.write(f"\n PHONE NUMBERS ({self.gui.phones_table.rowCount()})\n")
                        f.write("-"*80 + "\n")
                        for row in range(self.gui.phones_table.rowCount()):
                            phone = self.gui.phones_table.item(row, 0).text()
                            phone_format = self.gui.phones_table.item(row, 1).text()
                            source = self.gui.phones_table.item(row, 2).text()
                            f.write(f"  {phone:20s} | Format: {phone_format}\n")
                            f.write(f"  Found on: {source}\n\n")

                    # Leaked Keys
                    if self.gui.leaked_keys_table.rowCount() > 0:
                        f.write(f"\n LEAKED API KEYS & SECRETS ({self.gui.leaked_keys_table.rowCount()})\n")
                        f.write("-"*80 + "\n")
                        f.write("WARNING: These keys should be rotated immediately!\n\n")
                        for row in range(self.gui.leaked_keys_table.rowCount()):
                            key_type = self.gui.leaked_keys_table.item(row, 0).text()
                            key_preview = self.gui.leaked_keys_table.item(row, 1).text()
                            severity = self.gui.leaked_keys_table.item(row, 2).text()
                            source = self.gui.leaked_keys_table.item(row, 3).text()
                            f.write(f"  [{severity}] {key_type}\n")
                            f.write(f"  Preview: {key_preview}\n")
                            f.write(f"  Found on: {source}\n\n")

                    f.write("="*80 + "\n")
                    f.write("End of Resources Report\n")
                    f.write("="*80 + "\n")

                show_information(self.gui, "Success", f"Resources exported to:\n{filename}", setting_key="info_resources_exported")
            except Exception as e:
                QMessageBox.critical(self.gui, "Error", f"Failed to export resources:\n{e}")
