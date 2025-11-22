"""
Project Manager for Dominator
Handles project creation, saving, loading and management
"""

import os
import json
import shutil
import tempfile
from datetime import datetime
from pathlib import Path
from PyQt5.QtWidgets import (
    QDialog, QVBoxLayout, QHBoxLayout, QPushButton, QLabel,
    QLineEdit, QFileDialog, QListWidget, QListWidgetItem, QMessageBox,
    QGroupBox, QRadioButton, QButtonGroup, QFrame, QCheckBox,
    QScrollArea, QWidget, QSplitter
)
from PyQt5.QtCore import Qt, pyqtSignal, QSettings
from PyQt5.QtGui import QFont, QIcon


class ProjectStartupDialog(QDialog):
    """Startup dialog for project selection"""

    # Signals
    new_project = pyqtSignal(str, str)  # name, path
    open_project = pyqtSignal(str)  # path
    temp_project = pyqtSignal()  # temporary session

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Dominator - Project Selection")
        self.setMinimumWidth(650)
        self.setMinimumHeight(600)
        self.selected_action = None
        self.settings = QSettings("Dominator", "WebScanner")
        self.init_ui()
        self.check_remember_choice()

    def init_ui(self):
        layout = QVBoxLayout()
        layout.setSpacing(15)

        # Header
        header = QLabel("Welcome to Dominator")
        header.setFont(QFont("Arial", 24, QFont.Bold))
        header.setAlignment(Qt.AlignCenter)
        layout.addWidget(header)

        subtitle = QLabel("Web Vulnerability Scanner")
        subtitle.setFont(QFont("Arial", 12))
        subtitle.setAlignment(Qt.AlignCenter)
        subtitle.setStyleSheet("color: #666;")
        layout.addWidget(subtitle)

        # Separator
        line = QFrame()
        line.setFrameShape(QFrame.HLine)
        line.setStyleSheet("background-color: #ddd;")
        layout.addWidget(line)

        # New Project Section
        new_group = QGroupBox("Create New Project")
        new_layout = QVBoxLayout()

        name_layout = QHBoxLayout()
        name_layout.addWidget(QLabel("Project Name:"))
        self.project_name_input = QLineEdit()
        self.project_name_input.setPlaceholderText("my-security-audit")
        name_layout.addWidget(self.project_name_input)
        new_layout.addLayout(name_layout)

        path_layout = QHBoxLayout()
        path_layout.addWidget(QLabel("Location:"))
        self.project_path_input = QLineEdit()
        self.project_path_input.setPlaceholderText("Select folder...")
        # Set default to Documents
        default_path = str(Path.home() / "Documents" / "Dominator Projects")
        self.project_path_input.setText(default_path)
        path_layout.addWidget(self.project_path_input)
        browse_btn = QPushButton("Browse...")
        browse_btn.clicked.connect(self.browse_project_location)
        path_layout.addWidget(browse_btn)
        new_layout.addLayout(path_layout)

        create_btn = QPushButton("Create New Project")
        create_btn.setStyleSheet("""
            QPushButton {
                background-color: #4CAF50;
                color: white;
                font-weight: bold;
                padding: 10px;
                border-radius: 5px;
            }
            QPushButton:hover {
                background-color: #45a049;
            }
        """)
        create_btn.clicked.connect(self.create_new_project)
        new_layout.addWidget(create_btn)

        new_group.setLayout(new_layout)
        layout.addWidget(new_group)

        # Recent Projects Section
        recent_group = QGroupBox("Recent Projects")
        recent_layout = QVBoxLayout()

        self.recent_list = QListWidget()
        self.recent_list.setMinimumHeight(150)
        self.recent_list.itemDoubleClicked.connect(self.open_selected_project)
        self.load_recent_projects()
        recent_layout.addWidget(self.recent_list)

        buttons_layout = QHBoxLayout()

        open_btn = QPushButton("Open Selected")
        open_btn.setStyleSheet("""
            QPushButton {
                background-color: #2196F3;
                color: white;
                font-weight: bold;
                padding: 10px;
                border-radius: 5px;
            }
            QPushButton:hover {
                background-color: #1976D2;
            }
        """)
        open_btn.clicked.connect(self.open_selected_project)
        buttons_layout.addWidget(open_btn)

        browse_project_btn = QPushButton("Browse...")
        browse_project_btn.setStyleSheet("""
            QPushButton {
                background-color: #607D8B;
                color: white;
                font-weight: bold;
                padding: 10px;
                border-radius: 5px;
            }
            QPushButton:hover {
                background-color: #455A64;
            }
        """)
        browse_project_btn.clicked.connect(self.browse_for_project)
        buttons_layout.addWidget(browse_project_btn)

        remove_btn = QPushButton("Remove from List")
        remove_btn.setStyleSheet("""
            QPushButton {
                background-color: #9E9E9E;
                color: white;
                font-weight: bold;
                padding: 10px;
                border-radius: 5px;
            }
            QPushButton:hover {
                background-color: #757575;
            }
        """)
        remove_btn.clicked.connect(self.remove_from_recent)
        buttons_layout.addWidget(remove_btn)

        recent_layout.addLayout(buttons_layout)
        recent_group.setLayout(recent_layout)
        layout.addWidget(recent_group)

        # Temporary Session Button
        temp_btn = QPushButton("Start Temporary Session (No Project)")
        temp_btn.setStyleSheet("""
            QPushButton {
                background-color: #FF9800;
                color: white;
                font-weight: bold;
                padding: 10px;
                border-radius: 5px;
            }
            QPushButton:hover {
                background-color: #F57C00;
            }
        """)
        temp_btn.clicked.connect(self.start_temp_session)
        layout.addWidget(temp_btn)

        # Remember choice checkbox
        self.remember_checkbox = QCheckBox("Remember my choice and don't show this dialog again")
        self.remember_checkbox.setStyleSheet("color: #666; margin-top: 10px;")
        layout.addWidget(self.remember_checkbox)

        # Reset button for remembered choice
        reset_btn = QPushButton("Reset Startup Preferences")
        reset_btn.setStyleSheet("""
            QPushButton {
                background-color: transparent;
                color: #999;
                font-size: 10px;
                border: none;
                padding: 5px;
            }
            QPushButton:hover {
                color: #666;
            }
        """)
        reset_btn.clicked.connect(self.reset_preferences)
        layout.addWidget(reset_btn)

        self.setLayout(layout)
        self.setStyleSheet("""
            QDialog {
                background-color: #f5f5f5;
            }
            QGroupBox {
                font-weight: bold;
                border: 2px solid #ddd;
                border-radius: 8px;
                margin-top: 10px;
                padding: 15px;
            }
            QGroupBox::title {
                subcontrol-origin: margin;
                left: 10px;
                padding: 0 5px;
            }
            QLineEdit {
                padding: 8px;
                border: 1px solid #ccc;
                border-radius: 4px;
                background-color: white;
            }
            QListWidget {
                border: 1px solid #ccc;
                border-radius: 4px;
                background-color: white;
            }
            QListWidget::item {
                padding: 8px;
                border-bottom: 1px solid #eee;
            }
            QListWidget::item:selected {
                background-color: #2196F3;
                color: white;
            }
        """)

    def check_remember_choice(self):
        """Check if user has a remembered choice"""
        remembered = self.settings.value("startup/remember", False, type=bool)
        if remembered:
            action = self.settings.value("startup/action", "")
            path = self.settings.value("startup/path", "")

            if action == "temp":
                self.temp_project.emit()
                self.accept()
            elif action == "open" and path:
                if Path(path).exists():
                    self.open_project.emit(path)
                    self.accept()
                else:
                    # Project doesn't exist anymore, reset preferences
                    self.reset_preferences()

    def save_remember_choice(self, action, path=""):
        """Save the user's choice if remember is checked"""
        if self.remember_checkbox.isChecked():
            self.settings.setValue("startup/remember", True)
            self.settings.setValue("startup/action", action)
            self.settings.setValue("startup/path", path)
        else:
            self.settings.setValue("startup/remember", False)

    def reset_preferences(self):
        """Reset startup preferences"""
        self.settings.setValue("startup/remember", False)
        self.settings.setValue("startup/action", "")
        self.settings.setValue("startup/path", "")
        QMessageBox.information(
            self, "Preferences Reset",
            "Startup preferences have been reset. This dialog will show on next launch."
        )

    def browse_project_location(self):
        """Browse for project location"""
        folder = QFileDialog.getExistingDirectory(
            self, "Select Project Location",
            str(Path.home() / "Documents")
        )
        if folder:
            self.project_path_input.setText(folder)

    def create_new_project(self):
        """Create a new project"""
        name = self.project_name_input.text().strip()
        path = self.project_path_input.text().strip()

        if not name:
            QMessageBox.warning(self, "Error", "Please enter a project name")
            return

        if not path:
            QMessageBox.warning(self, "Error", "Please select a project location")
            return

        # Sanitize project name
        name = "".join(c for c in name if c.isalnum() or c in ('-', '_', ' '))

        # Create project directory
        project_dir = Path(path) / name

        if project_dir.exists():
            reply = QMessageBox.question(
                self, "Project Exists",
                f"Project '{name}' already exists. Open it instead?",
                QMessageBox.Yes | QMessageBox.No
            )
            if reply == QMessageBox.Yes:
                self.add_to_recent(str(project_dir))
                self.save_remember_choice("open", str(project_dir))
                self.open_project.emit(str(project_dir))
                self.accept()
            return

        try:
            project_dir.mkdir(parents=True)

            # Create complete project structure
            (project_dir / "reports").mkdir()
            (project_dir / "findings").mkdir()
            (project_dir / "resources").mkdir()
            (project_dir / "logs").mkdir()
            (project_dir / "payloads").mkdir()
            (project_dir / "requests").mkdir()

            # Create project file
            project_data = {
                "name": name,
                "created": datetime.now().isoformat(),
                "last_modified": datetime.now().isoformat(),
                "version": "1.0",
                "settings": {
                    "target": "",
                    "modules": [],
                    "threads": 10,
                    "timeout": 30,
                    "cookies": "",
                    "headers": ""
                },
                "scan_history": [],
                "notes": ""
            }

            with open(project_dir / "project.json", 'w') as f:
                json.dump(project_data, f, indent=2)

            # Add to recent projects
            self.add_to_recent(str(project_dir))
            self.save_remember_choice("open", str(project_dir))

            self.new_project.emit(name, str(project_dir))
            self.accept()

        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to create project: {e}")

    def open_selected_project(self):
        """Open the selected recent project"""
        current = self.recent_list.currentItem()
        if not current:
            QMessageBox.warning(self, "Error", "Please select a project")
            return

        project_path = current.data(Qt.UserRole)
        if not Path(project_path).exists():
            QMessageBox.warning(
                self, "Error",
                f"Project not found: {project_path}"
            )
            return

        self.add_to_recent(project_path)
        self.save_remember_choice("open", project_path)
        self.open_project.emit(project_path)
        self.accept()

    def browse_for_project(self):
        """Browse for an existing project"""
        folder = QFileDialog.getExistingDirectory(
            self, "Select Project Folder"
        )
        if folder:
            # Check if it's a valid project
            project_file = Path(folder) / "project.json"
            if not project_file.exists():
                reply = QMessageBox.question(
                    self, "Not a Project",
                    "This folder doesn't contain a Dominator project. Create one here?",
                    QMessageBox.Yes | QMessageBox.No
                )
                if reply == QMessageBox.Yes:
                    self.project_name_input.setText(Path(folder).name)
                    self.project_path_input.setText(str(Path(folder).parent))
                return

            self.add_to_recent(folder)
            self.save_remember_choice("open", folder)
            self.open_project.emit(folder)
            self.accept()

    def remove_from_recent(self):
        """Remove selected project from recent list"""
        current = self.recent_list.currentItem()
        if not current:
            return

        project_path = current.data(Qt.UserRole)

        # Remove from settings
        config_file = Path.home() / ".dominator" / "settings.json"
        if config_file.exists():
            try:
                with open(config_file) as f:
                    settings = json.load(f)

                recent = settings.get("recent_projects", [])
                recent = [p for p in recent if p.get('path') != project_path]
                settings["recent_projects"] = recent

                with open(config_file, 'w') as f:
                    json.dump(settings, f, indent=2)
            except:
                pass

        # Remove from list widget
        row = self.recent_list.row(current)
        self.recent_list.takeItem(row)

    def start_temp_session(self):
        """Start a temporary session without a project"""
        self.save_remember_choice("temp")
        self.temp_project.emit()
        self.accept()

    def load_recent_projects(self):
        """Load recent projects from settings"""
        config_file = Path.home() / ".dominator" / "settings.json"

        if config_file.exists():
            try:
                with open(config_file) as f:
                    settings = json.load(f)

                recent = settings.get("recent_projects", [])
                for project in recent[:10]:  # Show last 10
                    if Path(project['path']).exists():
                        # Format: Name (Last opened: date)
                        last_opened = project.get('last_opened', '')
                        if last_opened:
                            try:
                                dt = datetime.fromisoformat(last_opened)
                                date_str = dt.strftime("%Y-%m-%d %H:%M")
                            except:
                                date_str = ""
                        else:
                            date_str = ""

                        display_text = f"{project['name']}\n{project['path']}"
                        if date_str:
                            display_text += f"\nLast opened: {date_str}"

                        item = QListWidgetItem(display_text)
                        item.setData(Qt.UserRole, project['path'])
                        self.recent_list.addItem(item)
            except Exception as e:
                print(f"Error loading recent projects: {e}")

    def add_to_recent(self, project_path):
        """Add project to recent list in settings.json"""
        config_dir = Path.home() / ".dominator"
        config_dir.mkdir(exist_ok=True)
        config_file = config_dir / "settings.json"

        settings = {}
        if config_file.exists():
            try:
                with open(config_file) as f:
                    settings = json.load(f)
            except:
                pass

        recent = settings.get("recent_projects", [])

        # Remove if already exists
        recent = [p for p in recent if p.get('path') != project_path]

        # Add to front
        project_name = Path(project_path).name
        recent.insert(0, {
            'name': project_name,
            'path': project_path,
            'last_opened': datetime.now().isoformat()
        })

        # Keep only last 20
        recent = recent[:20]
        settings["recent_projects"] = recent

        with open(config_file, 'w') as f:
            json.dump(settings, f, indent=2)


class ProjectManager:
    """Manages project state and operations"""

    def __init__(self):
        self.project_path = None
        self.project_name = None
        self.project_data = {}
        self.is_temp = True
        self.modified = False

    def create_project(self, name, path):
        """Create a new project"""
        self.project_path = path
        self.project_name = name
        self.is_temp = False
        self.modified = False
        self.load_project()

    def open_project(self, path):
        """Open an existing project"""
        self.project_path = path
        self.project_name = Path(path).name
        self.is_temp = False
        self.modified = False
        self.load_project()

    def load_project(self):
        """Load project data from disk"""
        if not self.project_path:
            return False

        project_file = Path(self.project_path) / "project.json"
        if project_file.exists():
            try:
                with open(project_file) as f:
                    self.project_data = json.load(f)
                return True
            except Exception as e:
                print(f"Error loading project: {e}")
                return False
        return False

    def save_project(self):
        """Save project data to disk"""
        if self.is_temp or not self.project_path:
            return False

        self.project_data['last_modified'] = datetime.now().isoformat()

        project_file = Path(self.project_path) / "project.json"
        try:
            with open(project_file, 'w') as f:
                json.dump(self.project_data, f, indent=2)
            self.modified = False
            return True
        except Exception as e:
            print(f"Error saving project: {e}")
            return False

    def save_project_as(self, new_path, new_name=None):
        """Save project to a new location"""
        if not new_name:
            new_name = Path(new_path).name

        try:
            # Create new project directory
            new_dir = Path(new_path)
            new_dir.mkdir(parents=True, exist_ok=True)

            # Copy project structure
            if self.project_path and Path(self.project_path).exists():
                for item in Path(self.project_path).iterdir():
                    if item.is_dir():
                        shutil.copytree(item, new_dir / item.name, dirs_exist_ok=True)
                    else:
                        shutil.copy2(item, new_dir / item.name)
            else:
                # Create empty structure
                for subdir in ["reports", "findings", "resources", "logs", "payloads", "requests"]:
                    (new_dir / subdir).mkdir(exist_ok=True)

            # Update project data
            self.project_data['name'] = new_name
            self.project_data['last_modified'] = datetime.now().isoformat()

            # Save to new location
            project_file = new_dir / "project.json"
            with open(project_file, 'w') as f:
                json.dump(self.project_data, f, indent=2)

            # Update current project
            self.project_path = str(new_dir)
            self.project_name = new_name
            self.is_temp = False
            self.modified = False

            return True
        except Exception as e:
            print(f"Error saving project as: {e}")
            return False

    def export_project(self, export_path):
        """Export project as a ZIP file"""
        if not self.project_path:
            return False

        try:
            # Save current state first
            self.save_project()

            # Create ZIP archive
            archive_path = shutil.make_archive(
                export_path.replace('.zip', ''),
                'zip',
                self.project_path
            )
            return archive_path
        except Exception as e:
            print(f"Error exporting project: {e}")
            return None

    def import_project(self, import_path, destination):
        """Import project from a ZIP file"""
        try:
            # Extract ZIP to destination
            shutil.unpack_archive(import_path, destination)

            # Open the imported project
            self.open_project(destination)
            return True
        except Exception as e:
            print(f"Error importing project: {e}")
            return False

    def save_scan_config(self, config):
        """Save scan configuration"""
        if self.is_temp or not self.project_path:
            return

        self.project_data['settings'] = config
        self.modified = True
        self.save_project()

    def get_scan_config(self):
        """Get saved scan configuration"""
        return self.project_data.get('settings', {})

    def add_scan_to_history(self, scan_info):
        """Add a scan to history"""
        if self.is_temp:
            return

        if 'scan_history' not in self.project_data:
            self.project_data['scan_history'] = []

        self.project_data['scan_history'].append({
            'timestamp': datetime.now().isoformat(),
            **scan_info
        })
        self.modified = True
        self.save_project()

    def add_finding(self, finding):
        """Save a finding to the findings directory"""
        if self.is_temp or not self.project_path:
            return None

        findings_dir = Path(self.project_path) / "findings"
        findings_dir.mkdir(exist_ok=True)

        # Generate unique filename
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S_%f")
        severity = finding.get('severity', 'unknown').lower()
        vuln_type = finding.get('type', 'unknown').replace(' ', '_').lower()
        filename = f"{severity}_{vuln_type}_{timestamp}.json"

        filepath = findings_dir / filename
        try:
            with open(filepath, 'w') as f:
                json.dump(finding, f, indent=2)
            return str(filepath)
        except Exception as e:
            print(f"Error saving finding: {e}")
            return None

    def save_report(self, content, format_type, filename=None):
        """Save a report to the reports directory"""
        if self.is_temp or not self.project_path:
            return None

        reports_dir = Path(self.project_path) / "reports"
        reports_dir.mkdir(exist_ok=True)

        if not filename:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"scan_report_{timestamp}.{format_type}"

        filepath = reports_dir / filename
        try:
            mode = 'w' if format_type in ['txt', 'html', 'json'] else 'wb'
            with open(filepath, mode) as f:
                f.write(content)
            return str(filepath)
        except Exception as e:
            print(f"Error saving report: {e}")
            return None

    def add_log(self, log_content, log_name=None):
        """Add a log entry to the logs directory"""
        if self.is_temp or not self.project_path:
            return None

        logs_dir = Path(self.project_path) / "logs"
        logs_dir.mkdir(exist_ok=True)

        if not log_name:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            log_name = f"scan_{timestamp}.log"

        filepath = logs_dir / log_name
        try:
            with open(filepath, 'a') as f:
                f.write(log_content)
            return str(filepath)
        except Exception as e:
            print(f"Error writing log: {e}")
            return None

    def add_resource(self, resource_type, resource_data):
        """Save a discovered resource"""
        if self.is_temp or not self.project_path:
            return None

        resources_dir = Path(self.project_path) / "resources"
        resources_dir.mkdir(exist_ok=True)

        # Load or create resource file for this type
        resource_file = resources_dir / f"{resource_type}.json"

        existing = []
        if resource_file.exists():
            try:
                with open(resource_file) as f:
                    existing = json.load(f)
            except:
                existing = []

        existing.append({
            'timestamp': datetime.now().isoformat(),
            'data': resource_data
        })

        try:
            with open(resource_file, 'w') as f:
                json.dump(existing, f, indent=2)
            return str(resource_file)
        except Exception as e:
            print(f"Error saving resource: {e}")
            return None

    def get_reports_dir(self):
        """Get reports directory for this project"""
        if self.is_temp or not self.project_path:
            return None
        return Path(self.project_path) / "reports"

    def get_findings_dir(self):
        """Get findings directory for this project"""
        if self.is_temp or not self.project_path:
            return None
        return Path(self.project_path) / "findings"

    def get_resources_dir(self):
        """Get resources directory for this project"""
        if self.is_temp or not self.project_path:
            return None
        return Path(self.project_path) / "resources"

    def get_logs_dir(self):
        """Get logs directory for this project"""
        if self.is_temp or not self.project_path:
            return None
        return Path(self.project_path) / "logs"

    def get_payloads_dir(self):
        """Get payloads directory for this project"""
        if self.is_temp or not self.project_path:
            return None
        return Path(self.project_path) / "payloads"

    def get_requests_dir(self):
        """Get requests directory for this project"""
        if self.is_temp or not self.project_path:
            return None
        return Path(self.project_path) / "requests"

    def get_project_info(self):
        """Get project information for display"""
        if self.is_temp:
            return {
                'name': 'Temporary Session',
                'path': 'N/A',
                'created': 'N/A',
                'last_modified': 'N/A',
                'scan_count': 0
            }

        return {
            'name': self.project_name,
            'path': self.project_path,
            'created': self.project_data.get('created', 'N/A'),
            'last_modified': self.project_data.get('last_modified', 'N/A'),
            'scan_count': len(self.project_data.get('scan_history', []))
        }

    def close_project(self):
        """Close the current project"""
        if self.modified:
            self.save_project()

        self.project_path = None
        self.project_name = None
        self.project_data = {}
        self.is_temp = True
        self.modified = False

    def set_notes(self, notes):
        """Save project notes"""
        self.project_data['notes'] = notes
        self.modified = True

    def get_notes(self):
        """Get project notes"""
        return self.project_data.get('notes', '')
