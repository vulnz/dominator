"""
Scheduler System for Dominator
Schedule scans to run at specific times or on recurring schedules.
"""

import json
import os
import threading
import time
import uuid
from datetime import datetime, timedelta
from pathlib import Path

from PyQt5.QtWidgets import (
    QDialog, QVBoxLayout, QHBoxLayout, QLabel, QPushButton,
    QWidget, QLineEdit, QTextEdit, QCheckBox, QSpinBox, QComboBox,
    QGroupBox, QGridLayout, QFrame, QRadioButton, QButtonGroup,
    QTableWidget, QTableWidgetItem, QHeaderView, QAbstractItemView,
    QMessageBox, QScrollArea, QDateTimeEdit, QTimeEdit, QTabWidget,
    QListWidget, QListWidgetItem, QMenu, QAction
)
from PyQt5.QtGui import QFont, QColor, QIcon
from PyQt5.QtCore import Qt, pyqtSignal, QDateTime, QTime, QTimer, QThread


class SchedulerThread(QThread):
    """Background thread that monitors scheduled tasks and runs them when due"""

    task_started = pyqtSignal(str, str)  # task_id, task_name
    task_completed = pyqtSignal(str, str, bool)  # task_id, task_name, success
    task_output = pyqtSignal(str, str)  # task_id, output_text
    status_update = pyqtSignal(str)  # status message

    def __init__(self, schedules_file):
        super().__init__()
        self.schedules_file = schedules_file
        self.running = True
        self.running_tasks = {}  # task_id -> subprocess
        self.lock = threading.Lock()

    def run(self):
        """Main scheduler loop - checks every minute for due tasks"""
        while self.running:
            try:
                self.check_and_run_due_tasks()
            except Exception as e:
                self.status_update.emit(f"Scheduler error: {str(e)}")

            # Sleep for 60 seconds, but check for stop signal every second
            for _ in range(60):
                if not self.running:
                    break
                time.sleep(1)

    def stop(self):
        """Stop the scheduler thread"""
        self.running = False
        # Kill any running tasks
        with self.lock:
            for task_id, proc in list(self.running_tasks.items()):
                try:
                    proc.terminate()
                except:
                    pass

    def check_and_run_due_tasks(self):
        """Check for due tasks and run them"""
        schedules = self.load_schedules()
        now = datetime.now()

        for task in schedules:
            if not task.get('enabled', True):
                continue

            if task['id'] in self.running_tasks:
                continue  # Already running

            if self.is_task_due(task, now):
                self.run_task(task)
                self.update_next_run(task)

    def is_task_due(self, task, now):
        """Check if a task is due to run"""
        next_run_str = task.get('next_run')
        if not next_run_str:
            return False

        try:
            next_run = datetime.fromisoformat(next_run_str)
            return now >= next_run
        except:
            return False

    def run_task(self, task):
        """Run a scheduled task"""
        import subprocess
        import sys

        task_id = task['id']
        task_name = task.get('name', 'Unnamed Task')

        self.task_started.emit(task_id, task_name)

        # Build command
        parent_dir = Path(__file__).parent.parent.parent
        main_script = parent_dir / "main.py"

        command = [sys.executable, str(main_script)]

        # Add target
        target = task.get('target', '')
        if target:
            command.extend(['-t', target])

        # Add modules
        modules = task.get('modules', [])
        if modules:
            command.extend(['-m', ','.join(modules)])
        else:
            command.append('--all')

        # Add settings
        settings = task.get('settings', {})
        command.extend(['--threads', str(settings.get('threads', 10))])
        command.extend(['--timeout', str(settings.get('timeout', 15))])
        command.extend(['--max-time', str(settings.get('max_time', 45))])
        command.extend(['--format', settings.get('format', 'html,json,txt')])
        command.append('--auto-report')
        command.append('-v')

        # Set output directory to project folder
        project_path = task.get('project_path')
        if project_path:
            reports_dir = Path(project_path) / 'reports' / 'scheduled'
            reports_dir.mkdir(parents=True, exist_ok=True)
            command.extend(['-o', str(reports_dir)])

        def run_subprocess():
            try:
                # Hide console window on Windows - use multiple methods
                creation_flags = 0
                startupinfo = None
                cmd = list(command)

                if sys.platform == 'win32':
                    # CREATE_NO_WINDOW = 0x08000000
                    creation_flags = getattr(subprocess, 'CREATE_NO_WINDOW', 0x08000000)

                    # Also use startupinfo to hide window
                    startupinfo = subprocess.STARTUPINFO()
                    startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
                    startupinfo.wShowWindow = 0  # SW_HIDE

                    # Replace python.exe with pythonw.exe if available
                    if cmd and 'python.exe' in cmd[0].lower():
                        pythonw = cmd[0].replace('python.exe', 'pythonw.exe')
                        if Path(pythonw).exists():
                            cmd[0] = pythonw

                proc = subprocess.Popen(
                    cmd,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                    text=True,
                    bufsize=1,
                    creationflags=creation_flags,  # Hide console window
                    startupinfo=startupinfo
                )

                with self.lock:
                    self.running_tasks[task_id] = proc

                # Capture output
                output_lines = []
                for line in proc.stdout:
                    output_lines.append(line)
                    self.task_output.emit(task_id, line)

                proc.wait()
                success = proc.returncode == 0

                # Save output to file
                if project_path:
                    log_dir = Path(project_path) / 'logs' / 'scheduled'
                    log_dir.mkdir(parents=True, exist_ok=True)
                    log_file = log_dir / f"{task_name}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log"
                    with open(log_file, 'w') as f:
                        f.writelines(output_lines)

                # Update last run status
                self.update_last_run(task_id, success)

                with self.lock:
                    if task_id in self.running_tasks:
                        del self.running_tasks[task_id]

                self.task_completed.emit(task_id, task_name, success)

                # Send email notification if configured
                if task.get('email_notification') and task.get('email_address'):
                    self.send_notification(task, success, output_lines)

            except Exception as e:
                self.task_completed.emit(task_id, task_name, False)
                with self.lock:
                    if task_id in self.running_tasks:
                        del self.running_tasks[task_id]

        # Run in separate thread
        thread = threading.Thread(target=run_subprocess, daemon=True)
        thread.start()

    def update_last_run(self, task_id, success):
        """Update the last run timestamp and status for a task"""
        schedules = self.load_schedules()
        for task in schedules:
            if task['id'] == task_id:
                task['last_run'] = datetime.now().isoformat()
                task['last_status'] = 'success' if success else 'failed'
                break
        self.save_schedules(schedules)

    def update_next_run(self, task):
        """Update the next run time for a task based on its schedule"""
        schedules = self.load_schedules()

        for t in schedules:
            if t['id'] == task['id']:
                schedule_type = t.get('schedule_type', 'once')

                if schedule_type == 'once':
                    # Disable one-time tasks after running
                    t['enabled'] = False
                    t['next_run'] = None

                elif schedule_type == 'daily':
                    # Schedule for next day at same time
                    time_str = t.get('schedule_time', '00:00')
                    hour, minute = map(int, time_str.split(':'))
                    next_run = datetime.now().replace(hour=hour, minute=minute, second=0, microsecond=0)
                    if next_run <= datetime.now():
                        next_run += timedelta(days=1)
                    t['next_run'] = next_run.isoformat()

                elif schedule_type == 'weekly':
                    # Schedule for next occurrence on selected days
                    days = t.get('schedule_days', [])
                    time_str = t.get('schedule_time', '00:00')
                    hour, minute = map(int, time_str.split(':'))

                    next_run = None
                    current = datetime.now()

                    for i in range(1, 8):
                        check_date = current + timedelta(days=i)
                        if check_date.strftime('%A') in days:
                            next_run = check_date.replace(hour=hour, minute=minute, second=0, microsecond=0)
                            break

                    t['next_run'] = next_run.isoformat() if next_run else None

                elif schedule_type == 'monthly':
                    # Schedule for next month on same day
                    day = t.get('schedule_day', 1)
                    time_str = t.get('schedule_time', '00:00')
                    hour, minute = map(int, time_str.split(':'))

                    current = datetime.now()
                    if current.day >= day:
                        # Next month
                        if current.month == 12:
                            next_run = current.replace(year=current.year + 1, month=1, day=day, hour=hour, minute=minute, second=0, microsecond=0)
                        else:
                            next_run = current.replace(month=current.month + 1, day=day, hour=hour, minute=minute, second=0, microsecond=0)
                    else:
                        next_run = current.replace(day=day, hour=hour, minute=minute, second=0, microsecond=0)

                    t['next_run'] = next_run.isoformat()

                break

        self.save_schedules(schedules)

    def send_notification(self, task, success, output_lines):
        """Send email notification (placeholder - requires SMTP configuration)"""
        # This would require SMTP configuration
        # For now, just log that notification would be sent
        self.status_update.emit(f"Email notification would be sent to {task.get('email_address')}")

    def load_schedules(self):
        """Load schedules from file"""
        if os.path.exists(self.schedules_file):
            try:
                with open(self.schedules_file, 'r') as f:
                    return json.load(f)
            except:
                pass
        return []

    def save_schedules(self, schedules):
        """Save schedules to file"""
        try:
            with open(self.schedules_file, 'w') as f:
                json.dump(schedules, f, indent=2)
        except Exception as e:
            self.status_update.emit(f"Error saving schedules: {str(e)}")


class ScheduleDialog(QDialog):
    """Dialog for creating/editing a scheduled task"""

    def __init__(self, parent=None, task=None, projects=None):
        super().__init__(parent)
        self.task = task or {}
        self.projects = projects or []
        self.init_ui()

        if task:
            self.load_task_data(task)

    def init_ui(self):
        """Initialize the dialog UI"""
        self.setWindowTitle("Schedule Scan" if not self.task else "Edit Scheduled Scan")
        self.setMinimumSize(600, 700)
        self.setStyleSheet("""
            QDialog {
                background-color: white;
            }
            QLabel {
                color: #333333;
                font-size: 11px;
            }
            QGroupBox {
                background-color: #f8f8f8;
                border: 1px solid #e0e0e0;
                border-radius: 5px;
                margin-top: 10px;
                padding-top: 10px;
                font-weight: bold;
                font-size: 12px;
            }
            QGroupBox::title {
                subcontrol-origin: margin;
                left: 10px;
                padding: 0 5px;
            }
        """)

        layout = QVBoxLayout(self)
        layout.setSpacing(10)

        # Scroll area for content
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setStyleSheet("QScrollArea { border: none; }")

        content = QWidget()
        content_layout = QVBoxLayout(content)

        # Task Name
        name_group = QGroupBox("Task Name")
        name_layout = QVBoxLayout()
        self.name_input = QLineEdit()
        self.name_input.setPlaceholderText("e.g., Weekly Security Scan")
        self.name_input.setStyleSheet("padding: 8px; border: 1px solid #ccc; border-radius: 4px;")
        name_layout.addWidget(self.name_input)
        name_group.setLayout(name_layout)
        content_layout.addWidget(name_group)

        # Target/Project
        target_group = QGroupBox("Target")
        target_layout = QVBoxLayout()

        # Project selector
        project_layout = QHBoxLayout()
        project_layout.addWidget(QLabel("Project:"))
        self.project_combo = QComboBox()
        self.project_combo.addItem("-- None --", "")
        for project in self.projects:
            self.project_combo.addItem(project['name'], project['path'])
        self.project_combo.setStyleSheet("padding: 5px;")
        project_layout.addWidget(self.project_combo)
        target_layout.addLayout(project_layout)

        # Target URL
        self.target_input = QLineEdit()
        self.target_input.setPlaceholderText("https://example.com")
        self.target_input.setStyleSheet("padding: 8px; border: 1px solid #ccc; border-radius: 4px;")
        target_layout.addWidget(QLabel("Target URL:"))
        target_layout.addWidget(self.target_input)

        target_group.setLayout(target_layout)
        content_layout.addWidget(target_group)

        # Modules
        modules_group = QGroupBox("Modules")
        modules_layout = QVBoxLayout()

        # All modules checkbox
        self.all_modules_cb = QCheckBox("All Modules")
        self.all_modules_cb.setChecked(True)
        self.all_modules_cb.stateChanged.connect(self.toggle_module_selection)
        modules_layout.addWidget(self.all_modules_cb)

        # Module checkboxes
        modules_grid = QGridLayout()
        self.module_checkboxes = {}

        modules = [
            ('sqli', 'SQL Injection'), ('xss', 'XSS'), ('csrf', 'CSRF'),
            ('lfi', 'LFI'), ('rfi', 'RFI'), ('xxe', 'XXE'),
            ('cmdi', 'Command Injection'), ('ssti', 'SSTI'), ('xpath', 'XPath'),
            ('idor', 'IDOR'), ('ssrf', 'SSRF'), ('redirect', 'Open Redirect')
        ]

        for i, (key, name) in enumerate(modules):
            cb = QCheckBox(name)
            cb.setEnabled(False)
            self.module_checkboxes[key] = cb
            modules_grid.addWidget(cb, i // 3, i % 3)

        modules_layout.addLayout(modules_grid)
        modules_group.setLayout(modules_layout)
        content_layout.addWidget(modules_group)

        # Scan Settings
        settings_group = QGroupBox("Scan Settings")
        settings_layout = QGridLayout()

        settings_layout.addWidget(QLabel("Threads:"), 0, 0)
        self.threads_spin = QSpinBox()
        self.threads_spin.setRange(1, 50)
        self.threads_spin.setValue(10)
        settings_layout.addWidget(self.threads_spin, 0, 1)

        settings_layout.addWidget(QLabel("Timeout (s):"), 0, 2)
        self.timeout_spin = QSpinBox()
        self.timeout_spin.setRange(5, 300)
        self.timeout_spin.setValue(15)
        settings_layout.addWidget(self.timeout_spin, 0, 3)

        settings_layout.addWidget(QLabel("Max Time (min):"), 1, 0)
        self.max_time_spin = QSpinBox()
        self.max_time_spin.setRange(1, 600)
        self.max_time_spin.setValue(45)
        settings_layout.addWidget(self.max_time_spin, 1, 1)

        settings_layout.addWidget(QLabel("Format:"), 1, 2)
        self.format_combo = QComboBox()
        self.format_combo.addItems(['html', 'json', 'txt', 'html,json,txt'])
        self.format_combo.setCurrentText('html,json,txt')
        settings_layout.addWidget(self.format_combo, 1, 3)

        settings_group.setLayout(settings_layout)
        content_layout.addWidget(settings_group)

        # Schedule Options
        schedule_group = QGroupBox("Schedule")
        schedule_layout = QVBoxLayout()

        # Schedule type
        self.schedule_type_group = QButtonGroup()

        # Once
        once_layout = QHBoxLayout()
        self.once_radio = QRadioButton("Run once at:")
        self.once_radio.setChecked(True)
        self.schedule_type_group.addButton(self.once_radio)
        once_layout.addWidget(self.once_radio)

        self.once_datetime = QDateTimeEdit()
        self.once_datetime.setDateTime(QDateTime.currentDateTime().addSecs(3600))
        self.once_datetime.setCalendarPopup(True)
        self.once_datetime.setStyleSheet("padding: 5px;")
        once_layout.addWidget(self.once_datetime)
        once_layout.addStretch()
        schedule_layout.addLayout(once_layout)

        # Daily
        daily_layout = QHBoxLayout()
        self.daily_radio = QRadioButton("Run daily at:")
        self.schedule_type_group.addButton(self.daily_radio)
        daily_layout.addWidget(self.daily_radio)

        self.daily_time = QTimeEdit()
        self.daily_time.setTime(QTime(2, 0))
        self.daily_time.setStyleSheet("padding: 5px;")
        daily_layout.addWidget(self.daily_time)
        daily_layout.addStretch()
        schedule_layout.addLayout(daily_layout)

        # Weekly
        weekly_layout = QHBoxLayout()
        self.weekly_radio = QRadioButton("Run weekly on:")
        self.schedule_type_group.addButton(self.weekly_radio)
        weekly_layout.addWidget(self.weekly_radio)
        schedule_layout.addLayout(weekly_layout)

        # Day checkboxes
        days_layout = QHBoxLayout()
        self.day_checkboxes = {}
        for day in ['Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday', 'Sunday']:
            cb = QCheckBox(day[:3])
            self.day_checkboxes[day] = cb
            days_layout.addWidget(cb)
        schedule_layout.addLayout(days_layout)

        weekly_time_layout = QHBoxLayout()
        weekly_time_layout.addWidget(QLabel("At time:"))
        self.weekly_time = QTimeEdit()
        self.weekly_time.setTime(QTime(2, 0))
        self.weekly_time.setStyleSheet("padding: 5px;")
        weekly_time_layout.addWidget(self.weekly_time)
        weekly_time_layout.addStretch()
        schedule_layout.addLayout(weekly_time_layout)

        # Monthly
        monthly_layout = QHBoxLayout()
        self.monthly_radio = QRadioButton("Run monthly on day:")
        self.schedule_type_group.addButton(self.monthly_radio)
        monthly_layout.addWidget(self.monthly_radio)

        self.monthly_day = QSpinBox()
        self.monthly_day.setRange(1, 28)
        self.monthly_day.setValue(1)
        monthly_layout.addWidget(self.monthly_day)

        monthly_layout.addWidget(QLabel("at"))
        self.monthly_time = QTimeEdit()
        self.monthly_time.setTime(QTime(2, 0))
        self.monthly_time.setStyleSheet("padding: 5px;")
        monthly_layout.addWidget(self.monthly_time)
        monthly_layout.addStretch()
        schedule_layout.addLayout(monthly_layout)

        schedule_group.setLayout(schedule_layout)
        content_layout.addWidget(schedule_group)

        # Email Notification
        notify_group = QGroupBox("Email Notification (Optional)")
        notify_layout = QVBoxLayout()

        self.email_cb = QCheckBox("Send email notification on completion")
        notify_layout.addWidget(self.email_cb)

        email_input_layout = QHBoxLayout()
        email_input_layout.addWidget(QLabel("Email:"))
        self.email_input = QLineEdit()
        self.email_input.setPlaceholderText("user@example.com")
        self.email_input.setStyleSheet("padding: 5px;")
        email_input_layout.addWidget(self.email_input)
        notify_layout.addLayout(email_input_layout)

        notify_group.setLayout(notify_layout)
        content_layout.addWidget(notify_group)

        content_layout.addStretch()
        scroll.setWidget(content)
        layout.addWidget(scroll)

        # Buttons
        btn_layout = QHBoxLayout()
        btn_layout.addStretch()

        cancel_btn = QPushButton("Cancel")
        cancel_btn.clicked.connect(self.reject)
        btn_layout.addWidget(cancel_btn)

        save_btn = QPushButton("Save Schedule")
        save_btn.setStyleSheet("""
            QPushButton {
                background-color: #4CAF50;
                color: white;
                padding: 8px 20px;
                border-radius: 4px;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: #45a049;
            }
        """)
        save_btn.clicked.connect(self.save_task)
        btn_layout.addWidget(save_btn)

        layout.addLayout(btn_layout)

    def toggle_module_selection(self, state):
        """Toggle individual module selection"""
        enabled = state != Qt.Checked
        for cb in self.module_checkboxes.values():
            cb.setEnabled(enabled)
            if not enabled:
                cb.setChecked(False)

    def load_task_data(self, task):
        """Load task data into the dialog"""
        self.name_input.setText(task.get('name', ''))
        self.target_input.setText(task.get('target', ''))

        # Set project
        project_path = task.get('project_path', '')
        index = self.project_combo.findData(project_path)
        if index >= 0:
            self.project_combo.setCurrentIndex(index)

        # Set modules
        modules = task.get('modules', [])
        if modules:
            self.all_modules_cb.setChecked(False)
            for key, cb in self.module_checkboxes.items():
                cb.setEnabled(True)
                cb.setChecked(key in modules)

        # Set settings
        settings = task.get('settings', {})
        self.threads_spin.setValue(settings.get('threads', 10))
        self.timeout_spin.setValue(settings.get('timeout', 15))
        self.max_time_spin.setValue(settings.get('max_time', 45))
        self.format_combo.setCurrentText(settings.get('format', 'html,json,txt'))

        # Set schedule
        schedule_type = task.get('schedule_type', 'once')
        if schedule_type == 'once':
            self.once_radio.setChecked(True)
            if task.get('next_run'):
                dt = datetime.fromisoformat(task['next_run'])
                self.once_datetime.setDateTime(QDateTime(dt.year, dt.month, dt.day, dt.hour, dt.minute))
        elif schedule_type == 'daily':
            self.daily_radio.setChecked(True)
            time_str = task.get('schedule_time', '02:00')
            h, m = map(int, time_str.split(':'))
            self.daily_time.setTime(QTime(h, m))
        elif schedule_type == 'weekly':
            self.weekly_radio.setChecked(True)
            days = task.get('schedule_days', [])
            for day, cb in self.day_checkboxes.items():
                cb.setChecked(day in days)
            time_str = task.get('schedule_time', '02:00')
            h, m = map(int, time_str.split(':'))
            self.weekly_time.setTime(QTime(h, m))
        elif schedule_type == 'monthly':
            self.monthly_radio.setChecked(True)
            self.monthly_day.setValue(task.get('schedule_day', 1))
            time_str = task.get('schedule_time', '02:00')
            h, m = map(int, time_str.split(':'))
            self.monthly_time.setTime(QTime(h, m))

        # Set email
        self.email_cb.setChecked(task.get('email_notification', False))
        self.email_input.setText(task.get('email_address', ''))

    def save_task(self):
        """Save the task data"""
        # Validate
        if not self.name_input.text().strip():
            QMessageBox.warning(self, "Validation Error", "Please enter a task name.")
            return

        if not self.target_input.text().strip():
            QMessageBox.warning(self, "Validation Error", "Please enter a target URL.")
            return

        # Collect data
        task_data = {
            'id': self.task.get('id', str(uuid.uuid4())),
            'name': self.name_input.text().strip(),
            'target': self.target_input.text().strip(),
            'project_path': self.project_combo.currentData(),
            'enabled': True,
            'created': self.task.get('created', datetime.now().isoformat()),
        }

        # Modules
        if self.all_modules_cb.isChecked():
            task_data['modules'] = []
        else:
            task_data['modules'] = [key for key, cb in self.module_checkboxes.items() if cb.isChecked()]

        # Settings
        task_data['settings'] = {
            'threads': self.threads_spin.value(),
            'timeout': self.timeout_spin.value(),
            'max_time': self.max_time_spin.value(),
            'format': self.format_combo.currentText()
        }

        # Schedule
        if self.once_radio.isChecked():
            task_data['schedule_type'] = 'once'
            dt = self.once_datetime.dateTime().toPyDateTime()
            task_data['next_run'] = dt.isoformat()
        elif self.daily_radio.isChecked():
            task_data['schedule_type'] = 'daily'
            time = self.daily_time.time()
            task_data['schedule_time'] = f"{time.hour():02d}:{time.minute():02d}"
            # Calculate next run
            now = datetime.now()
            next_run = now.replace(hour=time.hour(), minute=time.minute(), second=0, microsecond=0)
            if next_run <= now:
                next_run += timedelta(days=1)
            task_data['next_run'] = next_run.isoformat()
        elif self.weekly_radio.isChecked():
            task_data['schedule_type'] = 'weekly'
            task_data['schedule_days'] = [day for day, cb in self.day_checkboxes.items() if cb.isChecked()]
            time = self.weekly_time.time()
            task_data['schedule_time'] = f"{time.hour():02d}:{time.minute():02d}"
            # Calculate next run
            now = datetime.now()
            for i in range(7):
                check_date = now + timedelta(days=i)
                if check_date.strftime('%A') in task_data['schedule_days']:
                    next_run = check_date.replace(hour=time.hour(), minute=time.minute(), second=0, microsecond=0)
                    if next_run > now:
                        task_data['next_run'] = next_run.isoformat()
                        break
        elif self.monthly_radio.isChecked():
            task_data['schedule_type'] = 'monthly'
            task_data['schedule_day'] = self.monthly_day.value()
            time = self.monthly_time.time()
            task_data['schedule_time'] = f"{time.hour():02d}:{time.minute():02d}"
            # Calculate next run
            now = datetime.now()
            if now.day >= task_data['schedule_day']:
                if now.month == 12:
                    next_run = now.replace(year=now.year + 1, month=1, day=task_data['schedule_day'],
                                          hour=time.hour(), minute=time.minute(), second=0, microsecond=0)
                else:
                    next_run = now.replace(month=now.month + 1, day=task_data['schedule_day'],
                                          hour=time.hour(), minute=time.minute(), second=0, microsecond=0)
            else:
                next_run = now.replace(day=task_data['schedule_day'],
                                      hour=time.hour(), minute=time.minute(), second=0, microsecond=0)
            task_data['next_run'] = next_run.isoformat()

        # Email
        task_data['email_notification'] = self.email_cb.isChecked()
        task_data['email_address'] = self.email_input.text().strip()

        self.task = task_data
        self.accept()

    def get_task(self):
        """Get the task data"""
        return self.task


class SchedulerManager(QDialog):
    """Main scheduler management dialog"""

    scheduler_updated = pyqtSignal()  # Emitted when schedules change

    def __init__(self, parent=None):
        super().__init__(parent)
        self.parent_gui = parent
        self.schedules_file = self.get_schedules_file()
        self.scheduler_thread = None
        self.init_ui()
        self.load_tasks()
        self.start_scheduler()

        # Update timer for display
        self.update_timer = QTimer()
        self.update_timer.timeout.connect(self.update_status_display)
        self.update_timer.start(30000)  # Update every 30 seconds

    def get_schedules_file(self):
        """Get the schedules file path"""
        config_dir = Path.home() / ".dominator"
        config_dir.mkdir(exist_ok=True)
        return str(config_dir / "schedules.json")

    def init_ui(self):
        """Initialize the UI"""
        self.setWindowTitle("Scheduler - Dominator")
        self.setMinimumSize(900, 600)
        self.setStyleSheet("""
            QDialog {
                background-color: white;
            }
            QLabel {
                color: #333333;
            }
            QTableWidget {
                background-color: white;
                border: 1px solid #e0e0e0;
                gridline-color: #f0f0f0;
            }
            QTableWidget::item {
                padding: 8px;
            }
            QHeaderView::section {
                background-color: #f5f5f5;
                padding: 8px;
                border: none;
                border-bottom: 1px solid #e0e0e0;
                font-weight: bold;
            }
        """)

        layout = QVBoxLayout(self)

        # Header
        header = QFrame()
        header.setStyleSheet("""
            QFrame {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
                    stop:0 #4CAF50, stop:1 #2196F3);
                border-radius: 8px;
                padding: 15px;
            }
        """)
        header_layout = QVBoxLayout(header)

        title = QLabel("Scan Scheduler")
        title.setFont(QFont("Arial", 16, QFont.Bold))
        title.setStyleSheet("color: white;")
        header_layout.addWidget(title)

        subtitle = QLabel("Schedule automated security scans")
        subtitle.setStyleSheet("color: rgba(255, 255, 255, 0.8);")
        header_layout.addWidget(subtitle)

        layout.addWidget(header)

        # Status bar
        status_frame = QFrame()
        status_frame.setStyleSheet("""
            QFrame {
                background-color: #f8f8f8;
                border: 1px solid #e0e0e0;
                border-radius: 5px;
                padding: 10px;
            }
        """)
        status_layout = QHBoxLayout(status_frame)

        self.next_scan_label = QLabel("Next scan: --")
        self.next_scan_label.setStyleSheet("font-weight: bold;")
        status_layout.addWidget(self.next_scan_label)

        status_layout.addStretch()

        self.running_count_label = QLabel("Running: 0")
        self.running_count_label.setStyleSheet("color: #4CAF50; font-weight: bold;")
        status_layout.addWidget(self.running_count_label)

        self.total_count_label = QLabel("Total: 0")
        status_layout.addWidget(self.total_count_label)

        layout.addWidget(status_frame)

        # Toolbar
        toolbar = QHBoxLayout()

        new_btn = QPushButton("+ New Schedule")
        new_btn.setStyleSheet("""
            QPushButton {
                background-color: #4CAF50;
                color: white;
                padding: 8px 16px;
                border-radius: 4px;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: #45a049;
            }
        """)
        new_btn.clicked.connect(self.new_task)
        toolbar.addWidget(new_btn)

        toolbar.addStretch()

        refresh_btn = QPushButton("Refresh")
        refresh_btn.clicked.connect(self.load_tasks)
        toolbar.addWidget(refresh_btn)

        layout.addLayout(toolbar)

        # Tasks table
        self.tasks_table = QTableWidget()
        self.tasks_table.setColumnCount(6)
        self.tasks_table.setHorizontalHeaderLabels(['Name', 'Target', 'Schedule', 'Next Run', 'Status', 'Actions'])
        self.tasks_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.Stretch)
        self.tasks_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.Stretch)
        self.tasks_table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeToContents)
        self.tasks_table.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeToContents)
        self.tasks_table.horizontalHeader().setSectionResizeMode(4, QHeaderView.ResizeToContents)
        self.tasks_table.horizontalHeader().setSectionResizeMode(5, QHeaderView.ResizeToContents)
        self.tasks_table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.tasks_table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.tasks_table.verticalHeader().setVisible(False)
        self.tasks_table.setContextMenuPolicy(Qt.CustomContextMenu)
        self.tasks_table.customContextMenuRequested.connect(self.show_context_menu)

        layout.addWidget(self.tasks_table)

        # Bottom buttons
        btn_layout = QHBoxLayout()
        btn_layout.addStretch()

        close_btn = QPushButton("Close")
        close_btn.clicked.connect(self.close)
        btn_layout.addWidget(close_btn)

        layout.addLayout(btn_layout)

    def start_scheduler(self):
        """Start the background scheduler thread"""
        if self.scheduler_thread and self.scheduler_thread.isRunning():
            return

        self.scheduler_thread = SchedulerThread(self.schedules_file)
        self.scheduler_thread.task_started.connect(self.on_task_started)
        self.scheduler_thread.task_completed.connect(self.on_task_completed)
        self.scheduler_thread.status_update.connect(self.on_status_update)
        self.scheduler_thread.start()

    def stop_scheduler(self):
        """Stop the background scheduler thread"""
        if self.scheduler_thread:
            self.scheduler_thread.stop()
            self.scheduler_thread.wait(5000)

    def load_tasks(self):
        """Load tasks from file and display in table"""
        self.tasks_table.setRowCount(0)

        schedules = []
        if os.path.exists(self.schedules_file):
            try:
                with open(self.schedules_file, 'r') as f:
                    schedules = json.load(f)
            except:
                pass

        for task in schedules:
            row = self.tasks_table.rowCount()
            self.tasks_table.insertRow(row)

            # Name
            name_item = QTableWidgetItem(task.get('name', 'Unnamed'))
            name_item.setData(Qt.UserRole, task.get('id'))
            if not task.get('enabled', True):
                name_item.setForeground(QColor('#999999'))
            self.tasks_table.setItem(row, 0, name_item)

            # Target
            target_item = QTableWidgetItem(task.get('target', ''))
            self.tasks_table.setItem(row, 1, target_item)

            # Schedule
            schedule_type = task.get('schedule_type', 'once')
            schedule_text = self.format_schedule(task)
            schedule_item = QTableWidgetItem(schedule_text)
            self.tasks_table.setItem(row, 2, schedule_item)

            # Next Run
            next_run = task.get('next_run', '')
            if next_run:
                try:
                    dt = datetime.fromisoformat(next_run)
                    next_run_text = dt.strftime('%Y-%m-%d %H:%M')
                except:
                    next_run_text = next_run
            else:
                next_run_text = '--'
            next_run_item = QTableWidgetItem(next_run_text)
            self.tasks_table.setItem(row, 3, next_run_item)

            # Status
            last_status = task.get('last_status', 'pending')
            status_item = QTableWidgetItem(last_status.capitalize())
            if last_status == 'success':
                status_item.setForeground(QColor('#4CAF50'))
            elif last_status == 'failed':
                status_item.setForeground(QColor('#f44336'))
            elif last_status == 'running':
                status_item.setForeground(QColor('#2196F3'))
            self.tasks_table.setItem(row, 4, status_item)

            # Actions
            actions_widget = QWidget()
            actions_layout = QHBoxLayout(actions_widget)
            actions_layout.setContentsMargins(4, 4, 4, 4)
            actions_layout.setSpacing(4)

            # Run now button
            run_btn = QPushButton("Run")
            run_btn.setMaximumWidth(50)
            run_btn.setStyleSheet("padding: 3px;")
            run_btn.clicked.connect(lambda checked, tid=task['id']: self.run_task_now(tid))
            actions_layout.addWidget(run_btn)

            # Edit button
            edit_btn = QPushButton("Edit")
            edit_btn.setMaximumWidth(50)
            edit_btn.setStyleSheet("padding: 3px;")
            edit_btn.clicked.connect(lambda checked, tid=task['id']: self.edit_task(tid))
            actions_layout.addWidget(edit_btn)

            # Toggle enable button
            toggle_btn = QPushButton("Off" if task.get('enabled', True) else "On")
            toggle_btn.setMaximumWidth(40)
            toggle_btn.setStyleSheet("padding: 3px;")
            toggle_btn.clicked.connect(lambda checked, tid=task['id']: self.toggle_task(tid))
            actions_layout.addWidget(toggle_btn)

            self.tasks_table.setCellWidget(row, 5, actions_widget)

        self.update_status_display()
        self.total_count_label.setText(f"Total: {len(schedules)}")

    def format_schedule(self, task):
        """Format schedule type for display"""
        schedule_type = task.get('schedule_type', 'once')

        if schedule_type == 'once':
            return "Once"
        elif schedule_type == 'daily':
            time = task.get('schedule_time', '00:00')
            return f"Daily at {time}"
        elif schedule_type == 'weekly':
            days = task.get('schedule_days', [])
            time = task.get('schedule_time', '00:00')
            day_abbrs = [d[:3] for d in days]
            return f"Weekly {','.join(day_abbrs)} at {time}"
        elif schedule_type == 'monthly':
            day = task.get('schedule_day', 1)
            time = task.get('schedule_time', '00:00')
            return f"Monthly day {day} at {time}"

        return schedule_type

    def update_status_display(self):
        """Update status indicators"""
        schedules = []
        if os.path.exists(self.schedules_file):
            try:
                with open(self.schedules_file, 'r') as f:
                    schedules = json.load(f)
            except:
                pass

        # Find next scheduled scan
        next_scan = None
        for task in schedules:
            if not task.get('enabled', True):
                continue
            next_run = task.get('next_run')
            if next_run:
                try:
                    dt = datetime.fromisoformat(next_run)
                    if next_scan is None or dt < next_scan:
                        next_scan = dt
                except:
                    pass

        if next_scan:
            self.next_scan_label.setText(f"Next scan: {next_scan.strftime('%Y-%m-%d %H:%M')}")
        else:
            self.next_scan_label.setText("Next scan: --")

        # Count running tasks
        running_count = 0
        if self.scheduler_thread:
            running_count = len(self.scheduler_thread.running_tasks)
        self.running_count_label.setText(f"Running: {running_count}")

    def new_task(self):
        """Create a new scheduled task"""
        projects = self.get_projects()
        dialog = ScheduleDialog(self, projects=projects)
        if dialog.exec_() == QDialog.Accepted:
            task = dialog.get_task()
            self.save_task(task)
            self.load_tasks()
            self.scheduler_updated.emit()

    def edit_task(self, task_id):
        """Edit an existing task"""
        schedules = self.load_schedules()
        task = None
        for t in schedules:
            if t['id'] == task_id:
                task = t
                break

        if not task:
            return

        projects = self.get_projects()
        dialog = ScheduleDialog(self, task=task, projects=projects)
        if dialog.exec_() == QDialog.Accepted:
            updated_task = dialog.get_task()
            self.save_task(updated_task)
            self.load_tasks()
            self.scheduler_updated.emit()

    def toggle_task(self, task_id):
        """Toggle task enabled/disabled"""
        schedules = self.load_schedules()
        for task in schedules:
            if task['id'] == task_id:
                task['enabled'] = not task.get('enabled', True)
                break
        self.save_schedules(schedules)
        self.load_tasks()
        self.scheduler_updated.emit()

    def delete_task(self, task_id):
        """Delete a task"""
        reply = QMessageBox.question(
            self, "Confirm Delete",
            "Are you sure you want to delete this scheduled task?",
            QMessageBox.Yes | QMessageBox.No
        )
        if reply != QMessageBox.Yes:
            return

        schedules = self.load_schedules()
        schedules = [t for t in schedules if t['id'] != task_id]
        self.save_schedules(schedules)
        self.load_tasks()
        self.scheduler_updated.emit()

    def run_task_now(self, task_id):
        """Run a task immediately"""
        schedules = self.load_schedules()
        for task in schedules:
            if task['id'] == task_id:
                if self.scheduler_thread:
                    self.scheduler_thread.run_task(task)
                    QMessageBox.information(self, "Task Started", f"Task '{task.get('name', 'Unnamed')}' has been started.")
                break

    def show_context_menu(self, pos):
        """Show context menu for task table"""
        item = self.tasks_table.itemAt(pos)
        if not item:
            return

        task_id = self.tasks_table.item(item.row(), 0).data(Qt.UserRole)

        menu = QMenu(self)

        run_action = menu.addAction("Run Now")
        run_action.triggered.connect(lambda: self.run_task_now(task_id))

        edit_action = menu.addAction("Edit")
        edit_action.triggered.connect(lambda: self.edit_task(task_id))

        menu.addSeparator()

        delete_action = menu.addAction("Delete")
        delete_action.triggered.connect(lambda: self.delete_task(task_id))

        menu.exec_(self.tasks_table.viewport().mapToGlobal(pos))

    def save_task(self, task):
        """Save a task to the schedules file"""
        schedules = self.load_schedules()

        # Update existing or add new
        found = False
        for i, t in enumerate(schedules):
            if t['id'] == task['id']:
                schedules[i] = task
                found = True
                break

        if not found:
            schedules.append(task)

        self.save_schedules(schedules)

    def load_schedules(self):
        """Load schedules from file"""
        if os.path.exists(self.schedules_file):
            try:
                with open(self.schedules_file, 'r') as f:
                    return json.load(f)
            except:
                pass
        return []

    def save_schedules(self, schedules):
        """Save schedules to file"""
        try:
            with open(self.schedules_file, 'w') as f:
                json.dump(schedules, f, indent=2)
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to save schedules: {str(e)}")

    def get_projects(self):
        """Get list of recent projects"""
        projects = []
        config_file = Path.home() / ".dominator" / "settings.json"
        if config_file.exists():
            try:
                with open(config_file) as f:
                    settings = json.load(f)
                projects = settings.get("recent_projects", [])
            except:
                pass
        return projects

    def on_task_started(self, task_id, task_name):
        """Handle task started event"""
        self.update_status_display()
        if self.parent_gui:
            self.parent_gui.output_console.append(f"[Scheduler] Task started: {task_name}")

    def on_task_completed(self, task_id, task_name, success):
        """Handle task completed event"""
        self.load_tasks()
        status = "completed successfully" if success else "failed"
        if self.parent_gui:
            self.parent_gui.output_console.append(f"[Scheduler] Task {task_name} {status}")

    def on_status_update(self, message):
        """Handle status update from scheduler thread"""
        if self.parent_gui:
            self.parent_gui.output_console.append(f"[Scheduler] {message}")

    def closeEvent(self, event):
        """Handle dialog close"""
        # Don't stop the scheduler thread - it should keep running
        self.update_timer.stop()
        event.accept()

    def get_scheduler_status(self):
        """Get current scheduler status for status bar display"""
        schedules = self.load_schedules()
        enabled_count = sum(1 for t in schedules if t.get('enabled', True))

        if enabled_count == 0:
            return None

        # Find next scan
        next_scan = None
        for task in schedules:
            if not task.get('enabled', True):
                continue
            next_run = task.get('next_run')
            if next_run:
                try:
                    dt = datetime.fromisoformat(next_run)
                    if next_scan is None or dt < next_scan:
                        next_scan = dt
                except:
                    pass

        if next_scan:
            return f"Scheduled: {enabled_count} tasks | Next: {next_scan.strftime('%H:%M')}"
        return f"Scheduled: {enabled_count} tasks"


# Global scheduler instance
_scheduler_manager = None

def get_scheduler_manager(parent=None):
    """Get or create the global scheduler manager"""
    global _scheduler_manager
    if _scheduler_manager is None:
        _scheduler_manager = SchedulerManager(parent)
    return _scheduler_manager

def check_due_scans():
    """Check and run any due scheduled scans - called on startup"""
    schedules_file = str(Path.home() / ".dominator" / "schedules.json")

    if not os.path.exists(schedules_file):
        return

    try:
        with open(schedules_file, 'r') as f:
            schedules = json.load(f)

        now = datetime.now()
        due_tasks = []

        for task in schedules:
            if not task.get('enabled', True):
                continue

            next_run = task.get('next_run')
            if next_run:
                try:
                    dt = datetime.fromisoformat(next_run)
                    if now >= dt:
                        due_tasks.append(task.get('name', 'Unnamed'))
                except:
                    pass

        if due_tasks:
            return due_tasks
    except:
        pass

    return None
