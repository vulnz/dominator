"""
Progress Tab Builder
Handles scan progress tracking, time estimates, and scan plan display.
Enhanced with circular progress, module grid, live logs, and comprehensive statistics.
"""

from PyQt5.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QGridLayout,
    QGroupBox, QLabel, QTableWidget, QPushButton,
    QScrollArea, QFrame, QProgressBar, QTextEdit,
    QComboBox, QSplitter, QTableWidgetItem, QSizePolicy,
    QSpacerItem
)
from PyQt5.QtCore import QTimer, Qt, QSize, pyqtSignal
from PyQt5.QtGui import QPainter, QColor, QPen, QFont, QBrush, QPainterPath
import datetime


class CircularProgressWidget(QWidget):
    """Custom circular progress indicator widget"""

    def __init__(self, parent=None):
        super().__init__(parent)
        self._value = 0
        self._max_value = 100
        self._primary_color = QColor(76, 175, 80)  # Green
        self._secondary_color = QColor(224, 224, 224)  # Light gray
        self._text_color = QColor(51, 51, 51)  # Dark gray
        self._line_width = 12
        self.setMinimumSize(180, 180)
        self.setMaximumSize(180, 180)

    def setValue(self, value):
        """Set the progress value (0-100)"""
        self._value = max(0, min(100, value))
        self.update()

    def value(self):
        """Get the current progress value"""
        return self._value

    def setColors(self, primary, secondary=None):
        """Set the progress colors"""
        self._primary_color = QColor(primary)
        if secondary:
            self._secondary_color = QColor(secondary)
        self.update()

    def paintEvent(self, event):
        """Paint the circular progress"""
        painter = QPainter(self)
        painter.setRenderHint(QPainter.Antialiasing)

        # Calculate dimensions
        width = self.width()
        height = self.height()
        side = min(width, height)

        # Center the drawing
        x = (width - side) // 2
        y = (height - side) // 2

        # Padding for the arc
        padding = self._line_width
        rect_size = side - 2 * padding

        # Draw background circle
        painter.setPen(QPen(self._secondary_color, self._line_width, Qt.SolidLine, Qt.RoundCap))
        painter.drawArc(x + padding, y + padding, rect_size, rect_size, 0, 360 * 16)

        # Draw progress arc
        if self._value > 0:
            painter.setPen(QPen(self._primary_color, self._line_width, Qt.SolidLine, Qt.RoundCap))
            span_angle = int(-self._value * 360 / self._max_value * 16)
            painter.drawArc(x + padding, y + padding, rect_size, rect_size, 90 * 16, span_angle)

        # Draw percentage text
        painter.setPen(self._text_color)
        font = QFont()
        font.setPointSize(28)
        font.setBold(True)
        painter.setFont(font)
        painter.drawText(x, y, side, side, Qt.AlignCenter, f"{self._value}%")


class ModuleCard(QFrame):
    """A card widget displaying module progress information"""

    def __init__(self, module_name, parent=None):
        super().__init__(parent)
        self.module_name = module_name
        self._status = "waiting"
        self._progress = 0
        self._payloads_tested = 0
        self._total_payloads = 0
        self._findings = 0

        self.setup_ui()

    def setup_ui(self):
        """Setup the card UI"""
        self.setFrameStyle(QFrame.StyledPanel | QFrame.Raised)
        self.setStyleSheet("""
            ModuleCard {
                background-color: #ffffff;
                border: 1px solid #e0e0e0;
                border-radius: 8px;
                padding: 8px;
            }
            ModuleCard:hover {
                border: 1px solid #4CAF50;
                background-color: #f8fff8;
            }
        """)

        layout = QVBoxLayout(self)
        layout.setSpacing(6)
        layout.setContentsMargins(10, 10, 10, 10)

        # Header with name and status icon
        header_layout = QHBoxLayout()

        self.name_label = QLabel(self.module_name)
        self.name_label.setStyleSheet("font-weight: bold; font-size: 11px; color: #333333;")
        header_layout.addWidget(self.name_label)

        header_layout.addStretch()

        self.status_icon = QLabel()
        self.status_icon.setFixedSize(16, 16)
        self.update_status_icon()
        header_layout.addWidget(self.status_icon)

        layout.addLayout(header_layout)

        # Progress bar
        self.progress_bar = QProgressBar()
        self.progress_bar.setMinimum(0)
        self.progress_bar.setMaximum(100)
        self.progress_bar.setValue(0)
        self.progress_bar.setTextVisible(False)
        self.progress_bar.setFixedHeight(8)
        self.progress_bar.setStyleSheet("""
            QProgressBar {
                background-color: #e0e0e0;
                border: none;
                border-radius: 4px;
            }
            QProgressBar::chunk {
                background-color: #4CAF50;
                border-radius: 4px;
            }
        """)
        layout.addWidget(self.progress_bar)

        # Stats row
        stats_layout = QHBoxLayout()

        self.payloads_label = QLabel("0/0")
        self.payloads_label.setStyleSheet("font-size: 9px; color: #666666;")
        self.payloads_label.setToolTip("Payloads tested / Total payloads")
        stats_layout.addWidget(self.payloads_label)

        stats_layout.addStretch()

        self.findings_label = QLabel("0 found")
        self.findings_label.setStyleSheet("font-size: 9px; color: #4CAF50;")
        self.findings_label.setToolTip("Vulnerabilities found")
        stats_layout.addWidget(self.findings_label)

        layout.addLayout(stats_layout)

    def update_status_icon(self):
        """Update the status icon based on current status"""
        icons = {
            "waiting": ("...", "#999999"),
            "running": (">>", "#FF9800"),
            "complete": ("OK", "#4CAF50"),
            "error": ("!!", "#f44336")
        }
        text, color = icons.get(self._status, ("?", "#999999"))
        self.status_icon.setText(text)
        self.status_icon.setStyleSheet(f"font-weight: bold; font-size: 10px; color: {color};")

    def setStatus(self, status):
        """Set the module status"""
        self._status = status
        self.update_status_icon()

        # Update progress bar color based on status
        colors = {
            "waiting": "#e0e0e0",
            "running": "#FF9800",
            "complete": "#4CAF50",
            "error": "#f44336"
        }
        color = colors.get(status, "#4CAF50")
        self.progress_bar.setStyleSheet(f"""
            QProgressBar {{
                background-color: #e0e0e0;
                border: none;
                border-radius: 4px;
            }}
            QProgressBar::chunk {{
                background-color: {color};
                border-radius: 4px;
            }}
        """)

    def setProgress(self, value):
        """Set the progress value"""
        self._progress = value
        self.progress_bar.setValue(value)

    def setPayloads(self, tested, total):
        """Set the payloads count"""
        self._payloads_tested = tested
        self._total_payloads = total
        self.payloads_label.setText(f"{tested}/{total}")

    def setFindings(self, count):
        """Set the findings count"""
        self._findings = count
        self.findings_label.setText(f"{count} found")
        if count > 0:
            self.findings_label.setStyleSheet("font-size: 9px; color: #f44336; font-weight: bold;")
        else:
            self.findings_label.setStyleSheet("font-size: 9px; color: #4CAF50;")


class LiveLogWidget(QTextEdit):
    """Custom text widget for displaying live logs with color coding"""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setReadOnly(True)
        self.setStyleSheet("""
            QTextEdit {
                background-color: #fafafa;
                color: #333333;
                border: 1px solid #e0e0e0;
                border-radius: 4px;
                font-family: 'Consolas', 'Monaco', monospace;
                font-size: 12px;
                padding: 8px;
                line-height: 1.4;
            }
        """)
        self._filter_level = "all"
        self._logs = []
        self._max_logs = 1000

    def add_log(self, message, level="info"):
        """Add a log entry with timestamp and color coding"""
        timestamp = datetime.datetime.now().strftime("%H:%M:%S")

        colors = {
            "info": "#333333",
            "warning": "#FF9800",
            "error": "#f44336",
            "success": "#4CAF50"
        }
        color = colors.get(level, "#333333")

        log_entry = {
            "timestamp": timestamp,
            "message": message,
            "level": level,
            "color": color
        }

        self._logs.append(log_entry)

        # Trim old logs
        if len(self._logs) > self._max_logs:
            self._logs = self._logs[-self._max_logs:]

        # Display if matches filter
        if self._filter_level == "all" or self._filter_level == level:
            html = f'<span style="color: #999999;">[{timestamp}]</span> '
            html += f'<span style="color: {color};">{message}</span>'
            self.append(html)

            # Auto-scroll to bottom
            scrollbar = self.verticalScrollBar()
            scrollbar.setValue(scrollbar.maximum())

    def set_filter(self, level):
        """Set the log filter level"""
        self._filter_level = level
        self.refresh_display()

    def refresh_display(self):
        """Refresh the display based on current filter"""
        self.clear()
        for log in self._logs:
            if self._filter_level == "all" or self._filter_level == log["level"]:
                html = f'<span style="color: #999999;">[{log["timestamp"]}]</span> '
                html += f'<span style="color: {log["color"]};">{log["message"]}</span>'
                self.append(html)


class ProgressTabBuilder:
    """Builder class for creating the Progress & Plan tab"""

    def __init__(self, gui, collapsible_box_class):
        """
        Initialize the builder with reference to main GUI

        Args:
            gui: Reference to DominatorGUI instance
            collapsible_box_class: The CollapsibleBox class (not used here but kept for consistency)
        """
        self.gui = gui
        self.CollapsibleBox = collapsible_box_class
        self.module_cards = {}

    def build(self):
        """Create and return the progress & plan tab widget"""
        widget = QWidget()
        main_layout = QVBoxLayout(widget)
        main_layout.setSpacing(10)
        main_layout.setContentsMargins(10, 10, 10, 10)

        # Create splitter for resizable sections
        splitter = QSplitter(Qt.Vertical)

        # Top section: Dashboard and Module Grid
        top_widget = QWidget()
        top_layout = QVBoxLayout(top_widget)
        top_layout.setContentsMargins(0, 0, 0, 0)

        # Progress Dashboard
        dashboard = self._create_dashboard()
        top_layout.addWidget(dashboard)

        # Module Progress Grid
        module_grid = self._create_module_grid()
        top_layout.addWidget(module_grid)

        splitter.addWidget(top_widget)

        # Bottom section: Time Stats and Live Logs
        bottom_widget = QWidget()
        bottom_layout = QHBoxLayout(bottom_widget)
        bottom_layout.setContentsMargins(0, 0, 0, 0)

        # Time Statistics
        time_stats = self._create_time_stats()
        bottom_layout.addWidget(time_stats, 1)

        # Live Log Section
        log_section = self._create_log_section()
        bottom_layout.addWidget(log_section, 2)

        splitter.addWidget(bottom_widget)

        # Set splitter proportions
        splitter.setStretchFactor(0, 2)
        splitter.setStretchFactor(1, 1)

        main_layout.addWidget(splitter)

        # Control Buttons
        controls = self._create_control_buttons()
        main_layout.addWidget(controls)

        # Initialize timer for elapsed time updates
        self.gui.scan_start_time = None
        self.gui.time_update_timer = QTimer()
        self.gui.time_update_timer.timeout.connect(self._update_all_displays)

        # Store reference to builder for updates
        self.gui.progress_tab_builder = self

        # Initialize request counter
        self.gui.total_requests = 0
        self.gui.requests_per_second = 0
        self._last_request_count = 0
        self._last_request_time = None

        return widget

    def _create_dashboard(self):
        """Create the progress dashboard section"""
        dashboard = QGroupBox("Progress Dashboard")
        dashboard.setStyleSheet("""
            QGroupBox {
                font-weight: bold;
                font-size: 12px;
                color: #333333;
                border: 1px solid #e0e0e0;
                border-radius: 8px;
                margin-top: 10px;
                padding-top: 10px;
                background-color: #ffffff;
            }
            QGroupBox::title {
                subcontrol-origin: margin;
                left: 10px;
                padding: 0 5px;
            }
        """)

        layout = QHBoxLayout(dashboard)
        layout.setSpacing(20)

        # Circular Progress
        progress_container = QVBoxLayout()
        self.gui.circular_progress = CircularProgressWidget()
        progress_container.addWidget(self.gui.circular_progress, 0, Qt.AlignCenter)
        layout.addLayout(progress_container)

        # Stats Panel
        stats_panel = QGridLayout()
        stats_panel.setSpacing(10)

        # Current Module
        stats_panel.addWidget(QLabel("Current Module:"), 0, 0)
        self.gui.current_module_dashboard = QLabel("Not started")
        self.gui.current_module_dashboard.setStyleSheet("font-weight: bold; color: #4CAF50; font-size: 12px;")
        self.gui.current_module_dashboard.setWordWrap(True)
        stats_panel.addWidget(self.gui.current_module_dashboard, 0, 1)

        # Requests
        stats_panel.addWidget(QLabel("Requests:"), 1, 0)
        self.gui.requests_label = QLabel("0 / 0")
        self.gui.requests_label.setStyleSheet("font-weight: bold; color: #2196F3; font-size: 12px;")
        stats_panel.addWidget(self.gui.requests_label, 1, 1)

        # Vulnerabilities Found
        stats_panel.addWidget(QLabel("Vulnerabilities:"), 2, 0)
        self.gui.vulns_found_label = QLabel("0")
        self.gui.vulns_found_label.setStyleSheet("font-weight: bold; color: #f44336; font-size: 12px;")
        stats_panel.addWidget(self.gui.vulns_found_label, 2, 1)

        # Estimated Time Remaining
        stats_panel.addWidget(QLabel("Time Remaining:"), 3, 0)
        self.gui.time_remaining_dashboard = QLabel("Calculating...")
        self.gui.time_remaining_dashboard.setStyleSheet("font-weight: bold; color: #FF9800; font-size: 12px;")
        stats_panel.addWidget(self.gui.time_remaining_dashboard, 3, 1)

        layout.addLayout(stats_panel)
        layout.addStretch()

        return dashboard

    def _create_module_grid(self):
        """Create the module progress grid"""
        grid_group = QGroupBox("Module Progress")
        grid_group.setStyleSheet("""
            QGroupBox {
                font-weight: bold;
                font-size: 12px;
                color: #333333;
                border: 1px solid #e0e0e0;
                border-radius: 8px;
                margin-top: 10px;
                padding-top: 10px;
                background-color: #ffffff;
            }
            QGroupBox::title {
                subcontrol-origin: margin;
                left: 10px;
                padding: 0 5px;
            }
        """)

        # Scroll area for the grid
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        scroll.setStyleSheet("""
            QScrollArea {
                border: none;
                background-color: transparent;
            }
        """)

        # Container for module cards
        self.gui.module_grid_container = QWidget()
        self.gui.module_grid_layout = QGridLayout(self.gui.module_grid_container)
        self.gui.module_grid_layout.setSpacing(10)

        scroll.setWidget(self.gui.module_grid_container)

        layout = QVBoxLayout(grid_group)
        layout.addWidget(scroll)

        return grid_group

    def _create_time_stats(self):
        """Create the time statistics section"""
        time_group = QGroupBox("Time Statistics")
        time_group.setStyleSheet("""
            QGroupBox {
                font-weight: bold;
                font-size: 12px;
                color: #333333;
                border: 1px solid #e0e0e0;
                border-radius: 8px;
                margin-top: 10px;
                padding-top: 10px;
                background-color: #ffffff;
            }
            QGroupBox::title {
                subcontrol-origin: margin;
                left: 10px;
                padding: 0 5px;
            }
        """)

        layout = QGridLayout(time_group)
        layout.setSpacing(8)

        # Start Time
        layout.addWidget(QLabel("Start Time:"), 0, 0)
        self.gui.scan_start_label = QLabel("Not started")
        self.gui.scan_start_label.setStyleSheet("color: #4CAF50; font-weight: bold;")
        layout.addWidget(self.gui.scan_start_label, 0, 1)

        # Elapsed Time
        layout.addWidget(QLabel("Elapsed Time:"), 1, 0)
        self.gui.elapsed_time_label = QLabel("00:00:00")
        self.gui.elapsed_time_label.setStyleSheet("color: #4CAF50; font-weight: bold; font-size: 16px;")
        layout.addWidget(self.gui.elapsed_time_label, 1, 1)

        # Estimated Completion
        layout.addWidget(QLabel("Est. Completion:"), 2, 0)
        self.gui.completion_time_label = QLabel("Calculating...")
        self.gui.completion_time_label.setStyleSheet("color: #2196F3;")
        layout.addWidget(self.gui.completion_time_label, 2, 1)

        # Average Time per Module
        layout.addWidget(QLabel("Avg Time/Module:"), 3, 0)
        self.gui.avg_module_time_label = QLabel("--:--")
        self.gui.avg_module_time_label.setStyleSheet("color: #666666;")
        layout.addWidget(self.gui.avg_module_time_label, 3, 1)

        # Requests per Second
        layout.addWidget(QLabel("Requests/sec:"), 4, 0)
        self.gui.rps_label = QLabel("0.0")
        self.gui.rps_label.setStyleSheet("color: #9C27B0; font-weight: bold;")
        layout.addWidget(self.gui.rps_label, 4, 1)

        # Add stretch at bottom
        layout.setRowStretch(5, 1)

        # For backward compatibility, create estimated_time_label as alias
        self.gui.estimated_time_label = self.gui.time_remaining_dashboard

        return time_group

    def _create_log_section(self):
        """Create the live log section"""
        log_group = QGroupBox("Live Activity Log")
        log_group.setStyleSheet("""
            QGroupBox {
                font-weight: bold;
                font-size: 12px;
                color: #333333;
                border: 1px solid #e0e0e0;
                border-radius: 8px;
                margin-top: 10px;
                padding-top: 10px;
                background-color: #ffffff;
            }
            QGroupBox::title {
                subcontrol-origin: margin;
                left: 10px;
                padding: 0 5px;
            }
        """)

        layout = QVBoxLayout(log_group)

        # Filter controls
        filter_layout = QHBoxLayout()
        filter_layout.addWidget(QLabel("Filter:"))

        self.gui.log_filter_combo = QComboBox()
        self.gui.log_filter_combo.addItems(["All", "Info", "Warning", "Error", "Success"])
        self.gui.log_filter_combo.setStyleSheet("""
            QComboBox {
                background-color: #ffffff;
                border: 1px solid #e0e0e0;
                border-radius: 4px;
                padding: 4px 8px;
                color: #333333;
            }
            QComboBox::drop-down {
                border: none;
            }
            QComboBox::down-arrow {
                width: 10px;
                height: 10px;
            }
        """)
        self.gui.log_filter_combo.currentTextChanged.connect(self._on_log_filter_changed)
        filter_layout.addWidget(self.gui.log_filter_combo)

        filter_layout.addStretch()

        # Clear button
        clear_btn = QPushButton("Clear")
        clear_btn.setStyleSheet("""
            QPushButton {
                background-color: #f5f5f5;
                border: 1px solid #e0e0e0;
                border-radius: 4px;
                padding: 4px 12px;
                color: #333333;
            }
            QPushButton:hover {
                background-color: #e0e0e0;
            }
        """)
        clear_btn.clicked.connect(self._clear_logs)
        filter_layout.addWidget(clear_btn)

        layout.addLayout(filter_layout)

        # Live log widget
        self.gui.live_log = LiveLogWidget()
        layout.addWidget(self.gui.live_log)

        return log_group

    def _create_control_buttons(self):
        """Create scan control buttons"""
        controls = QFrame()
        controls.setStyleSheet("""
            QFrame {
                background-color: #f5f5f5;
                border: 1px solid #e0e0e0;
                border-radius: 8px;
                padding: 10px;
            }
        """)

        layout = QHBoxLayout(controls)
        layout.setSpacing(10)

        # Pause/Resume button
        self.gui.progress_pause_btn = QPushButton("Pause Scan")
        self.gui.progress_pause_btn.setStyleSheet("""
            QPushButton {
                background-color: #FF9800;
                color: white;
                border: none;
                border-radius: 6px;
                padding: 10px 20px;
                font-weight: bold;
                font-size: 11px;
            }
            QPushButton:hover {
                background-color: #F57C00;
            }
            QPushButton:disabled {
                background-color: #cccccc;
            }
        """)
        self.gui.progress_pause_btn.clicked.connect(self._toggle_pause)
        self.gui.progress_pause_btn.setEnabled(False)
        layout.addWidget(self.gui.progress_pause_btn)

        # Stop button
        self.gui.progress_stop_btn = QPushButton("Stop Scan")
        self.gui.progress_stop_btn.setStyleSheet("""
            QPushButton {
                background-color: #f44336;
                color: white;
                border: none;
                border-radius: 6px;
                padding: 10px 20px;
                font-weight: bold;
                font-size: 11px;
            }
            QPushButton:hover {
                background-color: #D32F2F;
            }
            QPushButton:disabled {
                background-color: #cccccc;
            }
        """)
        self.gui.progress_stop_btn.clicked.connect(self._stop_scan)
        self.gui.progress_stop_btn.setEnabled(False)
        layout.addWidget(self.gui.progress_stop_btn)

        # Skip module button
        self.gui.skip_module_btn = QPushButton("Skip Module")
        self.gui.skip_module_btn.setStyleSheet("""
            QPushButton {
                background-color: #9E9E9E;
                color: white;
                border: none;
                border-radius: 6px;
                padding: 10px 20px;
                font-weight: bold;
                font-size: 11px;
            }
            QPushButton:hover {
                background-color: #757575;
            }
            QPushButton:disabled {
                background-color: #cccccc;
            }
        """)
        self.gui.skip_module_btn.clicked.connect(self._skip_module)
        self.gui.skip_module_btn.setEnabled(False)
        layout.addWidget(self.gui.skip_module_btn)

        layout.addStretch()

        return controls

    def _on_log_filter_changed(self, text):
        """Handle log filter change"""
        level_map = {
            "All": "all",
            "Info": "info",
            "Warning": "warning",
            "Error": "error",
            "Success": "success"
        }
        self.gui.live_log.set_filter(level_map.get(text, "all"))

    def _clear_logs(self):
        """Clear the live log"""
        self.gui.live_log.clear()
        self.gui.live_log._logs = []

    def _toggle_pause(self):
        """Toggle pause/resume for the scan"""
        if hasattr(self.gui, 'toggle_pause_scan'):
            self.gui.toggle_pause_scan()

        # Update button text
        if hasattr(self.gui, 'scan_thread') and self.gui.scan_thread:
            if hasattr(self.gui.scan_thread, 'paused') and self.gui.scan_thread.paused:
                self.gui.progress_pause_btn.setText("Resume Scan")
                self.gui.progress_pause_btn.setStyleSheet("""
                    QPushButton {
                        background-color: #4CAF50;
                        color: white;
                        border: none;
                        border-radius: 6px;
                        padding: 10px 20px;
                        font-weight: bold;
                        font-size: 11px;
                    }
                    QPushButton:hover {
                        background-color: #388E3C;
                    }
                """)
            else:
                self.gui.progress_pause_btn.setText("Pause Scan")
                self.gui.progress_pause_btn.setStyleSheet("""
                    QPushButton {
                        background-color: #FF9800;
                        color: white;
                        border: none;
                        border-radius: 6px;
                        padding: 10px 20px;
                        font-weight: bold;
                        font-size: 11px;
                    }
                    QPushButton:hover {
                        background-color: #F57C00;
                    }
                """)

    def _stop_scan(self):
        """Stop the current scan"""
        if hasattr(self.gui, 'stop_scan'):
            self.gui.stop_scan()

    def _skip_module(self):
        """Skip the current module"""
        # This would need backend support - for now just log
        self.gui.live_log.add_log("Skip module requested (not implemented in scanner)", "warning")

    def _update_all_displays(self):
        """Update all time-related displays"""
        if not self.gui.scan_start_time:
            return

        now = datetime.datetime.now()
        elapsed = now - self.gui.scan_start_time

        # Format elapsed time as HH:MM:SS
        hours = int(elapsed.total_seconds() // 3600)
        minutes = int((elapsed.total_seconds() % 3600) // 60)
        seconds = int(elapsed.total_seconds() % 60)
        elapsed_str = f"{hours:02d}:{minutes:02d}:{seconds:02d}"
        self.gui.elapsed_time_label.setText(elapsed_str)

        # Calculate estimated remaining time based on progress
        if hasattr(self.gui, 'progress_bar') and self.gui.progress_bar.value() > 0:
            progress_pct = self.gui.progress_bar.value() / 100.0
            if progress_pct > 0:
                estimated_total = elapsed.total_seconds() / progress_pct
                remaining = estimated_total - elapsed.total_seconds()

                if remaining > 0:
                    rem_hours = int(remaining // 3600)
                    rem_minutes = int((remaining % 3600) // 60)
                    rem_seconds = int(remaining % 60)
                    remaining_str = f"{rem_hours:02d}:{rem_minutes:02d}:{rem_seconds:02d}"
                    self.gui.time_remaining_dashboard.setText(remaining_str)

                    # Calculate completion time
                    completion_time = now + datetime.timedelta(seconds=remaining)
                    self.gui.completion_time_label.setText(completion_time.strftime("%H:%M:%S"))
                else:
                    self.gui.time_remaining_dashboard.setText("00:00:00")
                    self.gui.completion_time_label.setText("Now")
            else:
                self.gui.time_remaining_dashboard.setText("Calculating...")
                self.gui.completion_time_label.setText("Calculating...")
        else:
            self.gui.time_remaining_dashboard.setText("Calculating...")
            self.gui.completion_time_label.setText("Calculating...")

        # Update circular progress
        if hasattr(self.gui, 'progress_bar'):
            self.gui.circular_progress.setValue(self.gui.progress_bar.value())

        # Calculate average time per module
        if hasattr(self.gui, 'scan_thread') and self.gui.scan_thread:
            completed = self.gui.scan_thread.completed_modules
            if completed > 0:
                avg_seconds = elapsed.total_seconds() / completed
                avg_minutes = int(avg_seconds // 60)
                avg_secs = int(avg_seconds % 60)
                self.gui.avg_module_time_label.setText(f"{avg_minutes:02d}:{avg_secs:02d}")

        # Calculate requests per second
        current_requests = getattr(self.gui, 'total_requests', 0)
        current_time = now

        if self._last_request_time is not None:
            time_diff = (current_time - self._last_request_time).total_seconds()
            if time_diff > 0:
                request_diff = current_requests - self._last_request_count
                rps = request_diff / time_diff
                self.gui.rps_label.setText(f"{rps:.1f}")
                self.gui.requests_per_second = rps

        self._last_request_count = current_requests
        self._last_request_time = current_time

    def populate_module_grid(self, modules):
        """Populate the module grid with cards for each module"""
        # Clear existing cards
        self.module_cards.clear()
        while self.gui.module_grid_layout.count():
            item = self.gui.module_grid_layout.takeAt(0)
            if item.widget():
                item.widget().deleteLater()

        # Create cards for each module
        cols = 4  # Number of columns in grid
        for i, module_name in enumerate(modules):
            card = ModuleCard(module_name)
            row = i // cols
            col = i % cols
            self.gui.module_grid_layout.addWidget(card, row, col)
            self.module_cards[module_name.lower()] = card

    def update_module_status(self, module_name, status, progress=None, payloads=None, findings=None):
        """Update a module card's status"""
        # Find card by module name (case-insensitive partial match)
        card = None
        for key, c in self.module_cards.items():
            if module_name.lower() in key or key in module_name.lower():
                card = c
                break

        if card:
            if status:
                status_map = {
                    "pending": "waiting",
                    "running": "running",
                    "complete": "complete",
                    "failed": "error",
                    "error": "error"
                }
                card.setStatus(status_map.get(status.lower(), "waiting"))

            if progress is not None:
                card.setProgress(progress)

            if payloads:
                card.setPayloads(payloads[0], payloads[1])

            if findings is not None:
                card.setFindings(findings)

    def add_activity_log(self, message, level="info"):
        """Add an entry to the live activity log"""
        if hasattr(self.gui, 'live_log'):
            self.gui.live_log.add_log(message, level)

    def update_dashboard_stats(self, current_module=None, requests=None, total_requests=None, vulns=None):
        """Update the dashboard statistics"""
        if current_module:
            self.gui.current_module_dashboard.setText(current_module)

        if requests is not None or total_requests is not None:
            req = requests if requests is not None else 0
            total = total_requests if total_requests is not None else 0
            self.gui.requests_label.setText(f"{req} / {total}")
            self.gui.total_requests = req

        if vulns is not None:
            self.gui.vulns_found_label.setText(str(vulns))
            # Change color based on count
            if vulns > 0:
                self.gui.vulns_found_label.setStyleSheet("font-weight: bold; color: #f44336; font-size: 12px;")
            else:
                self.gui.vulns_found_label.setStyleSheet("font-weight: bold; color: #4CAF50; font-size: 12px;")

    def enable_controls(self, enabled=True):
        """Enable or disable scan control buttons"""
        self.gui.progress_pause_btn.setEnabled(enabled)
        self.gui.progress_stop_btn.setEnabled(enabled)
        self.gui.skip_module_btn.setEnabled(enabled)

    def reset_dashboard(self):
        """Reset the dashboard to initial state"""
        self.gui.circular_progress.setValue(0)
        self.gui.current_module_dashboard.setText("Not started")
        self.gui.requests_label.setText("0 / 0")
        self.gui.vulns_found_label.setText("0")
        self.gui.vulns_found_label.setStyleSheet("font-weight: bold; color: #4CAF50; font-size: 12px;")
        self.gui.time_remaining_dashboard.setText("Calculating...")
        self.gui.scan_start_label.setText("Not started")
        self.gui.elapsed_time_label.setText("00:00:00")
        self.gui.completion_time_label.setText("Calculating...")
        self.gui.avg_module_time_label.setText("--:--")
        self.gui.rps_label.setText("0.0")
        self.gui.total_requests = 0
        self._last_request_count = 0
        self._last_request_time = None

        # Reset pause button
        self.gui.progress_pause_btn.setText("Pause Scan")
        self.gui.progress_pause_btn.setStyleSheet("""
            QPushButton {
                background-color: #FF9800;
                color: white;
                border: none;
                border-radius: 6px;
                padding: 10px 20px;
                font-weight: bold;
                font-size: 11px;
            }
            QPushButton:hover {
                background-color: #F57C00;
            }
            QPushButton:disabled {
                background-color: #cccccc;
            }
        """)

    # Backward compatibility methods
    def update_time_display(self):
        """Backward compatibility wrapper"""
        self._update_all_displays()


# For backward compatibility with existing code that expects these attributes
def _ensure_backward_compatibility(gui):
    """Ensure backward compatibility with existing GUI code"""
    # Create placeholder tables if they don't exist
    if not hasattr(gui, 'progress_table'):
        gui.progress_table = QTableWidget(0, 2)
        gui.progress_table.setHorizontalHeaderLabels(["Item", "Status"])

    if not hasattr(gui, 'plan_table'):
        gui.plan_table = QTableWidget(0, 3)
        gui.plan_table.setHorizontalHeaderLabels(["Module", "Status", "Progress"])
