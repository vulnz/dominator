"""
Scan Wizard Dialog
A step-by-step wizard to guide users through configuring a scan.
"""

from PyQt5.QtWidgets import (
    QDialog, QVBoxLayout, QHBoxLayout, QLabel, QPushButton,
    QStackedWidget, QWidget, QLineEdit, QTextEdit, QCheckBox,
    QSpinBox, QComboBox, QGroupBox, QGridLayout, QFrame,
    QRadioButton, QButtonGroup, QProgressBar, QMessageBox,
    QScrollArea, QTableWidget, QTableWidgetItem, QHeaderView
)
from PyQt5.QtGui import QFont, QPixmap
from PyQt5.QtCore import Qt, pyqtSignal, QThread
import requests
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class ScanWizard(QDialog):
    """Step-by-step scan configuration wizard"""

    # Signal emitted when wizard is completed with configuration
    scan_configured = pyqtSignal(dict)

    def __init__(self, parent=None):
        super().__init__(parent)
        self.config = {}
        self.current_step = 0
        self.total_steps = 9  # Fixed: Was 8 but there are 9 steps (0-8)
        self.init_ui()

    def init_ui(self):
        """Initialize the wizard UI"""
        self.setWindowTitle("Scan Wizard - Dominator")
        self.setMinimumSize(700, 500)
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
            QCheckBox {
                font-size: 11px;
            }
            QComboBox {
                font-size: 11px;
            }
            QSpinBox {
                font-size: 11px;
            }
            QPushButton {
                font-size: 11px;
            }
        """)

        layout = QVBoxLayout(self)
        layout.setSpacing(15)

        # Header with progress
        header = self._create_header()
        layout.addWidget(header)

        # Stacked widget for wizard steps
        self.stack = QStackedWidget()

        # Create all steps
        self.stack.addWidget(self._create_step_welcome())      # Step 0
        self.stack.addWidget(self._create_step_target())       # Step 1
        self.stack.addWidget(self._create_step_tech_detect())  # Step 2 - Technology Detection
        self.stack.addWidget(self._create_step_scan_type())    # Step 3
        self.stack.addWidget(self._create_step_modules())      # Step 4 - Fixed: Was labeled "Step 3"
        self.stack.addWidget(self._create_step_headers())      # Step 5
        self.stack.addWidget(self._create_step_payloads())     # Step 6
        self.stack.addWidget(self._create_step_settings())     # Step 7
        self.stack.addWidget(self._create_step_confirm())      # Step 8

        layout.addWidget(self.stack)

        # Navigation buttons
        nav = self._create_navigation()
        layout.addWidget(nav)

        self.update_navigation()

    def _create_header(self):
        """Create header with title and progress bar"""
        header = QFrame()
        header.setStyleSheet("""
            QFrame {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
                    stop:0 #4CAF50, stop:1 #2196F3);
                border-radius: 8px;
                padding: 15px;
            }
        """)

        layout = QVBoxLayout(header)

        # Title
        self.step_title = QLabel("Welcome to Scan Wizard")
        self.step_title.setFont(QFont("Arial", 16, QFont.Bold))
        self.step_title.setStyleSheet("color: white;")
        layout.addWidget(self.step_title)

        # Subtitle
        self.step_subtitle = QLabel("Let's configure your scan step by step")
        self.step_subtitle.setStyleSheet("color: rgba(255, 255, 255, 0.8);")
        layout.addWidget(self.step_subtitle)

        # Progress bar
        self.progress = QProgressBar()
        self.progress.setRange(0, self.total_steps)
        self.progress.setValue(0)
        self.progress.setTextVisible(False)
        self.progress.setStyleSheet("""
            QProgressBar {
                background-color: rgba(255, 255, 255, 0.3);
                border-radius: 5px;
                height: 10px;
            }
            QProgressBar::chunk {
                background-color: white;
                border-radius: 5px;
            }
        """)
        layout.addWidget(self.progress)

        return header

    def _create_step_welcome(self):
        """Step 0: Welcome - Clean modern design"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setSpacing(20)
        layout.setContentsMargins(20, 10, 20, 10)

        # Header section
        header = QLabel("What would you like to scan?")
        header.setFont(QFont("Arial", 18, QFont.Bold))
        header.setAlignment(Qt.AlignCenter)
        header.setStyleSheet("color: #2c3e50;")
        layout.addWidget(header)

        # Subtitle
        subtitle = QLabel("Choose a scan type to get started")
        subtitle.setFont(QFont("Arial", 11))
        subtitle.setAlignment(Qt.AlignCenter)
        subtitle.setStyleSheet("color: #7f8c8d; margin-bottom: 10px;")
        layout.addWidget(subtitle)

        self.scan_mode_group = QButtonGroup()

        # Cards in horizontal layout
        cards_layout = QHBoxLayout()
        cards_layout.setSpacing(20)

        # Web Application Scan
        web_card = self._create_scan_mode_card(
            "🌐", "Web Application",
            "Scan websites for vulnerabilities like XSS, SQLi, CSRF and more",
            "web", "#27ae60"
        )
        cards_layout.addWidget(web_card)

        # API Scan
        api_card = self._create_scan_mode_card(
            "🔌", "API Testing",
            "Test REST/SOAP APIs for security issues and misconfigurations",
            "api", "#3498db"
        )
        cards_layout.addWidget(api_card)

        # GraphQL Scan
        graphql_card = self._create_scan_mode_card(
            "📊", "GraphQL",
            "Analyze GraphQL endpoints for introspection and query vulnerabilities",
            "graphql", "#9b59b6"
        )
        cards_layout.addWidget(graphql_card)

        layout.addLayout(cards_layout)

        # Spacer
        layout.addSpacing(15)

        # Steps preview - horizontal compact
        steps_frame = self._create_steps_preview()
        layout.addWidget(steps_frame)

        layout.addStretch()

        return widget

    def _create_scan_mode_card(self, icon, title, desc, value, color):
        """Create a clean scan mode card"""
        card = QFrame()
        card.setObjectName(f"card_{value}")
        card.setFixedHeight(200)
        card.setCursor(Qt.PointingHandCursor)

        if not hasattr(self, '_scan_mode_cards'):
            self._scan_mode_cards = {}

        layout = QVBoxLayout(card)
        layout.setSpacing(10)
        layout.setContentsMargins(20, 25, 20, 20)

        # Radio button (hidden but functional)
        radio = QRadioButton()
        radio.setProperty("scan_mode", value)
        radio.hide()
        self.scan_mode_group.addButton(radio)

        # Icon
        icon_lbl = QLabel(icon)
        icon_lbl.setFont(QFont("Segoe UI Emoji", 36))
        icon_lbl.setAlignment(Qt.AlignCenter)
        layout.addWidget(icon_lbl)

        # Title
        title_lbl = QLabel(title)
        title_lbl.setFont(QFont("Arial", 14, QFont.Bold))
        title_lbl.setAlignment(Qt.AlignCenter)
        layout.addWidget(title_lbl)

        # Description
        desc_lbl = QLabel(desc)
        desc_lbl.setAlignment(Qt.AlignCenter)
        desc_lbl.setWordWrap(True)
        desc_lbl.setStyleSheet("font-size: 11px;")
        layout.addWidget(desc_lbl)

        layout.addStretch()

        # Checkmark indicator
        check = QLabel("✓")
        check.setAlignment(Qt.AlignCenter)
        check.setFont(QFont("Arial", 16, QFont.Bold))
        check.setObjectName("checkmark")
        check.hide()
        layout.addWidget(check)

        self._scan_mode_cards[value] = {'card': card, 'color': color, 'check': check, 'title': title_lbl, 'desc': desc_lbl}

        def update_style(checked, c=card, col=color, chk=check, ttl=title_lbl, dsc=desc_lbl):
            if checked:
                c.setStyleSheet(f"""
                    QFrame#card_{value} {{
                        background-color: {col};
                        border: 3px solid {col};
                        border-radius: 15px;
                    }}
                    QLabel {{
                        color: white;
                        background: transparent;
                    }}
                """)
                chk.show()
            else:
                c.setStyleSheet(f"""
                    QFrame#card_{value} {{
                        background-color: #ffffff;
                        border: 2px solid #e0e0e0;
                        border-radius: 15px;
                    }}
                    QFrame#card_{value}:hover {{
                        border: 2px solid {col};
                        background-color: {col}11;
                    }}
                    QLabel {{
                        color: #2c3e50;
                        background: transparent;
                    }}
                """)
                chk.hide()

        radio.toggled.connect(update_style)
        card.mousePressEvent = lambda e, r=radio: r.setChecked(True)

        if value == "web":
            radio.setChecked(True)
            update_style(True)
        else:
            update_style(False)

        return card

    def _create_steps_preview(self):
        """Create horizontal steps preview"""
        frame = QFrame()
        frame.setStyleSheet("""
            QFrame {
                background-color: #f8f9fa;
                border-radius: 10px;
                padding: 10px;
            }
        """)

        layout = QHBoxLayout(frame)
        layout.setSpacing(5)
        layout.setContentsMargins(15, 12, 15, 12)

        steps = [
            ("🎯", "Target"),
            ("🔍", "Detect"),
            ("📦", "Modules"),
            ("🔑", "Auth"),
            ("⚙️", "Settings"),
            ("🚀", "Scan"),
        ]

        for i, (icon, name) in enumerate(steps):
            # Step container
            step = QWidget()
            step_layout = QHBoxLayout(step)
            step_layout.setContentsMargins(8, 5, 8, 5)
            step_layout.setSpacing(5)

            # Number badge
            num = QLabel(str(i + 1))
            num.setFixedSize(22, 22)
            num.setAlignment(Qt.AlignCenter)
            num.setFont(QFont("Arial", 9, QFont.Bold))
            num.setStyleSheet("""
                background-color: #3498db;
                color: white;
                border-radius: 11px;
            """)
            step_layout.addWidget(num)

            # Icon + Name
            text = QLabel(f"{icon} {name}")
            text.setStyleSheet("color: #2c3e50; font-size: 11px; font-weight: bold;")
            step_layout.addWidget(text)

            layout.addWidget(step)

            # Arrow between steps
            if i < len(steps) - 1:
                arrow = QLabel("→")
                arrow.setStyleSheet("color: #bdc3c7; font-size: 14px;")
                layout.addWidget(arrow)

        return frame

    def _create_step_target(self):
        """Step 1: Target configuration"""
        widget = QWidget()
        layout = QVBoxLayout(widget)

        # Single target
        single_group = QGroupBox("Target URL or IP")
        single_layout = QVBoxLayout()

        self.target_input = QLineEdit()
        self.target_input.setPlaceholderText("https://example.com or 192.168.1.1")
        self.target_input.setStyleSheet("""
            QLineEdit {
                padding: 10px;
                border: 1px solid #cccccc;
                border-radius: 5px;
                font-size: 14px;
            }
            QLineEdit:focus {
                border: 1px solid #4CAF50;
            }
        """)
        single_layout.addWidget(self.target_input)

        # Target type hints
        hints = QLabel(
            "Supported formats: URLs (http/https), domains, IP addresses, CIDR ranges"
        )
        hints.setStyleSheet("color: #888888; font-size: 11px;")
        single_layout.addWidget(hints)

        single_group.setLayout(single_layout)
        layout.addWidget(single_group)

        # Multiple targets
        multi_group = QGroupBox("Or Multiple Targets (one per line)")
        multi_layout = QVBoxLayout()

        self.multi_target_input = QTextEdit()
        self.multi_target_input.setPlaceholderText(
            "https://example.com\n"
            "https://api.example.com\n"
            "192.168.1.0/24"
        )
        self.multi_target_input.setMaximumHeight(100)
        self.multi_target_input.setStyleSheet("""
            QTextEdit {
                padding: 8px;
                border: 1px solid #cccccc;
                border-radius: 5px;
            }
        """)
        multi_layout.addWidget(self.multi_target_input)

        multi_group.setLayout(multi_layout)
        layout.addWidget(multi_group)

        layout.addStretch()

        return widget


    def _create_step_tech_detect(self):
        """Step 2: Technology Detection - Fingerprint the target before scanning"""
        widget = QWidget()
        layout = QVBoxLayout(widget)

        # Info label
        info = QLabel("Detect technologies before scanning to optimize module selection:")
        info.setStyleSheet("font-size: 13px; color: #666666; margin-bottom: 10px;")
        layout.addWidget(info)

        # Detect button
        btn_layout = QHBoxLayout()
        self.detect_tech_btn = QPushButton("🔍 Detect Technologies")
        self.detect_tech_btn.setStyleSheet("""
            QPushButton {
                background-color: #4CAF50;
                color: white;
                padding: 10px 20px;
                border: none;
                border-radius: 5px;
                font-size: 13px;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: #45a049;
            }
            QPushButton:disabled {
                background-color: #cccccc;
            }
        """)
        self.detect_tech_btn.clicked.connect(self._run_tech_detection)
        btn_layout.addWidget(self.detect_tech_btn)

        self.tech_status_label = QLabel("")
        self.tech_status_label.setStyleSheet("font-size: 11px; color: #666;")
        btn_layout.addWidget(self.tech_status_label)
        btn_layout.addStretch()
        layout.addLayout(btn_layout)

        # Results table
        self.tech_table = QTableWidget()
        self.tech_table.setColumnCount(4)
        self.tech_table.setHorizontalHeaderLabels(["Category", "Technology", "Version", "Source"])
        self.tech_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.tech_table.setAlternatingRowColors(True)
        self.tech_table.setStyleSheet("""
            QTableWidget {
                border: 1px solid #e0e0e0;
                border-radius: 5px;
                background-color: white;
            }
            QTableWidget::item {
                padding: 5px;
            }
            QHeaderView::section {
                background-color: #f0f0f0;
                padding: 8px;
                font-weight: bold;
                border: none;
            }
        """)
        layout.addWidget(self.tech_table)

        # Recommendation
        self.tech_recommendation = QLabel("")
        self.tech_recommendation.setWordWrap(True)
        self.tech_recommendation.setStyleSheet("""
            color: #1976D2;
            background-color: #E3F2FD;
            padding: 10px;
            border-radius: 5px;
            font-size: 11px;
        """)
        self.tech_recommendation.setVisible(False)
        layout.addWidget(self.tech_recommendation)

        # Skip option
        skip_label = QLabel("You can skip this step if you prefer to select modules manually.")
        skip_label.setStyleSheet("color: #888888; font-size: 10px; margin-top: 10px;")
        layout.addWidget(skip_label)

        return widget

    def _run_tech_detection(self):
        """Run technology detection on the target"""
        from passive_detectors.technology_detector import TechnologyDetector

        # Get target from previous step
        target = self.target_input.text().strip()
        if not target:
            targets = self.multi_target_input.toPlainText().strip().split("\n")
            target = targets[0] if targets else ""

        if not target:
            self.tech_status_label.setText("Please enter a target first!")
            self.tech_status_label.setStyleSheet("color: red;")
            return

        # Ensure URL format
        if not target.startswith(("http://", "https://")):
            target = "http://" + target

        self.detect_tech_btn.setEnabled(False)
        self.tech_status_label.setText("Detecting technologies...")
        self.tech_status_label.setStyleSheet("color: #666;")

        # Clear previous results
        self.tech_table.setRowCount(0)

        try:
            # Make request
            headers = {"User-Agent": "Dominator/1.0 (Technology Scanner)"}
            response = requests.get(target, headers=headers, timeout=10, verify=False, allow_redirects=True)

            # Get response headers as dict
            resp_headers = dict(response.headers)

            # Run technology detection
            found, technologies = TechnologyDetector.analyze(resp_headers, response.text, target)

            # Additional detection for OS, Cloud, etc.
            extra_techs = self._detect_extra_technologies(resp_headers, response.text, target)
            technologies.extend(extra_techs)

            # Deduplicate
            seen = set()
            unique_techs = []
            for tech in technologies:
                key = (tech.get("name", ""), tech.get("category", ""))
                if key not in seen:
                    seen.add(key)
                    unique_techs.append(tech)

            # Display results
            self.tech_table.setRowCount(len(unique_techs))
            for i, tech in enumerate(unique_techs):
                self.tech_table.setItem(i, 0, QTableWidgetItem(tech.get("category", "Unknown")))
                self.tech_table.setItem(i, 1, QTableWidgetItem(tech.get("name", "Unknown")))
                self.tech_table.setItem(i, 2, QTableWidgetItem(tech.get("version", "-")))
                self.tech_table.setItem(i, 3, QTableWidgetItem(tech.get("detection_method", "-")))

            # Store for module recommendations
            self._detected_technologies = unique_techs

            # Show recommendations
            self._show_tech_recommendations(unique_techs)

            self.tech_status_label.setText(f"Found {len(unique_techs)} technologies")
            self.tech_status_label.setStyleSheet("color: green;")

        except Exception as e:
            self.tech_status_label.setText(f"Detection failed: {str(e)[:50]}")
            self.tech_status_label.setStyleSheet("color: red;")

        self.detect_tech_btn.setEnabled(True)

    def _detect_extra_technologies(self, headers, content, url):
        """Detect additional technologies: OS, Cloud, etc."""
        import re as regex
        extra = []

        # Cloud providers from headers/content
        cloud_patterns = {
            r"amazonaws\.com|cloudfront\.net|elasticbeanstalk|s3\.amazonaws": ("Amazon AWS", "Cloud Provider"),
            r"azure|azurewebsites\.net|azure-dns": ("Microsoft Azure", "Cloud Provider"),
            r"googleapis\.com|appspot\.com|cloudflare": ("Google Cloud/Cloudflare", "Cloud Provider"),
            r"heroku|herokuapp\.com": ("Heroku", "Cloud Provider"),
            r"vercel\.app|vercel\.com": ("Vercel", "Cloud Provider"),
            r"netlify\.app|netlify\.com": ("Netlify", "Cloud Provider"),
        }

        # Check headers
        header_str = str(headers)
        for pattern, (name, cat) in cloud_patterns.items():
            if regex.search(pattern, header_str, regex.I) or regex.search(pattern, content, regex.I):
                extra.append({"name": name, "category": cat, "detection_method": "Header/Content Analysis"})

        # OS detection from Server header
        server = headers.get("Server", "")
        if "ubuntu" in server.lower() or "debian" in server.lower():
            extra.append({"name": "Linux (Ubuntu/Debian)", "category": "Operating System", "detection_method": "Server Header"})
        elif "win" in server.lower() or "iis" in server.lower():
            extra.append({"name": "Windows Server", "category": "Operating System", "detection_method": "Server Header"})
        elif "centos" in server.lower() or "rhel" in server.lower() or "fedora" in server.lower():
            extra.append({"name": "Linux (RHEL/CentOS)", "category": "Operating System", "detection_method": "Server Header"})

        # Additional frameworks
        if regex.search(r"laravel|illuminate", content, regex.I):
            extra.append({"name": "Laravel", "category": "PHP Framework", "detection_method": "Content Analysis"})
        if regex.search(r"symfony", content, regex.I):
            extra.append({"name": "Symfony", "category": "PHP Framework", "detection_method": "Content Analysis"})
        if regex.search(r"__next|_next/static", content, regex.I):
            extra.append({"name": "Next.js", "category": "JavaScript Framework", "detection_method": "Content Analysis"})
        if regex.search(r"tailwindcss|tailwind", content, regex.I):
            extra.append({"name": "Tailwind CSS", "category": "CSS Framework", "detection_method": "Content Analysis"})

        return extra

    def _show_tech_recommendations(self, technologies):
        """Show module recommendations based on detected technologies"""
        recommendations = []

        tech_names = [t.get("name", "").lower() for t in technologies]
        categories = [t.get("category", "").lower() for t in technologies]

        if any("php" in t for t in tech_names):
            recommendations.append("PHP detected: Enable php_object_injection, lfi modules")
        if any("wordpress" in t for t in tech_names):
            recommendations.append("WordPress: Enable dirbrute (wp-paths), xss, sqli modules")
        if any("java" in t or "tomcat" in t for t in tech_names):
            recommendations.append("Java detected: Enable xxe, ssti modules")
        if any("node" in t or "express" in t or "next.js" in t for t in tech_names):
            recommendations.append("Node.js: Enable prototype_pollution, nosql_injection modules")
        if any("mysql" in t or "postgresql" in t or "mssql" in t for t in tech_names):
            recommendations.append("Database detected: Enable sqli module with all payloads")
        if any("api" in c for c in categories):
            recommendations.append("API detected: Enable api_security, jwt_analysis modules")
        if any("cloud" in c for c in categories):
            recommendations.append("Cloud platform: Enable cloud_storage, ssrf modules")

        if recommendations:
            self.tech_recommendation.setText("💡 Recommendations:\n" + "\n".join(recommendations))
            self.tech_recommendation.setVisible(True)
        else:
            self.tech_recommendation.setVisible(False)

    def _create_step_scan_type(self):
        """Step 2: Scan type selection"""
        widget = QWidget()
        layout = QVBoxLayout(widget)

        info = QLabel("Select the type of scan you want to perform:")
        info.setStyleSheet("font-size: 13px; color: #666666; margin-bottom: 10px;")
        layout.addWidget(info)

        # Scan type options
        self.scan_type_group = QButtonGroup()

        # Quick Scan
        quick = self._create_scan_type_card(
            "⚡", "Quick Scan",
            "Fast scan with essential security checks.\nBest for initial assessment.",
            "quick"
        )
        layout.addWidget(quick)

        # Standard Scan
        standard = self._create_scan_type_card(
            "🔍", "Standard Scan",
            "Comprehensive scan with all common vulnerability checks.\nRecommended for most cases.",
            "standard"
        )
        layout.addWidget(standard)

        # Full Scan
        full = self._create_scan_type_card(
            "🔬", "Full Scan",
            "Deep scan with all modules and extensive testing.\nMay take longer but very thorough.",
            "full"
        )
        layout.addWidget(full)

        # Custom Scan
        custom = self._create_scan_type_card(
            "⚙️", "Custom Scan",
            "Configure your own module selection and settings.\nFor advanced users.",
            "custom"
        )
        layout.addWidget(custom)

        layout.addStretch()

        return widget

    def _create_scan_type_card(self, icon, title, description, value):
        """Create a scan type selection card"""
        card = QFrame()
        card.setStyleSheet("""
            QFrame {
                background-color: #f8f8f8;
                border: 2px solid #e0e0e0;
                border-radius: 8px;
                padding: 10px;
            }
            QFrame:hover {
                border-color: #4CAF50;
                background-color: #f0f8f0;
            }
        """)

        layout = QHBoxLayout(card)

        # Radio button
        radio = QRadioButton()
        radio.setProperty("scan_type", value)
        self.scan_type_group.addButton(radio)
        if value == "standard":
            radio.setChecked(True)
        layout.addWidget(radio)

        # Icon
        icon_label = QLabel(icon)
        icon_label.setFont(QFont("Segoe UI Emoji", 24))
        layout.addWidget(icon_label)

        # Text
        text_layout = QVBoxLayout()
        title_label = QLabel(title)
        title_label.setFont(QFont("Arial", 12, QFont.Bold))
        text_layout.addWidget(title_label)

        desc_label = QLabel(description)
        desc_label.setStyleSheet("color: #666666; font-size: 11px;")
        text_layout.addWidget(desc_label)

        layout.addLayout(text_layout)
        layout.addStretch()

        return card

    def _load_modules_dynamically(self):
        """Load all modules from modules/ directory"""
        from pathlib import Path
        modules = {}

        script_dir = Path(__file__).parent.parent.parent
        modules_dir = script_dir / "modules"

        if not modules_dir.exists():
            return modules

        CATEGORY_MAP = {
            "sqli": "Injection", "xss": "Injection", "cmdi": "Injection", "ssti": "Injection",
            "xxe": "Injection", "xpath": "Injection", "nosql": "Injection", "crlf": "Injection",
            "header_injection": "Injection", "formula": "Injection", "ssi": "Injection",
            "lfi": "File & Path", "rfi": "File & Path", "file_upload": "File & Path",
            "csrf": "Auth & Session", "session": "Auth & Session", "jwt": "Auth & Session",
            "weak_credentials": "Auth & Session", "idor": "Auth & Session",
            "api": "API Security", "graphql": "API Security", "websocket": "API Security",
            "dirbrute": "Recon", "subdomain": "Recon", "port": "Recon", "param": "Recon",
            "favicon": "Recon", "robots": "Recon",
            "git": "Info Disclosure", "env": "Info Disclosure", "backup": "Info Disclosure",
            "config": "Info Disclosure", "debug": "Info Disclosure", "package": "Info Disclosure",
            "base64": "Info Disclosure", "sensitive": "Info Disclosure",
            "ssrf": "Server & Network", "redirect": "Server & Network", "smuggling": "Server & Network",
            "host_header": "Server & Network", "cors": "Server & Network", "http_methods": "Server & Network",
            "forbidden": "Server & Network", "cgi": "Server & Network", "hpp": "Server & Network",
            "ssl": "Security Config", "security_headers": "Security Config", "csp": "Security Config",
            "tabnabbing": "Security Config", "cspt": "Security Config",
            "dom_xss": "Advanced", "prototype": "Advanced", "php_object": "Advanced",
            "type_juggling": "Advanced", "request_smuggling": "Advanced",
            "cloud": "Cloud", "storage": "Cloud",
        }

        for module_path in sorted(modules_dir.iterdir()):
            if not module_path.is_dir() or module_path.name.startswith('_'):
                continue
            if module_path.name in ['oob_detection']:
                continue

            module_id = module_path.name
            name = module_id.replace('_', ' ').title()
            category = "Other"

            # Try to load config
            toml_file = module_path / "config.toml"
            json_file = module_path / "config.json"

            if toml_file.exists():
                try:
                    import tomllib
                    with open(toml_file, 'rb') as f:
                        config = tomllib.load(f)
                    name = config.get('module', {}).get('name', name)
                    category = config.get('module', {}).get('category', category)
                except:
                    pass
            elif json_file.exists():
                try:
                    import json
                    with open(json_file, 'r') as f:
                        config = json.load(f)
                    name = config.get('name', name)
                    category = config.get('category', category)
                except:
                    pass

            # Auto-detect category from module name
            if category == "Other":
                for key, cat in CATEGORY_MAP.items():
                    if key in module_id.lower():
                        category = cat
                        break

            modules[module_id] = {'name': name, 'category': category}

        return modules

    def _create_step_modules(self):
        """Step 3: Module selection - Dynamic loading"""
        widget = QWidget()
        layout = QVBoxLayout(widget)

        # Load modules dynamically
        all_modules = self._load_modules_dynamically()
        total_count = len(all_modules)

        info = QLabel(f"Select the security modules to run ({total_count} available):")
        info.setStyleSheet("font-size: 13px; color: #666666; margin-bottom: 10px;")
        layout.addWidget(info)

        # Create scroll area for modules
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setStyleSheet("""
            QScrollArea {
                border: none;
                background-color: transparent;
            }
        """)

        scroll_content = QWidget()
        scroll_layout = QVBoxLayout(scroll_content)

        # Group modules by category
        categories = {}
        for mid, info_data in all_modules.items():
            cat = info_data.get('category', 'Other')
            if cat not in categories:
                categories[cat] = []
            categories[cat].append((mid, info_data['name']))

        # Category order and styles
        CATEGORY_ORDER = ["Injection", "File & Path", "Auth & Session", "API Security",
                         "Recon", "Info Disclosure", "Server & Network", "Security Config",
                         "Advanced", "Cloud", "Other"]

        CATEGORY_STYLES = {
            "Injection": {"icon": "💉", "color": "#e74c3c"},
            "File & Path": {"icon": "📁", "color": "#e67e22"},
            "Auth & Session": {"icon": "🔑", "color": "#9b59b6"},
            "API Security": {"icon": "🔌", "color": "#3498db"},
            "Recon": {"icon": "🔍", "color": "#27ae60"},
            "Info Disclosure": {"icon": "📦", "color": "#f39c12"},
            "Server & Network": {"icon": "🌐", "color": "#1abc9c"},
            "Security Config": {"icon": "🛡️", "color": "#795548"},
            "Advanced": {"icon": "⚡", "color": "#c0392b"},
            "Cloud": {"icon": "☁️", "color": "#2980b9"},
            "Other": {"icon": "🔧", "color": "#7f8c8d"},
        }

        self.module_checkboxes = {}

        for cat_name in CATEGORY_ORDER:
            if cat_name not in categories:
                continue

            modules_in_cat = categories[cat_name]
            style = CATEGORY_STYLES.get(cat_name, CATEGORY_STYLES["Other"])

            group = QGroupBox(f"{style['icon']} {cat_name} ({len(modules_in_cat)})")
            group.setStyleSheet(f"""
                QGroupBox {{
                    font-size: 12px;
                    font-weight: bold;
                    color: {style['color']};
                    border: 1px solid {style['color']}44;
                    border-radius: 5px;
                    margin-top: 8px;
                    padding-top: 8px;
                }}
                QGroupBox::title {{
                    subcontrol-origin: margin;
                    left: 10px;
                    padding: 0 5px;
                }}
            """)
            grid = QGridLayout()
            grid.setSpacing(5)

            for i, (mid, name) in enumerate(sorted(modules_in_cat, key=lambda x: x[1])):
                cb = QCheckBox(name)
                cb.setChecked(True)  # All enabled by default
                cb.setStyleSheet("font-size: 11px;")
                cb.setToolTip(f"Module: {mid}")
                self.module_checkboxes[mid] = cb
                grid.addWidget(cb, i // 3, i % 3)

            group.setLayout(grid)
            scroll_layout.addWidget(group)

        scroll.setWidget(scroll_content)
        layout.addWidget(scroll)

        # Select all / none
        btn_layout = QHBoxLayout()

        select_all = QPushButton(f"Select All ({total_count})")
        select_all.setStyleSheet("font-size: 11px; padding: 5px 10px;")
        select_all.clicked.connect(lambda: self._toggle_all_modules(True))
        btn_layout.addWidget(select_all)

        select_none = QPushButton("Select None")
        select_none.setStyleSheet("font-size: 11px; padding: 5px 10px;")
        select_none.clicked.connect(lambda: self._toggle_all_modules(False))
        btn_layout.addWidget(select_none)

        btn_layout.addStretch()

        # Module count label
        self.module_count_label = QLabel(f"Selected: {total_count}/{total_count}")
        self.module_count_label.setStyleSheet("font-size: 11px; color: #666666;")
        self._total_modules = total_count
        btn_layout.addWidget(self.module_count_label)

        layout.addLayout(btn_layout)

        # Connect checkboxes to update count
        for cb in self.module_checkboxes.values():
            cb.stateChanged.connect(self._update_module_count)

        return widget

    def _update_module_count(self):
        """Update the selected module count label"""
        count = sum(1 for cb in self.module_checkboxes.values() if cb.isChecked())
        total = getattr(self, '_total_modules', len(self.module_checkboxes))
        if hasattr(self, 'module_count_label'):
            self.module_count_label.setText(f"Selected: {count}/{total}")

    def _toggle_all_modules(self, checked):
        """Toggle all module checkboxes"""
        for cb in self.module_checkboxes.values():
            cb.setChecked(checked)
        self._update_module_count()

    def _create_step_headers(self):
        """Step 4: Headers, Cookies, and Authentication settings"""
        widget = QWidget()
        layout = QVBoxLayout(widget)

        info = QLabel("Configure custom headers, cookies, and authentication:")
        info.setStyleSheet("font-size: 13px; color: #666666; margin-bottom: 10px;")
        layout.addWidget(info)

        # Custom Headers
        headers_group = QGroupBox("Custom Headers")
        headers_layout = QVBoxLayout()

        self.headers_input = QTextEdit()
        self.headers_input.setPlaceholderText(
            "Header-Name: Header-Value\n"
            "Authorization: Bearer <token>\n"
            "X-Custom-Header: value"
        )
        self.headers_input.setMaximumHeight(80)
        self.headers_input.setStyleSheet("""
            QTextEdit {
                padding: 8px;
                border: 1px solid #cccccc;
                border-radius: 5px;
                font-size: 11px;
                font-family: 'Consolas', monospace;
            }
        """)
        headers_layout.addWidget(self.headers_input)

        headers_hint = QLabel("One header per line in 'Name: Value' format")
        headers_hint.setStyleSheet("color: #888888; font-size: 11px;")
        headers_layout.addWidget(headers_hint)

        headers_group.setLayout(headers_layout)
        layout.addWidget(headers_group)

        # Cookies
        cookies_group = QGroupBox("Cookies")
        cookies_layout = QVBoxLayout()

        self.cookies_input = QTextEdit()
        self.cookies_input.setPlaceholderText(
            "session=abc123; token=xyz789; user_id=12345"
        )
        self.cookies_input.setMaximumHeight(60)
        self.cookies_input.setStyleSheet("""
            QTextEdit {
                padding: 8px;
                border: 1px solid #cccccc;
                border-radius: 5px;
                font-size: 11px;
                font-family: 'Consolas', monospace;
            }
        """)
        cookies_layout.addWidget(self.cookies_input)

        cookies_hint = QLabel("Enter cookies in 'name=value; name2=value2' format")
        cookies_hint.setStyleSheet("color: #888888; font-size: 11px;")
        cookies_layout.addWidget(cookies_hint)

        cookies_group.setLayout(cookies_layout)
        layout.addWidget(cookies_group)

        # Authentication
        auth_group = QGroupBox("Authentication")
        auth_layout = QGridLayout()

        # Auth type
        auth_layout.addWidget(QLabel("Type:"), 0, 0)
        self.auth_type_combo = QComboBox()
        self.auth_type_combo.addItems(["None", "Basic Auth", "Bearer Token", "API Key"])
        self.auth_type_combo.setStyleSheet("font-size: 11px;")
        auth_layout.addWidget(self.auth_type_combo, 0, 1)

        # Username
        auth_layout.addWidget(QLabel("Username:"), 1, 0)
        self.auth_username = QLineEdit()
        self.auth_username.setPlaceholderText("Username or API key name")
        self.auth_username.setStyleSheet("font-size: 11px; padding: 5px;")
        auth_layout.addWidget(self.auth_username, 1, 1)

        # Password/Token
        auth_layout.addWidget(QLabel("Password/Token:"), 2, 0)
        self.auth_password = QLineEdit()
        self.auth_password.setPlaceholderText("Password or token value")
        self.auth_password.setEchoMode(QLineEdit.Password)
        self.auth_password.setStyleSheet("font-size: 11px; padding: 5px;")
        auth_layout.addWidget(self.auth_password, 2, 1)

        auth_group.setLayout(auth_layout)
        layout.addWidget(auth_group)

        layout.addStretch()

        return widget

    def _create_step_payloads(self):
        """Step 5: Super Advanced - Custom Payloads"""
        widget = QWidget()
        layout = QVBoxLayout(widget)

        info = QLabel("Super Advanced: Customize payloads for each module:")
        info.setStyleSheet("font-size: 13px; color: #666666; margin-bottom: 10px;")
        layout.addWidget(info)

        # Warning about advanced usage
        warning = QLabel(
            "Warning: Only modify payloads if you understand their purpose. "
            "Invalid payloads may cause scan failures or incomplete results."
        )
        warning.setStyleSheet("""
            color: #FF9800;
            background-color: #FFF3E0;
            padding: 8px;
            border-radius: 5px;
            font-size: 11px;
        """)
        warning.setWordWrap(True)
        layout.addWidget(warning)

        # Module selector
        selector_layout = QHBoxLayout()
        selector_layout.addWidget(QLabel("Select Module:"))

        self.payload_module_combo = QComboBox()
        self.payload_module_combo.addItems([
            "sqli - SQL Injection",
            "xss - Cross-Site Scripting",
            "cmdi - Command Injection",
            "ssti - Template Injection",
            "lfi - Local File Inclusion",
            "rfi - Remote File Inclusion",
            "ssrf - Server-Side Request Forgery",
            "xxe - XML External Entity",
        ])
        self.payload_module_combo.setStyleSheet("font-size: 11px;")
        selector_layout.addWidget(self.payload_module_combo)
        selector_layout.addStretch()

        layout.addLayout(selector_layout)

        # Payload editor
        payload_group = QGroupBox("Custom Payloads (one per line)")
        payload_layout = QVBoxLayout()

        self.payloads_input = QTextEdit()
        self.payloads_input.setPlaceholderText(
            "Enter custom payloads here, one per line.\n"
            "Leave empty to use default payloads.\n\n"
            "Example SQL Injection payloads:\n"
            "' OR '1'='1\n"
            "' UNION SELECT NULL--\n"
            "1; DROP TABLE users--"
        )
        self.payloads_input.setStyleSheet("""
            QTextEdit {
                padding: 8px;
                border: 1px solid #cccccc;
                border-radius: 5px;
                font-size: 11px;
                font-family: 'Consolas', monospace;
            }
        """)
        payload_layout.addWidget(self.payloads_input)

        payload_group.setLayout(payload_layout)
        layout.addWidget(payload_group)

        # Options
        options_layout = QHBoxLayout()

        self.append_payloads_cb = QCheckBox("Append to default payloads")
        self.append_payloads_cb.setChecked(True)
        self.append_payloads_cb.setStyleSheet("font-size: 11px;")
        options_layout.addWidget(self.append_payloads_cb)

        self.encode_payloads_cb = QCheckBox("URL encode payloads")
        self.encode_payloads_cb.setStyleSheet("font-size: 11px;")
        options_layout.addWidget(self.encode_payloads_cb)

        options_layout.addStretch()
        layout.addLayout(options_layout)

        return widget

    def _create_step_settings(self):
        """Step 6: Performance settings"""
        widget = QWidget()
        layout = QVBoxLayout(widget)

        # Threading & Performance
        thread_group = QGroupBox("Performance")
        thread_layout = QGridLayout()

        thread_layout.addWidget(QLabel("Threads:"), 0, 0)
        self.threads_spin = QSpinBox()
        self.threads_spin.setRange(1, 50)
        self.threads_spin.setValue(10)
        self.threads_spin.setToolTip("Number of concurrent threads for scanning")
        thread_layout.addWidget(self.threads_spin, 0, 1)

        thread_layout.addWidget(QLabel("Request Timeout (s):"), 0, 2)
        self.timeout_spin = QSpinBox()
        self.timeout_spin.setRange(5, 300)
        self.timeout_spin.setValue(15)
        self.timeout_spin.setToolTip("Timeout for each HTTP request in seconds")
        thread_layout.addWidget(self.timeout_spin, 0, 3)

        thread_group.setLayout(thread_layout)
        layout.addWidget(thread_group)

        # Time Limit Section
        time_group = QGroupBox("⏱️ Scan Time Limit")
        time_layout = QVBoxLayout()

        # Enable time limit checkbox
        self.enable_time_limit_cb = QCheckBox("Enable scan time limit")
        self.enable_time_limit_cb.setChecked(True)
        self.enable_time_limit_cb.setToolTip("Stop scan after specified time to prevent long-running scans")
        self.enable_time_limit_cb.stateChanged.connect(self._toggle_time_limit)
        time_layout.addWidget(self.enable_time_limit_cb)

        # Time limit controls
        self.time_limit_widget = QWidget()
        time_limit_layout = QHBoxLayout(self.time_limit_widget)
        time_limit_layout.setContentsMargins(20, 5, 0, 5)

        time_limit_layout.addWidget(QLabel("Maximum scan time:"))
        self.max_time_spin = QSpinBox()
        self.max_time_spin.setRange(1, 1440)  # 1 min to 24 hours
        self.max_time_spin.setValue(45)
        self.max_time_spin.setSuffix(" minutes")
        self.max_time_spin.setToolTip("Scan will stop after this duration")
        time_limit_layout.addWidget(self.max_time_spin)

        # Quick time presets
        time_limit_layout.addWidget(QLabel("  Presets:"))
        preset_15 = QPushButton("15m")
        preset_15.setFixedWidth(40)
        preset_15.clicked.connect(lambda: self.max_time_spin.setValue(15))
        time_limit_layout.addWidget(preset_15)

        preset_30 = QPushButton("30m")
        preset_30.setFixedWidth(40)
        preset_30.clicked.connect(lambda: self.max_time_spin.setValue(30))
        time_limit_layout.addWidget(preset_30)

        preset_60 = QPushButton("1h")
        preset_60.setFixedWidth(40)
        preset_60.clicked.connect(lambda: self.max_time_spin.setValue(60))
        time_limit_layout.addWidget(preset_60)

        preset_120 = QPushButton("2h")
        preset_120.setFixedWidth(40)
        preset_120.clicked.connect(lambda: self.max_time_spin.setValue(120))
        time_limit_layout.addWidget(preset_120)

        time_limit_layout.addStretch()
        time_layout.addWidget(self.time_limit_widget)

        time_group.setLayout(time_layout)
        layout.addWidget(time_group)

        # Subdomain Scanning Section
        subdomain_group = QGroupBox("🌐 Subdomain Scanning")
        subdomain_layout = QVBoxLayout()

        # Enable subdomain enumeration
        self.enum_subdomains_cb = QCheckBox("Enumerate subdomains before scanning")
        self.enum_subdomains_cb.setToolTip("Discover subdomains using passive techniques (crt.sh, DNS, etc.)")
        self.enum_subdomains_cb.stateChanged.connect(self._toggle_subdomain_options)
        subdomain_layout.addWidget(self.enum_subdomains_cb)

        # Subdomain options (hidden by default)
        self.subdomain_options_widget = QWidget()
        subdomain_options_layout = QGridLayout(self.subdomain_options_widget)
        subdomain_options_layout.setContentsMargins(20, 5, 0, 5)

        # Scan subdomains checkbox
        self.scan_subdomains_cb = QCheckBox("Also scan discovered subdomains")
        self.scan_subdomains_cb.setToolTip("Run vulnerability scans on discovered subdomains")
        subdomain_options_layout.addWidget(self.scan_subdomains_cb, 0, 0, 1, 2)

        # Subdomain limit
        subdomain_options_layout.addWidget(QLabel("Max subdomains to scan:"), 1, 0)
        self.subdomain_limit_spin = QSpinBox()
        self.subdomain_limit_spin.setRange(1, 100)
        self.subdomain_limit_spin.setValue(10)
        self.subdomain_limit_spin.setToolTip("Limit the number of subdomains to scan (to control scan time)")
        subdomain_options_layout.addWidget(self.subdomain_limit_spin, 1, 1)

        # Subdomain takeover check
        self.subdomain_takeover_cb = QCheckBox("Check for subdomain takeover vulnerabilities")
        self.subdomain_takeover_cb.setToolTip("Test if discovered subdomains are vulnerable to takeover")
        subdomain_options_layout.addWidget(self.subdomain_takeover_cb, 2, 0, 1, 2)

        self.subdomain_options_widget.setVisible(False)
        subdomain_layout.addWidget(self.subdomain_options_widget)

        subdomain_group.setLayout(subdomain_layout)
        layout.addWidget(subdomain_group)

        # Output format
        output_group = QGroupBox("Output")
        output_layout = QHBoxLayout()

        output_layout.addWidget(QLabel("Report Format:"))
        self.format_combo = QComboBox()
        self.format_combo.addItems(["HTML", "JSON", "TXT", "All Formats"])
        self.format_combo.setCurrentIndex(3)
        output_layout.addWidget(self.format_combo)

        output_layout.addStretch()

        output_group.setLayout(output_layout)
        layout.addWidget(output_group)

        # Options
        options_group = QGroupBox("Options")
        options_layout = QVBoxLayout()

        self.verbose_cb = QCheckBox("Verbose output")
        options_layout.addWidget(self.verbose_cb)

        self.follow_redirects_cb = QCheckBox("Follow redirects")
        self.follow_redirects_cb.setChecked(True)
        options_layout.addWidget(self.follow_redirects_cb)

        options_group.setLayout(options_layout)
        layout.addWidget(options_group)

        layout.addStretch()

        return widget

    def _toggle_time_limit(self, state):
        """Toggle time limit options visibility"""
        self.time_limit_widget.setEnabled(state == Qt.Checked)

    def _toggle_subdomain_options(self, state):
        """Toggle subdomain options visibility"""
        self.subdomain_options_widget.setVisible(state == Qt.Checked)

    def _create_step_confirm(self):
        """Step 5: Confirmation"""
        widget = QWidget()
        layout = QVBoxLayout(widget)

        # Summary
        self.summary_label = QTextEdit()
        self.summary_label.setReadOnly(True)
        self.summary_label.setStyleSheet("""
            QTextEdit {
                background-color: #f8f8f8;
                border: 1px solid #e0e0e0;
                border-radius: 5px;
                padding: 15px;
                font-family: 'Consolas', monospace;
            }
        """)
        layout.addWidget(self.summary_label)

        # Schedule option
        schedule_group = QGroupBox("Schedule Option")
        schedule_layout = QVBoxLayout()

        self.schedule_instead_cb = QCheckBox("Schedule this scan instead of running now")
        self.schedule_instead_cb.setStyleSheet("font-size: 12px;")
        self.schedule_instead_cb.stateChanged.connect(self._toggle_schedule_options)
        schedule_layout.addWidget(self.schedule_instead_cb)

        # Schedule time picker (hidden by default)
        self.schedule_options_widget = QWidget()
        schedule_options_layout = QHBoxLayout(self.schedule_options_widget)
        schedule_options_layout.setContentsMargins(20, 5, 0, 5)

        schedule_options_layout.addWidget(QLabel("Schedule for:"))

        from PyQt5.QtWidgets import QDateTimeEdit
        from PyQt5.QtCore import QDateTime
        self.schedule_datetime = QDateTimeEdit()
        self.schedule_datetime.setDateTime(QDateTime.currentDateTime().addSecs(3600))
        self.schedule_datetime.setCalendarPopup(True)
        self.schedule_datetime.setStyleSheet("padding: 5px;")
        schedule_options_layout.addWidget(self.schedule_datetime)

        schedule_options_layout.addStretch()
        self.schedule_options_widget.setVisible(False)
        schedule_layout.addWidget(self.schedule_options_widget)

        schedule_group.setLayout(schedule_layout)
        layout.addWidget(schedule_group)

        # Warning
        warning = QLabel(
            "Important: Only scan targets you have permission to test. "
            "Unauthorized scanning may be illegal."
        )
        warning.setStyleSheet("""
            color: #FF9800;
            background-color: #FFF3E0;
            padding: 10px;
            border-radius: 5px;
            font-size: 11px;
        """)
        warning.setWordWrap(True)
        layout.addWidget(warning)

        return widget

    def _toggle_schedule_options(self, state):
        """Toggle visibility of schedule options"""
        self.schedule_options_widget.setVisible(state == Qt.Checked)
        if state == Qt.Checked:
            self.next_btn.setText("Schedule Scan")
        else:
            self.next_btn.setText("Start Scan")

    def _create_navigation(self):
        """Create navigation buttons"""
        nav = QFrame()
        nav.setStyleSheet("""
            QFrame {
                background-color: #f0f0f0;
                border-radius: 5px;
                padding: 10px;
            }
        """)

        layout = QHBoxLayout(nav)

        # Cancel button
        self.cancel_btn = QPushButton("Cancel")
        self.cancel_btn.clicked.connect(self.reject)
        layout.addWidget(self.cancel_btn)

        layout.addStretch()

        # Back button
        self.back_btn = QPushButton("◀ Back")
        self.back_btn.clicked.connect(self.go_back)
        layout.addWidget(self.back_btn)

        # Next button
        self.next_btn = QPushButton("Next ▶")
        self.next_btn.setStyleSheet("""
            QPushButton {
                background-color: #4CAF50;
                color: white;
                padding: 8px 20px;
                border-radius: 5px;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: #45a049;
            }
        """)
        self.next_btn.clicked.connect(self.go_next)
        layout.addWidget(self.next_btn)

        return nav

    def update_navigation(self):
        """Update navigation button states"""
        self.back_btn.setEnabled(self.current_step > 0)

        if self.current_step == self.total_steps:
            self.next_btn.setText("🚀 Start Scan")
        else:
            self.next_btn.setText("Next ▶")

        # Update progress
        self.progress.setValue(self.current_step)

        # Update header
        titles = [
            ("🎯 Select Scan Type", "Choose your scan mode and see the roadmap"),
            ("Step 1: Target", "Enter the target URL or IP address to scan"),
            ("Step 2: Technology Detection", "Fingerprint the target to optimize scanning"),
            ("Step 3: Scan Type", "Choose the depth of scan to perform"),
            ("Step 4: Modules", "Select security modules to run"),
            ("Step 5: Headers & Auth", "Configure headers, cookies, and authentication"),
            ("Step 6: Custom Payloads", "Super Advanced - Add or modify payloads"),
            ("Step 7: Settings", "Configure performance and output settings"),
            ("Step 8: Confirm", "Review your configuration and start scanning"),
        ]

        if self.current_step < len(titles):
            self.step_title.setText(titles[self.current_step][0])
            self.step_subtitle.setText(titles[self.current_step][1])

    def go_back(self):
        """Go to previous step"""
        if self.current_step > 0:
            self.current_step -= 1
            self.stack.setCurrentIndex(self.current_step)
            self.update_navigation()

    def go_next(self):
        """Go to next step or finish"""
        # Validate current step
        if not self.validate_current_step():
            return

        if self.current_step < self.total_steps:
            self.current_step += 1
            self.stack.setCurrentIndex(self.current_step)
            self.update_navigation()

            # Update summary on last step
            if self.current_step == self.total_steps:
                self.update_summary()
        else:
            # Finish wizard
            self.finish_wizard()

    def validate_current_step(self):
        """Validate the current step"""
        if self.current_step == 1:  # Target step
            target = self.target_input.text().strip()
            multi = self.multi_target_input.toPlainText().strip()

            if not target and not multi:
                QMessageBox.warning(
                    self, "Validation Error",
                    "Please enter at least one target URL or IP address."
                )
                return False

        # FIXED: Validate module selection on modules step (step 4)
        if self.current_step == 4:  # Modules step
            selected_count = sum(1 for cb in self.module_checkboxes.values() if cb.isChecked())
            if selected_count == 0:
                QMessageBox.warning(
                    self, "No Modules Selected",
                    "Please select at least one security module to scan with.\n\n"
                    "Scanning without modules will produce no results."
                )
                return False

        return True

    def update_summary(self):
        """Update the summary text"""
        target = self.target_input.text().strip()
        if not target:
            target = self.multi_target_input.toPlainText().strip().split('\n')[0]

        # Get scan mode (web/api/graphql)
        scan_mode = "web"
        scan_mode_display = "Web Application"
        for btn in self.scan_mode_group.buttons():
            if btn.isChecked():
                scan_mode = btn.property("scan_mode")
                if scan_mode == "api":
                    scan_mode_display = "API Scan"
                elif scan_mode == "graphql":
                    scan_mode_display = "GraphQL"
                break

        # Get scan type (quick/standard/full/custom)
        scan_type = "standard"
        for btn in self.scan_type_group.buttons():
            if btn.isChecked():
                scan_type = btn.property("scan_type")
                break

        # Get selected modules
        selected_modules = [
            name for name, cb in self.module_checkboxes.items()
            if cb.isChecked()
        ]

        # Check for custom headers
        has_headers = bool(self.headers_input.toPlainText().strip())
        has_cookies = bool(self.cookies_input.toPlainText().strip())
        has_auth = self.auth_type_combo.currentText() != "None"
        has_payloads = bool(self.payloads_input.toPlainText().strip())

        # Time limit
        time_limit_enabled = self.enable_time_limit_cb.isChecked()
        time_limit_str = f"{self.max_time_spin.value()} minutes" if time_limit_enabled else "No limit"

        # Subdomain settings
        enum_subdomains = self.enum_subdomains_cb.isChecked()
        scan_subdomains = self.scan_subdomains_cb.isChecked() if enum_subdomains else False
        subdomain_limit = self.subdomain_limit_spin.value() if enum_subdomains else 0
        subdomain_takeover = self.subdomain_takeover_cb.isChecked() if enum_subdomains else False

        # Mode icons
        mode_icons = {"web": "🌐", "api": "🔌", "graphql": "📊"}

        # Build subdomain section
        subdomain_section = ""
        if enum_subdomains:
            subdomain_section = f"""
Subdomain Scanning:
   - Enumerate subdomains: Yes
   - Scan subdomains: {'Yes (max ' + str(subdomain_limit) + ')' if scan_subdomains else 'No'}
   - Takeover check: {'Yes' if subdomain_takeover else 'No'}
"""
        else:
            subdomain_section = """
Subdomain Scanning: Disabled
"""

        summary = f"""SCAN CONFIGURATION SUMMARY
{'='*40}

{mode_icons.get(scan_mode, '🌐')} Scan Mode: {scan_mode_display}

Target: {target}

Scan Type: {scan_type.upper()}

Modules ({len(selected_modules)}/{len(self.module_checkboxes)}):
   {', '.join(selected_modules[:10]) if selected_modules else 'None selected'}
   {'... and ' + str(len(selected_modules) - 10) + ' more' if len(selected_modules) > 10 else ''}

Authentication:
   - Custom Headers: {'Yes' if has_headers else 'No'}
   - Cookies: {'Yes' if has_cookies else 'No'}
   - Auth Type: {self.auth_type_combo.currentText()}

Advanced:
   - Custom Payloads: {'Yes' if has_payloads else 'No (using defaults)'}

Performance:
   - Threads: {self.threads_spin.value()}
   - Request Timeout: {self.timeout_spin.value()}s
   - Time Limit: {time_limit_str}
{subdomain_section}
Output Format: {self.format_combo.currentText()}

{'='*40}
Ready to start scan!
"""
        self.summary_label.setPlainText(summary)

    def finish_wizard(self):
        """Finish the wizard and emit configuration"""
        # Collect all configuration
        target = self.target_input.text().strip()
        multi_targets = self.multi_target_input.toPlainText().strip()

        # Auto-fix URLs missing scheme (http:// or https://)
        if target and not target.startswith(('http://', 'https://')):
            original_target = target
            target = f'https://{target}'
            print(f"[*] Wizard: Auto-fixed URL: '{original_target}' -> '{target}'")

        # Fix multi-targets too
        if multi_targets:
            fixed_multi = []
            for t in multi_targets.split('\n'):
                t = t.strip()
                if t and not t.startswith(('http://', 'https://')):
                    original = t
                    t = f'https://{t}'
                    print(f"[*] Wizard: Auto-fixed URL: '{original}' -> '{t}'")
                if t:
                    fixed_multi.append(t)
            multi_targets = '\n'.join(fixed_multi)

        # Get scan mode (web/api/graphql)
        scan_mode = "web"
        for btn in self.scan_mode_group.buttons():
            if btn.isChecked():
                scan_mode = btn.property("scan_mode")
                break

        # Get scan type (quick/standard/full/custom)
        scan_type = "standard"
        for btn in self.scan_type_group.buttons():
            if btn.isChecked():
                scan_type = btn.property("scan_type")
                break

        selected_modules = [
            name for name, cb in self.module_checkboxes.items()
            if cb.isChecked()
        ]

        # Parse custom headers
        headers = {}
        headers_text = self.headers_input.toPlainText().strip()
        if headers_text:
            for line in headers_text.split('\n'):
                if ':' in line:
                    key, value = line.split(':', 1)
                    headers[key.strip()] = value.strip()

        # Parse custom payloads
        custom_payloads = {}
        payloads_text = self.payloads_input.toPlainText().strip()
        if payloads_text:
            module_key = self.payload_module_combo.currentText().split(' - ')[0]
            custom_payloads[module_key] = payloads_text.split('\n')

        # Time limit settings
        time_limit_enabled = self.enable_time_limit_cb.isChecked()
        max_time = self.max_time_spin.value() if time_limit_enabled else 0  # 0 = no limit

        # Subdomain settings
        enum_subdomains = self.enum_subdomains_cb.isChecked()
        scan_subdomains = self.scan_subdomains_cb.isChecked() if enum_subdomains else False
        subdomain_limit = self.subdomain_limit_spin.value() if enum_subdomains else 10
        subdomain_takeover = self.subdomain_takeover_cb.isChecked() if enum_subdomains else False

        self.config = {
            'target': target if target else multi_targets.split('\n')[0],
            'targets': multi_targets.split('\n') if multi_targets else [target],
            'scan_mode': scan_mode,  # web, api, or graphql
            'scan_type': scan_type,
            'modules': selected_modules,
            'threads': self.threads_spin.value(),
            'timeout': self.timeout_spin.value(),
            'format': self.format_combo.currentText().lower(),
            'verbose': self.verbose_cb.isChecked(),
            'follow_redirects': self.follow_redirects_cb.isChecked(),
            # Time limit options
            'time_limit_enabled': time_limit_enabled,
            'max_time': max_time,  # in minutes, 0 = no limit
            # Subdomain options
            'enum_subdomains': enum_subdomains,
            'scan_subdomains': scan_subdomains,
            'subdomain_limit': subdomain_limit,
            'subdomain_takeover': subdomain_takeover,
            # Auth options
            'custom_headers': headers,
            'cookies': self.cookies_input.toPlainText().strip(),
            'auth_type': self.auth_type_combo.currentText(),
            'auth_username': self.auth_username.text().strip(),
            'auth_password': self.auth_password.text(),
            'custom_payloads': custom_payloads,
            'append_payloads': self.append_payloads_cb.isChecked(),
            'encode_payloads': self.encode_payloads_cb.isChecked(),
        }

        # Check if user wants to schedule instead of run now
        if hasattr(self, 'schedule_instead_cb') and self.schedule_instead_cb.isChecked():
            self._create_scheduled_task()
            return

        self.scan_configured.emit(self.config)
        self.accept()

    def _create_scheduled_task(self):
        """Create a scheduled task from wizard configuration"""
        import uuid
        import json
        import os
        from pathlib import Path
        from datetime import datetime

        # Get schedule time
        schedule_dt = self.schedule_datetime.dateTime().toPyDateTime()

        # Get scan mode display name
        scan_mode = self.config.get('scan_mode', 'web')
        mode_names = {'web': 'Web App', 'api': 'API', 'graphql': 'GraphQL'}
        mode_display = mode_names.get(scan_mode, 'Web App')

        # Create task data
        task = {
            'id': str(uuid.uuid4()),
            'name': f"{mode_display} Scan - {self.config['target'][:30]}",
            'target': self.config['target'],
            'project_path': '',
            'scan_mode': scan_mode,
            'modules': self.config['modules'],
            'settings': {
                'threads': self.config['threads'],
                'timeout': self.config['timeout'],
                'max_time': self.config['max_time'],
                'time_limit_enabled': self.config.get('time_limit_enabled', True),
                'format': self.config['format'],
                # Subdomain options
                'enum_subdomains': self.config.get('enum_subdomains', False),
                'scan_subdomains': self.config.get('scan_subdomains', False),
                'subdomain_limit': self.config.get('subdomain_limit', 10),
                'subdomain_takeover': self.config.get('subdomain_takeover', False),
            },
            'schedule_type': 'once',
            'next_run': schedule_dt.isoformat(),
            'enabled': True,
            'created': datetime.now().isoformat(),
            'email_notification': False,
            'email_address': ''
        }

        # Load existing schedules
        schedules_file = str(Path.home() / ".dominator" / "schedules.json")
        schedules = []
        if os.path.exists(schedules_file):
            try:
                with open(schedules_file, 'r') as f:
                    schedules = json.load(f)
            except:
                pass

        # Add new task
        schedules.append(task)

        # Save schedules
        config_dir = Path.home() / ".dominator"
        config_dir.mkdir(exist_ok=True)
        try:
            with open(schedules_file, 'w') as f:
                json.dump(schedules, f, indent=2)

            QMessageBox.information(
                self, "Scan Scheduled",
                f"Scan has been scheduled for:\n{schedule_dt.strftime('%Y-%m-%d %H:%M')}\n\n"
                f"Target: {self.config['target']}\n"
                f"Modules: {len(self.config['modules'])}\n\n"
                "You can manage scheduled scans from Tools > Scheduler."
            )
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to save schedule: {str(e)}")
            return

        self.accept()

    def get_config(self):
        """Get the wizard configuration"""
        return self.config
