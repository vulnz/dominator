"""
Target Profile Panel - Pre-Scan Intelligence Display

Displays target profile information collected before the scan:
- Technology stack detection
- WAF detection status
- Geolocation information
- Screenshot preview
- Security headers analysis
- SSL/TLS information
"""

import os
import base64
from PyQt5.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QGridLayout, QGroupBox,
    QLabel, QFrame, QScrollArea, QPushButton, QSplitter
)
from PyQt5.QtCore import Qt, QSize
from PyQt5.QtGui import QPixmap, QFont, QColor


class InfoCard(QFrame):
    """A styled card for displaying key-value information"""

    def __init__(self, title: str, parent=None):
        super().__init__(parent)
        self.setStyleSheet("""
            InfoCard {
                background-color: #ffffff;
                border: 1px solid #e0e0e0;
                border-radius: 8px;
            }
        """)

        layout = QVBoxLayout(self)
        layout.setSpacing(8)
        layout.setContentsMargins(12, 12, 12, 12)

        # Title
        title_label = QLabel(title)
        title_label.setStyleSheet("""
            font-weight: bold;
            font-size: 13px;
            color: #2e7d32;
            padding-bottom: 4px;
            border-bottom: 2px solid #4CAF50;
        """)
        layout.addWidget(title_label)

        # Content container
        self.content_layout = QGridLayout()
        self.content_layout.setSpacing(6)
        layout.addLayout(self.content_layout)

        self.row_count = 0

    def add_item(self, label: str, value: str, value_color: str = "#333333"):
        """Add a key-value pair to the card"""
        label_widget = QLabel(f"{label}:")
        label_widget.setStyleSheet("color: #666666; font-size: 11px;")

        # Handle empty/None/N/A values
        display_value = str(value).strip() if value else ""
        if not display_value or display_value in ("", "None", "N/A", "-", "()", "0ms"):
            display_value = "Not detected"
            value_color = "#9ca3af"  # Gray for not detected

        value_widget = QLabel(display_value)
        value_widget.setStyleSheet(f"color: {value_color}; font-weight: bold; font-size: 11px;")
        value_widget.setWordWrap(True)

        self.content_layout.addWidget(label_widget, self.row_count, 0, Qt.AlignTop)
        self.content_layout.addWidget(value_widget, self.row_count, 1, Qt.AlignTop)
        self.row_count += 1

    def add_list(self, label: str, items: list, color: str = "#333333"):
        """Add a list of items to the card"""
        if not items:
            self.add_item(label, "None detected")
            return

        label_widget = QLabel(f"{label}:")
        label_widget.setStyleSheet("color: #666666; font-size: 11px;")

        items_text = ", ".join(str(i) for i in items[:10])  # Limit to 10 items
        if len(items) > 10:
            items_text += f" (+{len(items) - 10} more)"

        value_widget = QLabel(items_text)
        value_widget.setStyleSheet(f"color: {color}; font-size: 11px;")
        value_widget.setWordWrap(True)

        self.content_layout.addWidget(label_widget, self.row_count, 0, Qt.AlignTop)
        self.content_layout.addWidget(value_widget, self.row_count, 1, Qt.AlignTop)
        self.row_count += 1


class ScreenshotWidget(QFrame):
    """Widget for displaying target screenshot"""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setStyleSheet("""
            ScreenshotWidget {
                background-color: #1a1a1a;
                border: 2px solid #333333;
                border-radius: 8px;
            }
        """)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(4, 4, 4, 4)

        # Title
        title = QLabel("Target Preview")
        title.setStyleSheet("""
            color: #ffffff;
            font-weight: bold;
            font-size: 12px;
            padding: 4px;
            background-color: #333333;
            border-radius: 4px;
        """)
        title.setAlignment(Qt.AlignCenter)
        layout.addWidget(title)

        # Screenshot image
        self.image_label = QLabel()
        self.image_label.setStyleSheet("background-color: #2a2a2a; border-radius: 4px;")
        self.image_label.setAlignment(Qt.AlignCenter)
        self.image_label.setMinimumSize(400, 300)
        self.image_label.setText("No screenshot available")
        self.image_label.setStyleSheet("color: #666666; font-size: 12px;")
        layout.addWidget(self.image_label)

        # URL label
        self.url_label = QLabel()
        self.url_label.setStyleSheet("""
            color: #4CAF50;
            font-size: 11px;
            padding: 4px;
            background-color: #2a2a2a;
            border-radius: 4px;
        """)
        self.url_label.setAlignment(Qt.AlignCenter)
        self.url_label.setWordWrap(True)
        layout.addWidget(self.url_label)

    def set_screenshot(self, path: str = None, base64_data: str = None, url: str = ""):
        """Set the screenshot from file path or base64 data"""
        pixmap = None

        if path and os.path.exists(path):
            pixmap = QPixmap(path)
        elif base64_data:
            try:
                image_data = base64.b64decode(base64_data)
                pixmap = QPixmap()
                pixmap.loadFromData(image_data)
            except Exception:
                pass

        if pixmap and not pixmap.isNull():
            # Scale to fit while maintaining aspect ratio
            scaled = pixmap.scaled(
                self.image_label.size(),
                Qt.KeepAspectRatio,
                Qt.SmoothTransformation
            )
            self.image_label.setPixmap(scaled)
            self.image_label.setStyleSheet("background-color: #2a2a2a; border-radius: 4px;")
        else:
            # Show helpful message about screenshot capture
            message = "Screenshot capture requires\nPlaywright or Selenium.\n\nInstall with:\npip install playwright\nplaywright install chromium"
            self.image_label.setText(message)
            self.image_label.setStyleSheet("""
                color: #9ca3af;
                font-size: 11px;
                background-color: #2a2a2a;
                padding: 20px;
            """)

        self.url_label.setText(url)

    def clear(self):
        """Clear the screenshot"""
        self.image_label.clear()
        self.image_label.setText("No screenshot available")
        self.url_label.clear()


class TargetProfilePanel(QWidget):
    """Panel displaying comprehensive target profile information"""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setup_ui()

    def setup_ui(self):
        """Setup the panel UI"""
        main_layout = QHBoxLayout(self)
        main_layout.setSpacing(10)
        main_layout.setContentsMargins(10, 10, 10, 10)

        # Left side: Information cards
        left_widget = QWidget()
        left_layout = QVBoxLayout(left_widget)
        left_layout.setSpacing(10)
        left_layout.setContentsMargins(0, 0, 0, 0)

        # Scroll area for cards
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        scroll.setStyleSheet("QScrollArea { border: none; background: transparent; }")

        scroll_content = QWidget()
        self.cards_layout = QVBoxLayout(scroll_content)
        self.cards_layout.setSpacing(10)

        # Create info cards
        self.basic_info_card = InfoCard("Basic Information")
        self.cards_layout.addWidget(self.basic_info_card)

        self.tech_card = InfoCard("Technology Stack")
        self.cards_layout.addWidget(self.tech_card)

        self.security_card = InfoCard("Security Analysis")
        self.cards_layout.addWidget(self.security_card)

        self.ssl_card = InfoCard("SSL/TLS Information")
        self.cards_layout.addWidget(self.ssl_card)

        self.infrastructure_card = InfoCard("Infrastructure")
        self.cards_layout.addWidget(self.infrastructure_card)

        self.cards_layout.addStretch()

        scroll.setWidget(scroll_content)
        left_layout.addWidget(scroll)

        main_layout.addWidget(left_widget, 2)

        # Right side: Screenshot
        self.screenshot_widget = ScreenshotWidget()
        main_layout.addWidget(self.screenshot_widget, 1)

    def update_profile(self, profile: dict):
        """Update the panel with profile data"""
        if not profile:
            return

        # Clear existing cards
        for card in [self.basic_info_card, self.tech_card, self.security_card,
                     self.ssl_card, self.infrastructure_card]:
            self._clear_card(card)

        # Basic Information
        self.basic_info_card.add_item("URL", profile.get('url', ''))
        self.basic_info_card.add_item("Domain", profile.get('domain', ''))
        self.basic_info_card.add_item("IP Address", profile.get('ip_address', ''))
        self.basic_info_card.add_item("Title", profile.get('title', ''))

        # Status code - format nicely
        status_code = profile.get('status_code', 0)
        if status_code and status_code > 0:
            self.basic_info_card.add_item("Status Code", str(status_code), "#4CAF50" if status_code < 400 else "#f44336")
        else:
            self.basic_info_card.add_item("Status Code", "")

        # Response time
        response_time = profile.get('response_time_ms')
        if response_time and response_time > 0:
            self.basic_info_card.add_item("Response Time", f"{response_time:.0f}ms")
        else:
            self.basic_info_card.add_item("Response Time", "")

        # Technology Stack
        self.tech_card.add_item("Web Server", profile.get('web_server', ''), "#2196F3")
        self.tech_card.add_item("Language", profile.get('programming_language', ''), "#9C27B0")
        self.tech_card.add_item("Framework", profile.get('framework', ''), "#FF9800")
        self.tech_card.add_item("CMS", profile.get('cms', ''), "#E91E63")

        js_libs = profile.get('javascript_libraries', [])
        if js_libs:
            self.tech_card.add_list("JS Libraries", js_libs, "#607D8B")

        # Security Analysis
        waf = profile.get('waf_detected', '')
        waf_color = "#f44336" if waf else "#4CAF50"
        self.security_card.add_item("WAF Detected", waf if waf else "None", waf_color)

        if waf:
            waf_conf = profile.get('waf_confidence')
            conf_str = f"{waf_conf*100:.0f}%" if waf_conf is not None else "N/A"
            self.security_card.add_item("WAF Confidence", conf_str, "#FF9800")

        missing_headers = profile.get('missing_security_headers', [])
        if missing_headers:
            self.security_card.add_list("Missing Headers", missing_headers, "#f44336")

        self.security_card.add_item("Login Page", "Yes" if profile.get('login_page') else "No")
        self.security_card.add_item("Forms Detected", str(profile.get('forms_detected', 0)))

        # SSL/TLS Information
        ssl_enabled = profile.get('ssl_enabled', False)
        self.ssl_card.add_item("SSL/TLS", "Enabled" if ssl_enabled else "Disabled",
                               "#4CAF50" if ssl_enabled else "#f44336")
        if ssl_enabled:
            self.ssl_card.add_item("Issuer", profile.get('ssl_issuer', ''))
            self.ssl_card.add_item("Expiry", profile.get('ssl_expiry', ''))
            self.ssl_card.add_item("Protocol", profile.get('ssl_protocol', ''))
            grade = profile.get('ssl_grade', '')
            grade_colors = {'A+': '#4CAF50', 'A': '#8BC34A', 'B': '#FFEB3B', 'C': '#FF9800', 'D': '#f44336', 'F': '#f44336'}
            self.ssl_card.add_item("Grade", grade, grade_colors.get(grade, '#666666'))

        # Infrastructure
        country = profile.get('country', '')
        country_code = profile.get('country_code', '')
        if country and country_code:
            self.infrastructure_card.add_item("Country", f"{country} ({country_code})")
        elif country:
            self.infrastructure_card.add_item("Country", country)
        else:
            self.infrastructure_card.add_item("Country", "")

        self.infrastructure_card.add_item("Hosting", profile.get('hosting_provider', ''))
        self.infrastructure_card.add_item("CDN", profile.get('cdn', ''))
        self.infrastructure_card.add_item("ASN", profile.get('asn', ''))

        # Interesting paths
        paths = profile.get('interesting_paths', [])
        if paths:
            self.infrastructure_card.add_list("Interesting Paths", paths, "#FF9800")

        # Update screenshot
        self.screenshot_widget.set_screenshot(
            path=profile.get('screenshot_path', ''),
            base64_data=profile.get('screenshot_base64', ''),
            url=profile.get('url', '')
        )

    def _clear_card(self, card: InfoCard):
        """Clear all items from a card"""
        while card.content_layout.count():
            item = card.content_layout.takeAt(0)
            if item.widget():
                item.widget().deleteLater()
        card.row_count = 0

    def clear(self):
        """Clear all profile data"""
        for card in [self.basic_info_card, self.tech_card, self.security_card,
                     self.ssl_card, self.infrastructure_card]:
            self._clear_card(card)
        self.screenshot_widget.clear()


class TargetProfileDialog(QWidget):
    """Standalone dialog for displaying target profile"""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Target Profile")
        self.setMinimumSize(900, 600)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)

        self.profile_panel = TargetProfilePanel()
        layout.addWidget(self.profile_panel)

        # Close button
        btn_layout = QHBoxLayout()
        btn_layout.addStretch()

        close_btn = QPushButton("Close")
        close_btn.setStyleSheet("""
            QPushButton {
                background-color: #4CAF50;
                color: white;
                border: none;
                border-radius: 6px;
                padding: 10px 30px;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: #388E3C;
            }
        """)
        close_btn.clicked.connect(self.close)
        btn_layout.addWidget(close_btn)

        layout.addLayout(btn_layout)

    def set_profile(self, profile: dict):
        """Set the profile data to display"""
        self.profile_panel.update_profile(profile)
