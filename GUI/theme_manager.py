#!/usr/bin/env python3
"""
Theme Manager - Handles application theming for Dominator GUI
"""

from PyQt5.QtCore import Qt
from PyQt5.QtGui import QColor, QPalette


class ThemeManager:
    """Manages application themes and styling"""

    # Theme configurations
    THEMES = {
        "light": {
            "bg_main": "#f5f5f5",
            "bg_alt": "#ffffff",
            "bg_input": "#ffffff",
            "bg_button": "#e0e0e0",
            "accent": "#2196F3",
            "accent_rgb": "33, 150, 243",
            "text_color": "black",
            "is_light": True
        },
        "hacker_green": {
            "bg_main": "#1a1a1a",
            "bg_alt": "#2a2a2a",
            "bg_input": "#2a2a2a",
            "bg_button": "#3a3a3a",
            "accent": "#00ff88",
            "accent_rgb": "0, 255, 136",
            "text_color": "white",
            "is_light": False
        },
        "cyber_blue": {
            "bg_main": "#0a0a1a",
            "bg_alt": "#1a1a2a",
            "bg_input": "#1a1a2a",
            "bg_button": "#2a2a3a",
            "accent": "#00d4ff",
            "accent_rgb": "0, 212, 255",
            "text_color": "white",
            "is_light": False
        },
        "purple_haze": {
            "bg_main": "#1a0a1a",
            "bg_alt": "#2a1a2a",
            "bg_input": "#2a1a2a",
            "bg_button": "#3a2a3a",
            "accent": "#c77dff",
            "accent_rgb": "199, 125, 255",
            "text_color": "white",
            "is_light": False
        },
        "blood_red": {
            "bg_main": "#1a0a0a",
            "bg_alt": "#2a1a1a",
            "bg_input": "#2a1a1a",
            "bg_button": "#3a2a2a",
            "accent": "#ff0055",
            "accent_rgb": "255, 0, 85",
            "text_color": "white",
            "is_light": False
        },
        "matrix": {
            "bg_main": "#000000",
            "bg_alt": "#0d0d0d",
            "bg_input": "#0d0d0d",
            "bg_button": "#1a1a1a",
            "accent": "#00ff00",
            "accent_rgb": "0, 255, 0",
            "text_color": "white",
            "is_light": False
        }
    }

    def __init__(self, gui):
        """Initialize with reference to main GUI window"""
        self.gui = gui
        self.current_theme = None

    def get_available_themes(self):
        """Return list of available theme names and IDs"""
        return [
            ("Light", "light"),
            ("Hacker Green", "hacker_green"),
            ("Cyber Blue", "cyber_blue"),
            ("Purple Haze", "purple_haze"),
            ("Blood Red", "blood_red"),
            ("Matrix", "matrix")
        ]

    def apply_theme(self, theme_id="hacker_green"):
        """Apply selected theme to the application"""
        theme = self.THEMES.get(theme_id, self.THEMES["hacker_green"])

        # Determine text color based on theme
        is_light = theme.get("is_light", False)
        text_color = Qt.black if is_light else Qt.white

        # Apply palette
        palette = QPalette()
        palette.setColor(QPalette.Window, QColor(theme["bg_main"]))
        palette.setColor(QPalette.WindowText, text_color)
        palette.setColor(QPalette.Base, QColor(theme["bg_input"]))
        palette.setColor(QPalette.AlternateBase, QColor(theme["bg_alt"]))
        palette.setColor(QPalette.ToolTipBase, QColor("#ffffff") if is_light else Qt.white)
        palette.setColor(QPalette.ToolTipText, Qt.black if is_light else Qt.white)
        palette.setColor(QPalette.Text, text_color)
        palette.setColor(QPalette.Button, QColor(theme["bg_button"]))
        palette.setColor(QPalette.ButtonText, text_color)
        palette.setColor(QPalette.BrightText, Qt.red)
        palette.setColor(QPalette.Link, QColor(theme["accent"]))
        palette.setColor(QPalette.Highlight, QColor(theme["accent"]))
        palette.setColor(QPalette.HighlightedText, Qt.white if is_light else Qt.black)

        self.gui.setPalette(palette)

        # Store current theme for dynamic elements
        self.current_theme = theme
        self.gui.current_theme = theme

        # Determine text color for CSS based on theme
        text_color_css = theme.get("text_color", "white")
        arrow_color = "black" if is_light else "white"

        # Additional stylesheet with theme colors
        self.gui.setStyleSheet(f"""
            QMainWindow {{
                background-color: {theme['bg_main']};
                color: {text_color_css};
            }}
            QWidget {{
                color: {text_color_css};
            }}
            QLabel {{
                color: {text_color_css};
            }}
            QGroupBox {{
                font-weight: bold;
                border: 2px solid {theme['bg_button']};
                border-radius: 8px;
                margin-top: 10px;
                padding: 15px;
                color: {theme['accent']};
            }}
            QGroupBox::title {{
                subcontrol-origin: margin;
                subcontrol-position: top left;
                padding: 5px 10px;
                color: {theme['accent']};
            }}
            QPushButton {{
                background-color: {theme['bg_button']};
                color: {text_color_css};
                border: none;
                padding: 8px 15px;
                border-radius: 4px;
                font-weight: bold;
            }}
            QPushButton:hover {{
                background-color: {theme['bg_alt']};
            }}
            QPushButton:pressed {{
                background-color: {theme['bg_input']};
            }}
            QLineEdit, QSpinBox, QComboBox {{
                background-color: {theme['bg_input']};
                border: 2px solid {theme['bg_button']};
                border-radius: 4px;
                padding: 6px;
                color: {text_color_css};
            }}
            QLineEdit:focus, QSpinBox:focus, QComboBox:focus {{
                border: 2px solid {theme['accent']};
            }}
            QComboBox::drop-down {{
                border: none;
                background-color: {theme['bg_button']};
            }}
            QComboBox::down-arrow {{
                image: none;
                border-left: 5px solid transparent;
                border-right: 5px solid transparent;
                border-top: 5px solid {arrow_color};
                margin-right: 5px;
            }}
            QComboBox QAbstractItemView {{
                background-color: {theme['bg_input']};
                color: {text_color_css};
                selection-background-color: {theme['accent']};
                selection-color: white;
                border: 2px solid {theme['bg_button']};
            }}
            QSpinBox::up-button, QSpinBox::down-button {{
                background-color: {theme['bg_button']};
                border: none;
            }}
            QSpinBox::up-arrow, QSpinBox::down-arrow {{
                width: 7px;
                height: 7px;
            }}
            QCheckBox {{
                spacing: 8px;
                color: {text_color_css};
            }}
            QCheckBox::indicator {{
                width: 18px;
                height: 18px;
                border: 2px solid {theme['bg_button']};
                border-radius: 3px;
                background-color: {theme['bg_input']};
            }}
            QCheckBox::indicator:checked {{
                background-color: {theme['accent']};
                border-color: {theme['accent']};
            }}
            QTabWidget::pane {{
                border: 2px solid {theme['bg_button']};
                border-radius: 4px;
                background-color: {theme['bg_main']};
            }}
            QTabBar::tab {{
                background-color: {theme['bg_alt']};
                color: {text_color_css};
                padding: 10px 20px;
                border: 2px solid {theme['bg_button']};
                border-bottom: none;
                border-top-left-radius: 4px;
                border-top-right-radius: 4px;
                margin-right: 2px;
            }}
            QTabBar::tab:selected {{
                background-color: {theme['bg_main']};
                color: {theme['accent']};
                border-bottom: 2px solid {theme['accent']};
            }}
            QTabBar::tab:hover {{
                background-color: {theme['bg_button']};
            }}
            QTextEdit {{
                color: {text_color_css};
            }}
            QListWidget {{
                color: {text_color_css};
            }}
            QLabel#categoryLabel {{
                font-weight: bold;
                color: {theme['accent']};
                margin-top: 5px;
            }}
            QTableWidget {{
                background-color: {theme['bg_input']};
                color: {text_color_css};
                border: 1px solid {theme['bg_button']};
                gridline-color: {theme['bg_button']};
            }}
            QTableWidget::item {{
                padding: 5px;
            }}
            QHeaderView::section {{
                background-color: {theme['bg_alt']};
                color: {text_color_css};
                padding: 5px;
                border: 1px solid {theme['bg_button']};
            }}
            QScrollBar {{
                background-color: {theme['bg_alt']};
            }}
            QScrollBar::handle {{
                background-color: {theme['bg_button']};
            }}
            QStatusBar {{
                background-color: {theme['bg_alt']};
                color: {text_color_css};
                padding: 5px;
            }}
            QProgressBar {{
                border: 2px solid {theme['bg_button']};
                border-radius: 5px;
                text-align: center;
                background-color: {theme['bg_input']};
                color: {text_color_css};
            }}
            QProgressBar::chunk {{
                background-color: {theme['accent']};
            }}
        """)

        # Update CollapsibleBox styling for theme
        collapsible_button_style = f"""
            QToolButton {{
                border: none;
                background-color: {theme['bg_button']};
                color: {text_color_css};
                font-weight: bold;
                font-size: 12px;
                padding: 8px;
                text-align: left;
            }}
            QToolButton:hover {{
                background-color: {theme['bg_alt']};
            }}
        """
        collapsible_content_style = f"background-color: {theme['bg_input']}; border-radius: 4px;"

        if hasattr(self.gui, 'module_box'):
            self.gui.module_box.toggle_button.setStyleSheet(collapsible_button_style)
            self.gui.module_box.content_area.setStyleSheet(collapsible_content_style)
        if hasattr(self.gui, 'settings_box'):
            self.gui.settings_box.toggle_button.setStyleSheet(collapsible_button_style)
            self.gui.settings_box.content_area.setStyleSheet(collapsible_content_style)

        # Update custom headers/cookies styling
        custom_input_style = f"""
            QTextEdit, QLineEdit {{
                background-color: {theme['bg_input']};
                color: {theme['accent']};
                border: 2px solid {theme['bg_button']};
                border-radius: 4px;
                padding: 6px;
                font-family: 'Consolas', 'Courier New', monospace;
                font-size: 12px;
            }}
        """
        if hasattr(self.gui, 'headers_input'):
            self.gui.headers_input.setStyleSheet(custom_input_style.replace("QLineEdit", "").strip())
        if hasattr(self.gui, 'cookies_input'):
            self.gui.cookies_input.setStyleSheet(custom_input_style.replace("QTextEdit, ", "").strip())

        # Update output console styling
        if hasattr(self.gui, 'output_console'):
            console_bg = "#f8f8f8" if is_light else "#0a0a0a"
            console_text = "#006600" if is_light else "#00ff00"
            self.gui.output_console.setStyleSheet(f"""
                QTextEdit {{
                    background-color: {console_bg};
                    color: {console_text};
                    border: 2px solid {theme['bg_button']};
                    border-radius: 5px;
                    padding: 10px;
                    font-size: 16px;
                }}
            """)

        # Update current module label
        if hasattr(self.gui, 'current_module_label'):
            self.gui.current_module_label.setStyleSheet(f"color: {theme['accent']}; font-size: 14px; font-weight: bold;")
