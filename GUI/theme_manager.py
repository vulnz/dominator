#!/usr/bin/env python3
"""
Theme Manager - Handles application theming for Dominator GUI

Provides consistent styling across all GUI components with proper:
- Font management (system fonts with fallbacks)
- Color consistency across themes
- Tab styling
- Widget styling with theme awareness
"""

from PyQt5.QtCore import Qt
from PyQt5.QtGui import QColor, QPalette, QFont, QFontDatabase
from PyQt5.QtWidgets import QApplication


class ThemeManager:
    """Manages application themes and styling"""

    # Standard font configuration
    FONT_FAMILY = "Segoe UI, Roboto, Arial, sans-serif"
    FONT_FAMILY_MONO = "Consolas, 'Courier New', monospace"
    FONT_SIZE_NORMAL = 10
    FONT_SIZE_SMALL = 9
    FONT_SIZE_LARGE = 12
    FONT_SIZE_TITLE = 14
    FONT_SIZE_HEADER = 16

    # Theme configurations with complete color definitions
    THEMES = {
        "light": {
            "name": "Light",
            "bg_main": "#f5f5f5",
            "bg_alt": "#ffffff",
            "bg_input": "#ffffff",
            "bg_button": "#e0e0e0",
            "bg_button_hover": "#d0d0d0",
            "bg_button_pressed": "#c0c0c0",
            "accent": "#2196F3",
            "accent_hover": "#1976D2",
            "accent_rgb": "33, 150, 243",
            "text_primary": "#212121",
            "text_secondary": "#757575",
            "text_disabled": "#bdbdbd",
            "text_on_accent": "#ffffff",
            "border": "#e0e0e0",
            "border_focus": "#2196F3",
            "success": "#4CAF50",
            "warning": "#FF9800",
            "error": "#f44336",
            "critical": "#d32f2f",
            "console_bg": "#fafafa",
            "console_text": "#1b5e20",
            "tab_selected_bg": "#ffffff",
            "tab_hover_bg": "#eeeeee",
            "scrollbar_bg": "#f0f0f0",
            "scrollbar_handle": "#c0c0c0",
            "is_light": True
        },
        "dark": {
            "name": "Dark",
            "bg_main": "#1e1e1e",
            "bg_alt": "#252526",
            "bg_input": "#2d2d30",
            "bg_button": "#3c3c3c",
            "bg_button_hover": "#4a4a4a",
            "bg_button_pressed": "#555555",
            "accent": "#0078d4",
            "accent_hover": "#1a8ae6",
            "accent_rgb": "0, 120, 212",
            "text_primary": "#ffffff",
            "text_secondary": "#a0a0a0",
            "text_disabled": "#606060",
            "text_on_accent": "#ffffff",
            "border": "#3c3c3c",
            "border_focus": "#0078d4",
            "success": "#4CAF50",
            "warning": "#FF9800",
            "error": "#f44336",
            "critical": "#ff1744",
            "console_bg": "#1a1a1a",
            "console_text": "#00ff00",
            "tab_selected_bg": "#1e1e1e",
            "tab_hover_bg": "#2d2d30",
            "scrollbar_bg": "#2d2d30",
            "scrollbar_handle": "#5a5a5a",
            "is_light": False
        },
        "hacker_green": {
            "name": "Hacker Green",
            "bg_main": "#0d1117",
            "bg_alt": "#161b22",
            "bg_input": "#21262d",
            "bg_button": "#21262d",
            "bg_button_hover": "#30363d",
            "bg_button_pressed": "#484f58",
            "accent": "#00ff88",
            "accent_hover": "#00cc6e",
            "accent_rgb": "0, 255, 136",
            "text_primary": "#e6edf3",
            "text_secondary": "#8b949e",
            "text_disabled": "#484f58",
            "text_on_accent": "#0d1117",
            "border": "#30363d",
            "border_focus": "#00ff88",
            "success": "#00ff88",
            "warning": "#ffa657",
            "error": "#ff7b72",
            "critical": "#f85149",
            "console_bg": "#010409",
            "console_text": "#00ff88",
            "tab_selected_bg": "#0d1117",
            "tab_hover_bg": "#21262d",
            "scrollbar_bg": "#161b22",
            "scrollbar_handle": "#30363d",
            "is_light": False
        },
        "cyber_blue": {
            "name": "Cyber Blue",
            "bg_main": "#0a0e14",
            "bg_alt": "#0f1419",
            "bg_input": "#1a1f26",
            "bg_button": "#1a1f26",
            "bg_button_hover": "#232a33",
            "bg_button_pressed": "#2d3640",
            "accent": "#00d4ff",
            "accent_hover": "#00a8cc",
            "accent_rgb": "0, 212, 255",
            "text_primary": "#e6e1cf",
            "text_secondary": "#a0a0a0",
            "text_disabled": "#555555",
            "text_on_accent": "#0a0e14",
            "border": "#232a33",
            "border_focus": "#00d4ff",
            "success": "#7bd88f",
            "warning": "#ffb454",
            "error": "#ff8080",
            "critical": "#ff5555",
            "console_bg": "#050810",
            "console_text": "#00d4ff",
            "tab_selected_bg": "#0a0e14",
            "tab_hover_bg": "#1a1f26",
            "scrollbar_bg": "#0f1419",
            "scrollbar_handle": "#2d3640",
            "is_light": False
        },
        "purple_haze": {
            "name": "Purple Haze",
            "bg_main": "#1a1a2e",
            "bg_alt": "#16213e",
            "bg_input": "#1f2940",
            "bg_button": "#1f2940",
            "bg_button_hover": "#2a3a55",
            "bg_button_pressed": "#354a6a",
            "accent": "#c77dff",
            "accent_hover": "#a855f7",
            "accent_rgb": "199, 125, 255",
            "text_primary": "#e4e4e7",
            "text_secondary": "#a1a1aa",
            "text_disabled": "#52525b",
            "text_on_accent": "#1a1a2e",
            "border": "#2a3a55",
            "border_focus": "#c77dff",
            "success": "#86efac",
            "warning": "#fcd34d",
            "error": "#f87171",
            "critical": "#ef4444",
            "console_bg": "#0f0f1a",
            "console_text": "#c77dff",
            "tab_selected_bg": "#1a1a2e",
            "tab_hover_bg": "#1f2940",
            "scrollbar_bg": "#16213e",
            "scrollbar_handle": "#354a6a",
            "is_light": False
        },
        "blood_red": {
            "name": "Blood Red",
            "bg_main": "#1a0a0a",
            "bg_alt": "#2a1515",
            "bg_input": "#352020",
            "bg_button": "#352020",
            "bg_button_hover": "#452a2a",
            "bg_button_pressed": "#553535",
            "accent": "#ff3355",
            "accent_hover": "#cc2944",
            "accent_rgb": "255, 51, 85",
            "text_primary": "#f5e6e6",
            "text_secondary": "#b8a0a0",
            "text_disabled": "#665555",
            "text_on_accent": "#ffffff",
            "border": "#452a2a",
            "border_focus": "#ff3355",
            "success": "#4ade80",
            "warning": "#fbbf24",
            "error": "#ff3355",
            "critical": "#dc2626",
            "console_bg": "#100505",
            "console_text": "#ff3355",
            "tab_selected_bg": "#1a0a0a",
            "tab_hover_bg": "#352020",
            "scrollbar_bg": "#2a1515",
            "scrollbar_handle": "#553535",
            "is_light": False
        },
        "matrix": {
            "name": "Matrix",
            "bg_main": "#000000",
            "bg_alt": "#0a0a0a",
            "bg_input": "#111111",
            "bg_button": "#111111",
            "bg_button_hover": "#1a1a1a",
            "bg_button_pressed": "#222222",
            "accent": "#00ff00",
            "accent_hover": "#00cc00",
            "accent_rgb": "0, 255, 0",
            "text_primary": "#00ff00",
            "text_secondary": "#00aa00",
            "text_disabled": "#005500",
            "text_on_accent": "#000000",
            "border": "#003300",
            "border_focus": "#00ff00",
            "success": "#00ff00",
            "warning": "#ffff00",
            "error": "#ff0000",
            "critical": "#ff0000",
            "console_bg": "#000000",
            "console_text": "#00ff00",
            "tab_selected_bg": "#000000",
            "tab_hover_bg": "#0a1a0a",
            "scrollbar_bg": "#050505",
            "scrollbar_handle": "#003300",
            "is_light": False
        }
    }

    def __init__(self, gui):
        """Initialize with reference to main GUI window"""
        self.gui = gui
        self.current_theme = None
        self.current_theme_id = None

    def get_available_themes(self):
        """Return list of available theme names and IDs"""
        return [(theme["name"], theme_id) for theme_id, theme in self.THEMES.items()]

    def get_current_theme(self):
        """Get the current theme configuration"""
        return self.current_theme

    def get_theme_color(self, color_name):
        """Get a specific color from the current theme"""
        if self.current_theme:
            return self.current_theme.get(color_name, "#ffffff")
        return "#ffffff"

    def apply_theme(self, theme_id="dark"):
        """Apply selected theme to the application"""
        theme = self.THEMES.get(theme_id, self.THEMES["dark"])
        self.current_theme = theme
        self.current_theme_id = theme_id

        is_light = theme.get("is_light", False)

        # Apply QPalette for native widget styling
        palette = QPalette()
        palette.setColor(QPalette.Window, QColor(theme["bg_main"]))
        palette.setColor(QPalette.WindowText, QColor(theme["text_primary"]))
        palette.setColor(QPalette.Base, QColor(theme["bg_input"]))
        palette.setColor(QPalette.AlternateBase, QColor(theme["bg_alt"]))
        palette.setColor(QPalette.ToolTipBase, QColor(theme["bg_alt"]))
        palette.setColor(QPalette.ToolTipText, QColor(theme["text_primary"]))
        palette.setColor(QPalette.Text, QColor(theme["text_primary"]))
        palette.setColor(QPalette.Button, QColor(theme["bg_button"]))
        palette.setColor(QPalette.ButtonText, QColor(theme["text_primary"]))
        palette.setColor(QPalette.BrightText, QColor(theme["error"]))
        palette.setColor(QPalette.Link, QColor(theme["accent"]))
        palette.setColor(QPalette.Highlight, QColor(theme["accent"]))
        palette.setColor(QPalette.HighlightedText, QColor(theme["text_on_accent"]))
        palette.setColor(QPalette.Disabled, QPalette.Text, QColor(theme["text_disabled"]))
        palette.setColor(QPalette.Disabled, QPalette.ButtonText, QColor(theme["text_disabled"]))

        self.gui.setPalette(palette)

        # Store theme for other components
        self.gui.current_theme = theme

        # Build and apply comprehensive stylesheet
        stylesheet = self._build_stylesheet(theme)
        self.gui.setStyleSheet(stylesheet)

        # Update specific components that need custom handling
        self._update_custom_components(theme)

    def _build_stylesheet(self, theme):
        """Build comprehensive stylesheet for all widgets"""
        t = theme  # Shorthand

        return f"""
            /* ============================================
               GLOBAL STYLES
               ============================================ */
            * {{
                font-family: {self.FONT_FAMILY};
                font-size: {self.FONT_SIZE_NORMAL}pt;
            }}

            QMainWindow {{
                background-color: {t['bg_main']};
            }}

            QWidget {{
                background-color: transparent;
                color: {t['text_primary']};
            }}

            /* ============================================
               LABELS
               ============================================ */
            QLabel {{
                color: {t['text_primary']};
                background-color: transparent;
                padding: 2px;
            }}

            QLabel[heading="true"] {{
                font-size: {self.FONT_SIZE_HEADER}pt;
                font-weight: bold;
                color: {t['accent']};
            }}

            /* ============================================
               GROUP BOXES
               ============================================ */
            QGroupBox {{
                font-weight: bold;
                font-size: {self.FONT_SIZE_NORMAL}pt;
                border: 1px solid {t['border']};
                border-radius: 6px;
                margin-top: 12px;
                padding: 12px;
                padding-top: 20px;
                background-color: {t['bg_alt']};
            }}

            QGroupBox::title {{
                subcontrol-origin: margin;
                subcontrol-position: top left;
                left: 10px;
                padding: 0 8px;
                color: {t['accent']};
                background-color: {t['bg_alt']};
            }}

            /* ============================================
               BUTTONS
               ============================================ */
            QPushButton {{
                background-color: {t['bg_button']};
                color: {t['text_primary']};
                border: 1px solid {t['border']};
                border-radius: 4px;
                padding: 8px 16px;
                font-weight: 500;
                min-height: 20px;
            }}

            QPushButton:hover {{
                background-color: {t['bg_button_hover']};
                border-color: {t['accent']};
            }}

            QPushButton:pressed {{
                background-color: {t['bg_button_pressed']};
            }}

            QPushButton:disabled {{
                background-color: {t['bg_button']};
                color: {t['text_disabled']};
                border-color: {t['border']};
            }}

            QPushButton[accent="true"], QPushButton#startButton {{
                background-color: {t['accent']};
                color: {t['text_on_accent']};
                border: none;
            }}

            QPushButton[accent="true"]:hover, QPushButton#startButton:hover {{
                background-color: {t['accent_hover']};
            }}

            QPushButton[danger="true"], QPushButton#stopButton {{
                background-color: {t['error']};
                color: white;
                border: none;
            }}

            QPushButton[danger="true"]:hover, QPushButton#stopButton:hover {{
                background-color: {t['critical']};
            }}

            /* ============================================
               INPUT FIELDS
               ============================================ */
            QLineEdit, QSpinBox, QDoubleSpinBox {{
                background-color: {t['bg_input']};
                color: {t['text_primary']};
                border: 1px solid {t['border']};
                border-radius: 4px;
                padding: 6px 10px;
                selection-background-color: {t['accent']};
                selection-color: {t['text_on_accent']};
            }}

            QLineEdit:focus, QSpinBox:focus, QDoubleSpinBox:focus {{
                border: 2px solid {t['accent']};
                padding: 5px 9px;
            }}

            QLineEdit:disabled, QSpinBox:disabled {{
                background-color: {t['bg_button']};
                color: {t['text_disabled']};
            }}

            QLineEdit::placeholder {{
                color: {t['text_secondary']};
            }}

            /* ============================================
               TEXT EDIT
               ============================================ */
            QTextEdit, QPlainTextEdit {{
                background-color: {t['bg_input']};
                color: {t['text_primary']};
                border: 1px solid {t['border']};
                border-radius: 4px;
                padding: 8px;
                selection-background-color: {t['accent']};
                selection-color: {t['text_on_accent']};
            }}

            QTextEdit:focus, QPlainTextEdit:focus {{
                border: 2px solid {t['accent']};
            }}

            /* ============================================
               COMBO BOX
               ============================================ */
            QComboBox {{
                background-color: {t['bg_input']};
                color: {t['text_primary']};
                border: 1px solid {t['border']};
                border-radius: 4px;
                padding: 6px 10px;
                min-height: 20px;
            }}

            QComboBox:hover {{
                border-color: {t['accent']};
            }}

            QComboBox:focus {{
                border: 2px solid {t['accent']};
            }}

            QComboBox::drop-down {{
                border: none;
                width: 24px;
                background-color: transparent;
            }}

            QComboBox::down-arrow {{
                image: none;
                border-left: 5px solid transparent;
                border-right: 5px solid transparent;
                border-top: 6px solid {t['text_secondary']};
                margin-right: 8px;
            }}

            QComboBox::down-arrow:hover {{
                border-top-color: {t['accent']};
            }}

            QComboBox QAbstractItemView {{
                background-color: {t['bg_input']};
                color: {t['text_primary']};
                border: 1px solid {t['border']};
                selection-background-color: {t['accent']};
                selection-color: {t['text_on_accent']};
                outline: none;
            }}

            /* ============================================
               SPIN BOX
               ============================================ */
            QSpinBox::up-button, QSpinBox::down-button,
            QDoubleSpinBox::up-button, QDoubleSpinBox::down-button {{
                background-color: {t['bg_button']};
                border: none;
                width: 16px;
            }}

            QSpinBox::up-button:hover, QSpinBox::down-button:hover,
            QDoubleSpinBox::up-button:hover, QDoubleSpinBox::down-button:hover {{
                background-color: {t['bg_button_hover']};
            }}

            QSpinBox::up-arrow, QDoubleSpinBox::up-arrow {{
                border-left: 4px solid transparent;
                border-right: 4px solid transparent;
                border-bottom: 5px solid {t['text_secondary']};
            }}

            QSpinBox::down-arrow, QDoubleSpinBox::down-arrow {{
                border-left: 4px solid transparent;
                border-right: 4px solid transparent;
                border-top: 5px solid {t['text_secondary']};
            }}

            /* ============================================
               CHECK BOX
               ============================================ */
            QCheckBox {{
                spacing: 8px;
                color: {t['text_primary']};
            }}

            QCheckBox::indicator {{
                width: 18px;
                height: 18px;
                border: 2px solid {t['border']};
                border-radius: 4px;
                background-color: {t['bg_input']};
            }}

            QCheckBox::indicator:hover {{
                border-color: {t['accent']};
            }}

            QCheckBox::indicator:checked {{
                background-color: {t['accent']};
                border-color: {t['accent']};
            }}

            QCheckBox::indicator:checked:hover {{
                background-color: {t['accent_hover']};
            }}

            QCheckBox:disabled {{
                color: {t['text_disabled']};
            }}

            /* ============================================
               RADIO BUTTON
               ============================================ */
            QRadioButton {{
                spacing: 8px;
                color: {t['text_primary']};
            }}

            QRadioButton::indicator {{
                width: 18px;
                height: 18px;
                border: 2px solid {t['border']};
                border-radius: 10px;
                background-color: {t['bg_input']};
            }}

            QRadioButton::indicator:hover {{
                border-color: {t['accent']};
            }}

            QRadioButton::indicator:checked {{
                background-color: {t['accent']};
                border-color: {t['accent']};
            }}

            /* ============================================
               TAB WIDGET - CRITICAL FOR PROPER APPEARANCE
               ============================================ */
            QTabWidget {{
                background-color: transparent;
            }}

            QTabWidget::pane {{
                border: 1px solid {t['border']};
                border-radius: 4px;
                background-color: {t['bg_main']};
                top: -1px;
            }}

            QTabBar {{
                background-color: transparent;
            }}

            QTabBar::tab {{
                background-color: {t['bg_alt']};
                color: {t['text_secondary']};
                border: 1px solid {t['border']};
                border-bottom: none;
                border-top-left-radius: 6px;
                border-top-right-radius: 6px;
                padding: 10px 18px;
                margin-right: 2px;
                font-weight: 500;
                min-width: 80px;
            }}

            QTabBar::tab:hover {{
                background-color: {t['tab_hover_bg']};
                color: {t['text_primary']};
            }}

            QTabBar::tab:selected {{
                background-color: {t['tab_selected_bg']};
                color: {t['accent']};
                border-bottom: 2px solid {t['accent']};
                font-weight: bold;
            }}

            QTabBar::tab:!selected {{
                margin-top: 2px;
            }}

            /* ============================================
               TABLE WIDGET
               ============================================ */
            QTableWidget, QTableView {{
                background-color: {t['bg_input']};
                color: {t['text_primary']};
                border: 1px solid {t['border']};
                border-radius: 4px;
                gridline-color: {t['border']};
                selection-background-color: {t['accent']};
                selection-color: {t['text_on_accent']};
            }}

            QTableWidget::item, QTableView::item {{
                padding: 6px;
                border: none;
            }}

            QTableWidget::item:selected, QTableView::item:selected {{
                background-color: {t['accent']};
                color: {t['text_on_accent']};
            }}

            QTableWidget::item:hover, QTableView::item:hover {{
                background-color: {t['bg_button_hover']};
            }}

            QHeaderView {{
                background-color: {t['bg_alt']};
            }}

            QHeaderView::section {{
                background-color: {t['bg_alt']};
                color: {t['text_primary']};
                padding: 8px;
                border: none;
                border-right: 1px solid {t['border']};
                border-bottom: 1px solid {t['border']};
                font-weight: bold;
            }}

            QHeaderView::section:hover {{
                background-color: {t['bg_button_hover']};
            }}

            /* ============================================
               LIST WIDGET
               ============================================ */
            QListWidget, QListView {{
                background-color: {t['bg_input']};
                color: {t['text_primary']};
                border: 1px solid {t['border']};
                border-radius: 4px;
                outline: none;
            }}

            QListWidget::item, QListView::item {{
                padding: 8px;
                border-radius: 4px;
                margin: 2px;
            }}

            QListWidget::item:selected, QListView::item:selected {{
                background-color: {t['accent']};
                color: {t['text_on_accent']};
            }}

            QListWidget::item:hover, QListView::item:hover {{
                background-color: {t['bg_button_hover']};
            }}

            /* ============================================
               TREE WIDGET
               ============================================ */
            QTreeWidget, QTreeView {{
                background-color: {t['bg_input']};
                color: {t['text_primary']};
                border: 1px solid {t['border']};
                border-radius: 4px;
                outline: none;
            }}

            QTreeWidget::item, QTreeView::item {{
                padding: 4px;
            }}

            QTreeWidget::item:selected, QTreeView::item:selected {{
                background-color: {t['accent']};
                color: {t['text_on_accent']};
            }}

            QTreeWidget::branch {{
                background-color: transparent;
            }}

            /* ============================================
               SCROLL BAR
               ============================================ */
            QScrollBar:vertical {{
                background-color: {t['scrollbar_bg']};
                width: 12px;
                border-radius: 6px;
                margin: 0;
            }}

            QScrollBar::handle:vertical {{
                background-color: {t['scrollbar_handle']};
                min-height: 30px;
                border-radius: 6px;
                margin: 2px;
            }}

            QScrollBar::handle:vertical:hover {{
                background-color: {t['accent']};
            }}

            QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {{
                height: 0;
                background: none;
            }}

            QScrollBar:horizontal {{
                background-color: {t['scrollbar_bg']};
                height: 12px;
                border-radius: 6px;
                margin: 0;
            }}

            QScrollBar::handle:horizontal {{
                background-color: {t['scrollbar_handle']};
                min-width: 30px;
                border-radius: 6px;
                margin: 2px;
            }}

            QScrollBar::handle:horizontal:hover {{
                background-color: {t['accent']};
            }}

            QScrollBar::add-line:horizontal, QScrollBar::sub-line:horizontal {{
                width: 0;
                background: none;
            }}

            /* ============================================
               PROGRESS BAR
               ============================================ */
            QProgressBar {{
                background-color: {t['bg_input']};
                border: 1px solid {t['border']};
                border-radius: 6px;
                text-align: center;
                color: {t['text_primary']};
                font-weight: bold;
                min-height: 20px;
            }}

            QProgressBar::chunk {{
                background-color: {t['accent']};
                border-radius: 5px;
            }}

            /* ============================================
               STATUS BAR
               ============================================ */
            QStatusBar {{
                background-color: {t['bg_alt']};
                color: {t['text_primary']};
                border-top: 1px solid {t['border']};
                padding: 4px 8px;
            }}

            QStatusBar::item {{
                border: none;
            }}

            /* ============================================
               MENU BAR
               ============================================ */
            QMenuBar {{
                background-color: {t['bg_alt']};
                color: {t['text_primary']};
                border-bottom: 1px solid {t['border']};
                padding: 4px;
            }}

            QMenuBar::item {{
                background-color: transparent;
                padding: 6px 12px;
                border-radius: 4px;
            }}

            QMenuBar::item:selected {{
                background-color: {t['accent']};
                color: {t['text_on_accent']};
            }}

            QMenu {{
                background-color: {t['bg_alt']};
                color: {t['text_primary']};
                border: 1px solid {t['border']};
                border-radius: 4px;
                padding: 4px;
            }}

            QMenu::item {{
                padding: 8px 24px;
                border-radius: 4px;
            }}

            QMenu::item:selected {{
                background-color: {t['accent']};
                color: {t['text_on_accent']};
            }}

            QMenu::separator {{
                height: 1px;
                background-color: {t['border']};
                margin: 4px 8px;
            }}

            /* ============================================
               TOOL BUTTON
               ============================================ */
            QToolButton {{
                background-color: transparent;
                color: {t['text_primary']};
                border: none;
                border-radius: 4px;
                padding: 6px;
            }}

            QToolButton:hover {{
                background-color: {t['bg_button_hover']};
            }}

            QToolButton:pressed {{
                background-color: {t['bg_button_pressed']};
            }}

            /* ============================================
               SPLITTER
               ============================================ */
            QSplitter::handle {{
                background-color: {t['border']};
            }}

            QSplitter::handle:horizontal {{
                width: 2px;
            }}

            QSplitter::handle:vertical {{
                height: 2px;
            }}

            QSplitter::handle:hover {{
                background-color: {t['accent']};
            }}

            /* ============================================
               DIALOG
               ============================================ */
            QDialog {{
                background-color: {t['bg_main']};
            }}

            QDialogButtonBox QPushButton {{
                min-width: 80px;
            }}

            /* ============================================
               TOOLTIP
               ============================================ */
            QToolTip {{
                background-color: {t['bg_alt']};
                color: {t['text_primary']};
                border: 1px solid {t['border']};
                border-radius: 4px;
                padding: 6px;
            }}

            /* ============================================
               SLIDER
               ============================================ */
            QSlider::groove:horizontal {{
                height: 6px;
                background-color: {t['bg_button']};
                border-radius: 3px;
            }}

            QSlider::handle:horizontal {{
                width: 16px;
                height: 16px;
                background-color: {t['accent']};
                border-radius: 8px;
                margin: -5px 0;
            }}

            QSlider::handle:horizontal:hover {{
                background-color: {t['accent_hover']};
            }}

            /* ============================================
               FRAME
               ============================================ */
            QFrame[frameShape="4"], QFrame[frameShape="5"] {{
                background-color: {t['border']};
            }}
        """

    def _update_custom_components(self, theme):
        """Update components that need special handling"""
        t = theme

        # Update CollapsibleBox styling
        collapsible_style = f"""
            QToolButton {{
                background-color: {t['bg_button']};
                color: {t['text_primary']};
                border: 1px solid {t['border']};
                border-radius: 4px;
                font-weight: bold;
                font-size: {self.FONT_SIZE_NORMAL}pt;
                padding: 10px;
                text-align: left;
            }}
            QToolButton:hover {{
                background-color: {t['bg_button_hover']};
                border-color: {t['accent']};
            }}
        """
        collapsible_content_style = f"""
            background-color: {t['bg_input']};
            border: 1px solid {t['border']};
            border-radius: 4px;
            border-top: none;
            border-top-left-radius: 0;
            border-top-right-radius: 0;
        """

        for box_name in ['module_box', 'settings_box', 'http_config_box']:
            if hasattr(self.gui, box_name):
                box = getattr(self.gui, box_name)
                if hasattr(box, 'toggle_button'):
                    box.toggle_button.setStyleSheet(collapsible_style)
                if hasattr(box, 'content_area'):
                    box.content_area.setStyleSheet(collapsible_content_style)

        # Update output console with monospace font
        if hasattr(self.gui, 'output_console'):
            self.gui.output_console.setStyleSheet(f"""
                QTextEdit {{
                    background-color: {t['console_bg']};
                    color: {t['console_text']};
                    border: 1px solid {t['border']};
                    border-radius: 6px;
                    padding: 12px;
                    font-family: {self.FONT_FAMILY_MONO};
                    font-size: {self.FONT_SIZE_NORMAL}pt;
                    selection-background-color: {t['accent']};
                    selection-color: {t['text_on_accent']};
                }}
            """)

        # Update headers/cookies inputs with monospace font
        mono_input_style = f"""
            background-color: {t['bg_input']};
            color: {t['accent']};
            border: 1px solid {t['border']};
            border-radius: 4px;
            padding: 8px;
            font-family: {self.FONT_FAMILY_MONO};
            font-size: {self.FONT_SIZE_SMALL}pt;
        """
        if hasattr(self.gui, 'headers_input'):
            self.gui.headers_input.setStyleSheet(f"QTextEdit {{ {mono_input_style} }}")
        if hasattr(self.gui, 'cookies_input'):
            self.gui.cookies_input.setStyleSheet(f"QLineEdit {{ {mono_input_style} }}")

        # Update current module label
        if hasattr(self.gui, 'current_module_label'):
            self.gui.current_module_label.setStyleSheet(f"""
                color: {t['accent']};
                font-size: {self.FONT_SIZE_TITLE}pt;
                font-weight: bold;
            """)

        # Update vulnerability count labels
        for label_name in ['total_vulns_label', 'critical_label', 'high_label', 'medium_label']:
            if hasattr(self.gui, label_name):
                label = getattr(self.gui, label_name)
                if 'critical' in label_name:
                    color = t['critical']
                elif 'high' in label_name:
                    color = t['error']
                elif 'medium' in label_name:
                    color = t['warning']
                else:
                    color = t['text_primary']
                label.setStyleSheet(f"color: {color}; font-weight: bold;")

        # Update start/stop/pause buttons
        if hasattr(self.gui, 'start_btn'):
            self.gui.start_btn.setStyleSheet(f"""
                QPushButton {{
                    background-color: {t['success']};
                    color: white;
                    font-weight: bold;
                    font-size: {self.FONT_SIZE_LARGE}pt;
                    padding: 10px 24px;
                    border: none;
                    border-radius: 6px;
                }}
                QPushButton:hover {{
                    background-color: #43a047;
                }}
                QPushButton:disabled {{
                    background-color: {t['bg_button']};
                    color: {t['text_disabled']};
                }}
            """)

        if hasattr(self.gui, 'stop_btn'):
            self.gui.stop_btn.setStyleSheet(f"""
                QPushButton {{
                    background-color: {t['error']};
                    color: white;
                    font-weight: bold;
                    font-size: {self.FONT_SIZE_LARGE}pt;
                    padding: 10px 24px;
                    border: none;
                    border-radius: 6px;
                }}
                QPushButton:hover {{
                    background-color: {t['critical']};
                }}
                QPushButton:disabled {{
                    background-color: {t['bg_button']};
                    color: {t['text_disabled']};
                }}
            """)

        if hasattr(self.gui, 'pause_btn'):
            self.gui.pause_btn.setStyleSheet(f"""
                QPushButton {{
                    background-color: {t['warning']};
                    color: white;
                    font-weight: bold;
                    font-size: {self.FONT_SIZE_LARGE}pt;
                    padding: 10px 24px;
                    border: none;
                    border-radius: 6px;
                }}
                QPushButton:hover {{
                    background-color: #f57c00;
                }}
                QPushButton:disabled {{
                    background-color: {t['bg_button']};
                    color: {t['text_disabled']};
                }}
            """)

        # Update plugins tab if it exists
        if hasattr(self.gui, 'plugins_tab_builder'):
            self.gui.plugins_tab_builder.apply_theme()
