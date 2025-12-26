"""
Dominator GUI Style Constants

Centralized styling configuration for consistent look and feel across all components.
All GUI components should import colors, fonts, and styles from this file.
"""

from PyQt5.QtGui import QFont, QColor


# ============================================================
# BRAND IDENTITY
# ============================================================
BRAND_NAME = "Dominator"
BRAND_TAGLINE = "Web Vulnerability Scanner"
BRAND_VERSION = "2.0"
BRAND_FULL = f"{BRAND_NAME} - {BRAND_TAGLINE}"


# ============================================================
# FONT CONFIGURATION
# ============================================================
FONT_FAMILY = "Segoe UI"
FONT_FAMILY_FALLBACK = "Roboto, Arial, sans-serif"
FONT_FAMILY_MONO = "Consolas"
FONT_FAMILY_MONO_FALLBACK = "'Courier New', monospace"

# Font sizes (in points)
FONT_SIZE_TINY = 8
FONT_SIZE_SMALL = 9
FONT_SIZE_NORMAL = 10
FONT_SIZE_MEDIUM = 11
FONT_SIZE_LARGE = 12
FONT_SIZE_TITLE = 14
FONT_SIZE_HEADER = 16
FONT_SIZE_HERO = 24


# ============================================================
# COLOR PALETTE - DOMINATOR BRAND COLORS
# ============================================================

# Primary brand colors
PRIMARY_GREEN = "#4CAF50"        # Dominator main color
PRIMARY_GREEN_DARK = "#388E3C"   # Hover state
PRIMARY_GREEN_LIGHT = "#81C784"  # Light accent

# Secondary colors
SECONDARY_BLUE = "#2196F3"       # Information
SECONDARY_BLUE_DARK = "#1976D2"  # Hover
SECONDARY_PURPLE = "#9C27B0"     # Special accents

# Severity colors (consistent across all views)
SEVERITY_CRITICAL = "#d32f2f"    # Red - Critical vulnerabilities
SEVERITY_HIGH = "#f44336"        # Light red - High vulnerabilities
SEVERITY_MEDIUM = "#FF9800"      # Orange - Medium vulnerabilities
SEVERITY_LOW = "#4CAF50"         # Green - Low vulnerabilities
SEVERITY_INFO = "#2196F3"        # Blue - Informational findings

# Status colors
STATUS_SUCCESS = "#4CAF50"       # Green
STATUS_WARNING = "#FF9800"       # Orange
STATUS_ERROR = "#f44336"         # Red
STATUS_PENDING = "#9E9E9E"       # Gray
STATUS_RUNNING = "#2196F3"       # Blue

# Background colors (Light theme)
BG_MAIN = "#f5f5f5"
BG_ALT = "#ffffff"
BG_INPUT = "#ffffff"
BG_CARD = "#ffffff"
BG_DARK = "#1a1a1a"

# Text colors
TEXT_PRIMARY = "#212121"
TEXT_SECONDARY = "#757575"
TEXT_MUTED = "#9e9e9e"
TEXT_ON_PRIMARY = "#ffffff"

# Border colors
BORDER_DEFAULT = "#e0e0e0"
BORDER_FOCUS = "#4CAF50"
BORDER_ERROR = "#f44336"

# Console/output colors
CONSOLE_BG = "#1a1a1a"
CONSOLE_TEXT = "#00ff88"


# ============================================================
# SPACING & SIZING
# ============================================================
SPACING_TINY = 4
SPACING_SMALL = 8
SPACING_NORMAL = 12
SPACING_MEDIUM = 16
SPACING_LARGE = 24
SPACING_XLARGE = 32

BORDER_RADIUS_SMALL = 4
BORDER_RADIUS_NORMAL = 6
BORDER_RADIUS_LARGE = 8
BORDER_RADIUS_ROUND = 20

BUTTON_HEIGHT_SMALL = 28
BUTTON_HEIGHT_NORMAL = 36
BUTTON_HEIGHT_LARGE = 44


# ============================================================
# COMMON STYLE CLASSES
# ============================================================

def get_button_style(bg_color=PRIMARY_GREEN, text_color=TEXT_ON_PRIMARY,
                     hover_color=PRIMARY_GREEN_DARK, border_radius=BORDER_RADIUS_NORMAL):
    """Get standard button stylesheet"""
    return f"""
        QPushButton {{
            background-color: {bg_color};
            color: {text_color};
            border: none;
            border-radius: {border_radius}px;
            padding: 10px 20px;
            font-weight: bold;
            font-size: {FONT_SIZE_NORMAL}pt;
            font-family: '{FONT_FAMILY}';
        }}
        QPushButton:hover {{
            background-color: {hover_color};
        }}
        QPushButton:pressed {{
            background-color: {hover_color};
            padding-top: 11px;
            padding-bottom: 9px;
        }}
        QPushButton:disabled {{
            background-color: #cccccc;
            color: #999999;
        }}
    """


def get_group_box_style(accent_color=PRIMARY_GREEN, border_color=BORDER_DEFAULT,
                        bg_color=BG_ALT):
    """Get standard group box stylesheet"""
    return f"""
        QGroupBox {{
            font-weight: bold;
            font-size: {FONT_SIZE_NORMAL}pt;
            font-family: '{FONT_FAMILY}';
            color: {accent_color};
            border: 1px solid {border_color};
            border-radius: {BORDER_RADIUS_LARGE}px;
            margin-top: 12px;
            padding: 15px;
            padding-top: 20px;
            background-color: {bg_color};
        }}
        QGroupBox::title {{
            subcontrol-origin: margin;
            left: 12px;
            padding: 0 8px;
            background-color: {bg_color};
            color: {accent_color};
        }}
    """


def get_input_style(bg_color=BG_INPUT, text_color=TEXT_PRIMARY,
                    border_color=BORDER_DEFAULT, focus_color=BORDER_FOCUS):
    """Get standard input field stylesheet"""
    return f"""
        QLineEdit, QTextEdit, QSpinBox, QComboBox {{
            background-color: {bg_color};
            color: {text_color};
            border: 1px solid {border_color};
            border-radius: {BORDER_RADIUS_NORMAL}px;
            padding: 8px 12px;
            font-size: {FONT_SIZE_NORMAL}pt;
            font-family: '{FONT_FAMILY}';
        }}
        QLineEdit:focus, QTextEdit:focus, QSpinBox:focus, QComboBox:focus {{
            border: 2px solid {focus_color};
            padding: 7px 11px;
        }}
    """


def get_table_style(header_bg=PRIMARY_GREEN, header_text=TEXT_ON_PRIMARY,
                    bg_color=BG_INPUT, alt_bg=BG_ALT, border_color=BORDER_DEFAULT):
    """Get standard table stylesheet"""
    return f"""
        QTableWidget {{
            background-color: {bg_color};
            color: {TEXT_PRIMARY};
            border: 1px solid {border_color};
            border-radius: {BORDER_RADIUS_NORMAL}px;
            gridline-color: {border_color};
            font-size: {FONT_SIZE_NORMAL}pt;
            font-family: '{FONT_FAMILY}';
        }}
        QTableWidget::item {{
            padding: 8px;
        }}
        QTableWidget::item:selected {{
            background-color: {PRIMARY_GREEN};
            color: {TEXT_ON_PRIMARY};
        }}
        QTableWidget::item:hover {{
            background-color: {PRIMARY_GREEN_LIGHT};
        }}
        QHeaderView::section {{
            background-color: {header_bg};
            color: {header_text};
            padding: 10px;
            border: none;
            font-weight: bold;
        }}
    """


def get_card_style(bg_color=BG_CARD, border_color=BORDER_DEFAULT,
                   shadow=True):
    """Get standard card/frame stylesheet"""
    shadow_style = "box-shadow: 0 2px 4px rgba(0,0,0,0.1);" if shadow else ""
    return f"""
        QFrame {{
            background-color: {bg_color};
            border: 1px solid {border_color};
            border-radius: {BORDER_RADIUS_LARGE}px;
            padding: 15px;
            {shadow_style}
        }}
    """


def get_tab_style(selected_color=PRIMARY_GREEN, bg_color=BG_ALT,
                  text_color=TEXT_PRIMARY, border_color=BORDER_DEFAULT):
    """Get standard tab widget stylesheet"""
    return f"""
        QTabWidget::pane {{
            border: 1px solid {border_color};
            border-radius: {BORDER_RADIUS_NORMAL}px;
            background-color: {bg_color};
        }}
        QTabBar::tab {{
            background-color: #f3f4f6;
            color: {text_color};
            padding: 10px 20px;
            border: 1px solid {border_color};
            border-bottom: none;
            border-radius: {BORDER_RADIUS_NORMAL}px {BORDER_RADIUS_NORMAL}px 0 0;
            margin-right: 2px;
            font-weight: 500;
            font-size: {FONT_SIZE_NORMAL}pt;
            font-family: '{FONT_FAMILY}';
        }}
        QTabBar::tab:selected {{
            background-color: {bg_color};
            color: {selected_color};
            border-bottom: 2px solid {selected_color};
            font-weight: bold;
        }}
        QTabBar::tab:hover {{
            background-color: #e5e7eb;
        }}
    """


def get_severity_badge_style(severity: str):
    """Get severity badge stylesheet based on severity level"""
    colors = {
        'CRITICAL': SEVERITY_CRITICAL,
        'HIGH': SEVERITY_HIGH,
        'MEDIUM': SEVERITY_MEDIUM,
        'LOW': SEVERITY_LOW,
        'INFO': SEVERITY_INFO
    }
    color = colors.get(severity.upper(), SEVERITY_INFO)
    return f"""
        QLabel {{
            background-color: {color};
            color: {TEXT_ON_PRIMARY};
            padding: 4px 12px;
            border-radius: {BORDER_RADIUS_ROUND}px;
            font-weight: bold;
            font-size: {FONT_SIZE_SMALL}pt;
        }}
    """


def get_progress_bar_style(color=PRIMARY_GREEN, bg_color=BORDER_DEFAULT):
    """Get progress bar stylesheet"""
    return f"""
        QProgressBar {{
            background-color: {bg_color};
            border: none;
            border-radius: {BORDER_RADIUS_NORMAL}px;
            text-align: center;
            color: {TEXT_PRIMARY};
            font-weight: bold;
            min-height: 20px;
        }}
        QProgressBar::chunk {{
            background-color: {color};
            border-radius: {BORDER_RADIUS_NORMAL - 1}px;
        }}
    """


def get_console_style():
    """Get console/output stylesheet"""
    return f"""
        QTextEdit {{
            background-color: {CONSOLE_BG};
            color: {CONSOLE_TEXT};
            border: 1px solid #333333;
            border-radius: {BORDER_RADIUS_NORMAL}px;
            padding: 12px;
            font-family: '{FONT_FAMILY_MONO}', {FONT_FAMILY_MONO_FALLBACK};
            font-size: {FONT_SIZE_NORMAL}pt;
            selection-background-color: {PRIMARY_GREEN};
            selection-color: {TEXT_ON_PRIMARY};
        }}
    """


# ============================================================
# HELPER FUNCTIONS
# ============================================================

def get_font(size=FONT_SIZE_NORMAL, bold=False, mono=False):
    """Get a QFont with standard settings"""
    family = FONT_FAMILY_MONO if mono else FONT_FAMILY
    font = QFont(family, size)
    if bold:
        font.setBold(True)
    return font


def get_color(color_str):
    """Get a QColor from hex string"""
    return QColor(color_str)


def severity_to_color(severity: str) -> str:
    """Convert severity string to color hex"""
    mapping = {
        'CRITICAL': SEVERITY_CRITICAL,
        'HIGH': SEVERITY_HIGH,
        'MEDIUM': SEVERITY_MEDIUM,
        'LOW': SEVERITY_LOW,
        'INFO': SEVERITY_INFO,
    }
    return mapping.get(severity.upper(), SEVERITY_INFO)


def status_to_color(status: str) -> str:
    """Convert status string to color hex"""
    mapping = {
        'SUCCESS': STATUS_SUCCESS,
        'COMPLETE': STATUS_SUCCESS,
        'WARNING': STATUS_WARNING,
        'ERROR': STATUS_ERROR,
        'FAILED': STATUS_ERROR,
        'PENDING': STATUS_PENDING,
        'WAITING': STATUS_PENDING,
        'RUNNING': STATUS_RUNNING,
        'IN_PROGRESS': STATUS_RUNNING,
    }
    return mapping.get(status.upper(), STATUS_PENDING)


# ============================================================
# BRANDED HEADER STYLE
# ============================================================

def get_header_style():
    """Get Dominator branded header stylesheet"""
    return f"""
        QFrame {{
            background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
                stop:0 {PRIMARY_GREEN}, stop:1 {SECONDARY_BLUE});
            border-radius: {BORDER_RADIUS_LARGE}px;
            padding: 15px;
        }}
        QLabel {{
            color: {TEXT_ON_PRIMARY};
            background: transparent;
        }}
    """


def get_brand_title_style():
    """Get Dominator brand title stylesheet"""
    return f"""
        font-size: {FONT_SIZE_HERO}pt;
        font-weight: bold;
        font-family: '{FONT_FAMILY}';
        color: {PRIMARY_GREEN};
    """
