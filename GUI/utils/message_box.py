#!/usr/bin/env python3
"""
Message Box Utilities for Dominator GUI
Provides settings-aware message boxes with "Do not show again" functionality
Also includes dialog tracking to prevent duplicate windows
"""

import json
import time
from pathlib import Path
from PyQt5.QtWidgets import QMessageBox, QCheckBox
from PyQt5.QtCore import Qt


# Settings file path
SETTINGS_FILE = Path(__file__).parent.parent.parent / "settings.json"


# Dialog tracking to prevent duplicates
class DialogTracker:
    """Tracks open dialogs to prevent duplicates"""
    _instance = None

    @classmethod
    def get_instance(cls):
        if cls._instance is None:
            cls._instance = DialogTracker()
        return cls._instance

    def __init__(self):
        self._open_dialogs = {}  # key -> (timestamp, count)
        self._cooldown = 2.0  # seconds before same dialog can appear again
        self._max_duplicates = 3  # max same dialogs in cooldown period

    def can_show(self, dialog_key):
        """Check if dialog can be shown (not a duplicate)"""
        now = time.time()

        if dialog_key in self._open_dialogs:
            last_time, count = self._open_dialogs[dialog_key]

            # Reset if cooldown passed
            if now - last_time > self._cooldown:
                self._open_dialogs[dialog_key] = (now, 1)
                return True

            # Block if too many duplicates
            if count >= self._max_duplicates:
                return False

            # Allow but increment count
            self._open_dialogs[dialog_key] = (last_time, count + 1)
            return True

        # First time seeing this dialog
        self._open_dialogs[dialog_key] = (now, 1)
        return True

    def clear(self):
        """Clear all tracked dialogs"""
        self._open_dialogs.clear()


def get_dialog_tracker():
    """Get the singleton dialog tracker"""
    return DialogTracker.get_instance()


def get_settings():
    """Load settings from JSON file"""
    try:
        if SETTINGS_FILE.exists():
            with open(SETTINGS_FILE, 'r', encoding='utf-8') as f:
                return json.load(f)
    except Exception as e:
        print(f"Error loading settings: {e}")
    return {}


def save_settings(settings):
    """Save settings to JSON file"""
    try:
        with open(SETTINGS_FILE, 'w', encoding='utf-8') as f:
            json.dump(settings, indent=2, fp=f)
        return True
    except Exception as e:
        print(f"Error saving settings: {e}")
        return False


def is_warning_suppressed(setting_key):
    """Check if a warning is suppressed by the user"""
    if not setting_key:
        return False

    settings = get_settings()
    suppressed_warnings = settings.get("suppressed_warnings", {})
    return suppressed_warnings.get(setting_key, False)


def suppress_warning(setting_key):
    """Mark a warning as suppressed"""
    if not setting_key:
        return

    settings = get_settings()
    if "suppressed_warnings" not in settings:
        settings["suppressed_warnings"] = {}

    settings["suppressed_warnings"][setting_key] = True
    save_settings(settings)


def reset_all_warnings():
    """Reset all 'do not show again' preferences"""
    settings = get_settings()
    settings["suppressed_warnings"] = {}
    save_settings(settings)


def show_warning(parent, title, message, setting_key=None):
    """
    Show warning with optional 'do not show again' checkbox

    Args:
        parent: Parent widget
        title: Dialog title
        message: Warning message
        setting_key: Unique key to save preference (e.g., "warning_proxy_started")

    Returns:
        QMessageBox.StandardButton: The button clicked (Ok, etc.)
    """
    # Check if user chose to hide this warning
    if setting_key and is_warning_suppressed(setting_key):
        return QMessageBox.Ok

    # Check for duplicate dialogs
    dialog_key = f"warning:{title}:{message[:50]}"
    tracker = get_dialog_tracker()
    if not tracker.can_show(dialog_key):
        return QMessageBox.Ok  # Silently skip duplicate

    # Create message box
    msg_box = QMessageBox(parent)
    msg_box.setIcon(QMessageBox.Warning)
    msg_box.setWindowTitle(title)
    msg_box.setText(message)
    msg_box.setStandardButtons(QMessageBox.Ok)

    # Add checkbox if setting_key provided
    checkbox = None
    if setting_key:
        checkbox = QCheckBox("Do not show this again")
        msg_box.setCheckBox(checkbox)

    # Show dialog
    result = msg_box.exec_()

    # Save preference if checkbox checked
    if checkbox and checkbox.isChecked():
        suppress_warning(setting_key)

    return result


def show_information(parent, title, message, setting_key=None):
    """
    Show information dialog with optional 'do not show again' checkbox

    Args:
        parent: Parent widget
        title: Dialog title
        message: Information message
        setting_key: Unique key to save preference

    Returns:
        QMessageBox.StandardButton: The button clicked
    """
    # Check if user chose to hide this message
    if setting_key and is_warning_suppressed(setting_key):
        return QMessageBox.Ok

    # Check for duplicate dialogs
    dialog_key = f"info:{title}:{message[:50]}"
    tracker = get_dialog_tracker()
    if not tracker.can_show(dialog_key):
        return QMessageBox.Ok  # Silently skip duplicate

    # Create message box
    msg_box = QMessageBox(parent)
    msg_box.setIcon(QMessageBox.Information)
    msg_box.setWindowTitle(title)
    msg_box.setText(message)
    msg_box.setStandardButtons(QMessageBox.Ok)

    # Add checkbox if setting_key provided
    checkbox = None
    if setting_key:
        checkbox = QCheckBox("Do not show this again")
        msg_box.setCheckBox(checkbox)

    # Show dialog
    result = msg_box.exec_()

    # Save preference if checkbox checked
    if checkbox and checkbox.isChecked():
        suppress_warning(setting_key)

    return result


def show_question(parent, title, message, buttons=None, default_button=None, setting_key=None, default_response=None):
    """
    Show question dialog with optional 'do not show again' checkbox

    Args:
        parent: Parent widget
        title: Dialog title
        message: Question message
        buttons: QMessageBox buttons (default: Yes | No)
        default_button: Default selected button
        setting_key: Unique key to save preference
        default_response: Response to return when warning is suppressed

    Returns:
        QMessageBox.StandardButton: The button clicked
    """
    if buttons is None:
        buttons = QMessageBox.Yes | QMessageBox.No
    if default_button is None:
        default_button = QMessageBox.No
    if default_response is None:
        default_response = QMessageBox.Yes

    # Check if user chose to hide this question
    if setting_key and is_warning_suppressed(setting_key):
        return default_response

    # Create message box
    msg_box = QMessageBox(parent)
    msg_box.setIcon(QMessageBox.Question)
    msg_box.setWindowTitle(title)
    msg_box.setText(message)
    msg_box.setStandardButtons(buttons)
    msg_box.setDefaultButton(default_button)

    # Add checkbox if setting_key provided
    checkbox = None
    if setting_key:
        checkbox = QCheckBox("Do not show this again")
        msg_box.setCheckBox(checkbox)

    # Show dialog
    result = msg_box.exec_()

    # Save preference if checkbox checked
    if checkbox and checkbox.isChecked():
        suppress_warning(setting_key)

    return result


def get_suppressed_warnings():
    """Get list of all suppressed warning keys"""
    settings = get_settings()
    suppressed = settings.get("suppressed_warnings", {})
    return [key for key, value in suppressed.items() if value]
