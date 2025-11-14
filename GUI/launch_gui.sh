#!/bin/bash
# Dominator GUI Launcher for Linux/macOS
# This script launches the Dominator GUI interface

echo "========================================"
echo "   DOMINATOR WEB SCANNER - GUI"
echo "   Advanced Vulnerability Scanner"
echo "========================================"
echo ""

# Check if Python is available
if ! command -v python3 &> /dev/null; then
    echo "ERROR: Python 3 is not installed"
    echo "Please install Python 3.7+ from your package manager"
    exit 1
fi

echo "[*] Checking PyQt5..."
python3 -c "import PyQt5" 2>/dev/null
if [ $? -ne 0 ]; then
    echo "[!] PyQt5 not found. Installing..."
    pip3 install PyQt5
    if [ $? -ne 0 ]; then
        echo "ERROR: Failed to install PyQt5"
        echo "Try: sudo apt install python3-pyqt5 (Ubuntu/Debian)"
        echo "Or:  brew install pyqt5 (macOS)"
        exit 1
    fi
    echo "[+] PyQt5 installed successfully"
fi

echo "[*] Launching Dominator GUI..."
echo ""
python3 dominator_gui.py

if [ $? -ne 0 ]; then
    echo ""
    echo "[!] GUI exited with error"
    read -p "Press Enter to continue..."
fi
