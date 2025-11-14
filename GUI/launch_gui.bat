@echo off
REM Dominator GUI Launcher for Windows
REM This script launches the Dominator GUI interface

echo ========================================
echo    DOMINATOR WEB SCANNER - GUI
echo    Advanced Vulnerability Scanner
echo ========================================
echo.

REM Check if Python is available
python --version >nul 2>&1
if errorlevel 1 (
    echo ERROR: Python is not installed or not in PATH
    echo Please install Python 3.7+ from https://www.python.org
    pause
    exit /b 1
)

echo [*] Checking PyQt5...
python -c "import PyQt5" >nul 2>&1
if errorlevel 1 (
    echo [!] PyQt5 not found. Installing...
    pip install PyQt5
    if errorlevel 1 (
        echo ERROR: Failed to install PyQt5
        pause
        exit /b 1
    )
    echo [+] PyQt5 installed successfully
)

echo [*] Launching Dominator GUI...
echo.
python dominator_gui.py

if errorlevel 1 (
    echo.
    echo [!] GUI exited with error
    pause
)
