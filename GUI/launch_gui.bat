@echo off
REM Dominator GUI Launcher for Windows
REM This script launches the Dominator GUI interface WITHOUT showing console windows

setlocal

REM Get script directory
set SCRIPT_DIR=%~dp0
set PARENT_DIR=%SCRIPT_DIR%..

REM Find pythonw.exe (no console window)
set PYTHON_PATH=

REM Check common locations for pythonw.exe
if exist "C:\Python312\pythonw.exe" set PYTHON_PATH=C:\Python312\pythonw.exe
if exist "C:\Python311\pythonw.exe" set PYTHON_PATH=C:\Python311\pythonw.exe
if exist "C:\Python310\pythonw.exe" set PYTHON_PATH=C:\Python310\pythonw.exe
if exist "C:\Python39\pythonw.exe" set PYTHON_PATH=C:\Python39\pythonw.exe

REM Try to find pythonw in PATH
if "%PYTHON_PATH%"=="" (
    for /f "tokens=*" %%i in ('where pythonw.exe 2^>nul') do set PYTHON_PATH=%%i
)

REM Fall back to python.exe if pythonw not found
if "%PYTHON_PATH%"=="" (
    for /f "tokens=*" %%i in ('where python.exe 2^>nul') do set PYTHON_PATH=%%i
)

if "%PYTHON_PATH%"=="" (
    echo ERROR: Python not found. Please install Python and add it to PATH.
    pause
    exit /b 1
)

REM Launch GUI with no window - use start /B with pythonw, or minimize with python
if /i "%PYTHON_PATH:~-11%"=="pythonw.exe" (
    start "" "%PYTHON_PATH%" "%PARENT_DIR%\main.py" --gui
) else (
    start /min "" "%PYTHON_PATH%" "%PARENT_DIR%\main.py" --gui
)

exit /b 0
