@echo off
:: Launch Dominator GUI without console window
:: This batch file finds pythonw.exe and launches the GUI silently

setlocal EnableDelayedExpansion

:: Get script directory
set SCRIPT_DIR=%~dp0

:: Find Python installation - prefer pythonw.exe (no console)
set PYTHON_PATH=

:: Check user's local Python installations first (common on Windows)
for %%V in (314 313 312 311 310 39) do (
    if exist "%LOCALAPPDATA%\Programs\Python\Python%%V\pythonw.exe" (
        set PYTHON_PATH=%LOCALAPPDATA%\Programs\Python\Python%%V\pythonw.exe
        goto :found
    )
)

:: Check system-wide installations
for %%V in (314 313 312 311 310 39) do (
    if exist "C:\Python%%V\pythonw.exe" (
        set PYTHON_PATH=C:\Python%%V\pythonw.exe
        goto :found
    )
)

:: Try to find pythonw in PATH
for /f "tokens=*" %%i in ('where pythonw.exe 2^>nul') do (
    set PYTHON_PATH=%%i
    goto :found
)

:: Fall back to python.exe if pythonw not found
for /f "tokens=*" %%i in ('where python.exe 2^>nul') do (
    set PYTHON_PATH=%%i
    goto :found
)

:found
if "%PYTHON_PATH%"=="" (
    echo ERROR: Python not found. Please install Python and add it to PATH.
    pause
    exit /b 1
)

:: Launch GUI silently
:: pythonw.exe runs without any console window
:: python.exe with /min minimizes the window immediately
if /i "!PYTHON_PATH:~-11!"=="pythonw.exe" (
    start "" "!PYTHON_PATH!" "%SCRIPT_DIR%main.py" --gui
) else (
    start /min "" "!PYTHON_PATH!" "%SCRIPT_DIR%main.py" --gui
)

exit /b 0
