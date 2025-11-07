@echo off
setlocal EnableDelayedExpansion

echo Starting Web Vulnerability Scanner...
echo Press Ctrl+C to stop immediately

REM Start Python script and capture its PID
start /B python main.py %*
set PYTHON_PID=!ERRORLEVEL!

REM Wait for user input or script completion
:WAIT_LOOP
timeout /t 1 /nobreak >nul 2>&1
if !ERRORLEVEL! == 1 (
    echo.
    echo [!] Ctrl+C detected - stopping scanner immediately...
    taskkill /F /IM python.exe >nul 2>&1
    taskkill /F /IM python3.exe >nul 2>&1
    echo [!] Scanner stopped
    exit /b 1
)

REM Check if Python process is still running
tasklist /FI "IMAGENAME eq python.exe" 2>NUL | find /I /N "python.exe" >nul
if !ERRORLEVEL! == 1 (
    tasklist /FI "IMAGENAME eq python3.exe" 2>NUL | find /I /N "python3.exe" >nul
    if !ERRORLEVEL! == 1 (
        echo Scanner completed normally
        exit /b 0
    )
)

goto WAIT_LOOP
