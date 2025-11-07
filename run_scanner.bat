@echo off
setlocal EnableDelayedExpansion

echo ================================================================================
echo                          DOMINATOR WEB SCANNER                              
echo                         Press Ctrl+C to stop immediately                     
echo ================================================================================

REM Check if Python is available
python --version >nul 2>&1
if !ERRORLEVEL! neq 0 (
    echo [ERROR] Python not found. Please install Python and add it to PATH.
    pause
    exit /b 1
)

echo Starting scanner with arguments: -t http://185.233.118.120:8082/xvwa/login.php -m dirbrute --timeout 15 --threads 5
echo.

REM Start Python script in background and get PID
for /f "tokens=2" %%i in ('wmic process call create "python main.py -t http://185.233.118.120:8082/xvwa/login.php -m dirbrute --timeout 15 --threads 5" ^| find "ProcessId"') do set PID=%%i

REM Monitor for completion or interruption
:WAIT_LOOP
timeout /t 1 /nobreak >nul 2>&1
if !ERRORLEVEL! == 1 (
    echo.
    echo [!] Ctrl+C обнаружен - немедленная остановка сканера...
    
    REM Kill Python processes forcefully
    taskkill /F /IM python.exe /T >nul 2>&1
    taskkill /F /IM python3.exe /T >nul 2>&1
    taskkill /F /IM py.exe /T >nul 2>&1
    
    echo [!] Сканер остановлен принудительно
    exit /b 130
)

REM Check if Python process is still running
tasklist /FI "IMAGENAME eq python.exe" 2>NUL | find /I "python.exe" >nul
if !ERRORLEVEL! == 1 (
    tasklist /FI "IMAGENAME eq python3.exe" 2>NUL | find /I "python3.exe" >nul
    if !ERRORLEVEL! == 1 (
        echo.
        echo [INFO] Сканер завершился нормально
        exit /b 0
    )
)

goto WAIT_LOOP
