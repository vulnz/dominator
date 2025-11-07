@echo off
setlocal EnableDelayedExpansion

echo ================================================================================
echo                          DOMINATOR WEB SCANNER LAUNCHER                      
echo                         Press Ctrl+C for immediate stop                       
echo ================================================================================

REM Check if Python is available
python --version >nul 2>&1
if !ERRORLEVEL! neq 0 (
    echo [ERROR] Python not found. Please install Python and add it to PATH.
    pause
    exit /b 1
)

REM Create temporary file to track scanner state
set TEMP_FILE=%TEMP%\scanner_state_%RANDOM%.tmp
echo RUNNING > "%TEMP_FILE%"

REM Start Python script in background
echo Starting scanner with arguments: %*
echo.
start /B cmd /c "python main.py %* 2>&1 & echo COMPLETED_!ERRORLEVEL! > \"%TEMP_FILE%\"" 

REM Monitor for Ctrl+C and scanner completion
:MONITOR_LOOP
REM Check if user pressed Ctrl+C (timeout returns 1 when interrupted)
timeout /t 1 /nobreak >nul 2>&1
if !ERRORLEVEL! == 1 (
    echo.
    echo [!] Ctrl+C обнаружен - немедленная остановка сканера...
    
    REM Kill all Python processes forcefully
    taskkill /F /IM python.exe /T >nul 2>&1
    taskkill /F /IM python3.exe /T >nul 2>&1
    taskkill /F /IM py.exe /T >nul 2>&1
    taskkill /F /IM cmd.exe /FI "WINDOWTITLE eq *main.py*" /T >nul 2>&1
    
    REM Clean up temp file
    if exist "%TEMP_FILE%" del "%TEMP_FILE%" >nul 2>&1
    
    echo [!] Сканер остановлен принудительно
    exit /b 130
)

REM Check if scanner completed normally
if exist "%TEMP_FILE%" (
    findstr /C:"COMPLETED" "%TEMP_FILE%" >nul 2>&1
    if !ERRORLEVEL! == 0 (
        REM Extract exit code
        for /f "tokens=1 delims=_" %%a in ('findstr /C:"COMPLETED" "%TEMP_FILE%"') do set EXIT_CODE=%%a
        for /f "tokens=2 delims=_" %%b in ('findstr /C:"COMPLETED" "%TEMP_FILE%"') do set EXIT_CODE=%%b
        
        echo.
        echo [INFO] Сканер завершился нормально (код выхода: !EXIT_CODE!)
        del "%TEMP_FILE%" >nul 2>&1
        exit /b !EXIT_CODE!
    )
) else (
    REM Temp file deleted - scanner might have crashed
    echo [WARNING] Сканер завершился неожиданно
    exit /b 1
)

REM Continue monitoring
goto MONITOR_LOOP
