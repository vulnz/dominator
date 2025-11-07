@echo off
setlocal EnableDelayedExpansion

echo ================================================================================
echo                          DOMINATOR WEB SCANNER LAUNCHER                      
echo                         Press Ctrl+C for immediate stop                       
echo ================================================================================

REM Create temporary file to track scanner state
set TEMP_FILE=%TEMP%\scanner_state_%RANDOM%.tmp
echo RUNNING > "%TEMP_FILE%"

REM Start Python script in background
echo Starting scanner with arguments: %*
start /B cmd /c "python main.py %* & echo COMPLETED > \"%TEMP_FILE%\"" 

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
    
    REM Clean up temp file
    if exist "%TEMP_FILE%" del "%TEMP_FILE%" >nul 2>&1
    
    echo [!] Сканер остановлен принудительно
    exit /b 130
)

REM Check if scanner completed normally
if exist "%TEMP_FILE%" (
    findstr /C:"COMPLETED" "%TEMP_FILE%" >nul 2>&1
    if !ERRORLEVEL! == 0 (
        echo.
        echo [INFO] Сканер завершился нормально
        del "%TEMP_FILE%" >nul 2>&1
        exit /b 0
    )
) else (
    REM Temp file deleted - scanner might have crashed
    echo [WARNING] Сканер завершился неожиданно
    exit /b 1
)

REM Continue monitoring
goto MONITOR_LOOP
