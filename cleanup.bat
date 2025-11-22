@echo off
REM Cleanup script for Dominator - Remove debug data, test files, and cache
REM Run this from the project root directory

echo ================================================
echo Dominator Cleanup Script
echo ================================================
echo.
echo This will remove:
echo   - Python cache (__pycache__, .pyc files)
echo   - Test reports (scan_report_*.html, .json)
echo   - Debug logs (*.log files)
echo   - Build artifacts (build/, dist/)
echo   - Browser user data (cache, profiles)
echo   - PyInstaller specs (*.spec)
echo   - Debug HTML files
echo   - Test files
echo.
pause

echo.
echo [+] Removing Python cache files...
for /d /r . %%d in (__pycache__) do @if exist "%%d" (
    echo     Deleting: %%d
    rd /s /q "%%d"
)

echo.
echo [+] Removing .pyc files...
del /s /q *.pyc 2>nul

echo.
echo [+] Removing PyInstaller spec files...
del /q *.spec 2>nul

echo.
echo [+] Removing test HTML reports...
del /q scan_report_*.html 2>nul
del /q GUI\scan_report_*.html 2>nul

echo.
echo [+] Removing test JSON reports...
del /q scan_report_*.json 2>nul

echo.
echo [+] Removing debug HTML files...
del /q ARCHITECTURE.html 2>nul
del /q TESTING_GUIDE.html 2>nul
del /q BROWSER_INTEGRATION_QUICKSTART.html 2>nul

echo.
echo [+] Removing test log files...
del /q *.log 2>nul
del /q rotation*.log 2>nul
del /q SCAN_*.log 2>nul
del /q test_*.log 2>nul
del /q gui_output.log 2>nul
del /q proxy_test.log 2>nul

echo.
echo [+] Removing build artifacts...
if exist "build\" (
    echo     Deleting: build\
    rd /s /q "build"
)
if exist "dist\" (
    echo     Deleting: dist\
    rd /s /q "dist"
)

echo.
echo [+] Removing old Chrome profile...
if exist "chrome_profile\" (
    echo     Deleting: chrome_profile\
    rd /s /q "chrome_profile"
)

echo.
echo [+] Cleaning Chromium portable user data...
if exist "chromium_portable\user_data\" (
    echo     Deleting: chromium_portable\user_data\
    rd /s /q "chromium_portable\user_data"
)

echo.
echo [+] Removing test files...
if exist "tests\test_*.py" (
    del /q tests\test_*.py 2>nul
)

echo.
echo [+] Removing Firefox portable help.html...
if exist "firefox_portable_app\help.html" (
    del /q "firefox_portable_app\help.html" 2>nul
)

echo.
echo ================================================
echo [+] Cleanup Complete!
echo ================================================
echo.
echo The repository is now clean.
echo Browser user data will be regenerated on next use.
echo.
pause
