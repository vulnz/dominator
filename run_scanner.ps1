# PowerShell script for running Web Vulnerability Scanner
param(
    [Parameter(ValueFromRemainingArguments=$true)]
    [string[]]$Arguments
)

Write-Host "================================================================================" -ForegroundColor Cyan
Write-Host "                          DOMINATOR WEB SCANNER                              " -ForegroundColor Cyan
Write-Host "                         Press Ctrl+C to stop immediately                     " -ForegroundColor Cyan
Write-Host "================================================================================" -ForegroundColor Cyan

# Check if Python is available
try {
    $pythonVersion = python --version 2>&1
    if ($LASTEXITCODE -ne 0) {
        throw "Python not found"
    }
    Write-Host "Using Python: $pythonVersion" -ForegroundColor Green
} catch {
    Write-Host "[ERROR] Python not found. Please install Python and add it to PATH." -ForegroundColor Red
    Read-Host "Press Enter to exit"
    exit 1
}

# Join arguments for display
$argsString = $Arguments -join " "
Write-Host "Starting scanner with arguments: $argsString" -ForegroundColor Yellow
Write-Host ""

# Start Python process
try {
    $process = Start-Process -FilePath "python" -ArgumentList "main.py $argsString" -PassThru -NoNewWindow
    
    # Monitor process
    Write-Host "Scanner started (PID: $($process.Id)). Press Ctrl+C to stop..." -ForegroundColor Green
    
    # Wait for process to complete or user interruption
    while (!$process.HasExited) {
        Start-Sleep -Milliseconds 500
        
        # Check if Ctrl+C was pressed (this will be handled by PowerShell's built-in handler)
        if ([Console]::KeyAvailable) {
            $key = [Console]::ReadKey($true)
            if ($key.Key -eq "C" -and $key.Modifiers -eq "Control") {
                Write-Host ""
                Write-Host "[!] Ctrl+C обнаружен - остановка сканера..." -ForegroundColor Red
                break
            }
        }
    }
    
    if (!$process.HasExited) {
        # Force kill the process and its children
        Write-Host "[!] Принудительная остановка процесса..." -ForegroundColor Red
        Stop-Process -Id $process.Id -Force -ErrorAction SilentlyContinue
        
        # Kill any remaining Python processes related to our scanner
        Get-Process -Name "python*" -ErrorAction SilentlyContinue | Where-Object {
            $_.CommandLine -like "*main.py*"
        } | Stop-Process -Force -ErrorAction SilentlyContinue
        
        Write-Host "[!] Сканер остановлен принудительно" -ForegroundColor Red
        exit 130
    } else {
        Write-Host ""
        Write-Host "[INFO] Сканер завершился нормально" -ForegroundColor Green
        exit $process.ExitCode
    }
    
} catch {
    Write-Host "[ERROR] Ошибка запуска сканера: $($_.Exception.Message)" -ForegroundColor Red
    exit 1
}
