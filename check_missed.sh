#!/bin/bash
echo "=== ПРОВЕРКА ПРОПУЩЕННЫХ УЯЗВИМОСТЕЙ ==="
echo ""
echo "XVWA известные уязвимости:"
echo ""

# Check each known vuln
checks=(
    "SQLi Blind:/sqli_blind/"
    "Command Injection:/cmdi/"
    "File Upload:/fileupload/"
    "LFI:/fi/"
    "RFI:/rfi/"
    "XPath:/xpath/"
    "XXE:/xxe/"
    "CSRF:/csrf/"
    "Weak Credentials:login.php"
)

report="scan_report_http___127.0.0.1_xvwa__20251112_144115.html"

for check in "${checks[@]}"; do
    name="${check%:*}"
    path="${check#*:}"
    
    if grep -q "$path" "$report" 2>/dev/null; then
        echo "✅ $name - НАЙДЕНО"
    else
        echo "❌ $name - ПРОПУЩЕНО!"
    fi
done

echo ""
echo "=== СТАТИСТИКА МОДУЛЕЙ ==="
grep -i "Command Injection\|Weak Credential\|File Upload\|XPath" "$report" | wc -l
