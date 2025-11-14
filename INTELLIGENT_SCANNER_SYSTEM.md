# DOMINATOR - Intelligent Scanner System
## Умная система сканирования с минимумом false positives

---

## 🎯 ЦЕЛИ СИСТЕМЫ

1. **Минимум False Positives**: < 5% false positive rate
2. **Максимум Coverage**: > 90% покрытие реальных уязвимостей
3. **Умное определение технологий**: Автоматическая настройка под язык/фрейворк
4. **Автоматические фиксы**: Система сама генерирует фиксы для FP

---

## 🧠 КОМПОНЕНТЫ СИСТЕМЫ

### 1. Tech Detector (`utils/tech_detector.py`)

**Функции:**
- Автоматическое определение языка программирования (PHP, ASP, JSP, Python, Ruby, Node.js)
- Определение web-сервера (Apache, IIS, Nginx, Tomcat)
- Определение фреймворка (Laravel, Django, Rails, Express, Flask, Spring)
- Генерация списка расширений для брутфорса на основе технологии

**Использование:**
```python
from utils.tech_detector import tech_detector

# Detect technology
tech_profile = tech_detector.detect(
    url='http://example.com/index.php',
    headers={'Server': 'Apache/2.4', 'X-Powered-By': 'PHP/7.4'},
    content='<html>...',
    cookies={'PHPSESSID': 'abc123'}
)

# Get extensions for brute force
extensions = tech_detector.get_extensions_for_bruteforce(tech_profile)
# Returns: ['.php', '.php3', '.php4', '.inc', '.txt', '.bak', ...]

# Check if module should test this site
should_test = tech_detector.should_test_module('php_object_injection', tech_profile)
# Returns: True (это PHP сайт)
```

**Детекция работает на основе:**
- HTTP headers (`X-Powered-By`, `Server`, `X-AspNet-Version`)
- URL расширений (`.php`, `.asp`, `.jsp`)
- Content patterns (`<?php`, `__VIEWSTATE`, `JSESSIONID`)
- Cookie names (`PHPSESSID`, `ASP.NET_SessionId`, `_rails_session`)

---

### 2. False Positive Analyzer (`utils/false_positive_analyzer.py`)

**Функции:**
- Автоматический анализ результатов сканирования
- Определение паттернов false positives
- Генерация Python кода для фиксов

**Встроенные правила:**

| Модуль | False Positive | Фикс |
|--------|---------------|------|
| PHP Object Injection | Детект на ASP/ASPX сайтах | Добавить проверку: только PHP сайты |
| SSTI | Слабый payload `7*7=49` | Использовать уникальные: `{{7*7*7}}=343` |
| XSS | Простая рефлексия без контекста | Проверять контекст (script, attribute, etc.) |
| SQLi Time-Based | Короткие задержки | Увеличить порог, требовать 3+ теста |
| LFI | HTTP redirect (30x) | Исключить 30x из детекции |
| SSRF | Запрос на тот же домен | Исключить same-domain |
| CSRF | GET без state change | Только POST/PUT/DELETE |
| DirBrute | Статические директории (`/css`, `/js`) | Исключить из findings |

**Использование:**
```python
from utils.false_positive_analyzer import fp_analyzer

# Analyze scan results
report = fp_analyzer.analyze_scan_results('scan_results.json')

print(f"False positives: {report['false_positives']}")
print(f"FP rate: {report['false_positive_rate']:.1f}%")

# Generate fix script
fix_script = fp_analyzer.generate_fixes(report)

# Save and execute
with open('auto_fixes.py', 'w') as f:
    f.write(fix_script)
```

---

### 3. Master Analysis Script (`analyze_and_fix.py`)

**Функции:**
- Анализирует ВСЕ репорты сразу
- Генерирует consolidated отчет
- Автоматически создает скрипт фиксов

**Использование:**
```bash
# После завершения сканов
python analyze_and_fix.py

# Output:
# - false_positive_analysis.json (детальный анализ)
# - auto_generated_fixes.py (скрипт фиксов)
```

---

## 🔄 WORKFLOW: Iterative Improvement

```
┌─────────────────┐
│  1. RUN SCANS   │
│  All 3 targets  │
└────────┬────────┘
         │
         v
┌─────────────────┐
│ 2. ANALYZE FPs  │
│ analyze_and_fix │
└────────┬────────┘
         │
         v
┌─────────────────┐
│ 3. APPLY FIXES  │
│ auto_generated  │
│    _fixes.py    │
└────────┬────────┘
         │
         v
┌─────────────────┐
│ 4. RE-SCAN      │
│ Verify fixes    │
└────────┬────────┘
         │
         v
     [Repeat until
      FP rate < 5%]
```

---

## 📋 ROTATION PROTOCOL

### ROTATION 3 - Current Status

**Fixes Applied:**
1. ✅ PHP Object Injection: METHOD 3 disabled, confidence 0.85+
2. ✅ SSTI: Unique payloads (343, 481, 5329)
3. ✅ OOB: Proof URLs in evidence

**Expected Results:**
- PHP Object Injection on TestASP: 11 → 0 (100% improvement)
- Overall FP rate: ~15% → < 10%

**Scans Running:**
- XVWA: `rotation3_xvwa.log`
- TestPHP: `rotation3_testphp.log`
- TestASP: `rotation3_testasp.log`

### ROTATION 4 - Plan

**After ROTATION 3 completes:**

1. **Run analysis:**
   ```bash
   python analyze_and_fix.py
   ```

2. **Review false_positive_analysis.json:**
   - Check FP rate by module
   - Identify new patterns

3. **Apply generated fixes:**
   ```bash
   python auto_generated_fixes.py
   ```

4. **Add tech detection to modules:**
   - Integrate `tech_detector` into scanner
   - Skip incompatible modules (e.g., PHP Object Injection on ASP)

5. **Re-run scans:**
   ```bash
   python main.py -t http://127.0.0.1/xvwa/ --auto-report --format html
   python main.py -t http://testphp.vulnweb.com/ --auto-report --format html
   python main.py -t http://testasp.vulnweb.com/ --auto-report --format html
   ```

---

## 🎨 НОВЫЕ МОДУЛИ

### XXE (XML External Entity)
**Status:** Planned
**File:** `modules/xxe/module.py`

**Features:**
- Error-based detection (XML parsing errors)
- OOB detection (external entity callback)
- File disclosure detection (`/etc/passwd`, `C:\windows\win.ini`)

**Payloads:**
```xml
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://oob-callback.com">]>
```

### RFI (Remote File Inclusion)
**Status:** Planned
**File:** `modules/rfi/module.py`

**Tech Detection:**
- Only test on PHP sites (RFI is PHP-specific)
- Skip on ASP/JSP/Python sites

---

## 📊 METRICS & TARGETS

### Current State (ROTATION 2)
| Metric | Value | Target |
|--------|-------|--------|
| Total Findings | 196 | 200+ |
| False Positives | ~30 (15%) | < 10 (5%) |
| PHP Obj Injection FPs | 11 on TestASP | 0 |
| Coverage (XVWA) | 60/~80 (75%) | 72/80 (90%) |

### Target State (ROTATION 5+)
| Metric | Target |
|--------|--------|
| False Positive Rate | < 5% |
| Coverage | > 90% |
| Precision | > 95% |
| Recall | > 90% |

**Формулы:**
```
Precision = True Positives / (True Positives + False Positives)
Recall = True Positives / (True Positives + False Negatives)
F1 Score = 2 * (Precision * Recall) / (Precision + Recall)
```

---

## 🛠️ INTEGRATION POINTS

### 1. Scanner Core Integration

**File:** `core/clean_scanner.py`

**Add tech detection:**
```python
from utils.tech_detector import tech_detector

# During crawling phase
tech_profile = tech_detector.detect(url, headers, content, cookies)

# Store in scan context
self.tech_profile = tech_profile

# Before running module
if not tech_detector.should_test_module(module_name, self.tech_profile):
    logger.info(f"Skipping {module_name} (incompatible with {tech_profile.language})")
    continue
```

### 2. Directory Brute Force Integration

**File:** `modules/dirbrute/module.py`

**Smart extension selection:**
```python
from utils.tech_detector import tech_detector

# Get extensions based on detected tech
extensions = tech_detector.get_extensions_for_bruteforce(tech_profile)

# Use only relevant extensions
for path in self.paths:
    for ext in extensions:
        test_url = f"{base_url}/{path}{ext}"
        # Test URL...
```

### 3. Module-Specific Tech Checks

**Example: PHP Object Injection**
```python
def scan(self, targets, http_client):
    # Check if site is PHP
    tech_profile = getattr(self, 'tech_profile', None)
    if tech_profile and tech_profile.language != 'php':
        logger.info("Skipping PHP Object Injection: not a PHP site")
        return []

    # Continue with scan...
```

---

## 🚀 QUICK START

### Run Complete Analysis Cycle

```bash
# 1. Run scans (already running in ROTATION 3)
# Wait for completion...

# 2. Analyze results
python analyze_and_fix.py

# 3. Review analysis
cat false_positive_analysis.json

# 4. Apply fixes
python auto_generated_fixes.py

# 5. Re-scan
python multi_target_scan.py -f test_targets.txt --format html
```

### Check Scan Progress

```bash
# Check if scans completed
tail -20 rotation3_*.log

# Count vulnerabilities
grep "vulnerabilities found" rotation3_*.log

# Check for PHP Object Injection on TestASP (should be 0)
grep -i "php object injection" rotation3_testasp.log
```

---

## 📈 SUCCESS CRITERIA

### ROTATION 3 ✅
- [x] PHP Object Injection: METHOD 3 disabled
- [x] SSTI: Unique payloads added
- [x] OOB: Proof URLs added
- [ ] Scans completed (in progress)
- [ ] Results analyzed

### ROTATION 4 🎯
- [ ] Tech detector integrated into scanner
- [ ] Auto-fix system validated
- [ ] FP rate < 10%
- [ ] New modules added (XXE, RFI)

### ROTATION 5+ 🏆
- [ ] FP rate < 5%
- [ ] Coverage > 90%
- [ ] All modules optimized
- [ ] Production-ready scanner

---

## 🔧 TROUBLESHOOTING

### Issue: High FP Rate

**Solution:**
1. Run `python analyze_and_fix.py`
2. Check `false_positive_analysis.json` for patterns
3. Apply `auto_generated_fixes.py`
4. Re-scan and verify

### Issue: Low Coverage

**Solution:**
1. Check payload limits in config files
2. Increase `max_payloads` to 200+
3. Lower confidence thresholds (0.4-0.6)
4. Add more detection patterns

### Issue: Module Skipped

**Solution:**
1. Check tech detection: `tech_profile.language`
2. Verify `should_test_module()` logic
3. Adjust module requirements in `tech_detector.py`

---

## 📚 FILES & STRUCTURE

```
dominator/
├── utils/
│   ├── tech_detector.py          # Technology detection
│   ├── false_positive_analyzer.py # FP analysis & fix generation
│   └── oob_detector.py            # OOB detection (already exists)
│
├── modules/
│   ├── php_object_injection/      # Fixed in ROTATION 3
│   ├── ssti/                      # Fixed in ROTATION 3
│   ├── xxe/                       # New module (planned)
│   └── rfi/                       # New module (planned)
│
├── analyze_and_fix.py             # Master analysis script
├── apply_rotation3_fixes.py       # ROTATION 3 fixes
├── auto_generated_fixes.py        # Generated by analyzer
│
├── rotation3_*.log                # Scan logs
├── scan_report_*.html             # Scan reports
├── false_positive_analysis.json   # FP analysis
└── INTELLIGENT_SCANNER_SYSTEM.md  # This file
```

---

**Last Updated:** 2025-11-13
**Status:** ROTATION 3 scans in progress, system ready for analysis

