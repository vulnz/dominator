# Retest System - Vulnerability Tracking Across Scans

## Overview

The Retest System allows you to track vulnerabilities across multiple scans and automatically identify which vulnerabilities have been:
- ✅ **FIXED** - Present in baseline but not in current scan
- 🆕 **NEW** - Present in current scan but not in baseline
- ⚠️ **STILL VULNERABLE** - Present in both baseline and current scan

## Usage

### 1. Save Initial Baseline Scan

Run your first scan and save it as a baseline for future comparisons:

```bash
python main.py -t http://example.com --save-baseline baseline.json --auto-report
```

This creates:
- `baseline.json` - Baseline scan data for future comparisons
- `scan_report_*.html` - Current scan report

### 2. Retest After Fixes

After making fixes, run a retest scan to compare against the baseline:

```bash
python main.py -t http://example.com --retest baseline.json --auto-report
```

This will:
1. Load vulnerabilities from `baseline.json`
2. Run a new scan
3. Compare results and mark each vulnerability as FIXED/NEW/STILL_VULNERABLE
4. Print a comparison summary to console
5. Generate HTML report with color-coded retest badges

### 3. Update Baseline

After confirming fixes, save the current scan as the new baseline:

```bash
python main.py -t http://example.com --retest baseline.json --save-baseline baseline_v2.json --auto-report
```

## Command-Line Flags

### `--retest <baseline_file>` (alias: `--baseline`)
Compare current scan with baseline and mark vulnerabilities:
```bash
--retest baseline.json
```

### `--save-baseline <output_file>`
Save current scan as baseline for future retests:
```bash
--save-baseline baseline.json
```

Both flags can be used together to compare AND update baseline in one scan.

## Console Output

When using `--retest`, you'll see a summary like:

```
================================================================================
RETEST COMPARISON SUMMARY
================================================================================
Baseline: baseline.json
Baseline vulnerabilities: 15
Current vulnerabilities: 8

✅ FIXED: 9
🆕 NEW: 2
⚠️  STILL VULNERABLE: 6

Fix Rate: 60.0%
================================================================================

Fixed Vulnerabilities:
  1. [SQL Injection] http://example.com/login.php - username
  2. [XSS] http://example.com/search.php - q
  3. [CSRF] http://example.com/profile.php
  ...
```

## HTML Report Features

### Visual Badges

Each vulnerability in the HTML report shows a color-coded badge:

- **✅ FIXED** (Green) - Vulnerability was fixed since baseline
- **🆕 NEW** (Yellow) - New vulnerability not present in baseline
- **⚠️ STILL VULNERABLE** (Red) - Vulnerability still present

### Timestamp Tracking

For STILL_VULNERABLE findings, the report shows:
- **First Seen**: Date from baseline when first discovered
- **Last Seen**: Current scan date

For FIXED findings:
- **Fixed Date**: Date when vulnerability was confirmed fixed

## How It Works

### Vulnerability Signature Matching

The system creates unique signatures for each vulnerability based on:
- URL (normalized, without query params)
- Module name
- Vulnerability type
- Parameter name

Example signature:
```
http://example.com/login.php|SQL Injection Scanner|sql_injection|username
```

This ensures the same vulnerability is tracked across scans even if:
- Query parameters change
- Payloads differ
- Response details vary

### Comparison Logic

```python
# FIXED: In baseline, NOT in current
for vuln in baseline:
    if vuln not in current:
        mark_as_FIXED(vuln)

# NEW: In current, NOT in baseline
for vuln in current:
    if vuln not in baseline:
        mark_as_NEW(vuln)

# STILL_VULNERABLE: In BOTH baseline and current
for vuln in baseline:
    if vuln in current:
        mark_as_STILL_VULNERABLE(vuln)
```

## Example Workflow

### Scenario: Initial Security Assessment

1. **Day 1 - Initial Scan**
```bash
python main.py -t http://testapp.com --save-baseline baseline_day1.json --auto-report
```
Result: 25 vulnerabilities found

2. **Day 3 - After Fixing Critical Issues**
```bash
python main.py -t http://testapp.com --retest baseline_day1.json --auto-report
```
Result:
- ✅ FIXED: 10 (Critical SQLi and XSS fixed)
- 🆕 NEW: 2 (Found new CSRF)
- ⚠️ STILL VULNERABLE: 15 (Medium/Low issues remain)

3. **Day 7 - After Full Remediation**
```bash
python main.py -t http://testapp.com --retest baseline_day1.json --save-baseline baseline_day7.json --auto-report
```
Result:
- ✅ FIXED: 23 (Almost everything fixed!)
- 🆕 NEW: 0 (No new vulnerabilities)
- ⚠️ STILL VULNERABLE: 2 (Low priority issues)

**Fix Rate: 92%** 🎉

## File Formats

### Baseline JSON Structure

```json
{
  "scan_date": "2025-11-13T10:30:00",
  "total_results": 25,
  "vulnerabilities": [
    {
      "vulnerability": true,
      "module": "SQL Injection Scanner",
      "type": "sql_injection",
      "url": "http://example.com/login.php",
      "parameter": "username",
      "severity": "Critical",
      "confidence": 0.95,
      "payload": "' OR '1'='1",
      "evidence": "Database error exposed..."
    }
  ],
  "results": [...]
}
```

### Annotated Results (with retest_status)

```json
{
  "vulnerability": true,
  "module": "SQL Injection Scanner",
  "type": "sql_injection",
  "url": "http://example.com/login.php",
  "parameter": "username",
  "severity": "Critical",
  "retest_status": "STILL_VULNERABLE",
  "first_seen": "2025-11-10T14:22:00",
  "last_seen": "2025-11-13T10:30:00"
}
```

## Advanced Use Cases

### 1. Continuous Monitoring

Run nightly scans and compare against baseline:
```bash
#!/bin/bash
python main.py -t http://production.com --retest baseline_production.json --auto-report --format html

# If new vulnerabilities found, alert team
if grep -q "NEW:" scan_report_*.html; then
    send_alert "New vulnerabilities detected!"
fi
```

### 2. Pre-Release Validation

Ensure all issues fixed before release:
```bash
python main.py -t http://staging.app --retest baseline_v1.0.json --auto-report

# Check if any STILL_VULNERABLE critical issues remain
# Fail CI/CD pipeline if found
```

### 3. Compliance Reporting

Track remediation progress over time:
```bash
# Week 1
python main.py -t http://app.com --save-baseline week1.json --auto-report

# Week 2
python main.py -t http://app.com --retest week1.json --save-baseline week2.json --auto-report

# Week 3
python main.py -t http://app.com --retest week2.json --save-baseline week3.json --auto-report

# Compare week1 → week3 for compliance report
python main.py -t http://app.com --retest week1.json --auto-report
```

## Technical Details

### Files Modified

1. **core/retest_manager.py** (NEW)
   - `RetestManager` class
   - Vulnerability comparison logic
   - Signature matching
   - Report generation

2. **menu.py**
   - Added `--retest` flag
   - Added `--save-baseline` flag

3. **main.py**
   - Integrated RetestManager after scan completion
   - Console summary printing
   - Result annotation before report generation

4. **core/report_generator.py**
   - Added retest badge CSS styles
   - Badge rendering for FIXED/NEW/STILL_VULNERABLE
   - Timestamp display (first_seen, last_seen, fixed_date)

### Signature Normalization

URLs are normalized to prevent false duplicates:
```python
# Before normalization
http://example.com/page?id=1&session=abc123
http://example.com/page?id=2&session=def456

# After normalization (for signature)
http://example.com/page
http://example.com/page

# Result: Recognized as same vulnerability
```

## Limitations

1. **URL Changes**: If URL path changes, vulnerability won't match
   - Example: `/api/v1/users` → `/api/v2/users` = different vulnerability

2. **Module Changes**: If vulnerability type changes, won't match
   - Example: LFI → RFI = different vulnerability

3. **Parameter Renames**: If parameter name changes, won't match
   - Example: `?user_id=1` → `?userId=1` = different vulnerability

## Best Practices

1. **Save Baselines Regularly**: Keep dated baselines for historical tracking
2. **Document Fixes**: When marking FIXED, document what was changed
3. **Review NEW Findings**: New vulnerabilities may indicate recent code changes
4. **Update Baseline After Major Fixes**: Use `--save-baseline` to establish new benchmark
5. **Automate Retests**: Run retests automatically in CI/CD pipeline

## FAQ

**Q: Can I compare scans from different targets?**
A: No, comparison is signature-based. Use same target URL for accurate tracking.

**Q: What happens if baseline file is missing?**
A: Scanner will show error and continue without retest comparison.

**Q: Can I retest with multiple baselines?**
A: No, only one baseline at a time. Compare sequentially for historical analysis.

**Q: Are passive findings included in retest?**
A: Yes, all vulnerabilities (active + passive) are tracked.

**Q: How to interpret Fix Rate?**
A: `Fix Rate = (FIXED / baseline_total) * 100%`
Example: 9 fixed out of 15 baseline = 60% fix rate

---

**Generated**: 2025-11-13
**Scanner Version**: DOMINATOR v2.4 (ROTATION 3)
**Feature**: Retest System with Baseline Tracking
