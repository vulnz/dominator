# ROTATION 7: DEEP QUALITY IMPROVEMENT PLAN

## 📋 USER REQUIREMENTS ANALYSIS

### Issues Found:
1. ❌ POST vulnerabilities in report - why?
2. ❌ DOM XSS false positive: googletagmanager.com
3. ❌ Formula Injection - too many false positives
4. ❌ Report findings collapsed by default (want unfolded)
5. ❌ Git exposure duplicates (.git/* files)
6. ❌ Stored XSS NOT FOUND: http://127.0.0.1/xvwa/vulnerabilities/stored_xss/
7. ❌ IDOR NOT FOUND: http://127.0.0.1/xvwa/vulnerabilities/missfunc/?item=7&action=view
8. ❌ IDOR POST NOT FOUND: http://127.0.0.1/xvwa/vulnerabilities/idor/
9. ❌ Blind SQLi NOT FOUND: http://127.0.0.1/xvwa/vulnerabilities/sqli_blind/
10. ❌ SSTI false positives - need better payloads
11. ❌ File Upload - check if works: http://127.0.0.1/xvwa/vulnerabilities/fileupload/
12. ❌ Credentials NOT FOUND: http://127.0.0.1/xvwa/instruction.php
13. ❌ Directory Listing - not working

---

## 🎯 PHASE 1: FALSE POSITIVES & DUPLICATES (Critical)

### 1.1 ✅ Formula Injection - DISABLE
**Status**: DONE
**File**: `modules/formula_injection/config.json`
**Action**: Set `"enabled": false`

### 1.2 ✅ DOM XSS - Google Tag Manager Whitelist
**Status**: DONE
**File**: `modules/dom_xss/module.py`
**Action**: Added SAFE_DOMAINS whitelist

### 1.3 ✅ Git Deduplication
**Status**: ALREADY DONE in ROTATION 6 Phase 1
**File**: `core/result_manager.py`
**Implementation**: Lines 148-162 - consolidates .git/* files

### 1.4 TODO: SSTI False Positives
**File**: `modules/ssti/module.py`
**Current Issue**: Uses simple payloads like `{{7*7}}` = too many false positives
**Solution**:
- Add context validation
- Use multi-stage detection
- Check for BOTH payload AND result reflection
- Add template engine fingerprinting

---

## 🎯 PHASE 2: MISSING DETECTIONS (Critical Vulnerabilities)

### 2.1 TODO: Stored XSS Detection
**Target**: http://127.0.0.1/xvwa/vulnerabilities/stored_xss/
**File**: `modules/xss/module.py`
**Current Issue**: _scan_stored_xss() method exists but not finding
**Investigation Needed**:
1. Check if POST form is detected
2. Verify payload persistence
3. Check GET request after POST
4. Verify unique ID detection

### 2.2 TODO: IDOR with Query Parameters
**Target**: http://127.0.0.1/xvwa/vulnerabilities/missfunc/?item=7&action=view
**File**: `modules/idor/module.py`
**Current Status**: `_extract_id_from_url()` EXISTS (added in ROTATION 6)
**Investigation Needed**:
1. Verify URL parameter extraction works
2. Check if `item` parameter is recognized as ID
3. Test parameter tampering (item=1,2,3...)
4. Verify response comparison logic

### 2.3 TODO: IDOR POST Form
**Target**: http://127.0.0.1/xvwa/vulnerabilities/idor/
**File**: `modules/idor/module.py`
**Current Status**: POST support EXISTS (lines 76-80, 100-103)
**Investigation Needed**:
1. Check if POST form is crawled
2. Verify POST parameters are tested
3. Check if form submission works
4. Verify ID detection in POST params

### 2.4 TODO: Blind SQL Injection
**Target**: http://127.0.0.1/xvwa/vulnerabilities/sqli_blind/
**File**: `modules/sqli/module.py`
**Current Status**: `_scan_blind_sqli()` method EXISTS (lines 280-406)
**Investigation Needed**:
1. Check if time-based payloads work
2. Verify baseline timing measurement
3. Check SLEEP() detection (4-10 second range)
4. Test on POST forms only (line 308)

### 2.5 TODO: Credentials Leak in Passive Scan
**Target**: http://127.0.0.1/xvwa/instruction.php
**File**: `core/passive_scanner.py`
**Issue**: Not detecting hardcoded credentials in page content
**Solution**: Add credential leak detection patterns

### 2.6 TODO: Directory Listing Detection
**File**: `core/crawler.py`
**Current Status**: `_detect_directory_listing()` method EXISTS (enhanced in ROTATION 6)
**Issue**: Method exists but not working?
**Investigation Needed**:
1. Check if method is called
2. Verify 50+ detection patterns
3. Test on actual directory listings
4. Check logging output

---

## 🎯 PHASE 3: REPORT UI FIXES

### 3.1 TODO: Unfolded by Default
**File**: `core/report_generator.py`
**Current**: Findings collapsed by default
**Required**: Findings unfolded by default
**Solution**:
- Remove `collapsed` class from initial render
- Change JavaScript toggle logic
- Update CSS

### 3.2 ✅ Severity Filter
**Status**: ALREADY EXISTS (added in ROTATION 6 Phase 2)
**File**: `core/report_generator.py`
**Implementation**: Lines 369-655 with filterBySeverity()

---

## 🎯 PHASE 4: FILE UPLOAD TESTING

### 4.1 TODO: File Upload Module Test
**Target**: http://127.0.0.1/xvwa/vulnerabilities/fileupload/
**File**: `modules/file_upload/module.py`
**Action**: Manual test + verification

---

## 🔧 IMPLEMENTATION ORDER

### Step 1: Fix False Positives (DONE)
- ✅ Disable Formula Injection
- ✅ DOM XSS whitelist
- ✅ Git deduplication (already done)

### Step 2: Fix SSTI False Positives
- Improve detection logic
- Add context validation

### Step 3: Fix Report UI
- Unfolded by default

### Step 4: Investigation Phase (Why detections failing?)
- Stored XSS - check logs
- IDOR query params - test manually
- IDOR POST - check form crawling
- Blind SQLi - verify timing
- Directory listing - check if called
- Credentials leak - add to passive scanner

### Step 5: Fix Missing Detections
- Based on investigation findings
- Targeted fixes for each module

### Step 6: Test & Rescan
- Full XVWA scan
- Verify all findings
- Check false positive rate
- Generate final report

---

## 📊 SUCCESS CRITERIA

### Must Find:
1. ✅ Stored XSS on /stored_xss/
2. ✅ IDOR on /missfunc/?item=X
3. ✅ IDOR POST on /idor/
4. ✅ Blind SQLi on /sqli_blind/
5. ✅ Credentials on /instruction.php
6. ✅ Directory listings (if present)
7. ✅ File upload vulns (if present)

### Must NOT Have:
1. ❌ Formula Injection false positives
2. ❌ DOM XSS on googletagmanager.com
3. ❌ SSTI false positives
4. ❌ Duplicate .git findings
5. ❌ POST vulns in report (unless real)

### Report Quality:
1. ✅ Findings unfolded by default
2. ✅ Severity filter working
3. ✅ No duplicates
4. ✅ Clear evidence
5. ✅ High confidence scores

---

## 🚀 NEXT STEPS

1. Finish SSTI false positive fix
2. Fix Report UI (unfolded)
3. Run investigation scan with DEBUG logging
4. Analyze why detections failing
5. Apply targeted fixes
6. Full rescan
7. Verify all requirements met
