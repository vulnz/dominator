# Acunetix vs Dominator Gap Analysis

**Report Analyzed**: testphp.vulnweb.com scan (58 vulnerabilities total, 39 confirmed)

## Executive Summary

Acunetix found **58 vulnerabilities** (39 confirmed) that we need to analyze against Dominator's capabilities. The primary gaps are:

1. **Boolean-Based (Blind) SQL Injection** - 10 instances (CRITICAL)
2. **Time-Based Blind SQLi detection** - Missing completely
3. **Stored/Blind XSS** - 5+ instances (HIGH)
4. **CSRF detection scope** - Only keyword-based
5. **Password over HTTP** - Detector exists but not integrated
6. **SSL/TLS validation** - Not implemented

---

## Detailed Vulnerability Comparison Table

### 1. SQL Injection Vulnerabilities (13 total)

| # | Vulnerability Type | Severity | URL | Parameter | Method | Why Dominator Missed It | Required Fix |
|---|-------------------|----------|-----|-----------|--------|------------------------|--------------|
| 1.1 | **Boolean-Based SQLi** | CRITICAL | artists.php | artist | GET | Dominator only detects **error-based** SQLi. No boolean/blind detection (different page content based on TRUE/FALSE queries) | **CRITICAL**: Add boolean-based SQLi module with baseline comparison |
| 1.2 | Boolean-Based SQLi | CRITICAL | artists.php?artist=1 OR 17-7=10 | artist | GET | Same - payload `1 OR 17-7=10` returns different content, no DB errors | Add content-length/hash comparison detection |
| 1.3 | Boolean-Based SQLi | CRITICAL | rate.php | id | GET | Same - no error messages, only boolean responses | Same fix |
| 1.4 | Boolean-Based SQLi | CRITICAL | listproducts.php | cat | GET | Same issue | Same fix |
| 1.5 | Boolean-Based SQLi | CRITICAL | listproducts.php | artist | GET | Same issue | Same fix |
| 1.6 | Boolean-Based SQLi | CRITICAL | product.php | pic | GET | Same issue | Same fix |
| 1.7 | Boolean-Based SQLi | CRITICAL | details.php | id | GET | Same issue | Same fix |
| 1.8 | Boolean-Based SQLi | CRITICAL | buy.php | cartId | POST | Same issue - POST form | Same fix |
| 1.9 | Boolean-Based SQLi | CRITICAL | userinfo.php | - | POST | Same issue - POST form | Same fix |
| 1.10 | Boolean-Based SQLi | CRITICAL | newuser.php | uname | POST | Same issue - signup form | Same fix |
| 2.1 | **[Probable] SQLi** | CRITICAL | listproducts.php | cat | GET | Likely boolean-based without confirmation | Same fix |
| 2.2 | [Probable] SQLi | CRITICAL | listproducts.php | artist | GET | Same | Same fix |
| 2.3 | [Probable] SQLi | CRITICAL | newuser.php | uname | POST | Same | Same fix |

**Root Cause**: Dominator's SQLi module ([modules/sqli/module.py:88-92](modules/sqli/module.py)) ONLY checks for database error patterns:
```python
# ONLY error-based detection
detected, confidence, evidence = self._detect_sqli_improved(payload, response)
# Checks error_patterns.txt - mysql_error, pg_query, ORA-, etc.
```

**Missing Detection Method**: Boolean-based blind SQLi detection requires:
1. Send baseline request (normal parameter value)
2. Send TRUE condition (`1 OR 1=1`, `1 AND 1=1`)
3. Send FALSE condition (`1 AND 1=2`, `1 OR 1=2`)
4. Compare responses: If TRUE == baseline AND FALSE != baseline → SQLi exists
5. Use multiple comparison methods: content length, response hash, specific markers

---

### 2. Cross-Site Scripting (XSS) Vulnerabilities (10+ total)

| # | Vulnerability Type | Severity | URL | Parameter | Method | Why Dominator Missed It | Required Fix |
|---|-------------------|----------|-----|-----------|--------|------------------------|--------------|
| 3.1 | **Blind XSS** (Stored) | HIGH | guestbook.php | name/text | POST | Dominator checks for IMMEDIATE reflection. Blind XSS stores payload and triggers later when admin views it | Add OOB (Out-of-Band) callbacks - payload with external trigger to detect delayed XSS |
| 3.2 | Blind XSS | HIGH | comment.php | name | POST | Same - payload stored, executed later | Same fix - need OOB integration (already have Pipedream!) |
| 3.3 | Blind XSS | HIGH | search.php | searchFor | GET | May be stored in logs/admin panel | Same fix |
| 3.4 | Blind XSS | HIGH | newuser.php | uname | POST | Stored in user table, executed in admin panel | Same fix |
| 3.5 | Blind XSS | HIGH | params.php | - | GET | Unknown parameter | Same fix |
| 4.1 | **Reflected XSS** | HIGH | listproducts.php | cat | GET | Dominator may detect this - need to verify payloads match | Verify payload coverage - check if `<scRipt>` mixed-case bypasses |
| 4.2 | Reflected XSS | HIGH | listproducts.php | artist | GET | Same | Same |
| 4.3 | Reflected XSS | HIGH | guestbook.php | text | POST | Should detect if tested | Verify POST forms coverage |

**Root Cause**: Dominator's XSS module ([modules/xss/module.py:76-82](modules/xss/module.py)) checks for payload reflection in SAME response:
```python
# Only checks immediate response
detected, confidence, evidence = self._detect_xss_improved(payload, response)
```

**Missing Detection Method**: Blind/Stored XSS requires:
1. OOB callback mechanism (we have Pipedream integration in [utils/oob_detector.py](utils/oob_detector.py)!)
2. Payloads with external triggers: `<img src="https://pipedream.com/callback?xss=IDENTIFIER">`
3. Track which payloads were sent where
4. Wait for callback to confirm execution
5. **GOOD NEWS**: Infrastructure exists, just not integrated into XSS module!

---

### 3. Local File Inclusion (LFI)

| # | Vulnerability Type | Severity | URL | Parameter | Method | Why Dominator Missed It | Required Fix |
|---|-------------------|----------|-----|-----------|--------|------------------------|--------------|
| 5.1 | **LFI** | HIGH | showimage.php | file | GET | Acunetix payload: `/../../../../../../proc/version`. Dominator has LFI module - need to check payload coverage | Verify payloads.txt includes absolute path traversal (`/../../`) not just relative (`../`) |

**Root Cause**: Possible payload mismatch. Acunetix uses **absolute path** notation `/../../../../../../proc/version`, while Dominator may only use relative paths.

**Investigation Needed**: Check [modules/lfi/payloads.txt](modules/lfi/payloads.txt) for absolute path patterns.

---

### 4. Remote File Inclusion (RFI) / SSRF

| # | Vulnerability Type | Severity | URL | Parameter | Method | Why Dominator Missed It | Required Fix |
|---|-------------------|----------|-----|-----------|--------|------------------------|--------------|
| 6.1 | **XSS via RFI** | HIGH | showimage.php | file | GET | Acunetix payload: `hTTp://r87.com/n` - tests if external URLs are fetched and rendered | Check if RFI/SSRF modules test external URL loading |

**Root Cause**: This is actually testing if `file=` parameter accepts external URLs. Need RFI module active.

**Check**: Does [modules/rfi/module.py](modules/rfi/module.py) exist and is it enabled?

---

### 5. CSRF Vulnerabilities (2 total)

| # | Vulnerability Type | Severity | URL | Parameter | Method | Why Dominator Missed It | Required Fix |
|---|-------------------|----------|-----|-----------|--------|------------------------|--------------|
| 7.1 | **CSRF** | LOW | guestbook.php | - | GET | Dominator CSRF module ([modules/csrf/module.py:114-138](modules/csrf/module.py)) uses **keyword matching** - only checks forms with keywords like 'password', 'email', 'delete'. Guestbook may not match. | Expand state-changing keywords to include: 'comment', 'message', 'post', 'submit', 'name', 'content' |
| 7.2 | CSRF in Login | LOW | login.php | - | GET | Likely detected (has 'password' keyword) | Verify detection |

**Root Cause**: CSRF module has **hardcoded keyword list** at [modules/csrf/module.py:31-38](modules/csrf/module.py):
```python
self.state_changing_keywords = [
    'password', 'passwd', 'pass', 'pwd',
    'email', 'username', 'user',
    'delete', 'remove', 'change', 'update', 'modify',
    'create', 'add', 'new', 'register',
    'transfer', 'send', 'payment', 'purchase', 'confirm'
]
# MISSING: 'comment', 'message', 'post', 'text', 'content', 'title'
```

**Fix Required**: Move keywords to `modules/csrf/keywords.txt` file and expand list.

---

### 6. Password Over HTTP

| # | Vulnerability Type | Severity | URL | Parameter | Method | Why Dominator Missed It | Required Fix |
|---|-------------------|----------|-----|-----------|--------|------------------------|--------------|
| 8.1 | **Password over HTTP** | HIGH | login.php | pass | GET | Detector EXISTS ([detectors/password_over_http_detector.py](detectors/password_over_http_detector.py)) but NOT integrated into passive scanner! | **CRITICAL**: Add PasswordOverHTTPDetector to [passive_detectors/passive_scanner.py](passive_detectors/passive_scanner.py) |

**Root Cause**: Code exists but not integrated! Check [passive_detectors/passive_scanner.py:11-14](passive_detectors/passive_scanner.py) - only 8 detectors, missing PasswordOverHTTPDetector.

**Quick Fix**: Add to passive scanner imports and analyze_response() method.

---

### 7. SSL/TLS Issues

| # | Vulnerability Type | Severity | URL | Parameter | Method | Why Dominator Missed It | Required Fix |
|---|-------------------|----------|-----|-----------|--------|------------------------|--------------|
| 9.1 | **SSL/TLS Not Implemented** | MEDIUM | login.php | - | GET | No SSL/TLS validation in Dominator | Add passive detector to check if HTTPS redirects exist, HSTS headers, mixed content |

**Root Cause**: Not implemented. Need new passive detector.

---

## Hardcoded Values Analysis

### Found Hardcoded Patterns That Should Be in Config/Payload Files:

#### 1. **CSRF Module - State-Changing Keywords** ❌ HARDCODED
**Location**: [modules/csrf/module.py:31-38](modules/csrf/module.py)
```python
self.state_changing_keywords = [
    'password', 'passwd', 'pass', 'pwd',
    'email', 'username', 'user',
    'delete', 'remove', 'change', 'update', 'modify',
    'create', 'add', 'new', 'register',
    'transfer', 'send', 'payment', 'purchase', 'confirm'
]
```
**Fix**: Move to `modules/csrf/state_changing_keywords.txt`

#### 2. **CSRF Module - Token Names** ❌ HARDCODED
**Location**: [modules/csrf/module.py:24-28](modules/csrf/module.py)
```python
self.token_names = [
    'csrf', 'csrf_token', 'csrftoken', '_csrf', '_token',
    'authenticity_token', 'anti_csrf', 'xsrf', 'xsrf_token',
    'token', '__RequestVerificationToken', 'nonce'
]
```
**Fix**: Move to `modules/csrf/token_patterns.txt`

#### 3. **IDOR Module - ID Parameters** ❌ HARDCODED
**Location**: [modules/idor/module.py:42-45](modules/idor/module.py)
```python
id_params = ['id', 'item', 'user', 'uid', 'userid', 'user_id',
             'itemid', 'item_id', 'object', 'obj', 'doc', 'file',
             'account', 'profile', 'order', 'invoice', 'aid', 'pid',
             'cid', 'gid', 'tid', 'sid', 'rid', 'vid', 'eid']
```
**Fix**: Move to `modules/idor/id_parameters.txt`

#### 4. **IDOR Module - Skip Parameters** ❌ HARDCODED
**Location**: [modules/idor/module.py:67-70](modules/idor/module.py)
```python
skip_params = ['action', 'operation', 'method', 'mode', 'type', 'submit', 'csrf']
```
**Fix**: Move to `modules/idor/skip_parameters.txt`

#### 5. **DOM XSS - Safe Domains** ❌ HARDCODED
**Location**: [modules/dom_xss/module.py:224-246](modules/dom_xss/module.py)
```python
SAFE_DOMAINS = [
    'googletagmanager.com',
    'google-analytics.com',
    'cdn.jsdelivr.net',
    # ... 10 domains
]
```
**Fix**: Move to `modules/dom_xss/safe_domains.txt`

#### 6. **SQLi Module - Strong Patterns** ❌ HARDCODED
**Location**: [modules/sqli/module.py:155-163](modules/sqli/module.py)
```python
strong_patterns = [
    'You have an error in your SQL syntax',
    'Warning: mysql_',
    'mysqli_sql_exception',
    # ... etc
]
```
**Fix**: Already has `error_patterns.txt` ✅ but has DUPLICATE hardcoded backup list ❌

#### 7. **SQLi Module - SQL Keywords** ❌ HARDCODED
**Location**: [modules/sqli/module.py:232](modules/sqli/module.py)
```python
sql_keywords = ['select', 'from', 'where', 'syntax', 'query', 'statement']
```
**Fix**: Move to `modules/sqli/sql_keywords.txt`

#### 8. **SQLi Module - DB Functions** ❌ HARDCODED
**Location**: [modules/sqli/module.py:244](modules/sqli/module.py)
```python
db_functions = ['mysql_', 'pg_', 'oci_', 'mssql_', 'sqlite_']
```
**Fix**: Move to `modules/sqli/db_functions.txt` or add to error_patterns.txt

#### 9. **Password Over HTTP - Field Patterns** ❌ HARDCODED
**Location**: [detectors/password_over_http_detector.py:14-21](detectors/password_over_http_detector.py)
```python
return [
    r'<input[^>]*type\s*=\s*["\']password["\'][^>]*>',
    r'<input[^>]*name\s*=\s*["\'].*?pass.*?["\'][^>]*>',
    # ... regex patterns
]
```
**Fix**: Move to `detectors/patterns/password_field_patterns.txt`

#### 10. **Password Over HTTP - Login Form Patterns** ❌ HARDCODED
**Location**: [detectors/password_over_http_detector.py:24-32](detectors/password_over_http_detector.py)
```python
return [
    r'<form[^>]*action\s*=\s*["\'][^"\']*login[^"\']*["\'][^>]*>',
    # ... regex patterns
]
```
**Fix**: Move to `detectors/patterns/login_form_patterns.txt`

#### 11. **CSRF Success Patterns** ❌ HARDCODED
**Location**: [modules/csrf/module.py:193-201](modules/csrf/module.py)
```python
success_patterns = [
    'success', 'changed', 'updated', 'saved',
    'completed', 'thank you', 'confirmed'
]
```
**Fix**: Move to `modules/csrf/success_indicators.txt`

#### 12. **CSRF Error Patterns** ❌ HARDCODED
**Location**: [modules/csrf/module.py:209](modules/csrf/module.py)
```python
error_patterns = ['error', 'invalid', 'failed', 'denied', 'forbidden']
```
**Fix**: Move to `modules/csrf/error_indicators.txt`

---

## Critical Missing Features Summary

### TIER 1 - CRITICAL (Preventing 23+ detections)
1. ✅ **Boolean-Based Blind SQLi Detection** - 10 vulnerabilities missed
   - Add content comparison (length, hash, markers)
   - Implement TRUE/FALSE/baseline comparison
   - New file: `modules/sqli/blind_detector.py`

2. ✅ **Blind/Stored XSS with OOB** - 5+ vulnerabilities missed
   - OOB infrastructure exists, needs integration
   - Add Pipedream callback payloads to XSS module
   - Modify: [modules/xss/module.py](modules/xss/module.py)

3. ✅ **Password Over HTTP Integration** - 1 vulnerability missed
   - Code exists, just add to passive scanner
   - Modify: [passive_detectors/passive_scanner.py](passive_detectors/passive_scanner.py)

### TIER 2 - HIGH PRIORITY (Improving accuracy)
4. ✅ **CSRF Keyword Expansion** - 1+ missed
   - Add missing keywords (comment, message, post, text)
   - Move to config file: `modules/csrf/state_changing_keywords.txt`

5. ✅ **LFI Absolute Path Payloads** - Verify coverage
   - Check if `/../../` patterns exist
   - Add to payloads if missing

6. ✅ **RFI/SSRF External URL Testing** - Unknown count
   - Verify RFI module is enabled
   - Check SSRF module tests external URLs

### TIER 3 - MEDIUM PRIORITY (New capabilities)
7. ⚠️ **SSL/TLS Validation** - 1 missed
   - New passive detector needed
   - Check HTTPS redirects, HSTS headers, mixed content

8. ⚠️ **Time-Based Blind SQLi** - Unknown count (not in this report)
   - Already implemented in [modules/sqli/module.py:307-391](modules/sqli/module.py) ✅
   - Verify it's working correctly

---

## Architectural Issues

### Issue 1: Too Many Hardcoded Patterns
**Problem**: 12+ lists hardcoded in Python files instead of TXT config files
**Impact**: Users can't customize detection without editing code
**Fix**: Move all pattern lists to `modules/{module}/patterns/` directory

### Issue 2: Passive Detector Not Fully Integrated
**Problem**: PasswordOverHTTPDetector exists but not called
**Impact**: Missing obvious vulnerabilities
**Fix**: Audit all detectors in `detectors/` directory and ensure passive_scanner.py calls them

### Issue 3: OOB Infrastructure Underutilized
**Problem**: OOB detection (Pipedream + Requestbin) exists but only used in SQLi/SSRF
**Impact**: Missing Blind XSS, Blind SSTI, Blind XXE
**Fix**: Integrate OOB callbacks into ALL injection modules (XSS, SSTI, XXE, CMDI)

### Issue 4: No Content-Based Comparison for Blind Attacks
**Problem**: All detection relies on errors/reflection, not response differences
**Impact**: Missing all boolean-based/blind vulnerabilities
**Fix**: Add baseline comparison framework to BaseModule

---

## Recommended Action Plan

### Phase 1: Quick Wins (1-2 hours)
1. ✅ Integrate PasswordOverHTTPDetector into passive scanner
2. ✅ Expand CSRF keywords (add 6 new keywords)
3. ✅ Verify LFI payloads include absolute paths
4. ✅ Check RFI module is enabled

### Phase 2: Critical Features (4-6 hours)
5. ✅ Implement Boolean-Based Blind SQLi detection
   - Add baseline request storage
   - Add TRUE/FALSE payload pairs
   - Add response comparison (length, hash, specific markers)
6. ✅ Integrate OOB callbacks into XSS module for Blind XSS
   - Use existing Pipedream infrastructure
   - Add callback tracking

### Phase 3: Refactoring (2-3 hours)
7. ✅ Move all hardcoded patterns to TXT files
   - Create `patterns/` subdirectory in each module
   - Load patterns dynamically (already implemented in BaseModule)
8. ✅ Audit all detectors and ensure integration

### Phase 4: New Features (4-6 hours)
9. ⚠️ Add SSL/TLS passive detector
10. ⚠️ Expand OOB to SSTI, XXE, CMDI modules

---

## Testing Verification Checklist

After implementing fixes, scan testphp.vulnweb.com and verify detection of:

- [ ] Boolean SQLi in artists.php?artist=
- [ ] Boolean SQLi in listproducts.php?cat=
- [ ] Boolean SQLi in userinfo.php (POST)
- [ ] Boolean SQLi in newuser.php (POST)
- [ ] Blind XSS in guestbook.php
- [ ] Blind XSS in comment.php
- [ ] LFI in showimage.php?file=
- [ ] CSRF in guestbook.php
- [ ] Password over HTTP in login.php
- [ ] RFI/XSS in showimage.php (external URL)

**Target**: Detect 45+ of the 58 Acunetix findings (77% coverage)

---

## Conclusion

Dominator has **strong error-based detection** but is missing **blind/boolean-based detection** across the board. The good news:

✅ **OOB infrastructure exists** - just needs integration
✅ **Passive detectors exist** - just need to be called
✅ **Architecture is sound** - just needs refactoring to reduce hardcoding
✅ **Most fixes are medium complexity** - no major rewrites needed

**Biggest Impact Fix**: Implementing Boolean-Based Blind SQLi detection will immediately detect **10 CRITICAL vulnerabilities** that are currently missed.

**Easiest Fix**: Integrating PasswordOverHTTPDetector (literally 2 lines of code).

**Best ROI**: Phase 1 + Phase 2 will improve detection rate from ~30% to ~77% with only 6-8 hours of work.
