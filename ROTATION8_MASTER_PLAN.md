# ROTATION 8 - MASTER PLAN: Close the Gap to Acunetix

## 🎯 OBJECTIVE
Based on comprehensive analysis of Acunetix scan report, implement missing detection capabilities and externalize hardcoded patterns.

**Current Detection Rate**: ~43% (compared to Acunetix)
**Target Detection Rate**: ~91%
**Improvement**: +48% more vulnerabilities detected

---

## 📊 ANALYSIS DOCUMENTS

Created comprehensive analysis in 3 documents:

1. **[ACUNETIX_GAP_ANALYSIS.md](ACUNETIX_GAP_ANALYSIS.md)** - Detailed vulnerability comparison table
2. **[HARDCODED_PATTERNS_ANALYSIS.md](HARDCODED_PATTERNS_ANALYSIS.md)** - Patterns that need externalization
3. **This document** - Implementation roadmap

---

## 🔥 CRITICAL GAPS & FIXES

### **GAP #1: Boolean-Based SQL Injection - CRITICAL**

**Impact**: Missing 10/13 critical SQLi vulnerabilities (77% miss rate)

**Status**: ❌ Completely missing

**Current Detection**:
- ✅ Error-based SQLi
- ✅ Time-based SQLi
- ❌ **Boolean-based SQLi**

**Why Critical**:
- Most common SQLi type in production (errors disabled)
- Works silently by observing true/false response differences
- Bypasses many WAFs

**Implementation Required**:

#### File: `modules/sqli/module.py`

Add new method `_detect_boolean_sqli()`:

```python
def _detect_boolean_sqli(self, url: str, param_name: str, original_value: str,
                         params: Dict, method: str, http_client: Any) -> tuple:
    """
    Detect Boolean-based SQL Injection

    Method:
    1. Get baseline response (original value)
    2. Send TRUE payload (e.g., 1 AND 1=1)
    3. Send FALSE payload (e.g., 1 AND 1=2)
    4. Compare responses

    If TRUE ≈ baseline AND FALSE ≠ baseline → Boolean SQLi confirmed
    """

    # Get baseline response
    if method == 'POST':
        baseline_response = http_client.post(url, data=params)
    else:
        baseline_response = http_client.get(url, params=params)

    if not baseline_response:
        return False, 0.0, ""

    baseline_text = baseline_response.text
    baseline_length = len(baseline_text)
    baseline_hash = hashlib.md5(baseline_text.encode()).hexdigest()

    # Boolean SQLi payloads
    boolean_payloads = [
        {
            'true': f"{original_value} AND 1=1",
            'false': f"{original_value} AND 1=2"
        },
        {
            'true': f"{original_value}' AND '1'='1",
            'false': f"{original_value}' AND '1'='2"
        },
        {
            'true': f"{original_value} OR 1=1",
            'false': f"{original_value} OR 1=2"
        }
    ]

    for payload_pair in boolean_payloads:
        # Test TRUE payload
        test_params_true = params.copy()
        test_params_true[param_name] = payload_pair['true']

        if method == 'POST':
            true_response = http_client.post(url, data=test_params_true)
        else:
            true_response = http_client.get(url, params=test_params_true)

        if not true_response:
            continue

        true_text = true_response.text
        true_length = len(true_text)
        true_hash = hashlib.md5(true_text.encode()).hexdigest()

        # Test FALSE payload
        test_params_false = params.copy()
        test_params_false[param_name] = payload_pair['false']

        if method == 'POST':
            false_response = http_client.post(url, data=test_params_false)
        else:
            false_response = http_client.get(url, params=test_params_false)

        if not false_response:
            continue

        false_text = false_response.text
        false_length = len(false_text)
        false_hash = hashlib.md5(false_text.encode()).hexdigest()

        # Analysis: TRUE should match baseline, FALSE should differ

        # Check 1: Content hash comparison
        true_matches_baseline = (true_hash == baseline_hash)
        false_differs_from_baseline = (false_hash != baseline_hash)

        # Check 2: Content length comparison
        true_length_similar = abs(true_length - baseline_length) < 50
        false_length_different = abs(false_length - baseline_length) > 100

        # Check 3: Specific content comparison (check for missing elements in FALSE)
        # Extract key HTML elements from baseline
        baseline_elements = self._extract_key_elements(baseline_text)
        true_elements = self._extract_key_elements(true_text)
        false_elements = self._extract_key_elements(false_text)

        elements_present_in_true = len(set(baseline_elements) & set(true_elements))
        elements_missing_in_false = len(set(baseline_elements) - set(false_elements))

        # Decision Logic
        confidence = 0.0

        # Strong indicator: Hash exact match for TRUE, different for FALSE
        if true_matches_baseline and false_differs_from_baseline:
            confidence = 0.95

        # Medium indicator: Length similar for TRUE, different for FALSE
        elif true_length_similar and false_length_different:
            confidence = 0.80

        # Weak indicator: Some elements present in TRUE but missing in FALSE
        elif elements_present_in_true > 5 and elements_missing_in_false > 3:
            confidence = 0.70

        if confidence >= 0.70:
            evidence = f"Boolean-based SQL Injection detected.\n"
            evidence += f"Baseline response: {baseline_length} bytes\n"
            evidence += f"TRUE payload ({payload_pair['true']}): {true_length} bytes (similar to baseline)\n"
            evidence += f"FALSE payload ({payload_pair['false']}): {false_length} bytes (differs from baseline)\n"
            evidence += f"Confidence: {confidence:.2f}\n"

            return True, confidence, evidence

    return False, 0.0, ""

def _extract_key_elements(self, html: str) -> List[str]:
    """Extract key HTML elements for comparison"""
    elements = []

    # Extract all HTML tags
    tags = re.findall(r'<(\w+)[^>]*>', html)
    elements.extend(tags)

    # Extract text content between tags
    text_content = re.findall(r'>([^<]+)<', html)
    # Filter out whitespace-only content
    text_content = [t.strip() for t in text_content if t.strip() and len(t.strip()) > 3]
    elements.extend(text_content[:20])  # First 20 text elements

    return elements
```

**Integration**: Call this method in main `scan()` loop after error-based detection.

**Payloads to Add** to `payloads.txt`:
```
# Boolean-based SQLi payloads
{ORIGINAL} AND 1=1
{ORIGINAL} AND 1=2
{ORIGINAL}' AND '1'='1
{ORIGINAL}' AND '1'='2
{ORIGINAL} OR 1=1
{ORIGINAL} OR 1=2
```

**Estimated Implementation Time**: 4-6 hours
**Expected Impact**: +10 critical findings

---

### **GAP #2: Blind XSS Detection - CRITICAL**

**Impact**: Missing 5/5 high-severity Blind XSS vulnerabilities (100% miss rate)

**Status**: ❌ Completely missing

**Current Detection**:
- ✅ Reflected XSS
- ✅ Stored XSS (immediate response)
- ❌ **Blind XSS (delayed/admin panel execution)**

**Why Critical**:
- Executes when admin views user input
- Steals admin sessions, CSRF tokens
- Current stored XSS only checks immediate response

**Good News**: Dominator ALREADY has OOB infrastructure!
- File: `utils/oob_detector.py`
- Supports: Requestbin.cn AND Pipedream
- Used by: SSRF module (working)

**Implementation Required**:

#### File: `modules/xss/module.py`

Modify stored XSS detection (lines 251-340):

```python
def _detect_stored_xss(self, targets: List[Dict], http_client: Any) -> List[Dict]:
    """Detect Stored XSS including Blind XSS"""

    from utils.oob_detector import OOBDetector
    import time

    results = []

    # Initialize OOB detector for Blind XSS
    oob_detector = OOBDetector()

    for target in post_targets:
        url = target.get('url')
        params = target.get('params', {})

        for param_name in params:
            # TECHNIQUE 1: Immediate Reflected Storage (existing)
            for payload in self.payloads[:20]:
                # Test as before...

            # TECHNIQUE 2: Blind XSS with OOB Detection (NEW!)
            logger.info(f"Testing Blind XSS with OOB for parameter: {param_name}")

            # Generate OOB identifier
            oob_id, oob_url = oob_detector.generate_oob_url()

            # Create OOB payloads
            oob_payloads = [
                f'<script src="{oob_url}"></script>',
                f'<img src="{oob_url}" />',
                f'<iframe src="{oob_url}"></iframe>',
                f'<svg onload="fetch(\'{oob_url}\')">',
                f'"><script src="{oob_url}"></script>',
                f'\' onload="fetch(\'{oob_url}\')" \'',
            ]

            for oob_payload in oob_payloads:
                test_params = params.copy()
                test_params[param_name] = oob_payload

                # Submit form with OOB payload
                logger.debug(f"Submitting OOB payload: {oob_payload[:50]}...")
                response = http_client.post(url, data=test_params)

                if not response:
                    continue

                # Wait for callback (10 seconds to allow admin panel load)
                logger.debug(f"Waiting 10 seconds for OOB callback...")
                time.sleep(10)

                # Check for OOB interaction
                if oob_detector.check_interaction(oob_id):
                    # BLIND XSS CONFIRMED!
                    result = self.create_result(
                        vulnerable=True,
                        url=url,
                        parameter=param_name,
                        payload=oob_payload,
                        evidence=f"Blind XSS confirmed via Out-of-Band callback!\n"
                                f"OOB URL: {oob_url}\n"
                                f"Payload was stored and executed when viewed (likely in admin panel).\n"
                                f"This allows session hijacking, keylogging, and complete account takeover.\n"
                                f"Callback received at: {time.strftime('%Y-%m-%d %H:%M:%S')}",
                        description="Blind Cross-Site Scripting (XSS) vulnerability detected via OOB callback. "
                                  "Payload is stored and executes when viewed by other users (admin panel).",
                        confidence=0.95
                    )

                    result['xss_type'] = 'Blind XSS (OOB Confirmed)'
                    result['oob_url'] = oob_url
                    result['cwe'] = 'CWE-79'
                    result['owasp'] = 'A03:2021'
                    result['cvss'] = '8.8'  # Higher severity for Blind XSS

                    results.append(result)
                    logger.info(f"✓ Blind XSS found via OOB in {param_name}!")

                    # Found one, no need to test more payloads for this param
                    break

    return results
```

**Payloads to Add** to `xss/payloads.txt`:
```
# Blind XSS payloads (OOB will be injected at runtime)
<script src="{OOB}"></script>
<img src="{OOB}" />
<iframe src="{OOB}"></iframe>
<svg onload="fetch('{OOB}')">
"><script src="{OOB}"></script>
' onload="fetch('{OOB}')" '
```

**Configuration**: Add to `modules/xss/config.json`:
```json
{
  "blind_xss_enabled": true,
  "oob_wait_time": 10,
  "oob_payloads_count": 6
}
```

**Estimated Implementation Time**: 2-3 hours
**Expected Impact**: +5 high findings

---

### **GAP #3: Password Over HTTP - Detector Exists BUT NOT Integrated**

**Impact**: Missing 1+ high-severity findings

**Status**: ⚠️ **Detector exists but never called**

**Fix Required**: **10 LINES OF CODE**

#### File: `passive_detectors/passive_scanner.py`

**Add import** (line 14):
```python
from detectors.password_over_http_detector import PasswordOverHTTPDetector
```

**Add detection** (after line 100, in `analyze_response()` method):
```python
# Password over HTTP detection (only for non-HTTPS URLs)
if url.startswith('http://'):
    is_vuln, evidence, forms = PasswordOverHTTPDetector.detect_password_over_http(
        url, response_text, 200
    )
    if is_vuln:
        finding = {
            'type': 'Password over HTTP',
            'severity': 'High',
            'url': url,
            'description': evidence,
            'recommendation': PasswordOverHTTPDetector.get_remediation_advice(),
            'cwe': 'CWE-319',
            'owasp': 'A02:2021',
            'confidence': 0.90
        }
        response_findings['sensitive_data'].append(finding)
        logger.info(f"Password over HTTP detected: {url}")
```

**Testing**: Scan `http://testphp.vulnweb.com/login.php` should detect password field.

**Estimated Implementation Time**: 10 minutes
**Expected Impact**: +1 high finding

---

### **GAP #4: HTTP-Only Site Detection**

**Impact**: Missing 1+ medium-severity findings

**Status**: ⚠️ Partial (checks HSTS but not HTTP-only)

#### File: `passive_detectors/security_headers_detector.py`

Add to `analyze()` method:

```python
# Check if site uses HTTP instead of HTTPS
if url.startswith('http://') and not url.startswith('http://localhost') and not url.startswith('http://127.0.0.1'):
    findings.append({
        'type': 'HTTP Only Site',
        'severity': 'Medium',
        'url': url,
        'description': 'Site uses HTTP instead of HTTPS. All traffic (including passwords) is transmitted in cleartext.',
        'recommendation': 'Implement HTTPS/TLS for entire site. Redirect all HTTP traffic to HTTPS. Enable HTTP Strict Transport Security (HSTS).',
        'cwe': 'CWE-319',
        'owasp': 'A02:2021',
        'confidence': 0.95
    })
```

**Estimated Implementation Time**: 15 minutes
**Expected Impact**: +1 medium finding

---

## 🎨 PATTERN EXTERNALIZATION

### **Quick Wins (Priority 1)**

#### 1. CSRF Token Names

**Create**: `modules/csrf/token_names.txt`
```
csrf
csrf_token
csrftoken
_csrf
_token
authenticity_token
anti_csrf
xsrf
xsrf_token
token
__RequestVerificationToken
nonce
```

**Modify**: `modules/csrf/module.py` line 24
```python
self.token_names = self._load_txt_file("token_names.txt")
```

---

#### 2. CSRF State-Changing Keywords

**Create**: `modules/csrf/state_changing_keywords.txt`
```
password
passwd
pass
pwd
email
username
user
delete
remove
change
update
modify
create
add
new
register
transfer
send
payment
purchase
confirm
```

**Modify**: `modules/csrf/module.py` line 31
```python
self.state_changing_keywords = self._load_txt_file("state_changing_keywords.txt")
```

---

#### 3. DOM XSS Safe Domains

**Create**: `modules/dom_xss/safe_domains.txt`
```
googletagmanager.com
google-analytics.com
cdn.jsdelivr.net
cdnjs.cloudflare.com
ajax.googleapis.com
code.jquery.com
maxcdn.bootstrapcdn.com
stackpath.bootstrapcdn.com
unpkg.com
polyfill.io
```

**Modify**: `modules/dom_xss/module.py` line 225
```python
safe_domains = self._load_txt_file("safe_domains.txt")
```

---

#### 4. IDOR ID Parameters

**Create**: `modules/idor/id_parameters.txt`
```
id
item
user
uid
userid
user_id
itemid
item_id
object
obj
doc
file
account
profile
order
invoice
aid
pid
cid
gid
tid
sid
rid
vid
eid
```

**Modify**: `modules/idor/module.py` line 42
```python
id_params = self._load_txt_file("id_parameters.txt")
```

---

#### 5. IDOR Skip Parameters

**Create**: `modules/idor/skip_parameters.txt`
```
action
operation
method
mode
type
submit
csrf
token
```

**Modify**: `modules/idor/module.py` line 68
```python
skip_params = self._load_txt_file("skip_parameters.txt")
```

---

### **All Other Patterns**

See [HARDCODED_PATTERNS_ANALYSIS.md](HARDCODED_PATTERNS_ANALYSIS.md) for complete list:
- `modules/csrf/success_patterns.txt`
- `modules/csrf/error_patterns.txt`
- `modules/xxe/xml_keywords.txt`
- `modules/ssrf/url_keywords.txt`
- `modules/sqli/sql_keywords.txt`
- `modules/sqli/db_function_prefixes.txt`

**Total**: 11 TXT files, ~126 patterns externalized

---

## 📋 IMPLEMENTATION ROADMAP

### **Phase 1: Quick Wins (2 hours)**

Priority: Get immediate improvements with minimal effort

1. ✅ **Password Over HTTP Integration** (10 minutes)
   - Modify: `passive_detectors/passive_scanner.py` (10 lines)
   - Expected: +1 high finding

2. ✅ **HTTP-Only Site Detection** (15 minutes)
   - Modify: `passive_detectors/security_headers_detector.py` (15 lines)
   - Expected: +1 medium finding

3. ✅ **Pattern Externalization - CSRF** (30 minutes)
   - Create: `token_names.txt`, `state_changing_keywords.txt`
   - Modify: `modules/csrf/module.py` (20 lines)

4. ✅ **Pattern Externalization - IDOR** (20 minutes)
   - Create: `id_parameters.txt`, `skip_parameters.txt`
   - Modify: `modules/idor/module.py` (10 lines)

5. ✅ **Pattern Externalization - DOM XSS** (15 minutes)
   - Create: `safe_domains.txt`
   - Modify: `modules/dom_xss/module.py` (10 lines)

6. ✅ **Pattern Externalization - Remaining** (30 minutes)
   - Create: 6 more TXT files
   - Modify: 3 more modules

**Phase 1 Total**: 2 hours, +2 findings, +126 patterns externalized

---

### **Phase 2: Blind XSS (3 hours)**

Priority: High-impact vulnerability detection

1. **OOB Integration for XSS** (2 hours)
   - Modify: `modules/xss/module.py` (80 lines)
   - Test with Requestbin/Pipedream
   - Expected: +5 high findings

2. **Configuration & Testing** (1 hour)
   - Add config options
   - Create test cases
   - Verify OOB callbacks work

**Phase 2 Total**: 3 hours, +5 high findings

---

### **Phase 3: Boolean-Based SQLi (6 hours)**

Priority: Highest impact (most missing vulnerabilities)

1. **Boolean Detection Logic** (3 hours)
   - Add `_detect_boolean_sqli()` method
   - Add `_extract_key_elements()` helper
   - Response comparison algorithms

2. **Integration & Payloads** (1 hour)
   - Integrate into main scan loop
   - Add Boolean payloads to TXT
   - Configuration options

3. **Testing & Tuning** (2 hours)
   - Test against XVWA, testphp.vulnweb.com
   - Adjust confidence thresholds
   - Reduce false positives

**Phase 3 Total**: 6 hours, +10 critical findings

---

### **Phase 4: Testing & Validation (2 hours)**

1. **Full XVWA Rescan** (1 hour)
   - Run complete scan
   - Compare results with previous scans
   - Verify all detections

2. **testphp.vulnweb.com Scan** (30 minutes)
   - Compare with Acunetix report
   - Calculate new detection rate
   - Document findings

3. **Documentation Update** (30 minutes)
   - Update README
   - Document new features
   - Create usage examples

**Phase 4 Total**: 2 hours

---

## 📊 EXPECTED RESULTS

### **Before ROTATION 8**:
```
Detection Rate: ~43% (compared to Acunetix)

Capabilities:
- ❌ Boolean-based SQLi
- ❌ Blind XSS
- ❌ Password over HTTP
- ❌ HTTP-only sites
- ⚠️ Hardcoded patterns (difficult to customize)

Findings on testphp.vulnweb.com:
- Acunetix: 58 vulnerabilities
- Dominator: ~25 vulnerabilities (estimated)
```

### **After ROTATION 8**:
```
Detection Rate: ~91% (compared to Acunetix)

Capabilities:
- ✅ Boolean-based SQLi
- ✅ Blind XSS (OOB)
- ✅ Password over HTTP
- ✅ HTTP-only sites
- ✅ All patterns in TXT files (easy to customize)

Findings on testphp.vulnweb.com:
- Acunetix: 58 vulnerabilities
- Dominator: ~53 vulnerabilities (estimated)
```

**Improvement**: +28 vulnerabilities detected (+112% increase)

---

## 🎯 PRIORITY RANKING

| Priority | Task | Impact | Time | Difficulty |
|----------|------|--------|------|------------|
| **P0** | Password Over HTTP Integration | High | 10 min | Very Low |
| **P0** | HTTP-Only Site Detection | Medium | 15 min | Very Low |
| **P1** | Pattern Externalization (All) | High | 2 hrs | Low |
| **P2** | Blind XSS (OOB) | High | 3 hrs | Medium |
| **P3** | Boolean-Based SQLi | Critical | 6 hrs | High |

**Recommended Order**: P0 → P1 → P2 → P3

**Rationale**:
1. P0 tasks are trivial (25 minutes total) but provide immediate value
2. P1 improves maintainability before adding complex features
3. P2 and P3 are complex but high-impact

---

## ✅ SUCCESS CRITERIA

### **Phase 1 Complete When**:
- [ ] Password over HTTP detected on `http://testphp.vulnweb.com/login.php`
- [ ] HTTP-only site warning appears for all HTTP scans
- [ ] All 11 TXT files created and modules load them correctly
- [ ] CSRF/IDOR/DOM XSS modules still function correctly

### **Phase 2 Complete When**:
- [ ] Blind XSS payload with OOB submitted successfully
- [ ] OOB callback detected within 10 seconds
- [ ] Blind XSS finding appears in report with "OOB Confirmed" evidence
- [ ] No false positives from OOB detection

### **Phase 3 Complete When**:
- [ ] Boolean-based SQLi detects `/artists.php?artist=1 AND 1=1` vs `AND 1=2`
- [ ] All 10 testphp.vulnweb.com Boolean SQLi instances detected
- [ ] False positive rate < 5%
- [ ] Confidence scoring accurate

### **Overall Success**:
- [ ] Detection rate vs Acunetix: 43% → 91%
- [ ] Total implementation time: < 13 hours
- [ ] All existing tests still pass
- [ ] No new false positives introduced

---

## 📝 TESTING PLAN

### **Test Suite 1: Quick Wins**
```bash
# Test Password over HTTP
python main.py scan http://testphp.vulnweb.com/login.php
# Expected: "Password over HTTP" finding

# Test HTTP-only detection
python main.py scan http://testphp.vulnweb.com
# Expected: "HTTP Only Site" warning

# Test pattern externalization
python main.py scan http://127.0.0.1/xvwa
# Expected: CSRF/IDOR/DOM XSS detections still work
```

### **Test Suite 2: Blind XSS**
```bash
# Test Blind XSS with OOB
python main.py scan http://testphp.vulnweb.com/guestbook.php
# Expected: "Blind XSS (OOB Confirmed)" if callback received

# Verify OOB detection
# 1. Check Requestbin.cn for incoming requests
# 2. Verify OOB ID matches payload
```

### **Test Suite 3: Boolean SQLi**
```bash
# Test Boolean-based SQLi
python main.py scan http://testphp.vulnweb.com/artists.php?artist=1
# Expected: "Boolean-based SQL Injection" finding

# Compare with Acunetix
# Count Boolean SQLi findings - should be ~10
```

---

## 🎉 FINAL DELIVERABLES

### **Code**:
1. Modified modules (6 files)
2. New TXT files (11 files)
3. New detection methods (3 methods)

### **Documentation**:
1. [ACUNETIX_GAP_ANALYSIS.md](ACUNETIX_GAP_ANALYSIS.md) ✅ Created
2. [HARDCODED_PATTERNS_ANALYSIS.md](HARDCODED_PATTERNS_ANALYSIS.md) ✅ Created
3. This document (ROTATION8_MASTER_PLAN.md) ✅ Created
4. Updated README.md with new features
5. Pattern file format documentation

### **Testing**:
1. Unit tests for new detection methods
2. Integration tests for OOB detection
3. Regression tests for existing modules
4. Full scan results comparison

---

## 🚀 READY TO START

**All analysis complete!**

Recommended starting point:
```bash
# Phase 1, Task 1: Password Over HTTP Integration (10 minutes)
# Edit: passive_detectors/passive_scanner.py
```

**Total Estimated Time**: 13 hours
**Expected Impact**: +48% detection rate improvement

**Let's close the gap to Acunetix!** 🎯
