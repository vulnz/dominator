# HARDCODED PATTERNS ANALYSIS - What Needs to Move

## 🎯 OBJECTIVE
Identify ALL hardcoded patterns, keywords, and detection logic that should be moved to:
1. **TXT files** (payloads, patterns, indicators)
2. **JSON config files** (module configurations)
3. **Detector classes** (reusable detection logic)

---

## 📊 HARDCODED PATTERNS INVENTORY

### ✅ ALREADY MOVED TO TXT FILES (Good Examples)

| Module | Pattern Type | File Location | Status |
|--------|-------------|---------------|--------|
| SQLi | Error patterns | `modules/sqli/error_patterns.txt` | ✅ Externalized |
| SQLi | Payloads | `modules/sqli/payloads.txt` | ✅ Externalized |
| XSS | Payloads | `modules/xss/payloads.txt` | ✅ Externalized |
| LFI | Payloads | `modules/lfi/payloads.txt` | ✅ Externalized |
| SSTI | Payloads | `modules/ssti/payloads.txt` | ✅ Externalized |

**Example of Good Practice**:
```python
# modules/sqli/module.py line 28
self.error_patterns = self._load_txt_file("error_patterns.txt")
```

---

## ❌ HARDCODED PATTERNS THAT NEED TO BE MOVED

### **1. CSRF Module - Multiple Hardcoded Lists**

**File**: `modules/csrf/module.py`

#### A. CSRF Token Names (Lines 24-28)
**Current Code**:
```python
self.token_names = [
    'csrf', 'csrf_token', 'csrftoken', '_csrf', '_token',
    'authenticity_token', 'anti_csrf', 'xsrf', 'xsrf_token',
    'token', '__RequestVerificationToken', 'nonce'
]
```

**Should be**: `modules/csrf/token_names.txt`
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

**Code Change**:
```python
# modules/csrf/module.py line 24
self.token_names = self._load_txt_file("token_names.txt")
```

---

#### B. State-Changing Keywords (Lines 31-38)
**Current Code**:
```python
self.state_changing_keywords = [
    'password', 'passwd', 'pass', 'pwd',
    'email', 'username', 'user',
    'delete', 'remove', 'change', 'update', 'modify',
    'create', 'add', 'new', 'register',
    'transfer', 'send', 'payment', 'purchase',
    'confirm'
]
```

**Should be**: `modules/csrf/state_changing_keywords.txt`
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

---

#### C. Success/Error Patterns (Lines 193-210)
**Current Code**:
```python
success_patterns = [
    'success',
    'changed',
    'updated',
    'saved',
    'completed',
    'thank you',
    'confirmed'
]

error_patterns = ['error', 'invalid', 'failed', 'denied', 'forbidden']
```

**Should be**:
- `modules/csrf/success_patterns.txt`
- `modules/csrf/error_patterns.txt`

---

### **2. IDOR Module - ID Parameter Keywords**

**File**: `modules/idor/module.py`

#### A. ID Parameter Patterns (Lines 42-45)
**Current Code**:
```python
id_params = ['id', 'item', 'user', 'uid', 'userid', 'user_id',
             'itemid', 'item_id', 'object', 'obj', 'doc', 'file',
             'account', 'profile', 'order', 'invoice', 'aid', 'pid',
             'cid', 'gid', 'tid', 'sid', 'rid', 'vid', 'eid']
```

**Should be**: `modules/idor/id_parameters.txt`
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

---

#### B. Skip Parameters (Line 68)
**Current Code**:
```python
skip_params = ['action', 'operation', 'method', 'mode', 'type', 'submit', 'csrf']
```

**Should be**: `modules/idor/skip_parameters.txt`
```
action
operation
method
mode
type
submit
csrf
```

---

### **3. DOM XSS Module - CDN Whitelist**

**File**: `modules/dom_xss/module.py`

#### Safe Domains Whitelist (Lines 225-236)
**Current Code**:
```python
SAFE_DOMAINS = [
    'googletagmanager.com',
    'google-analytics.com',
    'cdn.jsdelivr.net',
    'cdnjs.cloudflare.com',
    'ajax.googleapis.com',
    'code.jquery.com',
    'maxcdn.bootstrapcdn.com',
    'stackpath.bootstrapcdn.com',
    'unpkg.com',
    'polyfill.io'
]
```

**Should be**: `modules/dom_xss/safe_domains.txt`
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
# Add more safe CDN domains as needed
```

**Benefits**:
- Easy to add new safe domains without code changes
- Users can customize whitelist
- Version control tracks changes

---

### **4. XXE Module - XML Keywords**

**File**: `modules/xxe/module.py`

#### XML Detection Keywords (Line 154)
**Current Code**:
```python
xml_keywords = ['xml', 'soap', 'api', 'feed', 'rss', 'import', 'upload']
```

**Should be**: `modules/xxe/xml_keywords.txt`
```
xml
soap
api
feed
rss
import
upload
document
data
config
```

---

### **5. SSRF Module - Detection Patterns**

**File**: `modules/ssrf/module.py`

#### A. XSS Patterns in SSRF Check (Line 171)
**Current Code**:
```python
xss_patterns = ['<script', 'alert(', 'onerror=', 'onload=', 'javascript:']
```

**Should be**: Reuse `modules/xss/indicators.txt` OR create `modules/ssrf/xss_patterns.txt`

---

#### B. URL Parameter Keywords (Line 194)
**Current Code**:
```python
url_param_keywords = ['url', 'uri', 'img', 'image', 'file', 'path']
```

**Should be**: `modules/ssrf/url_keywords.txt`
```
url
uri
img
image
file
path
src
href
dest
destination
redirect
link
```

---

### **6. SQLi Module - Strong Patterns**

**File**: `modules/sqli/module.py`

#### Strong Error Patterns (Lines 155-163)
**Current Code**:
```python
strong_patterns = [
    'You have an error in your SQL syntax',
    'Warning: mysql_',
    'mysqli_sql_exception',
    'Fatal error: Uncaught exception',
    'Unclosed quotation mark',
    'ORA-01756',
    'PostgreSQL query failed'
]
```

**Issue**: These are DUPLICATES of patterns in `error_patterns.txt`!

**Fix**: Remove this hardcoded list and use only the TXT file.

---

#### SQL Validation Keywords (Lines 232-233)
**Current Code**:
```python
sql_keywords = ['select', 'from', 'where', 'syntax', 'query', 'statement']
```

**Should be**: `modules/sqli/sql_keywords.txt`
```
select
from
where
syntax
query
statement
insert
update
delete
table
database
```

---

#### Database Function Patterns (Line 244)
**Current Code**:
```python
db_functions = ['mysql_', 'pg_', 'oci_', 'mssql_', 'sqlite_']
```

**Should be**: `modules/sqli/db_function_prefixes.txt`
```
mysql_
pg_
oci_
mssql_
sqlite_
mysqli_
pgsql_
```

---

### **7. SSTI Module - Validation Patterns**

**File**: `modules/ssti/module.py`

#### Context Validation Keywords (Around line 200+)
**Needs Investigation**: Check if SSTI module has hardcoded template keywords that should be externalized.

---

### **8. Formula Injection - Multiple Hardcoded Lists**

**File**: `modules/formula_injection/module.py`

**NOTE**: This module is DISABLED due to false positives. When rewriting, externalize these:

#### A. Formula Starters (Line 28)
```python
self.formula_starters = ['=', '+', '-', '@', '|', '%']
```

**Should be**: `modules/formula_injection/formula_starters.txt`

---

#### B. Dangerous Keywords (Line 171)
```python
dangerous_keywords = ['cmd|', 'powershell', 'HYPERLINK', 'IMPORTXML', 'WEBSERVICE', 'DDE', 'Excel|', 'Word|']
```

**Should be**: `modules/formula_injection/dangerous_keywords.txt`

---

#### C. Context Indicators (Lines 271-282)
```python
table_indicators = ['<table', '<tr>', '<td>', '</td>', '<th>']
list_indicators = ['<ul>', '<li>', '<ol>', '</li>']
data_indicators = ['<div class="data', '<div class="row', '<span class="value']
```

**Should be**:
- `modules/formula_injection/table_indicators.txt`
- `modules/formula_injection/list_indicators.txt`
- `modules/formula_injection/data_indicators.txt`

---

### **9. Metadata - CWE/OWASP/CVSS Hardcoded**

**Problem**: Every module hardcodes security metadata.

**Examples**:
```python
# modules/cmdi/module.py lines 104-106
result['cwe'] = self.config.get('cwe', 'CWE-78')
result['owasp'] = self.config.get('owasp', 'A03:2021')
result['cvss'] = self.config.get('cvss', '9.8')
```

**Current Status**: ✅ **ALREADY USING CONFIG.JSON!**

This is CORRECT - the `.get('cwe', 'CWE-78')` pattern reads from `config.json` first, then falls back to hardcoded default.

**Recommendation**: Ensure ALL `config.json` files have these fields populated:
```json
{
  "cwe": "CWE-78",
  "owasp": "A03:2021",
  "cvss": "9.8"
}
```

---

## 🎯 SUMMARY OF REQUIRED CHANGES

### Files to Create (TXT):

| File | Purpose | Lines |
|------|---------|-------|
| `modules/csrf/token_names.txt` | CSRF token field patterns | ~12 |
| `modules/csrf/state_changing_keywords.txt` | Keywords indicating state changes | ~20 |
| `modules/csrf/success_patterns.txt` | Success message indicators | ~7 |
| `modules/csrf/error_patterns.txt` | Error message indicators | ~5 |
| `modules/idor/id_parameters.txt` | ID-like parameter names | ~25 |
| `modules/idor/skip_parameters.txt` | Non-ID parameters to ignore | ~7 |
| `modules/dom_xss/safe_domains.txt` | Whitelisted CDN domains | ~10 |
| `modules/xxe/xml_keywords.txt` | XML-related endpoint keywords | ~10 |
| `modules/ssrf/url_keywords.txt` | URL-related parameter names | ~12 |
| `modules/sqli/sql_keywords.txt` | SQL syntax validation keywords | ~11 |
| `modules/sqli/db_function_prefixes.txt` | Database function prefixes | ~7 |

**Total**: 11 new TXT files, ~126 patterns externalized

---

### Code Changes Required:

| Module | Lines to Change | Complexity |
|--------|----------------|------------|
| `modules/csrf/module.py` | ~30 lines | Low |
| `modules/idor/module.py` | ~10 lines | Low |
| `modules/dom_xss/module.py` | ~15 lines | Low |
| `modules/xxe/module.py` | ~5 lines | Very Low |
| `modules/ssrf/module.py` | ~10 lines | Low |
| `modules/sqli/module.py` | ~20 lines (remove duplicates) | Low |

**Total**: ~90 lines of code changes, all low complexity

---

## 🔧 IMPLEMENTATION PRIORITY

### **Priority 1: High-Value, Easy Wins**

1. **CSRF Token Names** - Most commonly customized
2. **DOM XSS Safe Domains** - Frequently needs updates
3. **IDOR ID Parameters** - Often needs app-specific params

### **Priority 2: Duplicate Elimination**

4. **SQLi Strong Patterns** - Remove duplication with TXT file

### **Priority 3: Consistency & Completeness**

5. **All remaining patterns** - For consistency across modules

---

## 🎨 PATTERN TEMPLATE

When creating new TXT files, use this format:

```
# Pattern Category: [Description]
# Last Updated: YYYY-MM-DD
#
# One pattern per line
# Lines starting with # are comments
# Empty lines are ignored

pattern1
pattern2
pattern3
```

**Example**: `modules/csrf/token_names.txt`
```
# CSRF Token Field Names
# Last Updated: 2025-01-13
# Common field names used for anti-CSRF tokens across frameworks

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

---

## 📊 BENEFITS OF EXTERNALIZATION

### **1. Maintainability**
- ✅ Update patterns without code changes
- ✅ Version control shows pattern changes clearly
- ✅ No need to rebuild/restart

### **2. Customization**
- ✅ Users can add app-specific patterns
- ✅ Different configs for different targets
- ✅ Easy A/B testing of pattern sets

### **3. Collaboration**
- ✅ Security researchers can contribute patterns via PR
- ✅ Pattern changes don't require Python knowledge
- ✅ Clear separation of logic vs data

### **4. Performance**
- ✅ Patterns loaded once at startup
- ✅ Easy to cache and optimize
- ✅ Can swap pattern files at runtime

### **5. Testing**
- ✅ Test different pattern sets easily
- ✅ Compare detection rates with different configs
- ✅ Rollback pattern changes if needed

---

## ✅ ACTION ITEMS

### Immediate (Next Commit):
- [ ] Create 11 TXT files listed above
- [ ] Modify 6 modules to load from TXT instead of hardcoded lists
- [ ] Remove duplicate strong_patterns in SQLi module
- [ ] Test all modules still work correctly

### Near-Term:
- [ ] Add comments to all TXT files explaining purpose
- [ ] Document pattern file format in module README
- [ ] Create pattern contribution guidelines

### Long-Term:
- [ ] Consider JSON for complex patterns (e.g., regex with metadata)
- [ ] Build pattern validation tool
- [ ] Create pattern effectiveness metrics

---

## 🎯 EXPECTED OUTCOME

**Before**:
- Patterns scattered across 6+ module files
- ~200 lines of hardcoded lists
- Code changes required to add patterns

**After**:
- All patterns in dedicated TXT files
- ~90 lines of code removed
- Patterns updated by editing text files
- Clear separation of code and data
- Easy to maintain and customize
