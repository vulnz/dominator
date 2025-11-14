# ROTATION 6 - Master Quality Improvement Plan

## Date: 2025-11-13
## Status: PLANNING → IMPLEMENTATION

---

## 🎯 **Critical Issues Identified**

### 1. Formula Injection False Positives
**Issue**: Reporting FPs on simple reflection
**Fix**: Already improved in ROTATION 4 - require export functionality OR dangerous payloads

### 2. IDOR Detection Gaps ⚠️ CRITICAL
**Issues**:
- Not extracting `id=` parameters from URLs properly
- Weak proof of vulnerability
- Missing detailed evidence

**Required Changes**:
- Extract ID parameters from URL query strings automatically
- Add visual proof: Show actual data differences between ID=1 and ID=2
- Include sample data from responses
- Better confidence scoring

### 3. Directory Listing Missing Detections ⚠️ CRITICAL
**Issue**: Not detecting many directory listings
**Fix**: Enhance detection patterns, add more indicators

### 4. GitHub Exposure Duplicates
**Issue**: Same `.git/` finding reported multiple times
**Fix**: Deduplicate by base URL in result_manager.py

### 5. Missing POST Support
**Issue**: Many modules only test GET
**Fix**: Ensure all modules test both GET and POST methods

### 6. Missing OOB Command Injection
**Issue**: CMDi module doesn't have OOB detection
**Fix**: Add OOB callbacks like RFI/SSRF modules

### 7. Vulnerability Naming Issues ⚠️ CRITICAL
**Current**: "CSRF Scanner", "SQL Injection Scanner", "information_disclosure"
**Required**: "Cross-Site Request Forgery (CSRF)", "SQL Injection", "Information Disclosure"

**Fix**: Update `create_result()` to use proper names from config.json

### 8. Missing Security Metadata ⚠️ CRITICAL
**Issue**: Not all findings include CWE, OWASP, CVSS
**Fix**: Ensure ALL modules add this metadata to results

### 9. Missing Remediation ⚠️ CRITICAL
**Issue**: No remediation advice in findings
**Fix**: Add remediation field to all results

### 10. Report UI Issues
**Current**: All findings expanded, no filtering
**Required**:
- Collapsible findings (expand/collapse individual or all)
- Severity filter dropdown
- Better organization

---

## 📋 **Implementation Plan**

### Phase 1: Core Infrastructure (Files: 3)
**Priority**: HIGH

1. **core/base_module.py** - Enhance `create_result()`
   - Add automatic CWE/OWASP/CVSS from config
   - Add remediation field
   - Fix vulnerability naming (use config name, not module name)

2. **core/result_manager.py** - Fix duplicates
   - Add git exposure deduplication
   - Improve directory listing deduplication

3. **data/remediations.json** (NEW FILE)
   - CWE-based remediation mappings
   - Standard remediation templates

### Phase 2: IDOR Module Enhancement (Files: 2)
**Priority**: CRITICAL

4. **modules/idor/module.py**
   - Add URL parameter extraction (id=1, id=2, etc.)
   - Add data comparison proof
   - Show actual content differences
   - Better evidence with sample data

5. **modules/idor/config.json**
   - Add remediation text
   - Update descriptions

### Phase 3: Directory Listing Enhancement (Files: 2)
**Priority**: HIGH

6. **modules/dirbrute/module.py**
   - Enhance directory listing detection
   - Add more HTML patterns
   - Detect Apache/Nginx/IIS directory indexes

7. **core/crawler.py**
   - Better passive directory listing detection
   - More detection patterns

### Phase 4: CMDi OOB Detection (Files: 2)
**Priority**: MEDIUM

8. **modules/cmdi/module.py**
   - Add OOBDetector integration
   - Test curl/wget callbacks
   - Add blind command injection detection

9. **modules/cmdi/config.json**
   - Add OOB configuration

### Phase 5: POST Support (Files: 6)
**Priority**: MEDIUM

10. Audit and fix POST support in:
    - modules/sqli/module.py
    - modules/xss/module.py
    - modules/lfi/module.py
    - modules/xpath/module.py
    - modules/ssti/module.py
    - modules/php_object_injection/module.py

### Phase 6: Report UI Overhaul (Files: 1)
**Priority**: HIGH

11. **core/report_generator.py**
    - Add JavaScript for expand/collapse
    - Add severity filter
    - Better CSS styling
    - Collapsible sections

---

## 🔧 **Detailed Implementation Steps**

### Step 1: Enhance base_module.py `create_result()`

```python
def create_result(self, vulnerable=False, url="", parameter="", payload="",
                  evidence="", description="", confidence=0.0, severity=None):
    """Enhanced result creation with full metadata"""

    # Get metadata from config
    cwe = self.config.get('cwe', 'CWE-Unknown')
    cwe_name = self.config.get('cwe_name', '')
    owasp = self.config.get('owasp', 'A00:2021')
    owasp_name = self.config.get('owasp_name', '')
    cvss = self.config.get('cvss', '0.0')
    cvss_vector = self.config.get('cvss_vector', '')

    # Get proper vulnerability name (not "Scanner" suffix)
    vuln_name = self.config.get('vulnerability_name', self.config.get('name', 'Unknown'))

    # Get remediation
    remediation = self.config.get('remediation', self._get_generic_remediation(cwe))

    return {
        'vulnerability': vulnerable,
        'type': vuln_name,  # Use proper name
        'module': self.config.get('name'),
        'url': url,
        'parameter': parameter,
        'payload': payload,
        'evidence': evidence,
        'description': description,
        'confidence': confidence,
        'severity': severity or self.config.get('severity', 'Medium'),
        'cwe': cwe,
        'cwe_name': cwe_name,
        'owasp': owasp,
        'owasp_name': owasp_name,
        'cvss': cvss,
        'cvss_vector': cvss_vector,
        'remediation': remediation,
        'timestamp': datetime.now().isoformat()
    }
```

### Step 2: IDOR Module - Extract ID Parameters

```python
def _extract_id_from_url(self, url: str) -> Optional[Dict]:
    """Extract ID parameter from URL"""
    from urllib.parse import urlparse, parse_qs

    parsed = urlparse(url)
    params = parse_qs(parsed.query)

    # Look for ID-like parameters
    id_keywords = ['id', 'item', 'user', 'uid', 'doc', 'file']

    for key, values in params.items():
        if any(keyword in key.lower() for keyword in id_keywords):
            return {
                'param': key,
                'value': values[0] if values else None,
                'full_params': params
            }

    return None
```

### Step 3: IDOR Module - Add Data Comparison Proof

```python
def _create_visual_proof(self, original_id, test_id, original_data, test_data):
    """Create visual proof of IDOR"""
    proof = f"\n\n=== PROOF OF VULNERABILITY ===\n"
    proof += f"Original ID ({original_id}):\n"
    proof += f"  Data Sample: {original_data[:200]}...\n\n"
    proof += f"Tampered ID ({test_id}):\n"
    proof += f"  Data Sample: {test_data[:200]}...\n\n"
    proof += f"Result: Different user/object data accessed without authorization!\n"
    return proof
```

### Step 4: Directory Listing - Enhanced Detection

```python
def _detect_directory_listing(self, html: str) -> bool:
    """Enhanced directory listing detection"""
    patterns = [
        r'<title>Index of /',  # Apache
        r'<h1>Index of',
        r'Directory Listing',
        r'<th>Name</th>.*<th>Last modified</th>.*<th>Size</th>',  # Apache table
        r'Parent Directory',
        r'\[To Parent Directory\]',  # IIS
        r'<pre><a href="\.\.">\.\.</a>',  # Nginx
        r'<a href="\?C=N;O=D">Name</a>',  # Apache sorting links
    ]

    # Check multiple patterns for higher confidence
    matches = sum(1 for p in patterns if re.search(p, html, re.I))
    return matches >= 2  # Require 2+ indicators
```

### Step 5: Report UI - Collapsible Findings

```html
<!-- JavaScript for expand/collapse -->
<script>
function toggleFinding(id) {
    var elem = document.getElementById('finding-' + id);
    elem.style.display = (elem.style.display === 'none') ? 'block' : 'none';
}

function expandAll() {
    document.querySelectorAll('[id^="finding-"]').forEach(e => e.style.display = 'block');
}

function collapseAll() {
    document.querySelectorAll('[id^="finding-"]').forEach(e => e.style.display = 'none');
}

function filterBySeverity() {
    var severity = document.getElementById('severity-filter').value;
    document.querySelectorAll('.finding-card').forEach(card => {
        if (severity === 'all' || card.dataset.severity === severity) {
            card.style.display = 'block';
        } else {
            card.style.display = 'none';
        }
    });
}
</script>

<!-- Severity Filter -->
<div class="filter-controls">
    <label>Filter by Severity:</label>
    <select id="severity-filter" onchange="filterBySeverity()">
        <option value="all">All</option>
        <option value="Critical">Critical</option>
        <option value="High">High</option>
        <option value="Medium">Medium</option>
        <option value="Low">Low</option>
        <option value="Info">Info</option>
    </select>
    <button onclick="expandAll()">Expand All</button>
    <button onclick="collapseAll()">Collapse All</button>
</div>
```

---

## 📊 **Expected Improvements**

### Quality Metrics:
- **False Positive Rate**: < 5% (currently ~10-15%)
- **IDOR Detection**: +300% (detect id= in URLs)
- **Directory Listing**: +200% (better patterns)
- **Report Usability**: +500% (filtering, collapsing)

### Coverage Metrics:
- **POST Testing**: 100% of modules (currently ~60%)
- **OOB Detection**: CMDi, SSRF, RFI, XXE (currently only RFI/SSRF)
- **Metadata**: 100% findings with CWE/OWASP/CVSS (currently ~50%)
- **Remediation**: 100% findings with fix advice (currently 0%)

---

## 🚀 **Execution Timeline**

**Total Estimated Time**: 2-3 hours for all phases

- **Phase 1**: 30 min (core infrastructure)
- **Phase 2**: 45 min (IDOR enhancement)
- **Phase 3**: 20 min (directory listing)
- **Phase 4**: 30 min (CMDi OOB)
- **Phase 5**: 30 min (POST support)
- **Phase 6**: 30 min (report UI)

---

## ✅ **Testing Strategy**

After implementation:
1. Run ROTATION 6 on all 3 targets
2. Manually verify IDOR findings have proper proof
3. Check report UI works (expand/collapse, filter)
4. Verify all findings have remediation
5. Confirm POST methods are tested
6. Validate no duplicate git findings

---

**Generated**: 2025-11-13
**Scope**: ROTATION 6 Quality Overhaul
**Status**: READY TO IMPLEMENT
