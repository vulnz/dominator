# Dominator Scanner - Testing Guide

Complete guide for testing Dominator against vulnerable targets and validating module effectiveness.

## Recommended Test Targets

### 1. Online Vulnerable Applications

#### OWASP Juice Shop
- **URL**: http://localhost:3000 (self-hosted)
- **GitHub**: https://github.com/juice-shop/juice-shop
- **Setup**: `docker run -p 3000:3000 bkimminich/juice-shop`
- **Vulnerabilities**: XSS, SQLi, CSRF, XXE, IDOR, and 90+ more
- **Difficulty**: Easy to Advanced

#### DVWA (Damn Vulnerable Web Application)
- **URL**: http://localhost/dvwa (self-hosted)
- **GitHub**: https://github.com/digininja/DVWA
- **Setup**: `docker run --rm -it -p 80:80 vulnerables/web-dvwa`
- **Vulnerabilities**: SQLi, XSS, CSRF, File Upload, CMDi
- **Difficulty**: Low, Medium, High, Impossible

#### bWAPP (Buggy Web Application)
- **URL**: http://localhost/bWAPP (self-hosted)
- **Download**: http://www.itsecgames.com/
- **Setup**: PHP + MySQL installation
- **Vulnerabilities**: 100+ web vulnerabilities
- **Difficulty**: Low, Medium, High

#### WebGoat
- **URL**: http://localhost:8080/WebGoat (self-hosted)
- **GitHub**: https://github.com/WebGoat/WebGoat
- **Setup**: `docker run -p 8080:8080 webgoat/webgoat`
- **Vulnerabilities**: Educational lessons with real vulns
- **Difficulty**: Guided tutorials

#### Mutillidae II
- **URL**: http://localhost/mutillidae (self-hosted)
- **GitHub**: https://github.com/webpwnized/mutillidae
- **Setup**: XAMPP/LAMP + Git clone
- **Vulnerabilities**: OWASP Top 10 coverage
- **Difficulty**: Easy to Hard

#### TestPHP (Acunetix)
- **URL**: http://testphp.vulnweb.com
- **Type**: Always-on testing site
- **Vulnerabilities**: SQLi, XSS, File Upload
- **Note**: Public test site, may be slow

#### TestASP.NET (Acunetix)
- **URL**: http://testaspnet.vulnweb.com
- **Type**: Always-on testing site
- **Vulnerabilities**: .NET specific vulns
- **Note**: Public test site

### 2. Self-Hosted Docker Lab

#### Quick Multi-Target Setup
```bash
# Create docker-compose.yml
version: '3'
services:
  dvwa:
    image: vulnerables/web-dvwa
    ports:
      - "80:80"

  juice-shop:
    image: bkimminich/juice-shop
    ports:
      - "3000:3000"

  webgoat:
    image: webgoat/webgoat
    ports:
      - "8080:8080"

  mutillidae:
    image: citizenstig/nowasp
    ports:
      - "8888:80"

# Start all targets
docker-compose up -d
```

## Testing Methodology

### 1. Baseline Scan (Quick Validation)

Test if scanner runs without errors:

```bash
python main.py -t http://testphp.vulnweb.com \
  --max-crawl-pages 10 \
  -m xss,sqli \
  --timeout 10 \
  -v
```

**Expected Result:**
- Scan completes in ~3-5 minutes
- Finds 2-5 XSS vulnerabilities
- Finds 1-3 SQLi vulnerabilities
- No crashes or errors

### 2. Module-Specific Testing

#### Test XSS Module
```bash
python main.py -t http://testphp.vulnweb.com \
  -m xss \
  --max-crawl-pages 20 \
  --auto-report --format html \
  -v
```

**Validation Checklist:**
- [ ] Reflected XSS detected in search parameter
- [ ] Payload properly reflected in response
- [ ] Evidence shows execution context
- [ ] Confidence score is appropriate (>0.7)
- [ ] HTML report generated with details

#### Test SQLi Module
```bash
python main.py -t http://testphp.vulnweb.com \
  -m sqli \
  --max-crawl-pages 20 \
  --auto-report --format html \
  -v
```

**Validation Checklist:**
- [ ] Error-based SQLi detected
- [ ] Database error message in evidence
- [ ] Correct error pattern matched (MySQL)
- [ ] Confidence score is high (>0.8)
- [ ] UNION-based detection attempted

#### Test LFI Module
```bash
python main.py -t http://testphp.vulnweb.com \
  -m lfi \
  --max-crawl-pages 20 \
  --auto-report --format html \
  -v
```

**Validation Checklist:**
- [ ] Path traversal detected
- [ ] File content visible in evidence
- [ ] Pattern matching works (etc/passwd or win.ini)
- [ ] No false positives on normal files

### 3. Full Scan Testing

#### Comprehensive Test
```bash
python main.py -t http://testphp.vulnweb.com \
  --all \
  --max-crawl-pages 50 \
  --threads 15 \
  --timeout 20 \
  --auto-report --format html,json,txt \
  -v
```

**Expected Results:**
- **Duration**: 15-25 minutes
- **Vulnerabilities**: 10-20 total
- **Critical**: 0-2
- **High**: 5-10
- **Medium**: 3-8
- **Low**: 1-3
- **Info**: 5-10 (passive findings)

**Quality Checks:**
- [ ] No duplicate vulnerabilities
- [ ] All severities properly classified
- [ ] Evidence is clear and actionable
- [ ] Remediation advice provided
- [ ] CVSS/OWASP/CWE mappings correct

### 4. Multi-Target Testing

Create `test_targets.txt`:
```
http://testphp.vulnweb.com
http://testaspnet.vulnweb.com
http://localhost/dvwa
```

Run multi-target scan:
```bash
python main.py -f test_targets.txt \
  -m xss,sqli,lfi \
  --max-crawl-pages 30 \
  --threads 15 \
  --auto-report --format html \
  -v
```

**Validation:**
- [ ] All 3 targets scanned
- [ ] Results separated by target
- [ ] Individual reports + combined report
- [ ] No cross-contamination of findings

### 5. GUI Testing

#### Launch GUI
```bash
python main.py --gui
```

**Manual Test Checklist:**

**Target Configuration:**
- [ ] Single target input works
- [ ] Multi-target input works
- [ ] File browsing works
- [ ] Target validation (URL format)

**Module Selection:**
- [ ] Individual module checkboxes work
- [ ] "Select All" checkbox works
- [ ] Module search/filter works
- [ ] Module descriptions visible

**Advanced Options:**
- [ ] Thread count adjustment works
- [ ] Timeout configuration works
- [ ] Max pages slider works
- [ ] Authentication fields appear/hide correctly

**Scan Execution:**
- [ ] Start scan button initiates scan
- [ ] Progress bar updates
- [ ] Real-time console output visible
- [ ] Stop scan button works
- [ ] Scan completes successfully

**Results Display:**
- [ ] Vulnerabilities appear in Results tab
- [ ] Severity colors correct (Critical=red, High=orange, etc.)
- [ ] Clicking vulnerability shows details
- [ ] Filters work (severity, type, search)
- [ ] Statistics update correctly

**Report Export:**
- [ ] HTML report button opens report
- [ ] JSON export works
- [ ] TXT export works
- [ ] Reports contain all findings

### 6. Performance Testing

#### Measure Scan Time
```bash
time python main.py -t http://testphp.vulnweb.com \
  --all \
  --max-crawl-pages 50 \
  --threads 15
```

**Benchmarks (testphp.vulnweb.com):**
- 20 pages, 3 modules: < 5 minutes
- 50 pages, 6 modules: < 15 minutes
- 50 pages, 20 modules: < 30 minutes

#### Memory Usage Test
```bash
# Linux/macOS
/usr/bin/time -v python main.py -t http://testphp.vulnweb.com --all

# Windows (Task Manager)
# Monitor "python.exe" memory usage during scan
```

**Expected Memory:**
- Small scan (20 pages): < 200 MB
- Medium scan (50 pages): < 400 MB
- Large scan (200 pages): < 800 MB

### 7. False Positive Testing

Test against clean sites to verify low false positive rate:

```bash
# Test against Google (should find nothing)
python main.py -t https://www.google.com \
  --max-crawl-pages 5 \
  -m xss,sqli \
  --timeout 10
```

**Expected Result:**
- 0 Critical/High vulnerabilities
- 0-3 Medium (likely passive findings)
- 5-10 Info (missing headers, version disclosure)

### 8. Edge Case Testing

#### Test Invalid Target
```bash
python main.py -t http://this-does-not-exist-12345.com
```
**Expected**: Error message, graceful exit

#### Test Timeout Handling
```bash
python main.py -t http://httpbin.org/delay/30 --timeout 5
```
**Expected**: Timeout warning, continues scan

#### Test Special Characters
```bash
python main.py -t "http://testphp.vulnweb.com/?search=test%20space"
```
**Expected**: Proper URL encoding, no crashes

#### Test Authentication
```bash
python main.py -t http://localhost/dvwa \
  --auth-type basic \
  --auth-username admin \
  --auth-password password
```
**Expected**: Successful authentication, pages crawled

### 9. Regression Testing

After making code changes, run regression tests:

```bash
# Quick regression (5 minutes)
python main.py -t http://testphp.vulnweb.com \
  --max-crawl-pages 20 \
  -m xss,sqli,lfi \
  --auto-report --format json \
  -v > regression_test.log

# Compare with baseline
diff regression_test.log baseline_test.log
```

**What to Check:**
- [ ] Same vulnerabilities found
- [ ] No new errors/warnings
- [ ] Scan time similar (±20%)
- [ ] Memory usage similar (±20%)

### 10. Payload Effectiveness Testing

Test individual payloads:

```bash
# Create custom payload file
echo '<script>alert("XSS")</script>' > custom_xss.txt

# Test with custom payloads
python main.py -t http://testphp.vulnweb.com \
  -m xss \
  --custom-payloads custom_xss.txt \
  --max-crawl-pages 10
```

**Validation:**
- [ ] Custom payload loaded
- [ ] Payload tested against parameters
- [ ] Detection logic works with custom payload

## Known Test Results

### TestPHP (http://testphp.vulnweb.com)

Expected findings with `--all --max-crawl-pages 50`:

| Vulnerability | Count | Confidence | Location |
|---------------|-------|------------|----------|
| Reflected XSS | 3-5 | High | search.php, hpp/ |
| SQL Injection | 1-2 | High | artists.php, listproducts.php |
| Missing Headers | 6-8 | Info | All pages |
| Version Disclosure | 2-3 | Low | Server headers |
| Email Disclosure | 1-2 | Info | Contact pages |

### DVWA (http://localhost/dvwa) - Low Security

Expected findings with `--all --max-crawl-pages 30`:

| Vulnerability | Count | Confidence | Location |
|---------------|-------|------------|----------|
| SQL Injection | 2-4 | Critical | vulnerabilities/sqli/ |
| Reflected XSS | 2-3 | High | vulnerabilities/xss_r/ |
| Stored XSS | 1-2 | Critical | vulnerabilities/xss_s/ |
| Command Injection | 1-2 | Critical | vulnerabilities/exec/ |
| File Upload | 1 | High | vulnerabilities/upload/ |
| CSRF | 3-5 | Medium | All forms |

### Juice Shop (http://localhost:3000)

Expected findings with `--all --max-crawl-pages 50`:

| Vulnerability | Count | Confidence | Location |
|---------------|-------|------------|----------|
| XSS | 5-8 | Medium-High | Search, reviews, admin |
| SQL Injection | 2-3 | High | Login, search |
| IDOR | 3-5 | Medium | API endpoints |
| XXE | 1-2 | High | File upload |
| SSRF | 1 | Medium | PDF generator |

## Troubleshooting Test Issues

### Issue: No Vulnerabilities Found

**Causes:**
1. Target is actually secure
2. Module thresholds too strict
3. Network issues preventing requests
4. Authentication required but not provided

**Solutions:**
```bash
# Enable verbose logging
python main.py -t TARGET -v

# Lower confidence threshold
# Edit modules/*/config.json: "confidence_threshold": 0.3

# Check network connectivity
curl -I TARGET
```

### Issue: Too Many False Positives

**Causes:**
1. Confidence thresholds too low
2. Pattern matching too broad
3. Response context not validated

**Solutions:**
```bash
# Increase confidence threshold
# Edit modules/*/config.json: "confidence_threshold": 0.8

# Enable stricter validation
# Code changes in modules/*/module.py
```

### Issue: Scan Hangs or Crashes

**Causes:**
1. Target has infinite redirects
2. Memory exhaustion
3. Thread deadlock

**Solutions:**
```bash
# Limit pages
--max-crawl-pages 20

# Reduce threads
--threads 5

# Add timeout
--timeout 10

# Monitor resources
watch -n 1 "ps aux | grep python"
```

## Reporting Issues

When reporting bugs, include:

1. **Command used**: Full command with all flags
2. **Target**: URL or description
3. **Expected result**: What should happen
4. **Actual result**: What actually happened
5. **Logs**: Output with `-v` verbose flag
6. **Environment**:
   - OS and version
   - Python version
   - Scanner version
   - Network setup (VPN, proxy, etc.)

Example:
```
Command: python main.py -t http://testphp.vulnweb.com -m xss -v
Target: testphp.vulnweb.com (public test site)
Expected: Find 3-5 XSS vulnerabilities
Actual: Found 0 vulnerabilities, no errors
Logs: [attach verbose output]
Environment:
  - Windows 11
  - Python 3.11.5
  - Scanner v1.10.0
  - No VPN/proxy
```

---

**Last Updated:** 2025-11-15
**Scanner Version:** 1.10.0
**Test Coverage:** 15/20 modules validated
**Next Review:** 2025-12-01
