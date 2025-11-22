# Gsec Scanner Analysis & Feature Recommendations for Dominator

## 📊 Executive Summary

**Gsec** is a comprehensive web security scanner that combines custom vulnerability scanners with Nuclei integration. After detailed analysis, I've identified **15+ valuable features** we can add to Dominator to make it even more powerful.

---

## 🔍 Gsec Features Analysis

### ✅ Features Dominator Already Has (Better Implementation)

| Feature | Dominator Status | Notes |
|---------|------------------|-------|
| XSS Detection | ✅ **Superior** | We have 43 payloads vs their basic detection |
| SQL Injection | ✅ **Superior** | We have error-based, time-based, and boolean-based |
| SSRF Detection | ✅ **Superior** | We have OOB detection with 19 payloads |
| Path Traversal/LFI | ✅ **Superior** | 61 payloads with multi-stage validation |
| Command Injection | ✅ **Superior** | 39 payloads with time-based detection |
| CSRF Detection | ✅ **Similar** | We have token pattern matching (12 patterns) |
| CORS Misconfiguration | ✅ **Similar** | Part of our passive analysis |
| Directory Brute Force | ✅ **Similar** | 250 paths + 16 extensions |
| HTTP Security Headers | ✅ **Similar** | Passive security header scanner |

### 🆕 Features Gsec Has That We Should Add

#### **HIGH PRIORITY - Missing Core Features:**

1. **Host Header Injection Detection** ⭐⭐⭐
   - **What it does:** Tests for Host header poisoning vulnerabilities
   - **Impact:** Can lead to password reset poisoning, web cache poisoning, SSRF
   - **Implementation:** New module `modules/host_header_injection/`

2. **HTTP Request Smuggling Detection** ⭐⭐⭐
   - **What it does:** Detects CL.TE, TE.CL, TE.TE desynchronization attacks
   - **Impact:** Critical vulnerability affecting proxies/load balancers
   - **Implementation:** New module `modules/http_smuggling/`

3. **GraphQL Security Testing** ⭐⭐⭐
   - **What it does:** Tests GraphQL endpoints for introspection, DoS, injection
   - **Impact:** Growing attack surface as GraphQL adoption increases
   - **Implementation:** New module `modules/graphql/`

4. **API Security Testing (BOLA/IDOR Advanced)** ⭐⭐⭐
   - **What it does:** Advanced IDOR/BOLA detection, HTTP verb tampering, mass assignment
   - **Impact:** Critical API vulnerabilities
   - **Implementation:** Enhance existing `modules/idor/` + new `modules/api_security/`

5. **Cloud Storage Enumeration** ⭐⭐
   - **What it does:** S3/Azure/GCP bucket discovery and misconfiguration detection
   - **Impact:** Exposed sensitive data, credentials leakage
   - **Implementation:** New module `modules/cloud_storage/`

6. **Session Management Testing** ⭐⭐
   - **What it does:** Session fixation, hijacking, timeout testing
   - **Impact:** Authentication bypass, account takeover
   - **Implementation:** New module `modules/session/`

7. **SSL/TLS Security Analysis** ⭐⭐
   - **What it does:** Certificate validation, weak ciphers, protocol version checks
   - **Impact:** Man-in-the-middle attacks, data interception
   - **Implementation:** New module `modules/ssl_tls/`

#### **MEDIUM PRIORITY - Reconnaissance Features:**

8. **Passive Reconnaissance Integration** ⭐⭐
   - **Shodan API Integration:** Find assets, open ports, vulnerabilities
   - **RapidDNS/Certsh:** Subdomain enumeration
   - **Wayback Machine:** Historical URL discovery
   - **Implementation:** New module `modules/passive_recon/`

9. **JavaScript Endpoint Extraction** ⭐
   - **What it does:** Deep JavaScript analysis for hidden endpoints/APIs
   - **Impact:** Discover hidden attack surface
   - **Implementation:** Enhance existing `core/url_parser.py` JS extraction

10. **Parameter Finder** ⭐
    - **What it does:** Identify vulnerable GET/POST parameters
    - **Impact:** Better target selection for fuzzing
    - **Implementation:** Enhance `core/url_parser.py`

#### **LOW PRIORITY - Already Covered or Less Critical:**

11. **Technology Fingerprinting**
    - **Status:** We already have basic tech detection in passive analysis
    - **Enhancement:** Add more detailed CMS/framework identification

12. **OS Fingerprinting**
    - **Status:** Low priority - not critical for web app testing
    - **Enhancement:** Can add to passive analysis if needed

---

## 🎯 Recommended Implementation Plan

### **Phase 1: High-Impact Security Features (2-3 weeks)**

**Week 1: Host Header Injection + HTTP Request Smuggling**
```
modules/host_header_injection/
├── __init__.py
├── scanner.py
├── payloads.txt (password reset poisoning, cache poisoning tests)
└── config.json

modules/http_smuggling/
├── __init__.py
├── scanner.py
├── payloads.txt (CL.TE, TE.CL, TE.TE variants)
└── config.json
```

**Week 2: GraphQL Security + Advanced API Testing**
```
modules/graphql/
├── __init__.py
├── scanner.py
├── queries.txt (introspection, mutations, batch queries)
└── config.json

modules/api_security/  (enhance existing IDOR)
├── __init__.py
├── scanner.py
├── payloads.txt (HTTP verbs, mass assignment, auth bypass)
└── config.json
```

**Week 3: Cloud Storage + Session Management**
```
modules/cloud_storage/
├── __init__.py
├── scanner.py
├── patterns.txt (S3, Azure, GCP bucket patterns)
└── config.json

modules/session/
├── __init__.py
├── scanner.py
├── tests.txt (fixation, hijacking, timeout tests)
└── config.json
```

### **Phase 2: Reconnaissance & Discovery (1-2 weeks)**

**Passive Recon Integration:**
```python
# modules/passive_recon/scanner.py
- Shodan API integration (optional, requires API key)
- Subdomain enumeration (RapidDNS, Certsh)
- Wayback URL discovery
- DNS reconnaissance
```

**Enhanced JavaScript Analysis:**
```python
# Enhance core/url_parser.py
- Better regex for API endpoint extraction
- JWT token detection
- API key/secret discovery in JS files
- Hidden parameter identification
```

### **Phase 3: SSL/TLS + Polish (1 week)**

**SSL/TLS Security:**
```
modules/ssl_tls/
├── __init__.py
├── scanner.py
├── checks.txt (weak ciphers, protocols, cert validation)
└── config.json
```

---

## 📝 Detailed Feature Specifications

### 1. Host Header Injection Module

**Vulnerability Types:**
- Password reset poisoning
- Web cache poisoning
- SSRF via Host header
- Virtual host confusion

**Test Payloads:**
```
evil.com
evil.com:@target.com
target.com@evil.com
127.0.0.1
localhost
0.0.0.0
[::1]
```

**Detection Method:**
1. Send requests with manipulated Host headers
2. Check if header is reflected in:
   - Password reset links
   - Redirects
   - Cached responses
3. Verify if internal/external resources are accessed

---

### 2. HTTP Request Smuggling Module

**Attack Variants:**
- **CL.TE:** Content-Length + Transfer-Encoding desync
- **TE.CL:** Transfer-Encoding + Content-Length desync
- **TE.TE:** Dual Transfer-Encoding confusion

**Test Methodology:**
```python
# CL.TE Example
POST / HTTP/1.1
Host: vulnerable.com
Content-Length: 6
Transfer-Encoding: chunked

0

GET /404 HTTP/1.1
Foo: x
```

**Detection:**
- Time-based detection (delayed responses)
- 404 errors on smuggled requests
- Response queue poisoning indicators

---

### 3. GraphQL Security Module

**Tests:**
```graphql
# Introspection query
{__schema{types{name,fields{name,type{name}}}}}

# Depth-based DoS
{user{posts{comments{author{posts{comments{...}}}}}}}

# Batch query exploitation
[
  {query: "{ user(id: 1) { email } }"},
  {query: "{ user(id: 2) { email } }"},
  ... (100 queries)
]

# Injection tests
{user(id: "1' OR '1'='1") {email}}
```

**Detection:**
- Introspection enabled
- No depth/complexity limits
- Batch query limits
- SQL/NoSQL injection in queries

---

### 4. API Security Module (Advanced IDOR/BOLA)

**HTTP Verb Tampering:**
```
GET /api/user/123 → 403 Forbidden
PUT /api/user/123 → 200 OK (should be 403)
DELETE /api/user/123 → 200 OK (should be 403)
PATCH /api/user/123 → 200 OK (should be 403)
```

**Mass Assignment:**
```json
POST /api/user
{
  "username": "attacker",
  "email": "attacker@evil.com",
  "role": "admin"  ← Mass assignment vulnerability
}
```

**Advanced BOLA:**
- UUID prediction/enumeration
- Wildcard injection (*/all)
- Parameter pollution
- Path traversal in API endpoints

---

### 5. Cloud Storage Enumeration Module

**S3 Bucket Patterns (25+):**
```
{company}-{keyword}
{keyword}-{company}
{company}.{keyword}
{company}-{env}
{company}-{env}-{region}
{keyword}.s3.amazonaws.com
s3.amazonaws.com/{keyword}

Keywords: backup, dev, prod, staging, public, private, assets,
          uploads, files, documents, images, data, logs, etc.
```

**Azure Storage:**
```
{company}.blob.core.windows.net
{keyword}.blob.core.windows.net
```

**GCP Storage:**
```
{keyword}.storage.googleapis.com
storage.googleapis.com/{bucket}
```

**Exposed File Detection (50+ extensions):**
```
.env, .git, .sql, .bak, credentials.json, config.json,
id_rsa, authorized_keys, .aws/, .docker/, etc.
```

---

### 6. Session Management Testing Module

**Tests:**

1. **Session Fixation:**
```
1. Get session ID before login
2. Login with credentials
3. Check if same session ID is valid after login
   → Vulnerable if session ID doesn't change
```

2. **Session Hijacking:**
```
1. Capture valid session
2. Test session from different IP/User-Agent
3. Check for IP/UA validation
```

3. **Session Timeout:**
```
1. Login and get session
2. Wait for timeout period
3. Check if session still valid after timeout
```

4. **Concurrent Sessions:**
```
1. Login from Browser A → Session 1
2. Login from Browser B → Session 2
3. Check if Session 1 is still valid
   → Vulnerable if both sessions active
```

---

### 7. SSL/TLS Security Module

**Checks:**

1. **Protocol Versions:**
```
SSLv2 - CRITICAL (disabled)
SSLv3 - HIGH (POODLE vulnerability)
TLS 1.0 - MEDIUM (deprecated)
TLS 1.1 - MEDIUM (deprecated)
TLS 1.2 - OK
TLS 1.3 - BEST
```

2. **Weak Ciphers:**
```
RC4 - CRITICAL
DES/3DES - HIGH
Export ciphers - CRITICAL
NULL ciphers - CRITICAL
Anonymous DH - CRITICAL
```

3. **Certificate Validation:**
```
- Expired certificate
- Self-signed certificate
- Hostname mismatch
- Weak signature algorithm (MD5, SHA1)
- Incomplete chain
```

---

## 🚀 Priority Matrix

| Feature | Impact | Effort | Priority | Timeline |
|---------|--------|--------|----------|----------|
| Host Header Injection | HIGH | LOW | ⭐⭐⭐ | Week 1 |
| HTTP Request Smuggling | HIGH | MEDIUM | ⭐⭐⭐ | Week 1 |
| GraphQL Security | HIGH | MEDIUM | ⭐⭐⭐ | Week 2 |
| Advanced API Testing | HIGH | LOW | ⭐⭐⭐ | Week 2 |
| Cloud Storage Enum | MEDIUM | LOW | ⭐⭐ | Week 3 |
| Session Testing | MEDIUM | LOW | ⭐⭐ | Week 3 |
| SSL/TLS Analysis | MEDIUM | MEDIUM | ⭐⭐ | Phase 3 |
| Passive Recon | MEDIUM | HIGH | ⭐ | Phase 2 |
| JS Endpoint Extraction | LOW | LOW | ⭐ | Phase 2 |

---

## 💡 Additional Enhancements Based on Gsec

### **Reporting Improvements:**

1. **Severity-based Auto-categorization**
   - Critical: RCE, Authentication Bypass, SQL Injection
   - High: XSS, SSRF, Arbitrary File Upload
   - Medium: CSRF, Information Disclosure
   - Low: Missing Security Headers

2. **Nuclei Integration (Optional)**
   - Run Nuclei templates after our scans
   - Combine results into unified report
   - Requires: `nuclei` CLI tool installed

3. **Scan Profiles:**
   ```
   --profile quick    → Top 10 OWASP only
   --profile standard → All active modules
   --profile full     → Active + Passive + Nuclei
   --profile api      → API-specific tests only
   --profile cloud    → Cloud security tests
   ```

---

## 📊 Comparison Matrix: Dominator vs Gsec

| Category | Dominator | Gsec | Winner |
|----------|-----------|------|--------|
| **Core Vulnerabilities** |
| SQL Injection | ✅ Advanced (3 techniques) | ✅ Basic | 🏆 Dominator |
| XSS | ✅ 43 payloads | ✅ Basic | 🏆 Dominator |
| SSRF | ✅ OOB detection | ✅ Basic | 🏆 Dominator |
| LFI/Path Traversal | ✅ 61 payloads | ✅ Basic | 🏆 Dominator |
| CMDi | ✅ Time-based detection | ❌ Not mentioned | 🏆 Dominator |
| CSRF | ✅ 12 token patterns | ✅ Basic | 🟰 Tie |
| SSTI | ✅ Advanced payloads | ❌ Not mentioned | 🏆 Dominator |
| XXE | ✅ 10 payloads | ❌ Not mentioned | 🏆 Dominator |
| XPath Injection | ✅ 18 payloads | ❌ Not mentioned | 🏆 Dominator |
| **Advanced Features** |
| Host Header Injection | ❌ **Missing** | ✅ | 🏆 Gsec |
| HTTP Request Smuggling | ❌ **Missing** | ✅ | 🏆 Gsec |
| GraphQL Testing | ❌ **Missing** | ✅ | 🏆 Gsec |
| Cloud Storage Enum | ❌ **Missing** | ✅ S3/Azure/GCP | 🏆 Gsec |
| Session Management | ❌ **Missing** | ✅ | 🏆 Gsec |
| SSL/TLS Analysis | ❌ **Missing** | ✅ | 🏆 Gsec |
| **Reconnaissance** |
| Passive Recon | ❌ Limited | ✅ Shodan/DNS/Certsh | 🏆 Gsec |
| Subdomain Enum | ❌ | ✅ | 🏆 Gsec |
| Wayback URLs | ❌ | ✅ | 🏆 Gsec |
| JS Endpoint Discovery | ⚠️ Basic | ✅ Advanced | 🏆 Gsec |
| **Scanning Features** |
| Multi-threading | ✅ 36 threads | ❓ Unknown | 🏆 Dominator |
| Browser Integration | ✅ Chromium/Firefox | ❌ | 🏆 Dominator |
| Proxy Interception | ✅ HTTPS proxy | ❌ | 🏆 Dominator |
| Form Detection | ✅ Advanced | ❓ Unknown | 🏆 Dominator |
| OOB Detection | ✅ Built-in | ❌ | 🏆 Dominator |
| **Reporting** |
| HTML Reports | ✅ Advanced | ✅ Basic | 🏆 Dominator |
| Live Reports | ✅ **NEW!** | ❌ | 🏆 Dominator |
| JSON/XML Export | ✅ | ✅ | 🟰 Tie |
| **Integration** |
| Nuclei Integration | ❌ | ✅ | 🏆 Gsec |
| GUI | ✅ Full GUI | ❌ | 🏆 Dominator |
| CLI | ✅ | ✅ | 🟰 Tie |

---

## 🎯 Final Recommendations

### **Immediate Actions (This Week):**

1. ✅ Implement **Live HTML Report** (Done!)
2. ⭐ Add **Host Header Injection** module
3. ⭐ Add **HTTP Request Smuggling** module

### **Short Term (Next 2-3 Weeks):**

4. ⭐ Add **GraphQL Security** module
5. ⭐ Enhance IDOR → **Advanced API Security** module
6. Add **Cloud Storage Enumeration** module
7. Add **Session Management Testing** module

### **Medium Term (1-2 Months):**

8. Add **SSL/TLS Security** module
9. Implement **Passive Reconnaissance** integration
10. Enhance JavaScript endpoint extraction
11. Optional: **Nuclei Integration** wrapper

### **Features to Skip:**

- ❌ OS Fingerprinting (low value for web app testing)
- ❌ Technology fingerprinting beyond what we have (already covered)

---

## 🚀 After Implementation: Dominator Will Be

**Current State:** Already better than Gsec in core vulnerability detection

**After Implementation:** **Best-in-class web security scanner** with:
- ✅ Superior vulnerability detection (19+ modules vs Gsec's ~10)
- ✅ Advanced features (GraphQL, API security, HTTP smuggling)
- ✅ Modern UI (GUI + Live HTML reports)
- ✅ Browser integration (unique to Dominator)
- ✅ Better performance (36 threads, optimized scanning)
- ✅ More comprehensive coverage (100+ vulnerabilities vs Gsec's ~50)

---

## 📚 Resources & References

**Gsec Repository:** https://github.com/gotr00t0day/Gsec

**Implementation References:**
- Host Header Injection: https://portswigger.net/web-security/host-header
- HTTP Request Smuggling: https://portswigger.net/web-security/request-smuggling
- GraphQL Security: https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html
- API Security: https://owasp.org/www-project-api-security/
- Cloud Storage: https://github.com/initstring/cloud_enum

---

**Summary:** Gsec is a good scanner, but **Dominator is already superior in core vulnerability detection**. By adding the 7-10 missing advanced features from Gsec, Dominator will become the **most comprehensive web security scanner** available.

**Estimated Total Implementation Time:** 4-6 weeks for all high-priority features
