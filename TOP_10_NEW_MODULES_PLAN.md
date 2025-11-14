# TOP 10 New Modules to Add - ROTATION 10

## Overview

These 10 new modules fill critical gaps in vulnerability coverage and align with OWASP Top 10 2021, modern attack vectors, and real-world pentesting needs.

**Current Modules**: 20
**Planned New Modules**: 10
**Total After Implementation**: 30 modules

---

## Module Selection Criteria

1. **OWASP Top 10 2021 Coverage** - Address missing OWASP categories
2. **Real-World Impact** - High-severity vulnerabilities found in production
3. **Modern Attack Vectors** - Cloud, API, GraphQL, JWT
4. **Acunetix Gap Analysis** - Vulnerabilities we're currently missing
5. **Low False Positive Rate** - Reliable detection methods

---

## TOP 10 New Modules

### 1. **CORS Misconfiguration** (HIGH Priority)
**OWASP**: A05:2021 - Security Misconfiguration
**Severity**: HIGH
**Why**: Extremely common in modern APIs, allows data theft

**Detection Method**:
- Send requests with various `Origin` headers
- Check if `Access-Control-Allow-Origin` reflects attacker origin
- Check for `Access-Control-Allow-Credentials: true`
- Wildcard (`*`) with credentials is critical

**Payloads**:
```
Origin: https://evil.com
Origin: null
Origin: http://localhost
Origin: file://
```

**Indicators**:
- Response: `Access-Control-Allow-Origin: https://evil.com`
- Response: `Access-Control-Allow-Credentials: true`

**File Structure**:
```
modules/cors/
├── module.py
├── config.json
├── payloads.txt (origin values)
```

**Priority**: 🔥 CRITICAL (very common, high impact)

---

### 2. **JWT Security Issues** (HIGH Priority)
**OWASP**: A02:2021 - Cryptographic Failures / A07:2021 - Identification Failures
**Severity**: CRITICAL
**Why**: JWT vulnerabilities are rampant in modern APIs

**Detection Method**:
- Extract JWT from headers/cookies/local storage
- Test "alg": "none" attack
- Test weak secret brute force (common secrets)
- Test key confusion (RS256 → HS256)
- Test expired token acceptance
- Test signature tampering

**Payloads**:
```python
# Algorithm confusion
{"alg": "none"}
{"alg": "HS256"}  # when RS256 expected

# Weak secrets to brute force
["secret", "123456", "password", "jwt_secret", "key"]

# Claim manipulation
{"admin": true, "role": "admin", "isAdmin": 1}
```

**Indicators**:
- Token with `alg: none` accepted
- Weak secret cracked
- Modified claims accepted

**File Structure**:
```
modules/jwt/
├── module.py
├── config.json
├── weak_secrets.txt
├── payloads.txt
```

**Priority**: 🔥 CRITICAL (common in APIs, critical impact)

---

### 3. **GraphQL Security** (MEDIUM-HIGH Priority)
**OWASP**: A01:2021 - Broken Access Control / A03:2021 - Injection
**Severity**: HIGH
**Why**: GraphQL adoption is exploding, many misconfigurations

**Detection Method**:
- Detect GraphQL endpoints (`/graphql`, `/api/graphql`, `/__graphql`)
- Test introspection query (schema disclosure)
- Test field suggestion (typo in field name)
- Test batching attacks (DoS)
- Test depth limit bypass (nested queries)
- Test authorization bypass (access hidden fields)

**Payloads**:
```graphql
# Introspection
{__schema{types{name,fields{name,type{name}}}}}

# Field suggestion
{user{idd}}  # Suggests: "Did you mean 'id'?"

# Batching attack
[{"query":"..."}, {"query":"..."}, ...]  # 100+ queries

# Nested query (depth attack)
{user{posts{comments{user{posts{comments{...}}}}}}}

# Authorization bypass
{users{id,email,password,ssn,creditCard}}
```

**Indicators**:
- Introspection enabled (schema leak)
- Field suggestions reveal hidden fields
- Batch queries accepted (DoS vector)
- Unauthorized fields accessible

**File Structure**:
```
modules/graphql/
├── module.py
├── config.json
├── payloads.txt (introspection, mutations)
```

**Priority**: 🔥 HIGH (modern API attack surface)

---

### 4. **HTTP Request Smuggling** (MEDIUM Priority)
**OWASP**: A03:2021 - Injection
**Severity**: CRITICAL
**Why**: Complex but devastating, bypasses WAF/firewalls

**Detection Method**:
- Test CL.TE (Content-Length vs Transfer-Encoding)
- Test TE.CL (Transfer-Encoding vs Content-Length)
- Test TE.TE (dual Transfer-Encoding)
- Detect desync via timing/response differences

**Payloads**:
```http
# CL.TE
Content-Length: 13
Transfer-Encoding: chunked

0

SMUGGLED

# TE.CL
Transfer-Encoding: chunked
Content-Length: 3

8
SMUGGLED
0
```

**Indicators**:
- Response timing differences
- 500 errors from smuggled request
- Unexpected response content

**File Structure**:
```
modules/http_smuggling/
├── module.py
├── config.json
├── payloads.txt
```

**Priority**: ⚠️ MEDIUM (complex, requires specific server configs)

---

### 5. **Race Condition / TOCTOU** (MEDIUM-HIGH Priority)
**OWASP**: A01:2021 - Broken Access Control
**Severity**: HIGH
**Why**: Common in payment, discount, voucher, and limit-based systems

**Detection Method**:
- Send simultaneous requests (10-50 concurrent)
- Test discount codes (apply same code multiple times)
- Test vouchers (redeem same voucher multiple times)
- Test rate limits (bypass via race condition)
- Test account creation (same email/username)

**Payloads**:
```python
# Same request sent 20 times concurrently
POST /api/apply-discount
discount_code=SAVE50

# Expected: Applied once
# Actual (vulnerable): Applied 20 times
```

**Indicators**:
- Same voucher/discount applied multiple times
- Rate limit bypassed
- Duplicate account creation

**File Structure**:
```
modules/race_condition/
├── module.py
├── config.json
```

**Priority**: 🔥 HIGH (common in e-commerce, high business impact)

---

### 6. **NoSQL Injection** (HIGH Priority)
**OWASP**: A03:2021 - Injection
**Severity**: CRITICAL
**Why**: MongoDB, Redis, CouchDB are everywhere, often vulnerable

**Detection Method**:
- Test MongoDB operators: `$ne`, `$gt`, `$regex`, `$where`
- Test authentication bypass: `{"$ne": null}`
- Test data extraction
- Test JavaScript injection in `$where`

**Payloads**:
```json
# Authentication bypass
{"username": {"$ne": null}, "password": {"$ne": null}}
{"username": {"$regex": ".*"}, "password": {"$regex": ".*"}}

# Data extraction
{"username": {"$gt": ""}}

# JavaScript injection (MongoDB)
{"$where": "this.password.length > 0"}
{"$where": "sleep(5000)"}  # Time-based blind
```

**Indicators**:
- Authentication bypass (logged in without credentials)
- Error messages mentioning MongoDB/NoSQL
- Time delays from `sleep()` injection
- Data leakage

**File Structure**:
```
modules/nosql_injection/
├── module.py
├── config.json
├── payloads.txt
```

**Priority**: 🔥 CRITICAL (very common, high impact)

---

### 7. **API Rate Limit Bypass** (MEDIUM Priority)
**OWASP**: A04:2021 - Insecure Design
**Severity**: MEDIUM-HIGH
**Why**: Enables brute force, scraping, DoS

**Detection Method**:
- Detect rate limit response (429, 403, specific message)
- Test IP-based bypass (X-Forwarded-For, X-Real-IP, etc.)
- Test case sensitivity (`/api/login` vs `/Api/Login`)
- Test trailing slash (`/api/login` vs `/api/login/`)
- Test HTTP method change (GET vs POST)
- Test null byte injection in path

**Payloads**:
```http
# Header injection
X-Forwarded-For: 127.0.0.1
X-Real-IP: 127.0.0.1
X-Originating-IP: 127.0.0.1
X-Client-IP: 127.0.0.1

# Path manipulation
/Api/login (case change)
/api/login/ (trailing slash)
/api/login%00 (null byte)

# Method change
GET /api/login (instead of POST)
```

**Indicators**:
- Rate limit bypassed with modified headers
- 200 OK instead of 429 after manipulation

**File Structure**:
```
modules/rate_limit_bypass/
├── module.py
├── config.json
├── payloads.txt (header values)
```

**Priority**: ⚠️ MEDIUM-HIGH (enables other attacks)

---

### 8. **Mass Assignment / Parameter Pollution** (HIGH Priority)
**OWASP**: A01:2021 - Broken Access Control
**Severity**: HIGH
**Why**: Common in Rails, Express, Django - leads to privilege escalation

**Detection Method**:
- Add suspicious parameters to requests
- Test: `isAdmin`, `admin`, `role`, `verified`, `credits`, `balance`
- Monitor response for parameter acceptance
- Test blind mass assignment (changes persist)

**Payloads**:
```json
# Privilege escalation
{"username": "test", "password": "test", "isAdmin": true}
{"username": "test", "password": "test", "role": "admin"}
{"username": "test", "password": "test", "admin": 1}

# Account manipulation
{"credits": 99999}
{"balance": 99999}
{"verified": true}
{"premium": true}
```

**Indicators**:
- Parameter accepted (visible in response)
- Privilege escalation successful
- Account values modified

**File Structure**:
```
modules/mass_assignment/
├── module.py
├── config.json
├── payloads.txt (parameter names)
```

**Priority**: 🔥 HIGH (common in modern frameworks)

---

### 9. **OAuth / OpenID Connect Flaws** (MEDIUM Priority)
**OWASP**: A07:2021 - Identification and Authentication Failures
**Severity**: CRITICAL
**Why**: OAuth misconfigurations lead to account takeover

**Detection Method**:
- Test redirect_uri validation (open redirect)
- Test state parameter (CSRF in OAuth flow)
- Test code reuse (authorization code replay)
- Test implicit flow issues
- Test scope escalation

**Payloads**:
```
# Open redirect in redirect_uri
redirect_uri=https://evil.com
redirect_uri=https://legitimate.com.evil.com
redirect_uri=https://legitimate.com@evil.com

# Missing state parameter (CSRF)
# Remove 'state' parameter from OAuth flow

# Scope escalation
scope=read,write,admin
```

**Indicators**:
- redirect_uri accepted with attacker domain
- State parameter not validated (CSRF possible)
- Excessive scopes granted

**File Structure**:
```
modules/oauth_flaws/
├── module.py
├── config.json
├── payloads.txt
```

**Priority**: ⚠️ MEDIUM (requires OAuth flow, high impact when present)

---

### 10. **Server-Side Prototype Pollution** (MEDIUM Priority)
**OWASP**: A03:2021 - Injection
**Severity**: HIGH
**Why**: Node.js/JavaScript backends are common, leads to RCE

**Detection Method**:
- Test `__proto__` pollution in JSON/query params
- Test `constructor.prototype` pollution
- Monitor for polluted properties in response
- Test for RCE via polluted properties

**Payloads**:
```json
# Prototype pollution
{"__proto__": {"isAdmin": true}}
{"constructor": {"prototype": {"isAdmin": true}}}

# Query parameter pollution
?__proto__[isAdmin]=true
?constructor[prototype][isAdmin]=true

# Nested pollution
{"user": {"__proto__": {"role": "admin"}}}
```

**Indicators**:
- Polluted property visible in response
- Unexpected behavior (privilege escalation)
- Server error revealing pollution

**File Structure**:
```
modules/prototype_pollution/
├── module.py
├── config.json
├── payloads.txt
```

**Priority**: ⚠️ MEDIUM-HIGH (Node.js specific, high impact)

---

## Implementation Priority Order

### Tier 1 - CRITICAL (Implement First)
1. **CORS Misconfiguration** - Ubiquitous in APIs
2. **JWT Security Issues** - Critical for modern auth
3. **NoSQL Injection** - MongoDB is everywhere
4. **Mass Assignment** - Common in frameworks

### Tier 2 - HIGH (Implement Second)
5. **GraphQL Security** - Growing attack surface
6. **Race Condition** - High business impact
7. **API Rate Limit Bypass** - Enables other attacks

### Tier 3 - MEDIUM (Implement Third)
8. **OAuth Flaws** - Complex but critical
9. **Prototype Pollution** - Node.js specific
10. **HTTP Request Smuggling** - Advanced technique

---

## Module Statistics After Implementation

| Category | Current | After +10 | Coverage |
|----------|---------|-----------|----------|
| Injection | 8 | 11 | ✅ Excellent |
| Broken Access Control | 2 | 5 | ✅ Good |
| Cryptographic Failures | 1 | 2 | ✅ Good |
| Security Misconfiguration | 3 | 4 | ✅ Good |
| Identification Failures | 2 | 4 | ✅ Good |
| **Total Modules** | **20** | **30** | **+50%** |

---

## Expected Detection Improvements

### Current Acunetix Coverage: ~42% (24/58 vulns)
### After TOP 10 Modules: ~70% (41/58 vulns)

**New Detections**:
- +3 CORS misconfigurations (HIGH)
- +5 JWT vulnerabilities (CRITICAL)
- +2 GraphQL issues (HIGH)
- +4 NoSQL injection (CRITICAL)
- +2 Mass assignment (HIGH)
- +1 OAuth flaw (CRITICAL)

**Total**: +17 new vulnerability detections across 10 modules

---

## Technical Implementation Notes

### Shared Components
- **OOB Detection**: Use existing OOBDetector for blind NoSQL, prototype pollution
- **Race Condition**: New concurrency utility needed
- **JWT**: New crypto utility for JWT parsing/signing

### False Positive Mitigation
- **CORS**: Confirm credentials + reflected origin
- **JWT**: Verify actual access change, not just token acceptance
- **GraphQL**: Confirm introspection enabled, not just endpoint detection
- **Mass Assignment**: Verify parameter actually affected backend

### Integration Points
- All modules inherit from `BaseModule`
- Use existing `http_client` for requests
- Integrate with passive scanner for response analysis
- Use progress bar utility for long-running tests

---

## File Structure Example

```
modules/
├── cors/
│   ├── module.py          # CORS detection logic
│   ├── config.json        # Severity: high, enabled: true
│   └── payloads.txt       # Origin values to test
├── jwt/
│   ├── module.py          # JWT vulnerability scanner
│   ├── config.json
│   ├── weak_secrets.txt   # Common JWT secrets
│   └── payloads.txt       # Algorithm confusion, claim tampering
├── graphql/
│   ├── module.py          # GraphQL security scanner
│   ├── config.json
│   └── payloads.txt       # Introspection, mutations, batching
... (7 more modules)
```

---

## Next Steps

1. **Create module templates** for all 10 modules
2. **Implement Tier 1 modules** (CORS, JWT, NoSQL, Mass Assignment)
3. **Test against known vulnerable apps**
4. **Implement Tier 2 modules** (GraphQL, Race Condition, Rate Limit)
5. **Implement Tier 3 modules** (OAuth, Prototype Pollution, HTTP Smuggling)
6. **Update README** with new module list
7. **Create ROTATION 10 summary**

---

**Estimated Implementation Time**:
- Tier 1: 1-2 days
- Tier 2: 1 day
- Tier 3: 1 day
- **Total**: 3-4 days for all 10 modules

**Expected Result**:
- 30 total modules
- 70% Acunetix coverage
- Industry-leading open-source vulnerability scanner
