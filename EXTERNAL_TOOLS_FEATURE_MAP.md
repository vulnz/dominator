# External Tools Feature Map

This document shows which features were analyzed from external security tools and implemented in Dominator.

## Feature Mapping Table

| External Tool | Feature | Implemented | Dominator Module | Notes |
|--------------|---------|-------------|------------------|-------|
| **Nmap** | Port scanning | ✅ Yes | `port_scan` | TCP connect scan on common ports |
| **Nmap** | Service detection | ✅ Yes | `port_scan` | Banner grabbing + service identification |
| **Nmap** | Banner grabbing | ✅ Yes | `port_scan` | HTTP/generic banner capture |
| **Nmap** | OS fingerprinting | ❌ No | - | Out of scope for web scanner |
| **Nmap** | Script engine (NSE) | ❌ No | - | Too complex, use dedicated modules |
| **Nmap** | UDP scanning | ❌ No | - | Focus on TCP web services |
| | | | | |
| **Nikto** | HTTP method testing | ✅ Yes | `http_methods` | PUT, DELETE, TRACE, WebDAV |
| **Nikto** | Backup file discovery | ✅ Yes | `backup_files` | .bak, .old, .sql, .git, etc. |
| **Nikto** | Server header analysis | ✅ Yes | `security_headers` | Version disclosure detection |
| **Nikto** | Default file checks | ✅ Yes | `backup_files` | phpinfo.php, web.config, etc. |
| **Nikto** | CGI vulnerability checks | ❌ No | - | Legacy, low priority |
| **Nikto** | Outdated software checks | ⚠️ Partial | `security_headers` | Server version in headers only |
| | | | | |
| **Wapiti** | XSS detection | ✅ Yes | `xss` | Reflection + DOM analysis |
| **Wapiti** | SQL injection | ✅ Yes | `sqli` | Error-based + blind + time-based |
| **Wapiti** | LFI/RFI | ✅ Yes | `lfi`, `rfi` | Path traversal + remote include |
| **Wapiti** | Command injection | ✅ Yes | `cmdi` | OS command injection |
| **Wapiti** | XXE injection | ✅ Yes | `xxe` | XML external entity |
| **Wapiti** | SSRF | ✅ Yes | `ssrf` | Server-side request forgery |
| **Wapiti** | CRLF injection | ✅ Yes | `redirect` | Header injection |
| **Wapiti** | Open redirect | ✅ Yes | `redirect` | URL redirect validation |
| **Wapiti** | Backup file detection | ✅ Yes | `backup_files` | Same as Nikto feature |
| **Wapiti** | Crawler integration | ✅ Yes | `core/crawler.py` | Form + link extraction |
| | | | | |
| **SSLScan** | SSL/TLS version check | ✅ Yes | `ssl_tls` | TLS 1.0/1.1/1.2/1.3 detection |
| **SSLScan** | Weak cipher detection | ✅ Yes | `ssl_tls` | RC4, DES, NULL ciphers |
| **SSLScan** | Certificate analysis | ✅ Yes | `ssl_tls` | Expiry, self-signed detection |
| **SSLScan** | BEAST/CRIME/POODLE | ⚠️ Partial | `ssl_tls` | Protocol-level only |
| **SSLScan** | Heartbleed check | ❌ No | - | Requires specialized probe |
| | | | | |
| **SSLyze** | Certificate chain validation | ✅ Yes | `ssl_tls` | Basic chain analysis |
| **SSLyze** | HSTS detection | ✅ Yes | `security_headers` | Header presence + max-age |
| **SSLyze** | Certificate expiration | ✅ Yes | `ssl_tls` | 30-day warning threshold |
| **SSLyze** | Self-signed detection | ✅ Yes | `ssl_tls` | Issuer == Subject check |
| **SSLyze** | Compression check | ❌ No | - | Low priority |
| **SSLyze** | Session resumption | ❌ No | - | Low priority |
| | | | | |
| **DrHeader** | CSP analysis | ✅ Yes | `security_headers` | Missing/weak CSP detection |
| **DrHeader** | HSTS analysis | ✅ Yes | `security_headers` | Missing/weak HSTS detection |
| **DrHeader** | X-Frame-Options | ✅ Yes | `security_headers` | Clickjacking protection |
| **DrHeader** | X-Content-Type-Options | ✅ Yes | `security_headers` | MIME sniffing protection |
| **DrHeader** | X-XSS-Protection | ✅ Yes | `security_headers` | Legacy XSS filter header |
| **DrHeader** | Referrer-Policy | ✅ Yes | `security_headers` | Referrer leakage prevention |
| **DrHeader** | Permissions-Policy | ✅ Yes | `security_headers` | Feature policy detection |
| **DrHeader** | Server disclosure | ✅ Yes | `security_headers` | Version info in headers |
| | | | | |
| **Amass** | DNS brute force | ✅ Yes | `subdomain` | Common subdomain wordlist |
| **Amass** | Certificate Transparency | ✅ Yes | `subdomain` | crt.sh API integration |
| **Amass** | DNS resolution | ✅ Yes | `subdomain` | A record validation |
| **Amass** | Passive reconnaissance | ✅ Yes | `subdomain` | CT logs (no active probing) |
| **Amass** | ASN enumeration | ❌ No | - | Out of scope |
| **Amass** | WHOIS lookup | ❌ No | - | Out of scope |
| | | | | |
| **Nuclei** | Template-based scanning | ⚠️ Similar | Module system | Modular vulnerability checks |
| **Nuclei** | CVE detection | ❌ No | - | Requires template library |
| **Nuclei** | Tech detection | ⚠️ Partial | `js_analysis` | Framework debug detection |
| **Nuclei** | Exposed panels | ⚠️ Partial | `backup_files` | Admin pages in wordlist |
| | | | | |
| **Masscan** | Fast port scanning | ⚠️ Partial | `port_scan` | Multi-threaded (50 workers) |
| **Masscan** | SYN scanning | ❌ No | - | Requires raw sockets |
| **Masscan** | Rate limiting | ❌ No | - | Not implemented |
| | | | | |
| **WFuzz** | Parameter fuzzing | ✅ Yes | All vuln modules | Injection point testing |
| **WFuzz** | Wordlist support | ✅ Yes | `dirbrute`, modules | Payload files |
| **WFuzz** | Response filtering | ✅ Yes | Core scanner | Status/size filtering |
| | | | | |
| **WPScan** | WordPress detection | ❌ No | - | CMS-specific, out of scope |
| **WPScan** | Plugin enumeration | ❌ No | - | CMS-specific, out of scope |
| | | | | |
| **OpenVAS** | Network vuln scanning | ❌ No | - | Network-level, out of scope |

## New Modules Created (Based on External Tools)

| Module | Based On | Category | Key Features |
|--------|----------|----------|--------------|
| `security_headers` | DrHeader | Passive | 8 security headers, dangerous header detection |
| `http_methods` | Nikto | Active | 8 HTTP methods, WebDAV detection |
| `backup_files` | Nikto, Wapiti | Active | 40+ sensitive file patterns |
| `subdomain` | Amass | Recon | DNS brute + CT logs, 50 common subdomains |
| `port_scan` | Nmap | Recon | 30+ ports, banner grabbing, service ID |
| `js_analysis` | Custom | Passive | 25+ secret patterns, debug mode detection |
| `ssl_tls` (enhanced) | SSLScan, SSLyze | Active | TLS versions, ciphers, cert analysis |

## Feature Categories Summary

### Fully Implemented ✅
- Port scanning with service detection (Nmap-style)
- HTTP security headers analysis (DrHeader-style)
- Dangerous HTTP methods (Nikto-style)
- Backup/sensitive file discovery (Nikto/Wapiti-style)
- Subdomain enumeration (Amass-style)
- SSL/TLS analysis (SSLScan/SSLyze-style)
- JavaScript secrets detection (SecretFinder-style)
- All OWASP Top 10 web vulnerabilities

### Partially Implemented ⚠️
- Advanced SSL attacks (BEAST, CRIME) - protocol detection only
- CVE-specific checks (Nuclei-style) - no template library
- Tech stack fingerprinting - framework debug detection only

### Not Implemented ❌
- Network-level scanning (OpenVAS)
- CMS-specific scanning (WPScan)
- Raw packet scanning (Masscan SYN)
- OS fingerprinting (Nmap)
- ASN/WHOIS enumeration (Amass)

## Secret Patterns in js_analysis (SecretFinder-style)

| Pattern Type | Regex Source | Risk Level |
|-------------|--------------|------------|
| AWS Access Key | `AKIA[0-9A-Z]{16}` | High |
| AWS Secret Key | `[A-Za-z0-9/+=]{40}` | High |
| Google API Key | `AIza[0-9A-Za-z\-_]{35}` | Medium |
| Slack Token | `xox[baprs]-...` | High |
| GitHub Token | `gh[pousr]_...` | High |
| Stripe API Key | `sk_live_...` | High |
| JWT Token | `eyJ...` | Medium |
| Private Key | `-----BEGIN...PRIVATE KEY-----` | Critical |
| S3 Bucket | `*.s3.amazonaws.com` | Medium |
| Firebase | `*.firebaseio.com` | Medium |
| MongoDB URI | `mongodb://...` | High |
| Internal IP | `10.x.x.x`, `192.168.x.x` | Low |

## Debug Mode Detection (js_analysis)

| Framework | Indicators |
|-----------|------------|
| React | `__REACT_DEVTOOLS_GLOBAL_HOOK__`, `__REDUX_DEVTOOLS_EXTENSION__` |
| Vue.js | `__VUE_DEVTOOLS_GLOBAL_HOOK__`, `Vue.config.devtools` |
| Angular | `ng.probe`, `angular.reloadWithDebugInfo` |
| Webpack | `webpack-dev-server`, `hot-update.json` |
| Source Maps | `//# sourceMappingURL=`, `.map` files |

## Port Scan Coverage (Nmap-style)

| Category | Ports |
|----------|-------|
| Web | 80, 443, 8080, 8443, 8000, 8888, 3000, 5000 |
| Database | 3306 (MySQL), 5432 (PostgreSQL), 27017 (MongoDB), 6379 (Redis) |
| Mail | 25, 465, 587, 110, 995, 143, 993 |
| Remote | 21 (FTP), 22 (SSH), 23 (Telnet), 3389 (RDP), 5900 (VNC) |
| Other | 53 (DNS), 389 (LDAP), 445 (SMB), 139 (NetBIOS) |

---

*Document generated: 2025-11-22*
*Total modules: 33 (6 new from external tool analysis)*
