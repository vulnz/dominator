# Dominator Web Vulnerability Scanner

🔥 **Advanced web vulnerability scanner** with 17+ detection modules, intelligent passive scanning, and OOB (Out-of-Band) detection capabilities.

[![GitHub stars](https://img.shields.io/github/stars/yourusername/dominator?style=social)](https://github.com/yourusername/dominator)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/)

---

## 🚀 Key Features

### ✅ **17 Active Vulnerability Scanners**
- **XSS** - Cross-Site Scripting (Reflected, Stored, DOM-based)
- **SQLi** - SQL Injection (Error-based + Time-based Blind)
- **LFI** - Local File Inclusion
- **RFI** - Remote File Inclusion
- **CSRF** - Cross-Site Request Forgery
- **IDOR** - Insecure Direct Object Reference
- **SSRF** - Server-Side Request Forgery
- **SSTI** - Server-Side Template Injection
- **XXE** - XML External Entity
- **XPath Injection**
- **PHP Object Injection**
- **Command Injection**
- **Open Redirect**
- **File Upload** vulnerabilities
- **Weak Credentials** testing
- **DirBrute** - Directory and File Bruteforce
- **Git** - Git Repository Exposure

### 🎯 **Intelligent Passive Scanning (8 Detectors)**
Automatically analyzes HTTP responses during crawling AND payload testing:
- **Sensitive Data** - API keys, passwords, tokens (60+ patterns)
- **Private Keys** - RSA, SSH, PGP, EC, DSA, JWT, Slack tokens
- **Path Disclosure** - File paths in error messages (4 pattern types)
- **Database Errors** - MySQL, PostgreSQL, MSSQL, Oracle (8 DB types)
- **Security Headers** - Missing CSP, HSTS, X-Frame-Options
- **Debug Information** - Stack traces, verbose errors
- **Backup Files** - .bak, .old, .backup exposures
- **API Endpoints** - Exposed REST/GraphQL/Swagger APIs
- **Technology Detection** - Framework/server fingerprinting
- **Version Disclosure** - Software version leaks
- **JS Secrets** - Hardcoded secrets in JavaScript

### 🌐 **Out-of-Band (OOB) Detection**
Dual OOB infrastructure for detecting **blind vulnerabilities**:
- **Pipedream.com** integration (primary)
- **Requestbin.cn** fallback
- Detects: Blind SSRF, Blind SQLi, Blind SSTI, Blind XXE
- Automatic callback verification

### 🔍 **Advanced Detection Features**
- **POST Form Coverage** - Tests ALL POST forms, not just keyword-based
- **Payload Response Analysis** - Passive scanning runs on EVERY payload response
- **3-Stage Validation** - Reduces false positives (SSTI, XSS, SQLi)
- **CDN Whitelisting** - Skips Google Tag Manager, CDN scripts (DOM XSS)
- **Context-Aware Detection** - Checks 150-char context for secrets/keys
- **Git Deduplication** - Smart signature-based duplicate removal
- **Extended IDOR Parameters** - 25+ ID parameter patterns (id, aid, pid, cid, etc.)
- **Blind SQLi** - Time-based detection with baseline comparison

### 📊 **Professional Reporting**
- **HTML** - Interactive reports with collapsible findings, severity filters
- **JSON** - Structured data for CI/CD integration
- **XML** - Standard XML format
- **TXT** - Plain text reports
- **Multi-Target Scanning** - Consolidated reports for multiple targets

---

## 📖 Usage

### Quick Start
```bash
# Basic scan
python main.py -t example.com

# Full scan with HTML report
python main.py -t example.com --all --auto-report --format html -v

# Specific modules
python main.py -t example.com -m xss,sqli,csrf,idor

# Multi-threaded scanning
python main.py -t example.com --threads 20 --timeout 15 -v
```

### Advanced Examples
```bash
# Test specific modules with detailed output
python main.py -t 127.0.0.1/xvwa/ -m sqli,xss,csrf --auto-report --format html -v

# Directory bruteforce with extended wordlist
python main.py -t example.com -m dirbrute --threads 30 --timeout 20

# Environment file detection
python main.py -t example.com -m env_secrets --threads 10

# Git exposure scanning
python main.py -t example.com -m git --auto-report
```

### Parameters

| Parameter | Description | Default |
|-----------|-------------|---------|
| `-t, --target` | Target URL to scan | *Required* |
| `-m, --modules` | Modules to use (comma-separated) | All enabled |
| `--all` | Use all available modules | False |
| `--threads` | Number of concurrent threads | 10 |
| `--timeout` | HTTP request timeout (seconds) | 10 |
| `--auto-report` | Auto-generate report after scan | False |
| `--format` | Report format (txt/html/json/xml) | txt |
| `-v, --verbose` | Verbose output | False |
| `--depth` | Crawling depth | 2 |
| `--max-urls` | Maximum URLs to crawl | 100 |

---

## 📋 Rotation 7 Improvements

This release includes **comprehensive ROTATION 7 improvements** based on deep analysis:

### ✅ False Positive Elimination
- **Formula Injection** - Disabled (too many FPs, needs rewrite)
- **DOM XSS** - CDN whitelist (Google Tag Manager, jsdelivr, cdnjs, etc.)
- **SSTI** - 3-stage validation (reflection check, context validation, pattern detection)

### ✅ Missing Detection Fixes
- **Stored XSS** - Now tests ALL POST forms (removed keyword filtering)
- **IDOR** - Extended parameters: aid, pid, cid, gid, tid, sid, rid, vid, eid
- **Blind SQLi** - Added GET support to time-based detection
- **Path Disclosure** - Detects file paths in error messages (Linux/Windows/stack traces)
- **Database Errors** - Passive detection during payload testing (8 DB types)
- **Directory Listing** - Fixed List/Dict bug, now properly reports findings

### 🔥 Critical New Features
- **Payload Response Analysis** - Passive scanner now runs on ALL payload responses, not just crawling
  - Integrated into 5 modules: SQLi, XSS, LFI, SSTI, IDOR
  - Catches path disclosure, DB errors, secrets in injection responses
- **Expanded Passive Detection** - All 8 passive detectors now active:
  - DebugInformationDetector, BackupFilesDetector, APIEndpointsDetector
- **Private Keys & Secrets Detection**:
  - RSA/SSH/PGP/EC/DSA private keys
  - JWT tokens, Slack tokens (4 types)
  - Extended AWS patterns
  - Base64 credentials, Bearer tokens
  - 5 generic key patterns (hex, Base58, UUID, mixed-case)
  - Context-aware anti-false-positive filtering

### 📈 Coverage Improvements
- **POST Forms** - 14/15 modules now test both GET and POST
- **IDOR Parameters** - Expanded from 12 to 25+ patterns
- **CSRF Keywords** - Enhanced state-changing detection
- **Git Deduplication** - Smart signature-based duplicate removal

---

## 🎯 Acunetix Gap Analysis

**New**: See [ACUNETIX_GAP_ANALYSIS.md](ACUNETIX_GAP_ANALYSIS.md) for detailed comparison with Acunetix findings.

**Key Findings**:
- Dominator has **strong error-based detection** ✅
- Missing: **Boolean-Based Blind SQLi** (10 vulns) ❌
- Missing: **Blind/Stored XSS with OOB** (5+ vulns) ❌
- Missing: **Password Over HTTP integration** (detector exists!) ❌

**Target**: Achieve 77% coverage (45+ of 58 Acunetix findings) with planned Phase 1+2 improvements.

---

## 🔧 Architecture

### Module Structure
```
modules/
├── {module_name}/
│   ├── module.py          # Scanner logic
│   ├── config.json        # Module configuration
│   ├── payloads.txt       # Attack payloads
│   └── patterns/          # Detection patterns (optional)
```

### Passive Detectors
```
passive_detectors/
├── passive_scanner.py          # Coordinator
├── sensitive_data_detector.py  # Keys, secrets, credentials
├── security_headers_detector.py
├── debug_information_detector.py
└── ... (8 total detectors)
```

### Reports Directory
```
reports/
├── scan_YYYYMMDD_HHMMSS.html  # HTML reports
├── scan_YYYYMMDD_HHMMSS.json  # JSON reports
└── multi_target_report_*.html  # Multi-scan reports
```

---

## 🚨 Security & Legal

⚠️ **WARNING**: Only use this tool on systems you own or have explicit permission to test.

**Legal Disclaimer**:
- Unauthorized scanning may violate laws (CFAA, GDPR, local cyber laws)
- This tool is for **authorized security testing**, **CTF competitions**, and **educational purposes** only
- The authors are NOT responsible for misuse or illegal activity
- Always obtain written permission before testing

**Responsible Use**:
- ✅ Your own applications/infrastructure
- ✅ Bug bounty programs with explicit scope
- ✅ Authorized penetration testing engagements
- ✅ Educational labs (XVWA, DVWA, WebGoat)
- ❌ Unauthorized scanning of third-party websites
- ❌ Production systems without approval
- ❌ Malicious intent

---

## 📚 Documentation

- [ROTATION 7 Complete Summary](ROTATION7_FINAL_COMPLETE.md) - All R7 improvements
- [Acunetix Gap Analysis](ACUNETIX_GAP_ANALYSIS.md) - Comparison with commercial scanner
- [Intelligent Scanner System](INTELLIGENT_SCANNER_SYSTEM.md) - Architecture deep dive
- [Passive Detectors Guide](PASSIVE_DETECTORS_COMPLETE.md) - Passive scanning details

---

## 🤝 Contributing

Contributions welcome! Areas of focus:
1. **Boolean-Based Blind SQLi** detection (TIER 1 priority)
2. **Blind XSS with OOB** integration (infrastructure exists!)
3. **SSL/TLS passive detector**
4. Moving hardcoded patterns to config files
5. Additional payload coverage

---

## 📄 License

MIT License - See [LICENSE](LICENSE) file for details

---

## 🙏 Acknowledgments

- OWASP for security testing methodologies
- XVWA, DVWA, WebGoat for training environments
- Acunetix for benchmark comparison data

---

**Made with ❤️ for the security community**
