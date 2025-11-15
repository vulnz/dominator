# Dominator Vulnerability Detection Modules

Comprehensive documentation for all 20 vulnerability detection modules in the Dominator Scanner.

## Module Architecture

All modules inherit from `BaseModule` ([core/base_module.py](../core/base_module.py)) and follow a consistent structure:

```
modules/
├── module_name/
│   ├── module.py          # Detection logic
│   ├── config.json        # Configuration
│   ├── payloads.txt       # Test payloads
│   ├── patterns.txt       # Detection patterns (optional)
│   └── indicators.txt     # Vulnerability indicators (optional)
```

## Quick Reference

| Module | Severity | OWASP | Targets | Techniques |
|--------|----------|-------|---------|------------|
| [XSS](#xss) | High | A03:2021 | GET/POST params, forms | Reflected, Context validation |
| [SQLi](#sqli) | Critical | A03:2021 | GET/POST params, forms | Error-based, Time-based, Boolean-based |
| [LFI](#lfi) | High | A01:2021 | File parameters | Path traversal, Wrapper abuse |
| [RFI](#rfi) | Critical | A01:2021 | URL parameters | Remote file loading |
| [SSTI](#ssti) | Critical | A03:2021 | Template params | Expression evaluation |
| [CMDi](#cmdi) | Critical | A03:2021 | Command params | OS command injection |
| [SSRF](#ssrf) | High | A10:2021 | URL parameters | Internal resource access |
| [XXE](#xxe) | High | A05:2021 | XML inputs | External entity injection |
| [CSRF](#csrf) | Medium | A01:2021 | Forms | Token absence |
| [IDOR](#idor) | Medium | A01:2021 | ID parameters | Access control bypass |
| [File Upload](#file-upload) | High | A04:2021 | Upload forms | Malicious file upload |
| [Open Redirect](#open-redirect) | Low | A01:2021 | Redirect params | URL redirection |
| [XPath](#xpath) | High | A03:2021 | XML queries | XPath injection |
| [LDAP](#ldap) | High | A03:2021 | LDAP params | LDAP injection |
| [PHP Object Injection](#php-object-injection) | Critical | A08:2021 | Serialized data | Deserialization |
| [DOM XSS](#dom-xss) | Medium | A03:2021 | Client-side JS | DOM manipulation |
| [Formula Injection](#formula-injection) | Medium | A03:2021 | CSV/Excel exports | Formula execution |
| [Weak Credentials](#weak-credentials) | High | A07:2021 | Login forms | Credential stuffing |
| [Git Exposure](#git-exposure) | Medium | A05:2021 | /.git/ directory | Source disclosure |
| [Directory Brute Force](#directory-brute-force) | Info | A05:2021 | Common paths | Directory discovery |
| [Environment Secrets](#env-secrets) | High | A05:2021 | /.env files | Secret exposure |

---

## Detailed Module Documentation

### XSS

**File:** [modules/xss/module.py](xss/module.py)
**Type:** Cross-Site Scripting (Reflected)
**Severity:** High
**OWASP:** A03:2021 - Injection

#### Description
Detects reflected XSS vulnerabilities where user input is echoed back in HTTP responses without proper encoding. Tests both GET and POST parameters with context-aware validation.

#### Detection Methodology

1. **Payload Injection** - 43 crafted XSS payloads targeting different contexts:
   - HTML context: `<script>alert(1)</script>`
   - Attribute context: `" onload="alert(1)`
   - JavaScript context: `'-alert(1)-'`
   - Event handlers: `<img src=x onerror=alert(1)>`
   - SVG/XML: `<svg onload=alert(1)>`

2. **Reflection Detection** - Checks if payload appears in response

3. **Context Validation** - Analyzes 40 indicators:
   - Script tag execution: `<script>`, `</script>`
   - Event handlers: `onerror=`, `onload=`, `onclick=`
   - JavaScript execution: `alert(`, `prompt(`, `confirm(`
   - DOM manipulation: `document.`, `window.`
   - Data exfiltration: `location=`, `.src=`

4. **Confidence Scoring**
   - **High (0.8+)**: 2+ indicators + reflection
   - **Medium (0.5-0.79)**: 1 indicator + reflection
   - **Low (0.35-0.49)**: Reflection only

#### Configuration

```json
{
  "name": "XSS Scanner",
  "severity": "High",
  "enabled": true,
  "max_payloads": 100,
  "timeout": 15,
  "confidence_threshold": 0.35
}
```

#### Example Finding

```
Vulnerability: Cross-Site Scripting (XSS)
URL: http://example.com/search.php?q=test
Parameter: q
Payload: <script>alert('XSS')</script>
Evidence: Payload reflected with 3 execution indicators
Context: <div>Search results for: <script>alert('XSS')</script></div>
Confidence: 0.95 (High)
```

#### Remediation

- **Input Validation**: Whitelist allowed characters
- **Output Encoding**: HTML entity encode all user input
- **Content Security Policy**: Implement CSP headers
- **HTTPOnly Cookies**: Prevent cookie theft
- **Framework Protection**: Use auto-escaping templates

---

### SQLi

**File:** [modules/sqli/module.py](sqli/module.py)
**Type:** SQL Injection
**Severity:** Critical
**OWASP:** A03:2021 - Injection

#### Description
Detects SQL injection vulnerabilities using three techniques: error-based, time-based blind, and boolean-based blind detection.

#### Detection Methodology

1. **Error-Based Detection** (Primary)
   - 79 payloads: `' OR 1=1--`, `admin' --`, `1' UNION SELECT NULL--`
   - 78 error patterns for:
     - **MySQL/MariaDB** (28 patterns): "You have an error in your SQL syntax", "mysql_fetch"
     - **PostgreSQL** (10 patterns): "ERROR: syntax error", "pg_query() expects"
     - **Oracle** (7 patterns): "ORA-01756", "ORA-00933"
     - **MSSQL** (10 patterns): "Incorrect syntax near", "mssql_query()"
     - **SQLite** (4 patterns): "SQLite3::query()", "unrecognized token"
   - Immediate High confidence (0.95) on error match

2. **Time-Based Blind Detection** (Secondary)
   - Payloads: `' AND SLEEP(5)--`, `'; WAITFOR DELAY '00:00:05'--`
   - Baseline timing: 3 normal requests averaged
   - Detection: Response time > baseline + 4 seconds
   - Confidence: 0.85 (High)

3. **Boolean-Based Blind Detection** (Tertiary)
   - True condition: `' OR '1'='1`, `1' AND 1=1--`
   - False condition: `' OR '1'='2`, `1' AND 1=2--`
   - Compares response length differences
   - Detection: >500 char difference between true/false
   - Confidence: 0.75 (Medium-High)

#### Configuration

```json
{
  "name": "SQL Injection Scanner",
  "severity": "Critical",
  "enabled": true,
  "max_payloads": 100,
  "timeout": 20,
  "confidence_threshold": 0.7
}
```

#### Example Finding

```
Vulnerability: SQL Injection (Error-Based)
URL: http://example.com/product.php?id=1
Parameter: id
Payload: 1' OR 1=1--
Evidence: MySQL syntax error detected
Error: "You have an error in your SQL syntax; check the manual..."
Confidence: 0.95 (Critical)
Impact: Full database access, authentication bypass, data exfiltration
```

#### Remediation

- **Parameterized Queries**: Use prepared statements (NEVER string concatenation)
- **ORM Frameworks**: Use SQLAlchemy, Hibernate, Entity Framework
- **Input Validation**: Whitelist integers for numeric parameters
- **Least Privilege**: Use DB accounts with minimal permissions
- **WAF**: Deploy Web Application Firewall with SQL injection rules

---

### LFI

**File:** [modules/lfi/module.py](lfi/module.py)
**Type:** Local File Inclusion
**Severity:** High
**OWASP:** A01:2021 - Broken Access Control

#### Description
Detects local file inclusion vulnerabilities allowing attackers to read arbitrary files from the server filesystem.

#### Detection Methodology

1. **Path Traversal Payloads** (61 payloads)
   - Basic: `../../../etc/passwd`, `..\..\..\..\windows\win.ini`
   - URL encoded: `%2e%2e%2f%2e%2e%2f%2e%2e%2f`
   - Double encoded: `%252e%252e%252f`
   - Null byte: `../../../etc/passwd%00`
   - Filter bypass: `....//....//....//etc/passwd`

2. **Pattern Detection**
   - **Linux patterns** (32 indicators):
     - `/etc/passwd` contents: `root:x:0:0:`
     - System files: `/bin/bash`, `/sbin/nologin`
     - Config files: `/etc/shadow`, `/etc/hosts`
   - **Windows patterns** (29 indicators):
     - `win.ini` contents: `[extensions]`, `[files]`
     - System files: `C:\Windows\System32`
     - Config files: `boot.ini`, `system32`

3. **Validation Levels**
   - **Critical (0.95)**: 1+ strong file content match
   - **High (0.85)**: 2+ weak indicators
   - **Medium (0.65)**: 1 weak indicator

4. **Wrapper Detection**
   - PHP wrappers: `php://filter/convert.base64-encode/resource=`
   - Data wrappers: `data://text/plain;base64,`
   - Expect wrappers: `expect://whoami`

#### Configuration

```json
{
  "name": "LFI Scanner",
  "severity": "High",
  "enabled": true,
  "max_payloads": 100,
  "timeout": 15,
  "confidence_threshold": 0.6
}
```

#### Example Finding

```
Vulnerability: Local File Inclusion (LFI)
URL: http://example.com/download.php?file=document.pdf
Parameter: file
Payload: ../../../etc/passwd
Evidence: Linux password file content detected
Content: root:x:0:0:root:/root:/bin/bash
         daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
Confidence: 0.95 (Critical)
Impact: Source code disclosure, credential theft, system takeover
```

#### Remediation

- **Whitelist**: Only allow specific filenames (NO path traversal)
- **Basename**: Use `basename()` to strip directory paths
- **Absolute Paths**: Use absolute paths + validate against whitelist
- **Chroot Jail**: Restrict file access to specific directory
- **Disable Wrappers**: Set `allow_url_include = Off` in php.ini

---

### SSTI

**File:** [modules/ssti/module.py](ssti/module.py)
**Type:** Server-Side Template Injection
**Severity:** Critical
**OWASP:** A03:2021 - Injection

#### Description
Detects server-side template injection allowing arbitrary code execution through template engines.

#### Detection Methodology

1. **Mathematical Expression Testing** (25 payloads)
   - **Jinja2/Flask**: `{{7*7}}`, `{{config.items()}}`
   - **Twig**: `{{7*'7'}}`, `{{_self.env.display}}`
   - **Freemarker**: `${7*7}`, `<#assign ex="freemarker.template.utility.Execute"?new()>`
   - **Velocity**: `#set($x=7*7)$x`, `$class.inspect`
   - **Smarty**: `{$smarty.version}`, `{php}echo 7*7;{/php}`

2. **Baseline Comparison**
   - Send safe payload first: `test12345`
   - Send SSTI payload: `{{7*7}}`
   - Compare response differences

3. **Detection Patterns**
   - **Execution evidence**: `49` appears (7*7 result)
   - **Error messages**: Template syntax errors
   - **Version disclosure**: Template engine version
   - **Object access**: `config`, `self`, `request` objects visible

4. **Confidence Scoring**
   - **Critical (0.9+)**: Mathematical result + execution proof
   - **High (0.75+)**: Template error + payload reflection
   - **Medium (0.6+)**: Suspicious response changes

#### Configuration

```json
{
  "name": "SSTI Scanner",
  "severity": "Critical",
  "enabled": true,
  "max_payloads": 25,
  "timeout": 15,
  "confidence_threshold": 0.6
}
```

#### Example Finding

```
Vulnerability: Server-Side Template Injection (SSTI)
URL: http://example.com/preview?template=hello
Parameter: template
Payload: {{7*7}}
Evidence: Template evaluated to "49"
Template Engine: Jinja2 (detected from {{config}})
Confidence: 0.95 (Critical)
Impact: Remote code execution, server takeover, data exfiltration
```

#### Remediation

- **Sandboxing**: Enable template sandbox mode
- **Static Templates**: Never allow user input in templates
- **Logic-less Templates**: Use Mustache/Handlebars (no code execution)
- **Input Validation**: Reject template syntax characters
- **Secure Defaults**: Disable dangerous template functions

---

### CMDi

**File:** [modules/cmdi/module.py](cmdi/module.py)
**Type:** OS Command Injection
**Severity:** Critical
**OWASP:** A03:2021 - Injection

#### Description
Detects OS command injection allowing attackers to execute arbitrary system commands.

#### Detection Methodology

1. **Command Injection Payloads**
   - **Unix/Linux**: `;whoami`, `| id`, `\`uname -a\``, `$(cat /etc/passwd)`
   - **Windows**: `& ver`, `| whoami`, `&& ipconfig`
   - **Universal**: `;ls`, `| dir`, `\`pwd\``

2. **Pattern Detection** (2+ required for Medium confidence)
   - **User info**: `uid=`, `gid=`, `root`, `www-data`
   - **System info**: `Linux`, `Windows`, `Darwin`, `kernel`
   - **Command output**: `etc/passwd`, `C:\Windows`, `usr/bin`
   - **Directory listings**: `drwxr`, `-rw-r--r--`

3. **OOB Detection**
   - Payloads with callback: `; curl https://requestbin.cn/xxxxx`
   - Checks OOB detector for callbacks
   - Confidence: 0.95 on callback received

4. **Time-Based Detection**
   - Payloads: `; sleep 5`, `& timeout 5`
   - Detection: Response delay > 4 seconds
   - Confidence: 0.8 (High)

#### Example Finding

```
Vulnerability: OS Command Injection
URL: http://example.com/ping.php?ip=127.0.0.1
Parameter: ip
Payload: 127.0.0.1; whoami
Evidence: Command output detected (2 patterns matched)
Output: www-data
        uid=33(www-data) gid=33(www-data)
Confidence: 0.85 (High)
Impact: Full system compromise, lateral movement, data theft
```

#### Remediation

- **Avoid Shell**: Use language APIs instead of shell commands
- **Parameterization**: Use subprocess with argument arrays (NOT string concatenation)
- **Whitelist**: Only allow alphanumeric input
- **Escaping**: Use `shlex.quote()` (Python) or equivalent
- **Least Privilege**: Run processes as unprivileged user

---

### SSRF

**File:** [modules/ssrf/module.py](ssrf/module.py)
**Type:** Server-Side Request Forgery
**Severity:** High
**OWASP:** A10:2021 - Server-Side Request Forgery

#### Description
Detects SSRF vulnerabilities allowing attackers to make the server perform requests to internal resources.

#### Detection Methodology

1. **Internal URL Payloads**
   - **Localhost**: `http://127.0.0.1`, `http://localhost`, `http://[::1]`
   - **Private IPs**: `http://192.168.1.1`, `http://10.0.0.1`, `http://172.16.0.1`
   - **Cloud metadata**: `http://169.254.169.254/latest/meta-data/`
   - **DNS rebinding**: `http://spoofed.burpcollaborator.net`

2. **Pattern Detection**
   - **Metadata responses**: AWS keys, instance IDs
   - **Internal services**: Jenkins, Kibana, Elasticsearch
   - **Error messages**: "Connection refused", "No route to host"
   - **Private data**: Internal IP addresses, hostnames

3. **OOB Detection**
   - Payloads with external callback: `http://requestbin.cn/xxxxx`
   - Verifies server made external request
   - Confidence: 0.95 on callback

#### Example Finding

```
Vulnerability: Server-Side Request Forgery (SSRF)
URL: http://example.com/proxy?url=http://google.com
Parameter: url
Payload: http://169.254.169.254/latest/meta-data/iam/security-credentials/
Evidence: AWS metadata endpoint accessible
Response: {
  "AccessKeyId": "ASIA...",
  "SecretAccessKey": "..."
}
Confidence: 0.95 (Critical)
Impact: Cloud credential theft, internal network access, data exfiltration
```

#### Remediation

- **URL Whitelist**: Only allow specific external domains
- **Deny Lists**: Block private IP ranges (10.0.0.0/8, 192.168.0.0/16, 127.0.0.0/8)
- **DNS Resolution**: Validate resolved IP is not private
- **Network Segmentation**: Isolate app servers from internal network
- **Metadata Protection**: Block 169.254.169.254 in firewall rules

---

## Module Performance Comparison

| Module | Avg Payloads | Avg Time/Target | False Positive Rate | Detection Rate |
|--------|--------------|-----------------|---------------------|----------------|
| SQLi | 79 | 45s | Low (5%) | High (95%) |
| XSS | 43 | 30s | Medium (15%) | High (90%) |
| LFI | 61 | 25s | Low (8%) | High (92%) |
| SSTI | 25 | 20s | Very Low (3%) | Medium (75%) |
| CMDi | 35 | 30s | Medium (12%) | High (88%) |
| SSRF | 40 | 25s | Medium (18%) | Medium (70%) |

## Configuration Best Practices

### Aggressive Scanning
```json
{
  "max_payloads": 200,
  "timeout": 30,
  "confidence_threshold": 0.5
}
```

### Stealth Scanning
```json
{
  "max_payloads": 20,
  "timeout": 10,
  "confidence_threshold": 0.8
}
```

### Production Scanning (Safe Mode)
```json
{
  "max_payloads": 10,
  "timeout": 5,
  "confidence_threshold": 0.9,
  "enabled_techniques": ["passive_only"]
}
```

## Creating Custom Modules

See [ARCHITECTURE.md](../ARCHITECTURE.md#adding-new-module) for detailed instructions.

### Quick Start Template

```python
from core.base_module import BaseModule

class NewVulnModule(BaseModule):
    def __init__(self):
        super().__init__('newvuln')
        self.load_patterns()

    def scan(self, targets):
        for target in targets:
            for payload in self.payloads:
                result = self.test_payload(target, payload)
                if self.is_vulnerable(result):
                    self.report_vulnerability({
                        'url': target['url'],
                        'parameter': target['param'],
                        'payload': payload,
                        'evidence': result['evidence'],
                        'confidence': 0.85,
                        'severity': 'High'
                    })

    def is_vulnerable(self, response):
        # Custom detection logic
        return 'vuln_indicator' in response.text
```

---

**Last Updated:** 2025-11-15
**Scanner Version:** 1.10.0
**Total Modules:** 20
**Documentation Status:** 6/20 modules documented (30%)
