# DOMINATOR WEB SCANNER - COMPLETE WORKFLOW GUIDE

## Table of Contents
1. [Overview](#overview)
2. [Feature Status](#feature-status)
3. [GUI Workflow](#gui-workflow)
4. [CLI Workflow](#cli-workflow)
5. [Scan Process Deep Dive](#scan-process-deep-dive)
6. [Module Execution](#module-execution)
7. [Result Handling](#result-handling)
8. [Troubleshooting](#troubleshooting)

---

## Overview

Dominator is a professional web vulnerability scanner with both CLI and GUI interfaces. It supports 25+ vulnerability detection modules, passive reconnaissance, and real-time reporting.

### Key Components
| Component | File | Purpose |
|-----------|------|---------|
| Main Entry | `main.py` | CLI entry point, argument parsing |
| Scanner Core | `core/clean_scanner.py` | Orchestrates scanning workflow |
| Crawler | `core/crawler.py` | Web crawling and URL discovery |
| Module Loader | `core/module_loader.py` | Dynamic module loading |
| HTTP Client | `core/http_client.py` | HTTP request handling |
| Result Manager | `core/result_manager.py` | Result collection & deduplication |
| Report Generator | `core/report_generator.py` | HTML/JSON/TXT/XML reports |
| GUI Main | `GUI/dominator_gui.py` | PyQt5 GUI interface |
| Scan Thread | `GUI/scan_thread.py` | Background scan execution |

---

## Feature Status

### GUI Tabs (7 Total)

| Tab | Status | Features |
|-----|--------|----------|
| **Scan Configuration** | COMPLETE | Target input, module selection, quick presets, scan settings, advanced options, authentication |
| **Custom Payloads** | COMPLETE | Module-specific payloads, file import/export, direct entry |
| **Results** | COMPLETE | 5 subtabs: Findings, Scan Output, Progress, Debug, Site Tree |
| **Scope** | COMPLETE | Project info, scope management, technology detection, geolocation |
| **Modules** | COMPLETE | Module browser, config editor, payload editor |
| **Plugins** | PARTIAL | UI complete, plugin execution needs integration |
| **Interceptor** | COMPLETE | Proxy server, request history, repeater, OOB detection |

### Menu Items

| Menu | Items | Status |
|------|-------|--------|
| **Project** | New, Open, Save, Save As, Export, Import, Recent, Close | COMPLETE |
| **File** | New Scan, Load/Save Config, Export Results, Scan Wizard, Exit | COMPLETE |
| **Edit** | Clear Targets, Clear Output, Clear Results | COMPLETE |
| **View** | Tab navigation shortcuts | COMPLETE |
| **Settings** | Notifications, Reset Warnings | COMPLETE |
| **Themes** | Light, Hacker Green, Cyber Blue, Purple Haze, Blood Red, Matrix | COMPLETE |
| **Tools** | Scheduler, Options | COMPLETE |
| **Help** | Documentation, About | COMPLETE |

### Core Features

| Feature | Status | Notes |
|---------|--------|-------|
| Multi-target scanning | COMPLETE | Single URL, file, multiple targets |
| 25+ vulnerability modules | COMPLETE | Active + Passive modules |
| Web crawling | COMPLETE | Sitemap, robots.txt, JS analysis, form discovery |
| Passive reconnaissance | COMPLETE | Tech detection, security headers, version disclosure |
| Real-time progress | COMPLETE | Progress bar, module status, time estimates |
| Report generation | COMPLETE | HTML, JSON, TXT, XML formats |
| Project management | COMPLETE | Save/load projects, recent projects |
| Scheduler | COMPLETE | One-time, daily, weekly, monthly schedules |
| Notifications | COMPLETE | Telegram, Email, Slack |
| Proxy interception | COMPLETE | HTTP/HTTPS interception, request modification |
| OOB detection | COMPLETE | Requestbin, Pipedream, custom servers |
| Browser integration | COMPLETE | Cookie/header capture, scan from browser |

---

## GUI Workflow

### Starting a New Scan

```
1. LAUNCH APPLICATION
   ├── python main.py --gui
   └── Project Selection Dialog appears
       ├── New Project → Create project folder structure
       ├── Open Project → Load existing project
       └── Temporary Session → No persistence

2. CONFIGURE SCAN (Scan Configuration Tab)
   ├── Enter Target(s)
   │   ├── Single URL: http://example.com
   │   ├── Multiple URLs: comma or newline separated
   │   └── From File: Browse for .txt file
   │
   ├── Select Modules
   │   ├── All Modules checkbox
   │   ├── Individual module checkboxes
   │   └── Search/filter modules
   │
   ├── Scan Settings
   │   ├── Threads: 1-50 (default: 10)
   │   ├── Timeout: 5-120 seconds (default: 30)
   │   ├── Max Time: 1-3600 minutes (default: 60)
   │   └── Output Format: html, json, txt, all
   │
   └── Advanced Options (collapsible)
       ├── Authentication (None, Basic, Bearer, API Key, OAuth, Custom)
       ├── HTTP Config (Headers, Cookies)
       ├── Crawler Settings (Max pages: 1-1000)
       └── ROTATION 9 Features
           ├── Recon Only Mode (passive only)
           ├── Rotate User-Agent
           └── Single Page Mode (no crawling)

3. START SCAN
   ├── Click "Start" button
   ├── Automatically switches to Results tab
   └── Real-time updates begin

4. MONITOR PROGRESS (Results Tab → Progress Subtab)
   ├── Circular progress indicator (0-100%)
   ├── Module execution grid (status per module)
   ├── Time tracking
   │   ├── Start time
   │   ├── Elapsed time
   │   ├── Estimated remaining
   │   └── Estimated completion
   └── Live activity log

5. VIEW FINDINGS (Results Tab → Findings Subtab)
   ├── Dashboard cards (Critical, High, Medium, Low counts)
   ├── Pie chart visualization
   ├── Filterable results table
   │   ├── Filter by severity
   │   ├── Filter by module
   │   ├── Filter by target
   │   └── Search box
   ├── Click finding → Detail panel shows:
   │   ├── Full vulnerability info
   │   ├── Parameter & payload
   │   ├── Evidence
   │   ├── CWE/OWASP/CVSS
   │   └── Remediation
   └── Discovered Resources (collapsible)
       ├── URLs & Endpoints
       ├── Social Media
       ├── Emails
       ├── Phones
       └── Leaked Keys

6. EXPORT RESULTS
   ├── Open HTML Report button
   ├── Generate Live Report button
   ├── Custom Report button
   ├── Export Filtered/Selected/All buttons
   └── Export Resources button

7. SAVE PROJECT
   └── Project → Save Project (Ctrl+Shift+S)
```

### Using the Interceptor

```
1. START PROXY (Interceptor Tab)
   ├── Configure port (default: 8080)
   ├── Click "Start Proxy"
   └── Proxy status shows "Running"

2. LAUNCH BROWSER
   ├── Click "Launch Chromium" or "Launch Firefox"
   ├── Browser opens with proxy configured
   └── SSL certificate auto-installed

3. BROWSE TARGET
   ├── Navigate to target website
   ├── All requests captured in History table
   └── Requests show: ID, Method, URL, Status, Size, Type, Time

4. INTERCEPT REQUESTS (Optional)
   ├── Enable "Intercept Requests" toggle
   ├── Requests pause for review
   ├── Options: Forward, Drop, Modify
   └── View/edit request/response

5. USE REPEATER
   ├── Right-click request → Send to Repeater
   ├── Multiple repeater tabs supported
   ├── Edit and resend requests
   └── View responses with syntax highlighting

6. SCAN FROM BROWSER
   ├── Right-click in browser → "Scan This Page"
   ├── Configure modules in dialog
   ├── Cookies/headers auto-captured
   └── Switches to Scan Configuration tab

7. OOB DETECTION
   ├── Switch to OOB subtab
   ├── Configure provider (Requestbin, Pipedream, Custom)
   ├── Copy OOB payloads
   ├── Monitor for callbacks
   └── View interaction details
```

### Scan Wizard

```
File → Scan Wizard (Ctrl+W)
    │
    ├── Step 1: Welcome
    │   └── Introduction to wizard
    │
    ├── Step 2: Target Selection
    │   ├── Enter target URL
    │   └── Import from file
    │
    ├── Step 3: Scan Type
    │   ├── Quick Scan (common vulns)
    │   ├── Full Scan (all modules)
    │   ├── OWASP Top 10
    │   └── Custom (select modules)
    │
    ├── Step 4: Performance
    │   ├── Thread count
    │   ├── Timeout settings
    │   └── Max scan time
    │
    ├── Step 5: Advanced Options
    │   ├── Authentication
    │   ├── Custom headers
    │   └── Crawl settings
    │
    ├── Step 6: Review
    │   └── Summary of all settings
    │
    └── Step 7: Complete
        └── Apply configuration to main GUI
```

---

## CLI Workflow

### Basic Usage

```bash
# Single target, all modules
python main.py -t http://example.com --all

# Single target, specific modules
python main.py -t http://example.com -m xss,sqli,cmdi

# Multiple targets from file
python main.py -f targets.txt -m xss,sqli

# With authentication
python main.py -t http://example.com -m sqli -H "Authorization: Bearer TOKEN"

# With cookies
python main.py -t http://example.com -m xss -c "session=abc123"

# Fast mode (optimized settings)
python main.py -t http://example.com --all --fast

# Recon only (passive)
python main.py -t http://example.com --recon-only

# Single page (no crawling)
python main.py -t http://example.com/page.php?id=1 --single-page -m sqli
```

### Command Line Options

```
Target Options:
  -t, --target TARGET     Single or multiple targets (comma-separated)
  -f, --file FILE         File containing targets (one per line)

Module Options:
  -m, --modules MODULES   Comma-separated module names
  --all                   Run all available modules
  --recon-only            Passive reconnaissance only

HTTP Options:
  -c, --cookies COOKIES   Cookie string (name=value; name2=value2)
  -H, --headers HEADER    HTTP header (can use multiple times)
  --proxy PROXY           HTTP/SOCKS proxy URL
  --timeout SECONDS       Request timeout (default: 30)
  --delay SECONDS         Delay between requests

Performance Options:
  --threads N             Number of threads (default: 10)
  --payload-limit N       Limit payloads per parameter
  --fast                  Enable fast mode optimizations
  --max-time MINUTES      Maximum scan duration

Crawler Options:
  --single-page           Don't crawl, test only specified URL
  --max-crawl-pages N     Maximum pages to crawl (default: 50)

Output Options:
  --auto-report           Auto-generate report on completion
  --format FORMAT         Report format: html,json,txt,xml (default: html)
  --report-mode MODE      Report detail: full or simple
  -v, --verbose           Verbose output
  -q, --quiet             Quiet mode

GUI Options:
  --gui                   Launch graphical interface
  --auto-start            Auto-start scan with GUI
```

### CLI Output Example

```
╔════════════════════════════════════════════════════════════════╗
║              DOMINATOR WEB VULNERABILITY SCANNER                ║
║              Advanced Security Testing Framework                ║
╚════════════════════════════════════════════════════════════════╝

Target: http://testphp.vulnweb.com
════════════════════════════════════════════════════════════════

[CRAWLER] Starting crawl of http://testphp.vulnweb.com
[CRAWLER] Found 45 URLs to analyze
[CRAWLER] Found 12 forms
[CRAWLER] Found 8 AJAX endpoints
[CRAWLER] Page discovery complete: 65 targets total

[PASSIVE] Running passive analysis...
[PASSIVE] Detected technologies: PHP, Apache, MySQL
[PASSIVE] Found 3 security header issues
[PASSIVE] Found 2 cookie security issues

Running module: xss
Description: Cross-Site Scripting (XSS) Detection
Module 'xss' completed: 8 findings (2 vulnerabilities)

Running module: sqli
Description: SQL Injection Detection
Module 'sqli' completed: 12 findings (3 vulnerabilities)

════════════════════════════════════════════════════════════════
                         SCAN RESULTS
════════════════════════════════════════════════════════════════

Critical Severity (1):
  [SQL Injection]
  URL: http://testphp.vulnweb.com/listproducts.php?cat=1
  Parameter: cat
  Payload: 1' OR '1'='1
  Evidence: MySQL error in response

High Severity (2):
  [Reflected XSS]
  URL: http://testphp.vulnweb.com/search.php?test=1
  Parameter: test
  Payload: <script>alert(1)</script>
  Evidence: Payload reflected unescaped

Total vulnerabilities: 5
  Critical: 1
  High: 2
  Medium: 2
  Low: 0

HTML report saved to scan_report_20251121_143052.html
```

---

## Scan Process Deep Dive

### Phase 1: Initialization

```
User Input (CLI/GUI)
        │
        ▼
┌─────────────────────────┐
│   Argument Parsing      │
│   (menu.py)             │
│   - Validate targets    │
│   - Parse modules       │
│   - Set options         │
└───────────┬─────────────┘
            │
            ▼
┌─────────────────────────┐
│   Configuration         │
│   (core/config.py)      │
│   - Normalize targets   │
│   - Discover modules    │
│   - Set HTTP options    │
└───────────┬─────────────┘
            │
            ▼
┌─────────────────────────┐
│   Scanner Init          │
│   (clean_scanner.py)    │
│   - Create HTTPClient   │
│   - Create Crawler      │
│   - Create ResultManager│
│   - Create ModuleLoader │
└───────────┬─────────────┘
            │
            ▼
┌─────────────────────────┐
│   Load Modules          │
│   (module_loader.py)    │
│   - Dynamic import      │
│   - Load config.json    │
│   - Load payloads.txt   │
│   - Load patterns.txt   │
└───────────┘
```

### Phase 2: Web Crawling

```
┌─────────────────────────┐
│   Start Crawl           │
│   (crawler.py)          │
└───────────┬─────────────┘
            │
            ▼
┌─────────────────────────┐
│   Extract Metadata      │
│   - Parse sitemap.xml   │
│   - Parse robots.txt    │
└───────────┬─────────────┘
            │
            ▼
┌─────────────────────────┐
│   Initial Request       │
│   - GET base URL        │
│   - Check dir listing   │
└───────────┬─────────────┘
            │
            ▼
┌─────────────────────────┐
│   Passive Analysis      │
│   - Security headers    │
│   - Tech detection      │
│   - Version disclosure  │
│   - WAF detection       │
│   - API endpoints       │
│   - JS secrets          │
└───────────┬─────────────┘
            │
            ▼
┌─────────────────────────┐
│   Extract JS Files      │
│   - Find <script> tags  │
│   - Download JS files   │
│   - Find AJAX endpoints │
│   - Find URL patterns   │
└───────────┬─────────────┘
            │
            ▼
┌─────────────────────────┐
│   Extract URLs          │
│   - href attributes     │
│   - src attributes      │
│   - action attributes   │
│   - Normalize URLs      │
└───────────┬─────────────┘
            │
            ▼
┌─────────────────────────┐
│   Deep Crawl            │
│   - Visit each URL      │
│   - Extract more URLs   │
│   - Find forms          │
│   - Extract parameters  │
└───────────┬─────────────┘
            │
            ▼
┌─────────────────────────┐
│   Return Discovered     │
│   - URLs with params    │
│   - Forms               │
│   - Passive findings    │
└───────────┘
```

### Phase 3: Module Execution

```
┌─────────────────────────┐
│   For Each Module       │
└───────────┬─────────────┘
            │
            ▼
┌─────────────────────────────────────────────┐
│   For Each Target (URL + params)            │
│   ┌───────────────────────────────────────┐ │
│   │   For Each Parameter                  │ │
│   │   ┌─────────────────────────────────┐ │ │
│   │   │   For Each Payload              │ │ │
│   │   │   - Create test request         │ │ │
│   │   │   - Send HTTP request           │ │ │
│   │   │   - Analyze response            │ │ │
│   │   │   - Detect vulnerability        │ │ │
│   │   │   - Score confidence            │ │ │
│   │   │   - Extract evidence            │ │ │
│   │   │   - Create finding if positive  │ │ │
│   │   └─────────────────────────────────┘ │ │
│   └───────────────────────────────────────┘ │
└─────────────────────────────────────────────┘
            │
            ▼
┌─────────────────────────┐
│   Return Module Results │
│   - Vulnerabilities     │
│   - Passive findings    │
└───────────┘
```

### Phase 4: Result Collection

```
┌─────────────────────────┐
│   Collect Results       │
│   (result_manager.py)   │
└───────────┬─────────────┘
            │
            ▼
┌─────────────────────────┐
│   For Each Result       │
│   - Check vulnerability │
│   - Deduplicate         │
│   - Update statistics   │
└───────────┬─────────────┘
            │
            ▼
┌─────────────────────────┐
│   Generate Reports      │
│   - HTML (interactive)  │
│   - JSON (machine)      │
│   - TXT (readable)      │
│   - XML (integration)   │
└───────────┘
```

---

## Module Execution

### Module Structure

```
modules/
├── xss/
│   ├── module.py          # Main module class
│   ├── config.json        # Configuration
│   ├── payloads.txt       # XSS payloads
│   ├── patterns.txt       # Detection patterns
│   └── indicators.txt     # Success indicators
├── sqli/
│   ├── module.py
│   ├── config.json
│   ├── payloads.txt
│   └── error_patterns.txt # SQL error messages
├── cmdi/
├── ssti/
├── lfi/
├── rfi/
├── xxe/
├── ssrf/
├── csrf/
├── idor/
├── redirect/
├── dom_xss/
├── file_upload/
├── weak_credentials/
├── php_object_injection/
├── xpath/
├── formula_injection/
├── dirbrute/
├── git/
├── env_secrets/
└── [more modules...]
```

### Module Config Example (config.json)

```json
{
  "enabled": true,
  "name": "SQL Injection",
  "description": "Detects SQL injection vulnerabilities",
  "severity": "Critical",
  "cwe": "CWE-89",
  "owasp": "A03:2021",
  "cvss": "9.8",
  "max_payloads": 50,
  "timeout": 10,
  "follow_redirects": true,
  "confidence_threshold": 0.7
}
```

### Payload Limit Priority

```
1. CLI --payload-limit (highest priority)
       │
       ▼
2. Module config.json max_payloads
       │
       ▼
3. No limit (use all payloads)
```

---

## Result Handling

### Result Structure

```json
{
  "vulnerability": true,
  "module": "sqli",
  "type": "SQL Injection",
  "url": "http://example.com/search?q=test",
  "method": "GET",
  "parameter": "q",
  "payload": "' OR '1'='1",
  "evidence": "You have an error in your SQL syntax",
  "description": "SQL injection allows attackers to...",
  "severity": "Critical",
  "confidence": 0.95,
  "remediation": "Use parameterized queries...",
  "cwe": "CWE-89",
  "cwe_name": "SQL Injection",
  "owasp": "A03:2021",
  "owasp_name": "Injection",
  "cvss": "9.8",
  "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
}
```

### Deduplication Logic

```
Signature = (url, parameter, payload_type, severity)

For each new result:
    if signature in existing_signatures:
        skip (duplicate)
    else:
        add to results
        add signature to existing_signatures
```

### GUI Signal Flow

```
ScanThread                          DominatorGUI
    │                                    │
    ├──output_signal(text)───────────────►append_output()
    │                                    │   └──add_scan_output_line()
    │                                    │
    ├──progress_signal(%, msg)───────────►update_progress()
    │                                    │   └──update_dashboard_stats()
    │                                    │
    ├──vulnerability_signal(sev, desc)───►add_vulnerability()
    │                                    │   ├──update_vuln_display()
    │                                    │   ├──add_finding_to_table()
    │                                    │   └──add_url_to_tree()
    │                                    │
    ├──stats_signal(vulns, done, total)──►update_stats()
    │                                    │
    ├──resource_signal(type, val, ...)───►add_resource()
    │                                    │
    ├──scope_signal(type, d1, d2, d3)────►add_scope_info()
    │                                    │
    ├──report_signal(filename)───────────►set_current_report()
    │                                    │
    └──finished_signal(return_code)──────►scan_finished()
```

---

## Troubleshooting

### Common Issues

| Issue | Cause | Solution |
|-------|-------|----------|
| **Scan output empty** | results_tab_builder not connected | Fixed in latest version |
| **Site Tree not updating** | Missing reference to results_tab_builder | Fixed: Store reference in create_results_tab() |
| **Module progress always 0** | Hardcoded module count | Fixed: Dynamic count from command |
| **Python popup windows** | Missing CREATE_NO_WINDOW flag | Fixed in main.py and chromium_manager.py |
| **Small activity log font** | Font size 10px | Fixed: Increased to 12px |
| **Debug tab empty** | No routing to debug tab | Fixed: Route via add_scan_output_line() |

### Debugging Tips

1. **Check Console Output**: Enable verbose mode with `-v`
2. **Check Debug Tab**: View all INFO/DEBUG messages
3. **Check Scan Output Tab**: See raw scanner output
4. **Check Project Logs**: `<project>/logs/` directory
5. **Test Single URL**: Use `--single-page` to test without crawling

### Performance Optimization

```bash
# Fast mode (recommended for quick scans)
python main.py -t http://example.com --all --fast

# Limit payloads (faster but less thorough)
python main.py -t http://example.com --all --payload-limit 10

# Single page (skip crawling)
python main.py -t http://example.com/page?id=1 --single-page -m sqli

# Increase threads (faster but more resource-intensive)
python main.py -t http://example.com --all --threads 20

# Set max time (prevent runaway scans)
python main.py -t http://example.com --all --max-time 30
```

---

## Version History

- **v1.5.0** - Current version
  - 25+ vulnerability modules
  - GUI with 7 tabs
  - Proxy interception (Burp-like)
  - OOB detection
  - Project management
  - Scheduler
  - Notifications (Telegram, Email, Slack)
  - 6 themes
  - Site Tree visualization
  - Debug tab
  - Dynamic module progress

---

*Document generated: 2025-11-21*
*Dominator Web Vulnerability Scanner*
