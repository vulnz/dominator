# GUI Changelog

## v1.7.0 - Fancy Module List View (2025-11-14)

### ✨ Major UI Redesign - Modules Tab
- **Replaced dropdown with fancy list view** showing all modules at once
- **Display full module names** from config.json instead of folder names
- **Show module descriptions** (80 chars preview) for each module
- **Color-coded severity indicators** - Critical (red), High (orange), Medium (yellow), Low (green), Info (blue)
- **3-panel layout**: Module list (left), Config editor (center), Payloads editor (right)
- **Live search/filter** - Filter modules by name or description in real-time
- **Module counter** - Shows "Modules: X/Total" with search results
- **Rich text display** - Each module shows:
  - Full name in bold green
  - Description preview in gray
  - Severity badge with color coding
  - Folder name in small text

### 🎨 UI Improvements
- Resizable split-view panels for customizable workspace
- Hover effects on module list items
- Selected module highlighted in green (#00ff88)
- Search bar with focus highlighting
- Auto-selects first module on load
- Removed emojis from Modules tab buttons for consistency

### 📝 Technical Details
**New Methods:**
- `load_modules_list()` - Loads all modules with metadata from config.json
- `filter_modules()` - Real-time filtering based on search text
- `on_module_selected()` - Handles module selection from list
- `reload_current_module()` - Reloads currently selected module data

**Updated Methods:**
- `create_modules_tab()` - Complete redesign with QListWidget
- `save_module_config()` - Now uses list item instead of dropdown
- `save_module_payloads()` - Now uses list item instead of dropdown
- `export_module_payloads()` - Now uses list item instead of dropdown

### 📝 Commits
- (pending) - feat: Redesign Modules tab with fancy list view and full module info

---

## v1.4.2 - Forbidden Paths Feature (2025-11-14)

### ✨ New Feature
- **Added Forbidden Paths input field** in Advanced Options → Crawler Settings
- Allows specifying paths/URLs that should NOT be crawled or tested
- Comma-separated format: `/logout,/delete,/admin/critical`
- Tooltip help text for user guidance
- Prevents accidental logout, sensitive operations during scans

### 📝 Commits
- `39d6c2a` - feat: Add Forbidden Paths input field to Crawler Settings

---

## v1.4.1 - UI Refinement (2025-11-14)

### 🎨 UI Improvements
- **Removed all emojis** from GUI for cleaner, more professional appearance
- Updated DOMINATOR header (removed 🎯)
- Removed emojis from all 7 tab names
- Removed emojis from menu items and group boxes
- Better compatibility across different font renderings

### 📝 Commits
- `5f839d8` - refactor: Remove emojis from GUI - cleaner professional look

---

## v1.4.0 - Scope Tab (2025-11-14)

### ✨ Major Features Added
- **New Scope Tab** for target reconnaissance and project management
- **Project Description** field for documenting scan objectives/authorization
- **Scan Scope** table showing URLs/domains with status and titles
- **Technology Detection** - Auto-detect frameworks, servers, CMS, databases:
  - Web Servers: Apache, Nginx, IIS
  - Languages: PHP, ASP.NET
  - Frameworks: React, Vue.js, Angular, Bootstrap
  - CMS: WordPress
  - Databases: MySQL, PostgreSQL
  - Libraries: jQuery
- **IP Geolocation** table with domain mapping (placeholder for future API integration)
- Real-time updates during scan
- Technology categorization (Language, Web Server, CMS, etc.)

### 📝 Commits
- `ffb551b` - feat: Add Scope tab with Technology Detection, IP Geo, Project Description, and Page Titles

---

## v1.3.0 - Resources Tab (2025-11-14)

### ✨ Major Features Added
- **New Resources Tab** with 4 categorized tables:
  - **Social Media Links**: Facebook, Twitter/X, LinkedIn, Instagram, GitHub, YouTube, TikTok
  - **Email Addresses**: Personal (Gmail, Yahoo, etc.) vs Business
  - **Phone Numbers**: International, US/Canada formats
  - **Leaked API Keys & Secrets**: AWS, Google, GitHub, Slack, Stripe, PayPal, JWT, Private Keys
- Real-time regex-based detection during scans
- Color-coded severity for leaked keys (CRITICAL/HIGH)
- Key preview truncation for security
- Export functionality to generate complete resources report
- Duplicate prevention across all tables

### 🔒 Security Features
- Leaked keys flagged as CRITICAL/HIGH severity
- Key previews truncated to prevent exposure
- Export includes rotation warnings

### 📝 Commits
- `6535d81` - feat: Add Resources tab with Social Media, Emails, Phones, and Leaked Keys detection

---

## v1.2.0 - Authentication Support (2025-11-14)

### ✨ New Features
- **Comprehensive Authentication Support** - 8 auth types:
  - None
  - Basic Auth (with Base64 encoding)
  - Digest Auth
  - NTLM Auth
  - Bearer Token
  - API Key (custom header)
  - OAuth 2.0
  - Custom Header
- Smart field enable/disable based on auth type
- Auto-generates auth headers
- Seamless integration with custom headers

### 📝 Commits
- `20e9aa6` - feat: Add comprehensive authentication support to GUI

---

## v1.1.2 - Vulnerability Detection Fix (2025-11-14)

### 🐛 Critical Fix
- **FIXED: Results tab showing empty** during scans - vulnerabilities weren't being detected
- **Root Cause**: Parser was looking for wrong output format (`[HIGH]`, `[CRITICAL]` tags that don't exist)
- **Solution**: Updated parser to detect actual scanner output format
- **Impact**: Results tab now shows vulnerabilities in real-time with correct severity colors

### 📝 Technical Details
The scanner outputs vulnerabilities in this format:
```
✓ Found: http://example.com/vuln.php (HTTP 200)
Critical Severity (2):
[SQL Injection]
  URL: http://example.com/login.php?id=1
```

**Previous Parser** was looking for:
- `[HIGH]`, `[CRITICAL]`, `[MEDIUM]` tags in output ❌
- `Found vulnerability:` messages ❌

**New Parser** correctly detects:
- ✅ ANSI color codes stripped (`[32mINFO[0m` → `INFO`)
- ✅ `✓ Found:` messages (actual vulnerability detection)
- ✅ Severity section headers (`Critical Severity (5):`)
- ✅ Vulnerability type lines (`[SQL Injection]`)
- ✅ `Total vulnerabilities:` summary line

### 📊 Before vs After
**Before** (v1.1.1):
```
Results Tab: Empty (no vulnerabilities detected)
Status Bar: 0 vulnerabilities
```

**After** (v1.1.2):
```
Results Tab:
  [CRITICAL] [SQL Injection]
  [HIGH] ✓ Found: /admin/config.php
  [MEDIUM] [Open Redirect]
Status Bar: Scan running... | 8/20 modules | 3 vulnerabilities
```

### 📝 Commits
- `9116d82` - fix: GUI now correctly detects and displays vulnerabilities

---

## v1.1.1 - Critical Bug Fix (2025-11-14)

### 🐛 Critical Fix
- **FIXED: "No modules found!" error** when running scans from GUI
- **Root Cause**: subprocess was running from `GUI/` directory instead of `dominator/` root
- **Solution**: Added `cwd=parent_dir` to `subprocess.Popen()` to set working directory
- **Impact**: GUI now correctly discovers all 20 modules in `modules/` folder

### 📝 Technical Details
When the GUI launched scans, it executed:
```python
subprocess.Popen([python, main.py, ...])
```
This ran `main.py` from the **current directory** (GUI/), which couldn't find:
- `modules/` folder
- `payloads/` folder
- `report/templates/` folder

**Fix Applied**:
```python
parent_dir = Path(__file__).parent.parent  # dominator/
subprocess.Popen([...], cwd=str(parent_dir))  # Run from dominator/ root
```

Now all file paths resolve correctly!

### 📊 Before vs After
**Before** (v1.1):
```
Available Modules: No modules found!
ERROR - No modules loaded! Check your -m parameter
```

**After** (v1.1.1):
```
Available Modules: 20 modules loaded
Running module: SQL Injection Scanner
Running module: XSS Scanner
...
```

### 📝 Commits
- `f05aa04` - fix: Set working directory to scanner root

---

## v1.1 - Real-Time Progress Update (2025-11-14)

### 🎯 Major Features Added
- **Real-time scan progress tracking** - Shows % complete as modules finish
- **Live module execution status** - Displays current module being tested
- **Instant vulnerability detection** - Vulnerabilities appear immediately when found
- **Color-coded vulnerability list** - Critical (🔴), High (🟠), Medium (🟡)
- **Auto-switching tabs** - Switches to Output on start, Results on completion
- **Live statistics** - Status bar shows: "X/20 modules | Y vulnerabilities"
- **Visual notifications** - Results tab turns red when vulnerabilities found

### 📊 What You'll See Now

#### During Scan:
```
Progress Bar: [████████░░░░░░░░░░] 40%
Current Module: 🔍 Testing: SQL Injection Scanner
Status Bar: Scan running... | 8/20 modules | 3 vulnerabilities
Console: Live output from scanner (all messages)
```

#### When Vulnerability Found:
```
Results Tab: 🔍 Results (turns RED)
Vulnerability List:
  [CRITICAL] SQL Injection found at /login.php?id=1
  [HIGH] XSS detected in /search.php?q=test
  [MEDIUM] Open Redirect at /redirect.php?url=
```

#### Statistics Display:
```
Total Vulnerabilities: 3
Critical: 1 | High: 1 | Medium: 1
```

### 🔧 Technical Improvements

#### New Signals in ScanThread:
- `vulnerability_signal(severity, description)` - Fires when vuln found
- `stats_signal(total_vulns, modules_done, modules_total)` - Updates stats

#### Enhanced Output Parsing:
The GUI now detects and displays:
- ✅ Module execution: "Running module: XSS Scanner"
- ✅ Module completion: "Module 'XSS Scanner' completed"
- ✅ Vulnerabilities: "[CRITICAL]", "[HIGH]", "[MEDIUM]"
- ✅ Crawling progress: "Crawling:", "Found page:", "Form discovered:"
- ✅ Target discovery: "Page discovery complete: 22 targets"
- ✅ Target scanning: "Target: http://example.com"

#### New Methods:
- `add_vulnerability(severity, description)` - Adds vuln to list with color
- `update_stats(total, done, total_modules)` - Updates status bar
- `update_vuln_display()` - Refreshes vulnerability counters
- Auto-scroll console to bottom on new output

### 🐛 Bug Fixes
- ✅ GUI no longer shows blank screen during scan
- ✅ Progress bar actually updates (was stuck at 0%)
- ✅ Module names now visible
- ✅ Vulnerability counts update in real-time
- ✅ Console output appears immediately (not buffered)

### 📝 Commits
- `ea6970a` - feat: Add real-time scan progress, module tracking, and vulnerability display
- `c82dd6c` - fix: Make all text white in GUI (was black on black)
- `ad445e1` - feat: Add professional PyQt5 GUI interface for Dominator Scanner

---

## v1.0 - Initial Release (2025-11-14)

### Features
- Dark theme GUI with neon green accents
- 4-tab interface: Scan Config, Advanced Options, Output, Results
- Module selection (all 20 modules)
- ROTATION 9 flags integration (--recon-only, --rotate-agent, --single-page)
- Background scanning with QThread (non-blocking UI)
- Windows/Linux/macOS launchers
- HTML report viewer

### Files
- `dominator_gui.py` - Main GUI application (800+ lines)
- `README.md` - Complete documentation
- `launch_gui.bat` - Windows launcher
- `launch_gui.sh` - Linux/macOS launcher
- `requirements.txt` - PyQt5 dependency
