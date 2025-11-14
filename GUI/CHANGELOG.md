# GUI Changelog

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
