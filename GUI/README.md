# 🎯 Dominator GUI - Professional Interface

Modern, dark-themed GUI interface for the Dominator Web Vulnerability Scanner.

## ✨ Features

### 🎨 **Modern Dark Theme**
- Professional gradient header
- Dark color scheme (easy on the eyes)
- Neon green accents (#00ff88)
- Smooth animations and hover effects

### 📋 **4 Main Tabs**

#### 1. 🎯 Scan Configuration
- **Target Input**: URL or file with multiple targets
- **Module Selection**: Choose specific modules or scan with all 20 modules
- **Scan Settings**:
  - Threads (1-50)
  - Timeout (5-300 seconds)
  - Max scan time (1-300 minutes)
  - Output format (HTML, JSON, TXT, or all)

#### 2. ⚙️ Advanced Options
- **ROTATION 9 Features**:
  - ✅ Recon-only mode (passive scanning)
  - ✅ User-Agent rotation (26 modern browsers)
  - ✅ Single-page mode (no crawling)
- **HTTP Configuration**:
  - Custom headers
  - Session cookies
- **Crawler Settings**:
  - Max crawl pages
  - Payload limit

#### 3. 📊 Scan Output
- **Real-time progress bar**
- **Current module indicator**
- **Live console output** (terminal-style with green text)
- Clear output button

#### 4. 🔍 Results
- **Scan summary** with vulnerability counts
- **Severity breakdown**: Critical, High, Medium
- **Vulnerability list**
- **Open HTML report** button

### 🚀 **Control Buttons**
- **START SCAN** (green, glowing)
- **STOP SCAN** (red, emergency style)

## 📦 Installation

### Requirements
```bash
pip install PyQt5
```

### Optional (for better experience)
```bash
pip install PyQt5-tools  # For Qt Designer
```

## 🏃 Usage

### Method 1: Direct Launch
```bash
cd GUI
python dominator_gui.py
```

### Method 2: Launcher Script (Windows)
```bash
launch_gui.bat
```

### Method 3: From Parent Directory
```bash
python GUI/dominator_gui.py
```

## 🎮 How to Use

### Basic Scan
1. Enter target URL in "Target URL" field (e.g., `http://testphp.vulnweb.com`)
2. Leave "All Modules" checked (or select specific modules)
3. Click **START SCAN**
4. Watch real-time output in "Scan Output" tab
5. View results in "Results" tab when complete

### Advanced Scan
1. Go to **Advanced Options** tab
2. Enable desired features:
   - Check "Recon Only Mode" for passive scanning
   - Check "Rotate User-Agent" for stealth
   - Add custom headers/cookies if needed
3. Return to **Scan Configuration** tab
4. Click **START SCAN**

### Multiple Targets
1. Create a text file with targets (one per line):
   ```
   http://testphp.vulnweb.com
   http://testaspnet.vulnweb.com
   http://testasp.vulnweb.com
   ```
2. Click "Browse..." button
3. Select your targets file
4. Click **START SCAN**

## 🎨 Theme Customization

The GUI uses a professional dark theme with:
- **Background**: `#1a1a1a` (dark gray)
- **Accent**: `#00ff88` (neon green)
- **Console**: `#0a0a0a` (terminal black) with `#00ff00` (green text)
- **Buttons**: Gradient effects on hover

To customize colors, edit the `apply_dark_theme()` method in `dominator_gui.py`.

## 📊 Features Breakdown

### Real-Time Updates
- **Live progress bar** that updates as modules complete (shows % complete)
- **Real-time console output** with all scanner messages
- **Current module indicator** shows which module is running
- **Vulnerability counter** updates instantly when vulnerabilities are found
- **Status bar** shows modules completed and vulnerability count
- **Auto-switching tabs**: switches to Output tab on scan start, Results tab on completion
- **Color-coded vulnerability list**: Critical (red), High (orange), Medium (yellow)
- **Results tab notification**: turns red when new vulnerabilities are found

### Error Handling
- Invalid target detection
- Missing PyQt5 warning
- Scan failure notifications

### Responsive Design
- Window resizes smoothly
- Splitters for adjustable layouts
- Scrollable areas for long content

## 🐛 Troubleshooting

### "PyQt5 not found" Error
```bash
pip install PyQt5
```

### GUI doesn't start
- Check Python version (3.7+)
- Verify PyQt5 installation: `python -c "import PyQt5"`
- Run with verbose output: `python dominator_gui.py -v`

### Scan doesn't run
- Ensure `main.py` exists in parent directory
- Check that scanner is functional: `python ../main.py -h`
- Verify target URL format (must include `http://` or `https://`)

## 🔧 Technical Details

### Architecture
- **PyQt5** for GUI framework
- **QThread** for background scanning (non-blocking UI)
- **subprocess** for running scanner process
- **Real-time output** via stdout capture

### Thread Safety
- Scan runs in separate QThread
- Signals/slots for UI updates
- Process can be terminated safely

### File Structure
```
GUI/
├── dominator_gui.py       # Main GUI application
├── README.md              # This file
└── launch_gui.bat         # Windows launcher (coming)
```

## 🚀 Future Enhancements

- [ ] Real-time vulnerability count updates
- [ ] Graphical vulnerability severity chart
- [ ] Export results to PDF
- [ ] Scan history browser
- [ ] Preset configurations (Quick Scan, Deep Scan, Stealth Scan)
- [ ] Live vulnerability notifications (system tray)
- [ ] Comparison between multiple scans
- [ ] Integration with Burp Suite
- [ ] Custom theme builder

## 📝 License

Part of the Dominator Web Vulnerability Scanner project.

## 🙏 Credits

- Built with **PyQt5** (Qt framework for Python)
- Designed for **Dominator Scanner** (20 modules, OWASP Top 10 coverage)
- Dark theme inspired by modern pentesting tools
