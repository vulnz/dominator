# GUI CLI Launch Feature

## Overview
The `--gui` flag allows you to launch the Dominator GUI from the command line with pre-configured parameters. This combines the convenience of CLI with the visual feedback of the GUI.

## Basic Usage

### Launch Empty GUI
```bash
python main.py --gui
```

### Launch GUI with Target
```bash
python main.py --gui -t http://example.com
```

### Launch GUI with Target File
```bash
python main.py --gui -f targets.txt
```

## Auto-Start Scans

Add `--auto-start` to automatically begin scanning after GUI loads:

```bash
# Launch GUI and auto-start scan with all modules
python main.py --gui -t http://example.com --all --auto-start

# Launch GUI with file and auto-start
python main.py --gui -f targets.txt --all --auto-start
```

## Pre-Configure Module Selection

### All Modules
```bash
python main.py --gui -t http://example.com --all
```

### Specific Modules
```bash
python main.py --gui -t http://example.com -m xss,sqli,lfi
```

## Pre-Configure HTTP Options

### Custom Headers
```bash
python main.py --gui -t http://example.com \
  -H "Authorization: Bearer token123" \
  -H "X-Custom-Header: value"
```

### Cookies
```bash
python main.py --gui -t http://example.com \
  -c "session=abc123; user=admin"
```

### Proxy
```bash
python main.py --gui -t http://example.com \
  --proxy http://127.0.0.1:8080
```

## Pre-Configure Advanced Options

### Threads and Timeout
```bash
python main.py --gui -t http://example.com --all \
  --threads 20 --timeout 30
```

### Crawler Settings
```bash
python main.py --gui -t http://example.com --all \
  --max-crawl-pages 100 --delay 0.5
```

### Special Flags
```bash
# Single-page mode (no crawling)
python main.py --gui -t http://example.com --all --single-page

# Rotate user agents
python main.py --gui -t http://example.com --all --rotate-agent

# Recon-only (passive scanning)
python main.py --gui -t http://example.com --recon-only
```

## Complete Examples

### Quick Scan with Auto-Start
```bash
python main.py --gui \
  -t http://testphp.vulnweb.com \
  --all \
  --threads 15 \
  --timeout 20 \
  --auto-start
```

### Multi-Target Scan
```bash
python main.py --gui \
  -f scan_targets.txt \
  --all \
  --threads 10 \
  --max-crawl-pages 50 \
  --auto-start
```

### Authenticated Scan
```bash
python main.py --gui \
  -t http://example.com \
  -m xss,sqli,csrf \
  -H "Authorization: Bearer your_token_here" \
  -c "session=your_session_id" \
  --threads 10 \
  --auto-start
```

### Stealth Scan with Delays
```bash
python main.py --gui \
  -t http://example.com \
  --all \
  --delay 1.0 \
  --rotate-agent \
  --threads 5 \
  --auto-start
```

### Recon-Only Passive Scan
```bash
python main.py --gui \
  -t http://example.com \
  --recon-only \
  --auto-start
```

## Workflow Integration

### Scripted GUI Launch
Create a script to launch GUI with your preferred settings:

**scan_gui.bat (Windows):**
```batch
@echo off
python main.py --gui -f targets.txt --all --threads 15 --auto-start
```

**scan_gui.sh (Linux/Mac):**
```bash
#!/bin/bash
python3 main.py --gui -f targets.txt --all --threads 15 --auto-start
```

### Project-Specific Configuration
```bash
# Development environment scan
python main.py --gui \
  -t http://localhost:3000 \
  -m xss,sqli,csrf \
  --threads 5 \
  --delay 0.2 \
  --auto-start

# Production environment scan
python main.py --gui \
  -t https://production.example.com \
  --recon-only \
  --rotate-agent \
  --auto-start
```

## Benefits

1. **Quick Launch** - No need to manually fill in GUI fields
2. **Repeatable Scans** - Save command in script for consistent testing
3. **Visual Monitoring** - See scan progress in real-time
4. **Report Access** - Easy access to HTML reports via GUI buttons
5. **Flexibility** - Modify settings in GUI after launch if needed

## Notes

- Without `--auto-start`, GUI opens with fields pre-filled but waits for manual start
- `--auto-start` requires either `-t` or `-f` parameter
- All CLI parameters are optional when using `--gui` (can launch empty GUI)
- GUI fields can be modified before starting scan even with pre-configured values
- Works on Windows, Linux, and macOS

## Error Handling

If PyQt5 is not installed:
```
Error: PyQt5 not installed. Install with: pip install PyQt5
```

Solution:
```bash
pip install PyQt5
```

## See Also

- [GUI Documentation](GUI/README.md) - Complete GUI user guide
- [CLI Documentation](README.md) - Command-line interface guide
- [Scanner Configuration](CONFIGURATION.md) - Advanced configuration options
