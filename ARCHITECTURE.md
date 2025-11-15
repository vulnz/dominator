# Dominator Scanner Architecture

## Overview
Dominator is a modular web vulnerability scanner with a multi-layer architecture designed for extensibility and maintainability.

## Core Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                        User Interface                        │
│  ┌─────────────┐              ┌──────────────────────────┐  │
│  │   CLI (main.py)              │   GUI (dominator_gui.py) │  │
│  └─────────────┘              └──────────────────────────┘  │
└────────────────┬────────────────────────┬───────────────────┘
                 │                        │
┌────────────────▼────────────────────────▼───────────────────┐
│                    Core Scanner Layer                        │
│  ┌──────────────────────────────────────────────────────┐   │
│  │  CleanScanner (core/clean_scanner.py)                │   │
│  │  - Orchestrates scan workflow                        │   │
│  │  - Manages module execution                          │   │
│  │  - Coordinates crawler and modules                   │   │
│  └──────────────────────────────────────────────────────┘   │
└──────────────┬───────────────────────────────────────────────┘
               │
┌──────────────▼───────────────────────────────────────────────┐
│                   Supporting Systems                         │
│  ┌─────────────┐  ┌──────────────┐  ┌──────────────────┐   │
│  │  Crawler    │  │ Passive      │  │ Result Manager   │   │
│  │  (crawler.py)│  │ Scanner      │  │ (result_manager.py)│  │
│  └─────────────┘  └──────────────┘  └──────────────────┘   │
└──────────────┬───────────────────────────────────────────────┘
               │
┌──────────────▼───────────────────────────────────────────────┐
│                    Vulnerability Modules                     │
│  ┌────────┐ ┌────────┐ ┌────────┐ ┌────────┐ ┌────────┐   │
│  │  XSS   │ │  SQLi  │ │  LFI   │ │  SSTI  │ │  ...   │   │
│  └────────┘ └────────┘ └────────┘ └────────┘ └────────┘   │
│              All inherit from BaseModule                     │
└──────────────┬───────────────────────────────────────────────┘
               │
┌──────────────▼───────────────────────────────────────────────┐
│                      Utilities Layer                         │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐      │
│  │ OOB Detector │  │ Tech Detector│  │ HTTP Utils   │      │
│  └──────────────┘  └──────────────┘  └──────────────┘      │
└─────────────────────────────────────────────────────────────┘
```

## Directory Structure

```
dominator/
├── main.py                    # CLI entry point
├── core/                      # Core scanner components
│   ├── clean_scanner.py      # Main scanner orchestrator
│   ├── base_module.py        # Base class for all modules
│   ├── module_loader.py      # Dynamic module loading
│   ├── crawler.py            # Web crawler
│   ├── result_manager.py     # Result storage/filtering
│   └── report_generator.py   # Report generation
├── modules/                   # Vulnerability detection modules
│   ├── xss/
│   │   ├── module.py         # XSS detection logic
│   │   ├── config.json       # Module configuration
│   │   ├── payloads.txt      # XSS payloads
│   │   └── patterns.txt      # Detection patterns
│   ├── sqli/
│   ├── lfi/
│   └── ... (20 modules total)
├── passive_detectors/         # Passive detection
│   ├── passive_scanner.py    # Security headers, tech detection
│   └── sensitive_data_detector.py
├── utils/                     # Utility functions
│   ├── oob_detector.py       # Out-of-band callback detection
│   ├── tech_detector.py      # Technology fingerprinting
│   └── false_positive_analyzer.py
├── GUI/                       # PyQt5 GUI
│   ├── dominator_gui.py      # Main GUI window
│   └── components/           # Modular GUI components
│       └── results_tab.py    # Enhanced results display
└── data/                      # Static data files
    └── patterns/             # Detection patterns
```

## Key Components

### 1. CleanScanner (core/clean_scanner.py)
**Responsibility:** Main orchestrator
- Initializes modules
- Manages scan workflow
- Coordinates crawler and vulnerability modules
- Handles result aggregation

**Key Methods:**
- `scan()`: Main entry point
- `run_module()`: Execute individual module
- `_prepare_targets()`: Convert crawler results to testable targets

### 2. BaseModule (core/base_module.py)
**Responsibility:** Base class for all vulnerability modules
- Provides common functionality
- Handles payload loading
- Manages HTTP requests
- Implements result reporting

**Key Methods:**
- `scan()`: Abstract method - implemented by each module
- `test_payload()`: Send payload and analyze response
- `report_vulnerability()`: Report found vulnerability

### 3. Crawler (core/crawler.py)
**Responsibility:** Discover attack surface
- Crawl web pages
- Extract URLs with parameters
- Find forms (GET/POST)
- Identify injection points

**Features:**
- Sitemap parsing
- robots.txt analysis
- Form extraction
- JavaScript file discovery
- AJAX endpoint detection

### 4. Result Manager (core/result_manager.py)
**Responsibility:** Manage scan results
- Store vulnerabilities
- Filter duplicates
- Categorize by severity
- Export to multiple formats

### 5. Module Loader (core/module_loader.py)
**Responsibility:** Dynamic module discovery
- Auto-discover modules in modules/ directory
- Load module configurations
- Initialize module instances
- Handle dependencies

## Data Flow

```
1. User Input
   ↓
2. CleanScanner.scan()
   ↓
3. Crawler discovers pages/forms/parameters
   ↓
4. Passive Scanner analyzes responses
   ↓
5. Targets prepared for active modules
   ↓
6. Modules test vulnerabilities in parallel
   ↓
7. Results collected and deduplicated
   ↓
8. Report generated (HTML/JSON/TXT)
   ↓
9. Output to user (GUI/CLI)
```

## Module Architecture

Each vulnerability module follows this structure:

```python
class ModuleNameModule(BaseModule):
    def __init__(self):
        super().__init__('module_name')
        self.load_patterns()

    def scan(self, targets):
        """Main scan logic"""
        for target in targets:
            results = self.test_target(target)
            if results:
                self.report_vulnerability(results)

    def test_target(self, target):
        """Test specific target"""
        for payload in self.payloads:
            response = self.test_payload(target, payload)
            if self.is_vulnerable(response):
                return self.build_result(target, payload, response)
        return None

    def is_vulnerable(self, response):
        """Vulnerability detection logic"""
        # Module-specific detection
        pass
```

## Configuration System

### Module Configuration (modules/*/config.json)
```json
{
  "name": "Module Name",
  "description": "Description",
  "severity": "High|Medium|Low",
  "enabled": true,
  "max_payloads": 100,
  "timeout": 15,
  "confidence_threshold": 0.7
}
```

## Result Format

```python
{
    'vulnerability_type': 'XSS',
    'severity': 'High',
    'confidence': 0.95,
    'url': 'http://example.com/page?id=1',
    'parameter': 'id',
    'method': 'GET',
    'payload': '<script>alert(1)</script>',
    'evidence': 'Payload reflected in response',
    'request': 'Full HTTP request',
    'response': 'Full HTTP response',
    'cwe': 'CWE-79',
    'owasp': 'A03:2021',
    'cvss': 7.1,
    'remediation': 'Fix recommendations'
}
```

## Threading Model

- **Crawler**: Single-threaded sequential
- **Passive Scanner**: Runs during crawling (same thread)
- **Active Modules**: Can run in parallel (ThreadPoolExecutor)
- **HTTP Requests**: Configurable thread pool (default: 10)

## Performance Optimizations

1. **Payload Limiting**: Max payloads per module (default: 100)
2. **Response Caching**: Cache identical requests
3. **Smart Timeout**: Adaptive timeouts based on response time
4. **Parallel Testing**: Multiple targets tested concurrently
5. **Early Exit**: Stop testing parameter after first valid finding

## Security Features

1. **Scope Validation**: Only scan specified domains
2. **Rate Limiting**: Configurable request delay
3. **Timeout Protection**: Prevent infinite waits
4. **Safe Mode**: Disable destructive payloads
5. **User-Agent Rotation**: 26 modern browser agents

## Extensibility Points

### Adding New Module

1. Create directory: `modules/new_module/`
2. Add files:
   - `module.py` (inherits BaseModule)
   - `config.json`
   - `payloads.txt`
3. Module auto-discovered on next run

### Adding New Report Format

1. Extend `ReportGenerator` in `core/report_generator.py`
2. Add new method: `generate_FORMAT()`
3. Register in `generate_report()` switch

### Adding GUI Component

1. Create component in `GUI/components/`
2. Inherit from `QWidget`
3. Emit signals for communication
4. Import in `GUI/__init__.py`

## Error Handling

- **Network Errors**: Retry with exponential backoff (max 3 attempts)
- **Timeouts**: Skip and log, continue with next target
- **Parse Errors**: Log and continue
- **Module Errors**: Isolate - don't crash entire scan

## Logging

Levels:
- **DEBUG**: Detailed execution flow
- **INFO**: Scan progress, findings count
- **WARNING**: Skipped targets, minor issues
- **ERROR**: Failures that don't stop scan
- **CRITICAL**: Fatal errors

## Future Architecture Improvements

1. **Plugin System**: Hot-reload modules without restart
2. **Distributed Scanning**: Multiple scanner instances
3. **Queue System**: RabbitMQ for large-scale scans
4. **Database Backend**: Store results in PostgreSQL
5. **API Server**: REST API for remote control
6. **Real-time Dashboard**: WebSocket updates

---

**Version**: 1.10.0
**Last Updated**: 2025-11-15
