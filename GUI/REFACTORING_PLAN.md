# GUI Refactoring Plan - Modular Structure

## Current State
- **File**: `dominator_gui.py`
- **Size**: 3142 lines, 132KB
- **Problem**: Too large, hard to maintain

## Target Structure

```
GUI/
├── dominator_gui.py (Main window, ~300 lines)
├── components/
│   ├── __init__.py
│   ├── results_tab.py ✅ (DONE - Enhanced Results with filters)
│   ├── scan_config_tab.py (Target, modules selection)
│   ├── advanced_options_tab.py (HTTP, crawler, auth settings)
│   ├── output_tab.py (Console output)
│   ├── progress_tab.py (Progress & Plan)
│   ├── scope_tab.py (Technology detection, IP geo)
│   ├── resources_tab.py (Emails, phones, API keys)
│   └── modules_tab.py (Module management)
├── widgets/
│   ├── __init__.py
│   ├── scan_thread.py (Background scanning)
│   └── theme_manager.py (Theme switching)
└── utils/
    ├── __init__.py
    └── helpers.py (Common utilities)
```

## Phase 1: Extract Tabs ✅ (Started)

### ✅ Results Tab (COMPLETED)
- **File**: `components/results_tab.py`
- **Size**: ~600 lines
- **Features**:
  - Table with 5 columns (Severity, Type, URL, Parameter, Confidence)
  - Filters: Severity, Type, Search, Verified only
  - 6 detail tabs: Overview, Request, Response, Evidence, Remediation, CURL
  - Copy buttons for Request, Response, CURL
  - Color-coded by severity
  - Statistics bar (Total, Critical, High, Medium, Low, Info)
  - Export button integration

### ⏳ Scan Config Tab (Next)
- Target input (single/multiple/file)
- Module selection with search
- Quick module groups (all, web, api, etc.)
- ~300-400 lines

### ⏳ Advanced Options Tab
- Authentication (8 types)
- HTTP configuration
- Crawler settings
- ~300-400 lines

### ⏳ Other Tabs
- Output Tab: ~150 lines
- Progress Tab: ~200 lines
- Scope Tab: ~250 lines
- Resources Tab: ~300 lines
- Modules Tab: ~400 lines

## Phase 2: Extract Widgets
- `ScanThread` → `widgets/scan_thread.py`
- Theme management → `widgets/theme_manager.py`

## Phase 3: Main Window Refactoring
Slim down `dominator_gui.py` to:
- Window initialization
- Tab assembly
- Signal/slot connections
- Menu bar
- ~300 lines

## Benefits

### Before:
- 1 file: 3142 lines
- Hard to navigate
- Difficult to maintain
- Risky to modify

### After:
- Main file: ~300 lines
- 8 tab files: ~250 lines each
- 2 widget files: ~200 lines each
- 1 utils file: ~100 lines
- **Total**: Same functionality, better organized

### Advantages:
1. ✅ Easy to find code
2. ✅ Safe to modify individual tabs
3. ✅ Better collaboration
4. ✅ Faster loading in IDE
5. ✅ Reusable components

## Implementation Steps

### Step 1: Results Tab ✅
```python
from components import ResultsTab

class DominatorGUI(QMainWindow):
    def __init__(self):
        super().__init__()
        self.results_tab = ResultsTab()
        self.tabs.addTab(self.results_tab, "Results")
```

### Step 2: Update Main File
- Import new ResultsTab
- Replace old create_results_tab()
- Connect signals
- Test functionality

### Step 3: Repeat for Other Tabs
- One tab at a time
- Test after each extraction
- Keep git commits small

### Step 4: Extract Scan Thread
- Move to widgets/scan_thread.py
- Keep signals interface same

### Step 5: Extract Theme Manager
- Move theme logic
- Keep compatibility

## Testing Checklist

After each extraction:
- [ ] GUI launches without errors
- [ ] Tab displays correctly
- [ ] Signals work (scan start/stop/finish)
- [ ] Theme applies correctly
- [ ] Data updates in real-time
- [ ] Filters work
- [ ] Export works
- [ ] No regression in other tabs

## Migration Guide

### Old Code (dominator_gui.py):
```python
def create_results_tab(self):
    # 500 lines of code...
```

### New Code:
```python
from components import ResultsTab

def create_results_tab(self):
    return ResultsTab()
```

## File Size Estimates

| File | Lines | Purpose |
|------|-------|---------|
| dominator_gui.py | 300 | Main window, tab assembly |
| results_tab.py | 600 ✅ | Enhanced results display |
| scan_config_tab.py | 350 | Target & module selection |
| advanced_options_tab.py | 400 | HTTP, auth, crawler settings |
| output_tab.py | 150 | Console output |
| progress_tab.py | 200 | Progress monitoring |
| scope_tab.py | 250 | Tech detection, IP geo |
| resources_tab.py | 300 | Resources discovery |
| modules_tab.py | 400 | Module management |
| scan_thread.py | 200 | Background scanning |
| theme_manager.py | 150 | Theme switching |
| helpers.py | 100 | Utilities |
| **TOTAL** | 3400 | (+258 lines for better structure) |

## Next Steps

1. ✅ Create components/results_tab.py (DONE)
2. ⏳ Update dominator_gui.py to use new ResultsTab
3. ⏳ Test integration
4. ⏳ Create scan_config_tab.py
5. ⏳ Create advanced_options_tab.py
6. ⏳ Continue with other tabs
7. ⏳ Extract widgets
8. ⏳ Final testing

## Compatibility

- ✅ No breaking changes for users
- ✅ Same functionality
- ✅ Better code organization
- ✅ Easier future development

---

**Status**: Phase 1 Started - Results Tab Complete
**Next**: Integrate ResultsTab into main GUI
**Target**: Complete refactoring in 2-3 days
