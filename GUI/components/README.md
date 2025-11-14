# GUI Components

Модульная структура GUI компонентов для Dominator Scanner.

## Структура

### Results Tab (`results_tab.py`) ✅
Расширенная вкладка результатов с детальным выводом уязвимостей.

**Возможности:**
- ✅ Таблица с 5 колонками (Severity, Type, URL, Parameter, Confidence)
- ✅ Фильтры: по Severity, Type, поиск по тексту, только verified
- ✅ 6 вкладок детализации:
  - **Overview** - общая информация, CWE, OWASP, CVSS
  - **Request** - HTTP запрос с кнопкой Copy
  - **Response** - HTTP ответ с подсветкой payload
  - **Evidence** - доказательства уязвимости
  - **Remediation** - рекомендации по исправлению
  - **CURL** - команда для воспроизведения с кнопкой Copy
- ✅ Статистика (Total, Critical, High, Medium, Low, Info)
- ✅ Цветовая кодировка по severity
- ✅ Кнопки Export и Clear

**Использование:**
```python
from components import ResultsTab

results_tab = ResultsTab()

# Добавить уязвимость
results_tab.add_vulnerability({
    'severity': 'High',
    'vulnerability_type': 'XSS',
    'url': 'http://example.com/search.php',
    'parameter': 'q',
    'confidence': 'High',
    'description': 'Reflected XSS vulnerability...',
    'request': 'GET /search.php?q=<script>alert(1)</script>',
    'response_body': '<html>...<script>alert(1)</script>...</html>',
    'evidence': 'Payload reflected in response',
    'remediation': 'Implement input validation and output encoding',
    'cwe': 'CWE-79',
    'owasp': 'A03:2021',
    'cvss': '7.1'
})
```

**Signals:**
- `export_requested` - triggered when user clicks Export button

## Upcoming Components

### Scan Config Tab
- Target input (URL, file)
- Module selection
- Quick presets

### Advanced Options Tab
- Authentication settings
- HTTP configuration
- Crawler options

### Other Tabs
- Output Tab
- Progress Tab
- Scope Tab
- Resources Tab
- Modules Tab

## Development Guidelines

1. **Each tab is self-contained** - all logic in one file
2. **Use signals for communication** - emit signals for main window to handle
3. **Keep methods small** - max 50 lines per method
4. **Add docstrings** - document all public methods
5. **Follow PyQt5 naming** - camelCase for Qt methods, snake_case for custom

## Testing

Test each component independently:
```bash
cd GUI
python -c "from components import ResultsTab; from PyQt5.QtWidgets import QApplication; app = QApplication([]); tab = ResultsTab(); tab.show(); app.exec_()"
```
