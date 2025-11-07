# Dominator Web Vulnerability Scanner

Продвинутый сканер веб-уязвимостей с поддержкой множества модулей обнаружения.

## Возможности

### Поддерживаемые модули:
- **XSS** - Cross-Site Scripting
- **SQLi** - SQL Injection  
- **LFI** - Local File Inclusion
- **RFI** - Remote File Inclusion
- **CSRF** - Cross-Site Request Forgery
- **IDOR** - Insecure Direct Object Reference
- **SSRF** - Server-Side Request Forgery
- **DirBrute** - Directory and File Bruteforce
- **Git** - Git Repository Exposure
- **ENV** - Environment Files Exposure (.env)
- **Security Headers** - Missing Security Headers
- **SSL/TLS** - SSL/TLS Configuration Issues

### Новые возможности:
- **Улучшенный DirBrute** с 10 новыми крутыми payload'ами:
  - `.well-known` - RFC 8615 well-known URIs
  - `actuator` - Spring Boot Actuator endpoints
  - `health`, `metrics`, `prometheus` - мониторинг endpoints
  - `swagger`, `graphql`, `graphiql` - API документация
  - `kibana`, `elasticsearch` - поисковые системы
  - Новые файлы: `docker-compose.yml`, `Dockerfile`, `package.json`, `composer.json`, `yarn.lock`

- **Новый модуль ENV** для поиска .env файлов:
  - Поиск 50+ вариантов .env файлов
  - Умное определение содержимого по паттернам
  - Анализ чувствительности (пароли, ключи, токены)
  - Маскировка чувствительных данных в отчете
  - Определение фреймворков (Laravel, React, Vue, Next.js)

## Использование

### Базовое сканирование:
```bash
python main.py -t example.com
```

### Сканирование конкретными модулями:
```bash
python main.py -t example.com -m xss,sqli,git,env
```

### Тестирование нового модуля ENV:
```bash
python main.py -t 185.233.118.120:8082/xvwa/ -m env --threads 5 --timeout 15 -v --auto-report --format html
```

### Улучшенный DirBrute:
```bash
python main.py -t example.com -m dirbrute --threads 10 --timeout 20 -v
```

### Полное сканирование с отчетом:
```bash
python main.py -t example.com --all --auto-report --format html -v
```

## Параметры

- `-t, --target` - Цель сканирования
- `-m, --modules` - Модули для использования
- `--all` - Использовать все модули
- `--threads` - Количество потоков
- `--timeout` - Таймаут запросов
- `--auto-report` - Автоматическое создание отчета
- `--format` - Формат отчета (txt, html, json, xml)
- `-v, --verbose` - Подробный вывод

## Отчеты

Сканер поддерживает несколько форматов отчетов:
- **HTML** - Интерактивный веб-отчет с фильтрацией
- **JSON** - Структурированные данные для интеграции
- **XML** - Стандартный XML формат
- **TXT** - Простой текстовый отчет

## Безопасность

⚠️ **ВНИМАНИЕ**: Используйте только на системах, которыми вы владеете или имеете разрешение на тестирование. Несанкционированное сканирование может нарушать законы.
