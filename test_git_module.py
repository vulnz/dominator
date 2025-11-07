#!/usr/bin/env python3
"""
Тестовый скрипт для проверки модуля gitexposed
"""

import sys
import os
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from core.config import Config
from core.scanner import VulnScanner

def test_git_module():
    """Тест модуля gitexposed на указанной цели"""
    
    # Создаем фиктивные аргументы для Config
    class MockArgs:
        def __init__(self):
            self.target = "http://185.233.118.120:8082/xvwa/"
            self.file = None
            self.modules = ["gitexposed"]
            self.single_url = True
            self.threads = 1
            self.timeout = 10
            self.request_limit = 100
            self.headers = None
            self.headers_file = None
            self.exclude = None
            self.use_all_modules = False
            self.all = False
            self.output = None
            self.format = 'txt'
            self.screenshot = False
            self.max_time = None
            self.verbose = False
            self.cookies = None
            self.proxy = None
            self.user_agent = None
            self.delay = 0
            self.random_agent = False
            self.auth = None
    
    # Настройка конфигурации для single scan без crawling
    mock_args = MockArgs()
    config = Config(mock_args)
    
    # Переопределяем заголовки
    config.headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
    }
    
    print("="*80)
    print("ТЕСТ МОДУЛЯ GITEXPOSED")
    print("="*80)
    print(f"Цель: {config.target}")
    print(f"Модуль: {config.modules[0]}")
    print(f"Single URL mode: {config.single_url}")
    print(f"Threads: {config.threads}")
    print(f"Timeout: {config.timeout}s")
    print("="*80)
    
    # Создание и запуск сканера
    scanner = VulnScanner(config)
    
    try:
        print("\nЗапуск сканирования...")
        results = scanner.scan()
        
        print("\n" + "="*80)
        print("РЕЗУЛЬТАТЫ СКАНИРОВАНИЯ")
        print("="*80)
        
        # Фильтрация результатов - только уязвимости git
        git_vulnerabilities = []
        for result in results:
            if 'vulnerability' in result and result.get('module') == 'gitexposed':
                git_vulnerabilities.append(result)
        
        if git_vulnerabilities:
            print(f"НАЙДЕНО {len(git_vulnerabilities)} GIT УЯЗВИМОСТЕЙ:")
            print("-" * 50)
            
            for i, vuln in enumerate(git_vulnerabilities, 1):
                print(f"\n{i}. {vuln.get('vulnerability', 'Unknown')}")
                print(f"   Цель: {vuln.get('target', '')}")
                print(f"   Файл: {vuln.get('parameter', '')}")
                print(f"   Серьезность: {vuln.get('severity', '')}")
                print(f"   Payload: {vuln.get('payload', '')}")
                print(f"   Доказательство: {vuln.get('evidence', '')}")
                print(f"   URL запроса: {vuln.get('request_url', '')}")
                
                # Показать snippet ответа
                response_snippet = vuln.get('response_snippet', '')
                if response_snippet:
                    snippet_preview = response_snippet[:200] + ('...' if len(response_snippet) > 200 else '')
                    print(f"   Ответ сервера: {snippet_preview}")
                
                print("-" * 50)
        else:
            print("GIT УЯЗВИМОСТИ НЕ НАЙДЕНЫ")
            
            # Показать общую статистику
            if results and len(results) > 0:
                scan_stats = results[0].get('scan_stats', {})
                if scan_stats:
                    print(f"\nСтатистика сканирования:")
                    print(f"- Время сканирования: {scan_stats.get('scan_duration', '0s')}")
                    print(f"- Всего запросов: {scan_stats.get('total_requests', 0)}")
                    print(f"- Протестировано URL: {scan_stats.get('total_urls', 0)}")
                    
                    payload_stats = scan_stats.get('payload_stats', {}).get('gitexposed', {})
                    if payload_stats:
                        print(f"- Использовано payloads: {payload_stats.get('payloads_used', 0)}")
                        print(f"- Выполнено запросов: {payload_stats.get('requests_made', 0)}")
                        print(f"- Успешных payloads: {payload_stats.get('successful_payloads', 0)}")
        
        print("\n" + "="*80)
        print("ТЕСТ ЗАВЕРШЕН")
        print("="*80)
        
    except Exception as e:
        print(f"\nОШИБКА ПРИ СКАНИРОВАНИИ: {e}")
        import traceback
        traceback.print_exc()
    
    finally:
        # Очистка ресурсов
        scanner.cleanup()

if __name__ == "__main__":
    test_git_module()
