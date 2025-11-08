#!/usr/bin/env python3
"""
Скрипт для запуска бенчмарк-теста на testphp.vulnweb.com
"""

import sys
import os
from core.config import Config
from core.scanner import VulnScanner

def run_benchmark():
    """Запуск бенчмарк-теста"""
    print("=" * 60)
    print("ЗАПУСК БЕНЧМАРК-ТЕСТА TESTPHP.VULNWEB.COM")
    print("=" * 60)
    
    # Настройка конфигурации для бенчмарка
    config_args = {
        'targets': ['http://testphp.vulnweb.com/'],
        'modules': ['xss', 'sqli', 'lfi', 'ssrf', 'dirbrute', 'infoleak'],
        'threads': 5,
        'timeout': 10,
        'request_limit': 1000,
        'debug': True,
        'headers': {
            'User-Agent': 'Dominator Security Scanner - Benchmark Test'
        }
    }
    
    try:
        # Создаем конфигурацию
        config = Config()
        
        # Устанавливаем параметры
        config.targets = config_args['targets']
        config.modules = config_args['modules']
        config.threads = config_args['threads']
        config.timeout = config_args['timeout']
        config.request_limit = config_args['request_limit']
        config.debug = config_args['debug']
        config.headers = config_args['headers']
        
        print(f"Цель: {config.targets[0]}")
        print(f"Модули: {', '.join(config.modules)}")
        print(f"Потоки: {config.threads}")
        print(f"Лимит запросов: {config.request_limit}")
        print("-" * 60)
        
        # Создаем и запускаем сканер
        scanner = VulnScanner(config)
        
        print("Начинаем сканирование...")
        results = scanner.scan()
        
        print("\nСканирование завершено!")
        print(f"Найдено результатов: {len(results)}")
        
        # Выводим результаты в консоль
        scanner.print_results(results)
        
        # Сохраняем HTML отчет
        report_filename = "benchmark_report.html"
        scanner.save_report(results, report_filename, 'html')
        
        print(f"\nОтчет сохранен: {report_filename}")
        
        # Проверяем наличие анализа бенчмарка
        benchmark_found = False
        for result in results:
            if 'benchmark_analysis' in result:
                benchmark_found = True
                break
        
        if benchmark_found:
            print("✅ Анализ бенчмарка выполнен успешно!")
            print("📊 Проверьте HTML отчет для детального анализа эффективности")
            print("📄 Также создан текстовый отчет benchmark_report_benchmark.txt")
        else:
            print("⚠️  Анализ бенчмарка не был выполнен")
        
        return results
        
    except Exception as e:
        print(f"Ошибка при выполнении бенчмарка: {e}")
        import traceback
        traceback.print_exc()
        return None
    finally:
        # Очистка ресурсов
        if 'scanner' in locals():
            scanner.cleanup()

if __name__ == "__main__":
    print("Dominator Security Scanner - Benchmark Test")
    print("Тестирование эффективности на testphp.vulnweb.com")
    print()
    
    results = run_benchmark()
    
    if results:
        print("\n" + "=" * 60)
        print("БЕНЧМАРК-ТЕСТ ЗАВЕРШЕН")
        print("=" * 60)
        print("Результаты сохранены в benchmark_report.html")
        print("Откройте файл в браузере для просмотра детального анализа")
    else:
        print("\n❌ Бенчмарк-тест не удался")
        sys.exit(1)
