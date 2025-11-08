#!/usr/bin/env python3
# -*- coding: utf-8 -*-
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
    print("ZAPUSK BENCHMARK-TESTA TESTPHP.VULNWEB.COM")
    print("=" * 60)
    
    # Настройка конфигурации для бенчмарка
    class MockArgs:
        def __init__(self):
            # Основные параметры сканирования
            self.target = 'http://testphp.vulnweb.com/'
            self.targets = ['http://testphp.vulnweb.com/']
            self.file = None
            self.modules = 'xss,sqli,lfi,ssrf,dirbrute,infoleak'
            self.all = False
            
            # Параметры производительности
            self.threads = 5
            self.timeout = 10
            self.request_limit = 1000
            self.delay = 0
            self.max_time = None
            
            # Параметры отладки и вывода
            self.debug = True
            self.verbose = False
            self.quiet = False
            self.no_color = False
            
            # Параметры HTTP
            self.headers = None
            self.headers_file = None
            self.cookies = None
            self.auth = None
            self.proxy = None
            self.user_agent = None
            self.random_agent = False
            
            # Параметры фильтрации
            self.exclude = None
            self.use_all = False
            
            # Параметры режимов сканирования
            self.filetree_mode = False
            self.filetree = False
            self.single_url = False
            self.nocrawl = False
            self.screenshot = False
            
            # Параметры краулера
            self.crawl_depth = 2
            self.crawl_limit = 100
            
            # Параметры вывода
            self.output = None
            self.format = 'html'
            
            # Дополнительные параметры, которые могут потребоваться
            self.wordlist = None
            self.extensions = None
            self.status_codes = None
            self.follow_redirects = True
            self.verify_ssl = False
            self.session = None
            self.rate_limit = None
            self.retry_count = 3
            self.backoff_factor = 1.0
            self.custom_payloads = None
            self.payload_file = None
            self.scope = None
            self.out_of_scope = None
            self.include_status = None
            self.exclude_status = None
            self.match_regex = None
            self.filter_regex = None
            self.match_size = None
            self.filter_size = None
            self.match_words = None
            self.filter_words = None
            self.match_lines = None
            self.filter_lines = None
            self.recursion_depth = 3
            self.force = False
            self.update = False
            self.config_file = None
            self.save_config = None
            self.load_config = None
            self.resume = None
            self.save_state = None
            self.load_state = None
    
    try:
        # Создаем конфигурацию с mock args
        mock_args = MockArgs()
        config = Config(mock_args)
        
        # Устанавливаем дополнительные параметры
        config.headers = {
            'User-Agent': 'Dominator Security Scanner - Benchmark Test'
        }
        
        print(f"Tsel: {config.targets[0]}")
        print(f"Moduli: {', '.join(config.modules)}")
        print(f"Potoki: {config.threads}")
        print(f"Limit zaprosov: {config.request_limit}")
        print("-" * 60)
        
        # Создаем и запускаем сканер
        scanner = VulnScanner(config)
        
        print("Nachinaem skanirovanie...")
        results = scanner.scan()
        
        print("\nSkanirovanie zaversheno!")
        print(f"Najdeno rezultatov: {len(results)}")
        
        # Выводим результаты в консоль
        scanner.print_results(results)
        
        # Сохраняем HTML отчет
        report_filename = "benchmark_report.html"
        scanner.save_report(results, report_filename, 'html')
        
        print(f"\nOtchet sohranen: {report_filename}")
        
        # Проверяем наличие анализа бенчмарка
        benchmark_found = False
        for result in results:
            if 'benchmark_analysis' in result:
                benchmark_found = True
                break
        
        if benchmark_found:
            print("[OK] Analiz benchmarka vypolnen uspeshno!")
            print("[INFO] Proverte HTML otchet dlya detalnogo analiza effektivnosti")
            print("[INFO] Takzhe sozdan tekstovyj otchet benchmark_report_benchmark.txt")
        else:
            print("[WARNING] Analiz benchmarka ne byl vypolnen")
        
        return results
        
    except Exception as e:
        print(f"Oshibka pri vypolnenii benchmarka: {e}")
        import traceback
        traceback.print_exc()
        return None
    finally:
        # Очистка ресурсов
        if 'scanner' in locals():
            scanner.cleanup()

if __name__ == "__main__":
    print("Dominator Security Scanner - Benchmark Test")
    print("Testirovanie effektivnosti na testphp.vulnweb.com")
    print()
    
    results = run_benchmark()
    
    if results:
        print("\n" + "=" * 60)
        print("BENCHMARK-TEST ZAVERSHEN")
        print("=" * 60)
        print("Rezultaty sohraneny v benchmark_report.html")
        print("Otkrojte fajl v brauzere dlya prosmotra detalnogo analiza")
    else:
        print("\n[ERROR] Benchmark-test ne udalsya")
        sys.exit(1)
