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
            self.targets = ['http://testphp.vulnweb.com/']
            self.modules = 'xss,sqli,lfi,ssrf,dirbrute,infoleak'
            self.threads = 5
            self.timeout = 10
            self.request_limit = 1000
            self.debug = True
            self.headers = None
            self.headers_file = None
            self.exclude = None
            self.use_all = False
            self.filetree_mode = False
            self.single_url = False
            self.nocrawl = False
            self.max_time = None
    
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
