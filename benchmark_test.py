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
            self.limit = 1000
            self.delay = 0
            self.max_time = None
            
            # Параметры отладки и вывода
            self.debug = True
            self.verbose = False
            self.quiet = False
            self.no_color = False
            
            # Параметры HTTP
            self.headers = []
            self.headers_file = None
            self.cookies = None
            self.auth = None
            self.proxy = None
            self.user_agent = None
            self.random_agent = False
            
            # Параметры фильтрации
            self.exclude = []
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
            self.page_limit = None
    
    scanner = None
    try:
        # Создаем конфигурацию с mock args
        mock_args = MockArgs()
        config = Config(mock_args)
        
        # Устанавливаем дополнительные параметры
        if hasattr(config, 'headers') and isinstance(config.headers, dict):
            config.headers.update({
                'User-Agent': 'Dominator Security Scanner - Benchmark Test'
            })
        else:
            config.headers = {
                'User-Agent': 'Dominator Security Scanner - Benchmark Test'
            }
        
        print(f"Tsel: {config.targets[0] if config.targets else 'N/A'}")
        print(f"Moduli: {', '.join(config.modules) if hasattr(config, 'modules') and config.modules else 'N/A'}")
        print(f"Potoki: {getattr(config, 'threads', 'N/A')}")
        print(f"Limit zaprosov: {getattr(config, 'request_limit', 'N/A')}")
        print("-" * 60)
        
        # Создаем и запускаем сканер
        scanner = VulnScanner(config)
        
        print("Nachinaem skanirovanie...")
        results = scanner.scan()
        
        print("\nSkanirovanie zaversheno!")
        print(f"Najdeno rezultatov: {len(results) if results else 0}")
        
        # Выводим результаты в консоль
        if results:
            scanner.print_results(results)
        
        # Сохраняем HTML отчет
        report_filename = "benchmark_report.html"
        if results:
            scanner.save_report(results, report_filename, 'html')
            print(f"\nOtchet sohranen: {report_filename}")
        else:
            print("\nNet rezultatov dlya sokhraneniya")
        
        # Проверяем наличие анализа бенчмарка
        benchmark_found = False
        if results:
            for result in results:
                if isinstance(result, dict) and 'benchmark_analysis' in result:
                    benchmark_found = True
                    break
        
        if benchmark_found:
            print("[OK] Analiz benchmarka vypolnen uspeshno!")
            print("[INFO] Proverte HTML otchet dlya detalnogo analiza effektivnosti")
            print("[INFO] Takzhe sozdan tekstovyj otchet benchmark_report_benchmark.txt")
        else:
            print("[WARNING] Analiz benchmarka ne byl vypolnen")
        
        return results
        
    except ImportError as e:
        print(f"Oshibka importa: {e}")
        print("Proverite, chto vse neobkhodimye moduli ustanovleny")
        return None
    except AttributeError as e:
        print(f"Oshibka atributa: {e}")
        print("Vozmozhno, nesovmestimost versij modulej")
        return None
    except Exception as e:
        print(f"Oshibka pri vypolnenii benchmarka: {e}")
        import traceback
        traceback.print_exc()
        return None
    finally:
        # Очистка ресурсов
        if scanner is not None:
            try:
                scanner.cleanup()
            except Exception as cleanup_error:
                print(f"Oshibka pri ochistke resursov: {cleanup_error}")

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
