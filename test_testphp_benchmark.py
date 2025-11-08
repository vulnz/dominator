#!/usr/bin/env python3
"""
Тест для TestPHP Benchmark
"""

import sys
import os
import locale

# Настройка кодировки для Windows
if sys.platform.startswith('win'):
    import codecs
    sys.stdout = codecs.getwriter('utf-8')(sys.stdout.detach())
    sys.stderr = codecs.getwriter('utf-8')(sys.stderr.detach())

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from analysis.testphp_benchmark import TestPHPBenchmark

def test_benchmark_basic():
    """Базовый тест функциональности бенчмарка"""
    print("Инициализация TestPHP Benchmark...")
    benchmark = TestPHPBenchmark()
    
    print(f"Загружено известных уязвимостей: {benchmark._count_total_known_vulnerabilities()}")
    print(f"XSS уязвимостей: {len(benchmark.known_vulnerabilities['xss'])}")
    print(f"SQL Injection уязвимостей: {len(benchmark.known_vulnerabilities['sqli'])}")
    print(f"LFI уязвимостей: {len(benchmark.known_vulnerabilities['lfi'])}")
    print(f"Чувствительных файлов: {len(benchmark.known_files)}")
    print(f"Директорий: {len(benchmark.known_directories)}")
    print(f"Случаев утечки информации: {len(benchmark.known_info_disclosure)}")
    
    # Тестовые результаты сканирования
    mock_scan_results = [
        {
            'module': 'xss',
            'vulnerability': 'Reflected XSS',
            'target': 'http://testphp.vulnweb.com/listproducts.php?cat=test',
            'parameter': 'cat',
            'severity': 'High'
        },
        {
            'module': 'sqli',
            'vulnerability': 'SQL Injection',
            'target': 'http://testphp.vulnweb.com/artists.php?artist=1',
            'parameter': 'artist',
            'severity': 'Critical'
        },
        {
            'module': 'dirbrute',
            'vulnerability': 'Directory Found',
            'request_url': 'http://testphp.vulnweb.com/Flash/',
            'severity': 'Info'
        },
        {
            'module': 'infoleak',
            'vulnerability': 'Information Disclosure',
            'target': 'http://testphp.vulnweb.com/secured/phpinfo.php',
            'evidence': 'PHP/5.1.6',
            'severity': 'Medium'
        }
    ]
    
    print("\nАнализ тестовых результатов...")
    analysis = benchmark.analyze_scan_results(mock_scan_results)
    
    print(f"Общий коэффициент обнаружения: {analysis['summary']['detection_rate']:.1f}%")
    print(f"Коэффициент ложных срабатываний: {analysis['summary']['false_positive_rate']:.1f}%")
    
    print("\nДетали по категориям:")
    for category, data in analysis['by_category'].items():
        if data['total_known'] > 0:
            print(f"  {category.upper()}: {data['detection_rate']:.1f}% ({len(data['correctly_identified'])}/{data['total_known']})")
    
    print("\nГенерация отчета...")
    report = benchmark.generate_benchmark_report(analysis)
    print("Отчет сгенерирован успешно!")
    
    # Сохранение отчета в файл
    with open('testphp_benchmark_report.txt', 'w', encoding='utf-8') as f:
        f.write(report)
    print("Отчет сохранен в testphp_benchmark_report.txt")
    
    return True

def test_vulnerability_matching():
    """Тест сопоставления уязвимостей"""
    print("\nТест сопоставления уязвимостей...")
    benchmark = TestPHPBenchmark()
    
    # Тест известной XSS уязвимости
    known_vuln = {
        'method': 'GET',
        'url': 'http://testphp.vulnweb.com/listproducts.php',
        'parameter': 'cat',
        'type': 'reflected_xss'
    }
    
    found_vuln = {
        'module': 'xss',
        'vulnerability': 'Reflected XSS',
        'target': 'http://testphp.vulnweb.com/listproducts.php?cat=test',
        'parameter': 'cat'
    }
    
    is_match = benchmark._is_vulnerability_match(known_vuln, found_vuln)
    confidence = benchmark._calculate_match_confidence(known_vuln, found_vuln)
    
    print(f"Совпадение уязвимости: {is_match}")
    print(f"Уверенность в совпадении: {confidence:.2f}")
    
    return is_match

def main():
    """Главная функция теста"""
    # Дополнительная настройка кодировки
    try:
        if sys.platform.startswith('win'):
            os.system('chcp 65001 >nul 2>&1')
    except:
        pass
    
    print("=" * 60)
    print("ТЕСТ TESTPHP BENCHMARK")
    print("=" * 60)
    
    try:
        # Базовый тест
        success1 = test_benchmark_basic()
        
        # Тест сопоставления
        success2 = test_vulnerability_matching()
        
        if success1 and success2:
            print("\n[OK] Все тесты прошли успешно!")
            return 0
        else:
            print("\n[FAIL] Некоторые тесты не прошли!")
            return 1
            
    except Exception as e:
        print(f"\n[ERROR] Ошибка при выполнении тестов: {e}")
        import traceback
        traceback.print_exc()
        return 1

if __name__ == "__main__":
    exit(main())
