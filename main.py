#!/usr/bin/env python3
"""
Web Vulnerability Scanner
Основной файл для запуска сканера
"""

import argparse
import sys
import os
from core.scanner import VulnScanner
from core.config import Config
from utils.file_handler import FileHandler

def create_parser():
    """Создание парсера аргументов командной строки"""
    parser = argparse.ArgumentParser(
        description='Web Vulnerability Scanner',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Примеры использования:
  python main.py -t example.com
  python main.py -t 192.168.1.1:8080
  python main.py -t https://example.com/path
  python main.py -f targets.txt -m xss,sqli
  python main.py -t example.com -c "session=abc123" -H "User-Agent: Custom"
  python main.py -t example.com -a jwt -o report.html --timeout 30
        """
    )
    
    # Основные параметры
    parser.add_argument('-t', '--target', 
                       help='Цель сканирования (IP, домен, URL, IP:порт, URL:порт, подсеть)')
    parser.add_argument('-f', '--file', 
                       help='Файл с целями для сканирования')
    
    # HTTP параметры
    parser.add_argument('-H', '--headers', action='append',
                       help='HTTP заголовки (можно использовать несколько раз)')
    parser.add_argument('-hf', '--headers-file',
                       help='Файл с HTTP заголовками')
    parser.add_argument('-c', '--cookies',
                       help='HTTP cookies')
    parser.add_argument('-a', '--auth',
                       choices=['jwt', 'basic'],
                       help='Тип авторизации')
    
    # Параметры сканирования
    parser.add_argument('-m', '--modules', 
                       help='Модули сканирования (через запятую)')
    parser.add_argument('--all', action='store_true', default=True,
                       help='Использовать все модули (по умолчанию)')
    parser.add_argument('--exclude',
                       help='Исключить пути из сканирования')
    parser.add_argument('--timeout', type=int, default=10,
                       help='Таймаут запросов в секундах')
    parser.add_argument('--threads', type=int, default=10,
                       help='Количество потоков')
    parser.add_argument('--limit', type=int,
                       help='Лимит запросов перед завершением')
    parser.add_argument('--page-limit', type=int,
                       help='Лимит страниц для сканирования')
    
    # Отчеты
    parser.add_argument('-o', '--output',
                       help='Файл для сохранения отчета')
    parser.add_argument('--format', 
                       choices=['xml', 'json', 'txt', 'html'],
                       default='txt',
                       help='Формат отчета')
    
    # Информационные команды
    parser.add_argument('--modules-list', action='store_true',
                       help='Показать все доступные модули')
    parser.add_argument('--help-examples', action='store_true',
                       help='Показать примеры использования')
    
    return parser

def show_modules():
    """Показать все доступные модули"""
    print("Доступные модули сканирования:")
    print("- xss: Cross-Site Scripting")
    print("- sqli: SQL Injection")
    print("- lfi: Local File Inclusion")
    print("- rfi: Remote File Inclusion")
    print("- xxe: XML External Entity")
    print("- csrf: Cross-Site Request Forgery")
    print("- idor: Insecure Direct Object Reference")
    print("- ssrf: Server-Side Request Forgery")

def main():
    """Основная функция"""
    parser = create_parser()
    args = parser.parse_args()
    
    # Показать модули и выйти
    if args.modules_list:
        show_modules()
        return
    
    # Проверить обязательные параметры
    if not args.target and not args.file:
        print("Ошибка: Необходимо указать цель (-t) или файл с целями (-f)")
        parser.print_help()
        sys.exit(1)
    
    try:
        # Создать конфигурацию
        config = Config(args)
        
        # Создать сканер
        scanner = VulnScanner(config)
        
        # Запустить сканирование
        print(f"Запуск сканирования...")
        results = scanner.scan()
        
        # Сохранить результаты
        if args.output:
            scanner.save_report(results, args.output, args.format)
            print(f"Отчет сохранен в {args.output}")
        else:
            scanner.print_results(results)
            
    except KeyboardInterrupt:
        print("\nСканирование прервано пользователем")
        sys.exit(1)
    except Exception as e:
        print(f"Ошибка: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
