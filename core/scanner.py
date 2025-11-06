"""
Основной класс сканера уязвимостей
"""

import time
import json
from typing import List, Dict, Any
from concurrent.futures import ThreadPoolExecutor, as_completed

from core.config import Config
from core.url_parser import URLParser
from utils.file_handler import FileHandler

class VulnScanner:
    """Основной класс сканера уязвимостей"""
    
    def __init__(self, config: Config):
        """Инициализация сканера"""
        self.config = config
        self.url_parser = URLParser()
        self.file_handler = FileHandler()
        self.results = []
        self.request_count = 0
        
    def scan(self) -> List[Dict[str, Any]]:
        """Основной метод сканирования"""
        targets = self.config.get_targets()
        
        if not targets:
            raise ValueError("Не найдено целей для сканирования")
        
        print(f"Найдено целей: {len(targets)}")
        print(f"Модули: {', '.join(self.config.modules)}")
        print(f"Потоков: {self.config.threads}")
        print("-" * 50)
        
        # Многопоточное сканирование
        with ThreadPoolExecutor(max_workers=self.config.threads) as executor:
            futures = []
            
            for target in targets:
                if self._should_stop():
                    break
                    
                future = executor.submit(self._scan_target, target)
                futures.append(future)
            
            # Сбор результатов
            for future in as_completed(futures):
                try:
                    result = future.result()
                    if result:
                        self.results.extend(result)
                except Exception as e:
                    print(f"Ошибка при сканировании: {e}")
        
        return self.results
    
    def _scan_target(self, target: str) -> List[Dict[str, Any]]:
        """Сканирование одной цели"""
        target_results = []
        
        try:
            print(f"Сканирование: {target}")
            
            # Парсинг URL и извлечение точек инъекции
            parsed_data = self.url_parser.parse(target)
            
            # Сканирование каждым модулем
            for module_name in self.config.modules:
                if self._should_stop():
                    break
                    
                module_results = self._run_module(module_name, parsed_data)
                target_results.extend(module_results)
            
        except Exception as e:
            print(f"Ошибка при сканировании {target}: {e}")
        
        return target_results
    
    def _run_module(self, module_name: str, parsed_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Запуск модуля сканирования"""
        results = []
        
        try:
            # Здесь будет загрузка и запуск модуля
            # Пока что заглушка
            print(f"  Модуль {module_name}: проверка...")
            
            # Имитация работы модуля
            time.sleep(0.1)
            self.request_count += 1
            
            # Пример результата
            if module_name == "xss":
                results.append({
                    'module': module_name,
                    'target': parsed_data.get('url', ''),
                    'vulnerability': 'Reflected XSS',
                    'severity': 'Medium',
                    'parameter': 'search',
                    'payload': '<script>alert(1)</script>',
                    'evidence': 'Script executed in response'
                })
            
        except Exception as e:
            print(f"Ошибка в модуле {module_name}: {e}")
        
        return results
    
    def _should_stop(self) -> bool:
        """Проверка условий остановки сканирования"""
        if self.config.request_limit and self.request_count >= self.config.request_limit:
            return True
        return False
    
    def save_report(self, results: List[Dict[str, Any]], filename: str, format_type: str):
        """Сохранение отчета"""
        if format_type == 'json':
            self.file_handler.save_json(results, filename)
        elif format_type == 'xml':
            self.file_handler.save_xml(results, filename)
        elif format_type == 'html':
            self.file_handler.save_html(results, filename)
        else:
            self.file_handler.save_txt(results, filename)
    
    def print_results(self, results: List[Dict[str, Any]]):
        """Вывод результатов в консоль"""
        if not results:
            print("Уязвимости не найдены")
            return
        
        print(f"\nНайдено уязвимостей: {len(results)}")
        print("=" * 60)
        
        for i, result in enumerate(results, 1):
            print(f"{i}. {result.get('vulnerability', 'Unknown')}")
            print(f"   Цель: {result.get('target', '')}")
            print(f"   Модуль: {result.get('module', '')}")
            print(f"   Серьезность: {result.get('severity', '')}")
            print(f"   Параметр: {result.get('parameter', '')}")
            print("-" * 40)
