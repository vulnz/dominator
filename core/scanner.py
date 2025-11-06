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
        """Main scanning method"""
        targets = self.config.get_targets()
        
        if not targets:
            raise ValueError("No targets found for scanning")
        
        print(f"Targets found: {len(targets)}")
        print(f"Modules: {', '.join(self.config.modules)}")
        print(f"Threads: {self.config.threads}")
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
                    print(f"Scanning error: {e}")
        
        return self.results
    
    def _scan_target(self, target: str) -> List[Dict[str, Any]]:
        """Scan single target"""
        target_results = []
        
        try:
            print(f"Scanning: {target}")
            
            # Парсинг URL и извлечение точек инъекции
            parsed_data = self.url_parser.parse(target)
            
            # Сканирование каждым модулем
            for module_name in self.config.modules:
                if self._should_stop():
                    break
                    
                module_results = self._run_module(module_name, parsed_data)
                target_results.extend(module_results)
            
        except Exception as e:
            print(f"Error scanning {target}: {e}")
        
        return target_results
    
    def _run_module(self, module_name: str, parsed_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Run scanning module"""
        results = []
        
        try:
            # Module loading and execution will be here
            # Placeholder for now
            print(f"  Module {module_name}: checking...")
            
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
            print(f"Error in module {module_name}: {e}")
        
        return results
    
    def _should_stop(self) -> bool:
        """Check scan stop conditions"""
        if self.config.request_limit and self.request_count >= self.config.request_limit:
            return True
        return False
    
    def save_report(self, results: List[Dict[str, Any]], filename: str, format_type: str):
        """Save report"""
        if format_type == 'json':
            self.file_handler.save_json(results, filename)
        elif format_type == 'xml':
            self.file_handler.save_xml(results, filename)
        elif format_type == 'html':
            self.file_handler.save_html(results, filename)
        else:
            self.file_handler.save_txt(results, filename)
    
    def print_results(self, results: List[Dict[str, Any]]):
        """Print results to console"""
        if not results:
            print("No vulnerabilities found")
            return
        
        print(f"\nVulnerabilities found: {len(results)}")
        print("=" * 60)
        
        for i, result in enumerate(results, 1):
            print(f"{i}. {result.get('vulnerability', 'Unknown')}")
            print(f"   Target: {result.get('target', '')}")
            print(f"   Module: {result.get('module', '')}")
            print(f"   Severity: {result.get('severity', '')}")
            print(f"   Parameter: {result.get('parameter', '')}")
            print("-" * 40)
