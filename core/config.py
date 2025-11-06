"""
Конфигурация сканера
"""

import os
from typing import List, Dict, Optional

class Config:
    """Класс конфигурации сканера"""
    
    def __init__(self, args):
        """Инициализация конфигурации из аргументов"""
        self.target = args.target
        self.target_file = args.file
        self.headers = self._parse_headers(args.headers, args.headers_file)
        self.cookies = args.cookies
        self.auth_type = args.auth
        self.modules = self._parse_modules(args.modules, args.all)
        self.exclude_paths = self._parse_exclude(args.exclude)
        self.timeout = args.timeout
        self.threads = args.threads
        self.request_limit = args.limit
        self.page_limit = args.page_limit
        self.output_file = args.output
        self.output_format = args.format
        
        # Пути к папкам
        self.modules_dir = "modules"
        self.payloads_dir = "payloads"
        self.detectors_dir = "detectors"
        self.templates_dir = "report/templates"
        
    def _parse_headers(self, headers: Optional[List[str]], headers_file: Optional[str]) -> Dict[str, str]:
        """Парсинг HTTP заголовков"""
        result = {}
        
        # Из аргументов командной строки
        if headers:
            for header in headers:
                if ':' in header:
                    key, value = header.split(':', 1)
                    result[key.strip()] = value.strip()
        
        # Из файла
        if headers_file and os.path.exists(headers_file):
            with open(headers_file, 'r', encoding='utf-8') as f:
                for line in f:
                    line = line.strip()
                    if line and ':' in line:
                        key, value = line.split(':', 1)
                        result[key.strip()] = value.strip()
        
        return result
    
    def _parse_modules(self, modules_str: Optional[str], use_all: bool) -> List[str]:
        """Парсинг модулей сканирования"""
        if modules_str:
            return [m.strip() for m in modules_str.split(',')]
        elif use_all:
            return ['xss', 'sqli', 'lfi', 'rfi', 'xxe', 'csrf', 'idor', 'ssrf']
        else:
            return []
    
    def _parse_exclude(self, exclude_str: Optional[str]) -> List[str]:
        """Парсинг исключаемых путей"""
        if exclude_str:
            return [path.strip() for path in exclude_str.split(',')]
        return []
    
    def get_targets(self) -> List[str]:
        """Получить список целей для сканирования"""
        targets = []
        
        # Из параметра -t
        if self.target:
            targets.append(self.target)
        
        # Из файла
        if self.target_file and os.path.exists(self.target_file):
            with open(self.target_file, 'r', encoding='utf-8') as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#'):
                        targets.append(line)
        
        return targets
