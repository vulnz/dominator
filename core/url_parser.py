"""
Модуль для парсинга URL и извлечения точек инъекции
"""

import re
from urllib.parse import urlparse, parse_qs, urljoin
from typing import Dict, List, Any, Optional

class URLParser:
    """Класс для парсинга URL и извлечения данных"""
    
    def __init__(self):
        """Инициализация парсера"""
        self.injection_points = []
        
    def parse(self, target: str) -> Dict[str, Any]:
        """Основной метод парсинга цели"""
        result = {
            'original_target': target,
            'url': '',
            'scheme': '',
            'host': '',
            'port': None,
            'path': '',
            'query_params': {},
            'injection_points': [],
            'forms': [],
            'cookies': [],
            'headers': []
        }
        
        # Нормализация URL
        normalized_url = self._normalize_url(target)
        result['url'] = normalized_url
        
        # Парсинг URL
        parsed = urlparse(normalized_url)
        result['scheme'] = parsed.scheme
        result['host'] = parsed.hostname or ''
        result['port'] = parsed.port
        result['path'] = parsed.path
        
        # Парсинг параметров запроса
        result['query_params'] = parse_qs(parsed.query)
        
        # Извлечение точек инъекции
        result['injection_points'] = self._extract_injection_points(result)
        
        return result
    
    def _normalize_url(self, target: str) -> str:
        """Нормализация URL"""
        # Если нет схемы, добавляем http://
        if not target.startswith(('http://', 'https://')):
            # Проверяем, есть ли порт
            if ':' in target and not target.startswith('//'):
                # Может быть IP:port или domain:port
                target = f"http://{target}"
            else:
                target = f"http://{target}"
        
        return target
    
    def _extract_injection_points(self, parsed_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Извлечение точек инъекции"""
        injection_points = []
        
        # GET параметры
        for param, values in parsed_data['query_params'].items():
            for value in values:
                injection_points.append({
                    'type': 'GET',
                    'parameter': param,
                    'value': value,
                    'location': 'query'
                })
        
        # Путь URL (для path traversal)
        if parsed_data['path']:
            injection_points.append({
                'type': 'PATH',
                'parameter': 'path',
                'value': parsed_data['path'],
                'location': 'path'
            })
        
        # Заголовки (будут добавлены позже при HTTP запросах)
        common_headers = ['User-Agent', 'Referer', 'X-Forwarded-For', 'X-Real-IP']
        for header in common_headers:
            injection_points.append({
                'type': 'HEADER',
                'parameter': header,
                'value': '',
                'location': 'header'
            })
        
        return injection_points
    
    def extract_urls_from_response(self, response_text: str, base_url: str) -> List[str]:
        """Извлечение URL из ответа сервера"""
        urls = []
        
        # Регулярные выражения для поиска URL
        patterns = [
            r'href=["\']([^"\']+)["\']',  # href атрибуты
            r'src=["\']([^"\']+)["\']',   # src атрибуты
            r'action=["\']([^"\']+)["\']', # action атрибуты форм
            r'url\(["\']?([^"\')\s]+)["\']?\)', # CSS url()
        ]
        
        for pattern in patterns:
            matches = re.findall(pattern, response_text, re.IGNORECASE)
            for match in matches:
                # Преобразование относительных URL в абсолютные
                absolute_url = urljoin(base_url, match)
                if absolute_url not in urls:
                    urls.append(absolute_url)
        
        return urls
    
    def extract_forms(self, response_text: str) -> List[Dict[str, Any]]:
        """Извлечение форм из HTML"""
        forms = []
        
        # Простой парсинг форм (можно улучшить с помощью BeautifulSoup)
        form_pattern = r'<form[^>]*>(.*?)</form>'
        forms_html = re.findall(form_pattern, response_text, re.DOTALL | re.IGNORECASE)
        
        for form_html in forms_html:
            form_data = {
                'method': 'GET',
                'action': '',
                'inputs': []
            }
            
            # Извлечение метода и action
            method_match = re.search(r'method=["\']([^"\']+)["\']', form_html, re.IGNORECASE)
            if method_match:
                form_data['method'] = method_match.group(1).upper()
            
            action_match = re.search(r'action=["\']([^"\']+)["\']', form_html, re.IGNORECASE)
            if action_match:
                form_data['action'] = action_match.group(1)
            
            # Извлечение input полей
            input_pattern = r'<input[^>]*>'
            inputs = re.findall(input_pattern, form_html, re.IGNORECASE)
            
            for input_html in inputs:
                input_data = {}
                
                # Извлечение атрибутов input
                name_match = re.search(r'name=["\']([^"\']+)["\']', input_html, re.IGNORECASE)
                if name_match:
                    input_data['name'] = name_match.group(1)
                
                type_match = re.search(r'type=["\']([^"\']+)["\']', input_html, re.IGNORECASE)
                input_data['type'] = type_match.group(1) if type_match else 'text'
                
                value_match = re.search(r'value=["\']([^"\']*)["\']', input_html, re.IGNORECASE)
                input_data['value'] = value_match.group(1) if value_match else ''
                
                if 'name' in input_data:
                    form_data['inputs'].append(input_data)
            
            forms.append(form_data)
        
        return forms
    
    def is_valid_target(self, target: str) -> bool:
        """Проверка валидности цели"""
        try:
            normalized = self._normalize_url(target)
            parsed = urlparse(normalized)
            return bool(parsed.hostname)
        except:
            return False
