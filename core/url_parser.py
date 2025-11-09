"""
Module for URL parsing and injection point extraction
"""

import re
from urllib.parse import urlparse, parse_qs, urljoin
from typing import Dict, List, Any, Optional

class URLParser:
    """Class for URL parsing and data extraction"""
    
    def __init__(self):
        """Initialize parser"""
        self.injection_points = []
        
    def parse(self, target: str) -> Dict[str, Any]:
        """Main target parsing method"""
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
        
        # URL normalization
        normalized_url = self._normalize_url(target)
        result['url'] = normalized_url
        
        # URL parsing
        parsed = urlparse(normalized_url)
        result['scheme'] = parsed.scheme
        result['host'] = parsed.hostname or ''
        result['port'] = parsed.port
        result['path'] = parsed.path
        
        # Query parameters parsing
        result['query_params'] = parse_qs(parsed.query)
        
        # Extract injection points
        result['injection_points'] = self._extract_injection_points(result)
        
        return result
    
    def _normalize_url(self, target: str) -> str:
        """URL normalization"""
        # If no scheme, add http://
        if not target.startswith(('http://', 'https://')):
            # Check if there's a port
            if ':' in target and not target.startswith('//'):
                # Could be IP:port or domain:port
                target = f"http://{target}"
            else:
                target = f"http://{target}"
        
        return target
    
    def _extract_injection_points(self, parsed_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Extract injection points"""
        injection_points = []
        
        # GET parameters
        for param, values in parsed_data['query_params'].items():
            for value in values:
                injection_points.append({
                    'type': 'GET',
                    'parameter': param,
                    'value': value,
                    'location': 'query'
                })
        
        # URL path (for path traversal)
        if parsed_data['path']:
            injection_points.append({
                'type': 'PATH',
                'parameter': 'path',
                'value': parsed_data['path'],
                'location': 'path'
            })
        
        # Headers (will be added later during HTTP requests)
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
        """Extract URLs from server response"""
        urls = []
        
        # Regular expressions for URL search - improved to avoid quote issues
        patterns = [
            r'href=(["\'])([^"\']+?)\1',  # href attributes with proper quote matching
            r'src=(["\'])([^"\']+?)\1',   # src attributes with proper quote matching
            r'action=(["\'])([^"\']+?)\1', # form action attributes with proper quote matching
            r'url\((["\']?)([^"\')\s]+?)\1\)', # CSS url() with optional quotes
            r'href=([^\s>"\']+)',  # href without quotes
            r'window\.location\s*=\s*(["\'])([^"\']+?)\1',  # JavaScript redirects
            r'location\.href\s*=\s*(["\'])([^"\']+?)\1',  # JavaScript location
        ]
        
        print(f"    [URL_PARSER] Extracting URLs from response ({len(response_text)} chars)")
        
        for i, pattern in enumerate(patterns):
            matches = re.findall(pattern, response_text, re.IGNORECASE)
            print(f"    [URL_PARSER] Pattern {i+1} found {len(matches)} matches")
            
            for match in matches:
                try:
                    # Handle tuple matches from quote-capturing patterns
                    if isinstance(match, tuple):
                        # For patterns that capture quotes, take the URL part
                        if len(match) == 2:
                            url_part = match[1]  # Second element is the URL
                        else:
                            url_part = match[0]  # Fallback to first element
                    else:
                        url_part = match
                    
                    # Skip empty matches, anchors, and non-HTTP URLs
                    if not url_part or url_part.startswith('#') or url_part.startswith('mailto:') or url_part.startswith('javascript:'):
                        continue
                    
                    # Additional cleaning
                    url_part = url_part.strip('\'"').strip()
                    
                    # Skip if contains quotes (malformed)
                    if '"' in url_part or "'" in url_part:
                        continue
                    
                    # Convert relative URLs to absolute
                    try:
                        absolute_url = urljoin(base_url, url_part)
                        
                        # Validate the final URL
                        if not self._is_valid_url(absolute_url):
                            continue
                        
                        # Only include HTTP/HTTPS URLs from same domain
                        if (absolute_url.startswith(('http://', 'https://')) and 
                            absolute_url not in urls and
                            len(absolute_url) < 500 and  # Avoid extremely long URLs
                            self._is_same_domain(absolute_url, base_url)):
                            urls.append(absolute_url)
                            print(f"    [URL_PARSER] Added URL: {absolute_url}")
                    except Exception as e:
                        print(f"    [URL_PARSER] Error processing URL '{url_part}': {e}")
                        continue
                        
                except Exception as e:
                    print(f"    [URL_PARSER] Error processing match '{match}': {e}")
                    continue
        
        print(f"    [URL_PARSER] Total unique URLs found: {len(urls)}")
        return urls
    
    def _is_same_domain(self, url1: str, url2: str) -> bool:
        """Check if two URLs are from the same domain"""
        try:
            domain1 = urlparse(url1).netloc.lower()
            domain2 = urlparse(url2).netloc.lower()
            return domain1 == domain2
        except Exception:
            return False
    
    def _is_valid_url(self, url: str) -> bool:
        """Validate URL format and structure"""
        try:
            parsed = urlparse(url)
            
            # Must have scheme and netloc
            if not parsed.scheme or not parsed.netloc:
                return False
            
            # Must be HTTP or HTTPS
            if parsed.scheme not in ('http', 'https'):
                return False
            
            # Should not contain quotes
            if '"' in url or "'" in url:
                return False
            
            # Should not have malformed path with quotes
            if parsed.path and ('"' in parsed.path or "'" in parsed.path):
                return False
            
            return True
        except Exception:
            return False
    
    def extract_forms(self, response_text: str) -> List[Dict[str, Any]]:
        """Extract forms from HTML"""
        forms = []
        
        # Debug: показываем часть HTML для анализа
        print(f"    [URL_PARSER] Analyzing HTML content ({len(response_text)} chars)")
        if '<form' in response_text.lower():
            print(f"    [URL_PARSER] HTML contains '<form' tag")
        else:
            print(f"    [URL_PARSER] HTML does NOT contain '<form' tag")
        
        # Улучшенный парсинг форм с несколькими паттернами
        form_patterns = [
            r'<form[^>]*>(.*?)</form>',  # Стандартный паттерн
            r'<form[^>]*>[\s\S]*?</form>',  # Альтернативный с [\s\S]
            r'<FORM[^>]*>[\s\S]*?</FORM>',  # Верхний регистр
        ]
        
        forms_html = []
        for pattern in form_patterns:
            matches = re.findall(pattern, response_text, re.DOTALL | re.IGNORECASE)
            if matches:
                forms_html.extend(matches)
                print(f"    [URL_PARSER] Pattern '{pattern[:20]}...' found {len(matches)} forms")
                break
        
        # Если не нашли формы, попробуем найти хотя бы теги <form>
        if not forms_html:
            form_tags = re.findall(r'<form[^>]*>', response_text, re.IGNORECASE)
            print(f"    [URL_PARSER] Found {len(form_tags)} <form> opening tags")
            if form_tags:
                # Показываем найденные теги форм
                for i, tag in enumerate(form_tags[:3]):
                    print(f"    [URL_PARSER] Form tag {i+1}: {tag[:100]}...")
                
                # Попробуем извлечь содержимое между тегами вручную
                for tag in form_tags:
                    # Найдем позицию этого тега
                    tag_pos = response_text.lower().find(tag.lower())
                    if tag_pos >= 0:
                        # Найдем закрывающий тег
                        end_pos = response_text.lower().find('</form>', tag_pos)
                        if end_pos >= 0:
                            form_content = response_text[tag_pos:end_pos + 7]
                            forms_html.append(form_content)
        
        print(f"    [URL_PARSER] Found {len(forms_html)} forms in HTML")
        
        for i, form_html in enumerate(forms_html):
            form_data = {
                'method': 'GET',
                'action': '',
                'inputs': []
            }
            
            # Показываем содержимое формы для отладки
            print(f"    [URL_PARSER] Processing form {i+1} content: {form_html[:200]}...")
            
            # Extract method and action с улучшенными паттернами
            method_patterns = [
                r'method=["\']([^"\']+)["\']',
                r'method=([^\s>]+)',
                r'METHOD=["\']([^"\']+)["\']',
                r'METHOD=([^\s>]+)'
            ]
            
            for pattern in method_patterns:
                method_match = re.search(pattern, form_html, re.IGNORECASE)
                if method_match:
                    form_data['method'] = method_match.group(1).upper()
                    break
            
            action_patterns = [
                r'action=["\']([^"\']+)["\']',
                r'action=([^\s>]+)',
                r'ACTION=["\']([^"\']+)["\']',
                r'ACTION=([^\s>]+)'
            ]
            
            for pattern in action_patterns:
                action_match = re.search(pattern, form_html, re.IGNORECASE)
                if action_match:
                    form_data['action'] = action_match.group(1).strip('\'"')
                    break
            
            # Extract input fields с улучшенными паттернами
            input_patterns = [
                r'<input[^>]*>',
                r'<INPUT[^>]*>',
                r'<textarea[^>]*>.*?</textarea>',
                r'<TEXTAREA[^>]*>.*?</TEXTAREA>',
                r'<select[^>]*>.*?</select>',
                r'<SELECT[^>]*>.*?</SELECT>'
            ]
            
            inputs = []
            for pattern in input_patterns:
                matches = re.findall(pattern, form_html, re.IGNORECASE | re.DOTALL)
                inputs.extend(matches)
            
            print(f"    [URL_PARSER] Form {i+1}: Method={form_data['method']}, Action='{form_data['action']}', Found {len(inputs)} input elements")
            
            for j, input_html in enumerate(inputs):
                input_data = {}
                
                print(f"    [URL_PARSER] Processing input {j+1}: {input_html[:100]}...")
                
                # Extract input attributes с улучшенными паттернами
                name_patterns = [
                    r'name=["\']([^"\']+)["\']',
                    r'name=([^\s>]+)',
                    r'NAME=["\']([^"\']+)["\']',
                    r'NAME=([^\s>]+)'
                ]
                
                for pattern in name_patterns:
                    name_match = re.search(pattern, input_html, re.IGNORECASE)
                    if name_match:
                        input_data['name'] = name_match.group(1).strip('\'"')
                        break
                
                type_patterns = [
                    r'type=["\']([^"\']+)["\']',
                    r'type=([^\s>]+)',
                    r'TYPE=["\']([^"\']+)["\']',
                    r'TYPE=([^\s>]+)'
                ]
                
                input_data['type'] = 'text'  # default
                for pattern in type_patterns:
                    type_match = re.search(pattern, input_html, re.IGNORECASE)
                    if type_match:
                        input_data['type'] = type_match.group(1).strip('\'"')
                        break
                
                # Определяем тип элемента по тегу
                if input_html.lower().startswith('<textarea'):
                    input_data['type'] = 'textarea'
                elif input_html.lower().startswith('<select'):
                    input_data['type'] = 'select'
                
                value_patterns = [
                    r'value=["\']([^"\']*)["\']',
                    r'value=([^\s>]*)',
                    r'VALUE=["\']([^"\']*)["\']',
                    r'VALUE=([^\s>]*)'
                ]
                
                input_data['value'] = ''
                for pattern in value_patterns:
                    value_match = re.search(pattern, input_html, re.IGNORECASE)
                    if value_match:
                        input_data['value'] = value_match.group(1).strip('\'"')
                        break
                
                # Extract additional attributes
                placeholder_match = re.search(r'placeholder=["\']([^"\']*)["\']', input_html, re.IGNORECASE)
                if placeholder_match:
                    input_data['placeholder'] = placeholder_match.group(1)
                
                if 'name' in input_data and input_data['name']:
                    form_data['inputs'].append(input_data)
                    print(f"    [URL_PARSER] Form {i+1} Input {j+1}: name='{input_data['name']}', type='{input_data['type']}', value='{input_data['value'][:20]}{'...' if len(str(input_data['value'])) > 20 else ''}'")
                else:
                    print(f"    [URL_PARSER] Form {i+1} Input {j+1}: SKIPPED (no name attribute), type='{input_data['type']}', html='{input_html[:50]}...'")
            
            forms.append(form_data)
            
            # ЯВНЫЙ ВЫВОД ПАРАМЕТРОВ ФОРМ
            if form_data['method'] == 'GET':
                get_params = [inp['name'] for inp in form_data['inputs'] if inp.get('name')]
                print(f"    [URL_PARSER] *** GET FORM PARAMS EXTRACTED: {get_params} ***")
            elif form_data['method'] in ['POST', 'PUT']:
                post_params = [inp['name'] for inp in form_data['inputs'] if inp.get('name')]
                print(f"    [URL_PARSER] *** POST FORM PARAMS EXTRACTED: {post_params} ***")
        
        return forms
    
    def is_valid_target(self, target: str) -> bool:
        """Check target validity"""
        try:
            normalized = self._normalize_url(target)
            parsed = urlparse(normalized)
            return bool(parsed.hostname)
        except:
            return False
