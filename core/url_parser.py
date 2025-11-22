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
            'params': {},  # Changed from query_params to params for compatibility with modules
            'query_params': {},  # Keep for backward compatibility
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

        # Query parameters parsing - convert parse_qs result to simple dict
        query_dict = parse_qs(parsed.query)
        # parse_qs returns lists, but we just want the first value for each param
        simple_params = {k: v[0] if v else '' for k, v in query_dict.items()}
        result['params'] = simple_params  # Modules expect this key
        result['query_params'] = simple_params  # Backward compatibility
        
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

        # Найдем все открывающие теги <form>
        form_start_pattern = r'<form[^>]*>'
        form_starts = []

        for match in re.finditer(form_start_pattern, response_text, re.IGNORECASE):
            form_starts.append({
                'start_pos': match.start(),
                'end_pos': match.end(),
                'tag': match.group(0)
            })
        
        forms_html = []
        
        # Для каждого открывающего тега найдем соответствующий закрывающий
        for i, form_start in enumerate(form_starts):
            # Ищем закрывающий тег </form> после текущего открывающего тега
            search_start = form_start['end_pos']
            
            # Найдем позицию закрывающего тега
            close_pattern = r'</form>'
            close_match = re.search(close_pattern, response_text[search_start:], re.IGNORECASE)
            
            if close_match:
                # Вычисляем абсолютную позицию закрывающего тега
                close_start = search_start + close_match.start()
                close_end = search_start + close_match.end()
                
                # Извлекаем полное содержимое формы
                full_form = response_text[form_start['start_pos']:close_end]
                forms_html.append(full_form)
            else:
                # Попробуем взять содержимое до конца документа или до следующей формы
                if i + 1 < len(form_starts):
                    # До следующей формы
                    next_form_pos = form_starts[i + 1]['start_pos']
                    partial_form = response_text[form_start['start_pos']:next_form_pos]
                else:
                    # До конца документа
                    partial_form = response_text[form_start['start_pos']:]
                
                # Добавляем закрывающий тег
                partial_form += '</form>'
                forms_html.append(partial_form)
        
        for i, form_html in enumerate(forms_html):
            form_data = {
                'method': 'GET',
                'action': '',
                'inputs': []
            }
            
            # Extract method and action
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
            
            # Extract input fields
            input_patterns = [
                r'<input[^>]*/?>',
                r'<input[^>]*>',
                r'<INPUT[^>]*/?>',
                r'<INPUT[^>]*>',
                r'<textarea[^>]*>.*?</textarea>',
                r'<TEXTAREA[^>]*>.*?</TEXTAREA>',
                r'<select[^>]*>.*?</select>',
                r'<SELECT[^>]*>.*?</SELECT>',
                # Handle unclosed/broken select tags - just extract opening tag
                r'<select[^>]*>',
                r'<SELECT[^>]*>'
            ]
            
            inputs = []
            for pattern in input_patterns:
                matches = re.findall(pattern, form_html, re.IGNORECASE | re.DOTALL)
                for match in matches:
                    if match not in inputs:
                        inputs.append(match)

            for input_html in inputs:
                input_data = {}

                # Extract input attributes
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
                    # Extract first option value from select
                    option_match = re.search(r'<option[^>]+value=["\']([^"\']+)["\']', input_html, re.IGNORECASE)
                    if option_match:
                        input_data['value'] = option_match.group(1)
                    else:
                        # Try to get any option text content
                        option_text = re.search(r'<option[^>]*>([^<]+)</option>', input_html, re.IGNORECASE)
                        if option_text:
                            input_data['value'] = option_text.group(1).strip()
                        else:
                            input_data['value'] = '1'  # Default value for select

                value_patterns = [
                    r'value=["\']([^"\']*)["\']',
                    r'value=([^\s>]*)',
                    r'VALUE=["\']([^"\']*)["\']',
                    r'VALUE=([^\s>]*)'
                ]

                if 'value' not in input_data or not input_data['value']:
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

            forms.append(form_data)

        return forms
    
    def is_valid_target(self, target: str) -> bool:
        """Check target validity"""
        try:
            normalized = self._normalize_url(target)
            parsed = urlparse(normalized)
            return bool(parsed.hostname)
        except:
            return False
