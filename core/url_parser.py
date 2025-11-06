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
        
        # Regular expressions for URL search
        patterns = [
            r'href=["\']([^"\']+)["\']',  # href attributes
            r'src=["\']([^"\']+)["\']',   # src attributes
            r'action=["\']([^"\']+)["\']', # form action attributes
            r'url\(["\']?([^"\')\s]+)["\']?\)', # CSS url()
            r'href=([^\s>]+)',  # href without quotes
            r'<a[^>]+href=["\']?([^"\'>\s]+)["\']?[^>]*>',  # anchor tags
            r'<form[^>]+action=["\']?([^"\'>\s]+)["\']?[^>]*>',  # form actions
            r'window\.location\s*=\s*["\']([^"\']+)["\']',  # JavaScript redirects
            r'location\.href\s*=\s*["\']([^"\']+)["\']',  # JavaScript location
        ]
        
        print(f"    [URL_PARSER] Extracting URLs from response ({len(response_text)} chars)")
        
        for i, pattern in enumerate(patterns):
            matches = re.findall(pattern, response_text, re.IGNORECASE)
            print(f"    [URL_PARSER] Pattern {i+1} found {len(matches)} matches")
            
            for match in matches:
                try:
                    # Skip empty matches, anchors, and non-HTTP URLs
                    if not match or match.startswith('#') or match.startswith('mailto:') or match.startswith('javascript:'):
                        continue
                    
                    # Convert relative URLs to absolute
                    absolute_url = urljoin(base_url, match)
                    
                    # Only include HTTP/HTTPS URLs from same domain
                    if (absolute_url.startswith(('http://', 'https://')) and 
                        absolute_url not in urls and
                        len(absolute_url) < 500):  # Avoid extremely long URLs
                        urls.append(absolute_url)
                        print(f"    [URL_PARSER] Added URL: {absolute_url}")
                        
                except Exception as e:
                    print(f"    [URL_PARSER] Error processing match '{match}': {e}")
                    continue
        
        print(f"    [URL_PARSER] Total unique URLs found: {len(urls)}")
        return urls
    
    def extract_forms(self, response_text: str) -> List[Dict[str, Any]]:
        """Extract forms from HTML"""
        forms = []
        
        # Simple form parsing (can be improved with BeautifulSoup)
        form_pattern = r'<form[^>]*>(.*?)</form>'
        forms_html = re.findall(form_pattern, response_text, re.DOTALL | re.IGNORECASE)
        
        for form_html in forms_html:
            form_data = {
                'method': 'GET',
                'action': '',
                'inputs': []
            }
            
            # Extract method and action
            method_match = re.search(r'method=["\']([^"\']+)["\']', form_html, re.IGNORECASE)
            if method_match:
                form_data['method'] = method_match.group(1).upper()
            
            action_match = re.search(r'action=["\']([^"\']+)["\']', form_html, re.IGNORECASE)
            if action_match:
                form_data['action'] = action_match.group(1)
            
            # Extract input fields
            input_pattern = r'<input[^>]*>'
            inputs = re.findall(input_pattern, form_html, re.IGNORECASE)
            
            for input_html in inputs:
                input_data = {}
                
                # Extract input attributes
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
        """Check target validity"""
        try:
            normalized = self._normalize_url(target)
            parsed = urlparse(normalized)
            return bool(parsed.hostname)
        except:
            return False
