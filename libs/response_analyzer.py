"""
Response analysis library
"""

import re
from typing import Dict, List, Tuple, Any, Optional
from difflib import SequenceMatcher

class ResponseAnalyzer:
    """Analyze HTTP responses for patterns and content"""
    
    def __init__(self):
        self.content_type_patterns = {
            'html': [r'<html', r'<head>', r'<body>', r'<!doctype'],
            'json': [r'^\s*{', r'^\s*\[', r'"[^"]+"\s*:', r'application/json'],
            'xml': [r'<\?xml', r'<[^>]+>', r'xmlns='],
            'javascript': [r'function\s*\(', r'var\s+\w+', r'document\.'],
            'css': [r'[^{}]+\s*{[^}]*}', r'@import', r'@media'],
            'php': [r'<\?php', r'<\?=', r'\$\w+'],
            'error': [r'error', r'exception', r'warning', r'fatal']
        }
    
    def analyze_response(self, response_text: str, response_code: int, 
                        response_headers: Dict[str, str] = None) -> Dict[str, Any]:
        """
        Comprehensive response analysis
        Returns analysis results
        """
        if response_headers is None:
            response_headers = {}
        
        analysis = {
            'content_type': self.detect_content_type(response_text, response_headers),
            'content_length': len(response_text),
            'has_forms': self.has_forms(response_text),
            'has_javascript': self.has_javascript(response_text),
            'has_errors': self.has_errors(response_text),
            'error_types': self.get_error_types(response_text),
            'is_empty': len(response_text.strip()) == 0,
            'is_redirect': response_code in [301, 302, 303, 307, 308],
            'is_error': response_code >= 400,
            'fingerprint': self.generate_fingerprint(response_text),
            'structure_score': self.calculate_structure_score(response_text)
        }
        
        return analysis
    
    def detect_content_type(self, response_text: str, headers: Dict[str, str]) -> str:
        """Detect content type from headers and content"""
        # Check headers first
        content_type = headers.get('content-type', '').lower()
        if 'html' in content_type:
            return 'html'
        elif 'json' in content_type:
            return 'json'
        elif 'xml' in content_type:
            return 'xml'
        elif 'javascript' in content_type:
            return 'javascript'
        elif 'css' in content_type:
            return 'css'
        
        # Analyze content patterns
        response_lower = response_text.lower()
        
        for content_type, patterns in self.content_type_patterns.items():
            matches = sum(1 for pattern in patterns 
                         if re.search(pattern, response_lower, re.IGNORECASE))
            if matches >= 2:  # Need at least 2 pattern matches
                return content_type
        
        return 'unknown'
    
    def has_forms(self, response_text: str) -> bool:
        """Check if response contains HTML forms"""
        return bool(re.search(r'<form[^>]*>', response_text, re.IGNORECASE))
    
    def has_javascript(self, response_text: str) -> bool:
        """Check if response contains JavaScript"""
        js_patterns = [
            r'<script[^>]*>', r'function\s*\(', r'var\s+\w+',
            r'document\.', r'window\.', r'onclick\s*='
        ]
        return any(re.search(pattern, response_text, re.IGNORECASE) 
                  for pattern in js_patterns)
    
    def has_errors(self, response_text: str) -> bool:
        """Check if response contains error messages"""
        error_patterns = [
            r'error', r'exception', r'warning', r'fatal',
            r'not found', r'access denied', r'forbidden'
        ]
        return any(re.search(pattern, response_text, re.IGNORECASE) 
                  for pattern in error_patterns)
    
    def get_error_types(self, response_text: str) -> List[str]:
        """Get types of errors found in response"""
        error_types = []
        response_lower = response_text.lower()
        
        error_patterns = {
            'php_error': [r'fatal error:', r'warning:', r'notice:', r'parse error:'],
            'mysql_error': [r'mysql_', r'mysqli_', r'sql syntax'],
            'file_error': [r'failed to open', r'no such file', r'permission denied'],
            'http_error': [r'not found', r'access denied', r'forbidden', r'internal server error'],
            'application_error': [r'exception', r'stack trace', r'error occurred']
        }
        
        for error_type, patterns in error_patterns.items():
            if any(re.search(pattern, response_lower) for pattern in patterns):
                error_types.append(error_type)
        
        return error_types
    
    def generate_fingerprint(self, response_text: str) -> str:
        """Generate response fingerprint for comparison"""
        import hashlib
        
        # Normalize response for fingerprinting
        normalized = re.sub(r'\s+', ' ', response_text.lower().strip())
        
        # Extract key characteristics
        characteristics = []
        
        # Length range
        length_range = (len(normalized) // 100) * 100
        characteristics.append(f"len:{length_range}")
        
        # Title
        title_match = re.search(r'<title[^>]*>(.*?)</title>', normalized)
        if title_match:
            title = title_match.group(1).strip()[:50]
            characteristics.append(f"title:{title}")
        
        # Error patterns
        if 'error' in normalized:
            characteristics.append("has_error")
        if 'not found' in normalized:
            characteristics.append("not_found")
        
        # Content structure
        if '<form' in normalized:
            characteristics.append("has_form")
        if 'function(' in normalized:
            characteristics.append("has_js")
        
        fingerprint_data = '|'.join(characteristics)
        return hashlib.md5(fingerprint_data.encode()).hexdigest()[:12]
    
    def calculate_structure_score(self, response_text: str) -> float:
        """Calculate structural complexity score (0.0 to 1.0)"""
        if not response_text.strip():
            return 0.0
        
        score = 0.0
        response_lower = response_text.lower()
        
        # HTML structure elements
        html_elements = ['<html', '<head', '<body', '<div', '<form', '<table']
        html_count = sum(1 for elem in html_elements if elem in response_lower)
        score += min(0.3, html_count * 0.05)
        
        # Interactive elements
        interactive_elements = ['<input', '<button', '<select', '<textarea']
        interactive_count = sum(1 for elem in interactive_elements if elem in response_lower)
        score += min(0.2, interactive_count * 0.05)
        
        # JavaScript elements
        js_elements = ['function(', 'var ', 'document.', 'window.']
        js_count = sum(1 for elem in js_elements if elem in response_lower)
        score += min(0.2, js_count * 0.05)
        
        # Content length factor
        length_factor = min(0.3, len(response_text) / 5000)
        score += length_factor
        
        return min(1.0, score)
    
    def compare_responses(self, response1: str, response2: str) -> float:
        """Compare two responses and return similarity score (0.0 to 1.0)"""
        return SequenceMatcher(None, response1, response2).ratio()
    
    def is_meaningful_content(self, response_text: str, min_length: int = 100) -> bool:
        """Check if response contains meaningful content"""
        if len(response_text.strip()) < min_length:
            return False
        
        # Remove HTML tags and check text content
        text_content = re.sub(r'<[^>]+>', '', response_text)
        text_content = re.sub(r'\s+', ' ', text_content).strip()
        
        if len(text_content) < min_length // 2:
            return False
        
        # Check for meaningful words (not just error messages)
        meaningful_patterns = [
            r'\b(login|register|search|contact|about|home|profile|settings)\b',
            r'\b(product|service|news|blog|gallery|portfolio)\b',
            r'\b(username|password|email|phone|address)\b'
        ]
        
        meaningful_count = sum(1 for pattern in meaningful_patterns 
                             if re.search(pattern, text_content, re.IGNORECASE))
        
        return meaningful_count > 0
    
    def extract_forms_data(self, response_text: str) -> List[Dict[str, Any]]:
        """Extract form data from HTML response"""
        forms = []
        
        form_pattern = r'<form[^>]*>(.*?)</form>'
        form_matches = re.findall(form_pattern, response_text, re.IGNORECASE | re.DOTALL)
        
        for form_content in form_matches:
            form_data = {
                'method': 'GET',
                'action': '',
                'inputs': []
            }
            
            # Extract method
            method_match = re.search(r'method\s*=\s*["\']?([^"\'>\s]+)', form_content, re.IGNORECASE)
            if method_match:
                form_data['method'] = method_match.group(1).upper()
            
            # Extract action
            action_match = re.search(r'action\s*=\s*["\']?([^"\'>\s]+)', form_content, re.IGNORECASE)
            if action_match:
                form_data['action'] = action_match.group(1)
            
            # Extract inputs
            input_pattern = r'<input[^>]*>'
            input_matches = re.findall(input_pattern, form_content, re.IGNORECASE)
            
            for input_tag in input_matches:
                input_data = {}
                
                # Extract input attributes
                name_match = re.search(r'name\s*=\s*["\']?([^"\'>\s]+)', input_tag, re.IGNORECASE)
                if name_match:
                    input_data['name'] = name_match.group(1)
                
                type_match = re.search(r'type\s*=\s*["\']?([^"\'>\s]+)', input_tag, re.IGNORECASE)
                if type_match:
                    input_data['type'] = type_match.group(1).lower()
                else:
                    input_data['type'] = 'text'
                
                value_match = re.search(r'value\s*=\s*["\']?([^"\'>\s]*)', input_tag, re.IGNORECASE)
                if value_match:
                    input_data['value'] = value_match.group(1)
                
                if input_data:
                    form_data['inputs'].append(input_data)
            
            forms.append(form_data)
        
        return forms
