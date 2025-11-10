"""
Passive IDOR (Insecure Direct Object Reference) detector
Analyzes HTTP responses to discover potential IDOR vulnerabilities
"""

import re
from typing import Dict, List, Tuple, Any

class IDORDetector:
    """Passive IDOR vulnerability detection"""
    
    @staticmethod
    def analyze(response_text: str, url: str, headers: Dict[str, str]) -> Tuple[bool, List[Dict[str, Any]]]:
        """
        Passive IDOR vulnerability analysis
        
        Args:
            response_text: HTTP response body
            url: Current URL being analyzed
            headers: HTTP response headers
            
        Returns:
            Tuple[bool, List[Dict]]: (has_findings, list_of_findings)
        """
        findings = []
        
        # Проверка URL на IDOR-уязвимые паттерны
        idor_url_patterns = [
            (r'[?&]id=(\d+)', 'ID Parameter'),
            (r'[?&]user_?id=(\d+)', 'User ID Parameter'),
            (r'[?&]account_?id=(\d+)', 'Account ID Parameter'),
            (r'[?&]profile_?id=(\d+)', 'Profile ID Parameter'),
            (r'[?&]item_?id=(\d+)', 'Item ID Parameter'),
            (r'[?&]item=([^&]+)', 'Item Parameter'),
            (r'[?&]itemcode=([^&]+)', 'Item Code Parameter'),
            (r'[?&]code=([^&]+)', 'Code Parameter'),
            (r'[?&]product_?id=(\d+)', 'Product ID Parameter'),
            (r'[?&]product=([^&]+)', 'Product Parameter'),
            (r'[?&]doc_?id=(\d+)', 'Document ID Parameter'),
            (r'[?&]file_?id=(\d+)', 'File ID Parameter'),
            (r'[?&]record_?id=(\d+)', 'Record ID Parameter'),
            (r'[?&]entry_?id=(\d+)', 'Entry ID Parameter'),
            (r'/users?/(\d+)', 'User Path ID'),
            (r'/profiles?/(\d+)', 'Profile Path ID'),
            (r'/accounts?/(\d+)', 'Account Path ID'),
            (r'/items?/(\d+)', 'Item Path ID'),
            (r'/products?/(\d+)', 'Product Path ID'),
        ]
        
        for pattern, param_type in idor_url_patterns:
            matches = re.findall(pattern, url, re.IGNORECASE)
            if matches:
                # Анализ ответа на наличие пользовательских данных
                user_data_found = IDORDetector._check_user_data(response_text)
                sensitive_data_found = IDORDetector._check_sensitive_data(response_text)
                item_data_found = IDORDetector._check_item_data(response_text)
                database_content_found = IDORDetector._check_database_content(response_text)
                
                # Определение серьезности
                severity = 'Low'
                if sensitive_data_found:
                    severity = 'High'
                elif user_data_found or item_data_found:
                    severity = 'Medium'
                elif database_content_found or len(response_text) > 500:  # Значительный контент
                    severity = 'Medium'
                
                findings.append({
                    'type': 'idor_potential',
                    'severity': severity,
                    'url': url,
                    'parameter_type': param_type,
                    'parameter_values': matches[:3],
                    'has_user_data': user_data_found,
                    'has_sensitive_data': sensitive_data_found,
                    'has_item_data': item_data_found,
                    'has_database_content': database_content_found,
                    'response_size': len(response_text),
                    'description': f'Potential IDOR vulnerability: {param_type} found in URL',
                    'recommendation': 'Implement proper authorization checks for object access',
                    'evidence': {
                        'url_pattern': pattern,
                        'found_values': matches[:3],
                        'response_analysis': {
                            'contains_user_data': user_data_found,
                            'contains_sensitive_data': sensitive_data_found,
                            'contains_item_data': item_data_found,
                            'contains_database_content': database_content_found,
                            'response_length': len(response_text)
                        }
                    }
                })
        
        # Проверка на прямые ссылки на объекты в ответе
        object_ref_patterns = [
            (r'href=["\']?[^"\']*[?&]id=\d+', 'Direct Object Links'),
            (r'href=["\']?[^"\']*[?&]user_id=\d+', 'User Object Links'),
            (r'action=["\']?[^"\']*[?&]id=\d+', 'Form Object References'),
            (r'data-id=["\']?\d+["\']?', 'Data ID Attributes'),
        ]
        
        for pattern, ref_type in object_ref_patterns:
            matches = re.findall(pattern, response_text, re.IGNORECASE)
            if matches and len(matches) > 2:  # Только если много ссылок
                findings.append({
                    'type': 'object_references',
                    'severity': 'Medium',
                    'url': url,
                    'reference_type': ref_type,
                    'count': len(matches),
                    'description': f'{ref_type} found in response ({len(matches)} occurrences)',
                    'recommendation': 'Use indirect object references or implement access controls',
                    'evidence': {
                        'pattern_matches': matches[:5],
                        'total_count': len(matches)
                    }
                })
        
        return len(findings) > 0, findings
    
    @staticmethod
    def _check_user_data(response_text: str) -> bool:
        """Check if response contains user-specific data"""
        user_indicators = [
            r'user\s*:\s*\w+',
            r'username\s*:\s*\w+',
            r'name\s*:\s*[a-zA-Z\s]+',
            r'email\s*:\s*\S+@\S+',
            r'profile\s+(?:of|for)\s+\w+',
            r'welcome\s+\w+',
            r'hello\s+\w+',
            r'logged\s+in\s+as\s+\w+',
        ]
        
        for pattern in user_indicators:
            if re.search(pattern, response_text, re.IGNORECASE):
                return True
        
        return False
    
    @staticmethod
    def _check_sensitive_data(response_text: str) -> bool:
        """Check if response contains sensitive data"""
        sensitive_patterns = [
            r'password\s*[:=]\s*\S+',
            r'ssn\s*[:=]\s*[\d\-]+',
            r'credit.?card\s*[:=]\s*[\d\-\s]+',
            r'phone\s*[:=]\s*[\d\-\+\(\)\s]+',
            r'address\s*[:=]\s*[^,\n]+',
            r'salary\s*[:=]\s*[\d,\.]+',
            r'balance\s*[:=]\s*[\d,\.]+',
        ]
        
        for pattern in sensitive_patterns:
            if re.search(pattern, response_text, re.IGNORECASE):
                return True
        
        return False
    
    @staticmethod
    def _check_item_data(response_text: str) -> bool:
        """Check if response contains item/product data that could indicate IDOR"""
        item_indicators = [
            r'item\s*(?:code|name|id)\s*[:=]\s*\S+',
            r'product\s*(?:code|name|id)\s*[:=]\s*\S+',
            r'<b>\s*item\s+(?:code|name)\s*:\s*</b>',
            r'<b>\s*product\s+(?:code|name)\s*:\s*</b>',
            r'<td><b>item\s+(?:code|name)',
            r'<td><b>product\s+(?:code|name)',
            r'price\s*[:=]\s*[\d,\.]+\$?',
            r'category\s*[:=]\s*\w+',
            r'description\s*[:=]\s*\S+',
            r'<b>\s*(?:price|category|description)\s*:\s*</b>',
        ]
        
        for pattern in item_indicators:
            if re.search(pattern, response_text, re.IGNORECASE):
                return True
        
        return False
    
    @staticmethod
    def _check_database_content(response_text: str) -> bool:
        """Check if response contains structured database content"""
        db_indicators = [
            r'<table>.*</table>',
            r'<tr><td><b>.*:</b>.*</td>',
            r'htmlspecialchars\(',
            r'fetch\(PDO::FETCH_NUM\)',
            r'while\(\$rows\s*=',
            r'<option\s+value=',
            r'select.*from.*where',
        ]
        
        for pattern in db_indicators:
            if re.search(pattern, response_text, re.IGNORECASE | re.DOTALL):
                return True
        
        return False
