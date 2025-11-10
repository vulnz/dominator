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
                
                # Generate test values for manual testing
                test_suggestions = []
                proof_examples = {}
                if matches:
                    original_value = matches[0]
                    param_name = IDORDetector._extract_parameter_name(pattern)
                    test_values = IDORDetector._generate_test_values(original_value, param_name)
                    
                    # Generate detailed proof examples
                    proof_examples = IDORDetector.generate_idor_proof_examples(url, param_name, original_value)
                    
                    # For item parameters, show specific sequential test values
                    if 'item' in param_name.lower():
                        specific_test_values = ['0', '1', '2', '3', '4']
                        for test_value in specific_test_values:
                            if test_value != original_value:
                                test_url = url.replace(f'{param_name}={original_value}', f'{param_name}={test_value}')
                                test_suggestions.append({
                                    'test_value': test_value,
                                    'test_url': test_url,
                                    'description': f'Test with {param_name}={test_value}',
                                    'expected_result': f'Different item data should be returned if IDOR exists'
                                })
                    else:
                        for test_value in test_values:
                            test_url = url.replace(f'{param_name}={original_value}', f'{param_name}={test_value}')
                            test_suggestions.append({
                                'test_value': test_value,
                                'test_url': test_url,
                                'description': f'Test with {param_name}={test_value}',
                                'expected_result': f'Should show different content if IDOR exists'
                            })
                
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
                    'test_suggestions': test_suggestions[:3],  # First 3 test suggestions
                    'proof_examples': proof_examples,
                    'description': f'Potential IDOR vulnerability: {param_type} found in URL. Original value: {original_value}',
                    'recommendation': f'MANUAL TEST REQUIRED: 1) Access original URL and note content. 2) Test these URLs: {" | ".join([t["test_url"] for t in test_suggestions[:3]])} 3) Compare responses - different content/sizes confirm IDOR vulnerability.',
                    'evidence': {
                        'url_pattern': pattern,
                        'found_values': matches[:3],
                        'test_examples': f"MANUAL TEST REQUIRED - Try these URLs: {' | '.join([t['test_url'] for t in test_suggestions[:3]])} - Different responses confirm IDOR vulnerability",
                        'suggested_tests': test_suggestions[:3],
                        'proof_of_concept': proof_examples,
                        'detailed_instructions': f"1) Access original URL: {url} 2) Test URLs: {', '.join([t['test_url'] for t in test_suggestions[:2]])} 3) Compare content - different data confirms IDOR",
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
    def generate_idor_proof_examples(url: str, parameter_name: str, original_value: str) -> Dict[str, Any]:
        """Generate proof-of-concept examples for IDOR testing"""
        test_values = IDORDetector._generate_test_values(original_value, parameter_name)
        
        examples = {
            'original_request': {
                'url': url,
                'parameter': f'{parameter_name}={original_value}',
                'description': 'Original request'
            },
            'test_requests': [],
            'manual_test_steps': [
                f'1. Access original URL: {url}',
                f'2. Note the content/data returned',
                f'3. Try test URLs below and compare responses:',
            ]
        }
        
        for i, test_value in enumerate(test_values):
            test_url = url.replace(f'{parameter_name}={original_value}', f'{parameter_name}={test_value}')
            examples['test_requests'].append({
                'url': test_url,
                'parameter': f'{parameter_name}={test_value}',
                'description': f'Test request {i+1}: Change {parameter_name} to {test_value}',
                'expected_if_vulnerable': 'Different content/data should be returned'
            })
            examples['manual_test_steps'].append(f'   - {test_url}')
        
        examples['manual_test_steps'].extend([
            '4. If different content is returned for different parameter values,',
            '   this confirms IDOR vulnerability',
            '5. Check if you can access other users\' data or unauthorized resources'
        ])
        
        return examples
    
    @staticmethod
    def _extract_parameter_name(pattern: str) -> str:
        """Extract parameter name from regex pattern"""
        # Extract parameter name from patterns like r'[?&]item=([^&]+)'
        if 'item=' in pattern:
            return 'item'
        elif 'itemcode=' in pattern:
            return 'itemcode'
        elif 'user_id=' in pattern:
            return 'user_id'
        elif 'id=' in pattern:
            return 'id'
        elif 'code=' in pattern:
            return 'code'
        elif 'product=' in pattern:
            return 'product'
        elif 'account_id=' in pattern:
            return 'account_id'
        elif 'profile_id=' in pattern:
            return 'profile_id'
        else:
            return 'id'  # Default
    
    @staticmethod
    def _generate_test_values(original_value: str, parameter_name: str) -> List[str]:
        """Generate 2-3 test values for IDOR testing"""
        test_values = []
        param_lower = parameter_name.lower()
        
        try:
            # Try numeric values
            orig_int = int(original_value)
            test_values = [
                str(orig_int + 1),
                str(orig_int - 1),
                str(orig_int + 10)
            ]
        except ValueError:
            # Non-numeric values
            if 'item' in param_lower:
                if original_value.startswith('ITEM'):
                    test_values = ['ITEM001', 'ITEM002', 'ITEM999']
                else:
                    test_values = ['1', '2', '100']
            elif 'code' in param_lower:
                test_values = ['A', 'B', 'C']
            elif 'user' in param_lower:
                test_values = ['1', '2', '999']
            else:
                test_values = ['1', '2', '3']
        
        # Remove original value and limit to 3
        return [v for v in test_values if v != original_value][:3]
    
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
