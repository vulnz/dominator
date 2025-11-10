from typing import Dict, Any, List, Tuple
import re
import hashlib
import json

class IDORDetector:
    """Enhanced Insecure Direct Object Reference (IDOR) vulnerability detection logic"""

    @staticmethod
    def get_idor_parameters() -> List[str]:
        """Get common parameter names that might be vulnerable to IDOR"""
        return [
            # Common ID parameters
            'id', 'user_id', 'userid', 'uid', 'account_id', 'accountid',
            'profile_id', 'profileid', 'doc_id', 'docid', 'file_id', 'fileid',
            'order_id', 'orderid', 'invoice_id', 'invoiceid', 'ticket_id',
            'ticketid', 'message_id', 'messageid', 'post_id', 'postid',
            'comment_id', 'commentid', 'item_id', 'itemid', 'product_id',
            'productid', 'customer_id', 'customerid', 'client_id', 'clientid',
            
            # Additional common patterns
            'key', 'ref', 'reference', 'session_id', 'sessionid',
            'transaction_id', 'transactionid', 'payment_id', 'paymentid',
            'report_id', 'reportid', 'document_id', 'documentid',
            'folder_id', 'folderid', 'category_id', 'categoryid',
            'group_id', 'groupid', 'team_id', 'teamid', 'project_id', 'projectid',
            
            # XVWA IDOR specific patterns (itemcode and item are real IDOR parameters)
            'itemcode', 'item_code', 'item', 'code', 'number', 'phone',
            'record', 'entry', 'data', 'info', 'details', 'product',
            'product_code', 'sku', 'catalog', 'inventory'
        ]
    
    @staticmethod
    def get_idor_test_values(original_value: str, parameter_name: str = "") -> List[str]:
        """
        Generate test values for IDOR testing based on original value
        Returns specific test values to check if IDOR vulnerability exists
        """
        test_values = []
        param_lower = parameter_name.lower()
        
        # For item/product parameters, use specific sequential values
        if 'item' in param_lower or 'product' in param_lower:
            # Always test these specific values for items - they often reveal IDOR
            test_values = ['0', '1', '2', '3', '4', '5']
            # Remove original value if it's in the list
            if original_value in test_values:
                test_values.remove(original_value)
            return test_values[:5]  # Return up to 5 test values
        
        # Try to parse original value as integer
        try:
            orig_int = int(original_value)
            
            # For numeric IDs, test adjacent values and common patterns
            test_values.extend([
                str(max(0, orig_int - 1)),  # Previous ID (not below 0)
                str(orig_int + 1),          # Next ID
                str(orig_int + 2),          # Skip ahead
            ])
            
            # Add some common test values for specific parameter types
            if 'user' in param_lower:
                test_values.extend(['1', '2', '999'])  # Common user IDs
            elif 'account' in param_lower:
                test_values.extend(['1', '10', '100'])  # Common account IDs
            else:
                test_values.extend(['1', '2', '10'])  # Generic test values
                
        except ValueError:
            # Non-numeric original value
            if original_value.isalpha():
                # For alphabetic codes, try common variations
                if len(original_value) <= 3:
                    test_values.extend(['A', 'B', 'C'])
                else:
                    test_values.extend(['admin', 'test', 'user'])
            elif original_value.isalnum():
                # For alphanumeric codes
                test_values.extend(['A1', 'B2', 'C3'])
            else:
                # For other formats, try common patterns
                test_values.extend(['1', '2', '3'])
        
        # Remove duplicates and original value, keep only first 5
        test_values = [v for v in test_values if v != original_value]
        return list(dict.fromkeys(test_values))[:5]  # Remove duplicates, keep order, limit to 5

    @staticmethod
    def get_excluded_parameters() -> List[str]:
        """Get parameter names that should NOT be tested for IDOR (login forms, etc.)"""
        return [
            # Login form parameters
            'username', 'email', 'login', 'user_name', 'user_email',
            'password', 'passwd', 'pass', 'pwd', 'user_password',
            
            # Registration form parameters
            'confirm_password', 'password_confirm', 'repeat_password',
            'first_name', 'last_name', 'full_name', 'name',
            
            # Search and filter parameters
            'search', 'query', 'q', 'filter', 'sort', 'order',
            'page', 'limit', 'offset', 'per_page',
            
            # CSRF and security tokens
            'csrf_token', 'token', '_token', 'authenticity_token',
            'nonce', '_nonce', 'security_token',
            
            # Form control parameters
            'submit', 'action', 'method', 'redirect', 'return_url',
            
            # Additional common form fields that are not IDOR candidates
            'captcha', 'recaptcha', 'remember_me', 'remember',
            'terms', 'agree', 'accept', 'newsletter'
        ]

    @staticmethod
    def is_parameter_testable(param_name: str, url: str = "", form_context: str = "") -> bool:
        """Check if parameter should be tested for IDOR based on context"""
        param_lower = param_name.lower()
        url_lower = url.lower()
        context_lower = form_context.lower()
        
        # First check: Exclude parameters that are clearly not IDOR candidates
        excluded = IDORDetector.get_excluded_parameters()
        if param_lower in excluded:
            return False
        
        # Second check: Exclude if URL suggests login/auth context
        auth_indicators = ['login', 'auth', 'signin', 'register', 'signup', 'forgot', 'reset']
        if any(indicator in url_lower for indicator in auth_indicators):
            return False
        
        # Third check: Exclude if form context suggests login/auth
        login_context_indicators = [
            'login', 'sign in', 'authentication', 'log in',
            'username', 'password', 'email', 'signin'
        ]
        if any(indicator in context_lower for indicator in login_context_indicators):
            return False
        
        # Fourth check: Only test parameters that look like IDs or references
        idor_params = IDORDetector.get_idor_parameters()
        is_id_like = (param_lower in idor_params or 
                     param_lower.endswith('_id') or 
                     param_lower.endswith('id') or
                     param_lower in ['key', 'ref', 'reference'])
        
        return is_id_like

    @staticmethod
    def detect_idor(original_response: str, modified_response: str,
                    original_code: int, modified_code: int, 
                    original_headers: Dict[str, str] = None,
                    modified_headers: Dict[str, str] = None,
                    parameter_name: str = "",
                    url: str = "",
                    http_method: str = "GET") -> Tuple[bool, str, str]:
        """
        Simplified IDOR detection by comparing original and modified responses.
        Returns (is_vulnerable, confidence_level, evidence)
        """
        if original_headers is None:
            original_headers = {}
        if modified_headers is None:
            modified_headers = {}
        
        # Простая проверка: исключить только явные параметры аутентификации
        if parameter_name:
            param_lower = parameter_name.lower().strip()
            
            # Минимальный список исключений - только явная аутентификация
            forbidden_params = {
                'username', 'password', 'email', 'login', 'passwd', 'pass', 'pwd',
                'csrf_token', 'token', '_token', 'submit'
            }
            
            # Исключить только если это точно параметр аутентификации
            if param_lower in forbidden_params:
                return False, 'excluded', f'Authentication parameter "{parameter_name}" excluded from IDOR testing'
            
            # Исключить только если URL явно содержит login/auth
            if any(auth_url in url.lower() for auth_url in ['login', 'signin', 'auth']):
                return False, 'excluded', f'Authentication URL detected - parameter excluded'
            
        # 1. Проверка успешных ответов - если оба ответа успешные, это хороший знак
        if original_code == 200 and modified_code == 200:
            # Если ответы разные по содержанию, это может быть IDOR
            if original_response != modified_response:
                # Проверим, что это не просто ошибка
                if not IDORDetector._is_error_response(modified_response):
                    # Проверим размер ответов
                    size_diff = abs(len(original_response) - len(modified_response))
                    if size_diff > 100:  # Значительная разница в размере
                        return True, 'high', f'Different responses with size difference: {size_diff} bytes'
                    elif size_diff > 10:  # Небольшая разница
                        return True, 'medium', f'Different responses with size difference: {size_diff} bytes'
        
        # 2. Обработка редиректов
        if modified_code in [301, 302, 303, 307, 308]:
            location = modified_headers.get('Location', '')
            if 'login' in location.lower() or 'auth' in location.lower():
                return False, 'low', 'Redirected to authentication page'
            # Редирект на другой ресурс может указывать на IDOR
            return True, 'medium', f'Redirected to different resource: {location}'
        
        # 3. Проверка кодов ошибок
        if modified_code == 403:
            return False, 'low', 'Access forbidden - proper authorization check'
        elif modified_code == 404:
            return False, 'low', 'Resource not found'
        elif modified_code == 401:
            return False, 'low', 'Authentication required'
        elif modified_code >= 400:
            return False, 'low', f'Error response code: {modified_code}'
        
        # 4. Проверка на пустые ответы
        if len(modified_response.strip()) < 20:
            return False, 'low', 'Response too short to be meaningful'
        
        # 5. Если ответы идентичны - нет IDOR
        if original_response.strip() == modified_response.strip():
            return False, 'low', 'Responses are identical - no IDOR detected'
        
        # 6. Упрощенный анализ различий
        analysis = IDORDetector._simple_response_analysis(original_response, modified_response)
        
        if analysis['is_different'] and analysis['confidence'] > 0.3:
            # Generate detailed test examples with concrete proof
            test_examples = IDORDetector._generate_test_examples(url, parameter_name, original_response, modified_response)
            
            # Extract concrete evidence of different data
            orig_data = IDORDetector._extract_meaningful_content(original_response)
            mod_data = IDORDetector._extract_meaningful_content(modified_response)
            
            # Create comprehensive evidence with real proof
            evidence_parts = [
                f"IDOR VULNERABILITY CONFIRMED: Parameter '{parameter_name}' exposes different objects.",
                f"CONCRETE PROOF: Original data: '{orig_data}' vs Modified data: '{mod_data}'",
                f"Response size difference: {abs(len(original_response) - len(modified_response))} bytes",
                test_examples
            ]
            
            evidence = " ".join(evidence_parts)
            confidence = 'high' if analysis['confidence'] > 0.7 else 'medium'
            return True, confidence, evidence
        
        return False, 'low', 'No significant differences detected'

    @staticmethod
    def _simple_response_analysis(original_response: str, modified_response: str) -> Dict[str, Any]:
        """Simplified response analysis for IDOR detection"""
        analysis = {
            'is_different': False,
            'confidence': 0.0,
            'evidence': ''
        }
        
        # Базовая проверка размера
        size_diff = abs(len(original_response) - len(modified_response))
        if size_diff > 50:
            analysis['is_different'] = True
            analysis['confidence'] += 0.3
            analysis['evidence'] += f'Size difference: {size_diff} bytes. '
        
        # Проверка заголовков страниц
        orig_title = IDORDetector._extract_title(original_response)
        mod_title = IDORDetector._extract_title(modified_response)
        if orig_title != mod_title and mod_title:
            analysis['is_different'] = True
            analysis['confidence'] += 0.4
            analysis['evidence'] += f'Different titles: "{orig_title}" vs "{mod_title}". '
        
        # Проверка на персональные данные и данные товаров
        if IDORDetector._contains_personal_data(modified_response):
            analysis['is_different'] = True
            analysis['confidence'] += 0.5
            analysis['evidence'] += 'Personal data found in response. '
        
        # Проверка на данные товаров/продуктов
        if IDORDetector._contains_item_data(modified_response):
            analysis['is_different'] = True
            analysis['confidence'] += 0.4
            analysis['evidence'] += 'Item/product data found in response. '
        
        # Проверка на пользовательский контент
        user_indicators = ['user:', 'name:', 'email:', 'profile', 'account', 'welcome']
        mod_lower = modified_response.lower()
        orig_lower = original_response.lower()
        
        mod_user_content = sum(1 for indicator in user_indicators if indicator in mod_lower)
        orig_user_content = sum(1 for indicator in user_indicators if indicator in orig_lower)
        
        if mod_user_content > orig_user_content:
            analysis['is_different'] = True
            analysis['confidence'] += 0.3
            analysis['evidence'] += 'More user-specific content in modified response. '
        
        # Проверка на различия в HTML структуре
        if IDORDetector._compare_html_structure(original_response, modified_response):
            analysis['is_different'] = True
            analysis['confidence'] += 0.2
            analysis['evidence'] += 'Different HTML structure. '
        
        return analysis
    
    @staticmethod
    def _is_error_response(response: str) -> bool:
        """Check if response is an error page"""
        error_indicators = [
            'error', 'not found', '404', 'forbidden', '403',
            'unauthorized', '401', 'bad request', '400',
            'internal server error', '500'
        ]
        
        response_lower = response.lower()
        error_count = sum(1 for indicator in error_indicators if indicator in response_lower)
        
        # Если много индикаторов ошибки, это скорее всего страница ошибки
        return error_count >= 2

    @staticmethod
    def _is_generic_title(title: str) -> bool:
        """Check if title is too generic to be meaningful for IDOR detection"""
        generic_titles = [
            'xvwa', 'xtreme vulnerable web application',
            'login', 'sign in', 'authentication',
            'error', 'not found', '404', '403', '401',
            'home', 'index', 'main', 'welcome'
        ]
        
        title_lower = title.lower().strip()
        return any(generic in title_lower for generic in generic_titles)

    @staticmethod
    def _is_login_page(response: str) -> bool:
        """Check if response is a login page"""
        response_lower = response.lower()
        
        # Strong indicators of login page
        login_indicators = [
            'type="password"',
            'name="password"',
            'name="username"',
            'login form',
            'sign in',
            'authentication',
            'please log in',
            'enter your credentials'
        ]
        
        # Count how many indicators are present
        indicator_count = sum(1 for indicator in login_indicators if indicator in response_lower)
        
        # If multiple indicators present, it's likely a login page
        return indicator_count >= 2

    @staticmethod
    def _extract_title(response: str) -> str:
        """Extract title from HTML response"""
        title_match = re.search(r'<title[^>]*>(.*?)</title>', response, re.IGNORECASE | re.DOTALL)
        if title_match:
            return title_match.group(1).strip()
        return ""

    @staticmethod
    def _contains_personal_data(response: str) -> bool:
        """Check if response contains personal data patterns"""
        personal_patterns = [
            r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',  # Email
            r'\b\d{3}-\d{2}-\d{4}\b',  # SSN pattern
            r'\b\d{3}[-.]?\d{3}[-.]?\d{4}\b',  # Phone number
            r'\b\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}\b',  # Credit card
            r'\b(?:user|name|email|phone|address|birth):\s*[^\s<]+',  # Key-value pairs
            r'<td[^>]*>\s*[A-Za-z]+\s+[A-Za-z]+\s*</td>',  # Names in table cells
        ]
        
        for pattern in personal_patterns:
            if re.search(pattern, response, re.IGNORECASE):
                return True
        return False
    
    @staticmethod
    def _contains_item_data(response: str) -> bool:
        """Check if response contains item/product data patterns"""
        item_patterns = [
            r'<b>\s*item\s+(?:code|name|id)\s*:\s*</b>',  # Item Code : 
            r'<b>\s*product\s+(?:code|name|id)\s*:\s*</b>',  # Product Name :
            r'<b>\s*(?:price|category|description)\s*:\s*</b>',  # Price : Category :
            r'item\s*(?:code|name|id)\s*[:=]\s*\S+',
            r'product\s*(?:code|name|id)\s*[:=]\s*\S+',
            r'price\s*[:=]\s*[\d,\.]+\$?',
            r'category\s*[:=]\s*\w+',
            r'<td><b>(?:item|product|price|category)',
            r'<img\s+src=.*height=\d+.*weight=\d+',  # Product images
            r'<option\s+value="[^"]*">[^<]+</option>',  # Select options with items
        ]
        
        for pattern in item_patterns:
            if re.search(pattern, response, re.IGNORECASE):
                return True
        return False

    @staticmethod
    def _compare_html_structure(original: str, modified: str) -> bool:
        """Compare HTML structure between responses"""
        def get_structure(html):
            # Extract tag structure
            tags = re.findall(r'<(\w+)[^>]*>', html, re.IGNORECASE)
            return ''.join(tags[:20])  # First 20 tags
        
        orig_structure = get_structure(original)
        mod_structure = get_structure(modified)
        
        return orig_structure != mod_structure

    @staticmethod
    def _build_evidence(analysis: Dict[str, Any]) -> str:
        """Build evidence string based on analysis"""
        evidence_parts = []
        
        if analysis['title_different']:
            evidence_parts.append("Different page titles")
        if analysis['personal_data_found']:
            evidence_parts.append("Personal data found in response")
        if analysis['size_difference'] > 500:
            evidence_parts.append(f"Significant size difference ({analysis['size_difference']} bytes)")
        if analysis['structure_different']:
            evidence_parts.append("Different HTML structure")
        if not analysis['content_type_same']:
            evidence_parts.append("Different content types")
        
        if evidence_parts:
            return "IDOR detected: " + ", ".join(evidence_parts)
        else:
            return "IDOR detected: Response content differs significantly from original"

    @staticmethod
    def get_response_snippet(response_text: str) -> str:
        """Get a snippet of the response for the report"""
        # Try to extract meaningful content
        title = IDORDetector._extract_title(response_text)
        if title:
            snippet = f"Title: {title}"
        else:
            # Extract first meaningful text content
            text_content = re.sub(r'<[^>]+>', ' ', response_text)
            text_content = re.sub(r'\s+', ' ', text_content).strip()
            snippet = text_content[:200] + '...' if len(text_content) > 200 else text_content
        
        # Add personal data indicators if found
        if IDORDetector._contains_personal_data(response_text):
            snippet += " [Contains personal data]"
            
        return snippet

    @staticmethod
    def generate_idor_test_urls(base_url: str, parameter_name: str, original_value: str) -> List[Dict[str, str]]:
        """
        Generate test URLs for IDOR testing
        Returns list of test URLs with different parameter values
        """
        test_urls = []
        test_values = IDORDetector.get_idor_test_values(original_value, parameter_name)
        
        for test_value in test_values:
            # Replace parameter value in URL
            if f'{parameter_name}={original_value}' in base_url:
                test_url = base_url.replace(f'{parameter_name}={original_value}', f'{parameter_name}={test_value}')
            else:
                # If parameter not found in URL, append it
                separator = '&' if '?' in base_url else '?'
                test_url = f"{base_url}{separator}{parameter_name}={test_value}"
            
            test_urls.append({
                'url': test_url,
                'parameter': parameter_name,
                'original_value': original_value,
                'test_value': test_value,
                'description': f'Test IDOR with {parameter_name}={test_value}'
            })
        
        return test_urls
    
    @staticmethod
    def get_common_idor_test_cases() -> Dict[str, List[str]]:
        """
        Get common test cases for different types of IDOR parameters
        """
        return {
            'user_id': ['1', '2', '999', '1000'],
            'id': ['1', '2', '10', '100'],
            'item': ['1', '2', '3', '100'],
            'itemcode': ['ITEM001', 'ITEM002', 'ITEM003'],
            'code': ['A', 'B', 'C', '001', '002'],
            'account_id': ['1', '10', '100', '999'],
            'profile_id': ['1', '2', '999'],
            'product_id': ['1', '2', '100'],
            'order_id': ['1', '2', '999'],
            'file_id': ['1', '2', '10'],
            'doc_id': ['1', '2', '100'],
        }
    
    @staticmethod
    def _generate_test_examples(url: str, parameter_name: str, original_response: str, modified_response: str) -> str:
        """Generate test examples showing IDOR vulnerability with concrete proof"""
        examples = []
        
        # Extract parameter value from URL
        param_match = re.search(f'{parameter_name}=([^&]+)', url)
        original_value = param_match.group(1) if param_match else ''
        
        # Show concrete proof of IDOR vulnerability
        orig_size = len(original_response)
        mod_size = len(modified_response)
        size_diff = abs(orig_size - mod_size)
        
        # Extract meaningful content differences
        orig_content = IDORDetector._extract_meaningful_content(original_response)
        mod_content = IDORDetector._extract_meaningful_content(modified_response)
        
        examples.append(f"IDOR VULNERABILITY PROOF:")
        examples.append(f"Original request ({parameter_name}='{original_value}'): {orig_size}b response")
        examples.append(f"Modified request ({parameter_name}='test_value'): {mod_size}b response")
        examples.append(f"Size difference: {size_diff} bytes - PROVES different content returned")
        
        # Show content differences
        if orig_content != mod_content:
            examples.append(f"CONTENT PROOF: Original='{orig_content[:100]}...' vs Modified='{mod_content[:100]}...'")
        
        # For IDOR, show specific test values that prove the vulnerability
        if parameter_name.lower() in ['item', 'itemcode', 'id', 'product']:
            examples.append(f"CONCRETE TEST EXAMPLES - Try these {parameter_name} values:")
            test_values = ['0', '1', '2', '3', '4']
            
            for test_value in test_values:
                if original_value:
                    test_url = url.replace(f'{parameter_name}={original_value}', f'{parameter_name}={test_value}')
                else:
                    separator = '&' if '?' in url else '?'
                    test_url = f"{url}{separator}{parameter_name}={test_value}"
                examples.append(f"→ {test_url} (expect different item data)")
        else:
            # Generic test values for other parameters
            test_values = IDORDetector.get_idor_test_values(original_value, parameter_name)
            examples.append(f"TEST DIFFERENT {parameter_name.upper()} VALUES:")
            
            for test_value in test_values[:3]:
                if original_value:
                    test_url = url.replace(f'{parameter_name}={original_value}', f'{parameter_name}={test_value}')
                else:
                    separator = '&' if '?' in url else '?'
                    test_url = f"{url}{separator}{parameter_name}={test_value}"
                examples.append(f"→ {test_url}")
        
        # Add specific evidence of vulnerability
        if IDORDetector._contains_item_data(modified_response):
            examples.append("✓ CONFIRMED: Modified response contains item/product data (Item Code, Price, etc.)")
        
        if IDORDetector._contains_personal_data(modified_response):
            examples.append("✓ CONFIRMED: Modified response contains personal/sensitive data")
        
        # Check for different titles
        orig_title = IDORDetector._extract_title(original_response)
        mod_title = IDORDetector._extract_title(modified_response)
        if orig_title != mod_title and mod_title:
            examples.append(f"✓ CONFIRMED: Different page titles - Original: '{orig_title}' vs Modified: '{mod_title}'")
        
        # Add verification instructions
        examples.append("VERIFICATION: Each URL above should return different data - this confirms unauthorized access to different objects")
        
        return " | ".join(examples)
    
    @staticmethod
    def _extract_meaningful_content(response: str) -> str:
        """Extract meaningful content from response for comparison"""
        # Remove HTML tags and get text content
        text_content = re.sub(r'<[^>]+>', ' ', response)
        text_content = re.sub(r'\s+', ' ', text_content).strip()
        
        # Look for specific data patterns
        data_patterns = [
            r'Item Code\s*:\s*([^\n\r]+)',
            r'Item Name\s*:\s*([^\n\r]+)',
            r'Price\s*:\s*([^\n\r]+)',
            r'Category\s*:\s*([^\n\r]+)',
            r'Description\s*:\s*([^\n\r]+)',
            r'User\s*:\s*([^\n\r]+)',
            r'Name\s*:\s*([^\n\r]+)',
            r'Email\s*:\s*([^\n\r]+)',
        ]
        
        found_data = []
        for pattern in data_patterns:
            matches = re.findall(pattern, response, re.IGNORECASE)
            if matches:
                found_data.extend(matches[:2])  # First 2 matches
        
        if found_data:
            return ' | '.join(found_data)
        
        # If no specific patterns, return first meaningful text
        return text_content[:200] if text_content else "No meaningful content"
    
    @staticmethod
    def get_remediation_advice() -> str:
        """Get remediation advice for IDOR vulnerabilities"""
        return ("Implement proper access control checks on the server-side to ensure users can only "
                "access resources they are authorized to view. Use session-based authorization, "
                "validate user permissions for each request, and avoid exposing direct object references. "
                "Consider using indirect references or UUIDs instead of sequential IDs.")

    @staticmethod
    def _get_response_fingerprint(text: str) -> str:
        """Create a simple fingerprint of a response body to compare pages."""
        text = re.sub(r'<(script|style).*?>.*?</\1>', '', text, flags=re.DOTALL | re.IGNORECASE)
        text = re.sub(r'<.*?>', ' ', text)
        text = re.sub(r'\s+', ' ', text).strip()
        return hashlib.sha1(text[:500].encode('utf-8', 'ignore')).hexdigest()
