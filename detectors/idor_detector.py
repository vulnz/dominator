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
            
            # XVWA IDOR specific patterns (itemcode is the real IDOR parameter)
            'itemcode', 'item_code', 'code', 'number', 'phone',
            'record', 'entry', 'data', 'info', 'details'
        ]

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
            evidence = f"Response analysis: {analysis['evidence']}"
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
        
        # Проверка на персональные данные
        if IDORDetector._contains_personal_data(modified_response):
            analysis['is_different'] = True
            analysis['confidence'] += 0.5
            analysis['evidence'] += 'Personal data found in response. '
        
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
