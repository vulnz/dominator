from typing import Dict, Any, List, Tuple
import re
import hashlib
import json

class IDORDetector:
    """Enhanced Insecure Direct Object Reference (IDOR) vulnerability detection logic"""

    @staticmethod
    def get_idor_parameters() -> List[str]:
        """Get common parameter names that might be vulnerable to IDOR - simplified list"""
        # We'll test ALL parameters with numeric values, not just these
        return []  # Empty list - test everything
    
    @staticmethod
    def get_idor_test_values(original_value: str, parameter_name: str = "") -> List[str]:
        """
        Generate intelligent test values for IDOR testing based on original value analysis
        Returns specific test values to check if IDOR vulnerability exists
        """
        test_values = []
        
        # Analyze original value to determine best test strategy
        value_analysis = IDORDetector._analyze_parameter_value(original_value, parameter_name)
        
        if value_analysis['type'] == 'numeric':
            orig_int = value_analysis['numeric_value']
            
            # Smart numeric testing based on value range
            if orig_int <= 10:
                # Small numbers - test adjacent and common values
                test_values = [
                    str(max(1, orig_int - 1)),   # Previous
                    str(orig_int + 1),           # Next
                    '1', '2', '3', '0'           # Common small values
                ]
            elif orig_int <= 100:
                # Medium numbers - test strategic values
                test_values = [
                    str(max(1, orig_int - 1)),   # Previous
                    str(orig_int + 1),           # Next
                    str(max(1, orig_int - 10)),  # Jump back
                    str(orig_int + 10),          # Jump forward
                    '1', '2', '10', '0'          # Common values
                ]
            else:
                # Large numbers - test wider range with MORE values
                test_values = [
                    str(max(1, orig_int - 1)),           # Previous
                    str(orig_int + 1),                   # Next
                    str(max(1, orig_int - 10)),          # Jump back 10
                    str(orig_int + 10),                  # Jump forward 10
                    str(max(1, orig_int - 100)),         # Jump back 100
                    str(orig_int + 100),                 # Jump forward 100
                    str(int(orig_int / 2)),              # Half
                    str(orig_int * 2),                   # Double
                    '1', '2', '3', '10', '100', '0'      # More common values
                ]
                
        elif value_analysis['type'] == 'alphanumeric':
            # Handle mixed alphanumeric values like "item123", "user456"
            base_text = value_analysis['text_part']
            base_num = value_analysis['numeric_part']
            
            if base_num is not None:
                test_values = [
                    f"{base_text}{max(1, base_num - 1)}",
                    f"{base_text}{base_num + 1}",
                    f"{base_text}1",
                    f"{base_text}2",
                    f"{base_text}10",
                    f"{base_text}0"
                ]
            else:
                # Pure text - try common variations
                test_values = ['1', '2', '3', '10', 'admin', 'test', '0']
                
        elif value_analysis['type'] == 'file_path':
            # Handle file paths like "./pictures/7.jpg"
            path_parts = value_analysis['path_parts']
            if path_parts['number']:
                base_path = path_parts['base_path']
                extension = path_parts['extension']
                orig_num = path_parts['number']
                
                test_values = [
                    f"{base_path}{max(1, orig_num - 1)}{extension}",
                    f"{base_path}{orig_num + 1}{extension}",
                    f"{base_path}1{extension}",
                    f"{base_path}2{extension}",
                    f"{base_path}10{extension}",
                    # Also test without path structure
                    str(orig_num - 1) if orig_num > 1 else '1',
                    str(orig_num + 1),
                    '1', '2', '10'
                ]
        else:
            # Fallback for unknown types
            test_values = ['1', '2', '3', '10', '100', '0']
        
        # Remove duplicates and original value
        test_values = [v for v in test_values if v != original_value and v is not None and v != '']
        
        # Add strategic empty/null tests
        test_values.extend(['', '0'])
        
        # Remove duplicates while preserving order
        seen = set()
        unique_values = []
        for val in test_values:
            if val not in seen:
                seen.add(val)
                unique_values.append(val)
        
        return unique_values[:15]  # Limit to 15 most strategic values

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
            'uname', 'fname', 'lname', 'fullname',
            
            # Contact information (not IDOR candidates)
            'phone', 'telephone', 'mobile', 'cell', 'fax',
            'uphone', 'user_phone', 'phone_number', 'tel',
            'address', 'street', 'city', 'state', 'zip', 'postal_code',
            'country', 'region', 'location',
            
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
    def is_parameter_testable(param_name: str, url: str = "", form_context: str = "", param_value: str = "") -> bool:
        """
        SUPER SIMPLE - test EVERYTHING except passwords!
        """
        if not param_name or not param_value:
            return False
            
        param_lower = param_name.lower().strip()
        
        # ONLY exclude passwords and tokens
        if param_lower in ['username', 'password', 'email', 'login', 'passwd', 'pass', 'pwd', 'csrf_token', 'token', '_token', 'submit']:
            return False
        
        # Test EVERYTHING ELSE!
        return True

    @staticmethod
    def detect_idor(original_response: str, modified_response: str,
                    original_code: int, modified_code: int, 
                    original_headers: Dict[str, str] = None,
                    modified_headers: Dict[str, str] = None,
                    parameter_name: str = "",
                    url: str = "",
                    http_method: str = "GET") -> Tuple[bool, str, str]:
        """
        SUPER SIMPLE IDOR detection - if responses are different, it's IDOR!
        Returns (is_vulnerable, confidence_level, evidence)
        """
        if original_headers is None:
            original_headers = {}
        if modified_headers is None:
            modified_headers = {}
        
        # STEP 1: Both responses must be successful
        if original_code != 200 or modified_code != 200:
            return False, 'low', f'One or both responses not HTTP 200 (original: {original_code}, modified: {modified_code})'
        
        # STEP 2: Responses must be different
        if original_response.strip() == modified_response.strip():
            return False, 'low', 'Responses are identical - no IDOR'
        
        # STEP 3: Size difference check - ANY difference is IDOR
        size_diff = abs(len(original_response) - len(modified_response))
        if size_diff > 10:  # Even 10 bytes difference = IDOR
            evidence = f"IDOR DETECTED: Response size difference of {size_diff} bytes indicates different content returned"
            return True, 'high', evidence
        
        # STEP 4: Content difference check - ANY content difference is IDOR
        if original_response != modified_response:
            evidence = f"IDOR DETECTED: Response content is different - parameter '{parameter_name}' allows access to different objects"
            return True, 'high', evidence
        
        return False, 'low', 'No differences detected'

    @staticmethod
    def _enhanced_response_analysis(original_response: str, modified_response: str,
                                  original_code: int, modified_code: int,
                                  original_headers: Dict[str, str], modified_headers: Dict[str, str],
                                  parameter_name: str, url: str) -> Dict[str, Any]:
        """
        Enhanced response analysis for IDOR detection with intelligent scoring
        """
        analysis = {
            'vulnerability_score': 0.0,
            'indicators': [],
            'reason': '',
            'evidence_details': {}
        }
        
        # 1. Response code analysis
        if original_code == 200 and modified_code == 200:
            analysis['vulnerability_score'] += 0.2
            analysis['indicators'].append('both_responses_successful')
        elif modified_code in [301, 302, 303, 307, 308]:
            location = modified_headers.get('Location', '')
            if 'login' in location.lower() or 'auth' in location.lower():
                analysis['reason'] = 'Redirected to authentication page'
                return analysis
            else:
                analysis['vulnerability_score'] += 0.3
                analysis['indicators'].append('redirect_to_different_resource')
        elif modified_code >= 400:
            analysis['reason'] = f'Error response code: {modified_code}'
            return analysis
        
        # 2. Content similarity analysis
        if original_response.strip() == modified_response.strip():
            analysis['reason'] = 'Responses are identical'
            return analysis
        
        # 3. Size difference analysis - MORE SENSITIVE
        size_diff = abs(len(original_response) - len(modified_response))
        if size_diff > 200:
            analysis['vulnerability_score'] += 0.4
            analysis['indicators'].append('significant_size_difference')
        elif size_diff > 50:
            analysis['vulnerability_score'] += 0.3
            analysis['indicators'].append('moderate_size_difference')
        elif size_diff > 10:
            analysis['vulnerability_score'] += 0.2
            analysis['indicators'].append('small_size_difference')
        
        analysis['evidence_details']['size_difference'] = size_diff
        
        # 4. Content type analysis
        orig_content = IDORDetector._analyze_content_type(original_response)
        mod_content = IDORDetector._analyze_content_type(modified_response)
        
        if orig_content != mod_content:
            analysis['vulnerability_score'] += 0.3
            analysis['indicators'].append('different_content_types')
        
        # 5. Title analysis
        orig_title = IDORDetector._extract_title(original_response)
        mod_title = IDORDetector._extract_title(modified_response)
        
        if orig_title != mod_title and mod_title:
            analysis['vulnerability_score'] += 0.4
            analysis['indicators'].append('different_titles')
            analysis['evidence_details']['title_change'] = f'"{orig_title}" -> "{mod_title}"'
        
        # 6. Data pattern analysis
        orig_patterns = IDORDetector._extract_data_patterns(original_response)
        mod_patterns = IDORDetector._extract_data_patterns(modified_response)
        
        pattern_score = IDORDetector._compare_data_patterns(orig_patterns, mod_patterns)
        analysis['vulnerability_score'] += pattern_score
        
        if pattern_score > 0.2:
            analysis['indicators'].append('different_data_patterns')
            analysis['evidence_details']['data_patterns'] = {
                'original': orig_patterns,
                'modified': mod_patterns
            }
        
        # 7. Error response filtering
        if IDORDetector._is_error_response(modified_response):
            analysis['vulnerability_score'] *= 0.3  # Reduce score for error responses
            analysis['indicators'].append('modified_response_is_error')
        
        # 8. Login page filtering
        if IDORDetector._is_login_page(modified_response):
            analysis['reason'] = 'Modified response is a login page'
            analysis['vulnerability_score'] = 0.0
            return analysis
        
        return analysis

    @staticmethod
    def _analyze_content_type(response: str) -> str:
        """Analyze the type of content in response"""
        response_lower = response.lower()
        
        if 'error' in response_lower and ('404' in response_lower or 'not found' in response_lower):
            return 'error_404'
        elif 'error' in response_lower:
            return 'error_generic'
        elif 'login' in response_lower and 'password' in response_lower:
            return 'login_form'
        elif IDORDetector._contains_item_data(response):
            return 'item_data'
        elif IDORDetector._contains_personal_data(response):
            return 'personal_data'
        elif '<table' in response_lower and '<tr' in response_lower:
            return 'tabular_data'
        elif '<form' in response_lower:
            return 'form_page'
        else:
            return 'generic_content'

    @staticmethod
    def _extract_data_patterns(response: str) -> Dict[str, int]:
        """Extract data patterns from response for comparison"""
        patterns = {
            'emails': len(re.findall(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b', response)),
            'phone_numbers': len(re.findall(r'\b\d{3}[-.]?\d{3}[-.]?\d{4}\b', response)),
            'item_codes': len(re.findall(r'\bitem\s*(?:code|id)\s*:\s*\w+', response, re.IGNORECASE)),
            'prices': len(re.findall(r'\$\d+\.?\d*|\d+\.?\d*\s*\$', response)),
            'dates': len(re.findall(r'\b\d{1,2}[/-]\d{1,2}[/-]\d{2,4}\b', response)),
            'ids': len(re.findall(r'\bid\s*[:=]\s*\d+', response, re.IGNORECASE)),
            'names': len(re.findall(r'\bname\s*[:=]\s*[A-Za-z\s]+', response, re.IGNORECASE)),
            'table_rows': len(re.findall(r'<tr[^>]*>', response, re.IGNORECASE)),
            'form_inputs': len(re.findall(r'<input[^>]*>', response, re.IGNORECASE)),
            'images': len(re.findall(r'<img[^>]*>', response, re.IGNORECASE))
        }
        
        return patterns

    @staticmethod
    def _compare_data_patterns(orig_patterns: Dict[str, int], mod_patterns: Dict[str, int]) -> float:
        """Compare data patterns and return vulnerability score contribution"""
        score = 0.0
        
        for pattern_type, orig_count in orig_patterns.items():
            mod_count = mod_patterns.get(pattern_type, 0)
            
            if pattern_type in ['item_codes', 'prices', 'ids', 'names'] and mod_count > orig_count:
                score += 0.2  # High value patterns
            elif pattern_type in ['emails', 'phone_numbers'] and mod_count > orig_count:
                score += 0.3  # Personal data patterns
            elif pattern_type in ['table_rows', 'images'] and abs(mod_count - orig_count) > 2:
                score += 0.1  # Structural differences
        
        return min(score, 0.5)  # Cap at 0.5

    @staticmethod
    def _build_comprehensive_evidence(analysis_result: Dict[str, Any], parameter_name: str, 
                                    url: str, original_response: str, modified_response: str) -> str:
        """Build comprehensive evidence string from analysis results"""
        evidence_parts = []
        
        # Main vulnerability statement
        evidence_parts.append(f"IDOR VULNERABILITY DETECTED: Parameter '{parameter_name}' allows unauthorized access to different objects.")
        
        # Score and confidence
        score = analysis_result['vulnerability_score']
        evidence_parts.append(f"Vulnerability Score: {score:.2f}/1.0")
        
        # Specific indicators
        indicators = analysis_result.get('indicators', [])
        if indicators:
            evidence_parts.append(f"Detection Indicators: {', '.join(indicators)}")
        
        # Evidence details
        details = analysis_result.get('evidence_details', {})
        
        if 'size_difference' in details:
            evidence_parts.append(f"Response Size Difference: {details['size_difference']} bytes")
        
        if 'title_change' in details:
            evidence_parts.append(f"Page Title Changed: {details['title_change']}")
        
        # Content analysis
        orig_content = IDORDetector._extract_meaningful_content(original_response)
        mod_content = IDORDetector._extract_meaningful_content(modified_response)
        
        if orig_content != mod_content:
            evidence_parts.append(f"Content Difference: Original='{orig_content[:100]}...' vs Modified='{mod_content[:100]}...'")
        
        # Test examples
        test_examples = IDORDetector._generate_test_examples(url, parameter_name, original_response, modified_response)
        evidence_parts.append(test_examples)
        
        return " | ".join(evidence_parts)
    
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
    def _analyze_parameter_value(value: str, param_name: str = "") -> Dict[str, Any]:
        """
        Analyze parameter value to determine its type and characteristics
        Returns analysis that helps generate better test values
        """
        analysis = {
            'type': 'unknown',
            'numeric_value': None,
            'text_part': None,
            'numeric_part': None,
            'path_parts': None
        }
        
        if not value:
            return analysis
        
        # Check if purely numeric
        if value.isdigit():
            analysis['type'] = 'numeric'
            analysis['numeric_value'] = int(value)
            return analysis
        
        # Check if file path
        if ('/' in value or '\\' in value) and ('.' in value):
            analysis['type'] = 'file_path'
            
            # Extract path components
            import re
            path_match = re.match(r'(.*/)?([^/]*?)(\d+)(\.[^.]+)?$', value)
            if path_match:
                base_path = path_match.group(1) or ''
                name_part = path_match.group(2) or ''
                number_part = int(path_match.group(3))
                extension = path_match.group(4) or ''
                
                analysis['path_parts'] = {
                    'base_path': base_path + name_part,
                    'number': number_part,
                    'extension': extension
                }
            return analysis
        
        # Check if alphanumeric (text + numbers)
        import re
        alphanumeric_match = re.match(r'([a-zA-Z_]+)(\d+)$', value)
        if alphanumeric_match:
            analysis['type'] = 'alphanumeric'
            analysis['text_part'] = alphanumeric_match.group(1)
            analysis['numeric_part'] = int(alphanumeric_match.group(2))
            return analysis
        
        # Check if contains numbers
        numbers = re.findall(r'\d+', value)
        if numbers:
            analysis['type'] = 'mixed'
            analysis['numeric_part'] = int(numbers[0])  # First number found
            return analysis
        
        # Pure text
        analysis['type'] = 'text'
        return analysis

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
