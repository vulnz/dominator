"""
Stored XSS vulnerability detection logic
"""

import re
from typing import List, Dict, Any, Tuple
from utils.payload_loader import PayloadLoader

class StoredXSSDetector:
    """Stored XSS vulnerability detection logic"""
    
    @staticmethod
    def get_stored_xss_payloads() -> List[str]:
        """Get stored XSS payloads with personalized dominator777 markers"""
        # Персонализированные payload'ы с уникальными маркерами
        dominator_payloads = [
            '<script>alert("dominator777_stored_xss_001")</script>',
            '<scRipt>alert("dominator777_stored_xss_002")</scRipt>',
            '<SCRIPT>alert("dominator777_stored_xss_003")</SCRIPT>',
            '<img src=x onerror=alert("dominator777_img_001")>',
            '<svg onload=alert("dominator777_svg_001")>',
            '<iframe src="javascript:alert(\'dominator777_iframe_001\')"></iframe>',
            '<body onload=alert("dominator777_body_001")>',
            '<div onclick=alert("dominator777_div_001")>dominator777</div>',
            '"><script>alert("dominator777_break_001")</script>',
            "'><script>alert('dominator777_break_002')</script>",
            '</script><script>alert("dominator777_break_003")</script>',
            '<script>confirm("dominator777_confirm_001")</script>',
            '<script>prompt("dominator777_prompt_001")</script>',
            'javascript:alert("dominator777_js_001")',
            '<marquee onstart=alert("dominator777_marquee_001")>',
            '<details open ontoggle=alert("dominator777_details_001")>',
            '<input onfocus=alert("dominator777_input_001") autofocus>',
            '<select onfocus=alert("dominator777_select_001") autofocus>',
            '<textarea onfocus=alert("dominator777_textarea_001") autofocus>',
            '<keygen onfocus=alert("dominator777_keygen_001") autofocus>'
        ]
        
        # Также используем существующие XSS payload'ы как fallback
        try:
            from payloads.xss_payloads import XSSPayloads
            basic_payloads = XSSPayloads.get_basic_payloads()[:10]
            return dominator_payloads + basic_payloads
        except:
            return dominator_payloads
    
    @staticmethod
    def get_stored_xss_indicators() -> List[str]:
        """Get stored XSS vulnerability indicators for detection"""
        indicators = PayloadLoader.load_indicators('xss_detection')
        if not indicators:
            # Fallback indicators if file not found
            indicators = [
                'alert(',
                'confirm(',
                'prompt(',
                'javascript:',
                '<script>',
                'onerror=',
                'onload=',
                'onclick='
            ]
        return indicators
    
    @staticmethod
    def detect_stored_xss(original_response: str, payload: str, follow_up_response: str = None) -> Tuple[bool, str, str]:
        """
        Detect stored XSS vulnerability with enhanced detection for real vulnerabilities
        Returns (is_vulnerable, evidence, severity)
        """
        if not payload or len(payload) < 3:
            return False, "No payload provided", "None"
        
        # If we have a follow-up response (second request), check it for stored payload
        response_to_check = follow_up_response if follow_up_response else original_response
        
        if not response_to_check:
            return False, "No response to analyze", "None"
        
        # Извлечь уникальный маркер dominator777 из payload
        dominator_marker = StoredXSSDetector._extract_dominator_marker(payload)
        
        # Проверить наличие маркера dominator777 в ответе
        if dominator_marker and dominator_marker in response_to_check:
            # Найти позицию маркера в ответе
            marker_pos = response_to_check.find(dominator_marker)
            context_start = max(0, marker_pos - 300)
            context_end = min(len(response_to_check), marker_pos + len(dominator_marker) + 300)
            context = response_to_check[context_start:context_end]
            
            # Проверить, что payload полностью присутствует
            if payload in response_to_check:
                # Найти позицию полного payload
                payload_pos = response_to_check.find(payload)
                payload_context_start = max(0, payload_pos - 200)
                payload_context_end = min(len(response_to_check), payload_pos + len(payload) + 200)
                payload_context = response_to_check[payload_context_start:payload_context_end].lower()
                
                # Исключить безопасные контексты
                safe_contexts = [
                    '<!--' in payload_context and '-->' in payload_context,  # HTML комментарии
                    'console.log' in payload_context,  # JavaScript логирование
                    'error' in payload_context and 'message' in payload_context,  # Сообщения об ошибках
                    'debug' in payload_context,  # Отладочная информация
                ]
                
                if any(safe_contexts):
                    return False, "Dominator777 payload found in safe context (comments/logs)", "None"
                
                # Проверить опасные контексты
                dangerous_contexts = [
                    '<script' in payload_context,  # Script теги
                    '<img' in payload_context and 'onerror' in payload_context,  # Image onerror
                    '<svg' in payload_context and 'onload' in payload_context,  # SVG onload
                    '<iframe' in payload_context and 'src' in payload_context,  # Iframe src
                    'javascript:' in payload_context,  # JavaScript protocol
                    'on' in payload_context and '=' in payload_context,  # Event handlers
                ]
                
                if any(dangerous_contexts):
                    # Определить тип контекста для более точного описания
                    context_type = "unknown"
                    if '<script' in payload_context:
                        context_type = "script tag"
                    elif '<img' in payload_context and 'onerror' in payload_context:
                        context_type = "image onerror handler"
                    elif '<svg' in payload_context:
                        context_type = "SVG element"
                    elif 'javascript:' in payload_context:
                        context_type = "JavaScript protocol"
                    elif 'on' in payload_context and '=' in payload_context:
                        context_type = "event handler"
                    
                    # Проверить, это Stored XSS или Reflected XSS
                    if follow_up_response and follow_up_response != original_response:
                        return True, f"DOMINATOR777 Stored XSS confirmed - payload '{dominator_marker}' persisted in {context_type}", "High"
                    else:
                        return True, f"DOMINATOR777 Stored XSS detected - payload '{dominator_marker}' found in {context_type}", "High"
                
                # Если payload найден, но не в опасном контексте
                return True, f"DOMINATOR777 payload stored but in safe context - marker '{dominator_marker}' found", "Medium"
            
            # Если только маркер найден, но не полный payload
            return True, f"DOMINATOR777 marker '{dominator_marker}' found in response (partial injection)", "Low"
        
        # Fallback: проверить обычные XSS индикаторы
        if payload in response_to_check:
            payload_pos = response_to_check.find(payload)
            context_start = max(0, payload_pos - 200)
            context_end = min(len(response_to_check), payload_pos + len(payload) + 200)
            context = response_to_check[context_start:context_end].lower()
            
            # Проверить опасные символы и контексты
            has_dangerous_chars = any(char in payload for char in ['<', '>', '"', "'", 'javascript:', 'alert', 'script'])
            dangerous_context = any([
                '<script' in context,
                'javascript:' in context,
                'onerror=' in context,
                'onload=' in context
            ])
            
            if has_dangerous_chars and dangerous_context:
                return True, f"Stored XSS detected - payload found in dangerous context", "High"
        
        return False, "No stored XSS detected", "None"
    
    @staticmethod
    def _extract_dominator_marker(payload: str) -> str:
        """Extract dominator777 marker from payload for precise detection"""
        # Поиск маркеров dominator777 в payload
        dominator_patterns = [
            r'dominator777[_\w]*',
            r'alert\(["\']([^"\']*dominator777[^"\']*)["\']',
            r'confirm\(["\']([^"\']*dominator777[^"\']*)["\']',
            r'prompt\(["\']([^"\']*dominator777[^"\']*)["\']'
        ]
        
        for pattern in dominator_patterns:
            match = re.search(pattern, payload, re.IGNORECASE)
            if match:
                if match.groups():
                    return match.group(1)  # Return captured group
                else:
                    return match.group(0)  # Return full match
        
        # Fallback: поиск любых уникальных строк в кавычках
        quoted_match = re.search(r'["\']([^"\']{10,})["\']', payload)
        if quoted_match:
            return quoted_match.group(1)
        
        return ""
    
    @staticmethod
    def _extract_unique_identifier(payload: str) -> str:
        """Extract unique identifier from payload for precise detection (legacy method)"""
        # Сначала попробовать найти dominator777 маркер
        dominator_marker = StoredXSSDetector._extract_dominator_marker(payload)
        if dominator_marker:
            return dominator_marker
        
        # Fallback к старой логике
        patterns = [
            r'STORED_XSS_TEST[_\d]*',
            r'STORED_XSS[_\d]*',
            r'XSS_TEST_\d+',
            r'alert\(["\']([^"\']+)["\']\)',
            r'confirm\(["\']([^"\']+)["\']\)',
            r'prompt\(["\']([^"\']+)["\']\)'
        ]
        
        for pattern in patterns:
            match = re.search(pattern, payload, re.IGNORECASE)
            if match:
                if match.groups():
                    return match.group(1)  # Return captured group
                else:
                    return match.group(0)  # Return full match
        
        return ""
    
    @staticmethod
    def get_evidence(payload: str, response: str, context: str) -> str:
        """Get evidence of stored XSS vulnerability"""
        if context == "None":
            return "No stored XSS detected"
        
        evidence = f"Stored XSS detected with payload: '{payload}'"
        
        if payload in response:
            evidence += f" - Payload found in response"
        
        # Check for specific contexts
        if '<script' in response.lower() and payload.lower() in response.lower():
            evidence += " - Payload executed in script context"
        elif 'javascript:' in response.lower() and payload.lower() in response.lower():
            evidence += " - Payload executed in JavaScript URL"
        elif re.search(r'on\w+=["\']?[^"\']*' + re.escape(payload), response, re.IGNORECASE):
            evidence += " - Payload executed in event handler"
        
        return evidence
    
    @staticmethod
    def get_response_snippet(payload: str, response: str) -> str:
        """Get relevant response snippet showing stored XSS"""
        if not response or payload not in response:
            return response[:200] if response else "No response"
        
        payload_pos = response.find(payload)
        start = max(0, payload_pos - 100)
        end = min(len(response), payload_pos + len(payload) + 100)
        
        snippet = response[start:end]
        
        # Highlight the payload in the snippet
        highlighted_snippet = snippet.replace(payload, f">>>{payload}<<<")
        
        return highlighted_snippet
    
    @staticmethod
    def get_test_payloads() -> List[str]:
        """Get test payloads for stored XSS detection"""
        from payloads.xss_payloads import XSSPayloads
        return XSSPayloads.get_basic_payloads()
    
    @staticmethod
    def get_remediation_advice() -> str:
        """Get remediation advice for stored XSS vulnerabilities"""
        return (
            "Implement proper input validation and output encoding for all user data. "
            "Use context-aware encoding (HTML, JavaScript, CSS, URL). "
            "Implement Content Security Policy (CSP) to prevent script execution. "
            "Sanitize all user input before storing in database. "
            "Use parameterized queries and avoid dynamic HTML generation."
        )
