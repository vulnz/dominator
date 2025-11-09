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
        """Get stored XSS payloads from existing XSS payload collection"""
        from payloads.xss_payloads import XSSPayloads
        
        # Use existing XSS payloads - they work for stored XSS too
        basic_payloads = XSSPayloads.get_basic_payloads()
        context_payloads = XSSPayloads.get_context_aware_payloads()
        
        # Combine and return first 20 most effective payloads
        all_payloads = basic_payloads + context_payloads
        return all_payloads[:20] if all_payloads else []
    
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
        Detect stored XSS vulnerability with strict validation to prevent false positives
        Returns (is_vulnerable, evidence, severity)
        """
        if not payload or len(payload) < 3:
            return False, "No payload provided", "None"
        
        # If we have a follow-up response (second request), check it for stored payload
        response_to_check = follow_up_response if follow_up_response else original_response
        
        if not response_to_check:
            return False, "No response to analyze", "None"
        
        # Строгая проверка: payload должен быть точно отражен
        if payload not in response_to_check:
            return False, "Payload not found in response", "None"
        
        # Найти позицию payload в ответе
        payload_pos = response_to_check.find(payload)
        if payload_pos == -1:
            return False, "Payload position not found", "None"
        
        # Получить контекст вокруг payload
        context_start = max(0, payload_pos - 200)
        context_end = min(len(response_to_check), payload_pos + len(payload) + 200)
        context = response_to_check[context_start:context_end].lower()
        
        # Исключить безопасные контексты (ложные срабатывания)
        safe_contexts = [
            '<!--' in context and '-->' in context,  # HTML комментарии
            'console.log' in context,  # JavaScript логирование
            'error' in context and 'message' in context,  # Сообщения об ошибках
            'debug' in context,  # Отладочная информация
            'log' in context and ('error' in context or 'info' in context),  # Логи
            'exception' in context and 'trace' in context,  # Трассировка исключений
        ]
        
        if any(safe_contexts):
            return False, "Payload found in safe context (comments/logs)", "None"
        
        # Проверить опасные контексты для Stored XSS
        dangerous_contexts = [
            '<script' in context and '</script>' in context,  # Внутри script тегов
            'on' in context and '=' in context,  # Event handlers (onclick, onload, etc.)
            'href=' in context,  # В ссылках
            'src=' in context,  # В источниках
            'action=' in context,  # В действиях форм
            'value=' in context and 'input' in context,  # В значениях input полей
        ]
        
        dangerous_found = any(dangerous_contexts)
        
        # Проверить, содержит ли payload опасные символы
        has_dangerous_chars = any(char in payload for char in ['<', '>', '"', "'", 'javascript:', 'on'])
        
        # Для Stored XSS требуем И опасный контекст И опасные символы
        if dangerous_found and has_dangerous_chars:
            # Дополнительная проверка: убедиться что это не отраженный XSS
            if follow_up_response and follow_up_response != original_response:
                return True, f"Stored XSS confirmed - payload persisted across requests in dangerous context", "High"
            else:
                return True, f"Potential Stored XSS - payload found in dangerous context", "Medium"
        
        # Если payload содержит script теги, это потенциально опасно
        if '<script>' in payload.lower() and '<script>' in context:
            if follow_up_response and follow_up_response != original_response:
                return True, f"Stored XSS with script injection confirmed", "High"
            else:
                return True, f"Potential script injection detected", "Medium"
        
        return False, "No stored XSS detected", "None"
    
    @staticmethod
    def _extract_unique_identifier(payload: str) -> str:
        """Extract unique identifier from payload for precise detection"""
        # Look for common unique patterns in payloads
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
        
        # If no pattern found, try to extract any quoted string
        quoted_match = re.search(r'["\']([^"\']{5,})["\']', payload)
        if quoted_match:
            return quoted_match.group(1)
        
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
