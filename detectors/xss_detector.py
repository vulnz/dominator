"""
XSS vulnerability detector
"""

import re

class XSSDetector:
    """XSS vulnerability detection logic"""
    
    @staticmethod
    def detect_reflected_xss(payload: str, response_text: str, response_code: int) -> bool:
        """Detect reflected XSS vulnerability with improved detection logic"""
        if response_code not in [200, 201, 202]:
            return False
        
        # Convert response to lowercase for case-insensitive matching
        response_lower = response_text.lower()
        payload_lower = payload.lower()
        
        # Check for exact payload reflection first
        if payload in response_text:
            print(f"    [XSS] Payload found in response, checking context...")
            return XSSDetector._is_dangerous_context(payload, response_text)
        
        # Check for URL-decoded payload reflection
        import urllib.parse
        try:
            decoded_payload = urllib.parse.unquote(payload)
            if decoded_payload != payload and decoded_payload in response_text:
                return XSSDetector._is_dangerous_context(decoded_payload, response_text)
        except:
            pass
        
        # Check for HTML-encoded payload reflection
        import html
        try:
            encoded_payload = html.escape(payload)
            if encoded_payload != payload and encoded_payload in response_text:
                # If payload is HTML-encoded, it's likely safe
                return False
        except:
            pass
        
        # Check for partial payload reflection (key parts)
        if '<script' in payload_lower:
            if '<script' in response_lower and 'alert' in response_lower:
                return True
        
        if 'javascript:' in payload_lower:
            if 'javascript:' in response_lower:
                return True
        
        if 'onerror' in payload_lower or 'onload' in payload_lower:
            if ('onerror' in response_lower or 'onload' in response_lower) and payload_lower.split('=')[0] in response_lower:
                return True
        
        # Check for XSS indicators in response
        xss_indicators = [
            'alert(',
            'confirm(',
            'prompt(',
            'document.cookie',
            'document.write',
            'eval(',
            'javascript:',
            'vbscript:',
            'onload=',
            'onerror=',
            'onclick=',
            'onmouseover='
        ]
        
        # If payload contains XSS patterns and they appear unescaped in response
        for indicator in xss_indicators:
            if indicator in payload_lower and indicator in response_lower:
                # Check if it's not just in comments or escaped
                if not XSSDetector._is_safely_encoded(indicator, response_text):
                    return True
        
        return False
    
    @staticmethod
    def _is_dangerous_context(payload: str, response_text: str) -> bool:
        """Check if payload appears in dangerous HTML context"""
        # Check if payload is in dangerous context (not just in comments or text)
        dangerous_contexts = [
            r'<script[^>]*>[^<]*' + re.escape(payload),
            r'<[^>]*\s+on\w+\s*=\s*["\']?[^"\']*' + re.escape(payload),
            r'<[^>]*\s+href\s*=\s*["\']?javascript:[^"\']*' + re.escape(payload),
            r'<[^>]*\s+src\s*=\s*["\']?[^"\']*' + re.escape(payload),
            r'<input[^>]*\s+value\s*=\s*["\']?' + re.escape(payload),
            r'<textarea[^>]*>[^<]*' + re.escape(payload)
        ]
        
        # Check if payload appears in dangerous context
        for context_pattern in dangerous_contexts:
            if re.search(context_pattern, response_text, re.IGNORECASE | re.DOTALL):
                return True
        
        # Check if payload contains HTML tags and they're not escaped
        if '<' in payload and '>' in payload:
            # Look for unescaped angle brackets
            if payload in response_text:
                # Check if the payload appears unescaped
                escaped_payload = payload.replace('<', '&lt;').replace('>', '&gt;')
                if escaped_payload not in response_text:
                    print(f"    [XSS] Unescaped HTML tags found in dangerous context")
                    return True
        
        # Additional check for simple payloads that might be reflected
        if payload in response_text:
            # Check for basic XSS patterns that are commonly vulnerable
            simple_patterns = ['<script', 'javascript:', 'onerror=', 'onload=', 'alert(']
            for pattern in simple_patterns:
                if pattern.lower() in payload.lower() and pattern.lower() in response_text.lower():
                    print(f"    [XSS] XSS pattern '{pattern}' found reflected")
                    return True
        
        return False
    
    @staticmethod
    def _is_safely_encoded(indicator: str, response_text: str) -> bool:
        """Check if XSS indicator is safely encoded in response"""
        # Check for HTML encoding
        import html
        encoded_indicator = html.escape(indicator)
        if encoded_indicator in response_text:
            return True
        
        # Check for URL encoding
        import urllib.parse
        url_encoded = urllib.parse.quote(indicator)
        if url_encoded in response_text:
            return True
        
        # Check if it's in HTML comments
        if f'<!--{indicator}' in response_text or f'{indicator}-->' in response_text:
            return True
        
        return False
    
    @staticmethod
    def detect_dom_xss(payload: str, response_text: str, response_code: int) -> bool:
        """Detect DOM-based XSS vulnerability"""
        if response_code != 200:
            return False
            
        # Look for JavaScript that might execute the payload
        dom_indicators = [
            'document.write',
            'innerHTML',
            'outerHTML',
            'eval(',
            'setTimeout(',
            'setInterval('
        ]
        
        return (payload in response_text and 
                any(indicator in response_text for indicator in dom_indicators))
    
    @staticmethod
    def get_evidence(payload: str, response_text: str) -> str:
        """Get evidence of XSS vulnerability"""
        if payload in response_text:
            # Find context where payload appears
            start_pos = response_text.find(payload)
            context_start = max(0, start_pos - 40)
            context_end = min(len(response_text), start_pos + len(payload) + 40)
            context = response_text[context_start:context_end]
            return f"Payload reflected in response: ...{context}..."
        return "Payload not found in response"
    
    @staticmethod
    def get_response_snippet(payload: str, response_text: str) -> str:
        """Get response snippet showing payload context"""
        if payload in response_text:
            start_pos = response_text.find(payload)
            context_start = max(0, start_pos - 40)
            context_end = min(len(response_text), start_pos + len(payload) + 40)
            return response_text[context_start:context_end]
        return "Payload not found in response"
import re
from typing import List, Dict, Any, Tuple
from urllib.parse import unquote

class XSSDetector:
    """XSS vulnerability detection logic optimized for XVWA"""
    
    @staticmethod
    def get_xss_indicators() -> List[str]:
        """Get XSS detection indicators"""
        return [
            '<script>alert(',
            'javascript:alert(',
            'onload=alert(',
            'onerror=alert(',
            'onmouseover=alert(',
            'onclick=alert(',
            'prompt(',
            'confirm(',
            'document.cookie',
            'document.write(',
            'innerHTML=',
            'eval(',
            'String.fromCharCode',
            'unescape(',
            'decodeURI(',
            'atob(',
            'Function(',
            'setTimeout(',
            'setInterval('
        ]

    @staticmethod
    def detect_xss(payload: str, response_text: str, response_code: int) -> Tuple[bool, str, str, Dict[str, Any]]:
        """Enhanced XSS detection for XVWA"""
        if response_code not in [200, 201, 202]:
            return False, "", "", {}

        # Decode response for better analysis
        decoded_response = unquote(response_text)
        decoded_payload = unquote(payload)
        
        # Check for direct payload reflection (most common in XVWA)
        if decoded_payload.lower() in decoded_response.lower():
            context = XSSDetector._analyze_xss_context(decoded_payload, decoded_response)
            if context['vulnerable']:
                return True, context['evidence'], context['severity'], {
                    'cwe': 'CWE-79',
                    'cvss': context['cvss'],
                    'owasp': 'A03:2021 – Injection',
                    'recommendation': 'Implement proper input validation and output encoding. Use Content Security Policy (CSP) headers.'
                }

        # Check for XSS indicators in response
        indicators = XSSDetector.get_xss_indicators()
        for indicator in indicators:
            if indicator.lower() in decoded_response.lower():
                if XSSDetector._is_dangerous_context(indicator, decoded_response):
                    return True, f"XSS indicator found: {indicator}", "High", {
                        'cwe': 'CWE-79',
                        'cvss': '6.1',
                        'owasp': 'A03:2021 – Injection',
                        'recommendation': 'Implement proper input validation and output encoding. Use Content Security Policy (CSP) headers.'
                    }

        return False, "", "", {}

    @staticmethod
    def _analyze_xss_context(payload: str, response_text: str) -> Dict[str, Any]:
        """Analyze XSS context to determine exploitability"""
        payload_lower = payload.lower()
        response_lower = response_text.lower()
        
        payload_pos = response_lower.find(payload_lower)
        if payload_pos == -1:
            return {'vulnerable': False, 'evidence': '', 'severity': 'Info', 'cvss': '0.0'}

        # Extract context around payload
        start = max(0, payload_pos - 100)
        end = min(len(response_text), payload_pos + len(payload) + 100)
        context = response_text[start:end]

        # Check for dangerous contexts (common in XVWA)
        dangerous_contexts = [
            (r'<script[^>]*>' + re.escape(payload), 'Script tag context', 'Critical', '9.6'),
            (r'on\w+\s*=\s*["\']?[^"\']*' + re.escape(payload), 'Event handler context', 'High', '8.8'),
            (r'javascript:[^"\']*' + re.escape(payload), 'JavaScript URL context', 'High', '8.8'),
            (r'<[^>]+\s+\w+\s*=\s*[^"\'\s]*' + re.escape(payload), 'Unquoted attribute context', 'High', '7.5'),
            (r'>[^<]*' + re.escape(payload) + r'[^<]*<', 'HTML content context', 'Medium', '6.1')
        ]

        for pattern, desc, severity, cvss in dangerous_contexts:
            if re.search(pattern, context, re.IGNORECASE):
                return {
                    'vulnerable': True,
                    'evidence': f"{desc}: {payload}",
                    'severity': severity,
                    'cvss': cvss
                }

        return {
            'vulnerable': True,
            'evidence': f"Payload reflected: {payload}",
            'severity': 'Medium',
            'cvss': '6.1'
        }

    @staticmethod
    def _is_dangerous_context(indicator: str, response_text: str) -> bool:
        """Check if indicator is in a dangerous context"""
        indicator_pos = response_text.lower().find(indicator.lower())
        if indicator_pos == -1:
            return False

        start = max(0, indicator_pos - 50)
        end = min(len(response_text), indicator_pos + len(indicator) + 50)
        context = response_text[start:end].lower()

        # Check if it's in a comment (usually safe)
        if '<!--' in context and '-->' in context:
            comment_start = context.rfind('<!--', 0, 50)
            comment_end = context.find('-->', 50)
            if comment_start != -1 and comment_end != -1:
                return False

        # Check for dangerous patterns
        dangerous_patterns = [
            r'<script[^>]*>',
            r'on\w+\s*=',
            r'javascript:',
            r'<style[^>]*>'
        ]

        for pattern in dangerous_patterns:
            if re.search(pattern, context, re.IGNORECASE):
                return True

        return True
