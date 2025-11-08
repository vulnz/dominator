"""
XSS vulnerability detector
"""

import re

class XSSDetector:
    """XSS vulnerability detection logic"""
    
    @staticmethod
    def detect_reflected_xss(payload: str, response_text: str, response_code: int) -> bool:
        """Universal XSS detection for any website"""
        if response_code not in [200, 201, 202, 404, 500]:
            return False
        
        # Multiple encoding checks for better detection
        variations = [
            payload,
            payload.lower(),
            payload.upper()
        ]
        
        # Add URL decoded variations
        import urllib.parse
        try:
            decoded = urllib.parse.unquote(payload)
            if decoded != payload:
                variations.extend([decoded, decoded.lower(), decoded.upper()])
        except:
            pass
        
        # Add HTML decoded variations  
        import html
        try:
            html_decoded = html.unescape(payload)
            if html_decoded != payload:
                variations.extend([html_decoded, html_decoded.lower(), html_decoded.upper()])
        except:
            pass
        
        response_lower = response_text.lower()
        
        # Check all variations for reflection
        for variation in variations:
            if variation in response_text or variation.lower() in response_lower:
                # Enhanced context analysis
                if XSSDetector._analyze_xss_context(variation, response_text):
                    return True
        
        # Check for XSS execution indicators regardless of exact payload match
        xss_execution_patterns = [
            r'<script[^>]*>.*alert\s*\(',
            r'javascript:\s*alert\s*\(',
            r'on\w+\s*=\s*["\']?[^"\']*alert\s*\(',
            r'eval\s*\(\s*["\'].*alert',
            r'setTimeout\s*\(\s*["\'].*alert',
            r'document\.write\s*\([^)]*alert'
        ]
        
        import re
        for pattern in xss_execution_patterns:
            if re.search(pattern, response_text, re.IGNORECASE | re.DOTALL):
                return True
        
        return False
    
    @staticmethod
    def _analyze_xss_context(payload: str, response_text: str) -> bool:
        """Enhanced universal XSS context analysis"""
        import re
        
        # Find all occurrences of the payload in response
        payload_positions = []
        start = 0
        while True:
            pos = response_text.lower().find(payload.lower(), start)
            if pos == -1:
                break
            payload_positions.append(pos)
            start = pos + 1
        
        if not payload_positions:
            return False
        
        # Analyze context around each occurrence
        for pos in payload_positions:
            context_start = max(0, pos - 200)
            context_end = min(len(response_text), pos + len(payload) + 200)
            context = response_text[context_start:context_end]
            
            # Check for dangerous contexts with flexible patterns
            dangerous_patterns = [
                # Script tag context
                r'<script[^>]*>[^<]*' + re.escape(payload),
                # Event handler context  
                r'<[^>]*\s+on\w+\s*=\s*["\']?[^"\'<>]*' + re.escape(payload),
                # JavaScript URL context
                r'<[^>]*\s+href\s*=\s*["\']?javascript:[^"\'<>]*' + re.escape(payload),
                # Unquoted attribute context
                r'<[^>]*\s+\w+\s*=\s*[^"\'\s<>]*' + re.escape(payload),
                # Style attribute context
                r'<[^>]*\s+style\s*=\s*["\']?[^"\'<>]*' + re.escape(payload),
                # Meta refresh context
                r'<meta[^>]*content\s*=\s*["\']?[^"\'<>]*' + re.escape(payload)
            ]
            
            for pattern in dangerous_patterns:
                if re.search(pattern, context, re.IGNORECASE | re.DOTALL):
                    return True
            
            # Check if payload contains executable content and is not encoded
            if any(xss_char in payload.lower() for xss_char in ['<script', 'javascript:', 'onerror=', 'onload=', 'alert(']):
                # Check if it's not HTML encoded
                if '&lt;' not in context and '&gt;' not in context:
                    # Check if it's not in comments
                    if not (re.search(r'<!--.*?' + re.escape(payload) + r'.*?-->', context, re.IGNORECASE | re.DOTALL)):
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
