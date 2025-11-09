"""
Insecure Reflected Content detector
"""

import re
from typing import Tuple, List, Dict, Any

class InsecureReflectedContentDetector:
    """Insecure Reflected Content detection logic"""
    
    @staticmethod
    def get_reflection_test_payloads() -> List[str]:
        """Get payloads to test for content reflection"""
        return [
            'DOMINATOR_REFLECT_TEST_12345',
            'UNIQUE_REFLECTION_MARKER_67890',
            'TEST_CONTENT_REFLECTION_ABCDEF',
            '<DOMINATOR_HTML_REFLECT>',
            'javascript:DOMINATOR_JS_REFLECT',
            'DOMINATOR"QUOTE\'REFLECT',
            'DOMINATOR<script>REFLECT</script>',
            'DOMINATOR%3Cscript%3EREFLECT'
        ]
    
    @staticmethod
    def detect_insecure_reflection(response_text: str, response_code: int, 
                                 payload: str, parameter: str) -> Tuple[bool, str, str, Dict[str, Any]]:
        """Detect insecure content reflection"""
        if response_code >= 400:
            return False, "", "", {}
        
        # Check if payload is reflected in response
        reflection_analysis = InsecureReflectedContentDetector._analyze_reflection(
            payload, response_text
        )
        
        if reflection_analysis['is_reflected']:
            context = reflection_analysis['context']
            encoding = reflection_analysis['encoding']
            position = reflection_analysis['position']
            
            # Determine severity based on context and encoding
            severity = InsecureReflectedContentDetector._determine_severity(context, encoding)
            
            evidence = (f"Parameter '{parameter}' reflects user input in {context} context "
                       f"with {encoding} encoding at position {position}")
            
            return True, evidence, severity, {
                'cwe': 'CWE-79',
                'cvss': '6.1' if severity == "High" else '4.3',
                'owasp': 'A03:2021 – Injection',
                'recommendation': 'Implement proper output encoding based on context (HTML, JavaScript, CSS, URL)',
                'reflection_details': reflection_analysis
            }
        
        return False, "", "", {}
    
    @staticmethod
    def _analyze_reflection(payload: str, response_text: str) -> Dict[str, Any]:
        """Analyze how payload is reflected in response"""
        result = {
            'is_reflected': False,
            'context': 'none',
            'encoding': 'none',
            'position': -1,
            'surrounding_content': ''
        }
        
        # Find payload in response (case sensitive)
        payload_pos = response_text.find(payload)
        if payload_pos == -1:
            # Try case insensitive
            payload_pos = response_text.lower().find(payload.lower())
            if payload_pos == -1:
                return result
        
        result['is_reflected'] = True
        result['position'] = payload_pos
        
        # Get surrounding content for context analysis
        start = max(0, payload_pos - 50)
        end = min(len(response_text), payload_pos + len(payload) + 50)
        result['surrounding_content'] = response_text[start:end]
        
        # Analyze context
        context_before = response_text[max(0, payload_pos - 100):payload_pos].lower()
        context_after = response_text[payload_pos + len(payload):payload_pos + len(payload) + 100].lower()
        
        # Determine context type
        if '<script' in context_before and '</script>' in context_after:
            result['context'] = 'javascript'
        elif '<style' in context_before and '</style>' in context_after:
            result['context'] = 'css'
        elif 'href=' in context_before or 'src=' in context_before:
            result['context'] = 'attribute'
        elif '<' in context_before and '>' in context_after:
            result['context'] = 'html_tag'
        elif payload_pos < 100:  # Near beginning of response
            result['context'] = 'first_byte'
        else:
            result['context'] = 'html_content'
        
        # Check encoding
        if '&lt;' in response_text or '&gt;' in response_text:
            result['encoding'] = 'html_encoded'
        elif '%3C' in response_text or '%3E' in response_text:
            result['encoding'] = 'url_encoded'
        elif '\\x' in response_text or '\\u' in response_text:
            result['encoding'] = 'unicode_escaped'
        else:
            result['encoding'] = 'none'
        
        return result
    
    @staticmethod
    def _determine_severity(context: str, encoding: str) -> str:
        """Determine severity based on reflection context and encoding"""
        # High risk contexts without proper encoding
        if context in ['javascript', 'first_byte', 'attribute'] and encoding == 'none':
            return "High"
        
        # Medium risk contexts
        if context in ['html_content', 'html_tag'] and encoding == 'none':
            return "Medium"
        
        # Lower risk if properly encoded
        if encoding in ['html_encoded', 'url_encoded']:
            return "Low"
        
        return "Medium"
    
    @staticmethod
    def get_evidence(parameter: str, context: str, encoding: str, position: int) -> str:
        """Get detailed evidence for insecure reflection"""
        return (f"Parameter '{parameter}' content reflected in {context} context "
                f"with {encoding} encoding at byte position {position}")
    
    @staticmethod
    def get_response_snippet(surrounding_content: str) -> str:
        """Get response snippet showing reflection context"""
        return f"Reflection context: {surrounding_content}"
    
    @staticmethod
    def get_remediation_advice() -> str:
        """Get remediation advice for insecure reflection"""
        return (
            "Implement context-aware output encoding: "
            "HTML encoding for HTML content, JavaScript encoding for JS context, "
            "URL encoding for URLs, CSS encoding for stylesheets. "
            "Use Content Security Policy (CSP) to prevent XSS attacks."
        )
