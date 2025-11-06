"""
SSTI (Server-Side Template Injection) vulnerability detection logic
"""

import re
from typing import List, Tuple, Dict, Any

class SSTIDetector:
    """SSTI vulnerability detection logic"""
    
    @staticmethod
    def get_ssti_indicators() -> List[str]:
        """Get SSTI detection indicators"""
        return [
            # Mathematical expressions results
            '49', '64', '343', '1728',  # Results of 7*7, 8*8, 7*7*7, 12*12*12
            
            # Template engine specific indicators
            'TemplateAssertionError', 'TemplateSyntaxError', 'UndefinedError',
            'jinja2.exceptions', 'django.template', 'tornado.template',
            'mako.exceptions', 'twig.error', 'smarty.exception',
            
            # Error messages
            'template syntax error', 'undefined variable', 'template not found',
            'invalid template', 'template compilation error',
            
            # Engine-specific errors
            'Twig_Error', 'Smarty_Exception', 'Mako_Exception',
            'Jinja2TemplateError', 'DjangoTemplateError'
        ]
    
    @staticmethod
    def get_template_engines() -> Dict[str, List[str]]:
        """Get template engine specific patterns"""
        return {
            'jinja2': [
                'jinja2', 'flask', 'ansible',
                'TemplateAssertionError', 'UndefinedError',
                'jinja2.exceptions'
            ],
            'django': [
                'django.template', 'DjangoTemplateError',
                'TemplateSyntaxError', 'TemplateDoesNotExist'
            ],
            'twig': [
                'Twig_Error', 'twig.error', 'TwigException',
                'Twig_Error_Syntax', 'Twig_Error_Runtime'
            ],
            'smarty': [
                'Smarty_Exception', 'smarty.exception',
                'SmartyException', 'Smarty_Internal_Exception'
            ],
            'mako': [
                'mako.exceptions', 'Mako_Exception',
                'MakoException', 'TemplateLookupException'
            ],
            'tornado': [
                'tornado.template', 'TornadoTemplateError',
                'ParseError', 'tornado.template.ParseError'
            ]
        }
    
    @staticmethod
    def detect_ssti(response_text: str, response_code: int, payload: str) -> bool:
        """Detect SSTI vulnerability"""
        if response_code >= 500:
            return False
        
        response_lower = response_text.lower()
        
        # Check for mathematical expression results
        if SSTIDetector._check_math_results(payload, response_text):
            return True
        
        # Check for template engine error messages
        indicators = SSTIDetector.get_ssti_indicators()
        for indicator in indicators:
            if indicator.lower() in response_lower:
                return True
        
        # Check for template engine specific patterns
        engines = SSTIDetector.get_template_engines()
        for engine, patterns in engines.items():
            for pattern in patterns:
                if pattern.lower() in response_lower:
                    return True
        
        return False
    
    @staticmethod
    def _check_math_results(payload: str, response_text: str) -> bool:
        """Check if mathematical expressions in payload were evaluated"""
        # Common SSTI math payloads and their results
        math_checks = {
            '7*7': '49',
            '8*8': '64', 
            '9*9': '81',
            '7*7*7': '343',
            '12*12*12': '1728',
            '6*6': '36',
            '5*5': '25'
        }
        
        for expr, result in math_checks.items():
            if expr in payload and result in response_text:
                # Make sure it's not just coincidental
                if len(response_text) > 100:  # Avoid false positives on short responses
                    return True
        
        return False
    
    @staticmethod
    def get_evidence(payload: str, response_text: str) -> str:
        """Get evidence of SSTI vulnerability"""
        evidence_parts = []
        
        # Check for math results
        if SSTIDetector._check_math_results(payload, response_text):
            evidence_parts.append("Mathematical expression in payload was evaluated in response")
        
        # Check for error messages
        indicators = SSTIDetector.get_ssti_indicators()
        found_indicators = []
        response_lower = response_text.lower()
        
        for indicator in indicators:
            if indicator.lower() in response_lower:
                found_indicators.append(indicator)
        
        if found_indicators:
            evidence_parts.append(f"Template engine error indicators found: {', '.join(found_indicators[:3])}")
        
        # Check for specific engines
        engines = SSTIDetector.get_template_engines()
        detected_engines = []
        
        for engine, patterns in engines.items():
            for pattern in patterns:
                if pattern.lower() in response_lower:
                    detected_engines.append(engine)
                    break
        
        if detected_engines:
            evidence_parts.append(f"Template engines detected: {', '.join(set(detected_engines))}")
        
        return "; ".join(evidence_parts) if evidence_parts else "SSTI indicators found in response"
    
    @staticmethod
    def get_response_snippet(payload: str, response_text: str) -> str:
        """Get relevant response snippet"""
        # Look for math results first
        math_checks = ['49', '64', '81', '343', '1728', '36', '25']
        for result in math_checks:
            if result in response_text:
                start = max(0, response_text.find(result) - 50)
                end = min(len(response_text), response_text.find(result) + 50)
                return response_text[start:end]
        
        # Look for error messages
        indicators = SSTIDetector.get_ssti_indicators()
        for indicator in indicators:
            if indicator.lower() in response_text.lower():
                pos = response_text.lower().find(indicator.lower())
                start = max(0, pos - 50)
                end = min(len(response_text), pos + len(indicator) + 50)
                return response_text[start:end]
        
        return response_text[:200] + "..." if len(response_text) > 200 else response_text
    
    @staticmethod
    def get_remediation_advice() -> str:
        """Get remediation advice for SSTI"""
        return """
        1. Avoid using user input directly in template rendering
        2. Use sandboxed template environments when possible
        3. Implement proper input validation and sanitization
        4. Use template engines with built-in security features
        5. Consider using logic-less templates (like Mustache)
        6. Implement Content Security Policy (CSP) headers
        7. Regular security audits of template usage
        """
    
    @staticmethod
    def get_evidence(payload: str, response_text: str) -> str:
        """Get evidence for SSTI"""
        evidence_parts = []
        
        # Check for template evaluation
        if '49' in response_text and '7*7' in payload:
            evidence_parts.append("Mathematical expression evaluated (7*7=49)")
        elif '14' in response_text and '7+7' in payload:
            evidence_parts.append("Mathematical expression evaluated (7+7=14)")
        
        # Check for template engine errors
        if 'template' in response_text.lower():
            evidence_parts.append("Template engine error detected")
        if 'jinja' in response_text.lower():
            evidence_parts.append("Jinja2 template engine detected")
        
        if evidence_parts:
            return f"SSTI detected: {'; '.join(evidence_parts)}"
        else:
            return f"Potential SSTI with payload: {payload}"
    
    @staticmethod
    def get_response_snippet(payload: str, response_text: str) -> str:
        """Get response snippet for SSTI"""
        if len(response_text) > 300:
            return response_text[:300] + "..."
        return response_text
