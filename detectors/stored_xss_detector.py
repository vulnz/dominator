"""
Stored XSS vulnerability detection logic
"""

import re
from typing import List, Dict, Any, Tuple

class StoredXSSDetector:
    """Stored XSS vulnerability detection logic"""
    
    @staticmethod
    def get_stored_xss_indicators() -> List[str]:
        """Get stored XSS vulnerability indicators"""
        return [
            # Script execution indicators
            '<script>alert(',
            '<script>confirm(',
            '<script>prompt(',
            'javascript:alert(',
            'javascript:confirm(',
            'javascript:prompt(',
            
            # Event handler indicators
            'onload=alert(',
            'onerror=alert(',
            'onclick=alert(',
            'onmouseover=alert(',
            'onfocus=alert(',
            
            # HTML injection indicators
            '<img src=x onerror=',
            '<svg onload=',
            '<iframe src=javascript:',
            '<body onload=',
            '<div onclick=',
            
            # Encoded payloads
            '&lt;script&gt;',
            '%3Cscript%3E',
            '&#60;script&#62;',
            
            # Common XSS test strings
            'XSS_TEST_PAYLOAD',
            'STORED_XSS_FOUND',
            'alert("xss")',
            'alert(\'xss\')',
            'alert(1)',
            'alert(document.cookie)'
        ]
    
    @staticmethod
    def detect_stored_xss(original_response: str, payload: str, follow_up_response: str = None) -> Tuple[bool, str, str]:
        """
        Detect stored XSS vulnerability
        Returns (is_vulnerable, evidence, severity)
        """
        if not payload or len(payload) < 3:
            return False, "No payload provided", "None"
        
        # If we have a follow-up response (second request), check it for stored payload
        response_to_check = follow_up_response if follow_up_response else original_response
        
        if not response_to_check:
            return False, "No response to analyze", "None"
        
        # Check if payload is reflected in dangerous context
        dangerous_contexts = [
            r'<script[^>]*>' + re.escape(payload),
            r'<[^>]*on\w+=["\']?[^"\']*' + re.escape(payload),
            r'<[^>]*src=["\']?[^"\']*' + re.escape(payload),
            r'<[^>]*href=["\']?[^"\']*' + re.escape(payload),
            r'javascript:[^"\']*' + re.escape(payload)
        ]
        
        for context in dangerous_contexts:
            if re.search(context, response_to_check, re.IGNORECASE):
                return True, f"Stored XSS detected in dangerous context: {context}", "High"
        
        # Check for unencoded payload reflection
        if payload in response_to_check:
            # Check if dangerous characters are unencoded
            dangerous_chars = ['<', '>', '"', "'", '&']
            if any(char in payload for char in dangerous_chars):
                # Find the reflection context
                payload_pos = response_to_check.find(payload)
                if payload_pos >= 0:
                    start = max(0, payload_pos - 100)
                    end = min(len(response_to_check), payload_pos + len(payload) + 100)
                    context_snippet = response_to_check[start:end]
                    
                    # Check if it's in HTML context
                    if re.search(r'<[^>]*' + re.escape(payload) + r'[^>]*>', context_snippet):
                        return True, "Stored XSS detected - unencoded HTML injection", "High"
                    elif 'javascript:' in context_snippet.lower():
                        return True, "Stored XSS detected - JavaScript URL injection", "High"
                    else:
                        return True, "Stored XSS detected - payload reflected unencoded", "Medium"
        
        # Check for XSS indicators
        indicators = StoredXSSDetector.get_stored_xss_indicators()
        found_indicators = []
        
        response_lower = response_to_check.lower()
        for indicator in indicators:
            if indicator.lower() in response_lower:
                found_indicators.append(indicator)
        
        if found_indicators:
            return True, f"Stored XSS indicators found: {', '.join(found_indicators[:3])}", "Medium"
        
        return False, "No stored XSS detected", "None"
    
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
        return [
            '<script>alert("STORED_XSS_TEST")</script>',
            '<img src=x onerror=alert("STORED_XSS")>',
            '<svg onload=alert("STORED_XSS")>',
            'javascript:alert("STORED_XSS")',
            '<iframe src="javascript:alert(\'STORED_XSS\')"></iframe>',
            '<body onload=alert("STORED_XSS")>',
            '<div onclick=alert("STORED_XSS")>Click</div>',
            '"><script>alert("STORED_XSS")</script>',
            "'><script>alert('STORED_XSS')</script>",
            '</script><script>alert("STORED_XSS")</script>',
            '<script>confirm("STORED_XSS")</script>',
            '<script>prompt("STORED_XSS")</script>'
        ]
    
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
