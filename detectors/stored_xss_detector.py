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
        return PayloadLoader.load_indicators('xss_detection')
    
    @staticmethod
    def detect_stored_xss(original_response: str, payload: str, follow_up_response: str = None) -> Tuple[bool, str, str]:
        """
        Detect stored XSS vulnerability with enhanced detection
        Returns (is_vulnerable, evidence, severity)
        """
        if not payload or len(payload) < 3:
            return False, "No payload provided", "None"
        
        # If we have a follow-up response (second request), check it for stored payload
        response_to_check = follow_up_response if follow_up_response else original_response
        
        if not response_to_check:
            return False, "No response to analyze", "None"
        
        # Extract unique identifier from payload for precise detection
        unique_id = StoredXSSDetector._extract_unique_identifier(payload)
        
        # Check if unique identifier is present in response
        if unique_id and unique_id in response_to_check:
            # Check if payload is reflected in dangerous context
            dangerous_contexts = [
                r'<script[^>]*>[^<]*' + re.escape(unique_id),
                r'<[^>]*on\w+=["\']?[^"\']*' + re.escape(unique_id),
                r'<[^>]*src=["\']?[^"\']*' + re.escape(unique_id),
                r'<[^>]*href=["\']?[^"\']*' + re.escape(unique_id),
                r'javascript:[^"\']*' + re.escape(unique_id)
            ]
            
            for context in dangerous_contexts:
                if re.search(context, response_to_check, re.IGNORECASE):
                    return True, f"Stored XSS detected - unique identifier '{unique_id}' found in dangerous context", "High"
            
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
            
            # If unique ID found but not in dangerous context, still potential issue
            return True, f"Potential Stored XSS - unique identifier '{unique_id}' found in response", "Medium"
        
        # Fallback: Check for XSS indicators
        indicators = StoredXSSDetector.get_stored_xss_indicators()
        found_indicators = []
        
        response_lower = response_to_check.lower()
        for indicator in indicators:
            if indicator.lower() in response_lower:
                found_indicators.append(indicator)
        
        if found_indicators:
            return True, f"Stored XSS indicators found: {', '.join(found_indicators[:3])}", "Low"
        
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
