"""
IDOR (Insecure Direct Object Reference) vulnerability detection logic
"""

import re
from typing import Tuple, List, Dict, Any

class IDORDetector:
    """IDOR vulnerability detection logic"""
    
    @staticmethod
    def get_idor_parameters() -> List[str]:
        """Get parameters commonly vulnerable to IDOR"""
        return [
            'id', 'user_id', 'userid', 'uid', 'account_id', 'accountid',
            'profile_id', 'profileid', 'doc_id', 'docid', 'file_id', 'fileid',
            'order_id', 'orderid', 'invoice_id', 'invoiceid', 'ticket_id',
            'ticketid', 'message_id', 'messageid', 'post_id', 'postid',
            'comment_id', 'commentid', 'item_id', 'itemid', 'product_id',
            'productid', 'customer_id', 'customerid', 'client_id', 'clientid'
        ]
    
    @staticmethod
    def detect_idor(original_response: str, modified_response: str, original_code: int, modified_code: int) -> bool:
        """
        Detect IDOR vulnerability by comparing responses
        Returns True if IDOR is detected
        """
        # Both responses should be successful
        if original_code >= 400 or modified_code >= 400:
            return False
        
        # Responses should be different (indicating different data accessed)
        if original_response == modified_response:
            return False
        
        # Check for indicators of different user data
        user_indicators = [
            r'user(?:name)?["\s:=]+([^"\s<>,]+)',
            r'email["\s:=]+([^"\s<>,]+)',
            r'name["\s:=]+([^"\s<>,]+)',
            r'profile["\s:=]+([^"\s<>,]+)',
            r'account["\s:=]+([^"\s<>,]+)'
        ]
        
        original_data = set()
        modified_data = set()
        
        for pattern in user_indicators:
            original_matches = re.findall(pattern, original_response, re.IGNORECASE)
            modified_matches = re.findall(pattern, modified_response, re.IGNORECASE)
            
            original_data.update(original_matches)
            modified_data.update(modified_matches)
        
        # If we found different user data, it's likely IDOR
        if original_data and modified_data and original_data != modified_data:
            return True
        
        # Check for different content lengths (might indicate different data)
        length_diff = abs(len(original_response) - len(modified_response))
        if length_diff > 100:  # Significant difference in content
            return True
        
        return False
    
    @staticmethod
    def get_evidence(original_response: str, modified_response: str) -> str:
        """Get evidence of IDOR vulnerability"""
        evidence_parts = []
        
        # Check for different user data
        user_patterns = [
            r'user(?:name)?["\s:=]+([^"\s<>,]+)',
            r'email["\s:=]+([^"\s<>,]+)',
            r'name["\s:=]+([^"\s<>,]+)'
        ]
        
        for pattern in user_patterns:
            orig_matches = re.findall(pattern, original_response, re.IGNORECASE)
            mod_matches = re.findall(pattern, modified_response, re.IGNORECASE)
            
            if orig_matches and mod_matches and orig_matches != mod_matches:
                evidence_parts.append(f"Different user data accessed: {orig_matches[0]} vs {mod_matches[0]}")
        
        # Check content length difference
        length_diff = abs(len(original_response) - len(modified_response))
        if length_diff > 100:
            evidence_parts.append(f"Significant content difference: {length_diff} bytes")
        
        if evidence_parts:
            return "IDOR vulnerability detected: " + "; ".join(evidence_parts)
        
        return "IDOR vulnerability detected: Different responses for different ID values"
    
    @staticmethod
    def get_response_snippet(response: str) -> str:
        """Get relevant response snippet"""
        # Look for user-specific data
        patterns = [
            r'user(?:name)?["\s:=]+[^"\s<>,]+',
            r'email["\s:=]+[^"\s<>,]+',
            r'name["\s:=]+[^"\s<>,]+'
        ]
        
        for pattern in patterns:
            match = re.search(pattern, response, re.IGNORECASE)
            if match:
                start = max(0, match.start() - 50)
                end = min(len(response), match.end() + 50)
                return response[start:end]
        
        return response[:200]
    
    @staticmethod
    def get_remediation_advice() -> str:
        """Get remediation advice for IDOR vulnerabilities"""
        return (
            "Implement proper access controls and authorization checks. "
            "Use indirect object references (like session-based mappings) instead of direct database IDs. "
            "Validate that the current user has permission to access the requested resource. "
            "Consider using UUIDs instead of sequential IDs."
        )
