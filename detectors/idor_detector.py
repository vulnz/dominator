from typing import Dict, Any
import re
import hashlib

class IDORDetector:
    """Insecure Direct Object Reference (IDOR) vulnerability detection logic"""

    @staticmethod
    def get_idor_parameters() -> list:
        """Get common parameter names that might be vulnerable to IDOR"""
        return [
            'id', 'user_id', 'userid', 'uid', 'account_id', 'accountid',
            'profile_id', 'profileid', 'doc_id', 'docid', 'file_id', 'fileid',
            'order_id', 'orderid', 'invoice_id', 'invoiceid', 'ticket_id',
            'ticketid', 'message_id', 'messageid', 'post_id', 'postid',
            'comment_id', 'commentid', 'item_id', 'itemid', 'product_id',
            'productid', 'customer_id', 'customerid', 'client_id', 'clientid'
        ]

    @staticmethod
    def detect_idor(original_response: str, modified_response: str,
                    original_code: int, modified_code: int) -> bool:
        """
        Detect IDOR by comparing original and modified responses.
        Returns True if an IDOR is likely present.
        """
        # 1. Check for successful response on modified request
        if modified_code != 200:
            return False
            
        # 2. Check that the modified response is not an error or login page
        modified_lower = modified_response.lower()
        error_indicators = ['error', 'not found', 'access denied', 'forbidden', 'login required', 'please log in']
        if any(indicator in modified_lower for indicator in error_indicators):
            return False

        # 3. Compare fingerprints to see if pages are substantially different
        original_fingerprint = IDORDetector._get_response_fingerprint(original_response)
        modified_fingerprint = IDORDetector._get_response_fingerprint(modified_response)
        
        # If fingerprints are the same, no IDOR
        if original_fingerprint == modified_fingerprint:
            return False
        
        return True

    @staticmethod
    def get_evidence(original_response: str, modified_response: str) -> str:
        """Generate evidence for the IDOR finding"""
        return "Access to a different resource was successful by changing the ID parameter, indicating an IDOR vulnerability."

    @staticmethod
    def get_response_snippet(response_text: str) -> str:
        """Get a snippet of the response for the report"""
        # Extract title or first few lines as a snippet
        title_match = re.search(r'<title>(.*?)</title>', response_text, re.IGNORECASE)
        if title_match:
            return f"Page Title: {title_match.group(1).strip()}"
        
        # Fallback to first 200 characters
        snippet = re.sub(r'\s+', ' ', response_text).strip()
        return snippet[:200] + '...' if len(snippet) > 200 else snippet

    @staticmethod
    def get_remediation_advice() -> str:
        """Get remediation advice for IDOR vulnerabilities"""
        return "Implement proper access control checks on the server-side to ensure that users can only access resources they are authorized to view. Do not rely on client-side controls or obscurity of IDs."

    @staticmethod
    def _get_response_fingerprint(text: str) -> str:
        """Create a simple fingerprint of a response body to compare pages."""
        text = re.sub(r'<(script|style).*?>.*?</\1>', '', text, flags=re.DOTALL | re.IGNORECASE)
        text = re.sub(r'<.*?>', ' ', text)
        text = re.sub(r'\s+', ' ', text).strip()
        return hashlib.sha1(text[:500].encode('utf-8', 'ignore')).hexdigest()
