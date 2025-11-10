from typing import Dict, Any, List, Tuple
import re
import hashlib
import json

class IDORDetector:
    """Enhanced Insecure Direct Object Reference (IDOR) vulnerability detection logic"""

    @staticmethod
    def get_idor_parameters() -> List[str]:
        """Get common parameter names that might be vulnerable to IDOR"""
        return [
            # Common ID parameters
            'id', 'user_id', 'userid', 'uid', 'account_id', 'accountid',
            'profile_id', 'profileid', 'doc_id', 'docid', 'file_id', 'fileid',
            'order_id', 'orderid', 'invoice_id', 'invoiceid', 'ticket_id',
            'ticketid', 'message_id', 'messageid', 'post_id', 'postid',
            'comment_id', 'commentid', 'item_id', 'itemid', 'product_id',
            'productid', 'customer_id', 'customerid', 'client_id', 'clientid',
            
            # Additional common patterns
            'key', 'ref', 'reference', 'token', 'session_id', 'sessionid',
            'transaction_id', 'transactionid', 'payment_id', 'paymentid',
            'report_id', 'reportid', 'document_id', 'documentid',
            'folder_id', 'folderid', 'category_id', 'categoryid',
            'group_id', 'groupid', 'team_id', 'teamid', 'project_id', 'projectid',
            
            # XVWA specific patterns
            'user', 'username', 'email', 'phone', 'number', 'code',
            'record', 'entry', 'data', 'info', 'details'
        ]

    @staticmethod
    def detect_idor(original_response: str, modified_response: str,
                    original_code: int, modified_code: int, 
                    original_headers: Dict[str, str] = None,
                    modified_headers: Dict[str, str] = None) -> Tuple[bool, str, str]:
        """
        Enhanced IDOR detection by comparing original and modified responses.
        Returns (is_vulnerable, confidence_level, evidence)
        """
        if original_headers is None:
            original_headers = {}
        if modified_headers is None:
            modified_headers = {}
            
        # 1. Handle redirect responses
        if modified_code in [301, 302, 303, 307, 308]:
            location = modified_headers.get('Location', '')
            if 'login' in location.lower() or 'auth' in location.lower():
                return False, 'low', 'Redirected to authentication page'
            # Redirect to different resource might indicate IDOR
            return True, 'medium', f'Redirected to different resource: {location}'
        
        # 2. Check for successful response codes
        if modified_code not in [200, 201, 202]:
            if modified_code == 403:
                return False, 'low', 'Access forbidden - proper authorization check'
            elif modified_code == 404:
                return False, 'low', 'Resource not found'
            elif modified_code == 401:
                return False, 'low', 'Authentication required'
            else:
                return False, 'low', f'Non-success response code: {modified_code}'
        
        # 3. Check for empty or minimal responses
        if len(modified_response.strip()) < 50:
            return False, 'low', 'Response too short to be meaningful'
            
        # 4. Enhanced error detection
        modified_lower = modified_response.lower()
        error_patterns = [
            'error', 'not found', 'access denied', 'forbidden', 
            'login required', 'please log in', 'unauthorized',
            'permission denied', 'invalid request', 'bad request',
            'you are not authorized', 'access restricted',
            'authentication required', 'session expired'
        ]
        
        if any(pattern in modified_lower for pattern in error_patterns):
            return False, 'low', 'Response contains error indicators'

        # 5. Compare response characteristics
        analysis = IDORDetector._analyze_response_differences(
            original_response, modified_response, original_headers, modified_headers
        )
        
        # 6. Determine vulnerability based on analysis
        if analysis['different_content'] and analysis['confidence'] > 0.3:
            evidence = IDORDetector._build_evidence(analysis)
            confidence = 'high' if analysis['confidence'] > 0.7 else 'medium'
            return True, confidence, evidence
        
        return False, 'low', 'Responses are too similar or indicate no IDOR'

    @staticmethod
    def _analyze_response_differences(original_response: str, modified_response: str,
                                    original_headers: Dict[str, str], 
                                    modified_headers: Dict[str, str]) -> Dict[str, Any]:
        """Analyze differences between original and modified responses"""
        analysis = {
            'different_content': False,
            'confidence': 0.0,
            'size_difference': 0,
            'title_different': False,
            'personal_data_found': False,
            'structure_different': False,
            'content_type_same': True
        }
        
        # Compare content types
        orig_ct = original_headers.get('Content-Type', '').lower()
        mod_ct = modified_headers.get('Content-Type', '').lower()
        if orig_ct != mod_ct:
            analysis['content_type_same'] = False
            analysis['confidence'] += 0.2
        
        # Compare response sizes
        size_diff = abs(len(original_response) - len(modified_response))
        analysis['size_difference'] = size_diff
        if size_diff > 100:  # Significant size difference
            analysis['different_content'] = True
            analysis['confidence'] += 0.3
        
        # Compare titles
        orig_title = IDORDetector._extract_title(original_response)
        mod_title = IDORDetector._extract_title(modified_response)
        if orig_title != mod_title and mod_title:
            analysis['title_different'] = True
            analysis['different_content'] = True
            analysis['confidence'] += 0.4
        
        # Check for personal data patterns in modified response
        if IDORDetector._contains_personal_data(modified_response):
            analysis['personal_data_found'] = True
            analysis['different_content'] = True
            analysis['confidence'] += 0.5
        
        # Compare HTML structure
        if IDORDetector._compare_html_structure(original_response, modified_response):
            analysis['structure_different'] = True
            analysis['different_content'] = True
            analysis['confidence'] += 0.3
        
        # Compare content fingerprints
        orig_fingerprint = IDORDetector._get_response_fingerprint(original_response)
        mod_fingerprint = IDORDetector._get_response_fingerprint(modified_response)
        if orig_fingerprint != mod_fingerprint:
            analysis['different_content'] = True
            analysis['confidence'] += 0.2
        
        return analysis

    @staticmethod
    def _extract_title(response: str) -> str:
        """Extract title from HTML response"""
        title_match = re.search(r'<title[^>]*>(.*?)</title>', response, re.IGNORECASE | re.DOTALL)
        if title_match:
            return title_match.group(1).strip()
        return ""

    @staticmethod
    def _contains_personal_data(response: str) -> bool:
        """Check if response contains personal data patterns"""
        personal_patterns = [
            r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',  # Email
            r'\b\d{3}-\d{2}-\d{4}\b',  # SSN pattern
            r'\b\d{3}[-.]?\d{3}[-.]?\d{4}\b',  # Phone number
            r'\b\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}\b',  # Credit card
            r'\b(?:user|name|email|phone|address|birth):\s*[^\s<]+',  # Key-value pairs
            r'<td[^>]*>\s*[A-Za-z]+\s+[A-Za-z]+\s*</td>',  # Names in table cells
        ]
        
        for pattern in personal_patterns:
            if re.search(pattern, response, re.IGNORECASE):
                return True
        return False

    @staticmethod
    def _compare_html_structure(original: str, modified: str) -> bool:
        """Compare HTML structure between responses"""
        def get_structure(html):
            # Extract tag structure
            tags = re.findall(r'<(\w+)[^>]*>', html, re.IGNORECASE)
            return ''.join(tags[:20])  # First 20 tags
        
        orig_structure = get_structure(original)
        mod_structure = get_structure(modified)
        
        return orig_structure != mod_structure

    @staticmethod
    def _build_evidence(analysis: Dict[str, Any]) -> str:
        """Build evidence string based on analysis"""
        evidence_parts = []
        
        if analysis['title_different']:
            evidence_parts.append("Different page titles")
        if analysis['personal_data_found']:
            evidence_parts.append("Personal data found in response")
        if analysis['size_difference'] > 500:
            evidence_parts.append(f"Significant size difference ({analysis['size_difference']} bytes)")
        if analysis['structure_different']:
            evidence_parts.append("Different HTML structure")
        if not analysis['content_type_same']:
            evidence_parts.append("Different content types")
        
        if evidence_parts:
            return "IDOR detected: " + ", ".join(evidence_parts)
        else:
            return "IDOR detected: Response content differs significantly from original"

    @staticmethod
    def get_response_snippet(response_text: str) -> str:
        """Get a snippet of the response for the report"""
        # Try to extract meaningful content
        title = IDORDetector._extract_title(response_text)
        if title:
            snippet = f"Title: {title}"
        else:
            # Extract first meaningful text content
            text_content = re.sub(r'<[^>]+>', ' ', response_text)
            text_content = re.sub(r'\s+', ' ', text_content).strip()
            snippet = text_content[:200] + '...' if len(text_content) > 200 else text_content
        
        # Add personal data indicators if found
        if IDORDetector._contains_personal_data(response_text):
            snippet += " [Contains personal data]"
            
        return snippet

    @staticmethod
    def get_remediation_advice() -> str:
        """Get remediation advice for IDOR vulnerabilities"""
        return ("Implement proper access control checks on the server-side to ensure users can only "
                "access resources they are authorized to view. Use session-based authorization, "
                "validate user permissions for each request, and avoid exposing direct object references. "
                "Consider using indirect references or UUIDs instead of sequential IDs.")

    @staticmethod
    def _get_response_fingerprint(text: str) -> str:
        """Create a simple fingerprint of a response body to compare pages."""
        text = re.sub(r'<(script|style).*?>.*?</\1>', '', text, flags=re.DOTALL | re.IGNORECASE)
        text = re.sub(r'<.*?>', ' ', text)
        text = re.sub(r'\s+', ' ', text).strip()
        return hashlib.sha1(text[:500].encode('utf-8', 'ignore')).hexdigest()
