"""
False positive filtering library
"""

import re
from typing import Dict, List, Tuple, Any

class FalsePositiveFilter:
    """Filter false positive vulnerabilities"""
    
    def __init__(self):
        self.confidence_thresholds = {
            'xss': 0.7,
            'sqli': 0.8,
            'lfi': 0.7,
            'dirbrute': 0.6,
            'gitexposed': 0.8,
            'csrf': 0.5,
            'default': 0.6
        }
    
    def filter_vulnerability(self, vuln: Dict[str, Any]) -> Tuple[bool, str]:
        """
        Filter vulnerability for false positives
        Returns (is_valid, reason)
        """
        module = vuln.get('module', '')
        response_text = vuln.get('response_snippet', '')
        payload = vuln.get('payload', '')
        evidence = vuln.get('evidence', '')
        
        # Generic false positive checks
        if self._is_generic_false_positive(vuln):
            return False, "Generic false positive detected"
        
        # Module-specific filtering
        if module == 'xss':
            return self._filter_xss_false_positive(vuln)
        elif module == 'sqli':
            return self._filter_sqli_false_positive(vuln)
        elif module == 'lfi':
            return self._filter_lfi_false_positive(vuln)
        elif module == 'dirbrute':
            return self._filter_dirbrute_false_positive(vuln)
        elif module == 'gitexposed':
            return self._filter_git_false_positive(vuln)
        elif module == 'csrf':
            return self._filter_csrf_false_positive(vuln)
        elif module == 'passive_debug':
            return self._filter_debug_false_positive(vuln)
        elif module == 'idor':
            return self._filter_idor_false_positive(vuln)
        
        return True, "No false positive detected"
    
    def _is_generic_false_positive(self, vuln: Dict[str, Any]) -> bool:
        """Check for generic false positive patterns"""
        response_text = vuln.get('response_snippet', '').lower()
        
        # Empty or very short responses
        if len(response_text.strip()) < 10:
            return True
        
        # Generic error pages that might be mistaken for vulnerabilities
        generic_errors = [
            'page not found', 'not found', '404', 'error 404',
            'access denied', 'forbidden', '403', 'error 403',
            'internal server error', '500', 'error 500',
            'bad request', '400', 'error 400'
        ]
        
        error_count = sum(1 for error in generic_errors if error in response_text)
        if error_count >= 2:
            return True
        
        return False
    
    def _filter_xss_false_positive(self, vuln: Dict[str, Any]) -> Tuple[bool, str]:
        """Filter XSS false positives"""
        response_text = vuln.get('response_snippet', '').lower()
        payload = vuln.get('payload', '')
        
        # Check if payload is actually reflected in a meaningful way
        if payload and payload.lower() not in response_text:
            return False, "Payload not found in response"
        
        # Check for HTML encoding that would prevent XSS
        if payload and '&lt;' in response_text and '&gt;' in response_text:
            return False, "Payload appears to be HTML encoded"
        
        # Check if reflection is in comments or non-executable context
        if payload and f'<!-- {payload}' in response_text:
            return False, "Payload reflected in HTML comments only"
        
        # Check for JavaScript context but with proper escaping
        if 'script' in payload.lower() and '\\' in response_text:
            return False, "Payload appears to be escaped in JavaScript context"
        
        return True, "Valid XSS vulnerability"
    
    def _filter_sqli_false_positive(self, vuln: Dict[str, Any]) -> Tuple[bool, str]:
        """Filter SQL injection false positives"""
        response_text = vuln.get('response_snippet', '').lower()
        evidence = vuln.get('evidence', '').lower()
        
        # Check for generic error messages that might not be SQL-related
        generic_errors = [
            'page not found', 'not found', 'invalid request',
            'bad request', 'access denied', 'forbidden'
        ]
        
        if any(error in response_text for error in generic_errors):
            return False, "Generic error message, not SQL-specific"
        
        # Check for actual SQL error patterns in evidence
        sql_indicators = [
            'mysql', 'postgresql', 'oracle', 'sqlite', 'mssql',
            'syntax error', 'sql', 'database', 'query'
        ]
        
        if not any(indicator in evidence for indicator in sql_indicators):
            return False, "No SQL-specific error indicators found"
        
        return True, "Valid SQL injection vulnerability"
    
    def _filter_lfi_false_positive(self, vuln: Dict[str, Any]) -> Tuple[bool, str]:
        """Filter LFI false positives"""
        response_text = vuln.get('response_snippet', '').lower()
        payload = vuln.get('payload', '')
        
        # Check for actual file content indicators
        file_indicators = [
            'root:', '/bin/', '/usr/', 'daemon:', 'sys:',  # /etc/passwd
            '[extensions]', '[files]', '[fonts]',  # win.ini
            '<?php', '#!/bin/', 'function', 'class'  # source code
        ]
        
        if not any(indicator in response_text for indicator in file_indicators):
            return False, "No file content indicators found"
        
        # Check if it's just error message about file not found
        error_indicators = [
            'file not found', 'no such file', 'cannot open',
            'failed to open', 'permission denied'
        ]
        
        if any(error in response_text for error in error_indicators):
            return False, "File error message, not actual file inclusion"
        
        return True, "Valid LFI vulnerability"
    
    def _filter_dirbrute_false_positive(self, vuln: Dict[str, Any]) -> Tuple[bool, str]:
        """Filter directory bruteforce false positives"""
        response_text = vuln.get('response_snippet', '').lower()
        target = vuln.get('target', '')
        
        # Check response size - very small responses are likely false positives
        if len(response_text) < 100:
            return False, "Response too small to be meaningful content"
        
        # Check for actual content vs error pages
        content_indicators = [
            '<form', '<input', '<table', '<div class=', '<div id=',
            'function(', 'var ', 'document.', 'window.'
        ]
        
        content_count = sum(1 for indicator in content_indicators if indicator in response_text)
        
        # Check for error indicators
        error_indicators = [
            'not found', '404', 'error', 'exception',
            'warning', 'notice', 'fatal'
        ]
        
        error_count = sum(1 for indicator in error_indicators if indicator in response_text)
        
        # If more errors than content, likely false positive
        if error_count > content_count and content_count < 2:
            return False, "More error indicators than content indicators"
        
        return True, "Valid directory/file found"
    
    def _filter_git_false_positive(self, vuln: Dict[str, Any]) -> Tuple[bool, str]:
        """Filter Git exposure false positives"""
        response_text = vuln.get('response_snippet', '').lower()
        target = vuln.get('target', '')
        
        # Check for actual Git content
        git_indicators = [
            'ref:', 'refs/', 'objects/', 'head', 'master', 'main',
            '[core]', 'repositoryformatversion', 'filemode',
            'bare = false', 'logallrefupdates'
        ]
        
        if not any(indicator in response_text for indicator in git_indicators):
            return False, "No Git-specific content found"
        
        # Check if it's just a 404 or error page
        if 'not found' in response_text and len(response_text) < 500:
            return False, "Appears to be 404 page, not Git content"
        
        return True, "Valid Git exposure"
    
    def _filter_csrf_false_positive(self, vuln: Dict[str, Any]) -> Tuple[bool, str]:
        """Filter CSRF false positives"""
        evidence = vuln.get('evidence', '').lower()
        response_text = vuln.get('response_snippet', '').lower()
        
        # Check if form actually exists and is meaningful
        if 'form' not in response_text and 'form' not in evidence:
            return False, "No form found in response"
        
        # Check for GET forms (not vulnerable to CSRF)
        if 'method' in evidence and 'get' in evidence:
            return False, "GET form not vulnerable to CSRF"
        
        # Check for forms with only hidden fields (might be legitimate)
        if 'hidden' in evidence and 'input' not in evidence.replace('hidden', ''):
            return False, "Form contains only hidden fields"
        
        return True, "Valid CSRF vulnerability"
    
    def calculate_confidence_score(self, vuln: Dict[str, Any]) -> float:
        """Calculate confidence score for vulnerability"""
        module = vuln.get('module', '')
        base_confidence = self.confidence_thresholds.get(module, self.confidence_thresholds['default'])
        
        # Adjust confidence based on evidence quality
        evidence = vuln.get('evidence', '').lower()
        response_text = vuln.get('response_snippet', '').lower()
        
        confidence_adjustments = 0.0
        
        # Positive indicators
        if 'high confidence' in evidence:
            confidence_adjustments += 0.2
        elif 'medium confidence' in evidence:
            confidence_adjustments += 0.1
        
        # Negative indicators
        if 'low confidence' in evidence:
            confidence_adjustments -= 0.2
        
        if len(response_text) < 50:
            confidence_adjustments -= 0.3
        
        # Error indicators reduce confidence
        error_count = sum(1 for error in ['error', 'warning', 'notice'] if error in response_text)
        if error_count > 2:
            confidence_adjustments -= 0.2
        
        final_confidence = max(0.0, min(1.0, base_confidence + confidence_adjustments))
        return final_confidence
    
    def _filter_debug_false_positive(self, vuln: Dict[str, Any]) -> Tuple[bool, str]:
        """Filter debug information false positives"""
        evidence = vuln.get('evidence', [])
        vuln_type = vuln.get('type', '')
        
        if vuln_type == 'development_comment':
            comment_type = vuln.get('comment_type', '').lower()
            
            # Check evidence for false positive patterns
            if isinstance(evidence, list):
                for comment in evidence:
                    comment_lower = str(comment).lower()
                    
                    # Common false positives for test comments
                    if 'test' in comment_type:
                        fp_patterns = [
                            'test case', 'test suite', 'test data', 'test file',
                            'test your', 'test our', 'test this', 'test the',
                            'unit test', 'integration test', 'test page'
                        ]
                        if any(pattern in comment_lower for pattern in fp_patterns):
                            return False, f"Generic test-related content, not development comment"
                    
                    # Common false positives for TODO comments
                    if 'todo' in comment_type:
                        fp_patterns = [
                            'todo list', 'todo item', 'todo task',
                            'customer todo', 'user todo'
                        ]
                        if any(pattern in comment_lower for pattern in fp_patterns):
                            return False, f"User-facing TODO, not development comment"
                    
                    # Very short comments are likely false positives
                    if len(str(comment).strip()) < 10:
                        return False, f"Comment too short to be meaningful development comment"
        
        return True, "Valid debug information finding"
    
    def _filter_idor_false_positive(self, vuln: Dict[str, Any]) -> Tuple[bool, str]:
        """Filter IDOR false positives"""
        target = vuln.get('target', '').lower()
        parameter = vuln.get('parameter', '').lower()
        payload = vuln.get('payload', '')
        evidence = vuln.get('evidence', '').lower()
        
        # Check if this is a registration, guestbook, or comment form
        form_type_indicators = [
            'signup', 'register', 'registration', 'newuser', 'adduser', 'createuser',
            'guestbook', 'comment', 'message', 'feedback'
        ]
        
        if any(indicator in target for indicator in form_type_indicators):
            return False, f"Form submission page ({', '.join(form_type_indicators)}) detected - not IDOR vulnerable"
        
        # Check if parameter is a form field (not an ID)
        form_field_params = [
            'phone', 'uphone', 'telephone', 'mobile', 'email', 'username',
            'name', 'fname', 'lname', 'address', 'city', 'state'
        ]
        
        if parameter in form_field_params:
            return False, f"Form field parameter '{parameter}' is not IDOR vulnerable"
        
        # Check for nonsensical payloads for form fields
        if parameter in ['phone', 'uphone', 'telephone'] and '../' in payload:
            return False, f"Path traversal payload '{payload}' makes no sense for phone field"
        
        # Check if evidence suggests form submission rather than IDOR
        form_evidence_indicators = [
            'add new user', 'create user', 'registration', 'signup',
            'user created', 'account created'
        ]
        
        if any(indicator in evidence for indicator in form_evidence_indicators):
            return False, "Evidence suggests form submission, not IDOR vulnerability"
        
        # Check for empty original values with form-like payloads
        if "original was ''" in evidence and '../' in payload:
            return False, "Empty original value with path traversal payload suggests form field, not IDOR"
        
        return True, "Valid IDOR vulnerability"
