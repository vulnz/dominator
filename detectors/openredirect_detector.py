"""
Open Redirect vulnerability detector
"""

import re
from urllib.parse import urlparse, parse_qs

class OpenRedirectDetector:
    """Open Redirect vulnerability detection logic"""
    
    @staticmethod
    def get_redirect_parameters() -> list:
        """Get common redirect parameter names"""
        return [
            'redirect', 'url', 'next', 'return', 'returnUrl', 'return_url',
            'goto', 'target', 'dest', 'destination', 'forward', 'continue',
            'redirect_uri', 'redirect_url', 'callback', 'callback_url',
            'success_url', 'failure_url', 'cancel_url', 'back', 'backurl',
            'site', 'domain', 'host', 'referer', 'referrer', 'origin',
            'returnto', 'redirect_to', 'return_to', 'checkout_url', 
            'continue_url', 'shop_url'
        ]
    
    @staticmethod
    def detect_open_redirect(response_text: str, response_code: int, response_headers: dict, 
                           payload_url: str, original_url: str) -> tuple:
        """Detect open redirect vulnerability"""
        
        # Check for HTTP redirects (3xx status codes)
        if 300 <= response_code < 400:
            location_header = response_headers.get('Location', '').lower()
            if location_header:
                # Check if redirect goes to our payload URL
                if payload_url.lower() in location_header:
                    return True, f"HTTP {response_code} redirect to: {location_header}", "redirect_header"
                
                # Check for external domain redirects
                try:
                    original_domain = urlparse(original_url).netloc.lower()
                    redirect_domain = urlparse(location_header).netloc.lower()
                    
                    if redirect_domain and redirect_domain != original_domain:
                        return True, f"External redirect to: {redirect_domain}", "external_redirect"
                except:
                    pass
        
        # Check for JavaScript redirects in response content
        js_redirect_patterns = [
            r'(?:window|document|self|top)\.location\s*=\s*["\']([^"\']+)["\']',
            r'(?:window|document|self|top)\.location\.href\s*=\s*["\']([^"\']+)["\']',
            r'(?:window|document|self|top)\.location\.assign\s*\(\s*["\']([^"\']+)["\']\s*\)',
            r'(?:window|document|self|top)\.location\.replace\s*\(\s*["\']([^"\']+)["\']\s*\)',
            r'window\.navigate\s*\(\s*["\']([^"\']+)["\']\s*\)'
        ]
        
        for pattern in js_redirect_patterns:
            matches = re.findall(pattern, response_text, re.IGNORECASE)
            for match in matches:
                if payload_url.lower() in match.lower():
                    return True, f"JavaScript redirect to: {match}", "js_redirect"
        
        # Check for HTML meta refresh redirects
        meta_refresh_pattern = r'<meta[^>]*http-equiv\s*=\s*["\']refresh["\'][^>]*content\s*=\s*["\'][^"\']*url\s*=\s*([^"\'>\s]+)'
        matches = re.findall(meta_refresh_pattern, response_text, re.IGNORECASE)
        for match in matches:
            if payload_url.lower() in match.lower():
                return True, f"Meta refresh redirect to: {match}", "meta_refresh"
        
        # Check for iframe src redirects
        iframe_src_pattern = r'<iframe[^>]*src\s*=\s*["\']([^"\']+)["\']'
        matches = re.findall(iframe_src_pattern, response_text, re.IGNORECASE)
        for match in matches:
            if payload_url.lower() in match.lower():
                return True, f"iframe src redirect to: {match}", "iframe_redirect"
        
        # Check for form action redirects
        form_action_pattern = r'<form[^>]*action\s*=\s*["\']([^"\']+)["\']'
        matches = re.findall(form_action_pattern, response_text, re.IGNORECASE)
        for match in matches:
            if payload_url.lower() in match.lower():
                return True, f"Form action redirect to: {match}", "form_action"
        
        return False, None, None
    
    @staticmethod
    def get_evidence(redirect_type: str, redirect_target: str) -> str:
        """Get evidence of open redirect vulnerability"""
        evidence_map = {
            "redirect_header": f"HTTP redirect header points to external URL: {redirect_target}",
            "external_redirect": f"Redirect to external domain detected: {redirect_target}",
            "js_redirect": f"JavaScript redirect to external URL: {redirect_target}",
            "meta_refresh": f"Meta refresh redirect to external URL: {redirect_target}",
            "iframe_redirect": f"iframe src points to external URL: {redirect_target}",
            "form_action": f"Form action points to external URL: {redirect_target}"
        }
        
        return evidence_map.get(redirect_type, f"Open redirect detected: {redirect_target}")
    
    @staticmethod
    def get_response_snippet(response_text: str, redirect_target: str, max_length: int = 300) -> str:
        """Get response snippet showing redirect context"""
        if redirect_target in response_text:
            start_pos = response_text.find(redirect_target)
            context_start = max(0, start_pos - 100)
            context_end = min(len(response_text), start_pos + len(redirect_target) + 100)
            return response_text[context_start:context_end]
        
        return response_text[:max_length] + "..." if len(response_text) > max_length else response_text
