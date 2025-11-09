"""
Enhanced XSS payload collection with context-aware detection
"""

from utils.payload_loader import PayloadLoader

class XSSPayloads:
    """Enhanced XSS payload collection with context-aware detection"""
    
    @staticmethod
    def get_basic_payloads():
        """Get basic XSS payloads from text file"""
        return PayloadLoader.load_payloads('xss_basic')
    
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
