"""
XSS payloads for testing Cross-Site Scripting vulnerabilities
"""

from utils.payload_loader import PayloadLoader

class XSSPayloads:
    """XSS payload collection optimized for testphp.vulnweb.com"""
    
    @staticmethod
    def get_basic_payloads():
        """Get basic XSS payloads from text file"""
        return PayloadLoader.load_payloads('xss')[:50]  # First 50 payloads
    
    @staticmethod
    def get_advanced_payloads():
        """Get advanced XSS payloads from text file"""
        all_payloads = PayloadLoader.load_payloads('xss')
        return all_payloads[50:] if len(all_payloads) > 50 else []
    
    @staticmethod
    def get_all_payloads():
        """Get all XSS payloads from text file"""
        return PayloadLoader.load_payloads('xss')
