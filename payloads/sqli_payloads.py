"""
SQL injection payloads for testing SQL injection vulnerabilities
"""

from utils.payload_loader import PayloadLoader

class SQLiPayloads:
    """SQL injection payload collection optimized for testphp.vulnweb.com"""
    
    @staticmethod
    def get_basic_payloads():
        """Get basic SQL injection payloads from text file"""
        all_payloads = PayloadLoader.load_payloads('sqli')
        return [p for p in all_payloads if not any(keyword in p.lower() for keyword in ['sleep', 'union', 'waitfor'])]
    
    @staticmethod
    def get_time_based_payloads():
        """Get time-based SQL injection payloads from text file"""
        all_payloads = PayloadLoader.load_payloads('sqli')
        return [p for p in all_payloads if any(keyword in p.lower() for keyword in ['sleep', 'waitfor'])]
    
    @staticmethod
    def get_union_payloads():
        """Get UNION-based SQL injection payloads from text file"""
        all_payloads = PayloadLoader.load_payloads('sqli')
        return [p for p in all_payloads if 'union' in p.lower()]
    
    @staticmethod
    def get_all_payloads():
        """Get all SQL injection payloads from text file"""
        return PayloadLoader.load_payloads('sqli')

    @staticmethod
    def get_waf_bypass_payloads():
        """Get WAF bypass SQL injection payloads"""
        return PayloadLoader.load_payloads('sqli_waf_bypass')
