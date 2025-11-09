"""
RFI payload collection
"""

from utils.payload_loader import PayloadLoader

class RFIPayloads:
    """RFI payload collection"""
    
    @staticmethod
    def get_basic_payloads():
        """Get basic RFI payloads from text file"""
        all_payloads = PayloadLoader.load_payloads('rfi')
        return [p for p in all_payloads if not any(keyword in p.lower() for keyword in ['%', 'zip://', 'phar://', 'gopher://', 'dict://'])][:20]
    
    @staticmethod
    def get_advanced_payloads():
        """Get advanced RFI payloads from text file"""
        all_payloads = PayloadLoader.load_payloads('rfi')
        return [p for p in all_payloads if any(keyword in p.lower() for keyword in ['%', 'zip://', 'phar://', 'gopher://', 'dict://'])]
    
    @staticmethod
    def get_all_payloads():
        """Get all RFI payloads from text file"""
        return PayloadLoader.load_payloads('rfi')
