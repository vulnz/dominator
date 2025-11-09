"""
XXE payload collection with enhanced detection
"""

from utils.payload_loader import PayloadLoader

class XXEPayloads:
    """XXE payload collection"""
    
    @staticmethod
    def get_basic_payloads():
        """Get basic XXE payloads from text file"""
        all_payloads = PayloadLoader.load_payloads('xxe')
        return [p for p in all_payloads if not any(keyword in p.lower() for keyword in ['%', 'http://evil.com', 'gopher://', 'dict://', 'ldap://'])][:10]
    
    @staticmethod
    def get_blind_payloads():
        """Get blind XXE payloads from text file"""
        all_payloads = PayloadLoader.load_payloads('xxe')
        return [p for p in all_payloads if any(keyword in p for keyword in ['%', 'http://evil.com'])][:5]
    
    @staticmethod
    def get_parameter_payloads():
        """Get XXE payloads for parameter injection from text file"""
        all_payloads = PayloadLoader.load_payloads('xxe')
        return [p for p in all_payloads if any(keyword in p for keyword in ['&', '%']) and not p.startswith('<?xml')][:5]
    
    @staticmethod
    def get_protocol_payloads():
        """Get protocol-based XXE payloads from text file"""
        all_payloads = PayloadLoader.load_payloads('xxe')
        return [p for p in all_payloads if any(keyword in p.lower() for keyword in ['gopher://', 'dict://', 'ldap://', 'sftp://', 'tftp://', 'ftp://'])]
    
    @staticmethod
    def get_all_payloads():
        """Get all XXE payloads from text file"""
        return PayloadLoader.load_payloads('xxe')
