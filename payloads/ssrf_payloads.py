"""
SSRF payload collection with enhanced detection
"""

from utils.payload_loader import PayloadLoader

class SSRFPayloads:
    """SSRF payload collection"""
    
    @staticmethod
    def get_basic_payloads():
        """Get basic SSRF payloads from text file"""
        all_payloads = PayloadLoader.load_payloads('ssrf')
        return [p for p in all_payloads if not any(keyword in p.lower() for keyword in ['169.254.169.254', 'metadata', 'gopher://', 'dict://', 'ldap://'])][:20]
    
    @staticmethod
    def get_advanced_payloads():
        """Get advanced SSRF payloads with bypass techniques from text file"""
        all_payloads = PayloadLoader.load_payloads('ssrf')
        return [p for p in all_payloads if any(keyword in p.lower() for keyword in ['gopher://', 'dict://', 'ldap://', 'sftp://', 'tftp://'])]
    
    @staticmethod
    def get_cloud_metadata_payloads():
        """Get cloud metadata SSRF payloads from text file"""
        all_payloads = PayloadLoader.load_payloads('ssrf')
        return [p for p in all_payloads if any(keyword in p.lower() for keyword in ['169.254.169.254', 'metadata', '100.100.100.200'])]
    
    @staticmethod
    def get_all_payloads():
        """Get all SSRF payloads from text file"""
        return PayloadLoader.load_payloads('ssrf')
