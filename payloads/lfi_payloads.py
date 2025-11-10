"""
LFI payloads for testing Local File Inclusion vulnerabilities
"""

from utils.payload_loader import PayloadLoader

class LFIPayloads:
    """LFI payload collection"""
    
    @staticmethod
    def get_linux_payloads():
        """Get Linux LFI payloads from text file"""
        all_payloads = PayloadLoader.load_payloads('lfi')
        return [p for p in all_payloads if not any(keyword in p.lower() for keyword in ['windows', 'win.ini', 'system.ini', 'boot.ini', 'c:\\'])]
    
    @staticmethod
    def get_windows_payloads():
        """Get Windows LFI payloads from text file"""
        all_payloads = PayloadLoader.load_payloads('lfi')
        return [p for p in all_payloads if any(keyword in p.lower() for keyword in ['windows', 'win.ini', 'system.ini', 'boot.ini', 'c:\\'])]
    
    @staticmethod
    def get_all_payloads():
        """Get all LFI payloads from text file"""
        return PayloadLoader.load_payloads('lfi')

    @staticmethod
    def get_waf_bypass_payloads():
        """Get WAF bypass LFI payloads"""
        return PayloadLoader.load_payloads('lfi_waf_bypass')
