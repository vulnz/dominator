"""
Open Redirect payload collection
"""

from utils.payload_loader import PayloadLoader

class OpenRedirectPayloads:
    """Open Redirect payload collection"""
    
    @staticmethod
    def get_basic_payloads():
        """Get basic open redirect payloads from text file"""
        all_payloads = PayloadLoader.load_payloads('openredirect')
        return [p for p in all_payloads if not any(keyword in p.lower() for keyword in ['javascript:', 'data:', 'vbscript:', 'file:', 'ftp:', 'ldap:'])][:15]
    
    @staticmethod
    def get_bypass_payloads():
        """Get bypass payloads for open redirect filters from text file"""
        all_payloads = PayloadLoader.load_payloads('openredirect')
        return [p for p in all_payloads if any(keyword in p for keyword in ['/\\', '\\/', '///', '////', '127.0.0.1', 'localhost', '192.168', '10.0.0', '172.16'])]
    
    @staticmethod
    def get_protocol_payloads():
        """Get protocol-based payloads from text file"""
        all_payloads = PayloadLoader.load_payloads('openredirect')
        return [p for p in all_payloads if any(keyword in p.lower() for keyword in ['javascript:', 'data:', 'vbscript:', 'file:', 'ftp:', 'ldap:', 'gopher:', 'dict:', 'sftp:', 'tftp:', 'mailto:', 'tel:', 'sms:'])]
    
    @staticmethod
    def get_all_payloads():
        """Get all open redirect payloads from text file"""
        return PayloadLoader.load_payloads('openredirect')
