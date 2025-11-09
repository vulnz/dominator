"""
Directory traversal payload collection
"""

from utils.payload_loader import PayloadLoader

class DirectoryTraversalPayloads:
    """Directory traversal payload collection"""
    
    @staticmethod
    def get_linux_payloads():
        """Get Linux/Unix directory traversal payloads from text file"""
        all_payloads = PayloadLoader.load_payloads('directory_traversal')
        return [p for p in all_payloads if not any(keyword in p.lower() for keyword in ['windows', 'win.ini', 'system.ini', 'boot.ini', 'c:\\'])]
    
    @staticmethod
    def get_windows_payloads():
        """Get Windows directory traversal payloads from text file"""
        all_payloads = PayloadLoader.load_payloads('directory_traversal')
        return [p for p in all_payloads if any(keyword in p.lower() for keyword in ['windows', 'win.ini', 'system.ini', 'boot.ini', 'c:\\'])]
    
    @staticmethod
    def get_generic_payloads():
        """Get generic directory traversal payloads from text file"""
        all_payloads = PayloadLoader.load_payloads('directory_traversal')
        return [p for p in all_payloads if any(keyword in p for keyword in ['../', '..\\', '%2e%2e', '%252e', '%c0%ae', '%u002e'])][:20]
    
    @staticmethod
    def get_all_payloads():
        """Get all directory traversal payloads from text file"""
        return PayloadLoader.load_payloads('directory_traversal')
