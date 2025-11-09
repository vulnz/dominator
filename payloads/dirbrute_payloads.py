"""
Directory and file bruteforce payloads
"""

from utils.payload_loader import PayloadLoader

class DirBrutePayloads:
    """Directory bruteforce payload collection"""
    
    @staticmethod
    def get_common_directories():
        """Get common directory names from text file"""
        all_payloads = PayloadLoader.load_payloads('dirbrute')
        return [p for p in all_payloads if '.' not in p and not p.endswith('.txt') and not p.endswith('.php') and not p.endswith('.html')]
    
    @staticmethod
    def get_common_files():
        """Get common file names from text file"""
        all_payloads = PayloadLoader.load_payloads('dirbrute')
        return [p for p in all_payloads if '.' in p and not p.startswith('.')]
    
    @staticmethod
    def get_hidden_files():
        """Get hidden files and directories from text file"""
        all_payloads = PayloadLoader.load_payloads('dirbrute')
        return [p for p in all_payloads if p.startswith('.')]
    
    @staticmethod
    def get_admin_paths():
        """Get admin-related paths from text file"""
        all_payloads = PayloadLoader.load_payloads('dirbrute')
        return [p for p in all_payloads if any(keyword in p.lower() for keyword in ['admin', 'manage', 'control', 'panel', 'dashboard'])]
    
    @staticmethod
    def get_config_files():
        """Get configuration files from text file"""
        all_payloads = PayloadLoader.load_payloads('dirbrute')
        return [p for p in all_payloads if any(keyword in p.lower() for keyword in ['config', 'settings', '.env', 'web.config', '.htaccess'])]
    
    @staticmethod
    def get_sensitive_files():
        """Get sensitive files from text file"""
        all_payloads = PayloadLoader.load_payloads('dirbrute')
        return [p for p in all_payloads if any(keyword in p.lower() for keyword in ['password', 'secret', 'key', 'token', 'credential', 'private'])]
    
    @staticmethod
    def get_file_extensions():
        """Get common file extensions to test"""
        return [
            '.php', '.html', '.htm', '.asp', '.aspx', '.jsp',
            '.py', '.rb', '.pl', '.cgi', '.sh',
            '.ini', '.conf', '.config', '.xml', '.json', '.yaml', '.yml',
            '.properties', '.cfg', '.env',
            '.sql', '.db', '.sqlite', '.mdb', '.accdb',
            '.bak', '.backup', '.old', '.orig', '.copy', '.tmp',
            '.save', '.swp', '~',
            '.zip', '.rar', '.tar', '.gz', '.7z', '.tar.gz',
            '.txt', '.log', '.csv', '.tsv', '.dat'
        ]
    
    @staticmethod
    def get_all_directories():
        """Get all directory payloads from text file"""
        return DirBrutePayloads.get_common_directories()
    
    @staticmethod
    def get_all_files():
        """Get all file payloads from text file"""
        return DirBrutePayloads.get_common_files()
    
    @staticmethod
    def get_all_payloads():
        """Get all directory bruteforce payloads from text file"""
        return PayloadLoader.load_payloads('dirbrute')
