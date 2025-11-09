"""
Directory payload collection for directory enumeration
"""

from utils.payload_loader import PayloadLoader

class DirectoryPayloads:
    """Directory payload collection"""
    
    @staticmethod
    def get_common_directories():
        """Get common directory names from wordlist file"""
        return PayloadLoader.load_wordlist('directories')[:100]  # Top 100 directories
    
    @staticmethod
    def get_admin_directories():
        """Get admin-related directories from wordlist file"""
        all_dirs = PayloadLoader.load_wordlist('directories')
        admin_keywords = ['admin', 'administrator', 'manage', 'control', 'panel', 'dashboard']
        return [d for d in all_dirs if any(keyword in d.lower() for keyword in admin_keywords)]
    
    @staticmethod
    def get_config_directories():
        """Get configuration directories from wordlist file"""
        all_dirs = PayloadLoader.load_wordlist('directories')
        config_keywords = ['config', 'configuration', 'settings', 'conf', 'cfg', 'etc']
        return [d for d in all_dirs if any(keyword in d.lower() for keyword in config_keywords)]
    
    @staticmethod
    def get_backup_directories():
        """Get backup directories from wordlist file"""
        all_dirs = PayloadLoader.load_wordlist('directories')
        backup_keywords = ['backup', 'backups', 'bak', 'old', 'archive', 'archives']
        return [d for d in all_dirs if any(keyword in d.lower() for keyword in backup_keywords)]
    
    @staticmethod
    def get_hidden_directories():
        """Get hidden directories from wordlist file"""
        all_dirs = PayloadLoader.load_wordlist('directories')
        return [d for d in all_dirs if d.startswith('.')]
    
    @staticmethod
    def get_all_directories():
        """Get all directories from wordlist file"""
        return PayloadLoader.load_wordlist('directories')
