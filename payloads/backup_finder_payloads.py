"""
Backup files finder payload collection
"""

from utils.payload_loader import PayloadLoader

class BackupFinderPayloads:
    """Backup files payload collection"""
    
    @staticmethod
    def get_backup_extensions():
        """Get backup file extensions from text file"""
        all_payloads = PayloadLoader.load_payloads('backup_finder')
        return [p for p in all_payloads if p.startswith('.') and len(p) <= 10]
    
    @staticmethod
    def get_backup_prefixes():
        """Get backup file prefixes from text file"""
        all_payloads = PayloadLoader.load_payloads('backup_finder')
        return [p for p in all_payloads if p.endswith('_') or p.endswith('-')]
    
    @staticmethod
    def get_common_backup_files():
        """Get common backup file names from text file"""
        all_payloads = PayloadLoader.load_payloads('backup_finder')
        return [p for p in all_payloads if '.' in p and not p.startswith('.') and not p.endswith('/')]
    
    @staticmethod
    def get_backup_directories():
        """Get common backup directory names from text file"""
        all_payloads = PayloadLoader.load_payloads('backup_finder')
        return [p for p in all_payloads if p.endswith('/')]
    
    @staticmethod
    def generate_backup_variants(base_filename: str):
        """Generate backup variants for a given filename"""
        variants = []
        
        # Add extensions
        for ext in BackupFinderPayloads.get_backup_extensions():
            variants.append(base_filename + ext)
        
        # Add prefixes
        for prefix in BackupFinderPayloads.get_backup_prefixes():
            variants.append(prefix + base_filename)
        
        # Add both prefix and extension
        for prefix in ['backup_', 'old_', 'copy_']:
            for ext in ['.bak', '.old', '.backup']:
                variants.append(prefix + base_filename + ext)
        
        return variants
    
    @staticmethod
    def get_all_backup_payloads():
        """Get all backup finder payloads from text file"""
        return PayloadLoader.load_payloads('backup_finder')
