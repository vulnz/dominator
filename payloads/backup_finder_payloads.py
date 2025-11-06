"""
Backup files finder payload collection
"""

class BackupFinderPayloads:
    """Backup files payload collection"""
    
    @staticmethod
    def get_backup_extensions():
        """Get backup file extensions to test"""
        return [
            '.bak', '.backup', '.old', '.orig', '.copy', '.tmp', '.temp',
            '.save', '.swp', '.swo', '.~', '.bkp', '.back', '.archive',
            '.1', '.2', '.3', '.001', '.002', '.003'
        ]
    
    @staticmethod
    def get_backup_prefixes():
        """Get backup file prefixes to test"""
        return [
            'backup_', 'bak_', 'old_', 'copy_', 'orig_', 'temp_',
            'tmp_', 'save_', 'archive_', 'backup-', 'old-'
        ]
    
    @staticmethod
    def get_common_backup_files():
        """Get common backup file names"""
        return [
            # Web files
            'index.php.bak', 'index.html.bak', 'config.php.bak',
            'database.php.bak', 'connection.php.bak', 'settings.php.bak',
            'admin.php.bak', 'login.php.bak', 'register.php.bak',
            
            # Configuration files
            'config.bak', 'configuration.bak', 'settings.bak',
            'web.config.bak', '.htaccess.bak', 'httpd.conf.bak',
            
            # Database files
            'database.sql', 'backup.sql', 'dump.sql', 'db.sql',
            'mysql.sql', 'data.sql', 'users.sql', 'admin.sql',
            
            # Archive files
            'backup.zip', 'backup.tar', 'backup.tar.gz', 'backup.rar',
            'site.zip', 'website.zip', 'www.zip', 'public_html.zip',
            
            # Log files
            'error.log', 'access.log', 'debug.log', 'application.log',
            'error_log', 'access_log', 'php_errors.log',
            
            # Temporary files
            'temp.php', 'tmp.php', 'test.php', 'debug.php',
            'phpinfo.php', 'info.php', 'test.html'
        ]
    
    @staticmethod
    def get_backup_directories():
        """Get common backup directory names"""
        return [
            'backup/', 'backups/', 'bak/', 'old/', 'archive/',
            'archives/', 'temp/', 'tmp/', 'save/', 'copy/',
            'backup-files/', 'old-files/', 'archived/',
            'backup_files/', 'old_files/', 'temp_files/',
            'backup2021/', 'backup2022/', 'backup2023/', 'backup2024/',
            'backup_2021/', 'backup_2022/', 'backup_2023/', 'backup_2024/'
        ]
    
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
        """Get all backup finder payloads"""
        return (BackupFinderPayloads.get_common_backup_files() +
                BackupFinderPayloads.get_backup_directories())
