"""
Directory and file bruteforce payloads
"""

class DirBrutePayloads:
    """Directory bruteforce payload collection"""
    
    @staticmethod
    def get_common_directories():
        """Get common directory names"""
        return [
            # Admin directories
            'admin', 'administrator', 'administration', 'manage', 'manager',
            'control', 'panel', 'cp', 'dashboard', 'console', 'backend',
            'staff', 'moderator', 'root', 'system', 'sys',
            
            # Content directories
            'content', 'data', 'files', 'uploads', 'download', 'downloads',
            'media', 'images', 'img', 'pics', 'pictures', 'photos',
            'documents', 'docs', 'assets', 'resources', 'static',
            
            # Application directories
            'app', 'application', 'apps', 'src', 'source', 'lib', 'libs',
            'includes', 'inc', 'modules', 'plugins', 'extensions', 'addons',
            'themes', 'templates', 'views', 'layouts',
            
            # Configuration directories
            'config', 'configuration', 'conf', 'settings', 'cfg',
            'etc', 'ini', 'xml', 'json', 'yaml', 'yml',
            
            # Database directories
            'db', 'database', 'databases', 'sql', 'mysql', 'postgres',
            'sqlite', 'data', 'backup', 'backups', 'dump', 'dumps',
            
            # Development directories
            'dev', 'development', 'test', 'testing', 'debug', 'staging',
            'beta', 'alpha', 'demo', 'sandbox', 'temp', 'tmp',
            
            # Security directories
            'security', 'auth', 'authentication', 'login', 'logout',
            'register', 'signup', 'signin', 'password', 'reset',
            
            # API directories
            'api', 'rest', 'webservice', 'ws', 'service', 'services',
            'endpoint', 'endpoints', 'v1', 'v2', 'v3', 'version',
            
            # Common web directories
            'www', 'web', 'public', 'html', 'htdocs', 'webroot',
            'site', 'sites', 'portal', 'home', 'index',
            
            # Framework directories
            'framework', 'core', 'kernel', 'engine', 'base',
            'common', 'shared', 'utils', 'utilities', 'helpers',
            
            # Backup directories
            'old', 'backup', 'bak', 'archive', 'archives', 'history',
            'previous', 'orig', 'original', 'copy', 'copies',
            
            # Hidden directories
            '.git', '.svn', '.hg', '.bzr', '.cvs',
            '.env', '.config', '.settings', '.cache', '.tmp'
        ]
    
    @staticmethod
    def get_common_files():
        """Get common file names"""
        return [
            # Configuration files
            'config.php', 'config.ini', 'config.xml', 'config.json',
            'settings.php', 'settings.ini', 'configuration.php',
            'app.config', 'web.config', '.env', '.htaccess',
            
            # Database files
            'database.php', 'db.php', 'connection.php', 'connect.php',
            'mysql.php', 'pdo.php', 'sqlite.db', 'database.sqlite',
            
            # Admin files
            'admin.php', 'administrator.php', 'login.php', 'signin.php',
            'auth.php', 'authenticate.php', 'panel.php', 'dashboard.php',
            'control.php', 'manage.php', 'manager.php',
            
            # Common web files
            'index.php', 'index.html', 'index.htm', 'default.php',
            'home.php', 'main.php', 'welcome.php', 'start.php',
            
            # Information files
            'info.php', 'phpinfo.php', 'test.php', 'debug.php',
            'version.php', 'status.php', 'health.php',
            
            # Upload files
            'upload.php', 'uploader.php', 'file.php', 'files.php',
            'download.php', 'media.php', 'image.php', 'photo.php',
            
            # API files
            'api.php', 'rest.php', 'webservice.php', 'service.php',
            'endpoint.php', 'ajax.php', 'json.php', 'xml.php',
            
            # Backup files
            'backup.php', 'dump.php', 'export.php', 'import.php',
            'restore.php', 'migrate.php', 'install.php', 'setup.php',
            
            # Security files
            'security.php', 'firewall.php', 'protection.php',
            'validate.php', 'sanitize.php', 'filter.php',
            
            # Common extensions
            'robots.txt', 'sitemap.xml', 'favicon.ico', 'crossdomain.xml',
            'humans.txt', 'readme.txt', 'changelog.txt', 'license.txt',
            
            # Log files
            'error.log', 'access.log', 'debug.log', 'app.log',
            'system.log', 'security.log', 'audit.log',
            
            # Sensitive files
            'passwords.txt', 'users.txt', 'accounts.txt', 'credentials.txt',
            'keys.txt', 'tokens.txt', 'secrets.txt', 'private.key'
        ]
    
    @staticmethod
    def get_file_extensions():
        """Get common file extensions to test"""
        return [
            # Web files
            '.php', '.html', '.htm', '.asp', '.aspx', '.jsp',
            '.py', '.rb', '.pl', '.cgi', '.sh',
            
            # Configuration files
            '.ini', '.conf', '.config', '.xml', '.json', '.yaml', '.yml',
            '.properties', '.cfg', '.env',
            
            # Database files
            '.sql', '.db', '.sqlite', '.mdb', '.accdb',
            
            # Backup files
            '.bak', '.backup', '.old', '.orig', '.copy', '.tmp',
            '.save', '.swp', '~',
            
            # Archive files
            '.zip', '.rar', '.tar', '.gz', '.7z', '.tar.gz',
            
            # Text files
            '.txt', '.log', '.csv', '.tsv', '.dat'
        ]
    
    @staticmethod
    def get_all_directories():
        """Get all directory payloads"""
        return DirBrutePayloads.get_common_directories()
    
    @staticmethod
    def get_all_files():
        """Get all file payloads"""
        return DirBrutePayloads.get_common_files()
