"""
Environment files (.env) payload collection
"""

class EnvPayloads:
    """Environment files payload collection"""
    
    @staticmethod
    def get_env_paths():
        """Get common .env file paths to test"""
        return [
            '.env',
            '.env.local',
            '.env.production',
            '.env.prod',
            '.env.development',
            '.env.dev',
            '.env.staging',
            '.env.stage',
            '.env.test',
            '.env.testing',
            '.env.backup',
            '.env.bak',
            '.env.old',
            '.env.orig',
            '.env.example',
            '.env.sample',
            '.env.template',
            '.env.dist',
            'env',
            'environment',
            'config.env',
            'app.env',
            'laravel.env',
            'django.env',
            'node.env',
            'react.env',
            'vue.env',
            'next.env',
            '.environment',
            '.config',
            'config/.env',
            'app/.env',
            'src/.env',
            'public/.env',
            'web/.env',
            'www/.env',
            'html/.env',
            'htdocs/.env',
            'webroot/.env',
            'site/.env',
            'application/.env',
            'backend/.env',
            'frontend/.env',
            'api/.env',
            'admin/.env',
            'panel/.env',
            'dashboard/.env',
            'cms/.env',
            'blog/.env',
            'shop/.env',
            'store/.env'
        ]
    
    @staticmethod
    def get_env_variations():
        """Get variations of .env file names"""
        base_names = ['.env', 'env', '.environment']
        extensions = ['', '.txt', '.bak', '.backup', '.old', '.orig', '.save', '.copy']
        environments = ['', '.local', '.dev', '.development', '.prod', '.production', 
                       '.staging', '.stage', '.test', '.testing']
        
        variations = []
        for base in base_names:
            for env in environments:
                for ext in extensions:
                    if env or ext:  # Don't duplicate base names
                        variations.append(f"{base}{env}{ext}")
        
        return variations
    
    @staticmethod
    def get_all_env_payloads():
        """Get all environment file paths to test"""
        return list(set(EnvPayloads.get_env_paths() + EnvPayloads.get_env_variations()))
