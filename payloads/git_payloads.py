"""
Git exposure payload collection
"""

from utils.payload_loader import PayloadLoader

class GitPayloads:
    """Git exposure payload collection"""
    
    @staticmethod
    def get_git_paths():
        """Get common git paths from text file"""
        all_payloads = PayloadLoader.load_payloads('git')
        return [p for p in all_payloads if p.startswith('.git/') and not p.startswith('.git/objects/')]
    
    @staticmethod
    def get_git_object_paths():
        """Get git object paths from text file"""
        all_payloads = PayloadLoader.load_payloads('git')
        return [p for p in all_payloads if p.startswith('.git/objects/')]
    
    @staticmethod
    def get_git_directory_variations():
        """Get variations of .git directory path from text file"""
        all_payloads = PayloadLoader.load_payloads('git')
        return [p for p in all_payloads if not p.startswith('.git/') or p == '.git' or p == '.git/']
    
    @staticmethod
    def get_git_config_files():
        """Get git configuration files from text file"""
        all_payloads = PayloadLoader.load_payloads('git')
        return [p for p in all_payloads if any(keyword in p for keyword in ['.gitignore', '.gitmodules', '.gitattributes'])]
    
    @staticmethod
    def get_all_git_payloads():
        """Get all git-related paths from text file"""
        return PayloadLoader.load_payloads('git')
