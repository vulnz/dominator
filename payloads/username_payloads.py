"""
Username payload collection for brute force attacks
"""

from utils.payload_loader import PayloadLoader

class UsernamePayloads:
    """Username payload collection"""
    
    @staticmethod
    def get_common_usernames():
        """Get common usernames from wordlist file"""
        return PayloadLoader.load_wordlist('usernames')[:50]  # Top 50 usernames
    
    @staticmethod
    def get_admin_usernames():
        """Get admin-related usernames from wordlist file"""
        all_usernames = PayloadLoader.load_wordlist('usernames')
        admin_keywords = ['admin', 'administrator', 'root', 'manager', 'operator', 'sa', 'dba']
        return [u for u in all_usernames if any(keyword in u.lower() for keyword in admin_keywords)]
    
    @staticmethod
    def get_service_usernames():
        """Get service account usernames from wordlist file"""
        all_usernames = PayloadLoader.load_wordlist('usernames')
        service_keywords = ['service', 'system', 'www-data', 'apache', 'nginx', 'mysql', 'postgres']
        return [u for u in all_usernames if any(keyword in u.lower() for keyword in service_keywords)]
    
    @staticmethod
    def get_default_usernames():
        """Get default usernames from wordlist file"""
        all_usernames = PayloadLoader.load_wordlist('usernames')
        default_keywords = ['admin', 'root', 'user', 'test', 'guest', 'demo', 'default']
        return [u for u in all_usernames if u.lower() in default_keywords]
    
    @staticmethod
    def get_all_usernames():
        """Get all usernames from wordlist file"""
        return PayloadLoader.load_wordlist('usernames')
