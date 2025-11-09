"""
Password payload collection for brute force attacks
"""

from utils.payload_loader import PayloadLoader

class PasswordPayloads:
    """Password payload collection"""
    
    @staticmethod
    def get_common_passwords():
        """Get common passwords from wordlist file"""
        return PayloadLoader.load_wordlist('passwords')[:100]  # Top 100 passwords
    
    @staticmethod
    def get_top_passwords(count: int = 50):
        """Get top N passwords from wordlist file"""
        all_passwords = PayloadLoader.load_wordlist('passwords')
        return all_passwords[:count] if len(all_passwords) >= count else all_passwords
    
    @staticmethod
    def get_weak_passwords():
        """Get weak/default passwords from wordlist file"""
        all_passwords = PayloadLoader.load_wordlist('passwords')
        weak_keywords = ['admin', 'password', '123', 'test', 'guest', 'demo', 'root', 'default']
        return [p for p in all_passwords if any(keyword in p.lower() for keyword in weak_keywords)]
    
    @staticmethod
    def get_numeric_passwords():
        """Get numeric passwords from wordlist file"""
        all_passwords = PayloadLoader.load_wordlist('passwords')
        return [p for p in all_passwords if p.isdigit()]
    
    @staticmethod
    def get_year_passwords():
        """Get year-based passwords from wordlist file"""
        all_passwords = PayloadLoader.load_wordlist('passwords')
        return [p for p in all_passwords if p.isdigit() and len(p) == 4 and p.startswith(('19', '20'))]
    
    @staticmethod
    def get_all_passwords():
        """Get all passwords from wordlist file"""
        return PayloadLoader.load_wordlist('passwords')
    
    @staticmethod
    def generate_variations(base_password: str):
        """Generate common password variations"""
        variations = [base_password]
        
        # Add common suffixes
        suffixes = ['123', '1', '!', '@', '#', '2023', '2024']
        for suffix in suffixes:
            variations.append(base_password + suffix)
        
        # Add capitalization variations
        variations.append(base_password.capitalize())
        variations.append(base_password.upper())
        variations.append(base_password.lower())
        
        # Add common prefixes
        prefixes = ['admin', 'user', 'test']
        for prefix in prefixes:
            variations.append(prefix + base_password)
        
        return list(set(variations))  # Remove duplicates
