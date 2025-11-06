"""
PHPInfo exposure payload collection
"""

from typing import List

class PHPInfoPayloads:
    """PHPInfo exposure payload collection"""
    
    @staticmethod
    def get_phpinfo_paths() -> List[str]:
        """Get common PHPInfo file paths"""
        return [
            'phpinfo.php',
            'info.php',
            'test.php',
            'phpinfo',
            'php.php',
            'i.php',
            'infophp.php',
            'php_info.php',
            'phpversion.php',
            'version.php',
            'configuration.php',
            'config.php',
            'server.php',
            'serverinfo.php',
            'sysinfo.php',
            'system.php',
            'admin/phpinfo.php',
            'admin/info.php',
            'admin/test.php',
            'test/phpinfo.php',
            'test/info.php',
            'dev/phpinfo.php',
            'dev/info.php',
            'debug/phpinfo.php',
            'debug/info.php',
            'tmp/phpinfo.php',
            'tmp/info.php',
            'temp/phpinfo.php',
            'temp/info.php'
        ]
    
    @staticmethod
    def get_phpinfo_parameters() -> List[str]:
        """Get parameters that might trigger PHPInfo"""
        return [
            'info',
            'phpinfo',
            'debug',
            'test',
            'show',
            'display',
            'view',
            'page',
            'action',
            'cmd',
            'function'
        ]
    
    @staticmethod
    def get_phpinfo_parameter_values() -> List[str]:
        """Get parameter values that might trigger PHPInfo"""
        return [
            'phpinfo',
            'info',
            'phpinfo()',
            'php_info',
            'server_info',
            'configuration',
            'config',
            'debug',
            'test',
            'version',
            'system'
        ]
    
    @staticmethod
    def get_all_phpinfo_payloads() -> List[str]:
        """Get all PHPInfo payloads"""
        payloads = []
        
        # Add direct paths
        payloads.extend(PHPInfoPayloads.get_phpinfo_paths())
        
        return payloads
