"""
Session Management payloads
Contains payloads for testing session management vulnerabilities
"""

class SessionManagementPayloads:
    """Session Management payload collection"""
    
    @staticmethod
    def get_all_payloads():
        """Get all session management payloads"""
        return SessionManagementPayloads.get_session_fixation_payloads() + SessionManagementPayloads.get_session_hijacking_payloads()
    
    @staticmethod
    def get_session_fixation_payloads():
        """Get session fixation test payloads"""
        return [
            'DOMINATOR_FIXED_SESSION_123456789',
            'FIXED_SESSION_ID_TEST',
            'admin_session_123',
            'test_session_456',
            '1234567890',
            'AAAAAAAAAA',
            'session_fixed_by_attacker'
        ]
    
    @staticmethod
    def get_session_hijacking_payloads():
        """Get session hijacking test payloads"""
        return [
            # Common session IDs to try
            'admin',
            'administrator',
            'root',
            '1',
            '0',
            'test',
            'guest',
            'session',
            '123456',
            'ABCDEF',
            # Predictable patterns
            '1111111111',
            '2222222222',
            'aaaaaaaaaa',
            'bbbbbbbbbb'
        ]
    
    @staticmethod
    def get_weak_session_patterns():
        """Get patterns that indicate weak session IDs"""
        return [
            r'^\d{1,6}$',  # Only digits, short
            r'^[a-zA-Z]{1,6}$',  # Only letters, short
            r'^(admin|test|guest|user)$',  # Common words
            r'^(123|abc|aaa|111).*$',  # Predictable starts
        ]
