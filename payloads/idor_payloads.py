"""
IDOR (Insecure Direct Object Reference) payload collection
"""

from typing import List

class IDORPayloads:
    """IDOR payload collection"""
    
    @staticmethod
    def get_numeric_payloads() -> List[str]:
        """Get numeric IDOR payloads"""
        return [
            '1', '2', '3', '0', '-1',
            '100', '999', '1000',
            '9999', '99999',
            '2147483647',  # Max int
            '-2147483648'  # Min int
        ]
    
    @staticmethod
    def get_sequential_payloads(original_id: str) -> List[str]:
        """Get sequential IDOR payloads based on original ID"""
        payloads = []
        
        try:
            # If original ID is numeric, try adjacent numbers
            if original_id.isdigit():
                num = int(original_id)
                payloads.extend([
                    str(num - 1),
                    str(num + 1),
                    str(num - 10),
                    str(num + 10),
                    str(num * 2),
                    str(num // 2) if num > 1 else '1'
                ])
        except:
            pass
        
        return payloads
    
    @staticmethod
    def get_common_ids() -> List[str]:
        """Get common ID values to test"""
        return [
            'admin', 'administrator', 'root', 'user',
            'test', 'guest', 'demo', 'default',
            'system', 'public', 'anonymous',
            '00000000-0000-0000-0000-000000000000',  # Empty GUID
            'ffffffff-ffff-ffff-ffff-ffffffffffff'   # Max GUID
        ]
    
    @staticmethod
    def get_all_payloads() -> List[str]:
        """Get all IDOR payloads"""
        payloads = []
        payloads.extend(IDORPayloads.get_numeric_payloads())
        payloads.extend(IDORPayloads.get_common_ids())
        return payloads
