from typing import List
from utils.payload_loader import PayloadLoader

class IDORPayloads:
    """IDOR payload collection"""

    @staticmethod
    def get_all_payloads() -> List[str]:
        """Get all IDOR payloads from text file"""
        return PayloadLoader.load_payloads('idor')

    @staticmethod
    def get_sequential_payloads(original_value: str) -> List[str]:
        """Generate sequential payloads based on an original value."""
        payloads = []
        
        # Try to treat as integer
        try:
            original_int = int(original_value)
            # Generate a few sequential and edge-case numbers
            for i in range(1, 4):
                payloads.append(str(original_int + i))
                if original_int - i > 0:
                    payloads.append(str(original_int - i))
            
            # Common privileged IDs
            payloads.extend(['1', '0', '100'])
            return list(set(payloads))
        except (ValueError, TypeError):
            # Not an integer, return empty. String manipulation is too complex for generic payloads.
            return []
