"""
Buffer Overflow payloads
Contains payloads for testing buffer overflow vulnerabilities
"""

class BufferOverflowPayloads:
    """Buffer Overflow payload collection"""
    
    @staticmethod
    def get_all_payloads():
        """Get all buffer overflow payloads"""
        return (BufferOverflowPayloads.get_basic_overflow_payloads() + 
                BufferOverflowPayloads.get_format_string_payloads() +
                BufferOverflowPayloads.get_unicode_overflow_payloads())
    
    @staticmethod
    def get_basic_overflow_payloads():
        """Get basic buffer overflow payloads"""
        payloads = []
        
        # Different buffer sizes
        sizes = [100, 500, 1000, 2000, 5000, 10000, 20000]
        chars = ['A', 'B', 'C', '0', '1', 'X']
        
        for size in sizes:
            for char in chars:
                payloads.append(char * size)
        
        return payloads
    
    @staticmethod
    def get_format_string_payloads():
        """Get format string attack payloads"""
        payloads = []
        
        # Format string specifiers
        format_specs = ['%s', '%x', '%d', '%n', '%p', '%c']
        counts = [10, 50, 100, 500, 1000]
        
        for spec in format_specs:
            for count in counts:
                payloads.append(spec * count)
        
        return payloads
    
    @staticmethod
    def get_unicode_overflow_payloads():
        """Get Unicode-based overflow payloads"""
        return [
            '\u0041' * 1000,  # Unicode 'A'
            '\u0042' * 2000,  # Unicode 'B'
            '\u0043' * 5000,  # Unicode 'C'
            '\u0000' * 1000,  # Null bytes
            '\uffff' * 1000,  # Max Unicode
            '\u0001' * 1000,  # Control character
            '\u0020' * 1000,  # Space character
            '\u007f' * 1000,  # DEL character
        ]
    
    @staticmethod
    def get_shellcode_patterns():
        """Get shellcode-like patterns"""
        return [
            '\x90' * 1000,  # NOP sled
            '\xcc' * 1000,  # INT3 instruction
            '\x41' * 1000,  # 'A' in hex
            '\x42' * 1000,  # 'B' in hex
            '\x43' * 1000,  # 'C' in hex
            '\x00' * 1000,  # Null bytes
            '\xff' * 1000,  # 0xFF bytes
            '\xde\xad\xbe\xef' * 250,  # DEADBEEF pattern
        ]
    
    @staticmethod
    def get_cyclic_patterns():
        """Get cyclic patterns for overflow detection"""
        # De Bruijn sequence patterns
        patterns = []
        
        # Generate simple cyclic patterns
        alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789'
        for length in [100, 500, 1000, 2000]:
            pattern = ''
            for i in range(length):
                pattern += alphabet[i % len(alphabet)]
            patterns.append(pattern)
        
        return patterns
