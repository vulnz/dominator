"""
SSTI (Server-Side Template Injection) payload collection
"""

from typing import List, Dict, Any
from utils.payload_loader import PayloadLoader

class SSTIPayloads:
    """SSTI payload collection"""
    
    @staticmethod
    def get_basic_payloads() -> List[str]:
        """Get basic SSTI payloads from text file"""
        all_payloads = PayloadLoader.load_payloads('ssti')
        return [p for p in all_payloads if not any(keyword in p.lower() for keyword in ['popen', 'system', 'exec', 'sleep', 'time', '__import__'])][:30]
    
    @staticmethod
    def get_rce_payloads() -> List[str]:
        """Get RCE SSTI payloads from text file"""
        all_payloads = PayloadLoader.load_payloads('ssti')
        return [p for p in all_payloads if any(keyword in p.lower() for keyword in ['popen', 'system', 'exec', '__import__'])][:15]
    
    @staticmethod
    def get_detection_payloads() -> List[str]:
        """Get SSTI detection payloads from text file"""
        all_payloads = PayloadLoader.load_payloads('ssti')
        return [p for p in all_payloads if any(keyword in p for keyword in ['{{7*7}}', '${7*7}', '#{7*7}', '%{7*7}', '{{8*8}}', '${8*8}', '{{9*9}}', '${9*9}'])]
    
    @staticmethod
    def get_blind_payloads() -> List[str]:
        """Get blind SSTI payloads from text file"""
        all_payloads = PayloadLoader.load_payloads('ssti')
        return [p for p in all_payloads if any(keyword in p.lower() for keyword in ['sleep', 'time'])][:5]
    
    @staticmethod
    def get_all_payloads() -> List[str]:
        """Get all SSTI payloads from text file"""
        return PayloadLoader.load_payloads('ssti')
    
    @staticmethod
    def get_engine_specific_payloads() -> Dict[str, List[str]]:
        """Get template engine specific payloads from text file"""
        all_payloads = PayloadLoader.load_payloads('ssti')
        
        return {
            'jinja2': [p for p in all_payloads if any(keyword in p for keyword in ['{{config}}', '{{request}}', '{{lipsum', '{{cycler', '{{joiner', '{{namespace'])],
            'django': [p for p in all_payloads if any(keyword in p for keyword in ['{{settings', '{{request.META}}'])],
            'ruby': [p for p in all_payloads if any(keyword in p for keyword in ['<%= ', '#{'])],
            'smarty': [p for p in all_payloads if any(keyword in p for keyword in ['{php}'])],
            'mako': [p for p in all_payloads if any(keyword in p for keyword in ['${__import__'])],
            'generic': [p for p in all_payloads if any(keyword in p for keyword in ['{{7*7}}', '${7*7}', '#{7*7}', '%{7*7}'])]
        }
