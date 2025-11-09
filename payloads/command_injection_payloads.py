"""
Command Injection payload collection
"""

from typing import List
from utils.payload_loader import PayloadLoader

class CommandInjectionPayloads:
    """Command Injection payload collection optimized for XVWA"""
    
    @staticmethod
    def get_linux_payloads() -> List[str]:
        """Get Linux command injection payloads from text file"""
        all_payloads = PayloadLoader.load_payloads('command_injection')
        return [p for p in all_payloads if not any(keyword in p.lower() for keyword in ['&', 'dir', 'ver', 'ipconfig', 'tasklist', 'systeminfo', 'netstat'])]
    
    @staticmethod
    def get_windows_payloads() -> List[str]:
        """Get Windows command injection payloads from text file"""
        all_payloads = PayloadLoader.load_payloads('command_injection')
        return [p for p in all_payloads if any(keyword in p.lower() for keyword in ['dir', 'ver', 'ipconfig', 'tasklist', 'systeminfo', 'netstat'])]
    
    @staticmethod
    def get_blind_payloads() -> List[str]:
        """Get blind command injection payloads from text file"""
        all_payloads = PayloadLoader.load_payloads('command_injection')
        return [p for p in all_payloads if any(keyword in p.lower() for keyword in ['sleep', 'ping'])]
    
    @staticmethod
    def get_all_payloads() -> List[str]:
        """Get all command injection payloads from text file"""
        return PayloadLoader.load_payloads('command_injection')
