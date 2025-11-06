"""
Text Injection payload collection
"""

class TextInjectionPayloads:
    """Text Injection payload collection"""
    
    @staticmethod
    def get_basic_payloads():
        """Get basic text injection payloads"""
        return [
            "test\ninjected",
            "test\rinjected", 
            "test\r\ninjected",
            "test%0ainjected",
            "test%0dinjected",
            "test%0d%0ainjected",
            "test\\ninjected",
            "test\\rinjected",
            "test\\r\\ninjected",
            "test\x0ainjected",
            "test\x0dinjected",
            "test\x0d\x0ainjected"
        ]
    
    @staticmethod
    def get_advanced_payloads():
        """Get advanced text injection payloads"""
        return [
            "test\u000ainjected",
            "test\u000dinjected", 
            "test\u000d\u000ainjected",
            "test\u2028injected",
            "test\u2029injected",
            "test\u0085injected",
            "test\u000binjected",
            "test\u000cinjected",
            "test\u001cinjected",
            "test\u001dinjected",
            "test\u001einjected",
            "test\u001finjected"
        ]
    
    @staticmethod
    def get_context_payloads():
        """Get context-specific text injection payloads"""
        return [
            'test"injected',
            "test'injected",
            "test`injected",
            "test;injected",
            "test|injected",
            "test&injected",
            "test>injected",
            "test<injected",
            "test)injected",
            "test(injected",
            "test]injected",
            "test[injected",
            "test}injected",
            "test{injected"
        ]
    
    @staticmethod
    def get_all_payloads():
        """Get all text injection payloads"""
        payloads = []
        payloads.extend(TextInjectionPayloads.get_basic_payloads())
        payloads.extend(TextInjectionPayloads.get_advanced_payloads())
        payloads.extend(TextInjectionPayloads.get_context_payloads())
        return payloads
