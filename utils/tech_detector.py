"""
Smart Technology Detection System
Автоматически определяет технологии и настраивает модули под язык программирования
"""

import re
from typing import Dict, List, Optional, Set
from dataclasses import dataclass


@dataclass
class TechProfile:
    """Profile of detected technology"""
    language: str  # php, asp, aspx, jsp, python, ruby, nodejs
    server: Optional[str] = None  # Apache, IIS, Nginx, etc
    framework: Optional[str] = None  # Laravel, Django, Express, etc
    extensions: List[str] = None  # File extensions to brute force

    def __post_init__(self):
        if self.extensions is None:
            self.extensions = self._get_default_extensions()

    def _get_default_extensions(self) -> List[str]:
        """Get default file extensions based on language"""
        ext_map = {
            'php': ['.php', '.php3', '.php4', '.php5', '.phtml', '.inc'],
            'asp': ['.asp', '.aspx', '.ashx', '.asmx', '.config', '.inc'],
            'jsp': ['.jsp', '.jspx', '.jsf', '.do', '.action'],
            'python': ['.py', '.pyc', '.pyo', '.wsgi'],
            'ruby': ['.rb', '.rhtml', '.erb'],
            'nodejs': ['.js', '.ts', '.json', '.node'],
            'perl': ['.pl', '.cgi', '.pm'],
            'coldfusion': ['.cfm', '.cfc', '.cfml'],
        }
        return ext_map.get(self.language, [])


class TechDetector:
    """
    Умный детектор технологий
    Анализирует headers, URLs, content для определения стека
    """

    def __init__(self):
        # Patterns for language detection
        self.language_patterns = {
            'php': {
                'headers': [
                    (r'X-Powered-By.*PHP', 'header'),
                    (r'Server.*PHP', 'header'),
                ],
                'urls': [
                    (r'\.php[345]?$', 'url'),
                    (r'\.phtml$', 'url'),
                    (r'/index\.php', 'url'),
                ],
                'content': [
                    (r'<\?php', 'source'),
                    (r'PHPSESSID', 'cookie'),
                    (r'php_admin_value', 'htaccess'),
                ],
            },
            'asp': {
                'headers': [
                    (r'X-Powered-By.*ASP\.NET', 'header'),
                    (r'Server.*IIS', 'header'),
                    (r'X-AspNet-Version', 'header'),
                ],
                'urls': [
                    (r'\.asp$', 'url'),
                    (r'\.aspx$', 'url'),
                    (r'\.ashx$', 'url'),
                    (r'/Default\.aspx?', 'url'),
                ],
                'content': [
                    (r'__VIEWSTATE', 'viewstate'),
                    (r'ASP\.NET_SessionId', 'cookie'),
                ],
            },
            'jsp': {
                'headers': [
                    (r'Server.*Tomcat', 'header'),
                    (r'Server.*JBoss', 'header'),
                    (r'Server.*WebLogic', 'header'),
                ],
                'urls': [
                    (r'\.jsp$', 'url'),
                    (r'\.jspx$', 'url'),
                    (r'\.do$', 'url'),
                    (r'\.action$', 'url'),
                ],
                'content': [
                    (r'JSESSIONID', 'cookie'),
                    (r'<%@\s*page', 'source'),
                ],
            },
            'python': {
                'headers': [
                    (r'Server.*Django', 'header'),
                    (r'Server.*Flask', 'header'),
                    (r'Server.*Werkzeug', 'header'),
                    (r'Server.*uWSGI', 'header'),
                ],
                'urls': [
                    (r'\.py$', 'url'),
                    (r'\.wsgi$', 'url'),
                ],
                'content': [
                    (r'csrfmiddlewaretoken', 'django'),
                    (r'__flask', 'flask'),
                ],
            },
            'ruby': {
                'headers': [
                    (r'Server.*Passenger', 'header'),
                    (r'X-Rack-Cache', 'header'),
                ],
                'urls': [
                    (r'\.rb$', 'url'),
                    (r'/rails/', 'url'),
                ],
                'content': [
                    (r'_rails_session', 'cookie'),
                    (r'authenticity_token', 'rails'),
                ],
            },
            'nodejs': {
                'headers': [
                    (r'X-Powered-By.*Express', 'header'),
                    (r'Server.*Node', 'header'),
                ],
                'urls': [
                    (r'\.js$', 'url'),
                    (r'/api/', 'url'),
                ],
                'content': [
                    (r'connect\.sid', 'cookie'),
                ],
            },
        }

        # Server detection patterns
        self.server_patterns = {
            'Apache': [r'Server.*Apache'],
            'IIS': [r'Server.*IIS', r'Server.*Microsoft-IIS'],
            'Nginx': [r'Server.*nginx'],
            'Tomcat': [r'Server.*Tomcat'],
            'LiteSpeed': [r'Server.*LiteSpeed'],
        }

        # Framework detection
        self.framework_patterns = {
            'Laravel': [r'laravel_session', r'X-Laravel'],
            'Django': [r'csrfmiddlewaretoken', r'django'],
            'Rails': [r'_rails_session', r'authenticity_token'],
            'Express': [r'X-Powered-By.*Express'],
            'Flask': [r'Server.*Werkzeug', r'__flask'],
            'Spring': [r'SPRING_SECURITY', r'\.do$'],
            'Symfony': [r'symfony', r'X-Symfony'],
            'CodeIgniter': [r'ci_session'],
            'CakePHP': [r'CAKEPHP'],
        }

    def detect(self, url: str, headers: Dict[str, str], content: str,
               cookies: Dict[str, str] = None) -> TechProfile:
        """
        Определяет технологию на основе URL, headers, content

        Args:
            url: URL страницы
            headers: HTTP headers
            content: Page content
            cookies: Cookies (optional)

        Returns:
            TechProfile with detected technology
        """
        detected_langs = {}

        # Check each language
        for lang, patterns in self.language_patterns.items():
            score = 0
            evidence = []

            # Check headers
            for pattern, evidence_type in patterns.get('headers', []):
                for header_name, header_value in headers.items():
                    if re.search(pattern, f"{header_name}: {header_value}", re.IGNORECASE):
                        score += 10
                        evidence.append(f"header:{header_name}")

            # Check URLs
            for pattern, evidence_type in patterns.get('urls', []):
                if re.search(pattern, url, re.IGNORECASE):
                    score += 5
                    evidence.append(f"url:{pattern}")

            # Check content
            for pattern, evidence_type in patterns.get('content', []):
                if re.search(pattern, content, re.IGNORECASE):
                    score += 3
                    evidence.append(f"content:{evidence_type}")

            # Check cookies
            if cookies:
                for cookie_name in cookies.keys():
                    for pattern, evidence_type in patterns.get('content', []):
                        if evidence_type == 'cookie' and re.search(pattern, cookie_name, re.IGNORECASE):
                            score += 5
                            evidence.append(f"cookie:{cookie_name}")

            if score > 0:
                detected_langs[lang] = {'score': score, 'evidence': evidence}

        # Get language with highest score
        if detected_langs:
            best_lang = max(detected_langs.items(), key=lambda x: x[1]['score'])
            language = best_lang[0]
        else:
            # Fallback: detect from URL extension
            language = self._detect_from_url(url)

        # Detect server
        server = self._detect_server(headers)

        # Detect framework
        framework = self._detect_framework(headers, content, cookies)

        return TechProfile(
            language=language or 'unknown',
            server=server,
            framework=framework
        )

    def _detect_from_url(self, url: str) -> Optional[str]:
        """Fallback detection from URL extension"""
        url_lower = url.lower()

        if re.search(r'\.php[345]?$', url_lower):
            return 'php'
        elif re.search(r'\.aspx?$', url_lower):
            return 'asp'
        elif re.search(r'\.jsp$', url_lower):
            return 'jsp'
        elif re.search(r'\.py$', url_lower):
            return 'python'
        elif re.search(r'\.rb$', url_lower):
            return 'ruby'
        elif re.search(r'\.js$', url_lower):
            return 'nodejs'

        return None

    def _detect_server(self, headers: Dict[str, str]) -> Optional[str]:
        """Detect web server"""
        for server, patterns in self.server_patterns.items():
            for pattern in patterns:
                for header_name, header_value in headers.items():
                    if re.search(pattern, f"{header_name}: {header_value}", re.IGNORECASE):
                        return server
        return None

    def _detect_framework(self, headers: Dict[str, str], content: str,
                          cookies: Dict[str, str] = None) -> Optional[str]:
        """Detect framework"""
        for framework, patterns in self.framework_patterns.items():
            for pattern in patterns:
                # Check headers
                for header_name, header_value in headers.items():
                    if re.search(pattern, f"{header_name}: {header_value}", re.IGNORECASE):
                        return framework

                # Check content
                if re.search(pattern, content, re.IGNORECASE):
                    return framework

                # Check cookies
                if cookies:
                    for cookie_name in cookies.keys():
                        if re.search(pattern, cookie_name, re.IGNORECASE):
                            return framework

        return None

    def get_extensions_for_bruteforce(self, tech_profile: TechProfile) -> List[str]:
        """
        Получить расширения файлов для брутфорса на основе технологии

        Args:
            tech_profile: Detected technology profile

        Returns:
            List of file extensions to brute force
        """
        base_extensions = tech_profile.extensions or []

        # Add common extensions
        common = ['.txt', '.bak', '.old', '.backup', '.swp', '~']

        # Add framework-specific files
        framework_files = {
            'Laravel': ['.env', 'composer.json', 'artisan'],
            'Django': ['settings.py', 'manage.py', 'wsgi.py'],
            'Rails': ['Gemfile', 'config.ru', 'database.yml'],
            'Express': ['package.json', 'server.js', 'app.js'],
            'Flask': ['app.py', 'wsgi.py', 'requirements.txt'],
            'Spring': ['application.properties', 'application.yml', 'pom.xml'],
        }

        if tech_profile.framework in framework_files:
            base_extensions.extend(framework_files[tech_profile.framework])

        return list(set(base_extensions + common))

    def should_test_module(self, module_name: str, tech_profile: TechProfile) -> bool:
        """
        Определить, нужно ли тестировать модуль на основе технологии

        Args:
            module_name: Name of vulnerability module
            tech_profile: Detected technology profile

        Returns:
            True if module should be tested
        """
        # Module to language mapping
        module_requirements = {
            'php_object_injection': ['php'],
            'ssti': ['python', 'ruby', 'nodejs', 'jsp'],  # Template engines
            'jsp_injection': ['jsp'],
            'asp_injection': ['asp'],
        }

        if module_name not in module_requirements:
            return True  # Test all modules by default

        required_langs = module_requirements[module_name]
        return tech_profile.language in required_langs or tech_profile.language == 'unknown'


# Global instance
tech_detector = TechDetector()
