"""
Source Code & Archive Exposure Detector

Intelligently detects exposed source code, archives, and sensitive files
with context-aware filtering to minimize false positives.

Key Features:
- Whitelist for code hosting platforms (GitHub, GitLab, etc.)
- Deduplication per domain (only report once per file type per domain)
- Confidence scoring based on multiple indicators
- Contextual awareness (download pages, package registries, etc.)
- Rate limiting findings to prevent spam

Detection Categories:
- Source code files (PHP, Python, Java, etc.)
- Archive files (ZIP, RAR, TAR, etc.)
- Database files (SQL dumps, SQLite, etc.)
- Configuration files (.env, config.php, etc.)
- Version control exposure (.git, .svn)
"""

import re
from typing import Dict, List, Tuple, Any, Optional, Set
from urllib.parse import urlparse
from dataclasses import dataclass
from collections import defaultdict


@dataclass
class ExposureFinding:
    """Structured exposure finding"""
    category: str
    file_type: str
    confidence: float
    severity: str
    evidence: str
    is_critical: bool = False


class SourceExposureDetector:
    """
    Source Code & Archive Exposure Detector

    Smart detection with minimal false positives.
    """

    # Maximum findings per category per domain to prevent spam
    MAX_FINDINGS_PER_CATEGORY = 3

    # Domains where source/archives are expected
    WHITELIST_DOMAINS = {
        # Code hosting
        'github.com', 'githubusercontent.com', 'raw.githubusercontent.com',
        'gitlab.com', 'bitbucket.org', 'codeberg.org', 'sr.ht',
        'sourceforge.net', 'launchpad.net', 'savannah.gnu.org',

        # Package registries
        'npmjs.com', 'registry.npmjs.org', 'yarnpkg.com',
        'pypi.org', 'files.pythonhosted.org',
        'rubygems.org', 'gems.ruby-lang.org',
        'packagist.org', 'repo.packagist.org',
        'mvnrepository.com', 'repo1.maven.org', 'central.maven.org',
        'nuget.org', 'api.nuget.org',
        'crates.io', 'cran.r-project.org',
        'cpan.org', 'metacpan.org',
        'hex.pm', 'pub.dev',

        # CDNs
        'cdn.jsdelivr.net', 'unpkg.com', 'cdnjs.cloudflare.com',
        'esm.sh', 'esm.run', 'skypack.dev',

        # Documentation/paste
        'pastebin.com', 'gist.github.com',
        'readthedocs.io', 'readthedocs.org',

        # Cloud storage (intentional sharing)
        'storage.googleapis.com', 's3.amazonaws.com',
        'blob.core.windows.net',

        # Archives
        'archive.org', 'web.archive.org',
    }

    # Patterns that indicate intentional file serving
    INTENTIONAL_PATH_PATTERNS = [
        r'/releases?/', r'/downloads?/', r'/dist/',
        r'/packages?/', r'/assets?/', r'/files?/',
        r'/artifacts?/', r'/binaries?/', r'/builds?/',
        r'/static/downloads?', r'/pub/', r'/archive/',
    ]

    # File types and their detection patterns
    SOURCE_CODE_SIGNATURES = {
        'PHP': {
            'extensions': ['.php', '.php3', '.php4', '.php5', '.phtml', '.phps'],
            'patterns': [
                r'^<\?php\s',
                r'<\?php\s+(?:declare|namespace|use|class|interface|trait|function)',
                r'<\?=\s*\$',
            ],
            'severity': 'Critical',
            'min_matches': 1,
        },
        'ASP.NET': {
            'extensions': ['.asp', '.aspx', '.ascx', '.ashx', '.asmx', '.cshtml', '.vbhtml'],
            'patterns': [
                r'<%@\s*(?:Page|Control|Master|WebHandler)',
                r'<%@\s*(?:Import|Assembly|Register)',
                r'<asp:\w+',
            ],
            'severity': 'Critical',
            'min_matches': 1,
        },
        'JSP': {
            'extensions': ['.jsp', '.jspx', '.jspf'],
            'patterns': [
                r'<%@\s*page\s+',
                r'<%@\s*taglib\s+',
                r'<jsp:\w+',
            ],
            'severity': 'Critical',
            'min_matches': 1,
        },
        'Python (Server)': {
            'extensions': ['.py'],
            'patterns': [
                r'^from\s+(?:flask|django|fastapi|tornado|pyramid|bottle)',
                r'^from\s+(?:sqlalchemy|peewee|tortoise)',
                r'@app\.route\s*\(',
                r'DATABASES\s*=\s*\{',
                r'SECRET_KEY\s*=',
            ],
            'severity': 'High',
            'min_matches': 2,  # Need multiple indicators for server code
        },
        'Java/Kotlin': {
            'extensions': ['.java', '.kt', '.scala'],
            'patterns': [
                r'package\s+[\w.]+;',
                r'@(?:RestController|Controller|Service|Repository)',
                r'@RequestMapping',
                r'import\s+(?:javax\.servlet|org\.springframework)',
            ],
            'severity': 'High',
            'min_matches': 2,
        },
        'Ruby': {
            'extensions': ['.rb', '.erb', '.rake'],
            'patterns': [
                r'^class\s+\w+Controller\s*<',
                r'Rails\.application',
                r'config\.secret_key_base',
            ],
            'severity': 'High',
            'min_matches': 2,
        },
        'Go': {
            'extensions': ['.go'],
            'patterns': [
                r'package\s+main',
                r'func\s+\w+Handler\s*\(',
                r'http\.HandleFunc',
            ],
            'severity': 'High',
            'min_matches': 2,
        },
    }

    # Configuration file patterns
    CONFIG_SIGNATURES = {
        '.env': {
            'patterns': [
                r'^[A-Z_]+=.+$',
                r'^(?:DB_|API_|SECRET_|AWS_|REDIS_)\w+=',
                r'^(?:DATABASE_URL|MONGO_URI|REDIS_URL)=',
            ],
            'severity': 'Critical',
            'min_matches': 2,
        },
        'wp-config.php': {
            'patterns': [
                r"define\s*\(\s*['\"]DB_(?:NAME|USER|PASSWORD|HOST)['\"]",
                r"define\s*\(\s*['\"](?:AUTH|SECURE_AUTH|LOGGED_IN)_KEY['\"]",
            ],
            'severity': 'Critical',
            'min_matches': 1,
        },
        'config.php': {
            'patterns': [
                r'\$(?:db|database|mysql)_(?:host|user|pass)',
                r'\$config\s*\[\s*[\'"](?:database|db|password)[\'"]',
            ],
            'severity': 'High',
            'min_matches': 1,
        },
        'settings.py': {
            'patterns': [
                r'^SECRET_KEY\s*=',
                r'^DATABASES\s*=\s*\{',
                r'^(?:EMAIL_HOST_PASSWORD|AWS_SECRET)',
            ],
            'severity': 'Critical',
            'min_matches': 1,
        },
        'application.properties': {
            'patterns': [
                r'^spring\.datasource\.password\s*=',
                r'^server\.ssl\.key-store-password\s*=',
            ],
            'severity': 'High',
            'min_matches': 1,
        },
        'appsettings.json': {
            'patterns': [
                r'"ConnectionStrings"\s*:\s*\{',
                r'"(?:Password|Secret|ApiKey)"\s*:\s*"[^"]+',
            ],
            'severity': 'High',
            'min_matches': 1,
        },
    }

    # Archive detection (based on magic bytes in text representation)
    ARCHIVE_INDICATORS = {
        'ZIP': {
            'magic': 'PK',
            'extensions': ['.zip', '.jar', '.war', '.ear', '.apk', '.docx', '.xlsx'],
            'severity': 'Medium',
        },
        'RAR': {
            'magic': 'Rar!',
            'extensions': ['.rar'],
            'severity': 'Medium',
        },
        'GZIP': {
            'extensions': ['.gz', '.tgz'],
            'severity': 'Medium',
        },
        '7ZIP': {
            'extensions': ['.7z'],
            'severity': 'Medium',
        },
        'TAR': {
            'extensions': ['.tar', '.tar.gz', '.tar.bz2', '.tar.xz'],
            'severity': 'Medium',
        },
    }

    # Database file patterns
    DATABASE_SIGNATURES = {
        'SQL Dump': {
            'extensions': ['.sql', '.sql.gz', '.dump'],
            'patterns': [
                r'^--\s*(?:MySQL|PostgreSQL|MariaDB|SQLite)\s+dump',
                r'^CREATE\s+(?:TABLE|DATABASE)\s+',
                r'^INSERT\s+INTO\s+[`\'"]?\w+[`\'"]?\s+VALUES',
                r'^DROP\s+TABLE\s+IF\s+EXISTS',
            ],
            'severity': 'Critical',
            'min_matches': 2,
        },
        'SQLite': {
            'extensions': ['.sqlite', '.sqlite3', '.db', '.db3'],
            'magic': 'SQLite format 3',
            'severity': 'Critical',
        },
    }

    # Version control exposure
    VCS_PATTERNS = {
        '.git': {
            'url_patterns': [r'/\.git/', r'/\.git$', r'/\.git/config', r'/\.git/HEAD'],
            'content_patterns': [
                r'^\[core\]',
                r'^ref:\s*refs/heads/',
            ],
            'severity': 'Critical',
        },
        '.svn': {
            'url_patterns': [r'/\.svn/', r'/\.svn/entries', r'/\.svn/wc\.db'],
            'severity': 'High',
        },
        '.hg': {
            'url_patterns': [r'/\.hg/', r'/\.hg/hgrc'],
            'severity': 'High',
        },
    }

    # Track findings to deduplicate across calls
    _findings_cache: Dict[str, Dict[str, int]] = defaultdict(lambda: defaultdict(int))

    @classmethod
    def detect(cls, response_text: str, url: str,
               headers: Dict[str, str] = None) -> Tuple[bool, List[Dict[str, Any]]]:
        """
        Detect source code and archive exposure.

        Args:
            response_text: HTTP response body
            url: URL being analyzed
            headers: HTTP response headers

        Returns:
            Tuple of (found_exposure, list_of_findings)
        """
        findings = []
        headers = headers or {}

        # Skip whitelisted domains
        if cls._is_whitelisted(url):
            return False, findings

        # Get domain for deduplication
        domain = cls._get_domain(url)
        content_type = headers.get('Content-Type', '') or headers.get('content-type', '')

        # Check for source code exposure
        source_findings = cls._check_source_code_exposure(url, response_text, content_type, domain)
        findings.extend(source_findings)

        # Check for config file exposure
        config_findings = cls._check_config_exposure(url, response_text, content_type, domain)
        findings.extend(config_findings)

        # Check for database exposure
        db_findings = cls._check_database_exposure(url, response_text, domain)
        findings.extend(db_findings)

        # Check for VCS exposure
        vcs_findings = cls._check_vcs_exposure(url, response_text, domain)
        findings.extend(vcs_findings)

        # Check for archive files (if URL indicates)
        archive_findings = cls._check_archive_exposure(url, response_text, content_type, domain)
        findings.extend(archive_findings)

        return len(findings) > 0, findings

    @classmethod
    def _is_whitelisted(cls, url: str) -> bool:
        """Check if URL is whitelisted"""
        try:
            parsed = urlparse(url)
            domain = parsed.netloc.lower()

            # Remove port
            if ':' in domain:
                domain = domain.split(':')[0]

            # Check exact match
            if domain in cls.WHITELIST_DOMAINS:
                return True

            # Check subdomain
            for whitelist in cls.WHITELIST_DOMAINS:
                if domain.endswith('.' + whitelist):
                    return True

            # Check path for intentional serving
            path = parsed.path.lower()
            for pattern in cls.INTENTIONAL_PATH_PATTERNS:
                if re.search(pattern, path, re.IGNORECASE):
                    return True

        except Exception:
            pass

        return False

    @classmethod
    def _get_domain(cls, url: str) -> str:
        """Extract domain from URL"""
        try:
            parsed = urlparse(url)
            domain = parsed.netloc.lower()
            if ':' in domain:
                domain = domain.split(':')[0]
            return domain
        except:
            return 'unknown'

    @classmethod
    def _should_report(cls, domain: str, category: str) -> bool:
        """Check if we should report this finding (rate limiting)"""
        current_count = cls._findings_cache[domain][category]
        if current_count >= cls.MAX_FINDINGS_PER_CATEGORY:
            return False
        cls._findings_cache[domain][category] += 1
        return True

    @classmethod
    def _check_source_code_exposure(cls, url: str, content: str,
                                    content_type: str, domain: str) -> List[Dict[str, Any]]:
        """Check for source code exposure"""
        findings = []

        if not content or len(content) < 50:
            return findings

        # Check URL extension
        path = urlparse(url).path.lower()

        for lang, config in cls.SOURCE_CODE_SIGNATURES.items():
            # Check extension match
            ext_match = any(path.endswith(ext) for ext in config['extensions'])

            # Check content patterns
            matches = 0
            matched_patterns = []
            for pattern in config['patterns']:
                if re.search(pattern, content[:10000], re.MULTILINE | re.IGNORECASE):
                    matches += 1
                    matched_patterns.append(pattern[:50])

            # Determine if this is real exposure
            if matches >= config['min_matches']:
                # For non-HTML content type serving source
                is_raw = 'text/plain' in content_type.lower() or \
                        'application/octet-stream' in content_type.lower()

                # PHP in HTML response is definitely exposed
                is_php_exposed = lang == 'PHP' and '<?php' in content[:1000] and \
                                 'text/html' not in content_type.lower()

                if ext_match or is_raw or is_php_exposed:
                    if not cls._should_report(domain, f'source_{lang}'):
                        continue

                    findings.append({
                        'type': f'{lang} Source Code Exposed',
                        'severity': config['severity'],
                        'url': url,
                        'language': lang,
                        'content_type': content_type,
                        'matched_indicators': matches,
                        'description': f'{lang} source code is being served raw. '
                                      f'Server may be misconfigured.',
                        'evidence': content[:300].strip() if len(content) > 300 else content.strip(),
                        'category': 'source_code_exposure',
                        'location': 'Response Body',
                        'recommendation': f'Configure server to process {lang} files properly. '
                                         f'Never serve source code as plain text.'
                    })

        return findings

    @classmethod
    def _check_config_exposure(cls, url: str, content: str,
                              content_type: str, domain: str) -> List[Dict[str, Any]]:
        """Check for configuration file exposure"""
        findings = []

        if not content or len(content) < 20:
            return findings

        path = urlparse(url).path.lower()
        filename = path.rsplit('/', 1)[-1] if '/' in path else path

        for config_name, config in cls.CONFIG_SIGNATURES.items():
            # Check if filename matches
            if config_name.lower() in filename.lower() or \
               (config_name == '.env' and path.endswith('.env')):

                # Verify content matches
                matches = 0
                for pattern in config['patterns']:
                    if re.search(pattern, content[:5000], re.MULTILINE):
                        matches += 1

                if matches >= config.get('min_matches', 1):
                    if not cls._should_report(domain, f'config_{config_name}'):
                        continue

                    # Redact sensitive values in evidence
                    evidence = cls._redact_sensitive(content[:400])

                    findings.append({
                        'type': f'Configuration File Exposed: {config_name}',
                        'severity': config['severity'],
                        'url': url,
                        'config_file': config_name,
                        'description': f'Configuration file {config_name} is accessible. '
                                      f'May contain database credentials, API keys, or secrets.',
                        'evidence': evidence,
                        'category': 'config_exposure',
                        'location': 'Response Body',
                        'recommendation': 'Block access to configuration files. '
                                         'Move sensitive files outside web root. '
                                         'Use environment variables for secrets.'
                    })

        return findings

    @classmethod
    def _check_database_exposure(cls, url: str, content: str, domain: str) -> List[Dict[str, Any]]:
        """Check for database file exposure"""
        findings = []

        if not content:
            return findings

        path = urlparse(url).path.lower()

        for db_type, config in cls.DATABASE_SIGNATURES.items():
            # Check extension
            if not any(path.endswith(ext) for ext in config.get('extensions', [])):
                continue

            # Check magic bytes or patterns
            is_match = False

            if 'magic' in config:
                if config['magic'] in content[:100]:
                    is_match = True

            if 'patterns' in config:
                matches = sum(1 for p in config['patterns']
                            if re.search(p, content[:5000], re.MULTILINE | re.IGNORECASE))
                if matches >= config.get('min_matches', 1):
                    is_match = True

            if is_match:
                if not cls._should_report(domain, f'database_{db_type}'):
                    continue

                findings.append({
                    'type': f'{db_type} Exposed',
                    'severity': config['severity'],
                    'url': url,
                    'database_type': db_type,
                    'description': f'{db_type} is publicly accessible. '
                                  f'Contains potentially sensitive data.',
                    'category': 'database_exposure',
                    'location': 'Response Body',
                    'recommendation': 'Remove database files from web-accessible locations. '
                                     'Block access via server configuration.'
                })

        return findings

    @classmethod
    def _check_vcs_exposure(cls, url: str, content: str, domain: str) -> List[Dict[str, Any]]:
        """Check for version control system exposure"""
        findings = []

        path = urlparse(url).path.lower()

        for vcs_type, config in cls.VCS_PATTERNS.items():
            # Check URL pattern
            url_match = any(re.search(p, path) for p in config['url_patterns'])

            if not url_match:
                continue

            # Verify with content if available
            content_verified = True
            if 'content_patterns' in config and content:
                content_verified = any(
                    re.search(p, content[:2000], re.MULTILINE)
                    for p in config['content_patterns']
                )

            if url_match and content_verified:
                if not cls._should_report(domain, f'vcs_{vcs_type}'):
                    continue

                findings.append({
                    'type': f'{vcs_type} Repository Exposed',
                    'severity': config['severity'],
                    'url': url,
                    'vcs_type': vcs_type,
                    'description': f'{vcs_type} repository is accessible. '
                                  f'Complete source code and history may be downloadable.',
                    'category': 'vcs_exposure',
                    'location': 'URL Path',
                    'recommendation': f'Block access to {vcs_type} directories. '
                                     f'Add to server deny rules: {vcs_type}'
                })

        return findings

    @classmethod
    def _check_archive_exposure(cls, url: str, content: str,
                               content_type: str, domain: str) -> List[Dict[str, Any]]:
        """Check for unexpected archive file exposure"""
        findings = []

        path = urlparse(url).path.lower()

        # Only check if URL doesn't indicate intentional download
        if any(re.search(p, path) for p in cls.INTENTIONAL_PATH_PATTERNS):
            return findings

        for archive_type, config in cls.ARCHIVE_INDICATORS.items():
            # Check extension
            if not any(path.endswith(ext) for ext in config.get('extensions', [])):
                continue

            # Verify it's not intended (check content-disposition)
            content_disp = ''
            for key in ['Content-Disposition', 'content-disposition']:
                if key in (headers or {}):
                    content_disp = headers[key].lower()
                    break

            # Skip if it's an attachment (intentional download)
            if 'attachment' in content_disp:
                continue

            # Check if content looks like archive (magic bytes as text)
            if 'magic' in config:
                if config['magic'] not in (content or '')[:10]:
                    continue

            if not cls._should_report(domain, f'archive_{archive_type}'):
                continue

            findings.append({
                'type': f'{archive_type} Archive Found',
                'severity': config['severity'],
                'url': url,
                'archive_type': archive_type,
                'description': f'{archive_type} archive file accessible. '
                              f'Review if intentional.',
                'category': 'archive_exposure',
                'location': 'URL Path',
                'recommendation': 'Review if archive should be publicly accessible. '
                                 'Move sensitive archives outside web root.'
            })

        return findings

    @classmethod
    def _redact_sensitive(cls, text: str) -> str:
        """Redact potentially sensitive values in evidence"""
        # Redact values after = in env files
        text = re.sub(r'((?:PASSWORD|SECRET|KEY|TOKEN|API_KEY|PRIVATE)\s*=\s*)[^\n\r]+',
                     r'\1[REDACTED]', text, flags=re.IGNORECASE)

        # Redact connection strings
        text = re.sub(r'((?:mongodb|mysql|postgres|redis)://[^:]+:)[^@]+(@)',
                     r'\1[REDACTED]\2', text, flags=re.IGNORECASE)

        return text

    @classmethod
    def reset_cache(cls):
        """Reset the findings cache (call between scans)"""
        cls._findings_cache.clear()


# Global variable to track headers for archive check
headers: Dict[str, str] = {}


def detect_source_exposure(response_text: str, url: str,
                          response_headers: Dict[str, str] = None) -> Tuple[bool, List[Dict[str, Any]]]:
    """Convenience function for source exposure detection"""
    global headers
    headers = response_headers or {}
    return SourceExposureDetector.detect(response_text, url, response_headers)
