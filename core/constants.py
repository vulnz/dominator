"""
Scanner Constants and Configuration Defaults

This module centralizes all magic numbers and configuration defaults
to improve maintainability and documentation.
"""

from typing import Final

# =============================================================================
# HTTP CLIENT CONFIGURATION
# =============================================================================

# Connection pool settings
POOL_CONNECTIONS: Final[int] = 100  # Max persistent connections to maintain
POOL_MAXSIZE: Final[int] = 20  # Max connections per host
POOL_BLOCK: Final[bool] = False  # Don't block when pool is full

# Timeout settings (in seconds)
DEFAULT_TIMEOUT: Final[int] = 15  # Default request timeout
MIN_TIMEOUT: Final[int] = 5  # Minimum allowed timeout
MAX_TIMEOUT: Final[int] = 300  # Maximum allowed timeout (5 minutes)

# Rate limiting
DEFAULT_REQUEST_LIMIT: Final[int] = 10000  # Max requests per scan
DEFAULT_DELAY: Final[float] = 0.0  # Delay between requests (seconds)

# Retry settings
MAX_RETRIES: Final[int] = 3  # Max retry attempts for failed requests
RETRY_BACKOFF: Final[float] = 0.5  # Backoff multiplier between retries


# =============================================================================
# CRAWLER CONFIGURATION
# =============================================================================

# Page limits
DEFAULT_MAX_PAGES: Final[int] = 50  # Default max pages to crawl
MAX_CRAWL_PAGES: Final[int] = 1000  # Hard limit on crawled pages
CRAWLER_DEPTH_MULTIPLIER: Final[int] = 2  # Safety multiplier for deep crawling

# URL deduplication
MAX_PARAM_VALUES_PER_PATTERN: Final[int] = 3  # Keep N URLs per param pattern
MAX_PATH_DEPTH: Final[int] = 10  # Maximum path depth to crawl

# Form handling
MAX_FORMS_PER_PAGE: Final[int] = 50  # Max forms to extract per page
MAX_INPUTS_PER_FORM: Final[int] = 100  # Max inputs to extract per form

# Content limits
MAX_RESPONSE_SIZE: Final[int] = 10 * 1024 * 1024  # 10MB max response
MAX_URL_LENGTH: Final[int] = 2048  # Max URL length


# =============================================================================
# THREADING CONFIGURATION
# =============================================================================

# Thread pool settings
DEFAULT_THREADS: Final[int] = 15  # Default worker threads
MIN_THREADS: Final[int] = 1  # Minimum worker threads
MAX_THREADS: Final[int] = 50  # Maximum worker threads (prevent explosion)

# Concurrent requests per module
DEFAULT_CONCURRENT_REQUESTS: Final[int] = 10  # Concurrent requests per module


# =============================================================================
# MODULE CONFIGURATION
# =============================================================================

# Payload limits
DEFAULT_MAX_PAYLOADS: Final[int] = 100  # Default max payloads per module
DEFAULT_PAYLOAD_LIMIT: Final[int] = 0  # 0 = no limit (user can override)

# Response analysis
MAX_RESPONSE_CONTEXT: Final[int] = 500  # Max chars for context extraction
CONTEXT_BEFORE: Final[int] = 100  # Chars before matched pattern
CONTEXT_AFTER: Final[int] = 50  # Chars after matched pattern


# =============================================================================
# RESULT AND REPORTING
# =============================================================================

# Finding limits
MAX_FINDINGS_PER_MODULE: Final[int] = 1000  # Max findings to keep per module
MAX_DUPLICATE_FINDINGS: Final[int] = 3  # Max duplicate findings to report

# Report limits
MAX_EVIDENCE_LENGTH: Final[int] = 5000  # Max evidence chars in report
MAX_RESPONSE_IN_REPORT: Final[int] = 5000  # Max response chars in report


# =============================================================================
# SUBDOMAIN SCANNING
# =============================================================================

DEFAULT_SUBDOMAIN_LIMIT: Final[int] = 10  # Default subdomains to scan
MAX_SUBDOMAIN_LIMIT: Final[int] = 100  # Maximum subdomains to scan
DNS_TIMEOUT: Final[int] = 5  # DNS resolution timeout


# =============================================================================
# WAF/BYPASS SETTINGS
# =============================================================================

CLOUDSCRAPER_DELAY: Final[float] = 0.5  # Delay for cloudscraper requests
BROWSER_TIMEOUT: Final[int] = 30000  # Browser timeout in ms
MAX_CLOUDFLARE_WAIT: Final[int] = 15  # Max seconds to wait for CF challenge


# =============================================================================
# PASSIVE SCANNER CONFIGURATION
# =============================================================================

# Finding accumulation limits
MAX_PASSIVE_FINDINGS: Final[int] = 10000  # Max passive findings to store
MAX_SECURITY_ISSUES: Final[int] = 5000  # Max security issues to store


# =============================================================================
# SEVERITY LEVELS
# =============================================================================

SEVERITY_CRITICAL: Final[str] = "Critical"
SEVERITY_HIGH: Final[str] = "High"
SEVERITY_MEDIUM: Final[str] = "Medium"
SEVERITY_LOW: Final[str] = "Low"
SEVERITY_INFO: Final[str] = "Info"

# Severity order for sorting
SEVERITY_ORDER: Final[dict] = {
    "Critical": 0,
    "High": 1,
    "Medium": 2,
    "Low": 3,
    "Info": 4
}


# =============================================================================
# USER AGENT STRINGS
# =============================================================================

DEFAULT_USER_AGENT: Final[str] = "Dominator/1.0"

BROWSER_USER_AGENTS: Final[list] = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Edge/120.0.0.0 Safari/537.36",
]


# =============================================================================
# FILE EXTENSIONS
# =============================================================================

# Extensions to ignore during crawling
IGNORED_EXTENSIONS: Final[frozenset] = frozenset({
    '.jpg', '.jpeg', '.png', '.gif', '.bmp', '.ico', '.svg', '.webp',
    '.css', '.woff', '.woff2', '.ttf', '.eot', '.otf',
    '.mp3', '.mp4', '.avi', '.mov', '.wmv', '.flv', '.webm',
    '.zip', '.rar', '.7z', '.tar', '.gz', '.bz2',
    '.pdf', '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx',
    '.exe', '.dll', '.so', '.dmg', '.deb', '.rpm',
})

# Extensions that may contain injectable content
INJECTABLE_EXTENSIONS: Final[frozenset] = frozenset({
    '.php', '.asp', '.aspx', '.jsp', '.jspx', '.do', '.action',
    '.cgi', '.pl', '.py', '.rb', '.cfm', '.cfml',
    '', '.html', '.htm', '.shtml', '.xhtml',
})


# =============================================================================
# URL DEDUPLICATION CONFIGURATION
# =============================================================================

# Pattern placeholders for URL normalization
NUMERIC_PATTERN_PLACEHOLDER: Final[str] = "[NUM]"
HASH_PATTERN_PLACEHOLDER: Final[str] = "[HASH]"
UUID_PATTERN_PLACEHOLDER: Final[str] = "[UUID]"
DATE_PATTERN_PLACEHOLDER: Final[str] = "[DATE]"
FILENAME_PATTERN_PLACEHOLDER: Final[str] = "[FILE]"

# Maximum URLs per pattern to keep (avoid testing /1.jpg, /2.jpg, /3.jpg, etc.)
MAX_URLS_PER_PATTERN: Final[int] = 2

# Regex patterns for URL normalization (compiled at import time for performance)
import re
RE_NUMERIC_ID: Final = re.compile(r'^[0-9]+$')
RE_HASH_LIKE: Final = re.compile(r'^[a-f0-9]{8,64}$', re.IGNORECASE)
RE_UUID: Final = re.compile(r'^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$', re.IGNORECASE)
RE_DATE: Final = re.compile(r'^\d{4}[-/]\d{2}[-/]\d{2}$')
RE_NUMERIC_FILENAME: Final = re.compile(r'^[0-9]+\.[a-zA-Z]{2,5}$')  # e.g., 12345.jpg

# Static file extensions that should NEVER be tested for injections
# These are files that cannot execute server-side code
STATIC_FILE_EXTENSIONS: Final[frozenset] = frozenset({
    # Images
    '.jpg', '.jpeg', '.png', '.gif', '.bmp', '.ico', '.svg', '.webp',
    '.tiff', '.tif', '.psd', '.ai', '.eps', '.raw',

    # Fonts
    '.woff', '.woff2', '.ttf', '.eot', '.otf',

    # Stylesheets
    '.css', '.scss', '.sass', '.less',

    # Audio
    '.mp3', '.wav', '.ogg', '.flac', '.aac', '.m4a', '.wma',

    # Video
    '.mp4', '.avi', '.mov', '.wmv', '.flv', '.webm', '.mkv', '.m4v',

    # Archives
    '.zip', '.rar', '.7z', '.tar', '.gz', '.bz2', '.xz',

    # Documents (mostly static, no injection points)
    '.pdf', '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx',
    '.odt', '.ods', '.odp', '.rtf',

    # Executables (static files, not web-injectable)
    '.exe', '.dll', '.so', '.dmg', '.deb', '.rpm', '.msi',

    # Data files (static)
    '.json', '.xml', '.yaml', '.yml', '.csv', '.txt', '.log',
    '.map',  # Source maps

    # Other static
    '.swf', '.fla',  # Flash (legacy)
})
