"""
Scanner configuration with input validation
"""

import os
import re
import logging
from typing import List, Dict, Optional
from urllib.parse import urlparse

logger = logging.getLogger(__name__)


class ConfigValidationError(ValueError):
    """Raised when configuration validation fails"""
    pass


class Config:
    """Scanner configuration class with comprehensive input validation"""

    # Validation constants
    MIN_TIMEOUT = 5
    MAX_TIMEOUT = 300
    DEFAULT_TIMEOUT = 15
    MIN_THREADS = 1
    MAX_THREADS = 50
    DEFAULT_THREADS = 15
    MAX_URL_LENGTH = 2048
    MAX_SUBDOMAIN_LIMIT = 100

    def __init__(self, args):
        """Initialize configuration from arguments with validation"""
        # Validate and set target
        self.target = self._validate_target(args.target)
        self.target_file = self._validate_file_path(args.file, 'target file')
        self.headers = self._parse_headers(args.headers, args.headers_file)
        self.cookies = self._validate_cookies(args.cookies)
        self.auth_type = args.auth
        self.modules = self._parse_modules(args.modules, args.all, getattr(args, 'filetree', False))
        self.exclude_paths = self._parse_exclude(args.exclude)

        # Validate timeout to ensure it's never None and within valid range
        self.timeout = self._validate_numeric(
            getattr(args, 'timeout', self.DEFAULT_TIMEOUT),
            'timeout',
            self.MIN_TIMEOUT,
            self.MAX_TIMEOUT,
            self.DEFAULT_TIMEOUT
        )

        # Validate and set proxy
        self.proxy = self._validate_proxy(getattr(args, 'proxy', None))

        # Validate threads
        self.threads = self._validate_numeric(
            args.threads,
            'threads',
            self.MIN_THREADS,
            self.MAX_THREADS,
            self.DEFAULT_THREADS
        )

        self.request_limit = self._validate_numeric(
            args.limit,
            'request_limit',
            0,
            100000,
            10000
        )
        self.page_limit = self._validate_numeric(
            args.page_limit,
            'page_limit',
            0,
            10000,
            50
        )
        self.output_file = args.output
        self.output_format = args.format
        self.single_url = getattr(args, 'single_url', False) or getattr(args, 'nocrawl', False)
        self.filetree = getattr(args, 'filetree', False)
        
        # Crawler settings
        self.crawler_depth = getattr(args, 'crawler_depth', 3)
        self.enable_js_crawling = getattr(args, 'enable_js_crawling', True)
        self.max_crawl_pages = getattr(args, 'max_crawl_pages', 100)

        # ROTATION 9 - New flags
        self.recon_only = getattr(args, 'recon_only', False)  # Passive recon only, no active attacks
        self.rotate_agent = getattr(args, 'rotate_agent', False)  # Random User-Agent rotation
        self.live_reporting = getattr(args, 'live', False)  # Real-time report updates
        self.no_ping = getattr(args, 'no_ping', False)  # Skip target alive check
        self.add_known_paths = getattr(args, 'add_known_paths', None)  # File with known paths to inject
        self.custom_payloads = getattr(args, 'custom_payloads', None)  # Custom payloads override

        # Headless browser mode for WAF/Cloudflare bypass
        self.use_browser = getattr(args, 'browser', False)  # Use headless browser
        self.waf_mode = getattr(args, 'waf_mode', False)  # WAF evasion techniques

        # API Testing mode - pre-parsed endpoints from API spec
        self.api_targets = getattr(args, 'api_targets', None)  # List of endpoint dicts from API parser
        self.api_mode = self.api_targets is not None and len(self.api_targets) > 0

        # Subdomain scanning options
        self.enum_subdomains = getattr(args, 'enum_subdomains', False)  # Enumerate subdomains first
        self.subdomain_takeover = getattr(args, 'subdomain_takeover', False)  # Check for takeovers
        self.scan_subdomains = getattr(args, 'scan_subdomains', False)  # Scan main + subdomains
        self.subdomain_limit = getattr(args, 'subdomain_limit', 10)  # Max subdomains to scan
        self.subdomain_wordlist = getattr(args, 'subdomain_wordlist', None)  # Custom wordlist
        self.subdomain_passive_only = getattr(args, 'subdomain_passive_only', False)  # Passive only

        # Directory paths
        self.modules_dir = "modules"
        self.payloads_dir = "payloads"
        self.detectors_dir = "detectors"
        self.templates_dir = "report/templates"
        
    def _discover_available_modules(self) -> List[str]:
        """
        Auto-discover all available modules from modules/ directory

        Returns:
            List of module names (directory names that contain module.py)
        """
        available_modules = []
        modules_dir = self.modules_dir if hasattr(self, 'modules_dir') else "modules"

        if not os.path.exists(modules_dir):
            return available_modules

        try:
            for item in os.listdir(modules_dir):
                module_path = os.path.join(modules_dir, item)

                # Check if it's a directory
                if not os.path.isdir(module_path):
                    continue

                # Check if module.py exists
                module_file = os.path.join(module_path, "module.py")
                if os.path.exists(module_file):
                    available_modules.append(item)

        except Exception as e:
            print(f"Warning: Error discovering modules: {e}")

        return available_modules

    def _parse_headers(self, headers: Optional[List[str]], headers_file: Optional[str]) -> Dict[str, str]:
        """Parse HTTP headers"""
        result = {}

        # From command line arguments
        if headers:
            for header in headers:
                if ':' in header:
                    key, value = header.split(':', 1)
                    result[key.strip()] = value.strip()

        # From file
        if headers_file and os.path.exists(headers_file):
            with open(headers_file, 'r', encoding='utf-8') as f:
                for line in f:
                    line = line.strip()
                    if line and ':' in line:
                        key, value = line.split(':', 1)
                        result[key.strip()] = value.strip()

        return result

    def _validate_target(self, target: Optional[str]) -> Optional[str]:
        """
        Validate target URL format and safety

        Args:
            target: Target URL to validate

        Returns:
            Validated target or None

        Raises:
            ConfigValidationError: If target is invalid
        """
        if not target:
            return None

        target = str(target).strip()

        # Check URL length
        if len(target) > self.MAX_URL_LENGTH:
            logger.warning(f"Target URL exceeds max length ({self.MAX_URL_LENGTH}), truncating")
            target = target[:self.MAX_URL_LENGTH]

        # Add scheme if missing
        if not target.startswith(('http://', 'https://')):
            target = f'https://{target}'

        # Parse and validate URL structure
        try:
            parsed = urlparse(target)

            # Must have netloc (hostname)
            if not parsed.netloc:
                raise ConfigValidationError(f"Invalid target URL: no hostname found in '{target}'")

            # Check for suspicious patterns
            suspicious_patterns = [
                r'[<>"\']',  # HTML/JS injection attempts
                r'\.\.',  # Path traversal in hostname
                r'\\',  # Backslashes
                r'\s',  # Whitespace
            ]
            for pattern in suspicious_patterns:
                if re.search(pattern, parsed.netloc):
                    raise ConfigValidationError(f"Invalid characters in target hostname: '{parsed.netloc}'")

            return target

        except ConfigValidationError:
            raise
        except Exception as e:
            logger.warning(f"Error validating target URL: {e}")
            return target  # Return as-is, let HTTP client handle

    def _validate_file_path(self, path: Optional[str], description: str) -> Optional[str]:
        """
        Validate file path exists and is readable

        Args:
            path: File path to validate
            description: Human-readable description for error messages

        Returns:
            Validated path or None
        """
        if not path:
            return None

        path = str(path).strip()

        # Check for path traversal attempts
        if '..' in path or path.startswith('/') and os.name == 'nt':
            logger.warning(f"Suspicious path pattern in {description}: {path}")

        if not os.path.exists(path):
            raise ConfigValidationError(f"{description.title()} not found: {path}")

        if not os.path.isfile(path):
            raise ConfigValidationError(f"{description.title()} is not a file: {path}")

        return path

    def _validate_cookies(self, cookies: Optional[str]) -> Optional[str]:
        """
        Validate and sanitize cookies string

        Args:
            cookies: Cookie string to validate

        Returns:
            Validated cookies or None
        """
        if not cookies:
            return None

        cookies = str(cookies).strip()

        # Basic sanitization - remove control characters
        cookies = ''.join(c for c in cookies if ord(c) >= 32 or c in '\t')

        # Warn about potentially dangerous patterns
        if '<script' in cookies.lower() or 'javascript:' in cookies.lower():
            logger.warning("Suspicious content in cookies (possible injection attempt)")

        return cookies

    def _validate_proxy(self, proxy: Optional[str]) -> Optional[str]:
        """
        Validate proxy URL format

        Args:
            proxy: Proxy URL to validate

        Returns:
            Validated proxy URL or None
        """
        if not proxy:
            return None

        proxy = str(proxy).strip()

        # Must start with http:// or https:// or socks5://
        if not proxy.startswith(('http://', 'https://', 'socks5://', 'socks4://')):
            proxy = f'http://{proxy}'

        try:
            parsed = urlparse(proxy)
            if not parsed.netloc:
                raise ConfigValidationError(f"Invalid proxy URL: {proxy}")
            return proxy
        except Exception as e:
            logger.warning(f"Error validating proxy URL: {e}")
            return proxy

    def _validate_numeric(self, value: any, name: str, min_val: int,
                          max_val: int, default: int) -> int:
        """
        Validate and clamp numeric value within range

        Args:
            value: Value to validate
            name: Parameter name for error messages
            min_val: Minimum allowed value
            max_val: Maximum allowed value
            default: Default value if validation fails

        Returns:
            Validated integer value
        """
        if value is None:
            return default

        try:
            value = int(value)
        except (ValueError, TypeError):
            logger.warning(f"Invalid {name} value '{value}', using default: {default}")
            return default

        if value < min_val:
            logger.debug(f"{name} value {value} below minimum, clamping to {min_val}")
            return min_val
        if value > max_val:
            logger.debug(f"{name} value {value} above maximum, clamping to {max_val}")
            return max_val

        return value

    def _parse_modules(self, modules_str: Optional[str], use_all: bool, filetree_mode: bool = False) -> List[str]:
        """Parse scanning modules"""
        # Auto-discover all available modules from modules/ directory
        all_modules = self._discover_available_modules()
        
        # If filetree mode is enabled, only use file/directory discovery modules
        if filetree_mode:
            filetree_modules = ['dirbrute', 'git', 'phpinfo']
            if modules_str:
                # Allow user to specify additional modules with filetree
                user_modules = [m.strip() for m in modules_str.split(',')]
                normalized_modules = [self._normalize_module_name(m) for m in user_modules]
                # Combine filetree modules with user modules
                return list(set(filetree_modules + normalized_modules))
            else:
                return filetree_modules
        
        if modules_str:
            # Handle special case where user specifies "all" as module name
            if modules_str.strip().lower() == 'all':
                return all_modules
            modules = [m.strip() for m in modules_str.split(',')]
            # Normalize module names
            return [self._normalize_module_name(m) for m in modules]
        elif use_all:
            return all_modules
        else:
            # If no modules specified and --all not used, use all modules by default
            return all_modules
    
    def _parse_exclude(self, exclude_str: Optional[str]) -> List[str]:
        """Parse excluded paths"""
        if exclude_str:
            return [path.strip() for path in exclude_str.split(',')]
        return []
    
    def get_targets(self) -> List[str]:
        """Get list of targets for scanning"""
        targets = []

        # From -t parameter
        if self.target:
            if isinstance(self.target, list):
                # Multiple targets passed as list
                targets.extend(self.target)
            else:
                # Single target passed as string
                targets.append(self.target)

        # From file
        if self.target_file and os.path.exists(self.target_file):
            try:
                with open(self.target_file, 'r', encoding='utf-8') as f:
                    for line in f:
                        line = line.strip()
                        if line and not line.startswith('#'):
                            targets.append(line)
            except (IOError, UnicodeDecodeError) as e:
                print(f"Warning: Error reading targets file {self.target_file}: {e}")

        # Auto-fix URLs missing scheme (http:// or https://)
        fixed_targets = []
        for target in targets:
            if not target.startswith(('http://', 'https://')):
                fixed_target = f'https://{target}'
                print(f"[*] Auto-fixed URL: '{target}' -> '{fixed_target}'")
                fixed_targets.append(fixed_target)
            else:
                fixed_targets.append(target)

        return fixed_targets
    
    def _normalize_module_name(self, module_name: str) -> str:
        """Normalize module names for consistency"""
        module_mapping = {
            'gitexposed': 'git',
            'git-exposed': 'git',
            'securityheaders': 'secheaders',
            'security-headers': 'secheaders',
            'httponlycookie': 'httponlycookies',
            'httponly-cookies': 'httponlycookies'
        }
        return module_mapping.get(module_name.lower(), module_name.lower())
