"""
Web crawler module for finding pages and parameters

Performance optimizations:
- Pre-compiled regex patterns for URL/link extraction
- Connection pooling via HTTPClient
- Efficient URL deduplication
- WAF bypass via cloudscraper or headless browser
"""

import requests
import urllib3
import re
import json
from typing import List, Dict, Any, Set
from urllib.parse import urljoin, urlparse, parse_qs, unquote
from core.url_parser import URLParser
from utils.payload_loader import PayloadLoader

# Import passive detectors
from passive_detectors.security_headers_detector import SecurityHeadersDetector
from passive_detectors.sensitive_data_detector import SensitiveDataDetector
from passive_detectors.technology_detector import TechnologyDetector
from passive_detectors.version_disclosure_detector import VersionDisclosureDetector
from passive_detectors.waf_detector import WAFDetector
from passive_detectors.api_endpoint_detector import APIEndpointDetector
from passive_detectors.js_secrets_detector import JSSecretsDetector

# Import WAF bypass module (optional)
try:
    from core.waf_bypass import WAFBypass, WAFDetector as WAFBypassDetector, check_waf_and_suggest, is_bypass_available
    WAF_BYPASS_AVAILABLE = True
except ImportError:
    WAF_BYPASS_AVAILABLE = False

# Disable SSL warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


# =============================================================================
# PRE-COMPILED REGEX PATTERNS - Performance optimization
# Compiling once at module load instead of every function call
# =============================================================================

# Link extraction patterns
RE_HREF = re.compile(r'href\s*=\s*["\']([^"\']+)["\']', re.IGNORECASE)
RE_SRC = re.compile(r'src\s*=\s*["\']([^"\']+)["\']', re.IGNORECASE)
RE_ACTION = re.compile(r'action\s*=\s*["\']([^"\']+)["\']', re.IGNORECASE)

# JavaScript URL extraction
RE_JS_URL = re.compile(r'["\']((https?://[^"\']+)|(/[^"\']+))["\']')
RE_JS_ENDPOINT = re.compile(r'["\']/(api|v\d|rest|graphql)/[^"\']*["\']', re.IGNORECASE)
RE_JS_FETCH = re.compile(r'fetch\s*\(\s*["\']([^"\']+)["\']', re.IGNORECASE)
RE_JS_AXIOS = re.compile(r'axios\.[a-z]+\s*\(\s*["\']([^"\']+)["\']', re.IGNORECASE)
RE_JS_XHR = re.compile(r'\.open\s*\(\s*["\'][A-Z]+["\']\s*,\s*["\']([^"\']+)["\']', re.IGNORECASE)

# Sitemap and robots patterns
RE_SITEMAP_LOC = re.compile(r'<loc>(.*?)</loc>', re.IGNORECASE)
RE_ROBOTS_DISALLOW = re.compile(r'Disallow:\s*(/[^\s]*)', re.IGNORECASE)
RE_ROBOTS_ALLOW = re.compile(r'Allow:\s*(/[^\s]*)', re.IGNORECASE)

# Form extraction
RE_FORM = re.compile(r'<form[^>]*>(.*?)</form>', re.IGNORECASE | re.DOTALL)
RE_INPUT = re.compile(r'<input[^>]*>', re.IGNORECASE)
RE_SELECT = re.compile(r'<select[^>]*name\s*=\s*["\']([^"\']+)["\']', re.IGNORECASE)
RE_TEXTAREA = re.compile(r'<textarea[^>]*name\s*=\s*["\']([^"\']+)["\']', re.IGNORECASE)

# Directory listing detection
RE_DATETIME = re.compile(r'\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}')
RE_DIR_TABLE = re.compile(
    r'<(?:table|pre)[^>]*>.*?(?:name|size|modified|date|type).*?</(?:table|pre)>',
    re.IGNORECASE | re.DOTALL
)

# Misc patterns
RE_HASH_LIKE = re.compile(r'^[a-f0-9]{8,}$')
RE_META_REDIRECT = re.compile(r'<meta[^>]*http-equiv\s*=\s*["\']refresh["\'][^>]*content\s*=\s*["\'][^"\']*url\s*=\s*([^"\']+)["\']', re.IGNORECASE)

class WebCrawler:
    """Web crawler for finding pages with parameters"""

    def __init__(self, config, http_client=None, use_browser=False):
        """Initialize crawler

        Args:
            config: Scanner configuration
            http_client: HTTPClient instance for proxy support (FIXED: was missing)
            use_browser: Use headless browser for WAF bypass (requires playwright)
        """
        self.config = config
        self.http_client = http_client  # FIXED: Store http_client for proxy/session support
        self.use_browser = use_browser
        self.browser = None  # Headless browser instance
        self.url_parser = URLParser()
        self.visited_urls: Set[str] = set()
        self.analyzed_urls: Set[str] = set()  # Track URLs that have been passively analyzed
        self.found_forms: List[Dict[str, Any]] = []
        self.ajax_endpoints: List[str] = []
        self.js_urls: List[str] = []
        self.sitemap_urls: List[str] = []
        self.robots_urls: List[str] = []
        self.discovered_directories: Set[str] = set()
        self.detected_wafs: Set[str] = set()

        # Passive detection results
        self.passive_findings: List[Dict[str, Any]] = []
        self.security_issues: List[Dict[str, Any]] = []
        self.sensitive_data_leaks: List[Dict[str, Any]] = []
        self.detected_technologies: List[Dict[str, Any]] = []
        self.version_disclosures: List[Dict[str, Any]] = []

        # Initialize headless browser if requested
        if self.use_browser:
            self._init_browser()

    def _init_browser(self):
        """Initialize WAF bypass client (cloudscraper or headless browser)"""
        if not WAF_BYPASS_AVAILABLE:
            print(f"    [CRAWLER] WARNING: WAF bypass requested but dependencies not available")
            print(f"    [CRAWLER] Install with: pip install cloudscraper")
            self.use_browser = False
            return

        try:
            proxy = getattr(self.config, 'proxy', None)
            timeout = getattr(self.config, 'timeout', 30)

            # Use WAFBypass which auto-selects best method (cloudscraper preferred)
            self.browser = WAFBypass(
                proxy=proxy,
                timeout=timeout,
                prefer_browser=False  # Prefer cloudscraper (faster)
            )
            print(f"    [CRAWLER] WAF bypass initialized (method: {self.browser._method})")
        except ImportError as e:
            print(f"    [CRAWLER] WARNING: Could not initialize WAF bypass: {e}")
            self.use_browser = False
        except Exception as e:
            print(f"    [CRAWLER] ERROR: Failed to start WAF bypass: {e}")
            self.use_browser = False

    def _browser_request(self, url: str):
        """Make request using WAF bypass (cloudscraper or browser)"""
        if not self.browser:
            return None

        try:
            response = self.browser.get(url)
            if response:
                # Response is already in proper format from WAFBypass
                return response
        except Exception as e:
            print(f"    [CRAWLER] WAF bypass request error: {e}")
        return None

    def close_browser(self):
        """Close WAF bypass client if running"""
        if self.browser:
            try:
                if hasattr(self.browser, 'close'):
                    self.browser.close()
                self.browser = None
            except:
                pass

    def _make_request(self, url: str, timeout: int = None, **kwargs):
        """
        Make HTTP request using browser, http_client, or direct requests

        Priority:
        1. Headless browser (if enabled) - for WAF bypass
        2. http_client - for proxy support and session pooling
        3. Direct requests - fallback

        Args:
            url: URL to request
            timeout: Request timeout
            **kwargs: Additional arguments (headers, verify, etc.)

        Returns:
            Response object or None
        """
        # Try headless browser first for WAF bypass
        if self.use_browser and self.browser:
            response = self._browser_request(url)
            if response and response.status_code == 200:
                return response
            # If browser fails or returns non-200, fall through to normal requests

        if self.http_client:
            # Use http_client for proxy support and session pooling
            response = self.http_client.get(url, **kwargs)
            if response:
                # Convert HTTPResponse to requests.Response-like object
                return response
            return None
        else:
            # Fallback to direct requests (backward compatibility)
            if timeout is None:
                timeout = self.config.timeout if self.config.timeout else 15

            # Add browser-like headers to avoid WAF/bot detection
            fallback_headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8',
                'Accept-Language': 'en-US,en;q=0.9',
                'Accept-Encoding': 'gzip, deflate, br',
                'Connection': 'keep-alive',
                'Upgrade-Insecure-Requests': '1',
            }
            # Merge with any custom headers
            if 'headers' in kwargs and kwargs['headers']:
                fallback_headers.update(kwargs['headers'])
            kwargs['headers'] = fallback_headers

            return requests.get(url, timeout=timeout, verify=False, **kwargs)

    def crawl_for_pages(self, base_url: str, max_pages: int = 50) -> List[str]:
        """Crawl website to find pages with parameters"""
        found_urls = []
        normalized_urls = []  # FIX: Initialize here to prevent unbound variable error

        try:
            print(f"    [CRAWLER] Starting crawl of {base_url} (max_pages: {max_pages})")

            # First, get data from sitemap and robots.txt
            print(f"    [CRAWLER] Extracting URLs from sitemap and robots.txt...")
            self._extract_sitemap_urls(base_url)
            self._extract_robots_urls(base_url)

            # FIXED: Use http_client for proxy support instead of direct requests
            timeout = self.config.timeout if self.config.timeout else 15
            response = self._make_request(base_url, timeout=timeout, headers=self.config.headers)
            
            no_ping = getattr(self.config, 'no_ping', False)
            if response.status_code == 200 or no_ping:
                if response.status_code != 200 and no_ping:
                    print(f"    [CRAWLER] Target returned {response.status_code} but --no-ping enabled, continuing...")
                else:
                    print(f"    [CRAWLER] Successfully connected to {base_url}")
                    
                # Check for directory listing on main page first
                if self._detect_directory_listing(response.text):
                    print(f"    [CRAWLER] Directory listing detected on main page: {base_url}")

                    # IMPORTANT: Add directory listing as a finding
                    dir_listing_finding = {
                        'vulnerability': True,
                        'module': 'Directory Listing',
                        'type': 'Directory Listing',
                        'url': base_url,
                        'severity': 'Medium',
                        'confidence': 0.95,
                        'description': 'Directory listing is enabled, exposing file/directory structure',
                        'evidence': 'Directory index page detected with file/folder listings',
                        'recommendation': 'Disable directory indexing in web server configuration',
                        'cwe': 'CWE-548',
                        'owasp': 'A05:2021',
                        'cvss': '5.3'
                    }
                    self.passive_findings.append(dir_listing_finding)

                    # Extract directory listing URLs
                    dir_urls = self._extract_directory_listing_urls(response.text, base_url)
                    found_urls.extend(dir_urls)
                    print(f"    [CRAWLER] Extracted {len(dir_urls)} URLs from main page directory listing")
                    
                # Run passive analysis on initial response
                self._run_passive_analysis(response.headers, response.text, base_url)

                # CRITICAL FIX: Extract forms from initial page (was missing!)
                initial_forms = self.url_parser.extract_forms(response.text)
                for form in initial_forms:
                    form['url'] = base_url  # Add source URL
                    self.found_forms.append(form)
                    print(f"    [CRAWLER] Found form on main page: {form['method']} {form.get('action', '(same page)')} with {len(form.get('inputs', []))} inputs")

                # Extract JavaScript and AJAX endpoints
                self._extract_js_endpoints(response.text, base_url)
                
                # Analyze discovered JavaScript files for more endpoints and secrets
                self._analyze_javascript_files(base_url)
                
                # Extract URLs from response
                urls = self._extract_all_urls(response.text, base_url)
                print(f"    [CRAWLER] Found {len(urls)} URLs to analyze")
                
                # Add sitemap and robots URLs
                urls.extend(self.sitemap_urls)
                urls.extend(self.robots_urls)
                
                # Add AJAX endpoints to URLs
                urls.extend(self.ajax_endpoints)
                
                # Filter and normalize URLs
                normalized_urls = self._normalize_and_filter_urls(urls, base_url, max_pages * 2)
                print(f"    [CRAWLER] Analyzing {len(normalized_urls)} normalized URLs for parameters...")
                
                # First pass - collect URLs with parameters
                for i, url in enumerate(normalized_urls):
                    try:
                        # OPTIMIZATION: Reduce logging for performance
                        if (i+1) % 10 == 0 or (i+1) == len(normalized_urls):
                            print(f"    [CRAWLER] Checked {i+1}/{len(normalized_urls)} URLs...")

                        # NOTE: Don't mark as visited yet - we haven't actually crawled the page
                        # The deep crawl needs to visit these pages to extract forms

                        parsed = self.url_parser.parse(url)

                        # Check if URL has parameters
                        if parsed['query_params'] and url not in found_urls:
                            found_urls.append(url)
                            print(f"    [CRAWLER] Found page with parameters: {url} ({list(parsed['query_params'].keys())})")

                    except Exception as e:
                        # OPTIMIZATION: Only log errors in verbose mode
                        continue
                
                # Second pass - crawl individual pages to find more URLs
                print(f"    [CRAWLER] Starting second pass crawling...")
                additional_urls = self._crawl_individual_pages(normalized_urls[:30], base_url)
                found_urls.extend(additional_urls)
                        
            else:
                print(f"    [CRAWLER] HTTP {response.status_code} response from {base_url}")
                # Detect WAF/Cloudflare blocks
                if response.status_code == 403:
                    # Check for Cloudflare indicators
                    cf_indicators = ['cloudflare', 'cf-ray', 'cf-request-id', '__cf_bm']
                    headers_str = str(response.headers).lower()
                    content_str = response.text.lower() if hasattr(response, 'text') else ''
                    if any(ind in headers_str or ind in content_str for ind in cf_indicators):
                        print(f"    [CRAWLER] WARNING: Cloudflare protection detected!")
                        print(f"    [CRAWLER] The site uses bot detection that blocks automated requests.")
                        print(f"    [CRAWLER] Try using: --waf-mode, browser interceptor, or a different target.")
                    else:
                        print(f"    [CRAWLER] WARNING: Access denied (403). Site may have WAF protection.")
                # FIX: Even if main page is blocked, still use sitemap/robots URLs
                if self.sitemap_urls or self.robots_urls:
                    print(f"    [CRAWLER] Using {len(self.sitemap_urls)} sitemap + {len(self.robots_urls)} robots URLs despite main page block")
                    all_urls = self.sitemap_urls + self.robots_urls
                    normalized_urls = self._normalize_and_filter_urls(all_urls, base_url, max_pages * 2)

        except Exception as e:
            print(f"    [CRAWLER] Error crawling {base_url}: {e}")
        
        # If still no URLs with parameters found, try deep crawling
        if not found_urls:
            print(f"    [CRAWLER] No parameters found, starting deep crawl...")
            # FIX: Pass discovered URLs to deep crawl so it can extract forms from them
            found_urls = self._deep_crawl(base_url, max_pages, initial_urls=normalized_urls)
        
        # ENHANCEMENT: Also include pages with forms as scan targets
        form_urls = [form.get('url', base_url) for form in self.found_forms if form.get('url')]
        for form_url in form_urls:
            if form_url not in found_urls:
                found_urls.append(form_url)

        # ENHANCEMENT: Include API endpoints as scan targets (WordPress wp-json, xmlrpc, etc.)
        api_patterns = ['wp-json', 'xmlrpc.php', '/api/', '/rest/', '/graphql']
        try:
            for url in normalized_urls:
                if any(pattern in url.lower() for pattern in api_patterns):
                    if url not in found_urls:
                        found_urls.append(url)
                        print(f"    [CRAWLER] Added API endpoint as target: {url}")
        except NameError:
            pass  # normalized_urls not defined in this code path

        # Include AJAX endpoints as targets
        for ajax_url in self.ajax_endpoints:
            if ajax_url not in found_urls:
                found_urls.append(ajax_url)

        print(f"    [CRAWLER] Found {len(found_urls)} pages with parameters")
        print(f"    [CRAWLER] Found {len(self.found_forms)} forms")
        print(f"    [CRAWLER] Found {len(self.ajax_endpoints)} AJAX endpoints")

        # Print passive detection summary
        self.print_passive_summary()

        return found_urls
    
    def _extract_js_endpoints(self, html_content: str, base_url: str):
        """Extract JavaScript and AJAX endpoints from HTML"""
        try:
            # Extract AJAX URLs from JavaScript
            ajax_patterns = PayloadLoader.load_patterns('ajax')
            if not ajax_patterns:
                print("    [CRAWLER] Warning: AJAX patterns not loaded, using fallback.")
                ajax_patterns = [
                    r'\.ajax\s*\(\s*["\']([^"\']+)["\']',
                    r'fetch\s*\(\s*["\']([^"\']+)["\']',
                    r'XMLHttpRequest.*?open\s*\(\s*["\'][^"\']*["\']\s*,\s*["\']([^"\']+)["\']',
                    r'axios\.[get|post|put|delete]+\s*\(\s*["\']([^"\']+)["\']',
                    r'url\s*:\s*["\']([^"\']+)["\']',
                    r'action\s*:\s*["\']([^"\']+)["\']'
                ]
            
            for pattern in ajax_patterns:
                matches = re.findall(pattern, html_content, re.IGNORECASE)
                for match in matches:
                    if match and not match.startswith(('javascript:', 'mailto:', '#')):
                        full_url = self._resolve_url(match, base_url)
                        if full_url and self._is_same_domain(full_url, base_url):
                            self.ajax_endpoints.append(full_url)
            
            # Extract JavaScript files for further analysis
            js_patterns = PayloadLoader.load_patterns('js_script')
            if not js_patterns:
                print("    [CRAWLER] Warning: JS script patterns not loaded, using fallback.")
                js_patterns = [
                    r'<script[^>]+src=["\']([^"\']+)["\']',
                    r'<script[^>]*>[^<]*src\s*=\s*["\']([^"\']+)["\']'
                ]
            
            for pattern in js_patterns:
                matches = re.findall(pattern, html_content, re.IGNORECASE)
                for match in matches:
                    if match and not match.startswith(('javascript:', 'data:')):
                        full_url = self._resolve_url(match, base_url)
                        if full_url and self._is_same_domain(full_url, base_url):
                            self.js_urls.append(full_url)
            
            print(f"    [CRAWLER] Found {len(self.ajax_endpoints)} AJAX endpoints")
            print(f"    [CRAWLER] Found {len(self.js_urls)} JavaScript files")
            
        except Exception as e:
            print(f"    [CRAWLER] Error extracting JS endpoints: {e}")
    
    def _extract_all_urls(self, html_content: str, base_url: str) -> List[str]:
        """Extract all URLs from HTML content with improved parsing"""
        urls = []
        
        try:
            # Use existing URL parser
            basic_urls = self.url_parser.extract_urls_from_response(html_content, base_url)
            urls.extend(basic_urls)
            
            # Extract additional URL patterns
            additional_patterns = PayloadLoader.load_patterns('url_extraction')
            if not additional_patterns:
                print("    [CRAWLER] Warning: URL extraction patterns not loaded, using fallback.")
                additional_patterns = [
                    r'href\s*=\s*["\']([^"\']+)["\']',
                    r'src\s*=\s*["\']([^"\']+)["\']',
                    r'action\s*=\s*["\']([^"\']+)["\']',
                    r'data-url\s*=\s*["\']([^"\']+)["\']',
                    r'data-href\s*=\s*["\']([^"\']+)["\']',
                    r'window\.location\s*=\s*["\']([^"\']+)["\']',
                    r'location\.href\s*=\s*["\']([^"\']+)["\']'
                ]
            
            for pattern in additional_patterns:
                matches = re.findall(pattern, html_content, re.IGNORECASE)
                for match in matches:
                    if match and not match.startswith(('javascript:', 'mailto:', '#', 'data:')):
                        full_url = self._resolve_url(match, base_url)
                        if full_url:
                            urls.append(full_url)
            
        except Exception as e:
            print(f"    [CRAWLER] Error extracting URLs: {e}")
        
        return list(set(urls))  # Remove duplicates
    
    def _normalize_and_filter_urls(self, urls: List[str], base_url: str, max_urls: int) -> List[str]:
        """Enhanced URL normalization with parameter prioritization"""
        normalized_urls = []
        seen_patterns = set()
        urls_with_params = []
        urls_without_params = []
        
        for url in urls:
            try:
                # Clean and normalize URL
                clean_url = self._clean_url(url)
                if not clean_url:
                    continue
                
                # Resolve relative URLs
                full_url = self._resolve_url(clean_url, base_url)
                if not full_url:
                    continue
                
                # Check domain
                if not self._is_same_domain(full_url, base_url):
                    continue
                
                # Skip certain file types but be less aggressive
                if self._should_skip_url(full_url):
                    continue
                
                # Prioritize URLs with parameters
                from urllib.parse import urlparse
                parsed = urlparse(full_url)
                if parsed.query:
                    urls_with_params.append(full_url)
                else:
                    urls_without_params.append(full_url)
                    
            except Exception as e:
                print(f"    [CRAWLER] Error normalizing URL {url}: {e}")
                continue
        
        # Add URLs with parameters first (higher priority)
        for url in urls_with_params:
            pattern = self._get_url_pattern(url)
            if pattern not in seen_patterns:
                seen_patterns.add(pattern)
                normalized_urls.append(url)
                if len(normalized_urls) >= max_urls:
                    break
        
        # Add URLs without parameters if we have space
        for url in urls_without_params:
            if len(normalized_urls) >= max_urls:
                break
            pattern = self._get_url_pattern(url)
            if pattern not in seen_patterns:
                seen_patterns.add(pattern)
                normalized_urls.append(url)
        
        return normalized_urls
    
    def _clean_url(self, url: str) -> str:
        """Clean and validate URL"""
        if not url:
            return ""
        
        # Remove quotes and decode
        url = url.strip('\'"').strip()
        url = unquote(url)
        
        # Remove any remaining quotes that might be part of the URL
        url = re.sub(r'^["\']|["\']$', '', url)
        
        # Fix malformed URLs like "https:/www.example.com/"
        if url.startswith('https:/') and not url.startswith('https://'):
            url = url.replace('https:/', 'https://')
        elif url.startswith('http:/') and not url.startswith('http://'):
            url = url.replace('http:/', 'http://')

        # Skip invalid URL schemes (but NOT fragment URLs)
        if any(invalid in url for invalid in ['javascript:', 'mailto:', 'tel:', 'ftp:', 'data:']):
            return ""

        # Strip URL fragments - they are client-side only, not sent to server
        # e.g., https://example.com/page#section -> https://example.com/page
        if '#' in url:
            url = url.split('#')[0]
            if not url:  # URL was just a fragment like "#section"
                return ""
        
        # Additional validation - URL should not contain quotes in the middle
        if '"' in url or "'" in url:
            return ""
        
        # URL should not end with quote characters
        if url.endswith(('"', "'")):
            return ""
        
        # Check for malformed paths with quotes
        try:
            parsed = urlparse(url)
            if parsed.path and ('"' in parsed.path or "'" in parsed.path):
                return ""
        except Exception:
            return ""
        
        return url
    
    def _resolve_url(self, url: str, base_url: str) -> str:
        """Resolve relative URLs to absolute"""
        try:
            if url.startswith(('http://', 'https://')):
                return url
            elif url.startswith('//'):
                parsed_base = urlparse(base_url)
                return f"{parsed_base.scheme}:{url}"
            elif url.startswith('/'):
                parsed_base = urlparse(base_url)
                return f"{parsed_base.scheme}://{parsed_base.netloc}{url}"
            else:
                return urljoin(base_url, url)
        except Exception:
            return ""
    
    def _should_skip_url(self, url: str) -> bool:
        """Check if URL should be skipped during crawling

        Skips:
        1. Static files (.jpg, .css, .pdf, etc.) - can't have injections
        2. Apache directory listing sort parameters - not real injection points
        3. URLs with only control parameters (C=N&O=D)

        Does NOT skip:
        - URLs with query parameters (even if static extension) - might be dynamic
        """
        from core.url_filter import is_static_file

        parsed = urlparse(url)
        path = parsed.path.lower()
        query = parsed.query.upper()

        # CRITICAL FIX: Skip Apache directory listing sorting parameters
        # These are NOT injection points, just UI controls for directory listings
        if query:
            # Apache httpd directory listing sorting (C=column, O=order)
            apache_sort_params = ['C=N', 'C=M', 'C=S', 'C=D', 'O=A', 'O=D']
            if any(param in query for param in apache_sort_params):
                # Check if it's ONLY sorting params (not mixed with real params)
                query_lower = query.lower()
                # If query only contains c=, o=, and & separators, skip it
                if all(c in 'co=nad&;ms' for c in query_lower.replace('%', '')):
                    print(f"    [CRAWLER] ✓ Skipping Apache directory listing sort: {url}")
                    return True

        # Don't skip if URL has OTHER query parameters (might be dynamic)
        # e.g., /image.jpg?id=123 might be a dynamic endpoint
        if parsed.query:
            return False

        # Use centralized static file detection
        return is_static_file(url)
    
    def _get_url_pattern(self, url: str) -> str:
        """Get URL pattern for deduplication

        Uses centralized URLFilter for consistent pattern detection.
        Replaces numeric IDs, hashes, UUIDs, and dates with placeholders.

        Examples:
            /products/123 -> /products/[NUM]
            /image/12345.jpg -> /image/[FILE].jpg
            /users/abc123def456 -> /users/[HASH]
        """
        try:
            from core.url_filter import URLFilter
            return URLFilter().get_url_pattern(url)
        except ImportError:
            # Fallback to basic pattern detection
            parsed = urlparse(url)
            path_parts = [part for part in parsed.path.split('/') if part]

            # Replace numeric IDs with placeholder
            pattern_parts = []
            for part in path_parts:
                if part.isdigit():
                    pattern_parts.append('[ID]')
                elif RE_HASH_LIKE.match(part):  # Hash-like strings
                    pattern_parts.append('[HASH]')
                else:
                    pattern_parts.append(part)

            pattern = f"{parsed.netloc}/{'/'.join(pattern_parts)}"

            # Add query parameter pattern
            if parsed.query:
                query_params = parse_qs(parsed.query)
                param_pattern = sorted(query_params.keys())
                pattern += f"?{','.join(param_pattern)}"

            return pattern
        except Exception:
            return url
    
    def _crawl_individual_pages(self, urls: List[str], base_url: str) -> List[str]:
        """Crawl individual pages to find more URLs with parameters"""
        found_urls = []
        
        for url in urls:
            if url in self.visited_urls:
                continue
                
            self.visited_urls.add(url)
            
            try:
                print(f"    [CRAWLER] Crawling individual page: {url}")

                # FIXED: Use http_client for proxy support
                response = self._make_request(url, timeout=self.config.timeout, headers=self.config.headers)
                
                if response.status_code == 200:
                    # Run passive analysis on each crawled page
                    self._run_passive_analysis(response.headers, response.text, url)

                    # Extract and store forms from this page
                    forms = self.url_parser.extract_forms(response.text)
                    for form in forms:
                        form['url'] = url  # Add source URL
                        self.found_forms.append(form)
                        print(f"    [CRAWLER] Found form: {form['method']} {form.get('action', '(same page)')} with inputs: {list(form['inputs'][:3])}")

                    # Check for directory listing on this page
                    if self._detect_directory_listing(response.text):
                        print(f"    [CRAWLER] Directory listing detected during deep crawl: {url}")

                        # Add directory listing finding
                        dir_listing_finding = {
                            'vulnerability': True,
                            'module': 'Directory Listing',
                            'type': 'Directory Listing',
                            'url': url,
                            'severity': 'Medium',
                            'confidence': 0.95,
                            'description': 'Directory listing is enabled, exposing file/directory structure',
                            'evidence': 'Directory index page detected with file/folder listings',
                            'recommendation': 'Disable directory indexing in web server configuration',
                            'cwe': 'CWE-548',
                            'owasp': 'A05:2021',
                            'cvss': '5.3'
                        }
                        self.passive_findings.append(dir_listing_finding)

                        # Extract directory listing URLs
                        dir_urls = self._extract_directory_listing_urls(response.text, url)
                        found_urls.extend(dir_urls)
                        print(f"    [CRAWLER] Extracted {len(dir_urls)} URLs from directory listing")

                    # Extract all URLs from this page
                    page_urls = self._extract_all_urls(response.text, url)
                    
                    for page_url in page_urls:
                        clean_url = self._clean_url(page_url)
                        full_url = self._resolve_url(clean_url, base_url)
                        
                        if (full_url and 
                            self._is_same_domain(full_url, base_url) and 
                            not self._should_skip_url(full_url)):
                            
                            # Check if has parameters
                            try:
                                parsed = self.url_parser.parse(full_url)
                                if parsed['query_params'] and full_url not in found_urls:
                                    found_urls.append(full_url)
                                    print(f"    [CRAWLER] Individual crawl found page with parameters: {full_url}")
                                    print(f"    [CRAWLER] Parameters: {list(parsed['query_params'].keys())}")
                            except Exception as e:
                                continue
                
            except Exception as e:
                print(f"    [CRAWLER] Error crawling individual page {url}: {e}")
                continue
        
        return found_urls
    
    def _deep_crawl(self, base_url: str, max_pages: int, initial_urls: List[str] = None) -> List[str]:
        """Perform deep crawling when no parameters found initially"""
        found_urls = []
        # FIX: Start with discovered URLs if provided, otherwise just base URL
        if initial_urls:
            crawl_queue = [base_url] + initial_urls[:max_pages]
            print(f"    [CRAWLER] Starting deep crawl with {len(crawl_queue)} initial URLs...")
        else:
            crawl_queue = [base_url]
            print(f"    [CRAWLER] Starting deep crawl...")
        crawled_count = 0
        
        while crawl_queue and crawled_count < max_pages:
            current_url = crawl_queue.pop(0)
            
            if current_url in self.visited_urls:
                continue
            
            self.visited_urls.add(current_url)
            crawled_count += 1
            
            try:
                print(f"    [CRAWLER] Deep crawling page {crawled_count}: {current_url}")

                # FIXED: Use http_client for proxy support
                response = self._make_request(current_url, timeout=self.config.timeout, headers=self.config.headers)
                
                if response.status_code == 200:
                    # Run passive analysis on deep crawled pages
                    self._run_passive_analysis(response.headers, response.text, current_url)

                    # FIX: Extract and store forms from this deep crawled page
                    forms = self.url_parser.extract_forms(response.text)
                    for form in forms:
                        form['url'] = current_url  # Add source URL
                        self.found_forms.append(form)
                        print(f"    [CRAWLER] Found form: {form['method']} {form.get('action', '(same page)')} with {len(form['inputs'])} inputs")

                    # Check for directory listing
                    if self._detect_directory_listing(response.text):
                        print(f"    [CRAWLER] Directory listing detected during deep crawl: {current_url}")
                        # Extract directory listing URLs
                        dir_urls = self._extract_directory_listing_urls(response.text, current_url)
                        found_urls.extend(dir_urls)

                    # Extract JavaScript endpoints
                    self._extract_js_endpoints(response.text, current_url)

                    # Extract all URLs
                    page_urls = self._extract_all_urls(response.text, current_url)
                    
                    for url in page_urls:
                        clean_url = self._clean_url(url)
                        full_url = self._resolve_url(clean_url, base_url)
                        
                        if (full_url and 
                            self._is_same_domain(full_url, base_url) and 
                            full_url not in self.visited_urls and
                            not self._should_skip_url(full_url)):
                            
                            # Check if has parameters
                            parsed = self.url_parser.parse(full_url)
                            if parsed['query_params']:
                                if full_url not in found_urls:
                                    found_urls.append(full_url)
                                    print(f"    [CRAWLER] Deep crawl found page with parameters: {full_url}")
                            else:
                                # Add to crawl queue for further exploration
                                if len(crawl_queue) < max_pages and full_url not in crawl_queue:
                                    crawl_queue.append(full_url)
                
            except Exception as e:
                print(f"    [CRAWLER] Error in deep crawl of {current_url}: {e}")
                continue
        
        return found_urls
    
    def _crawl_single_page(self, url: str) -> List[str]:
        """Crawl a single page for URLs"""
        try:
            # FIXED: Use http_client for proxy support
            response = self._make_request(url, timeout=self.config.timeout, headers=self.config.headers)
            
            if response.status_code == 200:
                return self._extract_all_urls(response.text, url)
        except:
            pass
        
        return []
    
    def _is_same_domain(self, url: str, base_url: str) -> bool:
        """Check if URL is from the same domain"""
        try:
            url_domain = urlparse(url).netloc.lower()
            base_domain = urlparse(base_url).netloc.lower()
            return url_domain == base_domain
        except:
            return False
    
    def get_found_forms(self) -> List[Dict[str, Any]]:
        """Get forms found during crawling"""
        return self.found_forms
    
    def _extract_sitemap_urls(self, base_url: str):
        """Extract URLs from sitemap.xml"""
        try:
            from urllib.parse import urljoin
            sitemap_paths = PayloadLoader.load_wordlist('sitemaps')
            if not sitemap_paths:
                print("    [CRAWLER] Warning: Sitemap paths not loaded, using fallback.")
                sitemap_paths = [
                    '/sitemap.xml',
                    '/sitemap_index.xml',
                    '/sitemaps.xml',
                    '/sitemap/sitemap.xml'
                ]
            
            sitemap_urls = [urljoin(base_url, path) for path in sitemap_paths]
            
            for sitemap_url in sitemap_urls:
                try:
                    # FIXED: Use http_client for proxy support
                    response = self._make_request(sitemap_url, timeout=self.config.timeout, headers=self.config.headers)
                    
                    if response.status_code == 200:
                        print(f"    [CRAWLER] Found sitemap: {sitemap_url}")
                        
                        # Extract URLs from XML
                        import re
                        url_patterns = [
                            r'<loc>(.*?)</loc>',
                            r'<url>(.*?)</url>'
                        ]
                        
                        for pattern in url_patterns:
                            matches = re.findall(pattern, response.text, re.IGNORECASE)
                            for match in matches:
                                if match.startswith('http') and self._is_same_domain(match, base_url):
                                    self.sitemap_urls.append(match)
                        
                        print(f"    [CRAWLER] Extracted {len(self.sitemap_urls)} URLs from sitemap")
                        break
                        
                except Exception as e:
                    continue
                    
        except Exception as e:
            print(f"    [CRAWLER] Error extracting sitemap URLs: {e}")
    
    def _extract_robots_urls(self, base_url: str):
        """Extract URLs from robots.txt"""
        try:
            from urllib.parse import urljoin
            robots_url = urljoin(base_url, '/robots.txt')

            # FIXED: Use http_client for proxy support
            response = self._make_request(robots_url, timeout=self.config.timeout, headers=self.config.headers)
            
            if response.status_code == 200:
                print(f"    [CRAWLER] Found robots.txt: {robots_url}")
                
                # Extract paths from robots.txt
                import re
                lines = response.text.split('\n')
                
                for line in lines:
                    line = line.strip()
                    if line.startswith('Disallow:') or line.startswith('Allow:'):
                        path = line.split(':', 1)[1].strip()
                        if path and path != '/':
                            full_url = urljoin(base_url, path)
                            if self._is_same_domain(full_url, base_url):
                                self.robots_urls.append(full_url)
                    elif line.startswith('Sitemap:'):
                        sitemap_url = line.split(':', 1)[1].strip()
                        if sitemap_url and self._is_same_domain(sitemap_url, base_url):
                            # Process additional sitemap
                            try:
                                sitemap_response = requests.get(
                                    sitemap_url,
                                    timeout=self.config.timeout,
                                    headers=self.config.headers,
                                    verify=False
                                )
                                if sitemap_response.status_code == 200:
                                    url_matches = re.findall(r'<loc>(.*?)</loc>', sitemap_response.text, re.IGNORECASE)
                                    for url_match in url_matches:
                                        if self._is_same_domain(url_match, base_url):
                                            self.sitemap_urls.append(url_match)
                            except:
                                pass
                
                print(f"    [CRAWLER] Extracted {len(self.robots_urls)} URLs from robots.txt")
                
        except Exception as e:
            print(f"    [CRAWLER] Error extracting robots URLs: {e}")
    
    def get_ajax_endpoints(self) -> List[str]:
        """Get AJAX endpoints found during crawling"""
        return self.ajax_endpoints
    
    def get_discovered_directories(self) -> Set[str]:
        """Get directories discovered during crawling"""
        return self.discovered_directories
    
    def _run_passive_analysis(self, headers: Dict[str, str], response_text: str, url: str):
        """
        Run all passive detectors on the response

        How it works:
        1. Analyzes each HTTP response during crawling
        2. Runs multiple passive detectors simultaneously
        3. Collects findings without sending additional requests
        4. Stores results for later reporting
        """
        try:
            # OPTIMIZATION: Skip if already analyzed (prevent duplicate work)
            if url in self.analyzed_urls:
                print(f"    [PASSIVE] Skipping {url} (already analyzed)")
                return

            self.analyzed_urls.add(url)
            print(f"    [PASSIVE] Running passive analysis on {url}")
            
            # WAF Detection
            has_waf, waf_findings = WAFDetector.analyze(headers, response_text, url)
            if has_waf:
                for finding in waf_findings:
                    self.detected_wafs.add(finding['waf_name'])
                print(f"    [PASSIVE] Found WAF: {', '.join(self.detected_wafs)}")

            # Security headers analysis
            has_security_issues, security_issues = SecurityHeadersDetector.analyze(headers, url)
            if has_security_issues:
                self.security_issues.extend(security_issues)
                print(f"    [PASSIVE] Found {len(security_issues)} security header issues")
            
            # Cookie security analysis
            has_cookie_issues, cookie_issues = SecurityHeadersDetector.analyze_cookies(headers, url)
            if has_cookie_issues:
                self.security_issues.extend(cookie_issues)
                print(f"    [PASSIVE] Found {len(cookie_issues)} cookie security issues")
            
            # Sensitive data detection
            has_sensitive_data, sensitive_leaks = SensitiveDataDetector.analyze(response_text, url, headers)
            if has_sensitive_data:
                self.sensitive_data_leaks.extend(sensitive_leaks)
                print(f"    [PASSIVE] Found {len(sensitive_leaks)} sensitive data leaks")
                
                # Log specific types of sensitive data found
                leak_types = set(leak.get('type', 'unknown') for leak in sensitive_leaks)
                print(f"    [PASSIVE] Leak types: {', '.join(leak_types)}")
            
            # Technology detection
            has_technologies, technologies = TechnologyDetector.analyze(headers, response_text, url)
            if has_technologies:
                self.detected_technologies.extend(technologies)
                tech_names = [tech.get('name', 'Unknown') for tech in technologies]
                print(f"    [PASSIVE] Detected technologies: {', '.join(tech_names)}")
            
            # API endpoint detection
            api_detector = APIEndpointDetector()
            api_findings = api_detector.detect(url, type('obj', (object,), {'text': response_text, 'headers': headers})(), None)
            if api_findings:
                self.passive_findings.extend(api_findings)
                print(f"    [PASSIVE] Found {len(api_findings)} API-related findings")

            # JavaScript secrets detection
            js_secrets_detector = JSSecretsDetector()
            js_secrets_findings = js_secrets_detector.detect(url, type('obj', (object,), {'text': response_text, 'headers': headers})(), None)
            if js_secrets_findings:
                self.passive_findings.extend(js_secrets_findings)
                print(f"    [PASSIVE] Found {len(js_secrets_findings)} exposed secret(s) in JavaScript!")

            # Version disclosure detection
            has_versions, version_disclosures = VersionDisclosureDetector.analyze(headers, response_text, url)
            if has_versions:
                self.version_disclosures.extend(version_disclosures)
                print(f"    [PASSIVE] Found {len(version_disclosures)} version disclosures")
            
            # Combine all findings
            all_findings = []
            all_findings.extend(waf_findings if has_waf else [])
            all_findings.extend(security_issues if has_security_issues else [])
            all_findings.extend(cookie_issues if has_cookie_issues else [])
            all_findings.extend(sensitive_leaks if has_sensitive_data else [])
            all_findings.extend(technologies if has_technologies else [])
            all_findings.extend(version_disclosures if has_versions else [])
            
            if all_findings:
                self.passive_findings.extend(all_findings)
                print(f"    [PASSIVE] Total findings for {url}: {len(all_findings)}")
            
        except Exception as e:
            print(f"    [PASSIVE] Error during passive analysis of {url}: {e}")
    
    def _analyze_javascript_files(self, base_url: str):
        """Downloads and analyzes discovered JavaScript files for endpoints and secrets."""
        if not self.js_urls:
            return
            
        print(f"    [CRAWLER] Analyzing content of {len(set(self.js_urls))} JavaScript files...")
        unique_js_urls = sorted(list(set(self.js_urls)))

        for js_url in unique_js_urls:
            if js_url in self.visited_urls:
                continue
            
            try:
                print(f"    [CRAWLER] Fetching JS file: {js_url}")
                # FIXED: Use http_client for proxy support
                response = self._make_request(js_url, timeout=self.config.timeout, headers=self.config.headers)
                self.visited_urls.add(js_url)

                if response.status_code == 200:
                    js_content = response.text
                    
                    # 1. Find new API endpoints from JS code
                    endpoint_patterns = PayloadLoader.load_patterns('js_api_endpoints')
                    if not endpoint_patterns:
                        print("    [CRAWLER] Warning: JS API endpoint patterns not loaded, using fallback.")
                        endpoint_patterns = [
                            r'["\']((?:/|/api/|/v\d+/|/rest/)[a-zA-Z0-9_./-]+)["\']'
                        ]
                    
                    # Also use AJAX patterns for more specific matching
                    ajax_patterns = PayloadLoader.load_patterns('ajax')
                    if ajax_patterns:
                        endpoint_patterns.extend(ajax_patterns)
                    
                    found_endpoints_in_file = 0
                    static_file_extensions = ['.js', '.css', '.png', '.jpg', '.jpeg', '.gif', '.svg', '.woff', '.ttf', '.eot']
                    
                    for pattern in endpoint_patterns:
                        matches = re.findall(pattern, js_content)
                        for match in matches:
                            if match and not any(match.lower().endswith(ext) for ext in static_file_extensions):
                                endpoint_url = self._resolve_url(match, base_url)
                                if self._is_same_domain(endpoint_url, base_url) and endpoint_url not in self.ajax_endpoints:
                                    self.ajax_endpoints.append(endpoint_url)
                                    found_endpoints_in_file += 1
                    
                    if found_endpoints_in_file > 0:
                        print(f"    [CRAWLER] Found {found_endpoints_in_file} new API endpoints in {js_url}")

                    # 2. Run all passive detectors on JS content to find secrets, etc.
                    self._run_passive_analysis(response.headers, js_content, js_url)

            except Exception as e:
                print(f"    [CRAWLER] Error analyzing JS file {js_url}: {e}")

    def get_passive_findings(self) -> Dict[str, List[Dict[str, Any]]]:
        """Get all passive detection findings"""
        return {
            'security_issues': self.security_issues,
            'sensitive_data_leaks': self.sensitive_data_leaks,
            'detected_technologies': self.detected_technologies,
            'version_disclosures': self.version_disclosures,
            'all_findings': self.passive_findings
        }
    
    def print_passive_summary(self):
        """Print summary of passive detection findings"""
        print(f"\n    [PASSIVE SUMMARY]")
        print(f"    Security Issues: {len(self.security_issues)}")
        print(f"    Sensitive Data Leaks: {len(self.sensitive_data_leaks)}")
        print(f"    Detected Technologies: {len(self.detected_technologies)}")
        print(f"    Version Disclosures: {len(self.version_disclosures)}")
        print(f"    Total Passive Findings: {len(self.passive_findings)}")
        
        # Print top sensitive data types found
        if self.sensitive_data_leaks:
            leak_types = {}
            for leak in self.sensitive_data_leaks:
                leak_type = leak.get('type', 'unknown')
                leak_types[leak_type] = leak_types.get(leak_type, 0) + 1
            
            print(f"    Top Sensitive Data Types:")
            for leak_type, count in sorted(leak_types.items(), key=lambda x: x[1], reverse=True)[:5]:
                print(f"      {leak_type}: {count}")
        
        # Print detected technologies
        if self.detected_technologies:
            tech_names = set(tech.get('name', 'Unknown') for tech in self.detected_technologies)
            print(f"    Detected Technologies: {', '.join(list(tech_names)[:10])}")
    
    def _detect_directory_listing(self, response_text: str) -> bool:
        """Detect if response contains directory listing (ENHANCED)"""
        response_lower = response_text.lower()

        # Enhanced directory listing indicators
        directory_indicators = PayloadLoader.load_indicators('directory_listing')
        if not directory_indicators:
            print("    [CRAWLER] Warning: Directory listing indicators not loaded, using fallback.")
            directory_indicators = [
                # Apache directory listing
                'index of /',
                '<title>index of',
                '<h1>index of',
                'parent directory',
                '[to parent directory]',
                '<pre><a href="../">../</a>',
                '<a href="?c=n;o=d">name</a>',
                '<a href="?c=m;o=a">last modified</a>',
                '<a href="?c=s;o=a">size</a>',
                '<a href="?c=d;o=a">description</a>',
                'folder.gif',
                'dir.gif',

                # Nginx directory listing
                'directory listing for',
                '<h1>directory listing',

                # IIS directory listing
                '<title>localhost - /',
                'directory listing -- /',
                '[dir]',
                '[   ]',

                # Generic patterns
                'last modified',
                'size</th>',
                'name</th>',
                '<th>name</th>',
                '<th>last modified</th>',
                '<th>size</th>',
                '<th>description</th>',

                # More Apache patterns
                'apache/ server at',
                'apache server at',
                'indexing policy',

                # Table-based listings
                '<table summary="directory listing">',
                '<caption>directory listing for',

                # More Nginx patterns
                'autoindex on',

                # Additional patterns
                '<a href="../">parent directory</a>',
                'href="../">..</a>',
                '<a href="/">[to parent directory]</a>'
            ]

        # Check for multiple indicators to reduce false positives
        indicators_found = sum(1 for indicator in directory_indicators
                             if indicator in response_lower)

        # Enhanced structural checks
        has_parent_dir = (
            '../' in response_text or
            '[to parent directory]' in response_lower or
            'parent directory' in response_lower
        )

        # Count file/directory links (excluding sorting/navigation)
        link_pattern = r'<a href="(?!\\?[cso]=)[^"]*">[^<]+</a>'
        file_links = [m for m in re.finditer(link_pattern, response_text)]
        has_file_links = len(file_links) > 3

        # Check for size column indicators
        has_size_column = (
            ('size' in response_lower and ('kb' in response_lower or
                                           'mb' in response_lower or
                                           'bytes' in response_lower or
                                           '<th>size</th>' in response_lower))
        )

        # Check for date/time column (common in directory listings)
        has_datetime = bool(re.search(r'\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}', response_text))

        # Check for table structure with Name/Size/Modified columns
        has_table_structure = bool(re.search(
            r'<th[^>]*>(name|filename|file)',
            response_text,
            re.IGNORECASE
        ))

        # Enhanced detection logic with multiple criteria
        # Require 2+ indicators OR strong structural evidence
        structural_evidence = sum([
            has_parent_dir,
            has_file_links,
            has_size_column,
            has_datetime,
            has_table_structure
        ])

        # Directory listing detected if:
        # 1. Multiple text indicators (2+), OR
        # 2. Strong structural evidence (3+ structural indicators), OR
        # 3. Parent directory link + file links + (size OR datetime)
        return (
            indicators_found >= 2 or
            structural_evidence >= 3 or
            (has_parent_dir and has_file_links and (has_size_column or has_datetime))
        )
    
    def _extract_directory_listing_urls(self, response_text: str, base_url: str) -> List[str]:
        """Extract URLs from directory listing, filtering out sorting parameters"""
        urls = []
        
        try:
            # Extract all href links
            href_pattern = r'<a href="([^"]+)"[^>]*>([^<]+)</a>'
            matches = re.findall(href_pattern, response_text, re.IGNORECASE)
            
            for href, link_text in matches:
                # Skip parent directory links
                if href in ['../', '../', '..']:
                    continue
                
                # Skip ALL sorting and directory listing control parameters
                if href.startswith('?'):
                    # Check for directory listing sorting parameters
                    if any(param in href.upper() for param in ['C=', 'O=', 'SORT=', 'ORDER=']):
                        print(f"    [CRAWLER] Skipping directory listing control parameter: {href}")
                        continue
                
                # Skip empty or invalid links
                if not href or href == '#':
                    continue
                
                # Resolve to full URL
                full_url = self._resolve_url(href, base_url)
                if full_url and self._is_same_domain(full_url, base_url):
                    urls.append(full_url)
                    print(f"    [CRAWLER] Directory listing URL found: {full_url}")
        
        except Exception as e:
            print(f"    [CRAWLER] Error extracting directory listing URLs: {e}")
        
        return urls
