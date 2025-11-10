"""
Web crawler module for finding pages and parameters
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

# Disable SSL warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class WebCrawler:
    """Web crawler for finding pages with parameters"""
    
    def __init__(self, config):
        """Initialize crawler"""
        self.config = config
        self.url_parser = URLParser()
        self.visited_urls: Set[str] = set()
        self.found_forms: List[Dict[str, Any]] = []
        self.ajax_endpoints: List[str] = []
        self.js_urls: List[str] = []
        self.sitemap_urls: List[str] = []
        self.robots_urls: List[str] = []
        self.discovered_directories: Set[str] = set()
        
        # Passive detection results
        self.passive_findings: List[Dict[str, Any]] = []
        self.security_issues: List[Dict[str, Any]] = []
        self.sensitive_data_leaks: List[Dict[str, Any]] = []
        self.detected_technologies: List[Dict[str, Any]] = []
        self.version_disclosures: List[Dict[str, Any]] = []
        
    def crawl_for_pages(self, base_url: str, max_pages: int = 50) -> List[str]:
        """Crawl website to find pages with parameters"""
        found_urls = []
        
        try:
            print(f"    [CRAWLER] Starting crawl of {base_url} (max_pages: {max_pages})")
            
            # First, get data from sitemap and robots.txt
            print(f"    [CRAWLER] Extracting URLs from sitemap and robots.txt...")
            self._extract_sitemap_urls(base_url)
            self._extract_robots_urls(base_url)
            
            response = requests.get(
                base_url,
                timeout=self.config.timeout,
                headers=self.config.headers,
                verify=False
            )
            
            if response.status_code == 200:
                print(f"    [CRAWLER] Successfully connected to {base_url}")
                    
                # Check for directory listing on main page first
                if self._detect_directory_listing(response.text):
                    print(f"    [CRAWLER] Directory listing detected on main page: {base_url}")
                    # Extract directory listing URLs
                    dir_urls = self._extract_directory_listing_urls(response.text, base_url)
                    found_urls.extend(dir_urls)
                    print(f"    [CRAWLER] Extracted {len(dir_urls)} URLs from main page directory listing")
                    
                # Run passive analysis on initial response
                self._run_passive_analysis(response.headers, response.text, base_url)
                    
                # Extract JavaScript and AJAX endpoints
                self._extract_js_endpoints(response.text, base_url)
                
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
                        print(f"    [CRAWLER] Checking URL {i+1}/{len(normalized_urls)}: {url}")
                        
                        parsed = self.url_parser.parse(url)
                        print(f"    [CRAWLER] Parsed parameters: {list(parsed['query_params'].keys())}")
                        
                        # Check if URL has parameters
                        if parsed['query_params'] and url not in found_urls:
                            found_urls.append(url)
                            print(f"    [CRAWLER] Found page with parameters: {url}")
                            print(f"    [CRAWLER] Parameters: {list(parsed['query_params'].keys())}")
                        elif not parsed['query_params']:
                            print(f"    [CRAWLER] No parameters in URL: {url}")
                            
                    except Exception as e:
                        print(f"    [CRAWLER] Error parsing URL {url}: {e}")
                        continue
                
                # Second pass - crawl individual pages to find more URLs
                print(f"    [CRAWLER] Starting second pass crawling...")
                additional_urls = self._crawl_individual_pages(normalized_urls[:30], base_url)
                found_urls.extend(additional_urls)
                        
            else:
                print(f"    [CRAWLER] HTTP {response.status_code} response from {base_url}")
                
        except Exception as e:
            print(f"    [CRAWLER] Error crawling {base_url}: {e}")
        
        # If still no URLs with parameters found, try deep crawling
        if not found_urls:
            print(f"    [CRAWLER] No parameters found, starting deep crawl...")
            found_urls = self._deep_crawl(base_url, max_pages)
        
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
        
        # Skip invalid URLs
        if any(invalid in url for invalid in ['javascript:', 'mailto:', 'tel:', 'ftp:', '#']):
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
        """Check if URL should be skipped"""
        # Only skip obvious static files, be less aggressive
        skip_extensions = PayloadLoader.load_wordlist('skip_extensions')
        if not skip_extensions:
            print("    [CRAWLER] Warning: Skip extensions not loaded, using fallback.")
            skip_extensions = [
                '.css', '.js', '.jpg', '.jpeg', '.png', '.gif', '.svg', '.ico',
                '.mp3', '.mp4', '.avi', '.mov', '.wmv', '.flv'
            ]
        
        parsed = urlparse(url)
        path = parsed.path.lower()
        
        # Don't skip if URL has query parameters (might be dynamic)
        if parsed.query:
            return False
        
        return any(path.endswith(ext) for ext in skip_extensions)
    
    def _get_url_pattern(self, url: str) -> str:
        """Get URL pattern for deduplication"""
        try:
            parsed = urlparse(url)
            # Create pattern based on path structure
            path_parts = [part for part in parsed.path.split('/') if part]
            
            # Replace numeric IDs with placeholder
            pattern_parts = []
            for part in path_parts:
                if part.isdigit():
                    pattern_parts.append('[ID]')
                elif re.match(r'^[a-f0-9]{8,}$', part):  # Hash-like strings
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
                
                response = requests.get(
                    url,
                    timeout=self.config.timeout,
                    headers=self.config.headers,
                    verify=False
                )
                
                if response.status_code == 200:
                    # Run passive analysis on each crawled page
                    self._run_passive_analysis(response.headers, response.text, url)
                    
                    # Check for directory listing on this page
                    if self._detect_directory_listing(response.text):
                        print(f"    [CRAWLER] Directory listing detected on: {url}")
                        # Extract directory listing URLs
                        dir_urls = self._extract_directory_listing_urls(response.text, url)
                        found_urls.extend(dir_urls)
                    
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
    
    def _deep_crawl(self, base_url: str, max_pages: int) -> List[str]:
        """Perform deep crawling when no parameters found initially"""
        found_urls = []
        crawl_queue = [base_url]
        crawled_count = 0
        
        print(f"    [CRAWLER] Starting deep crawl...")
        
        while crawl_queue and crawled_count < max_pages:
            current_url = crawl_queue.pop(0)
            
            if current_url in self.visited_urls:
                continue
            
            self.visited_urls.add(current_url)
            crawled_count += 1
            
            try:
                print(f"    [CRAWLER] Deep crawling page {crawled_count}: {current_url}")
                
                response = requests.get(
                    current_url,
                    timeout=self.config.timeout,
                    headers=self.config.headers,
                    verify=False
                )
                
                if response.status_code == 200:
                    # Run passive analysis on deep crawled pages
                    self._run_passive_analysis(response.headers, response.text, current_url)
                    
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
            response = requests.get(
                url,
                timeout=self.config.timeout,
                headers=self.config.headers,
                verify=False
            )
            
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
                    response = requests.get(
                        sitemap_url,
                        timeout=self.config.timeout,
                        headers=self.config.headers,
                        verify=False
                    )
                    
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
            
            response = requests.get(
                robots_url,
                timeout=self.config.timeout,
                headers=self.config.headers,
                verify=False
            )
            
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
            print(f"    [PASSIVE] Running passive analysis on {url}")
            
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
            
            # Version disclosure detection
            has_versions, version_disclosures = VersionDisclosureDetector.analyze(headers, response_text, url)
            if has_versions:
                self.version_disclosures.extend(version_disclosures)
                print(f"    [PASSIVE] Found {len(version_disclosures)} version disclosures")
            
            # Combine all findings
            all_findings = []
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
        """Detect if response contains directory listing"""
        response_lower = response_text.lower()
        
        # Enhanced directory listing indicators
        directory_indicators = PayloadLoader.load_indicators('directory_listing')
        if not directory_indicators:
            print("    [CRAWLER] Warning: Directory listing indicators not loaded, using fallback.")
            directory_indicators = [
                'index of /',
                'directory listing',
                'parent directory',
                '<title>index of',
                'directory listing for',
                '[to parent directory]',
                'folder.gif',
                'dir.gif',
                '[dir]',
                '[   ]',
                'last modified',
                'size</th>',
                'name</th>',
                '<pre><a href="../">../</a>',
                '<a href="?c=n;o=d">name</a>',
                '<a href="?c=m;o=a">last modified</a>',
                '<a href="?c=s;o=a">size</a>',
                '<a href="?c=d;o=a">description</a>'
            ]
        
        # Check for multiple indicators to reduce false positives
        indicators_found = sum(1 for indicator in directory_indicators 
                             if indicator in response_lower)
        
        # Also check for typical directory listing structure
        has_parent_dir = '../' in response_text or '[to parent directory]' in response_lower
        has_file_links = len([m for m in re.finditer(r'<a href="[^"]*">[^<]+</a>', response_text)]) > 3
        has_size_column = 'size' in response_lower and ('kb' in response_lower or 'mb' in response_lower or 'bytes' in response_lower)
        
        # Directory listing detected if we have multiple indicators or strong structural evidence
        return indicators_found >= 2 or (has_parent_dir and has_file_links) or (has_file_links and has_size_column)
    
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
