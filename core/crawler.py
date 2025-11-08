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
        
    def crawl_for_pages(self, base_url: str, max_pages: int = 50) -> List[str]:
        """Crawl website to find pages with parameters"""
        found_urls = []
        
        try:
            print(f"    [CRAWLER] Starting enhanced crawl of {base_url}")
            response = requests.get(
                base_url,
                timeout=self.config.timeout,
                headers=self.config.headers,
                verify=False
            )
            
            if response.status_code == 200:
                print(f"    [CRAWLER] Successfully connected to {base_url}")
                
                # Extract JavaScript and AJAX endpoints
                self._extract_js_endpoints(response.text, base_url)
                
                # Extract URLs from response
                urls = self._extract_all_urls(response.text, base_url)
                print(f"    [CRAWLER] Found {len(urls)} URLs to analyze")
                
                # Add AJAX endpoints to URLs
                urls.extend(self.ajax_endpoints)
                
                # Filter and normalize URLs - increase limit
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
                additional_urls = self._crawl_individual_pages(normalized_urls[:20], base_url)
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
        
        return found_urls
    
    def _extract_js_endpoints(self, html_content: str, base_url: str):
        """Extract JavaScript and AJAX endpoints from HTML"""
        try:
            # Extract AJAX URLs from JavaScript
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
        skip_extensions = [
            '.css', '.js', '.jpg', '.jpeg', '.png', '.gif', '.svg', '.ico',
            '.pdf', '.zip', '.rar', '.mp3', '.mp4', '.avi', '.mov', '.wmv', '.flv'
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
    
    def get_ajax_endpoints(self) -> List[str]:
        """Get AJAX endpoints found during crawling"""
        return self.ajax_endpoints
