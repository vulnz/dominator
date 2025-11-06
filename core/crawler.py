"""
Web crawler module for finding pages and parameters
"""

import requests
import urllib3
from typing import List, Dict, Any
from urllib.parse import urljoin, urlparse
from core.url_parser import URLParser

# Disable SSL warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class WebCrawler:
    """Web crawler for finding pages with parameters"""
    
    def __init__(self, config):
        """Initialize crawler"""
        self.config = config
        self.url_parser = URLParser()
        self.visited_urls = set()
        
    def crawl_for_pages(self, base_url: str, max_pages: int = 20) -> List[str]:
        """Crawl website to find pages with parameters"""
        found_urls = []
        
        try:
            print(f"    [CRAWLER] Starting crawl of {base_url}")
            response = requests.get(
                base_url,
                timeout=self.config.timeout,
                headers=self.config.headers,
                verify=False
            )
            
            if response.status_code == 200:
                print(f"    [CRAWLER] Successfully connected to {base_url}")
                # Extract URLs from response
                urls = self.url_parser.extract_urls_from_response(response.text, base_url)
                print(f"    [CRAWLER] Found {len(urls)} URLs to analyze")
                
                # Filter URLs with parameters and same domain
                print(f"    [CRAWLER] Analyzing URLs for parameters...")
                for i, url in enumerate(urls[:max_pages]):
                    try:
                        print(f"    [CRAWLER] Checking URL {i+1}/{min(len(urls), max_pages)}: {url}")
                        
                        # Skip non-HTTP URLs and fragments
                        if not url.startswith(('http://', 'https://')):
                            print(f"    [CRAWLER] Skipping non-HTTP URL: {url}")
                            continue
                            
                        # Check if same domain
                        if not self._is_same_domain(url, base_url):
                            print(f"    [CRAWLER] Skipping different domain: {url}")
                            continue
                        
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
                        
            else:
                print(f"    [CRAWLER] HTTP {response.status_code} response from {base_url}")
                
        except Exception as e:
            print(f"    [CRAWLER] Error crawling {base_url}: {e}")
        
        # If no URLs with parameters found, try to crawl deeper
        if not found_urls and len(urls) > 0:
            print(f"    [CRAWLER] No parameters found, trying to crawl individual pages...")
            for url in urls[:5]:  # Try first 5 pages
                try:
                    if self._is_same_domain(url, base_url):
                        print(f"    [CRAWLER] Crawling page: {url}")
                        sub_urls = self._crawl_single_page(url)
                        for sub_url in sub_urls:
                            parsed = self.url_parser.parse(sub_url)
                            if parsed['query_params'] and sub_url not in found_urls:
                                found_urls.append(sub_url)
                                print(f"    [CRAWLER] Found page with parameters: {sub_url}")
                                print(f"    [CRAWLER] Parameters: {list(parsed['query_params'].keys())}")
                except Exception as e:
                    print(f"    [CRAWLER] Error crawling page {url}: {e}")
                    continue
        
        print(f"    [CRAWLER] Found {len(found_urls)} pages with parameters")
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
                return self.url_parser.extract_urls_from_response(response.text, url)
        except:
            pass
        
        return []
    
    def _is_same_domain(self, url: str, base_url: str) -> bool:
        """Check if URL is from the same domain"""
        try:
            url_domain = urlparse(url).netloc
            base_domain = urlparse(base_url).netloc
            return url_domain == base_domain
        except:
            return False
