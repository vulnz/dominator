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
                for url in urls[:max_pages]:
                    try:
                        parsed = self.url_parser.parse(url)
                        # Check if URL has parameters and is from same domain
                        if (parsed['query_params'] and 
                            url not in found_urls and 
                            self._is_same_domain(url, base_url)):
                            found_urls.append(url)
                            print(f"    [CRAWLER] Found page with parameters: {url}")
                            print(f"    [CRAWLER] Parameters: {list(parsed['query_params'].keys())}")
                    except Exception as e:
                        print(f"    [CRAWLER] Error parsing URL {url}: {e}")
                        continue
                        
            else:
                print(f"    [CRAWLER] HTTP {response.status_code} response from {base_url}")
                
        except Exception as e:
            print(f"    [CRAWLER] Error crawling {base_url}: {e}")
        
        print(f"    [CRAWLER] Found {len(found_urls)} pages with parameters")
        return found_urls
    
    def _is_same_domain(self, url: str, base_url: str) -> bool:
        """Check if URL is from the same domain"""
        try:
            url_domain = urlparse(url).netloc
            base_domain = urlparse(base_url).netloc
            return url_domain == base_domain
        except:
            return False
