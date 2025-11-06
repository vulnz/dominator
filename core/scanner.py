"""
Main vulnerability scanner class
"""

import time
import json
import requests
import urllib3
from typing import List, Dict, Any
from concurrent.futures import ThreadPoolExecutor, as_completed

from core.config import Config
from core.url_parser import URLParser
from core.crawler import WebCrawler
from utils.file_handler import FileHandler
from payloads import XSSPayloads, SQLiPayloads, LFIPayloads
from detectors import XSSDetector, SQLiDetector, LFIDetector

# Disable SSL warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class VulnScanner:
    """Main vulnerability scanner class"""
    
    def __init__(self, config: Config):
        """Initialize scanner"""
        self.config = config
        self.url_parser = URLParser()
        self.crawler = WebCrawler(config)
        self.file_handler = FileHandler()
        self.results = []
        self.request_count = 0
        
    def scan(self) -> List[Dict[str, Any]]:
        """Main scanning method"""
        targets = self.config.get_targets()
        
        if not targets:
            raise ValueError("No targets found for scanning")
        
        print(f"Targets found: {len(targets)}")
        print(f"Modules: {', '.join(self.config.modules)}")
        print(f"Threads: {self.config.threads}")
        print("-" * 50)
        
        # Multi-threaded scanning
        with ThreadPoolExecutor(max_workers=self.config.threads) as executor:
            futures = []
            
            for target in targets:
                if self._should_stop():
                    break
                    
                future = executor.submit(self._scan_target, target)
                futures.append(future)
            
            # Collect results
            for future in as_completed(futures):
                try:
                    result = future.result()
                    if result:
                        self.results.extend(result)
                except Exception as e:
                    print(f"Scanning error: {e}")
        
        return self.results
    
    def _scan_target(self, target: str) -> List[Dict[str, Any]]:
        """Scan single target"""
        target_results = []
        
        try:
            print(f"Scanning: {target}")
            
            # Parse URL and extract injection points
            parsed_data = self.url_parser.parse(target)
            
            # Test connectivity first
            if not self._test_connectivity(parsed_data['url']):
                print(f"  Cannot connect to {target}")
                return target_results
            
            # Debug: Show detected URL and parameters
            print(f"  [DEBUG] Parsed URL: {parsed_data['url']}")
            print(f"  [DEBUG] Host: {parsed_data['host']}")
            print(f"  [DEBUG] Path: {parsed_data['path']}")
            print(f"  [DEBUG] Query parameters: {list(parsed_data['query_params'].keys())}")
            
            # If no parameters in URL, try to find pages with parameters
            if not parsed_data['query_params']:
                print(f"  [DEBUG] No parameters found, starting crawler...")
                crawled_urls = self.crawler.crawl_for_pages(parsed_data['url'])
                
                if not crawled_urls:
                    print(f"  [DEBUG] No pages with parameters found by crawler")
                
                for url in crawled_urls:
                    crawled_data = self.url_parser.parse(url)
                    if crawled_data['query_params']:
                        print(f"  [DEBUG] Testing page: {url}")
                        print(f"  [DEBUG] Parameters to test: {list(crawled_data['query_params'].keys())}")
                        for module_name in self.config.modules:
                            if self._should_stop():
                                break
                            module_results = self._run_module(module_name, crawled_data)
                            target_results.extend(module_results)
            else:
                # Scan with each module
                print(f"  [DEBUG] Testing parameters: {list(parsed_data['query_params'].keys())}")
                for module_name in self.config.modules:
                    if self._should_stop():
                        break
                        
                    module_results = self._run_module(module_name, parsed_data)
                    target_results.extend(module_results)
            
        except Exception as e:
            print(f"Error scanning {target}: {e}")
        
        return target_results
    
    def _run_module(self, module_name: str, parsed_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Run scanning module"""
        results = []
        
        try:
            print(f"  [MODULE] {module_name.upper()}: Starting scan...")
            print(f"  [MODULE] {module_name.upper()}: Target URL: {parsed_data['url']}")
            
            # Perform actual HTTP requests and testing
            vulnerabilities = self._test_module(module_name, parsed_data)
            results.extend(vulnerabilities)
            
            if vulnerabilities:
                print(f"  [MODULE] {module_name.upper()}: Found {len(vulnerabilities)} vulnerabilities")
            else:
                print(f"  [MODULE] {module_name.upper()}: No vulnerabilities found")
            
        except Exception as e:
            print(f"  [MODULE] {module_name.upper()}: Error - {e}")
        
        return results
    
    def _test_connectivity(self, url: str) -> bool:
        """Test if target is reachable"""
        try:
            response = requests.get(
                url, 
                timeout=self.config.timeout,
                headers=self.config.headers,
                allow_redirects=True,
                verify=False
            )
            return response.status_code < 500
        except:
            return False
    
    def _test_module(self, module_name: str, parsed_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Test specific vulnerability module"""
        results = []
        self.request_count += 1
        
        try:
            if module_name == "xss":
                results.extend(self._test_xss(parsed_data))
            elif module_name == "sqli":
                results.extend(self._test_sqli(parsed_data))
            elif module_name == "lfi":
                results.extend(self._test_lfi(parsed_data))
            # Add more modules as needed
                
        except Exception as e:
            print(f"    Error testing {module_name}: {e}")
        
        return results
    
    def _test_xss(self, parsed_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Test for XSS vulnerabilities"""
        results = []
        base_url = parsed_data['url']
        
        # Get XSS payloads
        xss_payloads = XSSPayloads.get_all_payloads()
        
        # Test GET parameters
        for param, values in parsed_data['query_params'].items():
            print(f"    [XSS] Testing parameter: {param}")
            
            for payload in xss_payloads:
                try:
                    print(f"    [XSS] Trying payload: {payload[:50]}...")
                    
                    # Create test URL
                    test_params = parsed_data['query_params'].copy()
                    test_params[param] = [payload]
                    
                    # Build query string
                    query_parts = []
                    for k, v_list in test_params.items():
                        for v in v_list:
                            query_parts.append(f"{k}={v}")
                    
                    test_url = f"{base_url.split('?')[0]}?{'&'.join(query_parts)}"
                    print(f"    [XSS] Request URL: {test_url}")
                    
                    response = requests.get(
                        test_url,
                        timeout=self.config.timeout,
                        headers=self.config.headers,
                        verify=False
                    )
                    
                    print(f"    [XSS] Response code: {response.status_code}")
                    
                    # Use XSS detector
                    if XSSDetector.detect_reflected_xss(payload, response.text, response.status_code):
                        evidence = XSSDetector.get_evidence(payload, response.text)
                        print(f"    [XSS] VULNERABILITY FOUND! Parameter: {param}")
                        
                        results.append({
                            'module': 'xss',
                            'target': base_url,
                            'vulnerability': 'Reflected XSS',
                            'severity': 'Medium',
                            'parameter': param,
                            'payload': payload,
                            'evidence': evidence,
                            'request_url': test_url
                        })
                        break  # Found XSS, no need to test more payloads for this param
                        
                except Exception as e:
                    print(f"    [XSS] Error testing payload: {e}")
                    continue
        
        return results
    
    def _test_sqli(self, parsed_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Test for SQL injection vulnerabilities"""
        results = []
        base_url = parsed_data['url']
        
        # Get SQL injection payloads
        sqli_payloads = SQLiPayloads.get_all_payloads()
        
        # Test GET parameters
        for param, values in parsed_data['query_params'].items():
            print(f"    [SQLI] Testing parameter: {param}")
            
            for payload in sqli_payloads:
                try:
                    print(f"    [SQLI] Trying payload: {payload[:50]}...")
                    
                    # Create test URL
                    test_params = parsed_data['query_params'].copy()
                    test_params[param] = [payload]
                    
                    # Build query string
                    query_parts = []
                    for k, v_list in test_params.items():
                        for v in v_list:
                            query_parts.append(f"{k}={v}")
                    
                    test_url = f"{base_url.split('?')[0]}?{'&'.join(query_parts)}"
                    print(f"    [SQLI] Request URL: {test_url}")
                    
                    response = requests.get(
                        test_url,
                        timeout=self.config.timeout,
                        headers=self.config.headers,
                        verify=False
                    )
                    
                    print(f"    [SQLI] Response code: {response.status_code}")
                    
                    # Use SQLi detector
                    is_vulnerable, pattern = SQLiDetector.detect_error_based_sqli(response.text, response.status_code)
                    
                    if is_vulnerable:
                        evidence = SQLiDetector.get_evidence(pattern)
                        print(f"    [SQLI] VULNERABILITY FOUND! Parameter: {param}")
                        
                        results.append({
                            'module': 'sqli',
                            'target': base_url,
                            'vulnerability': 'SQL Injection',
                            'severity': 'High',
                            'parameter': param,
                            'payload': payload,
                            'evidence': evidence,
                            'request_url': test_url
                        })
                        break  # Found SQLi, no need to test more payloads for this param
                            
                except Exception as e:
                    print(f"    [SQLI] Error testing payload: {e}")
                    continue
        
        return results
    
    def _test_lfi(self, parsed_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Test for Local File Inclusion vulnerabilities"""
        results = []
        base_url = parsed_data['url']
        
        # Get LFI payloads
        lfi_payloads = LFIPayloads.get_all_payloads()
        
        # Test GET parameters
        for param, values in parsed_data['query_params'].items():
            print(f"    [LFI] Testing parameter: {param}")
            
            for payload in lfi_payloads:
                try:
                    print(f"    [LFI] Trying payload: {payload[:50]}...")
                    
                    # Create test URL
                    test_params = parsed_data['query_params'].copy()
                    test_params[param] = [payload]
                    
                    # Build query string
                    query_parts = []
                    for k, v_list in test_params.items():
                        for v in v_list:
                            query_parts.append(f"{k}={v}")
                    
                    test_url = f"{base_url.split('?')[0]}?{'&'.join(query_parts)}"
                    print(f"    [LFI] Request URL: {test_url}")
                    
                    response = requests.get(
                        test_url,
                        timeout=self.config.timeout,
                        headers=self.config.headers,
                        verify=False
                    )
                    
                    print(f"    [LFI] Response code: {response.status_code}")
                    
                    # Use LFI detector
                    is_vulnerable, pattern = LFIDetector.detect_lfi(response.text, response.status_code)
                    
                    if is_vulnerable:
                        evidence = LFIDetector.get_evidence(pattern)
                        print(f"    [LFI] VULNERABILITY FOUND! Parameter: {param}")
                        
                        results.append({
                            'module': 'lfi',
                            'target': base_url,
                            'vulnerability': 'Local File Inclusion',
                            'severity': 'High',
                            'parameter': param,
                            'payload': payload,
                            'evidence': evidence,
                            'request_url': test_url
                        })
                        break  # Found LFI, no need to test more payloads for this param
                            
                except Exception as e:
                    print(f"    [LFI] Error testing payload: {e}")
                    continue
        
        return results


    def _should_stop(self) -> bool:
        """Check scan stop conditions"""
        if self.config.request_limit and self.request_count >= self.config.request_limit:
            return True
        return False
    
    def save_report(self, results: List[Dict[str, Any]], filename: str, format_type: str):
        """Save report"""
        if format_type == 'json':
            self.file_handler.save_json(results, filename)
        elif format_type == 'xml':
            self.file_handler.save_xml(results, filename)
        elif format_type == 'html':
            self.file_handler.save_html(results, filename)
        else:
            self.file_handler.save_txt(results, filename)
    
    def print_results(self, results: List[Dict[str, Any]]):
        """Print results to console"""
        if not results:
            print("No vulnerabilities found")
            return
        
        print(f"\nVulnerabilities found: {len(results)}")
        print("=" * 60)
        
        for i, result in enumerate(results, 1):
            print(f"{i}. {result.get('vulnerability', 'Unknown')}")
            print(f"   Target: {result.get('target', '')}")
            print(f"   Module: {result.get('module', '')}")
            print(f"   Severity: {result.get('severity', '')}")
            print(f"   Parameter: {result.get('parameter', '')}")
            print("-" * 40)
