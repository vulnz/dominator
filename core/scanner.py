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
from payloads import XSSPayloads, SQLiPayloads, LFIPayloads, CSRFPayloads
from detectors import XSSDetector, SQLiDetector, LFIDetector, CSRFDetector

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
        self.scan_stats = {
            'total_requests': 0,
            'total_urls': 0,
            'total_params': 0,
            'scan_duration': '0s',
            'start_time': None,
            'end_time': None
        }
        
    def scan(self) -> List[Dict[str, Any]]:
        """Main scanning method"""
        import time
        self.scan_stats['start_time'] = time.time()
        
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
        
        # Calculate scan duration
        self.scan_stats['end_time'] = time.time()
        duration = self.scan_stats['end_time'] - self.scan_stats['start_time']
        self.scan_stats['scan_duration'] = f"{duration:.1f}s"
        self.scan_stats['total_requests'] = self.request_count
        
        # Add scan stats to results
        if self.results:
            for result in self.results:
                result['scan_stats'] = self.scan_stats
        else:
            # Create empty result with stats for reporting
            self.results = [{'scan_stats': self.scan_stats}]
        
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
            
            # Update stats
            self.scan_stats['total_urls'] += 1
            self.scan_stats['total_params'] += len(parsed_data['query_params'])
            
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
                        
                        # Update stats
                        self.scan_stats['total_urls'] += 1
                        self.scan_stats['total_params'] += len(crawled_data['query_params'])
                        
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
            elif module_name == "csrf":
                results.extend(self._test_csrf(parsed_data))
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
                        response_snippet = XSSDetector.get_response_snippet(payload, response.text)
                        print(f"    [XSS] VULNERABILITY FOUND! Parameter: {param}")
                        
                        results.append({
                            'module': 'xss',
                            'target': base_url,
                            'vulnerability': 'Reflected XSS',
                            'severity': 'Medium',
                            'parameter': param,
                            'payload': payload,
                            'evidence': evidence,
                            'request_url': test_url,
                            'detector': 'XSSDetector.detect_reflected_xss',
                            'response_snippet': response_snippet
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
                        response_snippet = SQLiDetector.get_response_snippet(pattern, response.text)
                        print(f"    [SQLI] VULNERABILITY FOUND! Parameter: {param}")
                        
                        results.append({
                            'module': 'sqli',
                            'target': base_url,
                            'vulnerability': 'SQL Injection',
                            'severity': 'High',
                            'parameter': param,
                            'payload': payload,
                            'evidence': evidence,
                            'request_url': test_url,
                            'detector': 'SQLiDetector.detect_error_based_sqli',
                            'response_snippet': response_snippet
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
                        response_snippet = LFIDetector.get_response_snippet(pattern, response.text)
                        print(f"    [LFI] VULNERABILITY FOUND! Parameter: {param}")
                        
                        results.append({
                            'module': 'lfi',
                            'target': base_url,
                            'vulnerability': 'Local File Inclusion',
                            'severity': 'High',
                            'parameter': param,
                            'payload': payload,
                            'evidence': evidence,
                            'request_url': test_url,
                            'detector': 'LFIDetector.detect_lfi',
                            'response_snippet': response_snippet
                        })
                        break  # Found LFI, no need to test more payloads for this param
                            
                except Exception as e:
                    print(f"    [LFI] Error testing payload: {e}")
                    continue
        
        return results


    def _test_csrf(self, parsed_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Test for CSRF vulnerabilities"""
        results = []
        base_url = parsed_data['url']
        
        try:
            print(f"    [CSRF] Testing CSRF protection...")
            
            # First, get the initial page to analyze forms and CSRF protection
            response = requests.get(
                base_url,
                timeout=self.config.timeout,
                headers=self.config.headers,
                verify=False
            )
            
            print(f"    [CSRF] Initial response code: {response.status_code}")
            
            # Check for CSRF protection on the page
            is_vulnerable, evidence = CSRFDetector.detect_csrf_vulnerability(
                response.text, 
                dict(response.headers)
            )
            
            if is_vulnerable:
                response_snippet = CSRFDetector.get_response_snippet(response.text)
                print(f"    [CSRF] VULNERABILITY FOUND! Missing CSRF protection")
                
                results.append({
                    'module': 'csrf',
                    'target': base_url,
                    'vulnerability': 'Missing CSRF Protection',
                    'severity': 'Medium',
                    'parameter': 'N/A',
                    'payload': 'N/A',
                    'evidence': evidence,
                    'request_url': base_url,
                    'detector': 'CSRFDetector.detect_csrf_vulnerability',
                    'response_snippet': response_snippet
                })
            else:
                print(f"    [CSRF] CSRF protection appears to be implemented")
            
            # Test CSRF bypass techniques if we have forms
            csrf_payloads = CSRFPayloads.get_all_payloads()
            
            # Look for forms in the response
            import re
            form_pattern = r'<form[^>]*action=["\']?([^"\'>\s]+)["\']?[^>]*>'
            forms = re.findall(form_pattern, response.text, re.IGNORECASE)
            
            if forms:
                print(f"    [CSRF] Found {len(forms)} form(s) to test")
                
                for i, form_action in enumerate(forms[:3]):  # Test max 3 forms
                    # Resolve relative URLs
                    if form_action.startswith('/'):
                        form_url = f"{parsed_data['scheme']}://{parsed_data['host']}{form_action}"
                    elif form_action.startswith('http'):
                        form_url = form_action
                    else:
                        form_url = f"{base_url.rstrip('/')}/{form_action}"
                    
                    print(f"    [CSRF] Testing form {i+1}: {form_url}")
                    
                    # Test a few bypass payloads
                    for payload in csrf_payloads[:5]:  # Test first 5 payloads
                        try:
                            print(f"    [CSRF] Trying payload: {payload['name']}")
                            
                            # Prepare request data
                            request_data = payload.get('data', {})
                            request_headers = self.config.headers.copy()
                            
                            # Add payload-specific headers
                            if 'headers' in payload:
                                request_headers.update(payload['headers'])
                            
                            # Make the request based on method
                            method = payload.get('method', 'POST').upper()
                            
                            if method == 'POST':
                                test_response = requests.post(
                                    form_url,
                                    data=request_data,
                                    headers=request_headers,
                                    timeout=self.config.timeout,
                                    verify=False,
                                    allow_redirects=False
                                )
                            elif method == 'PUT':
                                test_response = requests.put(
                                    form_url,
                                    data=request_data,
                                    headers=request_headers,
                                    timeout=self.config.timeout,
                                    verify=False,
                                    allow_redirects=False
                                )
                            elif method == 'DELETE':
                                test_response = requests.delete(
                                    form_url,
                                    data=request_data,
                                    headers=request_headers,
                                    timeout=self.config.timeout,
                                    verify=False,
                                    allow_redirects=False
                                )
                            else:
                                continue
                            
                            print(f"    [CSRF] Response code: {test_response.status_code}")
                            
                            # Check if request was successful (potential CSRF bypass)
                            if test_response.status_code in [200, 201, 202, 302, 303]:
                                # Check if the response indicates success
                                success_indicators = [
                                    'success', 'updated', 'created', 'deleted', 
                                    'saved', 'submitted', 'processed'
                                ]
                                
                                response_lower = test_response.text.lower()
                                if any(indicator in response_lower for indicator in success_indicators):
                                    print(f"    [CSRF] POTENTIAL BYPASS FOUND! Payload: {payload['name']}")
                                    
                                    results.append({
                                        'module': 'csrf',
                                        'target': form_url,
                                        'vulnerability': 'CSRF Protection Bypass',
                                        'severity': 'High',
                                        'parameter': 'form_action',
                                        'payload': str(request_data),
                                        'evidence': f"Request succeeded with {payload['description']}. Response code: {test_response.status_code}",
                                        'request_url': form_url,
                                        'detector': 'CSRFDetector.bypass_test',
                                        'response_snippet': test_response.text[:500]
                                    })
                                    break  # Found bypass, no need to test more payloads for this form
                            
                        except Exception as e:
                            print(f"    [CSRF] Error testing payload {payload['name']}: {e}")
                            continue
            else:
                print(f"    [CSRF] No forms found to test")
                
        except Exception as e:
            print(f"    [CSRF] Error during CSRF testing: {e}")
        
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
        print("\n" + "="*80)
        print("SCAN RESULTS SUMMARY".center(80))
        print("="*80)
        
        # Print scan statistics
        stats = self.scan_stats
        print(f"Scan Duration:        {stats['scan_duration']}")
        print(f"Total Requests:       {stats['total_requests']}")
        print(f"URLs Discovered:      {stats['total_urls']}")
        print(f"Parameters Tested:    {stats['total_params']}")
        print(f"Modules Used:         {', '.join(self.config.modules)}")
        print(f"Threads:              {self.config.threads}")
        print("-" * 80)
        
        if not results:
            print("VULNERABILITY STATUS: CLEAN")
            print("No vulnerabilities found during the scan.")
            print("="*80)
            return
        
        # Group by severity
        high_vulns = [v for v in results if v.get('severity', '').lower() == 'high']
        medium_vulns = [v for v in results if v.get('severity', '').lower() == 'medium']
        low_vulns = [v for v in results if v.get('severity', '').lower() == 'low']
        
        print(f"VULNERABILITY STATUS: {len(results)} ISSUES FOUND")
        print(f"High Severity:        {len(high_vulns)}")
        print(f"Medium Severity:      {len(medium_vulns)}")
        print(f"Low Severity:         {len(low_vulns)}")
        print("="*80)
        
        if high_vulns:
            print(f"\nHIGH SEVERITY VULNERABILITIES ({len(high_vulns)} found):")
            print("-" * 50)
            for i, result in enumerate(high_vulns, 1):
                self._print_vulnerability(i, result)
        
        if medium_vulns:
            print(f"\nMEDIUM SEVERITY VULNERABILITIES ({len(medium_vulns)} found):")
            print("-" * 50)
            for i, result in enumerate(medium_vulns, 1):
                self._print_vulnerability(i, result)
        
        if low_vulns:
            print(f"\nLOW SEVERITY VULNERABILITIES ({len(low_vulns)} found):")
            print("-" * 50)
            for i, result in enumerate(low_vulns, 1):
                self._print_vulnerability(i, result)
        
        print("="*80)
        print("RECOMMENDATION: Review and remediate all vulnerabilities above.")
        print("="*80)
    
    def _print_vulnerability(self, index: int, result: Dict[str, Any]):
        """Print single vulnerability details"""
        print(f"\n  {index}. {result.get('vulnerability', 'Unknown')}")
        print(f"     Target: {result.get('target', '')}")
        print(f"     Parameter: {result.get('parameter', '')}")
        print(f"     Module: {result.get('module', '')}")
        print(f"     Detector: {result.get('detector', 'Unknown')}")
        print(f"     Payload: {result.get('payload', '')[:100]}{'...' if len(str(result.get('payload', ''))) > 100 else ''}")
        print(f"     Request: {result.get('request_url', '')}")
        
        # Show response snippet if available
        response_snippet = result.get('response_snippet', '')
        if response_snippet:
            print(f"     Response: ...{response_snippet[:80]}{'...' if len(response_snippet) > 80 else ''}")
        
        print(f"     Evidence: {result.get('evidence', '')}")
        print("     " + "-"*50)
