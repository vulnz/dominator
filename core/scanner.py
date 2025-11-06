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
from payloads import XSSPayloads, SQLiPayloads, LFIPayloads, CSRFPayloads, DirBrutePayloads
from detectors import XSSDetector, SQLiDetector, LFIDetector, CSRFDetector, DirBruteDetector, Real404Detector

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
        self.found_vulnerabilities = set()  # For deduplication
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
                
                # For CSRF testing, also test pages without parameters (they might have forms)
                if 'csrf' in self.config.modules:
                    print(f"  [DEBUG] Testing main page for CSRF (no parameters needed)")
                    csrf_results = self._run_module('csrf', parsed_data)
                    target_results.extend(csrf_results)
                
                if not crawled_urls:
                    print(f"  [DEBUG] No pages with parameters found by crawler")
                
                # Test important pages that might have forms
                important_pages = self._get_important_pages()
                
                if 'csrf' in self.config.modules:
                    for page in important_pages:
                        test_url = f"{parsed_data['scheme']}://{parsed_data['host']}{page}"
                        try:
                            test_response = requests.get(test_url, timeout=5, verify=False)
                            if test_response.status_code == 200:
                                print(f"  [DEBUG] Testing important page for CSRF: {test_url}")
                                page_data = self.url_parser.parse(test_url)
                                csrf_results = self._run_module('csrf', page_data)
                                target_results.extend(csrf_results)
                        except:
                            continue
                
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
                    elif 'csrf' in self.config.modules:
                        # Test pages without parameters for CSRF (they might have forms)
                        print(f"  [DEBUG] Testing page for CSRF: {url}")
                        csrf_results = self._run_module('csrf', crawled_data)
                        target_results.extend(csrf_results)
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
            elif module_name == "dirbrute":
                results.extend(self._test_dirbrute(parsed_data))
            # Add more modules as needed
                
        except Exception as e:
            print(f"    Error testing {module_name}: {e}")
        
        return results
    
    def _test_xss(self, parsed_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Test for XSS vulnerabilities with enhanced validation"""
        results = []
        base_url = parsed_data['url']
        
        # Get XSS payloads
        xss_payloads = XSSPayloads.get_all_payloads()
        
        # Test GET parameters
        for param, values in parsed_data['query_params'].items():
            print(f"    [XSS] Testing parameter: {param}")
            
            # Create deduplication key for this parameter
            param_key = f"xss_{base_url.split('?')[0]}_{param}"
            if param_key in self.found_vulnerabilities:
                print(f"    [XSS] Skipping parameter {param} - already tested")
                continue
            
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
                    
                    # Skip if response looks like 404
                    if self._is_likely_404_response(response.text, response.status_code):
                        print(f"    [XSS] Skipping - response appears to be 404")
                        continue
                    
                    # Use XSS detector
                    if XSSDetector.detect_reflected_xss(payload, response.text, response.status_code):
                        evidence = XSSDetector.get_evidence(payload, response.text)
                        response_snippet = XSSDetector.get_response_snippet(payload, response.text)
                        print(f"    [XSS] VULNERABILITY FOUND! Parameter: {param}")
                        
                        # Mark as found to prevent duplicates
                        self.found_vulnerabilities.add(param_key)
                        
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
            
            # Skip CSRF testing for error responses
            if response.status_code >= 400:
                print(f"    [CSRF] Skipping CSRF test - error response ({response.status_code})")
                return results
            
            # Extract all forms from the page
            import re
            form_pattern = r'<form[^>]*>(.*?)</form>'
            forms = re.findall(form_pattern, response.text, re.IGNORECASE | re.DOTALL)
            
            if not forms:
                print(f"    [CSRF] No forms found on page")
                return results
            
            print(f"    [CSRF] Found {len(forms)} form(s) to analyze")
            
            # Analyze each form individually
            form_action_pattern = r'<form[^>]*action=["\']?([^"\'>\s]+)["\']?[^>]*>'
            form_method_pattern = r'<form[^>]*method=["\']?([^"\'>\s]+)["\']?[^>]*>'
            
            form_actions = re.findall(form_action_pattern, response.text, re.IGNORECASE)
            form_methods = re.findall(form_method_pattern, response.text, re.IGNORECASE)
            
            vulnerable_forms = []
            
            for i, form_content in enumerate(forms):
                form_action = form_actions[i] if i < len(form_actions) else ''
                form_method = form_methods[i].upper() if i < len(form_methods) else 'GET'
                
                print(f"    [CSRF] Analyzing form {i+1}: action='{form_action}', method='{form_method}'")
                
                # Skip GET forms (not vulnerable to CSRF)
                if form_method == 'GET':
                    print(f"    [CSRF] Skipping GET form")
                    continue
                
                # Check if form has CSRF protection
                has_csrf_protection = False
                csrf_indicators = CSRFDetector.get_csrf_indicators()
                
                for indicator in csrf_indicators:
                    if indicator.lower() in form_content.lower():
                        has_csrf_protection = True
                        print(f"    [CSRF] Form {i+1} has CSRF protection: {indicator}")
                        break
                
                if not has_csrf_protection:
                    print(f"    [CSRF] Form {i+1} is VULNERABLE - no CSRF protection found")
                    
                    # Create unique form identifier based on form action only (ignore base URL)
                    # This will suppress duplicates like listproducts.php?cat=1, listproducts.php?cat=2, etc.
                    normalized_action = self._normalize_form_action(form_action)
                    form_id = f"csrf_form_{normalized_action}_{form_method}"
                    
                    if form_id not in self.found_vulnerabilities:
                        self.found_vulnerabilities.add(form_id)
                        
                        vulnerable_forms.append({
                            'action': form_action,
                            'method': form_method,
                            'content': form_content[:200] + '...' if len(form_content) > 200 else form_content
                        })
                    else:
                        print(f"    [CSRF] Form {i+1} vulnerability suppressed (similar form already found)")
            
            # Report vulnerabilities
            if vulnerable_forms:
                for form_info in vulnerable_forms:
                    evidence = f"Form with action '{form_info['action']}' and method '{form_info['method']}' lacks CSRF protection"
                    
                    results.append({
                        'module': 'csrf',
                        'target': base_url,
                        'vulnerability': 'Missing CSRF Protection',
                        'severity': 'Medium',
                        'parameter': f"form_action: {form_info['action']}",
                        'payload': 'N/A',
                        'evidence': evidence,
                        'request_url': base_url,
                        'detector': 'CSRFDetector.form_analysis',
                        'response_snippet': form_info['content']
                    })
                
                print(f"    [CSRF] VULNERABILITY FOUND! {len(vulnerable_forms)} vulnerable form(s)")
            else:
                print(f"    [CSRF] All forms have CSRF protection or no POST forms found")
            
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
                            success_codes = [200, 201, 202, 302, 303]
                            if test_response.status_code in success_codes:
                                # Check if the response indicates success
                                success_indicators = self._get_success_indicators()
                                
                                response_lower = test_response.text.lower()
                                if any(indicator in response_lower for indicator in success_indicators):
                                    # Create deduplication key for bypass vulnerabilities
                                    bypass_dedup_key = f"csrf_bypass_{form_url}_{payload['name']}"
                                    
                                    if bypass_dedup_key not in self.found_vulnerabilities:
                                        self.found_vulnerabilities.add(bypass_dedup_key)
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
                                    else:
                                        print(f"    [CSRF] Duplicate bypass vulnerability suppressed")
                                    break  # Found bypass, no need to test more payloads for this form
                            
                        except Exception as e:
                            print(f"    [CSRF] Error testing payload {payload['name']}: {e}")
                            continue
            else:
                print(f"    [CSRF] No forms found to test")
                
        except Exception as e:
            print(f"    [CSRF] Error during CSRF testing: {e}")
        
        return results

    def _test_dirbrute(self, parsed_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Test for directory and file bruteforce"""
        results = []
        base_url = parsed_data['url']
        
        # Remove query parameters from base URL
        if '?' in base_url:
            base_url = base_url.split('?')[0]
        
        # Get the directory part for proper baseline generation
        if base_url.endswith('.php') or base_url.endswith('.html') or base_url.endswith('.asp'):
            # For file URLs like listproducts.php, use the directory containing the file
            base_dir = '/'.join(base_url.split('/')[:-1]) + '/'
        else:
            # Ensure base URL ends with /
            if not base_url.endswith('/'):
                base_url += '/'
            base_dir = base_url
        
        try:
            print(f"    [DIRBRUTE] Starting directory and file bruteforce...")
            print(f"    [DIRBRUTE] Base URL: {base_url}")
            print(f"    [DIRBRUTE] Base directory for 404 baseline: {base_dir}")
            
            # Get baseline 404 response for real 404 detection
            print(f"    [DIRBRUTE] Generating baseline 404 responses...")
            baseline_404_text, baseline_404_size = Real404Detector.generate_baseline_404(
                base_dir, None
            )
            
            if baseline_404_text:
                print(f"    [DIRBRUTE] Baseline 404 generated: {baseline_404_size} bytes (average)")
                print(f"    [DIRBRUTE] Baseline fingerprint: {Real404Detector.get_response_fingerprint(baseline_404_text)}")
            else:
                print(f"    [DIRBRUTE] Could not generate baseline 404 - proceeding without baseline")
                baseline_404_text = None
                baseline_404_size = 0
            
            # Test directories first
            directories = DirBrutePayloads.get_all_directories()
            found_directories = []
            
            print(f"    [DIRBRUTE] Testing {len(directories)} directories...")
            
            for directory in directories[:50]:  # Limit to first 50 directories
                try:
                    if base_url.endswith('.php') or base_url.endswith('.html') or base_url.endswith('.asp'):
                        # For file-based URLs, test as path info
                        test_url = f"{base_url}/{directory}/"
                    else:
                        test_url = f"{base_url}{directory}/"
                    
                    response = requests.get(
                        test_url,
                        timeout=self.config.timeout,
                        headers=self.config.headers,
                        verify=False,
                        allow_redirects=False
                    )
                    
                    print(f"    [DIRBRUTE] Testing directory: {directory} -> {response.status_code} ({len(response.text)} bytes)")
                    
                    is_valid, evidence = DirBruteDetector.is_valid_response(
                        response.text, response.status_code, len(response.text), baseline_404_text, baseline_404_size
                    )
                    
                    if is_valid:
                        print(f"    [DIRBRUTE] DIRECTORY FOUND: {directory}/ - {evidence}")
                        
                        # Check for directory listing
                        has_listing = DirBruteDetector.detect_directory_listing(response.text)
                        severity = 'Medium' if has_listing else 'Low'
                        
                        results.append({
                            'module': 'dirbrute',
                            'target': test_url,
                            'vulnerability': 'Directory Found' + (' with Listing' if has_listing else ''),
                            'severity': severity,
                            'parameter': f'directory: {directory}',
                            'payload': directory,
                            'evidence': evidence + (' - Directory listing enabled' if has_listing else ''),
                            'request_url': test_url,
                            'detector': 'DirBruteDetector.is_valid_response',
                            'response_snippet': DirBruteDetector.get_response_snippet(response.text)
                        })
                        
                        found_directories.append(directory)
                        
                        # If directory found, recursively test files in it
                        self._test_files_in_directory(base_url, directory, results, baseline_404_text, baseline_404_size)
                    else:
                        print(f"    [DIRBRUTE] Directory not found: {directory} - {evidence}")
                        
                except Exception as e:
                    print(f"    [DIRBRUTE] Error testing directory {directory}: {e}")
                    continue
            
            # Test common files in root directory
            files = DirBrutePayloads.get_all_files()
            print(f"    [DIRBRUTE] Testing {len(files)} files...")
            
            for file in files[:50]:  # Limit to first 50 files
                try:
                    if base_url.endswith('.php') or base_url.endswith('.html') or base_url.endswith('.asp'):
                        # For file-based URLs, test as path info
                        test_url = f"{base_url}/{file}"
                    else:
                        test_url = f"{base_url}{file}"
                    
                    response = requests.get(
                        test_url,
                        timeout=self.config.timeout,
                        headers=self.config.headers,
                        verify=False
                    )
                    
                    print(f"    [DIRBRUTE] Testing file: {file} -> {response.status_code} ({len(response.text)} bytes)")
                    
                    is_valid, evidence = DirBruteDetector.is_valid_response(
                        response.text, response.status_code, len(response.text), baseline_404_text, baseline_404_size
                    )
                    
                    if is_valid:
                        print(f"    [DIRBRUTE] FILE FOUND: {file} - {evidence}")
                        
                        # Check for sensitive content
                        is_sensitive, sensitive_evidence = DirBruteDetector.detect_sensitive_file(
                            response.text, file
                        )
                        
                        severity = 'High' if is_sensitive else 'Low'
                        vuln_type = 'Sensitive File Found' if is_sensitive else 'File Found'
                        
                        results.append({
                            'module': 'dirbrute',
                            'target': test_url,
                            'vulnerability': vuln_type,
                            'severity': severity,
                            'parameter': f'file: {file}',
                            'payload': file,
                            'evidence': evidence + (f' - {sensitive_evidence}' if is_sensitive else ''),
                            'request_url': test_url,
                            'detector': 'DirBruteDetector.is_valid_response',
                            'response_snippet': DirBruteDetector.get_response_snippet(response.text)
                        })
                    else:
                        print(f"    [DIRBRUTE] File not found: {file} - {evidence}")
                        
                except Exception as e:
                    print(f"    [DIRBRUTE] Error testing file {file}: {e}")
                    continue
            
            if results:
                print(f"    [DIRBRUTE] Found {len(results)} directories/files")
            else:
                print(f"    [DIRBRUTE] No directories or files found")
                
        except Exception as e:
            print(f"    [DIRBRUTE] Error during directory bruteforce: {e}")
        
        return results
    
    def _test_files_in_directory(self, base_url: str, directory: str, results: List[Dict[str, Any]], baseline_404_text: str = None, baseline_404_size: int = 0):
        """Test files in a found directory"""
        files = DirBrutePayloads.get_all_files()
        
        print(f"    [DIRBRUTE] Testing files in directory: {directory}/")
        
        for file in files[:20]:  # Limit to first 20 files per directory
            try:
                test_url = f"{base_url}{directory}/{file}"
                
                response = requests.get(
                    test_url,
                    timeout=self.config.timeout,
                    headers=self.config.headers,
                    verify=False
                )
                
                is_valid, evidence = DirBruteDetector.is_valid_response(
                    response.text, response.status_code, len(response.text), baseline_404_text, baseline_404_size
                )
                
                if is_valid:
                    print(f"    [DIRBRUTE] FILE FOUND: {directory}/{file} - {evidence}")
                    
                    # Check for sensitive content
                    is_sensitive, sensitive_evidence = DirBruteDetector.detect_sensitive_file(
                        response.text, file
                    )
                    
                    severity = 'High' if is_sensitive else 'Low'
                    vuln_type = 'Sensitive File Found' if is_sensitive else 'File Found'
                    
                    results.append({
                        'module': 'dirbrute',
                        'target': test_url,
                        'vulnerability': vuln_type,
                        'severity': severity,
                        'parameter': f'file: {directory}/{file}',
                        'payload': f"{directory}/{file}",
                        'evidence': evidence + (f' - {sensitive_evidence}' if is_sensitive else ''),
                        'request_url': test_url,
                        'detector': 'DirBruteDetector.is_valid_response',
                        'response_snippet': DirBruteDetector.get_response_snippet(response.text)
                    })
                    
            except Exception as e:
                continue

    def _get_important_pages(self) -> List[str]:
        """Get list of important pages that might contain forms"""
        # Use DirBrutePayloads to get common files instead of hardcoded list
        common_files = DirBrutePayloads.get_common_files()
        important_pages = []
        
        for file in common_files:
            if any(keyword in file.lower() for keyword in ['login', 'admin', 'register', 'contact', 'guestbook']):
                important_pages.append(f'/{file}')
        
        return important_pages[:20]  # Limit to first 20 important pages
    
    def _is_likely_404_response(self, response_text: str, response_code: int) -> bool:
        """Quick check if response is likely a 404 page"""
        if response_code == 404:
            return True
        
        response_lower = response_text.lower()
        quick_404_indicators = [
            'page not found', 'not found', '404', 'file not found',
            'страница не найдена', 'файл не найден'
        ]
        
        return any(indicator in response_lower for indicator in quick_404_indicators)
    
    def _normalize_form_action(self, form_action: str) -> str:
        """Normalize form action to group similar forms together"""
        if not form_action:
            return 'empty_action'
        
        # Remove query parameters to group similar pages
        if '?' in form_action:
            base_action = form_action.split('?')[0]
        else:
            base_action = form_action
        
        # Remove leading slash and normalize
        normalized = base_action.lstrip('/')
        
        # Group common patterns
        common_patterns = {
            'search.php': 'search_form',
            'login.php': 'login_form', 
            'register.php': 'register_form',
            'contact.php': 'contact_form',
            'guestbook.php': 'guestbook_form',
            'admin.php': 'admin_form'
        }
        
        for pattern, group_name in common_patterns.items():
            if pattern in normalized:
                return group_name
        
        return normalized
    
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
