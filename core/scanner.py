"""
Main vulnerability scanner class
"""

import time
import json
import re
import requests
import urllib3
from typing import List, Dict, Any
from concurrent.futures import ThreadPoolExecutor, as_completed

from core.config import Config
from core.url_parser import URLParser
from core.crawler import WebCrawler
from utils.file_handler import FileHandler
from utils.screenshot_handler import ScreenshotHandler
# Import payload classes
from payloads.xss_payloads import XSSPayloads
from payloads.sqli_payloads import SQLiPayloads
from payloads.lfi_payloads import LFIPayloads
from payloads.csrf_payloads import CSRFPayloads
from payloads.dirbrute_payloads import DirBrutePayloads
from payloads.git_payloads import GitPayloads
from payloads.directory_traversal_payloads import DirectoryTraversalPayloads
from payloads.ssrf_payloads import SSRFPayloads
from payloads.rfi_payloads import RFIPayloads
from payloads.blind_xss_payloads import BlindXSSPayloads
from payloads.phpinfo_payloads import PHPInfoPayloads
from payloads.xxe_payloads import XXEPayloads
from payloads.command_injection_payloads import CommandInjectionPayloads
from payloads.idor_payloads import IDORPayloads
from payloads.nosql_injection_payloads import NoSQLInjectionPayloads

# Import detector classes
from detectors.xss_detector import XSSDetector
from detectors.sqli_detector import SQLiDetector
from detectors.lfi_detector import LFIDetector
from detectors.csrf_detector import CSRFDetector
from detectors.dirbrute_detector import DirBruteDetector
from detectors.real404_detector import Real404Detector
from detectors.git_detector import GitDetector
from detectors.directory_traversal_detector import DirectoryTraversalDetector
from detectors.security_headers_detector import SecurityHeadersDetector
from detectors.ssrf_detector import SSRFDetector
from detectors.rfi_detector import RFIDetector
from detectors.version_disclosure_detector import VersionDisclosureDetector
from detectors.clickjacking_detector import ClickjackingDetector
from detectors.blind_xss_detector import BlindXSSDetector
from detectors.password_over_http_detector import PasswordOverHTTPDetector
from detectors.outdated_software_detector import OutdatedSoftwareDetector
from detectors.database_error_detector import DatabaseErrorDetector
from detectors.phpinfo_detector import PHPInfoDetector
from detectors.ssl_tls_detector import SSLTLSDetector
from detectors.httponly_cookie_detector import HttpOnlyCookieDetector
from Wappalyzer import Wappalyzer, WebPage
from detectors.xxe_detector import XXEDetector
from detectors.idor_detector import IDORDetector
from detectors.command_injection_detector import CommandInjectionDetector
from detectors.path_traversal_detector import PathTraversalDetector
from detectors.ldap_injection_detector import LDAPInjectionDetector
from detectors.nosql_injection_detector import NoSQLInjectionDetector
from detectors.file_upload_detector import FileUploadDetector
from detectors.cors_detector import CORSDetector
from detectors.jwt_detector import JWTDetector
from detectors.insecure_deserialization_detector import InsecureDeserializationDetector
from detectors.http_response_splitting_detector import HTTPResponseSplittingDetector

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
        self.screenshot_handler = ScreenshotHandler()
        self.results = []
        self.request_count = 0
        self.found_vulnerabilities = set()  # For deduplication
        self.tested_domains_ssl = set()  # For SSL/TLS deduplication
        self.scan_stats = {
            'total_requests': 0,
            'total_urls': 0,
            'total_params': 0,
            'scan_duration': '0s',
            'start_time': None,
            'end_time': None,
            'technologies': {}
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
    
    def cleanup(self):
        """Cleanup resources"""
        if hasattr(self, 'screenshot_handler'):
            self.screenshot_handler.cleanup()
    
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
            import traceback
            traceback.print_exc()
        
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
            elif module_name == "gitexposed":
                results.extend(self._test_git_exposed(parsed_data))
            elif module_name == "dirtraversal":
                results.extend(self._test_directory_traversal(parsed_data))
            elif module_name == "secheaders":
                results.extend(self._test_security_headers(parsed_data))
            elif module_name == "ssrf":
                results.extend(self._test_ssrf(parsed_data))
            elif module_name == "rfi":
                results.extend(self._test_rfi(parsed_data))
            elif module_name == "versiondisclosure":
                results.extend(self._test_version_disclosure(parsed_data))
            elif module_name == "clickjacking":
                results.extend(self._test_clickjacking(parsed_data))
            elif module_name == "blindxss":
                results.extend(self._test_blind_xss(parsed_data))
            elif module_name == "passwordoverhttp":
                results.extend(self._test_password_over_http(parsed_data))
            elif module_name == "outdatedsoftware":
                results.extend(self._test_outdated_software(parsed_data))
            elif module_name == "databaseerrors":
                results.extend(self._test_database_errors(parsed_data))
            elif module_name == "phpinfo":
                results.extend(self._test_phpinfo(parsed_data))
            elif module_name == "ssltls":
                results.extend(self._test_ssl_tls(parsed_data))
            elif module_name == "httponlycookies":
                results.extend(self._test_httponly_cookies(parsed_data))
            elif module_name == "technology":
                results.extend(self._test_technology_detection(parsed_data))
            elif module_name == "xxe":
                results.extend(self._test_xxe(parsed_data))
            elif module_name == "idor":
                results.extend(self._test_idor(parsed_data))
            elif module_name == "commandinjection":
                results.extend(self._test_command_injection(parsed_data))
            elif module_name == "pathtraversal":
                results.extend(self._test_path_traversal(parsed_data))
            elif module_name == "ldapinjection":
                results.extend(self._test_ldap_injection(parsed_data))
            elif module_name == "nosqlinjection":
                results.extend(self._test_nosql_injection(parsed_data))
            elif module_name == "fileupload":
                results.extend(self._test_file_upload(parsed_data))
            elif module_name == "cors":
                results.extend(self._test_cors(parsed_data))
            elif module_name == "jwt":
                results.extend(self._test_jwt(parsed_data))
            elif module_name == "deserialization":
                results.extend(self._test_insecure_deserialization(parsed_data))
            elif module_name == "responsesplitting":
                results.extend(self._test_http_response_splitting(parsed_data))
            else:
                print(f"    [WARNING] Unknown module: {module_name}")
                
        except Exception as e:
            print(f"    [ERROR] Error testing {module_name}: {e}")
            import traceback
            traceback.print_exc()
        
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
                    if response.status_code == 404:
                        print(f"    [XSS] Skipping - response appears to be 404")
                        continue
                    
                    # Use XSS detector
                    if XSSDetector.detect_reflected_xss(payload, response.text, response.status_code):
                        evidence = XSSDetector.get_evidence(payload, response.text)
                        response_snippet = XSSDetector.get_response_snippet(payload, response.text)
                        print(f"    [XSS] VULNERABILITY FOUND! Parameter: {param}")
                        
                        # Mark as found to prevent duplicates
                        self.found_vulnerabilities.add(param_key)
                        
                        # Take screenshot for XSS vulnerability
                        screenshot_filename = None
                        try:
                            import time
                            vuln_id = f"xss_{param}_{int(time.time())}"
                            screenshot_filename = self.screenshot_handler.take_screenshot_with_payload(
                                test_url, "xss", vuln_id, payload
                            )
                        except Exception as e:
                            print(f"    [XSS] Could not take screenshot: {e}")
                        
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
                            'response_snippet': response_snippet,
                            'screenshot': screenshot_filename
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
            
            # Also get the original page content for comparison
            original_response = None
            original_fingerprint = None
            try:
                original_response = requests.get(
                    base_url,
                    timeout=self.config.timeout,
                    headers=self.config.headers,
                    verify=False
                )
                original_fingerprint = Real404Detector.get_response_fingerprint(original_response.text)
                print(f"    [DIRBRUTE] Original page fingerprint: {original_fingerprint}")
            except:
                pass
            
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
                    
                    # Additional checks for false positives
                    if is_valid:
                        # Check if response size is too similar to baseline
                        if baseline_404_size > 0:
                            size_diff = abs(len(response.text) - baseline_404_size)
                            size_ratio = size_diff / baseline_404_size if baseline_404_size > 0 else 1
                            
                            # Skip if size difference is less than 5% or less than 50 bytes
                            if size_ratio < 0.05 or size_diff < 50:
                                print(f"    [DIRBRUTE] Skipping directory {directory} - size too similar to 404 baseline ({len(response.text)} vs {baseline_404_size} bytes)")
                                is_valid = False
                        
                        # Check if response content is identical to original page
                        if is_valid and original_fingerprint:
                            response_fingerprint = Real404Detector.get_response_fingerprint(response.text)
                            if response_fingerprint == original_fingerprint:
                                print(f"    [DIRBRUTE] Skipping directory {directory} - identical content to original page")
                                is_valid = False
                    
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
                        self._test_files_in_directory(base_url, directory, results, baseline_404_text, baseline_404_size, original_fingerprint)
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
                    
                    # Additional checks for false positives
                    if is_valid:
                        # Check if response size is too similar to baseline
                        if baseline_404_size > 0:
                            size_diff = abs(len(response.text) - baseline_404_size)
                            size_ratio = size_diff / baseline_404_size if baseline_404_size > 0 else 1
                            
                            # Skip if size difference is less than 5% or less than 50 bytes
                            if size_ratio < 0.05 or size_diff < 50:
                                print(f"    [DIRBRUTE] Skipping file {file} - size too similar to 404 baseline ({len(response.text)} vs {baseline_404_size} bytes)")
                                is_valid = False
                        
                        # Check if response content is identical to original page
                        if is_valid and original_fingerprint:
                            response_fingerprint = Real404Detector.get_response_fingerprint(response.text)
                            if response_fingerprint == original_fingerprint:
                                print(f"    [DIRBRUTE] Skipping file {file} - identical content to original page")
                                is_valid = False
                    
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
    
    def _test_files_in_directory(self, base_url: str, directory: str, results: List[Dict[str, Any]], baseline_404_text: str = None, baseline_404_size: int = 0, original_fingerprint: str = None):
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
                
                # Additional checks for false positives
                if is_valid:
                    # Check if response size is too similar to baseline
                    if baseline_404_size > 0:
                        size_diff = abs(len(response.text) - baseline_404_size)
                        size_ratio = size_diff / baseline_404_size if baseline_404_size > 0 else 1
                        
                        # Skip if size difference is less than 5% or less than 50 bytes
                        if size_ratio < 0.05 or size_diff < 50:
                            print(f"    [DIRBRUTE] Skipping file {directory}/{file} - size too similar to 404 baseline ({len(response.text)} vs {baseline_404_size} bytes)")
                            is_valid = False
                    
                    # Check if response content is identical to original page
                    if is_valid and original_fingerprint:
                        response_fingerprint = Real404Detector.get_response_fingerprint(response.text)
                        if response_fingerprint == original_fingerprint:
                            print(f"    [DIRBRUTE] Skipping file {directory}/{file} - identical content to original page")
                            is_valid = False
                
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
    
    def _test_git_exposed(self, parsed_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Test for exposed .git repository"""
        results = []
        base_url = parsed_data['url']
        
        # Remove query parameters from base URL
        if '?' in base_url:
            base_url = base_url.split('?')[0]
        
        # Get the base directory URL
        if base_url.endswith('.php') or base_url.endswith('.html') or base_url.endswith('.asp'):
            # For file URLs, use the directory containing the file
            base_dir = '/'.join(base_url.split('/')[:-1]) + '/'
        else:
            # Ensure base URL ends with /
            if not base_url.endswith('/'):
                base_url += '/'
            base_dir = base_url
        
        try:
            print(f"    [GITEXPOSED] Testing for exposed .git repository...")
            print(f"    [GITEXPOSED] Base directory: {base_dir}")
            
            # Get git paths to test
            git_paths = GitPayloads.get_all_git_payloads()
            
            print(f"    [GITEXPOSED] Testing {len(git_paths)} git paths...")
            
            for git_path in git_paths:
                try:
                    test_url = f"{base_dir}{git_path}"
                    
                    response = requests.get(
                        test_url,
                        timeout=self.config.timeout,
                        headers=self.config.headers,
                        verify=False,
                        allow_redirects=False
                    )
                    
                    print(f"    [GITEXPOSED] Testing: {git_path} -> {response.status_code} ({len(response.text)} bytes)")
                    
                    # Use Git detector
                    is_exposed, evidence, severity = GitDetector.detect_git_exposure(
                        response.text, response.status_code, test_url
                    )
                    
                    if is_exposed:
                        print(f"    [GITEXPOSED] GIT EXPOSURE FOUND: {git_path} - {evidence}")
                        
                        # Get detailed evidence and response snippet
                        detailed_evidence = GitDetector.get_evidence(
                            git_path.split('/')[-1] if '/' in git_path else git_path,
                            response.text
                        )
                        response_snippet = GitDetector.get_response_snippet(response.text)
                        remediation = GitDetector.get_remediation_advice(git_path)
                        
                        results.append({
                            'module': 'gitexposed',
                            'target': test_url,
                            'vulnerability': 'Git Repository Exposed',
                            'severity': severity,
                            'parameter': f'git_path: {git_path}',
                            'payload': git_path,
                            'evidence': detailed_evidence,
                            'request_url': test_url,
                            'detector': 'GitDetector.detect_git_exposure',
                            'response_snippet': response_snippet,
                            'remediation': remediation
                        })
                    else:
                        print(f"    [GITEXPOSED] No exposure: {git_path} - {evidence}")
                        
                except Exception as e:
                    print(f"    [GITEXPOSED] Error testing {git_path}: {e}")
                    continue
            
            if results:
                print(f"    [GITEXPOSED] Found {len(results)} git exposures")
            else:
                print(f"    [GITEXPOSED] No git repository exposures found")
                
        except Exception as e:
            print(f"    [GITEXPOSED] Error during git exposure testing: {e}")
        
        return results
    
    def _test_directory_traversal(self, parsed_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Test for directory traversal vulnerabilities"""
        results = []
        base_url = parsed_data['url']
        
        # Get directory traversal payloads
        traversal_payloads = DirectoryTraversalPayloads.get_all_payloads()
        
        # Test GET parameters
        for param, values in parsed_data['query_params'].items():
            print(f"    [DIRTRAVERSAL] Testing parameter: {param}")
            
            # Create deduplication key for this parameter
            param_key = f"dirtraversal_{base_url.split('?')[0]}_{param}"
            if param_key in self.found_vulnerabilities:
                print(f"    [DIRTRAVERSAL] Skipping parameter {param} - already tested")
                continue
            
            for payload in traversal_payloads[:20]:  # Test first 20 payloads
                try:
                    print(f"    [DIRTRAVERSAL] Trying payload: {payload[:50]}...")
                    
                    # Create test URL
                    test_params = parsed_data['query_params'].copy()
                    test_params[param] = [payload]
                    
                    # Build query string
                    query_parts = []
                    for k, v_list in test_params.items():
                        for v in v_list:
                            query_parts.append(f"{k}={v}")
                    
                    test_url = f"{base_url.split('?')[0]}?{'&'.join(query_parts)}"
                    print(f"    [DIRTRAVERSAL] Request URL: {test_url}")
                    
                    response = requests.get(
                        test_url,
                        timeout=self.config.timeout,
                        headers=self.config.headers,
                        verify=False
                    )
                    
                    print(f"    [DIRTRAVERSAL] Response code: {response.status_code}")
                    
                    # Skip if response looks like 404
                    if response.status_code == 404:
                        print(f"    [DIRTRAVERSAL] Skipping - response appears to be 404")
                        continue
                    
                    # Use Directory Traversal detector
                    if DirectoryTraversalDetector.detect_directory_traversal(response.text, response.status_code, payload):
                        evidence = DirectoryTraversalDetector.get_evidence(payload, response.text)
                        response_snippet = DirectoryTraversalDetector.get_response_snippet(payload, response.text)
                        print(f"    [DIRTRAVERSAL] VULNERABILITY FOUND! Parameter: {param}")
                        
                        # Mark as found to prevent duplicates
                        self.found_vulnerabilities.add(param_key)
                        
                        results.append({
                            'module': 'dirtraversal',
                            'target': base_url,
                            'vulnerability': 'Directory Traversal',
                            'severity': 'High',
                            'parameter': param,
                            'payload': payload,
                            'evidence': evidence,
                            'request_url': test_url,
                            'detector': 'DirectoryTraversalDetector.detect_directory_traversal',
                            'response_snippet': response_snippet
                        })
                        break  # Found traversal, no need to test more payloads for this param
                        
                except Exception as e:
                    print(f"    [DIRTRAVERSAL] Error testing payload: {e}")
                    continue
        
        return results
    
    def _test_security_headers(self, parsed_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Test for missing security headers and insecure cookies"""
        results = []
        base_url = parsed_data['url']
        
        try:
            print(f"    [SECHEADERS] Testing security headers...")
            
            # Make request to get headers
            response = requests.get(
                base_url,
                timeout=self.config.timeout,
                headers=self.config.headers,
                verify=False
            )
            
            print(f"    [SECHEADERS] Response code: {response.status_code}")
            
            # Skip if error response
            if response.status_code >= 400:
                print(f"    [SECHEADERS] Skipping - error response ({response.status_code})")
                return results
            
            # Check for missing security headers
            missing_headers = SecurityHeadersDetector.detect_missing_security_headers(response.headers)
            
            if missing_headers:
                print(f"    [SECHEADERS] Found {len(missing_headers)} missing security headers")
                
                for header_info in missing_headers:
                    results.append({
                        'module': 'secheaders',
                        'target': base_url,
                        'vulnerability': f'Missing Security Header: {header_info["header"]}',
                        'severity': header_info['severity'],
                        'parameter': f'header: {header_info["header"]}',
                        'payload': 'N/A',
                        'evidence': f'{header_info["description"]}. {header_info["recommendation"]}',
                        'request_url': base_url,
                        'detector': 'SecurityHeadersDetector.detect_missing_security_headers',
                        'response_snippet': f'Current value: {header_info.get("current_value", "Not set")}'
                    })
            else:
                print(f"    [SECHEADERS] All important security headers are present")
            
            # Check for insecure cookies
            insecure_cookies = SecurityHeadersDetector.detect_insecure_cookies(response.headers)
            
            if insecure_cookies:
                print(f"    [SECHEADERS] Found {len(insecure_cookies)} insecure cookies")
                
                for cookie_info in insecure_cookies:
                    for issue in cookie_info['issues']:
                        results.append({
                            'module': 'secheaders',
                            'target': base_url,
                            'vulnerability': f'Insecure Cookie: {issue["issue"]}',
                            'severity': issue['severity'],
                            'parameter': f'cookie: {cookie_info["cookie_name"]}',
                            'payload': 'N/A',
                            'evidence': f'Cookie "{cookie_info["cookie_name"]}" {issue["description"]}',
                            'request_url': base_url,
                            'detector': 'SecurityHeadersDetector.detect_insecure_cookies',
                            'response_snippet': cookie_info['cookie_header']
                        })
            else:
                print(f"    [SECHEADERS] No insecure cookies found")
            
        except Exception as e:
            print(f"    [SECHEADERS] Error during security headers testing: {e}")
        
        return results
    
    def _test_ssrf(self, parsed_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Test for SSRF vulnerabilities"""
        results = []
        base_url = parsed_data['url']
        
        # Get SSRF payloads
        ssrf_payloads = SSRFPayloads.get_all_payloads()
        
        # Test GET parameters
        for param, values in parsed_data['query_params'].items():
            print(f"    [SSRF] Testing parameter: {param}")
            
            # Create deduplication key for this parameter
            param_key = f"ssrf_{base_url.split('?')[0]}_{param}"
            if param_key in self.found_vulnerabilities:
                print(f"    [SSRF] Skipping parameter {param} - already tested")
                continue
            
            for payload in ssrf_payloads[:10]:  # Test first 10 payloads
                try:
                    print(f"    [SSRF] Trying payload: {payload[:50]}...")
                    
                    # Create test URL
                    test_params = parsed_data['query_params'].copy()
                    test_params[param] = [payload]
                    
                    # Build query string
                    query_parts = []
                    for k, v_list in test_params.items():
                        for v in v_list:
                            query_parts.append(f"{k}={v}")
                    
                    test_url = f"{base_url.split('?')[0]}?{'&'.join(query_parts)}"
                    print(f"    [SSRF] Request URL: {test_url}")
                    
                    response = requests.get(
                        test_url,
                        timeout=self.config.timeout,
                        headers=self.config.headers,
                        verify=False
                    )
                    
                    print(f"    [SSRF] Response code: {response.status_code}")
                    
                    # Use SSRF detector
                    if SSRFDetector.detect_ssrf(response.text, response.status_code, payload):
                        evidence = SSRFDetector.get_evidence(payload, response.text)
                        response_snippet = SSRFDetector.get_response_snippet(payload, response.text)
                        print(f"    [SSRF] VULNERABILITY FOUND! Parameter: {param}")
                        
                        # Mark as found to prevent duplicates
                        self.found_vulnerabilities.add(param_key)
                        
                        results.append({
                            'module': 'ssrf',
                            'target': base_url,
                            'vulnerability': 'Server-Side Request Forgery',
                            'severity': 'High',
                            'parameter': param,
                            'payload': payload,
                            'evidence': evidence,
                            'request_url': test_url,
                            'detector': 'SSRFDetector.detect_ssrf',
                            'response_snippet': response_snippet
                        })
                        break  # Found SSRF, no need to test more payloads for this param
                        
                except Exception as e:
                    print(f"    [SSRF] Error testing payload: {e}")
                    continue
        
        return results
    
    def _test_rfi(self, parsed_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Test for RFI vulnerabilities"""
        results = []
        base_url = parsed_data['url']
        
        # Get RFI payloads
        rfi_payloads = RFIPayloads.get_all_payloads()
        
        # Test GET parameters
        for param, values in parsed_data['query_params'].items():
            print(f"    [RFI] Testing parameter: {param}")
            
            # Create deduplication key for this parameter
            param_key = f"rfi_{base_url.split('?')[0]}_{param}"
            if param_key in self.found_vulnerabilities:
                print(f"    [RFI] Skipping parameter {param} - already tested")
                continue
            
            for payload in rfi_payloads[:15]:  # Test first 15 payloads
                try:
                    print(f"    [RFI] Trying payload: {payload[:50]}...")
                    
                    # Create test URL
                    test_params = parsed_data['query_params'].copy()
                    test_params[param] = [payload]
                    
                    # Build query string
                    query_parts = []
                    for k, v_list in test_params.items():
                        for v in v_list:
                            query_parts.append(f"{k}={v}")
                    
                    test_url = f"{base_url.split('?')[0]}?{'&'.join(query_parts)}"
                    print(f"    [RFI] Request URL: {test_url}")
                    
                    response = requests.get(
                        test_url,
                        timeout=self.config.timeout,
                        headers=self.config.headers,
                        verify=False
                    )
                    
                    print(f"    [RFI] Response code: {response.status_code}")
                    
                    # Use RFI detector
                    if RFIDetector.detect_rfi(response.text, response.status_code, payload):
                        evidence = RFIDetector.get_evidence(payload, response.text)
                        response_snippet = RFIDetector.get_response_snippet(payload, response.text)
                        print(f"    [RFI] VULNERABILITY FOUND! Parameter: {param}")
                        
                        # Mark as found to prevent duplicates
                        self.found_vulnerabilities.add(param_key)
                        
                        results.append({
                            'module': 'rfi',
                            'target': base_url,
                            'vulnerability': 'Remote File Inclusion',
                            'severity': 'High',
                            'parameter': param,
                            'payload': payload,
                            'evidence': evidence,
                            'request_url': test_url,
                            'detector': 'RFIDetector.detect_rfi',
                            'response_snippet': response_snippet
                        })
                        break  # Found RFI, no need to test more payloads for this param
                        
                except Exception as e:
                    print(f"    [RFI] Error testing payload: {e}")
                    continue
        
        return results
    
    def _test_version_disclosure(self, parsed_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Test for version disclosure vulnerabilities with deduplication"""
        results = []
        base_url = parsed_data['url']
        
        # Extract domain for deduplication
        from urllib.parse import urlparse
        parsed_url = urlparse(base_url)
        domain = parsed_url.hostname
        
        # Create deduplication key for this domain
        domain_key = f"version_disclosure_{domain}"
        if domain_key in self.found_vulnerabilities:
            print(f"    [VERSIONDISCLOSURE] Skipping version disclosure test for {domain} - already tested")
            return results
        
        try:
            print(f"    [VERSIONDISCLOSURE] Testing version disclosure...")
            
            # Mark domain as tested
            self.found_vulnerabilities.add(domain_key)
            
            # Make request to get headers and content
            response = requests.get(
                base_url,
                timeout=self.config.timeout,
                headers=self.config.headers,
                verify=False
            )
            
            print(f"    [VERSIONDISCLOSURE] Response code: {response.status_code}")
            
            # Skip if error response
            if response.status_code >= 400:
                print(f"    [VERSIONDISCLOSURE] Skipping - error response ({response.status_code})")
                return results
            
            # Check for version disclosures
            disclosures = VersionDisclosureDetector.detect_version_disclosure(response.text, response.headers)
            
            if disclosures:
                print(f"    [VERSIONDISCLOSURE] Found {len(disclosures)} version disclosures")
                
                # Deduplicate by software name and version
                seen_versions = set()
                
                for disclosure in disclosures:
                    software = disclosure['software']
                    version = disclosure['version']
                    
                    # Create deduplication key for this software version
                    version_key = f"{software}_{version}"
                    if version_key in seen_versions:
                        print(f"    [VERSIONDISCLOSURE] Skipping duplicate {software} {version}")
                        continue
                    
                    seen_versions.add(version_key)
                    
                    severity = VersionDisclosureDetector.get_severity(software, version)
                    evidence = f"Version disclosure: {software} {version} found in {disclosure['location']}"
                    
                    results.append({
                        'module': 'versiondisclosure',
                        'target': base_url,
                        'vulnerability': f'Version Disclosure ({software.title()})',
                        'severity': severity,
                        'parameter': f'version: {software}',
                        'payload': 'N/A',
                        'evidence': evidence,
                        'request_url': base_url,
                        'detector': 'VersionDisclosureDetector.detect_version_disclosure',
                        'response_snippet': f'Version: {version}'
                    })
            else:
                print(f"    [VERSIONDISCLOSURE] No version disclosures found")
            
        except Exception as e:
            print(f"    [VERSIONDISCLOSURE] Error during version disclosure testing: {e}")
        
        return results
    
    def _test_clickjacking(self, parsed_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Test for clickjacking vulnerabilities"""
        results = []
        base_url = parsed_data['url']
        
        try:
            print(f"    [CLICKJACKING] Testing clickjacking protection...")
            
            # Make request to get headers
            response = requests.get(
                base_url,
                timeout=self.config.timeout,
                headers=self.config.headers,
                verify=False
            )
            
            print(f"    [CLICKJACKING] Response code: {response.status_code}")
            
            # Skip if error response
            if response.status_code >= 400:
                print(f"    [CLICKJACKING] Skipping - error response ({response.status_code})")
                return results
            
            # Check for clickjacking protection
            clickjacking_result = ClickjackingDetector.detect_clickjacking(response.headers)
            
            if clickjacking_result['vulnerable']:
                print(f"    [CLICKJACKING] VULNERABILITY FOUND! Missing clickjacking protection")
                
                severity = 'Medium' if clickjacking_result['missing_headers'] else 'Low'
                
                results.append({
                    'module': 'clickjacking',
                    'target': base_url,
                    'vulnerability': 'Missing Clickjacking Protection',
                    'severity': severity,
                    'parameter': 'headers',
                    'payload': 'N/A',
                    'evidence': clickjacking_result['evidence'],
                    'request_url': base_url,
                    'detector': 'ClickjackingDetector.detect_clickjacking',
                    'response_snippet': 'Missing X-Frame-Options or CSP frame-ancestors'
                })
            else:
                print(f"    [CLICKJACKING] Clickjacking protection is properly configured")
            
        except Exception as e:
            print(f"    [CLICKJACKING] Error during clickjacking testing: {e}")
        
        return results
    
    def _test_blind_xss(self, parsed_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Test for Blind XSS vulnerabilities"""
        results = []
        base_url = parsed_data['url']
        
        # Get Blind XSS payloads
        blind_xss_payloads = BlindXSSPayloads.get_all_payloads()
        
        # Test GET parameters
        for param, values in parsed_data['query_params'].items():
            print(f"    [BLINDXSS] Testing parameter: {param}")
            
            # Create deduplication key for this parameter
            param_key = f"blindxss_{base_url.split('?')[0]}_{param}"
            if param_key in self.found_vulnerabilities:
                print(f"    [BLINDXSS] Skipping parameter {param} - already tested")
                continue
            
            for payload in blind_xss_payloads[:10]:  # Test first 10 payloads
                try:
                    # Replace callback host with a test domain
                    test_payload = BlindXSSPayloads.replace_callback_host(payload, 'blindxss-test.example.com')
                    print(f"    [BLINDXSS] Trying payload: {test_payload[:50]}...")
                    
                    # Create test URL
                    test_params = parsed_data['query_params'].copy()
                    test_params[param] = [test_payload]
                    
                    # Build query string
                    query_parts = []
                    for k, v_list in test_params.items():
                        for v in v_list:
                            query_parts.append(f"{k}={v}")
                    
                    test_url = f"{base_url.split('?')[0]}?{'&'.join(query_parts)}"
                    print(f"    [BLINDXSS] Request URL: {test_url}")
                    
                    response = requests.get(
                        test_url,
                        timeout=self.config.timeout,
                        headers=self.config.headers,
                        verify=False
                    )
                    
                    print(f"    [BLINDXSS] Response code: {response.status_code}")
                    
                    # Use Blind XSS detector (simulate no callback for now)
                    if BlindXSSDetector.detect_blind_xss(test_payload, response.text, response.status_code, callback_received=False):
                        evidence = BlindXSSDetector.get_evidence(test_payload, response.text, callback_received=False)
                        response_snippet = BlindXSSDetector.get_response_snippet(test_payload, response.text)
                        print(f"    [BLINDXSS] POTENTIAL VULNERABILITY FOUND! Parameter: {param}")
                        
                        # Mark as found to prevent duplicates
                        self.found_vulnerabilities.add(param_key)
                        
                        results.append({
                            'module': 'blindxss',
                            'target': base_url,
                            'vulnerability': 'Potential Blind XSS',
                            'severity': 'High',
                            'parameter': param,
                            'payload': test_payload,
                            'evidence': evidence,
                            'request_url': test_url,
                            'detector': 'BlindXSSDetector.detect_blind_xss',
                            'response_snippet': response_snippet
                        })
                        break  # Found potential blind XSS, no need to test more payloads for this param
                        
                except Exception as e:
                    print(f"    [BLINDXSS] Error testing payload: {e}")
                    continue
        
        return results
    
    def _test_password_over_http(self, parsed_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Test for password transmission over HTTP"""
        results = []
        base_url = parsed_data['url']
        
        try:
            print(f"    [PASSWORDOVERHTTP] Testing password over HTTP...")
            
            # Make request to get page content
            response = requests.get(
                base_url,
                timeout=self.config.timeout,
                headers=self.config.headers,
                verify=False
            )
            
            print(f"    [PASSWORDOVERHTTP] Response code: {response.status_code}")
            
            # Use Password over HTTP detector
            is_vulnerable, evidence, forms_found = PasswordOverHTTPDetector.detect_password_over_http(
                base_url, response.text, response.status_code
            )
            
            if is_vulnerable:
                print(f"    [PASSWORDOVERHTTP] VULNERABILITY FOUND! {evidence}")
                
                detailed_evidence = PasswordOverHTTPDetector.get_evidence(forms_found)
                remediation = PasswordOverHTTPDetector.get_remediation_advice()
                
                results.append({
                    'module': 'passwordoverhttp',
                    'target': base_url,
                    'vulnerability': 'Password Transmitted over HTTP',
                    'severity': 'High',
                    'parameter': 'password_field',
                    'payload': 'N/A',
                    'evidence': detailed_evidence,
                    'request_url': base_url,
                    'detector': 'PasswordOverHTTPDetector.detect_password_over_http',
                    'response_snippet': f'Found {len(forms_found)} form(s) with password fields',
                    'remediation': remediation
                })
            else:
                print(f"    [PASSWORDOVERHTTP] No password over HTTP issues found")
            
        except Exception as e:
            print(f"    [PASSWORDOVERHTTP] Error during password over HTTP testing: {e}")
        
        return results
    
    def _test_outdated_software(self, parsed_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Test for outdated software versions with deduplication"""
        results = []
        base_url = parsed_data['url']
        
        # Extract domain for deduplication
        from urllib.parse import urlparse
        parsed_url = urlparse(base_url)
        domain = parsed_url.hostname
        
        # Create deduplication key for this domain
        domain_key = f"outdated_software_{domain}"
        if domain_key in self.found_vulnerabilities:
            print(f"    [OUTDATEDSOFTWARE] Skipping outdated software test for {domain} - already tested")
            return results
        
        try:
            print(f"    [OUTDATEDSOFTWARE] Testing outdated software...")
            
            # Mark domain as tested
            self.found_vulnerabilities.add(domain_key)
            
            # Make request to get headers and content
            response = requests.get(
                base_url,
                timeout=self.config.timeout,
                headers=self.config.headers,
                verify=False
            )
            
            print(f"    [OUTDATEDSOFTWARE] Response code: {response.status_code}")
            
            # Use Outdated Software detector
            detections = OutdatedSoftwareDetector.detect_outdated_software(
                dict(response.headers), response.text
            )
            
            if detections:
                print(f"    [OUTDATEDSOFTWARE] Found {len(detections)} outdated software components")
                
                # Deduplicate by software name and version
                seen_versions = set()
                
                for detection in detections:
                    software = detection['software']
                    version = detection['version']
                    severity = detection['severity']
                    known_vulns = detection.get('known_vulnerabilities', [])
                    
                    # Create deduplication key for this software version
                    version_key = f"{software}_{version}"
                    if version_key in seen_versions:
                        print(f"    [OUTDATEDSOFTWARE] Skipping duplicate {software} {version}")
                        continue
                    
                    seen_versions.add(version_key)
                    
                    evidence = f"{software.upper()} version {version}"
                    if known_vulns:
                        evidence += f" has known vulnerabilities: {', '.join(known_vulns[:3])}"
                    
                    remediation = OutdatedSoftwareDetector.get_remediation_advice(software, version)
                    
                    results.append({
                        'module': 'outdatedsoftware',
                        'target': base_url,
                        'vulnerability': f'Outdated {software.title()} Version',
                        'severity': severity,
                        'parameter': f'software: {software}',
                        'payload': 'N/A',
                        'evidence': evidence,
                        'request_url': base_url,
                        'detector': 'OutdatedSoftwareDetector.detect_outdated_software',
                        'response_snippet': f'Version: {version}',
                        'remediation': remediation
                    })
            else:
                print(f"    [OUTDATEDSOFTWARE] No outdated software detected")
            
        except Exception as e:
            print(f"    [OUTDATEDSOFTWARE] Error during outdated software testing: {e}")
        
        return results
    
    def _test_database_errors(self, parsed_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Test for database error message disclosure"""
        results = []
        base_url = parsed_data['url']
        
        # Test GET parameters with error-inducing payloads
        for param, values in parsed_data['query_params'].items():
            print(f"    [DATABASEERRORS] Testing parameter: {param}")
            
            # Create deduplication key for this parameter
            param_key = f"dberrors_{base_url.split('?')[0]}_{param}"
            if param_key in self.found_vulnerabilities:
                print(f"    [DATABASEERRORS] Skipping parameter {param} - already tested")
                continue
            
            # Test with error-inducing payloads
            error_payloads = ["'", '"', "' OR '1'='1", "'; DROP TABLE users; --", "%27"]
            
            for payload in error_payloads:
                try:
                    print(f"    [DATABASEERRORS] Trying payload: {payload}")
                    
                    # Create test URL
                    test_params = parsed_data['query_params'].copy()
                    test_params[param] = [payload]
                    
                    # Build query string
                    query_parts = []
                    for k, v_list in test_params.items():
                        for v in v_list:
                            query_parts.append(f"{k}={v}")
                    
                    test_url = f"{base_url.split('?')[0]}?{'&'.join(query_parts)}"
                    print(f"    [DATABASEERRORS] Request URL: {test_url}")
                    
                    response = requests.get(
                        test_url,
                        timeout=self.config.timeout,
                        headers=self.config.headers,
                        verify=False
                    )
                    
                    print(f"    [DATABASEERRORS] Response code: {response.status_code}")
                    
                    # Use Database Error detector
                    is_vulnerable, db_type, evidence, error_messages = DatabaseErrorDetector.detect_database_errors(
                        response.text, response.status_code
                    )
                    
                    if is_vulnerable:
                        detailed_evidence = DatabaseErrorDetector.get_evidence(db_type, error_messages)
                        response_snippet = DatabaseErrorDetector.get_response_snippet(error_messages, response.text)
                        remediation = DatabaseErrorDetector.get_remediation_advice()
                        
                        print(f"    [DATABASEERRORS] VULNERABILITY FOUND! Parameter: {param}, DB: {db_type}")
                        
                        # Mark as found to prevent duplicates
                        self.found_vulnerabilities.add(param_key)
                        
                        results.append({
                            'module': 'databaseerrors',
                            'target': base_url,
                            'vulnerability': 'Database Error Message Disclosure',
                            'severity': 'Low',
                            'parameter': param,
                            'payload': payload,
                            'evidence': detailed_evidence,
                            'request_url': test_url,
                            'detector': 'DatabaseErrorDetector.detect_database_errors',
                            'response_snippet': response_snippet,
                            'remediation': remediation
                        })
                        break  # Found database error, no need to test more payloads for this param
                        
                except Exception as e:
                    print(f"    [DATABASEERRORS] Error testing payload: {e}")
                    continue
        
        return results

    def _test_phpinfo(self, parsed_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Test for PHPInfo exposure"""
        results = []
        base_url = parsed_data['url']
        
        # Remove query parameters from base URL
        if '?' in base_url:
            base_url = base_url.split('?')[0]
        
        # Get the base directory URL
        if base_url.endswith('.php') or base_url.endswith('.html') or base_url.endswith('.asp'):
            # For file URLs, use the directory containing the file
            base_dir = '/'.join(base_url.split('/')[:-1]) + '/'
        else:
            # Ensure base URL ends with /
            if not base_url.endswith('/'):
                base_url += '/'
            base_dir = base_url
        
        try:
            print(f"    [PHPINFO] Testing for PHPInfo exposure...")
            print(f"    [PHPINFO] Base directory: {base_dir}")
            
            # Get PHPInfo paths to test
            phpinfo_paths = PHPInfoPayloads.get_all_phpinfo_payloads()
            
            print(f"    [PHPINFO] Testing {len(phpinfo_paths)} PHPInfo paths...")
            
            for phpinfo_path in phpinfo_paths[:30]:  # Limit to first 30 paths
                try:
                    test_url = f"{base_dir}{phpinfo_path}"
                    
                    response = requests.get(
                        test_url,
                        timeout=self.config.timeout,
                        headers=self.config.headers,
                        verify=False,
                        allow_redirects=False
                    )
                    
                    print(f"    [PHPINFO] Testing: {phpinfo_path} -> {response.status_code} ({len(response.text)} bytes)")
                    
                    # Use PHPInfo detector
                    is_exposed, evidence, severity = PHPInfoDetector.detect_phpinfo_exposure(
                        response.text, response.status_code, test_url
                    )
                    
                    if is_exposed:
                        print(f"    [PHPINFO] PHPINFO EXPOSURE FOUND: {phpinfo_path} - {evidence}")
                        
                        # Get detailed evidence and response snippet
                        detailed_evidence = PHPInfoDetector.get_evidence(
                            PHPInfoDetector.get_phpinfo_indicators(), response.text
                        )
                        response_snippet = PHPInfoDetector.get_response_snippet(response.text)
                        remediation = PHPInfoDetector.get_remediation_advice()
                        
                        results.append({
                            'module': 'phpinfo',
                            'target': test_url,
                            'vulnerability': 'PHPInfo Page Exposed',
                            'severity': severity,
                            'parameter': f'phpinfo_path: {phpinfo_path}',
                            'payload': phpinfo_path,
                            'evidence': detailed_evidence,
                            'request_url': test_url,
                            'detector': 'PHPInfoDetector.detect_phpinfo_exposure',
                            'response_snippet': response_snippet,
                            'remediation': remediation
                        })
                    else:
                        print(f"    [PHPINFO] No exposure: {phpinfo_path} - {evidence}")
                        
                except Exception as e:
                    print(f"    [PHPINFO] Error testing {phpinfo_path}: {e}")
                    continue
            
            # Also test for PHPInfo via parameters
            if parsed_data['query_params']:
                print(f"    [PHPINFO] Testing PHPInfo via parameters...")
                
                phpinfo_params = PHPInfoPayloads.get_phpinfo_parameters()
                phpinfo_values = PHPInfoPayloads.get_phpinfo_parameter_values()
                
                for param in list(parsed_data['query_params'].keys())[:5]:  # Test first 5 parameters
                    for value in phpinfo_values[:10]:  # Test first 10 values
                        try:
                            # Create test URL
                            test_params = parsed_data['query_params'].copy()
                            test_params[param] = [value]
                            
                            # Build query string
                            query_parts = []
                            for k, v_list in test_params.items():
                                for v in v_list:
                                    query_parts.append(f"{k}={v}")
                            
                            test_url = f"{parsed_data['url'].split('?')[0]}?{'&'.join(query_parts)}"
                            
                            response = requests.get(
                                test_url,
                                timeout=self.config.timeout,
                                headers=self.config.headers,
                                verify=False
                            )
                            
                            # Use PHPInfo detector
                            is_exposed, evidence, severity = PHPInfoDetector.detect_phpinfo_exposure(
                                response.text, response.status_code, test_url
                            )
                            
                            if is_exposed:
                                print(f"    [PHPINFO] PHPINFO VIA PARAMETER FOUND: {param}={value}")
                                
                                detailed_evidence = PHPInfoDetector.get_evidence(
                                    PHPInfoDetector.get_phpinfo_indicators(), response.text
                                )
                                response_snippet = PHPInfoDetector.get_response_snippet(response.text)
                                remediation = PHPInfoDetector.get_remediation_advice()
                                
                                results.append({
                                    'module': 'phpinfo',
                                    'target': test_url,
                                    'vulnerability': 'PHPInfo via Parameter',
                                    'severity': severity,
                                    'parameter': param,
                                    'payload': value,
                                    'evidence': detailed_evidence,
                                    'request_url': test_url,
                                    'detector': 'PHPInfoDetector.detect_phpinfo_exposure',
                                    'response_snippet': response_snippet,
                                    'remediation': remediation
                                })
                                break  # Found PHPInfo, no need to test more values for this param
                                
                        except Exception as e:
                            continue
            
            if results:
                print(f"    [PHPINFO] Found {len(results)} PHPInfo exposures")
            else:
                print(f"    [PHPINFO] No PHPInfo exposures found")
                
        except Exception as e:
            print(f"    [PHPINFO] Error during PHPInfo testing: {e}")
        
        return results
    
    def _test_ssl_tls(self, parsed_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Test for SSL/TLS implementation"""
        results = []
        base_url = parsed_data['url']
        
        # Extract domain for deduplication
        from urllib.parse import urlparse
        parsed_url = urlparse(base_url)
        domain = parsed_url.hostname
        
        if domain in self.tested_domains_ssl:
            print(f"    [SSLTLS] Skipping SSL/TLS test for {domain} - already tested")
            return results
        
        try:
            print(f"    [SSLTLS] Testing SSL/TLS implementation for domain: {domain}")
            
            # Mark domain as tested
            self.tested_domains_ssl.add(domain)
            
            # Use SSL/TLS detector
            has_ssl, evidence, severity, details = SSLTLSDetector.detect_ssl_tls_implementation(base_url)
            
            if not has_ssl or severity in ['High', 'Medium']:
                print(f"    [SSLTLS] SSL/TLS ISSUE FOUND: {evidence}")
                
                issue_type = details.get('issue', 'ssl_issue')
                remediation = SSLTLSDetector.get_remediation_advice(issue_type)
                
                vulnerability_name = "SSL/TLS Not Implemented"
                if has_ssl:
                    if 'weak' in evidence.lower():
                        vulnerability_name = "Weak SSL/TLS Configuration"
                    elif 'not enforced' in evidence.lower():
                        vulnerability_name = "SSL/TLS Not Enforced"
                
                # Take screenshot for SSL/TLS issues
                screenshot_filename = None
                try:
                    import time
                    vuln_id = f"ssl_{domain}_{int(time.time())}"
                    screenshot_filename = self.screenshot_handler.take_screenshot(
                        base_url, "ssl_tls", vuln_id
                    )
                except Exception as e:
                    print(f"    [SSLTLS] Could not take screenshot: {e}")
                
                results.append({
                    'module': 'ssltls',
                    'target': base_url,
                    'vulnerability': vulnerability_name,
                    'severity': severity,
                    'parameter': 'ssl_configuration',
                    'payload': 'N/A',
                    'evidence': evidence,
                    'request_url': base_url,
                    'detector': 'SSLTLSDetector.detect_ssl_tls_implementation',
                    'response_snippet': f"TLS Version: {details.get('tls_version', 'N/A')}, Cipher: {details.get('cipher', 'N/A')}",
                    'remediation': remediation,
                    'screenshot': screenshot_filename
                })
            else:
                print(f"    [SSLTLS] SSL/TLS properly configured for {domain}")
            
        except Exception as e:
            print(f"    [SSLTLS] Error during SSL/TLS testing: {e}")
        
        return results
    
    def _test_httponly_cookies(self, parsed_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Test for HttpOnly cookie security"""
        results = []
        base_url = parsed_data['url']
        
        try:
            print(f"    [HTTPONLYCOOKIES] Testing HttpOnly cookie security...")
            
            # Make request to get cookies
            response = requests.get(
                base_url,
                timeout=self.config.timeout,
                headers=self.config.headers,
                verify=False
            )
            
            print(f"    [HTTPONLYCOOKIES] Response code: {response.status_code}")
            
            # Skip if error response
            if response.status_code >= 400:
                print(f"    [HTTPONLYCOOKIES] Skipping - error response ({response.status_code})")
                return results
            
            # Check for insecure cookies
            insecure_cookies = HttpOnlyCookieDetector.detect_httponly_cookies(dict(response.headers))
            
            if insecure_cookies:
                print(f"    [HTTPONLYCOOKIES] Found {len(insecure_cookies)} insecure cookies")
                
                for cookie_info in insecure_cookies:
                    for issue in cookie_info['issues']:
                        results.append({
                            'module': 'httponlycookies',
                            'target': base_url,
                            'vulnerability': f'Cookie Security Issue: {issue["issue"]}',
                            'severity': issue['severity'],
                            'parameter': f'cookie: {cookie_info["cookie_name"]}',
                            'payload': 'N/A',
                            'evidence': f'Cookie "{cookie_info["cookie_name"]}" {issue["description"]}',
                            'request_url': base_url,
                            'detector': 'HttpOnlyCookieDetector.detect_httponly_cookies',
                            'response_snippet': cookie_info['cookie_header'],
                            'remediation': HttpOnlyCookieDetector.get_remediation_advice(issue['issue'])
                        })
            else:
                print(f"    [HTTPONLYCOOKIES] No insecure cookies found")
            
        except Exception as e:
            print(f"    [HTTPONLYCOOKIES] Error during HttpOnly cookie testing: {e}")
        
        return results

    def _test_technology_detection(self, parsed_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Test for technology detection using Wappalyzer"""
        results = []
        base_url = parsed_data['url']
        
        try:
            print(f"    [TECHNOLOGY] Detecting technologies with Wappalyzer...")
            
            # Make request to get headers and content
            response = requests.get(
                base_url,
                timeout=self.config.timeout,
                headers=self.config.headers,
                verify=False
            )
            
            print(f"    [TECHNOLOGY] Response code: {response.status_code}")
            
            # Skip if error response
            if response.status_code >= 400:
                print(f"    [TECHNOLOGY] Skipping - error response ({response.status_code})")
                return results
            
            # Use Wappalyzer to detect technologies
            wappalyzer = Wappalyzer.latest()
            webpage = WebPage.new_from_response(response)
            technologies = wappalyzer.analyze(webpage)
            
            if technologies:
                print(f"    [TECHNOLOGY] Found {len(technologies)} technologies")
                
                # Store technologies in scan stats
                domain = parsed_data.get('host', 'unknown')
                self.scan_stats['technologies'][domain] = list(technologies)
                
                for tech_name in technologies:
                    results.append({
                        'module': 'technology',
                        'target': base_url,
                        'vulnerability': f'Technology Detected: {tech_name}',
                        'severity': 'Info',
                        'parameter': f'technology: {tech_name}',
                        'payload': 'N/A',
                        'evidence': f'Technology {tech_name} detected by Wappalyzer',
                        'request_url': base_url,
                        'detector': 'Wappalyzer.analyze',
                        'response_snippet': f'Technology: {tech_name}'
                    })
            else:
                print(f"    [TECHNOLOGY] No technologies detected")
            
        except Exception as e:
            print(f"    [TECHNOLOGY] Error during technology detection: {e}")
        
        return results

    def _test_xxe(self, parsed_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Test for XXE vulnerabilities"""
        results = []
        base_url = parsed_data['url']
        
        # Get XXE payloads
        xxe_payloads = XXEPayloads.get_all_payloads()
        
        # Test GET parameters
        for param, values in parsed_data['query_params'].items():
            print(f"    [XXE] Testing parameter: {param}")
            
            # Create deduplication key for this parameter
            param_key = f"xxe_{base_url.split('?')[0]}_{param}"
            if param_key in self.found_vulnerabilities:
                print(f"    [XXE] Skipping parameter {param} - already tested")
                continue
            
            for payload in xxe_payloads[:10]:  # Test first 10 payloads
                try:
                    print(f"    [XXE] Trying payload: {payload[:50]}...")
                    
                    # Create test URL
                    test_params = parsed_data['query_params'].copy()
                    test_params[param] = [payload]
                    
                    # Build query string
                    query_parts = []
                    for k, v_list in test_params.items():
                        for v in v_list:
                            query_parts.append(f"{k}={v}")
                    
                    test_url = f"{base_url.split('?')[0]}?{'&'.join(query_parts)}"
                    print(f"    [XXE] Request URL: {test_url}")
                    
                    response = requests.get(
                        test_url,
                        timeout=self.config.timeout,
                        headers=self.config.headers,
                        verify=False
                    )
                    
                    print(f"    [XXE] Response code: {response.status_code}")
                    
                    # Use XXE detector
                    if XXEDetector.detect_xxe(response.text, response.status_code, payload):
                        evidence = XXEDetector.get_evidence(payload, response.text)
                        response_snippet = XXEDetector.get_response_snippet(payload, response.text)
                        remediation = XXEDetector.get_remediation_advice()
                        print(f"    [XXE] VULNERABILITY FOUND! Parameter: {param}")
                        
                        # Mark as found to prevent duplicates
                        self.found_vulnerabilities.add(param_key)
                        
                        results.append({
                            'module': 'xxe',
                            'target': base_url,
                            'vulnerability': 'XML External Entity (XXE)',
                            'severity': 'High',
                            'parameter': param,
                            'payload': payload,
                            'evidence': evidence,
                            'request_url': test_url,
                            'detector': 'XXEDetector.detect_xxe',
                            'response_snippet': response_snippet,
                            'remediation': remediation
                        })
                        break  # Found XXE, no need to test more payloads for this param
                        
                except Exception as e:
                    print(f"    [XXE] Error testing payload: {e}")
                    continue
        
        return results

    def _test_idor(self, parsed_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Test for IDOR vulnerabilities"""
        results = []
        base_url = parsed_data['url']
        
        # Get IDOR payloads
        idor_payloads = IDORPayloads.get_all_payloads()
        
        # Test GET parameters that look like IDs
        id_params = [param for param in parsed_data['query_params'].keys() 
                    if any(id_word in param.lower() for id_word in IDORDetector.get_idor_parameters())]
        
        for param in id_params:
            print(f"    [IDOR] Testing parameter: {param}")
            
            # Create deduplication key for this parameter
            param_key = f"idor_{base_url.split('?')[0]}_{param}"
            if param_key in self.found_vulnerabilities:
                print(f"    [IDOR] Skipping parameter {param} - already tested")
                continue
            
            try:
                # Get original response
                original_response = requests.get(
                    parsed_data['url'],
                    timeout=self.config.timeout,
                    headers=self.config.headers,
                    verify=False
                )
                
                original_value = parsed_data['query_params'][param][0]
                
                # Generate sequential payloads based on original value
                sequential_payloads = IDORPayloads.get_sequential_payloads(original_value)
                test_payloads = sequential_payloads + idor_payloads[:10]
                
                for payload in test_payloads:
                    try:
                        print(f"    [IDOR] Trying payload: {payload}")
                        
                        # Create test URL
                        test_params = parsed_data['query_params'].copy()
                        test_params[param] = [payload]
                        
                        # Build query string
                        query_parts = []
                        for k, v_list in test_params.items():
                            for v in v_list:
                                query_parts.append(f"{k}={v}")
                        
                        test_url = f"{base_url.split('?')[0]}?{'&'.join(query_parts)}"
                        
                        modified_response = requests.get(
                            test_url,
                            timeout=self.config.timeout,
                            headers=self.config.headers,
                            verify=False
                        )
                        
                        print(f"    [IDOR] Response code: {modified_response.status_code}")
                        
                        # Use IDOR detector
                        if IDORDetector.detect_idor(
                            original_response.text, modified_response.text,
                            original_response.status_code, modified_response.status_code
                        ):
                            evidence = IDORDetector.get_evidence(original_response.text, modified_response.text)
                            response_snippet = IDORDetector.get_response_snippet(modified_response.text)
                            remediation = IDORDetector.get_remediation_advice()
                            print(f"    [IDOR] VULNERABILITY FOUND! Parameter: {param}")
                            
                            # Mark as found to prevent duplicates
                            self.found_vulnerabilities.add(param_key)
                            
                            results.append({
                                'module': 'idor',
                                'target': base_url,
                                'vulnerability': 'Insecure Direct Object Reference',
                                'severity': 'High',
                                'parameter': param,
                                'payload': payload,
                                'evidence': evidence,
                                'request_url': test_url,
                                'detector': 'IDORDetector.detect_idor',
                                'response_snippet': response_snippet,
                                'remediation': remediation
                            })
                            break  # Found IDOR, no need to test more payloads for this param
                            
                    except Exception as e:
                        print(f"    [IDOR] Error testing payload: {e}")
                        continue
                        
            except Exception as e:
                print(f"    [IDOR] Error getting original response: {e}")
                continue
        
        return results

    def _test_command_injection(self, parsed_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Test for Command Injection vulnerabilities"""
        results = []
        base_url = parsed_data['url']
        
        # Get command injection payloads
        cmd_payloads = CommandInjectionPayloads.get_all_payloads()
        
        # Test GET parameters
        for param, values in parsed_data['query_params'].items():
            print(f"    [CMDINJECTION] Testing parameter: {param}")
            
            # Create deduplication key for this parameter
            param_key = f"cmdinjection_{base_url.split('?')[0]}_{param}"
            if param_key in self.found_vulnerabilities:
                print(f"    [CMDINJECTION] Skipping parameter {param} - already tested")
                continue
            
            for payload in cmd_payloads[:15]:  # Test first 15 payloads
                try:
                    print(f"    [CMDINJECTION] Trying payload: {payload}")
                    
                    # Create test URL
                    test_params = parsed_data['query_params'].copy()
                    test_params[param] = [payload]
                    
                    # Build query string
                    query_parts = []
                    for k, v_list in test_params.items():
                        for v in v_list:
                            query_parts.append(f"{k}={v}")
                    
                    test_url = f"{base_url.split('?')[0]}?{'&'.join(query_parts)}"
                    print(f"    [CMDINJECTION] Request URL: {test_url}")
                    
                    response = requests.get(
                        test_url,
                        timeout=self.config.timeout,
                        headers=self.config.headers,
                        verify=False
                    )
                    
                    print(f"    [CMDINJECTION] Response code: {response.status_code}")
                    
                    # Use Command Injection detector
                    if CommandInjectionDetector.detect_command_injection(response.text, response.status_code, payload):
                        evidence = CommandInjectionDetector.get_evidence(payload, response.text)
                        response_snippet = CommandInjectionDetector.get_response_snippet(payload, response.text)
                        remediation = CommandInjectionDetector.get_remediation_advice()
                        print(f"    [CMDINJECTION] VULNERABILITY FOUND! Parameter: {param}")
                        
                        # Mark as found to prevent duplicates
                        self.found_vulnerabilities.add(param_key)
                        
                        results.append({
                            'module': 'commandinjection',
                            'target': base_url,
                            'vulnerability': 'Command Injection',
                            'severity': 'High',
                            'parameter': param,
                            'payload': payload,
                            'evidence': evidence,
                            'request_url': test_url,
                            'detector': 'CommandInjectionDetector.detect_command_injection',
                            'response_snippet': response_snippet,
                            'remediation': remediation
                        })
                        break  # Found command injection, no need to test more payloads for this param
                        
                except Exception as e:
                    print(f"    [CMDINJECTION] Error testing payload: {e}")
                    continue
        
        return results

    def _test_path_traversal(self, parsed_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Test for Path Traversal vulnerabilities"""
        results = []
        base_url = parsed_data['url']
        
        # Path traversal payloads
        path_payloads = [
            '../../../etc/passwd',
            '..\\..\\..\\windows\\win.ini',
            '/etc/passwd',
            'C:\\windows\\win.ini',
            '....//....//....//etc/passwd',
            '....\\\\....\\\\....\\\\windows\\\\win.ini'
        ]
        
        # Test GET parameters
        for param, values in parsed_data['query_params'].items():
            print(f"    [PATHTRAVERSAL] Testing parameter: {param}")
            
            # Create deduplication key for this parameter
            param_key = f"pathtraversal_{base_url.split('?')[0]}_{param}"
            if param_key in self.found_vulnerabilities:
                print(f"    [PATHTRAVERSAL] Skipping parameter {param} - already tested")
                continue
            
            for payload in path_payloads:
                try:
                    print(f"    [PATHTRAVERSAL] Trying payload: {payload}")
                    
                    # Create test URL
                    test_params = parsed_data['query_params'].copy()
                    test_params[param] = [payload]
                    
                    # Build query string
                    query_parts = []
                    for k, v_list in test_params.items():
                        for v in v_list:
                            query_parts.append(f"{k}={v}")
                    
                    test_url = f"{base_url.split('?')[0]}?{'&'.join(query_parts)}"
                    
                    response = requests.get(
                        test_url,
                        timeout=self.config.timeout,
                        headers=self.config.headers,
                        verify=False
                    )
                    
                    print(f"    [PATHTRAVERSAL] Response code: {response.status_code}")
                    
                    # Use Path Traversal detector
                    if PathTraversalDetector.detect_path_traversal(response.text, response.status_code, payload):
                        evidence = PathTraversalDetector.get_evidence(payload, response.text)
                        response_snippet = PathTraversalDetector.get_response_snippet(payload, response.text)
                        remediation = PathTraversalDetector.get_remediation_advice()
                        print(f"    [PATHTRAVERSAL] VULNERABILITY FOUND! Parameter: {param}")
                        
                        # Mark as found to prevent duplicates
                        self.found_vulnerabilities.add(param_key)
                        
                        results.append({
                            'module': 'pathtraversal',
                            'target': base_url,
                            'vulnerability': 'Path Traversal',
                            'severity': 'High',
                            'parameter': param,
                            'payload': payload,
                            'evidence': evidence,
                            'request_url': test_url,
                            'detector': 'PathTraversalDetector.detect_path_traversal',
                            'response_snippet': response_snippet,
                            'remediation': remediation
                        })
                        break  # Found path traversal, no need to test more payloads for this param
                        
                except Exception as e:
                    print(f"    [PATHTRAVERSAL] Error testing payload: {e}")
                    continue
        
        return results

    def _test_ldap_injection(self, parsed_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Test for LDAP Injection vulnerabilities"""
        results = []
        base_url = parsed_data['url']
        
        # LDAP injection payloads
        ldap_payloads = [
            '*', '*)(&', '*))%00', '*()|%26',
            '*(|(mail=*))', '*(|(objectclass=*))',
            '*)(uid=*))(|(uid=*',
            '*)(|(cn=*))', '*)(|(sn=*))'
        ]
        
        # Test GET parameters
        for param, values in parsed_data['query_params'].items():
            print(f"    [LDAPINJECTION] Testing parameter: {param}")
            
            # Create deduplication key for this parameter
            param_key = f"ldapinjection_{base_url.split('?')[0]}_{param}"
            if param_key in self.found_vulnerabilities:
                print(f"    [LDAPINJECTION] Skipping parameter {param} - already tested")
                continue
            
            for payload in ldap_payloads:
                try:
                    print(f"    [LDAPINJECTION] Trying payload: {payload}")
                    
                    # Create test URL
                    test_params = parsed_data['query_params'].copy()
                    test_params[param] = [payload]
                    
                    # Build query string
                    query_parts = []
                    for k, v_list in test_params.items():
                        for v in v_list:
                            query_parts.append(f"{k}={v}")
                    
                    test_url = f"{base_url.split('?')[0]}?{'&'.join(query_parts)}"
                    
                    response = requests.get(
                        test_url,
                        timeout=self.config.timeout,
                        headers=self.config.headers,
                        verify=False
                    )
                    
                    print(f"    [LDAPINJECTION] Response code: {response.status_code}")
                    
                    # Use LDAP Injection detector
                    if LDAPInjectionDetector.detect_ldap_injection(response.text, response.status_code, payload):
                        evidence = LDAPInjectionDetector.get_evidence(payload, response.text)
                        response_snippet = LDAPInjectionDetector.get_response_snippet(payload, response.text)
                        remediation = LDAPInjectionDetector.get_remediation_advice()
                        print(f"    [LDAPINJECTION] VULNERABILITY FOUND! Parameter: {param}")
                        
                        # Mark as found to prevent duplicates
                        self.found_vulnerabilities.add(param_key)
                        
                        results.append({
                            'module': 'ldapinjection',
                            'target': base_url,
                            'vulnerability': 'LDAP Injection',
                            'severity': 'High',
                            'parameter': param,
                            'payload': payload,
                            'evidence': evidence,
                            'request_url': test_url,
                            'detector': 'LDAPInjectionDetector.detect_ldap_injection',
                            'response_snippet': response_snippet,
                            'remediation': remediation
                        })
                        break  # Found LDAP injection, no need to test more payloads for this param
                        
                except Exception as e:
                    print(f"    [LDAPINJECTION] Error testing payload: {e}")
                    continue
        
        return results

    def _test_nosql_injection(self, parsed_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Test for NoSQL Injection vulnerabilities"""
        results = []
        base_url = parsed_data['url']
        
        # Get NoSQL injection payloads
        nosql_payloads = NoSQLInjectionPayloads.get_all_payloads()
        
        # Test GET parameters
        for param, values in parsed_data['query_params'].items():
            print(f"    [NOSQLINJECTION] Testing parameter: {param}")
            
            # Create deduplication key for this parameter
            param_key = f"nosqlinjection_{base_url.split('?')[0]}_{param}"
            if param_key in self.found_vulnerabilities:
                print(f"    [NOSQLINJECTION] Skipping parameter {param} - already tested")
                continue
            
            for payload in nosql_payloads[:15]:  # Test first 15 payloads
                try:
                    print(f"    [NOSQLINJECTION] Trying payload: {payload[:50]}...")
                    
                    # Create test URL
                    test_params = parsed_data['query_params'].copy()
                    test_params[param] = [payload]
                    
                    # Build query string
                    query_parts = []
                    for k, v_list in test_params.items():
                        for v in v_list:
                            query_parts.append(f"{k}={v}")
                    
                    test_url = f"{base_url.split('?')[0]}?{'&'.join(query_parts)}"
                    
                    response = requests.get(
                        test_url,
                        timeout=self.config.timeout,
                        headers=self.config.headers,
                        verify=False
                    )
                    
                    print(f"    [NOSQLINJECTION] Response code: {response.status_code}")
                    
                    # Use NoSQL Injection detector
                    if NoSQLInjectionDetector.detect_nosql_injection(response.text, response.status_code, payload):
                        evidence = NoSQLInjectionDetector.get_evidence(payload, response.text)
                        response_snippet = NoSQLInjectionDetector.get_response_snippet(payload, response.text)
                        remediation = NoSQLInjectionDetector.get_remediation_advice()
                        print(f"    [NOSQLINJECTION] VULNERABILITY FOUND! Parameter: {param}")
                        
                        # Mark as found to prevent duplicates
                        self.found_vulnerabilities.add(param_key)
                        
                        results.append({
                            'module': 'nosqlinjection',
                            'target': base_url,
                            'vulnerability': 'NoSQL Injection',
                            'severity': 'High',
                            'parameter': param,
                            'payload': payload,
                            'evidence': evidence,
                            'request_url': test_url,
                            'detector': 'NoSQLInjectionDetector.detect_nosql_injection',
                            'response_snippet': response_snippet,
                            'remediation': remediation
                        })
                        break  # Found NoSQL injection, no need to test more payloads for this param
                        
                except Exception as e:
                    print(f"    [NOSQLINJECTION] Error testing payload: {e}")
                    continue
        
        return results

    def _test_file_upload(self, parsed_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Test for File Upload vulnerabilities"""
        results = []
        base_url = parsed_data['url']
        
        try:
            print(f"    [FILEUPLOAD] Testing for file upload vulnerabilities...")
            
            # Make request to get page content
            response = requests.get(
                base_url,
                timeout=self.config.timeout,
                headers=self.config.headers,
                verify=False
            )
            
            print(f"    [FILEUPLOAD] Response code: {response.status_code}")
            
            # Use File Upload detector
            is_vulnerable, evidence, severity = FileUploadDetector.detect_file_upload_vulnerability(
                response.text, response.status_code, base_url
            )
            
            if is_vulnerable:
                print(f"    [FILEUPLOAD] VULNERABILITY FOUND! {evidence}")
                
                response_snippet = FileUploadDetector.get_response_snippet(response.text)
                remediation = FileUploadDetector.get_remediation_advice()
                
                results.append({
                    'module': 'fileupload',
                    'target': base_url,
                    'vulnerability': 'File Upload Vulnerability',
                    'severity': severity,
                    'parameter': 'file_upload_form',
                    'payload': 'N/A',
                    'evidence': evidence,
                    'request_url': base_url,
                    'detector': 'FileUploadDetector.detect_file_upload_vulnerability',
                    'response_snippet': response_snippet,
                    'remediation': remediation
                })
            else:
                print(f"    [FILEUPLOAD] No file upload vulnerabilities found")
            
        except Exception as e:
            print(f"    [FILEUPLOAD] Error during file upload testing: {e}")
        
        return results

    def _test_cors(self, parsed_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Test for CORS misconfigurations"""
        results = []
        base_url = parsed_data['url']
        
        try:
            print(f"    [CORS] Testing CORS configuration...")
            
            # Test with different Origin headers
            test_origins = [
                'http://evil.com',
                'https://attacker.com',
                'null',
                'http://localhost',
                base_url  # Same origin
            ]
            
            for origin in test_origins:
                try:
                    headers = self.config.headers.copy()
                    headers['Origin'] = origin
                    
                    response = requests.get(
                        base_url,
                        timeout=self.config.timeout,
                        headers=headers,
                        verify=False
                    )
                    
                    print(f"    [CORS] Testing origin {origin}: {response.status_code}")
                    
                    # Use CORS detector
                    is_vulnerable, evidence, severity, issues = CORSDetector.detect_cors_misconfiguration(
                        dict(response.headers), origin
                    )
                    
                    if is_vulnerable:
                        print(f"    [CORS] CORS MISCONFIGURATION FOUND! {evidence}")
                        
                        detailed_evidence = CORSDetector.get_evidence(issues, dict(response.headers))
                        
                        for issue in issues:
                            remediation = CORSDetector.get_remediation_advice(issue['issue'])
                            
                            results.append({
                                'module': 'cors',
                                'target': base_url,
                                'vulnerability': f'CORS Misconfiguration: {issue["issue"]}',
                                'severity': issue['severity'],
                                'parameter': f'origin: {origin}',
                                'payload': origin,
                                'evidence': detailed_evidence,
                                'request_url': base_url,
                                'detector': 'CORSDetector.detect_cors_misconfiguration',
                                'response_snippet': f'Access-Control-Allow-Origin: {response.headers.get("Access-Control-Allow-Origin", "Not set")}',
                                'remediation': remediation
                            })
                        break  # Found CORS issue, no need to test more origins
                        
                except Exception as e:
                    print(f"    [CORS] Error testing origin {origin}: {e}")
                    continue
            
            if not results:
                print(f"    [CORS] No CORS misconfigurations found")
            
        except Exception as e:
            print(f"    [CORS] Error during CORS testing: {e}")
        
        return results

    def _test_jwt(self, parsed_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Test for JWT vulnerabilities"""
        results = []
        base_url = parsed_data['url']
        
        try:
            print(f"    [JWT] Testing for JWT vulnerabilities...")
            
            # Make request to get response
            response = requests.get(
                base_url,
                timeout=self.config.timeout,
                headers=self.config.headers,
                verify=False
            )
            
            print(f"    [JWT] Response code: {response.status_code}")
            
            # Use JWT detector
            is_vulnerable, evidence, severity, issues = JWTDetector.detect_jwt_vulnerabilities(
                response.text, dict(response.headers), base_url
            )
            
            if is_vulnerable and issues:
                print(f"    [JWT] JWT VULNERABILITIES FOUND! {evidence}")
                
                tokens_found = len(re.findall(r'eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*', response.text))
                detailed_evidence = JWTDetector.get_evidence(issues, tokens_found)
                response_snippet = JWTDetector.get_response_snippet(response.text)
                
                for issue in issues:
                    remediation = JWTDetector.get_remediation_advice(issue['issue'])
                    
                    results.append({
                        'module': 'jwt',
                        'target': base_url,
                        'vulnerability': f'JWT Vulnerability: {issue["issue"]}',
                        'severity': issue['severity'],
                        'parameter': 'jwt_token',
                        'payload': 'N/A',
                        'evidence': detailed_evidence,
                        'request_url': base_url,
                        'detector': 'JWTDetector.detect_jwt_vulnerabilities',
                        'response_snippet': response_snippet,
                        'remediation': remediation
                    })
            elif is_vulnerable:
                print(f"    [JWT] JWT tokens found - manual analysis recommended")
                
                results.append({
                    'module': 'jwt',
                    'target': base_url,
                    'vulnerability': 'JWT Tokens Detected',
                    'severity': 'Info',
                    'parameter': 'jwt_token',
                    'payload': 'N/A',
                    'evidence': evidence,
                    'request_url': base_url,
                    'detector': 'JWTDetector.detect_jwt_vulnerabilities',
                    'response_snippet': JWTDetector.get_response_snippet(response.text)
                })
            else:
                print(f"    [JWT] No JWT tokens found")
            
        except Exception as e:
            print(f"    [JWT] Error during JWT testing: {e}")
        
        return results

    def _test_insecure_deserialization(self, parsed_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Test for Insecure Deserialization vulnerabilities"""
        results = []
        base_url = parsed_data['url']
        
        # Deserialization payloads
        deser_payloads = [
            'rO0ABXNyABFqYXZhLnV0aWwuSGFzaE1hcA==',  # Java serialized HashMap
            'O:8:"stdClass":0:{}',  # PHP serialized object
            'a:1:{s:4:"test";s:4:"test";}',  # PHP serialized array
            'YToxOntzOjQ6InRlc3QiO3M6NDoidGVzdCI7fQ==',  # Base64 PHP serialized
        ]
        
        # Test GET parameters
        for param, values in parsed_data['query_params'].items():
            print(f"    [DESERIALIZATION] Testing parameter: {param}")
            
            # Create deduplication key for this parameter
            param_key = f"deserialization_{base_url.split('?')[0]}_{param}"
            if param_key in self.found_vulnerabilities:
                print(f"    [DESERIALIZATION] Skipping parameter {param} - already tested")
                continue
            
            for payload in deser_payloads:
                try:
                    print(f"    [DESERIALIZATION] Trying payload: {payload[:30]}...")
                    
                    # Create test URL
                    test_params = parsed_data['query_params'].copy()
                    test_params[param] = [payload]
                    
                    # Build query string
                    query_parts = []
                    for k, v_list in test_params.items():
                        for v in v_list:
                            query_parts.append(f"{k}={v}")
                    
                    test_url = f"{base_url.split('?')[0]}?{'&'.join(query_parts)}"
                    
                    response = requests.get(
                        test_url,
                        timeout=self.config.timeout,
                        headers=self.config.headers,
                        verify=False
                    )
                    
                    print(f"    [DESERIALIZATION] Response code: {response.status_code}")
                    
                    # Use Insecure Deserialization detector
                    is_vulnerable, evidence, severity = InsecureDeserializationDetector.detect_insecure_deserialization(
                        response.text, response.status_code, payload
                    )
                    
                    if is_vulnerable:
                        response_snippet = InsecureDeserializationDetector.get_response_snippet(payload, response.text)
                        remediation = InsecureDeserializationDetector.get_remediation_advice()
                        print(f"    [DESERIALIZATION] VULNERABILITY FOUND! Parameter: {param}")
                        
                        # Mark as found to prevent duplicates
                        self.found_vulnerabilities.add(param_key)
                        
                        results.append({
                            'module': 'deserialization',
                            'target': base_url,
                            'vulnerability': 'Insecure Deserialization',
                            'severity': severity,
                            'parameter': param,
                            'payload': payload,
                            'evidence': evidence,
                            'request_url': test_url,
                            'detector': 'InsecureDeserializationDetector.detect_insecure_deserialization',
                            'response_snippet': response_snippet,
                            'remediation': remediation
                        })
                        break  # Found deserialization issue, no need to test more payloads for this param
                        
                except Exception as e:
                    print(f"    [DESERIALIZATION] Error testing payload: {e}")
                    continue
        
        return results

    def _test_http_response_splitting(self, parsed_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Test for HTTP Response Splitting vulnerabilities"""
        results = []
        base_url = parsed_data['url']
        
        # HTTP Response Splitting payloads
        splitting_payloads = [
            '%0d%0aSet-Cookie: test=injected',
            '%0d%0aLocation: http://evil.com',
            '%0aSet-Cookie: test=injected',
            '\r\nSet-Cookie: test=injected',
            '\nSet-Cookie: test=injected',
            '%0d%0a%0d%0a<script>alert("XSS")</script>',
            '%0a%0a<script>alert("XSS")</script>'
        ]
        
        # Test GET parameters
        for param, values in parsed_data['query_params'].items():
            print(f"    [RESPONSESPLITTING] Testing parameter: {param}")
            
            # Create deduplication key for this parameter
            param_key = f"responsesplitting_{base_url.split('?')[0]}_{param}"
            if param_key in self.found_vulnerabilities:
                print(f"    [RESPONSESPLITTING] Skipping parameter {param} - already tested")
                continue
            
            for payload in splitting_payloads:
                try:
                    print(f"    [RESPONSESPLITTING] Trying payload: {payload}")
                    
                    # Create test URL
                    test_params = parsed_data['query_params'].copy()
                    test_params[param] = [payload]
                    
                    # Build query string
                    query_parts = []
                    for k, v_list in test_params.items():
                        for v in v_list:
                            query_parts.append(f"{k}={v}")
                    
                    test_url = f"{base_url.split('?')[0]}?{'&'.join(query_parts)}"
                    
                    response = requests.get(
                        test_url,
                        timeout=self.config.timeout,
                        headers=self.config.headers,
                        verify=False
                    )
                    
                    print(f"    [RESPONSESPLITTING] Response code: {response.status_code}")
                    
                    # Use HTTP Response Splitting detector
                    if HTTPResponseSplittingDetector.detect_response_splitting(
                        response.text, response.status_code, payload, dict(response.headers)
                    ):
                        evidence = HTTPResponseSplittingDetector.get_evidence(payload, response.text, dict(response.headers))
                        response_snippet = HTTPResponseSplittingDetector.get_response_snippet(payload, response.text)
                        remediation = HTTPResponseSplittingDetector.get_remediation_advice()
                        print(f"    [RESPONSESPLITTING] VULNERABILITY FOUND! Parameter: {param}")
                        
                        # Mark as found to prevent duplicates
                        self.found_vulnerabilities.add(param_key)
                        
                        results.append({
                            'module': 'responsesplitting',
                            'target': base_url,
                            'vulnerability': 'HTTP Response Splitting',
                            'severity': 'High',
                            'parameter': param,
                            'payload': payload,
                            'evidence': evidence,
                            'request_url': test_url,
                            'detector': 'HTTPResponseSplittingDetector.detect_response_splitting',
                            'response_snippet': response_snippet,
                            'remediation': remediation
                        })
                        break  # Found response splitting, no need to test more payloads for this param
                        
                except Exception as e:
                    print(f"    [RESPONSESPLITTING] Error testing payload: {e}")
                    continue
        
        return results

    def _get_important_pages(self) -> List[str]:
        """Get list of important pages that might contain forms"""
        # Use DirBrutePayloads to get common files instead of hardcoded list
        common_files = DirBrutePayloads.get_common_files()
        important_pages = []
        
        for file in common_files:
            if any(keyword in file.lower() for keyword in ['login', 'admin', 'register', 'contact', 'guestbook']):
                important_pages.append(f'/{file}')
        
        return important_pages[:20]  # Limit to first 20 important pages
    
    def _get_success_indicators(self) -> List[str]:
        """Get indicators that suggest a request was successful"""
        return [
            'success', 'successful', 'completed', 'saved', 'updated', 'created',
            'added', 'submitted', 'processed', 'confirmed', 'accepted',
            'thank you', 'thanks', 'welcome', 'congratulations',
            'успешно', 'сохранено', 'обновлено', 'создано', 'добавлено',
            'спасибо', 'поздравляем', 'добро пожаловать'
        ]
    
    def _is_likely_404_response(self, response_text: str, response_code: int) -> bool:
        """Quick check if response is likely a 404 page"""
        if response_code == 404:
            return True
        
        # For testphp.vulnweb.com, don't filter out responses based on content
        # as it may contain legitimate vulnerabilities
        return False
    
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
        print(f"Scan Duration:        {stats.get('scan_duration', '0s')}")
        print(f"Total Requests:       {stats.get('total_requests', 0)}")
        print(f"URLs Discovered:      {stats.get('total_urls', 0)}")
        print(f"Parameters Tested:    {stats.get('total_params', 0)}")
        print(f"Modules Used:         {', '.join(self.config.modules)}")
        print(f"Threads:              {self.config.threads}")
        print("-" * 80)
        
        if not vulnerabilities:
            print("VULNERABILITY STATUS: CLEAN")
            print("No vulnerabilities found during the scan.")
            print("="*80)
            return
        
        # Filter out scan stats and group by severity
        vulnerabilities = [v for v in results if 'vulnerability' in v]
        high_vulns = [v for v in vulnerabilities if v.get('severity', '').lower() == 'high']
        medium_vulns = [v for v in vulnerabilities if v.get('severity', '').lower() == 'medium']
        low_vulns = [v for v in vulnerabilities if v.get('severity', '').lower() == 'low']
        info_vulns = [v for v in vulnerabilities if v.get('severity', '').lower() == 'info']
        
        print(f"VULNERABILITY STATUS: {len(vulnerabilities)} ISSUES FOUND")
        print(f"High Severity:        {len(high_vulns)}")
        print(f"Medium Severity:      {len(medium_vulns)}")
        print(f"Low Severity:         {len(low_vulns)}")
        print(f"Info:                 {len(info_vulns)}")
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
