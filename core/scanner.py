"""
Main vulnerability scanner class
"""

import time
import json
import re
import requests
import urllib3
import html
from urllib.parse import quote_plus
from typing import List, Dict, Any
from concurrent.futures import ThreadPoolExecutor, as_completed

from core.config import Config
from core.url_parser import URLParser
from core.crawler import WebCrawler
from utils.file_handler import FileHandler
from utils.screenshot_handler import ScreenshotHandler
from libs.false_positive_filter import FalsePositiveFilter
from libs.response_analyzer import ResponseAnalyzer
from libs.path_manager import PathManager
# Import payload classes with error handling
try:
    from payloads.xss_payloads import XSSPayloads
    from payloads.sqli_payloads import SQLiPayloads
    from payloads.lfi_payloads import LFIPayloads
    from payloads.csrf_payloads import CSRFPayloads
    from payloads.dirbrute_payloads import DirBrutePayloads
    from utils.payload_loader import PayloadLoader
except ImportError as e:
    print(f"Warning: Could not import payload classes: {e}")
    # Create dummy classes to prevent crashes
    class DummyPayloads:
        @staticmethod
        def get_all_payloads():
            return ["'", '"', "<script>alert(1)</script>"]
    
    XSSPayloads = SQLiPayloads = LFIPayloads = CSRFPayloads = DummyPayloads
    DirBrutePayloads = DummyPayloads
    
    class PayloadLoader:
        @staticmethod
        def load_payloads(payload_type):
            return ["'", '"', "<script>alert(1)</script>"]
        @staticmethod
        def get_vulnerability_metadata(module_name, severity='Medium'):
            return {'cwe': 'CWE-200', 'owasp': 'A06:2021', 'cvss': '6.5', 'recommendation': 'Fix vulnerability'}

try:
    from payloads.git_payloads import GitPayloads
except ImportError:
    class GitPayloads:
        @staticmethod
        def get_all_git_payloads():
            return ['.git/', '.git/config', '.git/HEAD', '.git/index', '.git/logs/HEAD']

try:
    from payloads.directory_traversal_payloads import DirectoryTraversalPayloads
    from payloads.ssrf_payloads import SSRFPayloads
    from payloads.rfi_payloads import RFIPayloads
    from payloads.blind_xss_payloads import BlindXSSPayloads
    from payloads.phpinfo_payloads import PHPInfoPayloads
    from payloads.xxe_payloads import XXEPayloads
    from payloads.command_injection_payloads import CommandInjectionPayloads
    from payloads.idor_payloads import IDORPayloads
    from payloads.nosql_injection_payloads import NoSQLInjectionPayloads
    from payloads.ssti_payloads import SSTIPayloads
    from payloads.crlf_payloads import CRLFPayloads
    from payloads.textinjection_payloads import TextInjectionPayloads
    from payloads.htmlinjection_payloads import HTMLInjectionPayloads
except ImportError as e:
    print(f"Warning: Could not import payload classes: {e}")
    # Create dummy classes to prevent crashes
    class DummyPayloads:
        @staticmethod
        def get_all_payloads():
            return ["'", '"', "<script>alert(1)</script>"]
    
    XSSPayloads = SQLiPayloads = LFIPayloads = CSRFPayloads = DummyPayloads
    DirBrutePayloads = DirectoryTraversalPayloads = DummyPayloads
    if 'GitPayloads' not in locals():
        GitPayloads = DummyPayloads
    SSRFPayloads = RFIPayloads = BlindXSSPayloads = PHPInfoPayloads = DummyPayloads
    XXEPayloads = CommandInjectionPayloads = IDORPayloads = NoSQLInjectionPayloads = DummyPayloads
    SSTIPayloads = CRLFPayloads = TextInjectionPayloads = HTMLInjectionPayloads = DummyPayloads

# Import detector classes with error handling
try:
    from detectors.xss_detector import XSSDetector
except ImportError:
    class XSSDetector:
        @staticmethod
        def detect_reflected_xss(payload, response_text, response_code):
            return payload.lower() in response_text.lower()

try:
    from detectors.sqli_detector import SQLiDetector
except ImportError:
    class SQLiDetector:
        @staticmethod
        def detect_error_based_sqli(response_text, response_code):
            sql_errors = ['mysql', 'sql syntax', 'ora-', 'postgresql']
            return any(error in response_text.lower() for error in sql_errors), "SQL error detected"

try:
    from detectors.lfi_detector import LFIDetector
except ImportError:
    class LFIDetector:
        @staticmethod
        def detect_lfi(response_text, response_code):
            lfi_indicators = ['root:', '[extensions]', '<?php']
            return any(indicator in response_text for indicator in lfi_indicators), "File inclusion detected"

try:
    from detectors.csrf_detector import CSRFDetector
except ImportError:
    class CSRFDetector:
        @staticmethod
        def get_csrf_indicators():
            return ['csrf_token', '_token', 'authenticity_token']

try:
    from detectors.dirbrute_detector import DirBruteDetector
except ImportError:
    class DirBruteDetector:
        @staticmethod
        def is_valid_response(response_text, response_code, content_length, baseline_404=None, baseline_size=0):
            return response_code == 200, f"HTTP {response_code}"

try:
    from detectors.real404_detector import Real404Detector
except ImportError:
    class Real404Detector:
        @staticmethod
        def generate_baseline_404(base_url, session=None):
            return "", 0
        @staticmethod
        def detect_real_404(response_text, response_code, content_length, baseline_404=None, baseline_size=0):
            return response_code == 404, "404 detected", 1.0

try:
    from detectors.git_detector import GitDetector
except ImportError:
    class GitDetector:
        @staticmethod
        def detect_git_exposure(response_text, response_code, url):
            return '.git' in response_text, "Git content detected", "High"
        @staticmethod
        def get_evidence(file_type, response_text):
            return f"Git exposure detected: {file_type}"
        @staticmethod
        def get_response_snippet(response_text, max_length=300):
            return response_text[:max_length] + "..." if len(response_text) > max_length else response_text
        @staticmethod
        def get_remediation_advice(git_path):
            return "Remove .git directory from web-accessible locations"

try:
    from detectors.directory_traversal_detector import DirectoryTraversalDetector
except ImportError:
    class DirectoryTraversalDetector:
        @staticmethod
        def detect_directory_traversal(response_text, response_code, payload):
            return 'root:' in response_text or '[extensions]' in response_text

try:
    from detectors.security_headers_detector import SecurityHeadersDetector
except ImportError:
    class SecurityHeadersDetector:
        @staticmethod
        def detect_missing_security_headers(headers):
            return []
        @staticmethod
        def detect_insecure_cookies(headers):
            return []

try:
    from detectors.ssrf_detector import SSRFDetector
except ImportError:
    class SSRFDetector:
        @staticmethod
        def detect_ssrf(response_text, response_code, payload):
            return 'localhost' in response_text or '127.0.0.1' in response_text

try:
    from detectors.rfi_detector import RFIDetector
except ImportError:
    class RFIDetector:
        @staticmethod
        def detect_rfi(response_text, response_code, payload):
            return 'http://' in payload and '<?php' in response_text

try:
    from detectors.version_disclosure_detector import VersionDisclosureDetector
except ImportError:
    class VersionDisclosureDetector:
        @staticmethod
        def detect_version_disclosure(response_text, headers):
            return []
        @staticmethod
        def get_severity(software, version):
            return "Medium"

try:
    from detectors.clickjacking_detector import ClickjackingDetector
except ImportError:
    class ClickjackingDetector:
        @staticmethod
        def detect_clickjacking(headers):
            return {'vulnerable': 'X-Frame-Options' not in headers, 'evidence': 'Missing X-Frame-Options'}

try:
    from detectors.blind_xss_detector import BlindXSSDetector
except ImportError:
    class BlindXSSDetector:
        @staticmethod
        def detect_blind_xss(payload, response_text, response_code, callback_received=False):
            return callback_received

try:
    from detectors.stored_xss_detector import StoredXSSDetector
except ImportError:
    class StoredXSSDetector:
        @staticmethod
        def get_stored_xss_indicators():
            return ['<script>alert("StoredXSS")</script>', '<img src=x onerror=alert("StoredXSS")>', 'javascript:alert("StoredXSS")']
        @staticmethod
        def detect_stored_xss(payload, response_text, response_code):
            return payload.lower() in response_text.lower()

try:
    from detectors.password_over_http_detector import PasswordOverHTTPDetector
except ImportError:
    class PasswordOverHTTPDetector:
        @staticmethod
        def detect_password_over_http(url, response_text, response_code):
            return url.startswith('http://') and 'password' in response_text.lower(), "HTTP password form", []

try:
    from detectors.outdated_software_detector import OutdatedSoftwareDetector
except ImportError:
    class OutdatedSoftwareDetector:
        @staticmethod
        def detect_outdated_software(headers, response_text):
            return []

try:
    from detectors.database_error_detector import DatabaseErrorDetector
except ImportError:
    class DatabaseErrorDetector:
        @staticmethod
        def detect_database_errors(response_text, response_code):
            return False, '', '', []

try:
    from detectors.phpinfo_detector import PHPInfoDetector
except ImportError:
    class PHPInfoDetector:
        @staticmethod
        def detect_phpinfo_exposure(response_text, response_code, url):
            return 'phpinfo' in response_text.lower(), "PHPInfo detected", "High"

try:
    from detectors.ssl_tls_detector import SSLTLSDetector
except ImportError:
    class SSLTLSDetector:
        @staticmethod
        def detect_ssl_tls_implementation(url):
            return url.startswith('https://'), "HTTPS detected", "Low", {}

try:
    from detectors.httponly_cookie_detector import HttpOnlyCookieDetector
except ImportError:
    class HttpOnlyCookieDetector:
        @staticmethod
        def detect_httponly_cookies(headers):
            return []

try:
    import warnings
    # Suppress Wappalyzer regex warnings
    with warnings.catch_warnings():
        warnings.filterwarnings("ignore", category=UserWarning, module="Wappalyzer")
        from Wappalyzer import Wappalyzer, WebPage
except ImportError:
    class Wappalyzer:
        @staticmethod
        def latest():
            return Wappalyzer()
        def analyze(self, webpage):
            return []
    class WebPage:
        @staticmethod
        def new_from_response(response):
            return WebPage()

try:
    from detectors.xxe_detector import XXEDetector
except ImportError:
    class XXEDetector:
        @staticmethod
        def detect_xxe(response_text, response_code, payload):
            return 'ENTITY' in payload and 'root:' in response_text

try:
    from detectors.idor_detector import IDORDetector
except ImportError:
    class IDORDetector:
        @staticmethod
        def get_idor_parameters():
            return ['id', 'user_id', 'userid']
        @staticmethod
        def detect_idor(orig_response, mod_response, orig_code, mod_code):
            return orig_response != mod_response

try:
    from detectors.command_injection_detector import CommandInjectionDetector
except ImportError:
    class CommandInjectionDetector:
        @staticmethod
        def detect_command_injection(response_text, response_code, payload):
            return 'uid=' in response_text or 'Volume in drive' in response_text
        @staticmethod
        def get_evidence(payload, response_text):
            return f"Command injection detected with payload: {payload}"
        @staticmethod
        def get_response_snippet(payload, response_text):
            return response_text[:200] + "..." if len(response_text) > 200 else response_text
        @staticmethod
        def get_remediation_advice():
            return "Avoid executing system commands with user input. Use parameterized APIs."

try:
    from detectors.path_traversal_detector import PathTraversalDetector
except ImportError:
    class PathTraversalDetector:
        @staticmethod
        def detect_path_traversal(response_text, response_code, payload):
            return 'root:' in response_text or '[extensions]' in response_text

try:
    from detectors.ldap_injection_detector import LDAPInjectionDetector
except ImportError:
    class LDAPInjectionDetector:
        @staticmethod
        def detect_ldap_injection(response_text, response_code, payload):
            return 'ldap' in response_text.lower()

try:
    from detectors.nosql_injection_detector import NoSQLInjectionDetector
except ImportError:
    class NoSQLInjectionDetector:
        @staticmethod
        def detect_nosql_injection(response_text, response_code, payload):
            return 'mongodb' in response_text.lower()

try:
    from detectors.file_upload_detector import FileUploadDetector
except ImportError:
    class FileUploadDetector:
        @staticmethod
        def detect_file_upload_vulnerability(response_text, response_code, url):
            return 'type="file"' in response_text, "File upload form detected", "Medium"

try:
    from detectors.cors_detector import CORSDetector
except ImportError:
    class CORSDetector:
        @staticmethod
        def detect_cors_misconfiguration(headers, origin=None):
            return False, "No CORS issues", "None", []

try:
    from detectors.jwt_detector import JWTDetector
except ImportError:
    class JWTDetector:
        @staticmethod
        def detect_jwt_vulnerabilities(response_text, headers, url):
            return 'eyJ' in response_text, "JWT token found", "Low", []

try:
    from detectors.insecure_deserialization_detector import InsecureDeserializationDetector
except ImportError:
    class InsecureDeserializationDetector:
        @staticmethod
        def detect_insecure_deserialization(response_text, response_code, payload):
            return False, "No deserialization detected", "None"

try:
    from detectors.http_response_splitting_detector import HTTPResponseSplittingDetector
except ImportError:
    class HTTPResponseSplittingDetector:
        @staticmethod
        def detect_response_splitting(response_text, response_code, payload, headers):
            return '\r\n' in response_text

try:
    from detectors.ssti_detector import SSTIDetector
except ImportError:
    class SSTIDetector:
        @staticmethod
        def detect_ssti(response_text, response_code, payload):
            return '49' in response_text and '7*7' in payload

try:
    from detectors.crlf_detector import CRLFDetector
except ImportError:
    class CRLFDetector:
        @staticmethod
        def detect_crlf_injection(response_text, response_code, payload, headers):
            return '\r\n' in response_text or '%0d%0a' in payload

try:
    from detectors.textinjection_detector import TextInjectionDetector
except ImportError:
    class TextInjectionDetector:
        @staticmethod
        def detect_text_injection(response_text, response_code, payload):
            return payload in response_text
        @staticmethod
        def get_evidence(payload, response_text):
            return f"Text injection detected with payload: {payload}"
        @staticmethod
        def get_response_snippet(payload, response_text):
            return response_text[:200] + "..." if len(response_text) > 200 else response_text
        @staticmethod
        def get_remediation_advice():
            return "Implement proper input validation and output encoding."

try:
    from detectors.htmlinjection_detector import HTMLInjectionDetector
except ImportError:
    class HTMLInjectionDetector:
        @staticmethod
        def detect_html_injection(response_text, response_code, payload):
            return payload in response_text and '<' in payload and '>' in payload
        @staticmethod
        def get_evidence(payload, response_text):
            return f"HTML injection detected with payload: {payload}"
        @staticmethod
        def get_response_snippet(payload, response_text):
            return response_text[:200] + "..." if len(response_text) > 200 else response_text
        @staticmethod
        def get_remediation_advice():
            return "Implement proper HTML encoding and Content Security Policy (CSP)."

try:
    from detectors.host_header_detector import HostHeaderDetector
except ImportError:
    class HostHeaderDetector:
        @staticmethod
        def detect_host_header_injection(base_url, headers, timeout=10):
            return False, "Host header detector not available", "Info", []

try:
    from detectors.prototype_pollution_detector import PrototypePollutionDetector
except ImportError:
    class PrototypePollutionDetector:
        @staticmethod
        def detect_prototype_pollution(url, headers, timeout=10):
            return False, "Prototype pollution detector not available", "Info", []

try:
    from detectors.vhost_detector import VHostDetector
except ImportError:
    class VHostDetector:
        @staticmethod
        def detect_virtual_hosts(base_url, headers, timeout=10):
            return False, "VHost detector not available", "Info", []

# Disable SSL warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class VulnScanner:
    """Main vulnerability scanner class"""
    
    def __init__(self, config: Config):
        """Initialize scanner"""
        self.config = config
        self.debug = getattr(config, 'debug', False)
        self.payload_limit = getattr(config, 'payload_limit', 0)
        self.url_parser = URLParser()
        self.crawler = WebCrawler(config)
        self.file_handler = FileHandler()
        self.screenshot_handler = ScreenshotHandler()
        self.false_positive_filter = FalsePositiveFilter()
        self.response_analyzer = ResponseAnalyzer()
        self.path_manager = PathManager()
        self.results = []
        self.request_count = 0
        self.found_vulnerabilities = set()  # For deduplication
        self.tested_domains_ssl = set()  # For SSL/TLS deduplication
        self.scan_stats = {
            'total_requests': 0,
            'total_urls': 0,
            'total_params': 0,
            'total_forms': 0,
            'total_payloads_used': 0,
            'total_ajax_endpoints': 0,
            'total_js_files': 0,
            'scan_duration': '0s',
            'start_time': None,
            'end_time': None,
            'technologies': {},
            'module_stats': {},
            'payload_stats': {}
        }
        self.stop_requested = False  # Flag for graceful stopping
        
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
                if self._should_stop() or self.stop_requested:
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
    
    def _build_test_url(self, base_url: str, test_params: Dict[str, List[str]]) -> str:
        """Build properly encoded test URL"""
        query_parts = []
        for k, v_list in test_params.items():
            for v in v_list:
                query_parts.append(f"{quote_plus(k)}={quote_plus(str(v))}")
        
        return f"{base_url.split('?')[0]}?{'&'.join(query_parts)}"
    
    def _scan_target(self, target: str) -> List[Dict[str, Any]]:
        """Scan single target"""
        target_results = []
        all_found_pages = []  # Collect all pages for comprehensive testing
        
        try:
            print(f"Scanning: {target}")
            
            # Parse URL and extract injection points
            parsed_data = self.url_parser.parse(target)
            
            # Test connectivity first
            if not self._test_connectivity(parsed_data['url']):
                print(f"  Cannot connect to {target}")
                return target_results
            
            # Debug: Show detected URL and parameters
            if self.debug:
                print(f"  [DEBUG] Parsed URL: {parsed_data['url']}")
                print(f"  [DEBUG] Host: {parsed_data['host']}")
                print(f"  [DEBUG] Path: {parsed_data['path']}")
                print(f"  [DEBUG] Query parameters: {list(parsed_data['query_params'].keys())}")
            
            # If no parameters found but URL has query string, try manual parsing
            if not parsed_data['query_params'] and '?' in parsed_data['url']:
                if self.debug:
                    print(f"  [DEBUG] Manual parameter extraction from URL...")
                from urllib.parse import urlparse, parse_qs
                parsed_url = urlparse(parsed_data['url'])
                if parsed_url.query:
                    manual_params = parse_qs(parsed_url.query, keep_blank_values=True)
                    parsed_data['query_params'] = manual_params
                    if self.debug:
                        print(f"  [DEBUG] Manually extracted parameters: {list(manual_params.keys())}")
            
            
            # Update stats
            self.scan_stats['total_urls'] += 1
            self.scan_stats['total_params'] += len(parsed_data['query_params'])
            
            # Add main page to testing list
            all_found_pages.append(parsed_data)
            
            # Always enable crawling unless explicitly disabled with --single-url or --nocrawl
            skip_crawling = getattr(self.config, 'single_url', False) or getattr(self.config, 'nocrawl', False)
            
            if not skip_crawling:
                # Always crawl for additional pages
                if self.debug:
                    print(f"  [DEBUG] Starting enhanced crawler to find additional pages...")
                crawled_urls = self.crawler.crawl_for_pages(parsed_data['url'])
                
                # Update crawler stats
                self.scan_stats['total_ajax_endpoints'] = len(self.crawler.get_ajax_endpoints())
                self.scan_stats['total_js_files'] = len(self.crawler.js_urls)
                
                if crawled_urls:
                    if self.debug:
                        print(f"  [DEBUG] Crawler found {len(crawled_urls)} additional pages")
                    for url in crawled_urls:
                        crawled_data = self.url_parser.parse(url)
                        all_found_pages.append(crawled_data)
                        
                        # Update stats
                        self.scan_stats['total_urls'] += 1
                        self.scan_stats['total_params'] += len(crawled_data['query_params'])
                else:
                    if self.debug:
                        print(f"  [DEBUG] No additional pages found by crawler")
                
                # Only test pages that were actually discovered by the crawler
                if self.debug:
                    print(f"  [DEBUG] Using only crawler-discovered pages")
            else:
                if self.debug:
                    if getattr(self.config, 'single_url', False):
                        print(f"  [DEBUG] Single URL mode enabled - skipping crawler")
                    elif getattr(self.config, 'nocrawl', False):
                        print(f"  [DEBUG] No-crawl mode enabled - skipping crawler")
                    else:
                        print(f"  [DEBUG] Crawling disabled by configuration")
            
            # Collect file tree data if filetree is enabled
            if getattr(self.config, 'filetree', False):
                file_paths = set()
            
                # Collect paths from crawled pages
                for page_data in all_found_pages:
                    if page_data.get('url'):
                        try:
                            from urllib.parse import urlparse
                            parsed_url = urlparse(page_data['url'])
                            if parsed_url.path and parsed_url.path != '/':
                                file_paths.add(parsed_url.path)
                        except:
                            pass
            
                # Collect paths from crawler if available
                if hasattr(self.crawler, 'found_urls') and self.crawler.found_urls:
                    for url in self.crawler.found_urls:
                        try:
                            from urllib.parse import urlparse
                            parsed_url = urlparse(url)
                            if parsed_url.path and parsed_url.path != '/':
                                file_paths.add(parsed_url.path)
                        except:
                            pass
            
                # Collect paths from dirbrute results if dirbrute was run
                for result in target_results:
                    if result.get('module') == 'dirbrute' and result.get('request_url'):
                        try:
                            from urllib.parse import urlparse
                            parsed_url = urlparse(result['request_url'])
                            if parsed_url.path and parsed_url.path != '/':
                                file_paths.add(parsed_url.path)
                        except:
                            pass
        
                # Store file tree data in scan stats
                if file_paths:
                    self.scan_stats['file_tree_paths'] = sorted(list(file_paths))
                    if self.debug:
                        print(f"  [DEBUG] Collected {len(file_paths)} file paths for tree structure")
                else:
                    if self.debug:
                        print(f"  [DEBUG] No file paths found for tree structure")
        
            # Now test ALL found pages with ALL modules
            if self.debug:
                print(f"  [DEBUG] Testing {len(all_found_pages)} total pages with all modules")
        
            for page_data in all_found_pages:
                # Extract forms if not already done
                if 'forms' not in page_data:
                    try:
                        response = requests.get(page_data['url'], timeout=10, verify=False)
                        if response.status_code == 200:
                            forms = self.url_parser.extract_forms(response.text)
                            page_data['forms'] = forms
                            self.scan_stats['total_forms'] += len(forms)
                    except:
                        page_data['forms'] = []
            
                # Test each module on this page
                for module_name in self.config.modules:
                    if self._should_stop() or self.stop_requested:
                        break
                
                    # Initialize module stats if not exists
                    if module_name not in self.scan_stats['module_stats']:
                        self.scan_stats['module_stats'][module_name] = {
                            'pages_tested': 0,
                            'parameters_tested': 0,
                            'forms_tested': 0,
                            'vulnerabilities_found': 0
                        }
                
                    # Update module stats
                    self.scan_stats['module_stats'][module_name]['pages_tested'] += 1
                    self.scan_stats['module_stats'][module_name]['parameters_tested'] += len(page_data['query_params'])
                    self.scan_stats['module_stats'][module_name]['forms_tested'] += len(page_data.get('forms', []))
                
                    if self.debug:
                        print(f"  [DEBUG] Testing {module_name.upper()} on {page_data['url']}")
                    module_results = self._run_module(module_name, page_data)
                
                    # Count vulnerabilities found by this module
                    self.scan_stats['module_stats'][module_name]['vulnerabilities_found'] += len(module_results)
                
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
        except requests.exceptions.ConnectionError:
            print(f"  [CONNECTIVITY] Connection failed to {url}")
            return False
        except requests.exceptions.Timeout:
            print(f"  [CONNECTIVITY] Timeout connecting to {url}")
            return False
        except Exception as e:
            print(f"  [CONNECTIVITY] Error connecting to {url}: {e}")
            return False
    
    def _test_module(self, module_name: str, parsed_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Test specific vulnerability module"""
        results = []
        
        # Initialize payload stats for this module if not exists
        if module_name not in self.scan_stats['payload_stats']:
            self.scan_stats['payload_stats'][module_name] = {
                'payloads_used': 0,
                'requests_made': 0,
                'successful_payloads': 0
            }
        
        # Enhanced form extraction with better error handling
        if 'forms' not in parsed_data or not parsed_data['forms']:
            try:
                print(f"    [MODULE] {module_name.upper()}: Extracting forms from {parsed_data['url']}")
                response = requests.get(
                    parsed_data['url'],
                    timeout=self.config.timeout,
                    headers=self.config.headers,
                    verify=False,
                    allow_redirects=True
                )
                if response.status_code == 200:
                    forms = self.url_parser.extract_forms(response.text)
                    parsed_data['forms'] = forms
                    print(f"    [MODULE] {module_name.upper()}: Successfully extracted {len(forms)} forms from page")
                    
                    # Log detailed form information with enhanced analysis
                    for i, form in enumerate(forms):
                        form_method = form.get('method', 'GET').upper()
                        form_action = form.get('action', '')
                        form_inputs = form.get('inputs', [])
                        form_enctype = form.get('enctype', 'application/x-www-form-urlencoded')
                        
                        print(f"    [FORM] Form {i+1}: Method={form_method}, Action='{form_action}', Inputs={len(form_inputs)}, Enctype={form_enctype}")
                        
                        # Count input types
                        input_types = {}
                        testable_inputs = 0
                        for input_field in form_inputs:
                            input_type = input_field.get('type', 'text')
                            input_types[input_type] = input_types.get(input_type, 0) + 1
                            if input_type not in ['submit', 'button', 'reset', 'image']:
                                testable_inputs += 1
                        
                        print(f"    [FORM] Form {i+1} Input types: {input_types}, Testable: {testable_inputs}")
                        
                        # Log first few input details
                        for j, input_field in enumerate(form_inputs[:5]):  # Show first 5 inputs
                            input_name = input_field.get('name', 'unnamed')
                            input_type = input_field.get('type', 'text')
                            input_value = input_field.get('value', '')
                            input_placeholder = input_field.get('placeholder', '')
                            print(f"    [FORM] Input {j+1}: name='{input_name}', type='{input_type}', value='{input_value[:20]}', placeholder='{input_placeholder[:20]}'")
                        
                        if len(form_inputs) > 5:
                            print(f"    [FORM] ... and {len(form_inputs) - 5} more inputs")
                            
                elif response.status_code in [301, 302, 303, 307, 308]:
                    print(f"    [MODULE] {module_name.upper()}: Page redirected (HTTP {response.status_code}) - following redirect")
                    parsed_data['forms'] = []
                else:
                    print(f"    [MODULE] {module_name.upper()}: Failed to extract forms - HTTP {response.status_code}")
                    parsed_data['forms'] = []
            except requests.exceptions.Timeout:
                print(f"    [MODULE] {module_name.upper()}: Timeout extracting forms")
                parsed_data['forms'] = []
            except requests.exceptions.ConnectionError:
                print(f"    [MODULE] {module_name.upper()}: Connection error extracting forms")
                parsed_data['forms'] = []
            except Exception as e:
                print(f"    [MODULE] {module_name.upper()}: Error extracting forms: {e}")
                parsed_data['forms'] = []
        else:
            forms_count = len(parsed_data.get('forms', []))
            print(f"    [MODULE] {module_name.upper()}: Using cached {forms_count} forms")
            
            # Log cached form summary
            if forms_count > 0:
                methods = {}
                total_inputs = 0
                for form in parsed_data['forms']:
                    method = form.get('method', 'GET').upper()
                    methods[method] = methods.get(method, 0) + 1
                    total_inputs += len(form.get('inputs', []))
                print(f"    [MODULE] {module_name.upper()}: Cached forms - Methods: {methods}, Total inputs: {total_inputs}")
        
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
            elif module_name == "git" or module_name == "gitexposed":
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
            elif module_name == "storedxss":
                results.extend(self._test_stored_xss(parsed_data))
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
            elif module_name == "ssti":
                results.extend(self._test_ssti(parsed_data))
            elif module_name == "crlf":
                results.extend(self._test_crlf(parsed_data))
            elif module_name == "textinjection":
                results.extend(self._test_text_injection(parsed_data))
            elif module_name == "htmlinjection":
                results.extend(self._test_html_injection(parsed_data))
            elif module_name == "hostheader":
                results.extend(self._test_host_header(parsed_data))
            elif module_name == "prototypepollution":
                results.extend(self._test_prototype_pollution(parsed_data))
            elif module_name == "vhost":
                results.extend(self._test_vhost(parsed_data))
            elif module_name == "infoleak":
                results.extend(self._test_information_leakage(parsed_data))
            elif module_name == "openredirect":
                results.extend(self._test_open_redirect(parsed_data))
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
        
        # Update payload stats
        self.scan_stats['payload_stats']['xss']['payloads_used'] += len(xss_payloads)
        
        # Test GET parameters with enhanced logging
        print(f"    [XSS] Found {len(parsed_data['query_params'])} GET parameters to test: {list(parsed_data['query_params'].keys())}")
        
        for param, values in parsed_data['query_params'].items():
            print(f"    [XSS] Testing GET parameter: {param} with {len(values)} value(s): {values[:3]}{'...' if len(values) > 3 else ''}")
            
            # Create deduplication key for this parameter
            param_key = f"xss_{base_url.split('?')[0]}_{param}"
            if param_key in self.found_vulnerabilities:
                print(f"    [XSS] Skipping parameter {param} - already tested")
                continue
            
            payload_count = self.payload_limit if self.payload_limit > 0 else 50
            for payload in xss_payloads[:payload_count]:
                try:
                    print(f"    [XSS] Trying payload: {payload[:50]}...")
                    
                    # Create test URL
                    test_params = parsed_data['query_params'].copy()
                    test_params[param] = [payload]
                    
                    # Build query string with minimal encoding for XSS payloads
                    from urllib.parse import quote_plus
                    query_parts = []
                    for k, v_list in test_params.items():
                        for v in v_list:
                            # Use quote_plus but preserve XSS characters
                            encoded_key = quote_plus(k)
                            # Minimal encoding - only encode & and # to prevent URL breaking
                            encoded_value = str(v).replace('&', '%26').replace('#', '%23')
                            query_parts.append(f"{encoded_key}={encoded_value}")
                    
                    test_url = f"{base_url.split('?')[0]}?{'&'.join(query_parts)}"
                    print(f"    [XSS] Request URL: {test_url}")
                    
                    response = requests.get(
                        test_url,
                        timeout=self.config.timeout,
                        headers=self.config.headers,
                        verify=False
                    )
                    
                    # Update request count
                    self.request_count += 1
                    self.scan_stats['payload_stats']['xss']['requests_made'] += 1
                    
                    print(f"    [XSS] Response code: {response.status_code}")
                    
                    # Check if we should stop due to request limit or max time
                    if self._should_stop():
                        if self.stop_requested:
                            print(f"    [XSS] Stopping - maximum time reached")
                        else:
                            print(f"    [XSS] Stopping - reached request limit ({self.config.request_limit})")
                        break  # Break from payload loop, not return from function
                    
                    # Check if 404 response contains meaningful content
                    if response.status_code == 404:
                        if self._is_meaningful_404(response.text):
                            if self.debug:
                                print(f"    [XSS] 404 response contains meaningful content, continuing analysis")
                        else:
                            print(f"    [XSS] Skipping - empty 404 response")
                            continue
                    
                    # Use XSS detector with enhanced logging
                    print(f"    [XSS] Checking if payload is reflected in response...")
                    print(f"    [XSS] Response length: {len(response.text)} chars")
                    
                    # Расширенная проверка отражения payload (включая различные кодировки)
                    payload_lower = payload.lower()
                    response_lower = response.text.lower()
                        
                    # Проверяем различные варианты кодирования payload
                    payload_variants = [
                        payload,  # Оригинальный
                        payload_lower,  # Нижний регистр
                        payload.replace('<', '&lt;').replace('>', '&gt;'),  # HTML entities
                        payload.replace('<', '%3C').replace('>', '%3E'),  # URL encoding
                        payload.replace('"', '&quot;').replace("'", '&#x27;'),  # Quote encoding
                        payload.replace(' ', '+'),  # Space to plus
                        payload.replace(' ', '%20'),  # Space to %20
                        payload.replace('<script>', '&lt;script&gt;'),  # Script tag encoding
                        payload.replace('alert', 'alert'),  # Keep alert as is
                        payload.replace('javascript:', 'javascript%3A')  # JS protocol encoding
                    ]
                        
                    payload_in_response = any(variant in response.text or variant in response_lower for variant in payload_variants)
                    
                    print(f"    [XSS] Payload reflected: {payload_in_response}")
                    
                    # Debug: Show first 200 chars of response if payload is found
                    if payload_in_response:
                        response_preview = response.text[:200].replace('\n', ' ').replace('\r', ' ')
                        print(f"    [XSS] Response preview: {response_preview}...")
                    
                    # Простая и надежная проверка отражения XSS payload
                    payload_in_response = payload in response.text
                    print(f"    [XSS] Payload reflected in response: {payload_in_response}")
                    
                    # Дополнительная проверка различных кодировок payload
                    if not payload_in_response:
                        payload_variants = [
                            payload.lower(),
                            payload.replace('<', '&lt;').replace('>', '&gt;'),
                            payload.replace('<', '%3C').replace('>', '%3E'),
                            payload.replace('"', '&quot;').replace("'", '&#x27;'),
                            payload.replace(' ', '+'),
                            payload.replace(' ', '%20')
                        ]
                        
                        for variant in payload_variants:
                            if variant in response.text:
                                payload_in_response = True
                                print(f"    [XSS] Payload variant found: {variant}")
                                break
                    
                    # Используем XSS детектор для дополнительной проверки
                    try:
                        xss_result = XSSDetector.detect_reflected_xss(payload, response.text, response.status_code)
                        if isinstance(xss_result, dict):
                            xss_detected_by_detector = xss_result.get('vulnerable', False)
                            detection_method = xss_result.get('detection_method', 'reflection_check')
                            xss_type = xss_result.get('xss_type', 'Reflected XSS')
                            confidence = xss_result.get('confidence', 0.8)
                        else:
                            xss_detected_by_detector = bool(xss_result)
                            detection_method = "basic_detection"
                            xss_type = "Reflected XSS"
                            confidence = 0.8
                    except Exception as e:
                        print(f"    [XSS] Detector error: {e}")
                        xss_detected_by_detector = False
                        detection_method = "reflection_check"
                        xss_type = "Reflected XSS"
                        confidence = 0.7
                    
                    # Окончательное решение: payload отражен ИЛИ детектор нашел XSS
                    xss_detected = payload_in_response or xss_detected_by_detector
                    
                    if xss_detected:
                        print(f"    [XSS] XSS DETECTED: {xss_type} (method: {detection_method}, confidence: {confidence:.2f})")
                    else:
                        print(f"    [XSS] No XSS detected")
                    
                    if xss_detected:
                        try:
                            evidence = XSSDetector.get_evidence(payload, response.text, xss_result)
                            response_snippet = self._get_contextual_response_snippet(payload, response.text)
                        except Exception as e:
                            print(f"    [XSS] Error getting evidence: {e}")
                            evidence = f"{xss_type} detected with payload: {payload}"
                            response_snippet = "Response analysis failed"
                            
                        # Create vulnerability object for filtering
                        vulnerability = {
                            'module': 'xss',
                            'target': base_url,
                            'vulnerability': xss_type,
                            'severity': 'High' if confidence >= 0.8 else 'Medium',
                            'parameter': param,
                            'payload': payload,
                            'evidence': evidence,
                            'request_url': test_url,
                            'detector': f'XSSDetector.enhanced_detection ({detection_method})',
                            'response_snippet': response_snippet,
                            'xss_type': xss_type,
                            'confidence': confidence,
                            'detection_method': detection_method
                        }
                        
                        # Filter false positives
                        try:
                            is_valid, filter_reason = self.false_positive_filter.filter_vulnerability(vulnerability)
                        except:
                            is_valid, filter_reason = True, "Filter not available"
                            
                        if is_valid:
                            print(f"    [XSS] VULNERABILITY FOUND! Parameter: {param}")
                                
                            # Mark as found to prevent duplicates
                            self.found_vulnerabilities.add(param_key)
                                
                            # Update successful payload count
                            self.scan_stats['payload_stats']['xss']['successful_payloads'] += 1
                            self.scan_stats['total_payloads_used'] += 1
                                
                            # Take screenshot for XSS vulnerability
                            screenshot_filename = None
                            try:
                                import time
                                vuln_id = f"xss_{param}_{int(time.time())}"
                                screenshot_filename = self.screenshot_handler.take_screenshot_with_payload(
                                    test_url, "xss", vuln_id, payload
                                )
                                vulnerability['screenshot'] = screenshot_filename
                            except Exception as e:
                                print(f"    [XSS] Could not take screenshot: {e}")
                                
                            results.append(vulnerability)
                            break  # Found XSS, no need to test more payloads for this param
                        else:
                            print(f"    [XSS] False positive filtered: {filter_reason}")
                    else:
                        print(f"    [XSS] No XSS detected for payload: {payload[:30]}...")
                        
                        # Debug: Check if payload is in response but not detected as XSS
                        if payload in response.text:
                            print(f"    [XSS] DEBUG: Payload found in response but not classified as XSS")
                            # Show context around payload
                            payload_pos = response.text.find(payload)
                            if payload_pos >= 0:
                                start = max(0, payload_pos - 50)
                                end = min(len(response.text), payload_pos + len(payload) + 50)
                                context = response.text[start:end].replace('\n', ' ').replace('\r', ' ')
                                print(f"    [XSS] DEBUG: Context: ...{context}...")
                        
                except Exception as e:
                    print(f"    [XSS] Error testing payload: {e}")
                    continue
        
        # Test POST forms with enhanced form analysis
        forms_data = parsed_data.get('forms', [])
        print(f"    [XSS] Found {len(forms_data)} forms to test")
        
        for i, form_data in enumerate(forms_data):
            form_method = form_data.get('method', 'GET').upper()
            form_action = form_data.get('action', '')
            form_inputs = form_data.get('inputs', [])
            
            print(f"    [XSS] Analyzing form {i+1}: method={form_method}, action='{form_action}', inputs={len(form_inputs)}")
            
            # Log detailed form input information
            for j, input_field in enumerate(form_inputs):
                input_name = input_field.get('name', 'unnamed')
                input_type = input_field.get('type', 'text')
                input_value = input_field.get('value', '')
                print(f"    [XSS] Form {i+1} Input {j+1}: name='{input_name}', type='{input_type}', value='{input_value[:20]}{'...' if len(str(input_value)) > 20 else ''}'")
            
            if form_method in ['POST', 'PUT'] and form_inputs:
                print(f"    [XSS] Testing {form_method} form {i+1}: {form_action} with {len(form_inputs)} inputs")
            elif form_method == 'GET' and form_inputs:
                print(f"    [XSS] Testing GET form {i+1} (will test as URL parameters)")
            elif not form_inputs:
                print(f"    [XSS] Skipping form {i+1} - no testable inputs found")
            else:
                print(f"    [XSS] Testing form {i+1} with method: {form_method}")
                
                # Build form URL with better URL construction
                if form_action.startswith('/'):
                    form_url = f"{parsed_data['scheme']}://{parsed_data['host']}{form_action}"
                elif form_action.startswith('http'):
                    form_url = form_action
                elif form_action:
                    # Handle relative URLs
                    base_path = '/'.join(base_url.split('/')[:-1]) if base_url.count('/') > 3 else base_url.rstrip('/')
                    form_url = f"{base_path}/{form_action}"
                else:
                    form_url = base_url
                
                print(f"    [XSS] Form URL resolved to: {form_url}")
                
                # Test each form input with enhanced filtering
                testable_inputs = []
                for input_data in form_inputs:
                    input_name = input_data.get('name')
                    input_type = input_data.get('type', 'text')
                    
                    if not input_name:
                        print(f"    [XSS] Skipping input without name: type={input_type}")
                        continue
                    elif input_type in ['submit', 'button', 'reset', 'image']:
                        print(f"    [XSS] Skipping non-testable input: name={input_name}, type={input_type}")
                        continue
                    elif input_type == 'hidden' and input_name.lower() in ['csrf_token', '_token', 'authenticity_token']:
                        print(f"    [XSS] Skipping security token: name={input_name}, type={input_type}")
                        continue
                    else:
                        testable_inputs.append(input_data)
                        print(f"    [XSS] Found testable input: name={input_name}, type={input_type}")
                
                print(f"    [XSS] Testing {len(testable_inputs)} testable inputs in form {i+1}")
                
                for input_data in testable_inputs:
                    input_name = input_data.get('name')
                    input_type = input_data.get('type', 'text')
                    
                    print(f"    [XSS] Testing form input: {input_name} (type: {input_type})")
                    
                    # Create deduplication key for this form input
                    form_key = f"xss_form_{form_url.split('?')[0]}_{input_name}"
                    if form_key in self.found_vulnerabilities:
                        print(f"    [XSS] Skipping form input {input_name} - already tested")
                        continue
                    
                    payload_count = self.payload_limit if self.payload_limit > 0 else 25
                    for payload in xss_payloads[:payload_count]:
                        try:
                            print(f"    [XSS] Trying form payload: {payload[:50]}...")
                            
                            # Prepare form data with better default values
                            post_data = {}
                            for inp in form_inputs:
                                inp_name = inp.get('name')
                                inp_value = inp.get('value', '')
                                inp_type = inp.get('type', 'text')
                                
                                if inp_name and inp_type not in ['submit', 'button', 'reset', 'image']:
                                    if inp_name == input_name:
                                        post_data[inp_name] = payload
                                    else:
                                        # Use appropriate default values based on input type
                                        if inp_type == 'email':
                                            post_data[inp_name] = inp_value or 'test@example.com'
                                        elif inp_type == 'password':
                                            post_data[inp_name] = inp_value or 'password123'
                                        elif inp_type == 'number':
                                            post_data[inp_name] = inp_value or '123'
                                        elif inp_type == 'url':
                                            post_data[inp_name] = inp_value or 'http://example.com'
                                        else:
                                            post_data[inp_name] = inp_value or 'test'
                            
                            print(f"    [XSS] Sending {form_method} request to {form_url}")
                            print(f"    [XSS] Form data keys: {list(post_data.keys())}")
                            
                            if form_method == 'POST':
                                response = requests.post(
                                    form_url,
                                    data=post_data,
                                    timeout=self.config.timeout,
                                    headers=self.config.headers,
                                    verify=False,
                                    allow_redirects=True
                                )
                            elif form_method == 'PUT':
                                response = requests.put(
                                    form_url,
                                    data=post_data,
                                    timeout=self.config.timeout,
                                    headers=self.config.headers,
                                    verify=False,
                                    allow_redirects=True
                                )
                            else:  # GET form - build URL with parameters
                                # Build query string for GET form
                                query_parts = []
                                for k, v in post_data.items():
                                    from urllib.parse import quote_plus
                                    query_parts.append(f"{quote_plus(k)}={quote_plus(str(v))}")
                                
                                get_url = f"{form_url}?{'&'.join(query_parts)}" if query_parts else form_url
                                print(f"    [XSS] GET form URL: {get_url}")
                                
                                response = requests.get(
                                    get_url,
                                    timeout=self.config.timeout,
                                    headers=self.config.headers,
                                    verify=False,
                                    allow_redirects=True
                                )
                            
                            print(f"    [XSS] Form response code: {response.status_code}")
                            print(f"    [XSS] Response length: {len(response.text)} chars")
                            
                            # Check if payload is reflected in form response
                            form_payload_reflected = payload in response.text
                            print(f"    [XSS] Payload reflected in form response: {form_payload_reflected}")
                            
                            # Простая проверка отражения payload в форме
                            form_payload_reflected = payload in response.text
                            print(f"    [XSS] Form payload reflected: {form_payload_reflected}")
                            
                            # Используем XSS детектор как дополнительную проверку
                            try:
                                form_xss_result = XSSDetector.detect_reflected_xss(payload, response.text, response.status_code)
                                if isinstance(form_xss_result, dict):
                                    form_xss_detected = form_xss_result.get('vulnerable', False)
                                else:
                                    form_xss_detected = bool(form_xss_result)
                            except Exception as e:
                                print(f"    [XSS] Form detector error: {e}")
                                form_xss_detected = False
                            
                            # Окончательное решение для форм
                            if form_payload_reflected or form_xss_detected:
                                evidence = f"XSS payload '{payload}' reflected in {form_method} form response"
                                response_snippet = self._get_contextual_response_snippet(payload, response.text)
                                print(f"    [XSS] FORM VULNERABILITY FOUND! Input: {input_name}")
                                
                                # Mark as found to prevent duplicates
                                self.found_vulnerabilities.add(form_key)
                                
                                vulnerability = {
                                    'module': 'xss',
                                    'target': form_url,
                                    'vulnerability': f'Reflected XSS in {form_method} Form',
                                    'severity': 'Medium',
                                    'parameter': input_name,
                                    'payload': payload,
                                    'evidence': evidence,
                                    'request_url': form_url,
                                    'detector': 'XSSDetector.detect_reflected_xss',
                                    'response_snippet': response_snippet
                                }
                                
                                # Filter false positives
                                try:
                                    is_valid, filter_reason = self.false_positive_filter.filter_vulnerability(vulnerability)
                                except:
                                    is_valid = True
                                
                                if is_valid:
                                    results.append(vulnerability)
                                    break  # Found XSS, no need to test more payloads for this input
                                
                        except Exception as e:
                            print(f"    [XSS] Error testing form payload: {e}")
                            continue
        
        return results
    
    def _test_sqli(self, parsed_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Test for SQL injection vulnerabilities"""
        results = []
        base_url = parsed_data['url']
        
        # Get SQL injection payloads
        sqli_payloads = SQLiPayloads.get_all_payloads()
        
        # Update payload stats
        if 'sqli' not in self.scan_stats['payload_stats']:
            self.scan_stats['payload_stats']['sqli'] = {'payloads_used': 0, 'requests_made': 0, 'successful_payloads': 0}
        self.scan_stats['payload_stats']['sqli']['payloads_used'] += len(sqli_payloads)
        
        # Test GET parameters
        print(f"    [SQLI] Found {len(parsed_data['query_params'])} GET parameters to test: {list(parsed_data['query_params'].keys())}")
        
        for param, values in parsed_data['query_params'].items():
            print(f"    [SQLI] Testing GET parameter: {param} with values: {values}")
            
            # Create deduplication key for this parameter and base URL
            base_url_clean = base_url.split('?')[0]
            param_key = f"sqli_{base_url_clean}_{param}"
            if param_key in self.found_vulnerabilities:
                print(f"    [SQLI] Skipping parameter {param} - already tested")
                continue
            
            payload_count = self.payload_limit if self.payload_limit > 0 else 40
            for payload in sqli_payloads[:payload_count]:
                try:
                    print(f"    [SQLI] Trying GET payload: {payload[:50]}...")
                    
                    # Create test URL
                    test_params = parsed_data['query_params'].copy()
                    test_params[param] = [payload]
                    
                    # Build query string with minimal encoding for SQL injection
                    from urllib.parse import quote_plus
                    query_parts = []
                    for k, v_list in test_params.items():
                        for v in v_list:
                            # Use quote_plus but preserve SQL injection characters
                            encoded_key = quote_plus(k)
                            # Only encode & and # to prevent URL breaking, preserve SQL chars
                            encoded_value = str(v).replace('&', '%26').replace('#', '%23')
                            query_parts.append(f"{encoded_key}={encoded_value}")
                    
                    test_url = f"{base_url.split('?')[0]}?{'&'.join(query_parts)}"
                    print(f"    [SQLI] Request URL: {test_url}")
                    
                    response = requests.get(
                        test_url,
                        timeout=self.config.timeout,
                        headers=self.config.headers,
                        verify=False
                    )
                    
                    # Update request count
                    self.request_count += 1
                    self.scan_stats['payload_stats']['sqli']['requests_made'] += 1
                    
                    print(f"    [SQLI] Response code: {response.status_code}")
                    
                    # Check if we should stop due to request limit or max time
                    if self._should_stop():
                        if self.stop_requested:
                            print(f"    [SQLI] Stopping - maximum time reached")
                        else:
                            print(f"    [SQLI] Stopping - reached request limit ({self.config.request_limit})")
                        break  # Break from payload loop, not return from function
                    
                    # Enhanced SQLi detection with detailed logging
                    try:
                        print(f"    [SQLI] Running primary SQL injection detector...")
                        is_vulnerable, pattern = SQLiDetector.detect_error_based_sqli(response.text, response.status_code)
                        print(f"    [SQLI] Primary detector result: vulnerable={is_vulnerable}, pattern='{pattern}'")
                        
                        # Расширенные проверки для всех сайтов
                        if not is_vulnerable:
                            print(f"    [SQLI] Running extended SQL error pattern checks...")
                            # Load SQL error patterns from file
                            sql_error_patterns = PayloadLoader.load_error_patterns()
                            sql_errors = []
                            for db_type, patterns in sql_error_patterns.items():
                                sql_errors.extend(patterns)
                    
                            if not sql_errors:
                                # Fallback to basic patterns if file not found
                                sql_errors = ['mysql', 'sql syntax', 'error:', 'exception']
                            response_lower = response.text.lower()
                                
                            for error in sql_errors:
                                if error in response_lower:
                                    is_vulnerable = True
                                    pattern = f"SQL error detected: {error}"
                                    print(f"    [SQLI] SQL injection detected by error pattern: {error}")
                                    break
                            
                            # Additional check for SQL injection indicators
                            if not is_vulnerable and "'" in payload:
                                print(f"    [SQLI] Checking for SQL function indicators...")
                                sql_indicators = ['mysql_fetch', 'pg_exec', 'sqlite_query', 'odbc_exec']
                                for indicator in sql_indicators:
                                    if indicator in response_lower:
                                        is_vulnerable = True
                                        pattern = f"SQL function detected: {indicator}"
                                        print(f"    [SQLI] SQL injection detected by function: {indicator}")
                                        break
                            
                            if not is_vulnerable:
                                print(f"    [SQLI] No SQL injection indicators found in response")
                                # Show response snippet for debugging
                                response_snippet = response.text[:200].replace('\n', ' ').replace('\r', ' ')
                                print(f"    [SQLI] Response snippet: {response_snippet}...")
                        
                    except Exception as e:
                        print(f"    [SQLI] SQLi detector error: {e}")
                        is_vulnerable = False
                        pattern = "Detection failed"
                    
                    if is_vulnerable:
                        try:
                            evidence = f"SQL injection detected - error pattern: {pattern}"
                            response_snippet = self._get_contextual_response_snippet(payload, response.text)
                        except Exception as e:
                            evidence = f"SQL injection detected with payload: {payload}"
                            response_snippet = "Response analysis failed"
                        print(f"    [SQLI] VULNERABILITY FOUND! Parameter: {param}")
                        
                        vulnerability = {
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
                        }
                        
                        # Filter false positives
                        try:
                            is_valid, filter_reason = self.false_positive_filter.filter_vulnerability(vulnerability)
                        except:
                            is_valid = True
                        
                        if is_valid:
                            # Mark as found to prevent duplicates
                            self.found_vulnerabilities.add(param_key)
                            
                            # Update successful payload count
                            self.scan_stats['payload_stats']['sqli']['successful_payloads'] += 1
                            self.scan_stats['total_payloads_used'] += 1
                            
                            results.append(vulnerability)
                            break  # Found SQLi, no need to test more payloads for this param
                            
                except Exception as e:
                    print(f"    [SQLI] Error testing payload: {e}")
                    continue
        
        # Test POST forms
        forms_data = parsed_data.get('forms', [])
        for i, form_data in enumerate(forms_data):
            form_method = form_data.get('method', 'GET').upper()
            form_action = form_data.get('action', '')
            form_inputs = form_data.get('inputs', [])
            
            if form_method in ['POST', 'PUT'] and form_inputs:
                print(f"    [SQLI] Testing {form_method} form {i+1}: {form_action}")
                
                # Build form URL
                if form_action.startswith('/'):
                    form_url = f"{parsed_data['scheme']}://{parsed_data['host']}{form_action}"
                elif form_action.startswith('http'):
                    form_url = form_action
                else:
                    form_url = f"{base_url.rstrip('/')}/{form_action}" if form_action else base_url
                
                # Test each form input
                for input_data in form_inputs:
                    input_name = input_data.get('name')
                    input_type = input_data.get('type', 'text')
                    
                    # Skip non-testable inputs and search fields for stored XSS
                    if not input_name or input_type in ['submit', 'button', 'hidden']:
                        continue
                    
                    # Skip search fields - they don't store data permanently
                    if any(search_word in input_name.lower() for search_word in ['search', 'find', 'query', 'q']):
                        print(f"    [STOREDXSS] Skipping search field: {input_name}")
                        continue
                    
                    print(f"    [SQLI] Testing form input: {input_name}")
                    
                    # Create deduplication key for this form input
                    form_key = f"sqli_form_{form_url.split('?')[0]}_{input_name}"
                    if form_key in self.found_vulnerabilities:
                        print(f"    [SQLI] Skipping form input {input_name} - already tested")
                        continue
                    
                    payload_count = self.payload_limit if self.payload_limit > 0 else 20
                    for payload in sqli_payloads[:payload_count]:
                        try:
                            print(f"    [SQLI] Trying form payload: {payload[:50]}...")
                            
                            # Prepare form data
                            post_data = {}
                            for inp in form_inputs:
                                inp_name = inp.get('name')
                                inp_value = inp.get('value', 'test')
                                inp_type = inp.get('type', 'text')
                                
                                if inp_name and inp_type not in ['submit', 'button']:
                                    if inp_name == input_name:
                                        post_data[inp_name] = payload
                                    else:
                                        post_data[inp_name] = inp_value
                            
                            if form_method == 'POST':
                                response = requests.post(
                                    form_url,
                                    data=post_data,
                                    timeout=self.config.timeout,
                                    headers=self.config.headers,
                                    verify=False
                                )
                            else:  # PUT
                                response = requests.put(
                                    form_url,
                                    data=post_data,
                                    timeout=self.config.timeout,
                                    headers=self.config.headers,
                                    verify=False
                                )
                            
                            # Update request count
                            self.request_count += 1
                            self.scan_stats['payload_stats']['sqli']['requests_made'] += 1
                            
                            print(f"    [SQLI] Form response code: {response.status_code}")
                            
                            # Use SQLi detector
                            try:
                                is_vulnerable, pattern = SQLiDetector.detect_error_based_sqli(response.text, response.status_code)
                            except:
                                is_vulnerable = False
                                pattern = "Detection failed"
                            
                            if is_vulnerable:
                                evidence = f"SQL injection in {form_method} form - error pattern: {pattern}"
                                response_snippet = self._get_contextual_response_snippet(payload, response.text)
                                print(f"    [SQLI] FORM VULNERABILITY FOUND! Input: {input_name}")
                                
                                # Mark as found to prevent duplicates
                                self.found_vulnerabilities.add(form_key)
                                
                                vulnerability = {
                                    'module': 'sqli',
                                    'target': form_url,
                                    'vulnerability': f'SQL Injection in {form_method} Form',
                                    'severity': 'High',
                                    'parameter': input_name,
                                    'payload': payload,
                                    'evidence': evidence,
                                    'request_url': form_url,
                                    'detector': 'SQLiDetector.detect_error_based_sqli',
                                    'response_snippet': response_snippet
                                }
                                
                                # Filter false positives
                                try:
                                    is_valid, filter_reason = self.false_positive_filter.filter_vulnerability(vulnerability)
                                except:
                                    is_valid = True
                                
                                if is_valid:
                                    # Update successful payload count
                                    self.scan_stats['payload_stats']['sqli']['successful_payloads'] += 1
                                    self.scan_stats['total_payloads_used'] += 1
                                    
                                    results.append(vulnerability)
                                    break  # Found SQLi, no need to test more payloads for this input
                                
                        except Exception as e:
                            print(f"    [SQLI] Error testing form payload: {e}")
                            continue
        
        return results
    
    def _test_lfi(self, parsed_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Test for Local File Inclusion vulnerabilities"""
        results = []
        base_url = parsed_data['url']
        
        # Get LFI payloads
        lfi_payloads = LFIPayloads.get_all_payloads()
        
        # Update payload stats
        if 'lfi' not in self.scan_stats['payload_stats']:
            self.scan_stats['payload_stats']['lfi'] = {'payloads_used': 0, 'requests_made': 0, 'successful_payloads': 0}
        self.scan_stats['payload_stats']['lfi']['payloads_used'] += len(lfi_payloads)
        
        # Test common LFI-prone endpoints based on discovered parameters
        file_params = [param for param in parsed_data['query_params'].keys() 
                      if any(keyword in param.lower() for keyword in ['file', 'path', 'doc', 'page', 'include', 'load', 'read'])]
        
        if file_params:
            print(f"    [LFI] Found file-related parameters: {file_params}")
            # Enhanced payload testing for file-related parameters will be handled below
        
        # Test GET parameters from current URL
        for param, values in parsed_data['query_params'].items():
            print(f"    [LFI] Testing GET parameter: {param}")
            
            # Create deduplication key for this parameter
            param_key = f"lfi_{base_url.split('?')[0]}_{param}"
            if param_key in self.found_vulnerabilities:
                print(f"    [LFI] Skipping parameter {param} - already tested")
                continue
            
            # Enhanced payload testing for file-related parameters
            payload_limit = 50 if any(file_keyword in param.lower() for file_keyword in ['file', 'path', 'doc', 'page', 'include']) else 30
            
            final_payload_limit = self.payload_limit if self.payload_limit > 0 else payload_limit
            for payload in lfi_payloads[:final_payload_limit]:
                try:
                    print(f"    [LFI] Trying GET payload: {payload[:50]}...")
                    
                    # Create test URL
                    test_params = parsed_data['query_params'].copy()
                    test_params[param] = [payload]
                    
                    # Build query string with proper URL encoding
                    from urllib.parse import urlencode, quote_plus
                    query_parts = []
                    for k, v_list in test_params.items():
                        for v in v_list:
                            query_parts.append(f"{quote_plus(k)}={quote_plus(str(v))}")
                    
                    test_url = self._build_test_url(base_url, test_params)
                    print(f"    [LFI] Request URL: {test_url}")
                    
                    response = requests.get(
                        test_url,
                        timeout=self.config.timeout,
                        headers=self.config.headers,
                        verify=False
                    )
                    
                    # Update request count
                    self.request_count += 1
                    self.scan_stats['payload_stats']['lfi']['requests_made'] += 1
                    
                    print(f"    [LFI] Response code: {response.status_code}")
                    
                    # Enhanced LFI detection
                    is_vulnerable, pattern = self._enhanced_lfi_detection(response.text, response.status_code, payload)
                    
                    if is_vulnerable:
                        try:
                            evidence = f"Local file inclusion detected - pattern: {pattern}"
                            response_snippet = self._get_contextual_response_snippet(payload, response.text)
                        except Exception as e:
                            evidence = f"LFI detected with payload: {payload}"
                            response_snippet = "Response analysis failed"
                        print(f"    [LFI] VULNERABILITY FOUND! Parameter: {param}")
                        
                        # Mark as found to prevent duplicates
                        self.found_vulnerabilities.add(param_key)
                        
                        vulnerability = {
                            'module': 'lfi',
                            'target': base_url,
                            'vulnerability': 'Local File Inclusion',
                            'severity': 'High',
                            'parameter': param,
                            'payload': payload,
                            'evidence': evidence,
                            'request_url': test_url,
                            'detector': 'Enhanced LFI Detection',
                            'response_snippet': response_snippet
                        }
                        
                        # Filter false positives
                        try:
                            is_valid, filter_reason = self.false_positive_filter.filter_vulnerability(vulnerability)
                        except:
                            is_valid = True
                        
                        if is_valid:
                            # Update successful payload count
                            self.scan_stats['payload_stats']['lfi']['successful_payloads'] += 1
                            self.scan_stats['total_payloads_used'] += 1
                            
                            results.append(vulnerability)
                            break  # Found LFI, no need to test more payloads for this param
                            
                except Exception as e:
                    print(f"    [LFI] Error testing payload: {e}")
                    continue
        
        # Test POST forms
        forms_data = parsed_data.get('forms', [])
        for i, form_data in enumerate(forms_data):
            form_method = form_data.get('method', 'GET').upper()
            form_action = form_data.get('action', '')
            form_inputs = form_data.get('inputs', [])
            
            if form_method in ['POST', 'PUT'] and form_inputs:
                print(f"    [LFI] Testing {form_method} form {i+1}: {form_action}")
                
                # Build form URL
                if form_action.startswith('/'):
                    form_url = f"{parsed_data['scheme']}://{parsed_data['host']}{form_action}"
                elif form_action.startswith('http'):
                    form_url = form_action
                else:
                    form_url = f"{base_url.rstrip('/')}/{form_action}" if form_action else base_url
                
                # Test each form input
                for input_data in form_inputs:
                    input_name = input_data.get('name')
                    input_type = input_data.get('type', 'text')
                    
                    if not input_name or input_type in ['submit', 'button', 'hidden']:
                        continue
                    
                    print(f"    [LFI] Testing form input: {input_name}")
                    
                    # Create deduplication key for this form input
                    form_key = f"lfi_form_{form_url.split('?')[0]}_{input_name}"
                    if form_key in self.found_vulnerabilities:
                        print(f"    [LFI] Skipping form input {input_name} - already tested")
                        continue
                    
                    payload_count = self.payload_limit if self.payload_limit > 0 else 20
                    for payload in lfi_payloads[:payload_count]:
                        try:
                            print(f"    [LFI] Trying form payload: {payload[:50]}...")
                            
                            # Prepare form data
                            post_data = {}
                            for inp in form_inputs:
                                inp_name = inp.get('name')
                                inp_value = inp.get('value', 'test')
                                inp_type = inp.get('type', 'text')
                                
                                if inp_name and inp_type not in ['submit', 'button']:
                                    if inp_name == input_name:
                                        post_data[inp_name] = payload
                                    else:
                                        post_data[inp_name] = inp_value
                            
                            if form_method == 'POST':
                                response = requests.post(
                                    form_url,
                                    data=post_data,
                                    timeout=self.config.timeout,
                                    headers=self.config.headers,
                                    verify=False
                                )
                            else:  # PUT
                                response = requests.put(
                                    form_url,
                                    data=post_data,
                                    timeout=self.config.timeout,
                                    headers=self.config.headers,
                                    verify=False
                                )
                            
                            # Update request count
                            self.request_count += 1
                            self.scan_stats['payload_stats']['lfi']['requests_made'] += 1
                            
                            print(f"    [LFI] Form response code: {response.status_code}")
                            
                            # Use LFI detector
                            try:
                                is_vulnerable, pattern = LFIDetector.detect_lfi(response.text, response.status_code)
                            except:
                                is_vulnerable = False
                                pattern = "Detection failed"
                            
                            if is_vulnerable:
                                evidence = f"Local file inclusion in {form_method} form - pattern: {pattern}"
                                response_snippet = self._get_contextual_response_snippet(payload, response.text)
                                print(f"    [LFI] FORM VULNERABILITY FOUND! Input: {input_name}")
                                
                                # Mark as found to prevent duplicates
                                self.found_vulnerabilities.add(form_key)
                                
                                vulnerability = {
                                    'module': 'lfi',
                                    'target': form_url,
                                    'vulnerability': f'Local File Inclusion in {form_method} Form',
                                    'severity': 'High',
                                    'parameter': input_name,
                                    'payload': payload,
                                    'evidence': evidence,
                                    'request_url': form_url,
                                    'detector': 'LFIDetector.detect_lfi',
                                    'response_snippet': response_snippet
                                }
                                
                                # Filter false positives
                                try:
                                    is_valid, filter_reason = self.false_positive_filter.filter_vulnerability(vulnerability)
                                except:
                                    is_valid = True
                                
                                if is_valid:
                                    # Update successful payload count
                                    self.scan_stats['payload_stats']['lfi']['successful_payloads'] += 1
                                    self.scan_stats['total_payloads_used'] += 1
                                    
                                    results.append(vulnerability)
                                    break  # Found LFI, no need to test more payloads for this input
                                
                        except Exception as e:
                            print(f"    [LFI] Error testing form payload: {e}")
                            continue
        
        return results
    
    def _test_lfi_endpoint(self, parsed_data: Dict[str, Any], lfi_payloads: List[str]) -> List[Dict[str, Any]]:
        """Test specific endpoint for LFI vulnerabilities"""
        results = []
        base_url = parsed_data['url']
        
        for param, values in parsed_data['query_params'].items():
            print(f"    [LFI] Testing endpoint parameter: {param}")
            
            # Create deduplication key for this parameter
            param_key = f"lfi_{base_url.split('?')[0]}_{param}"
            if param_key in self.found_vulnerabilities:
                print(f"    [LFI] Skipping endpoint parameter {param} - already tested")
                continue
            
            for payload in lfi_payloads[:40]:  # More payloads for known endpoints
                try:
                    print(f"    [LFI] Trying endpoint payload: {payload[:50]}...")
                    
                    # Create test URL
                    test_params = parsed_data['query_params'].copy()
                    test_params[param] = [payload]
                    
                    test_url = self._build_test_url(base_url, test_params)
                    print(f"    [LFI] Endpoint request URL: {test_url}")
                    
                    response = requests.get(
                        test_url,
                        timeout=self.config.timeout,
                        headers=self.config.headers,
                        verify=False
                    )
                    
                    # Update request count
                    self.request_count += 1
                    self.scan_stats['payload_stats']['lfi']['requests_made'] += 1
                    
                    print(f"    [LFI] Endpoint response code: {response.status_code}")
                    
                    # Enhanced LFI detection
                    is_vulnerable, pattern = self._enhanced_lfi_detection(response.text, response.status_code, payload)
                    
                    if is_vulnerable:
                        print(f"    [LFI] ENDPOINT VULNERABILITY FOUND! Parameter: {param}")
                        
                        # Mark as found to prevent duplicates
                        self.found_vulnerabilities.add(param_key)
                        
                        evidence = f"Local file inclusion detected in endpoint - pattern: {pattern}"
                        response_snippet = response.text[:200] + "..." if len(response.text) > 200 else response.text
                        
                        vulnerability = {
                            'module': 'lfi',
                            'target': base_url,
                            'vulnerability': 'Local File Inclusion (Known Endpoint)',
                            'severity': 'High',
                            'parameter': param,
                            'payload': payload,
                            'evidence': evidence,
                            'request_url': test_url,
                            'detector': 'Enhanced LFI Detection (Known Endpoint)',
                            'response_snippet': response_snippet
                        }
                        
                        # Update successful payload count
                        self.scan_stats['payload_stats']['lfi']['successful_payloads'] += 1
                        self.scan_stats['total_payloads_used'] += 1
                        
                        results.append(vulnerability)
                        break  # Found LFI, no need to test more payloads for this param
                        
                except Exception as e:
                    print(f"    [LFI] Error testing endpoint payload: {e}")
                    continue
        
        return results
    
    def _enhanced_lfi_detection(self, response_text: str, response_code: int, payload: str) -> tuple:
        """Enhanced LFI detection with multiple methods"""
        try:
            # Primary detection using LFIDetector
            is_vulnerable, pattern = LFIDetector.detect_lfi(response_text, response_code)
            if is_vulnerable:
                print(f"    [LFI] Primary detector found LFI: {pattern}")
                return True, pattern
            
            # Load LFI indicators from file
            lfi_indicators = PayloadLoader.load_indicators('lfi')
            if not lfi_indicators:
                # Fallback to basic indicators if file not found
                lfi_indicators = ['root:', '[extensions]', '<?php', 'failed to open stream']
            
            response_lower = response_text.lower()
            for indicator in lfi_indicators:
                if indicator.lower() in response_lower:
                    print(f"    [LFI] Enhanced detection found indicator: {indicator}")
                    return True, f"LFI indicator found: {indicator}"
            
            # Check for file content patterns
            if len(response_text) > 100:  # Only check substantial responses
                # Look for passwd file structure
                if ':x:' in response_text and '/bin/' in response_text:
                    print(f"    [LFI] Enhanced detection found passwd file structure")
                    return True, "Unix passwd file structure detected"
                
                # Look for Windows ini file structure
                if '[' in response_text and ']' in response_text and '=' in response_text:
                    lines = response_text.split('\n')
                    ini_sections = [line.strip() for line in lines if line.strip().startswith('[') and line.strip().endswith(']')]
                    if len(ini_sections) >= 2:
                        print(f"    [LFI] Enhanced detection found Windows INI file structure")
                        return True, "Windows INI file structure detected"
                
                # Look for PHP code
                if '<?php' in response_text or '<?=' in response_text:
                    print(f"    [LFI] Enhanced detection found PHP code")
                    return True, "PHP source code detected"
            
            # Check response size and content type changes
            if response_code == 200 and len(response_text) > 500:
                # Look for significant content that might be a file
                if any(keyword in payload.lower() for keyword in ['etc/passwd', 'win.ini', 'boot.ini']):
                    # If we requested a system file and got substantial content, it might be LFI
                    if not any(html_tag in response_lower for html_tag in ['<html', '<body', '<div', '<script']):
                        print(f"    [LFI] Enhanced detection found non-HTML response to system file request")
                        return True, "Non-HTML response to system file request"
            
            print(f"    [LFI] Enhanced detection found no LFI indicators")
            return False, "No LFI detected"
            
        except Exception as e:
            print(f"    [LFI] Enhanced detection error: {e}")
            return False, f"Detection error: {e}"
    
    def _test_csrf(self, parsed_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Test for CSRF vulnerabilities"""
        results = []
        base_url = parsed_data['url']
        
        # Update payload stats
        if 'csrf' not in self.scan_stats['payload_stats']:
            self.scan_stats['payload_stats']['csrf'] = {'payloads_used': 0, 'requests_made': 0, 'successful_payloads': 0}
        
        try:
            print(f"    [CSRF] Testing CSRF protection...")
            
            # Check if we already have forms extracted
            forms_data = parsed_data.get('forms', [])
            
            if not forms_data:
                # First, get the initial page to analyze forms and CSRF protection
                response = requests.get(
                    base_url,
                    timeout=self.config.timeout,
                    headers=self.config.headers,
                    verify=False
                )
                
                # Update request count
                self.request_count += 1
                self.scan_stats['payload_stats']['csrf']['requests_made'] += 1
                
                print(f"    [CSRF] Initial response code: {response.status_code}")
                
                # Skip CSRF testing for error responses
                if response.status_code >= 400:
                    print(f"    [CSRF] Skipping CSRF test - error response ({response.status_code})")
                    return results
                
                # Extract all forms from the page
                forms_data = self.url_parser.extract_forms(response.text)
                response_text = response.text
            else:
                # Use cached response if available
                try:
                    response = requests.get(
                        base_url,
                        timeout=self.config.timeout,
                        headers=self.config.headers,
                        verify=False
                    )
                    response_text = response.text
                except:
                    response_text = ""
            
            if not forms_data:
                print(f"    [CSRF] No forms found on page")
                return results
            
            print(f"    [CSRF] Found {len(forms_data)} form(s) to analyze")
            
            # Analyze each form for CSRF protection
            vulnerable_forms = []
            
            for i, form_data in enumerate(forms_data):
                form_method = form_data.get('method', 'GET').upper()
                form_action = form_data.get('action', '')
                form_inputs = form_data.get('inputs', [])
                
                print(f"    [CSRF] Analyzing form {i+1}: action='{form_action}', method='{form_method}'")
                
                # Skip GET forms (not vulnerable to CSRF)
                if form_method == 'GET':
                    print(f"    [CSRF] Skipping GET form")
                    continue
                
                # Check if form has CSRF protection
                has_csrf_protection = False
                csrf_indicators = CSRFDetector.get_csrf_indicators()
                
                # Check in form inputs
                for input_data in form_inputs:
                    input_name = input_data.get('name', '').lower()
                    if any(indicator.lower() in input_name for indicator in csrf_indicators):
                        has_csrf_protection = True
                        print(f"    [CSRF] Form {i+1} has CSRF protection: {input_name}")
                        break
                
                if not has_csrf_protection:
                    print(f"    [CSRF] Form {i+1} is VULNERABLE - no CSRF protection found")
                    
                    # Create unique form identifier
                    normalized_action = self._normalize_form_action(form_action)
                    form_id = f"csrf_form_{normalized_action}_{form_method}"
                    
                    if form_id not in self.found_vulnerabilities:
                        self.found_vulnerabilities.add(form_id)
                        
                        vulnerable_forms.append({
                            'action': form_action,
                            'method': form_method,
                            'inputs': form_inputs,
                            'form_data': form_data
                        })
                    else:
                        print(f"    [CSRF] Form {i+1} vulnerability suppressed (similar form already found)")
            
            # Report vulnerabilities
            if vulnerable_forms:
                for form_info in vulnerable_forms:
                    evidence = f"Form with action '{form_info['action']}' and method '{form_info['method']}' lacks CSRF protection"
                    
                    # Create form content snippet
                    form_snippet = f"Method: {form_info['method']}, Action: {form_info['action']}"
                    if form_info['inputs']:
                        input_names = [inp.get('name', 'unnamed') for inp in form_info['inputs'][:5]]
                        form_snippet += f", Inputs: {', '.join(input_names)}"
                    
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
                        'response_snippet': form_snippet
                    })
                
                print(f"    [CSRF] VULNERABILITY FOUND! {len(vulnerable_forms)} vulnerable form(s)")
            else:
                print(f"    [CSRF] All forms have CSRF protection or no POST forms found")
            
                
        except Exception as e:
            print(f"    [CSRF] Error during CSRF testing: {e}")
        
        return results

    def _test_dirbrute(self, parsed_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Test for directory and file bruteforce"""
        results = []
        base_url = parsed_data['url']
        
        # Update payload stats
        if 'dirbrute' not in self.scan_stats['payload_stats']:
            self.scan_stats['payload_stats']['dirbrute'] = {'payloads_used': 0, 'requests_made': 0, 'successful_payloads': 0}
        
        # Remove query parameters from base URL
        if '?' in base_url:
            base_url = base_url.split('?')[0]
        
        # Determine if target is a file or directory
        from urllib.parse import urlparse
        parsed_url = urlparse(base_url)
        path = parsed_url.path
        
        # Check if path ends with common file extensions
        is_file = any(path.lower().endswith(ext) for ext in ['.php', '.html', '.htm', '.asp', '.aspx', '.jsp', '.py'])
        
        if is_file:
            # For file URLs, use the directory containing the file
            base_dir = '/'.join(base_url.split('/')[:-1]) + '/'
            print(f"    [DIRBRUTE] Target is a file, using directory: {base_dir}")
        else:
            # Ensure base URL ends with /
            if not base_url.endswith('/'):
                base_url += '/'
            base_dir = base_url
            print(f"    [DIRBRUTE] Target is a directory: {base_dir}")
        
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
            
            # Get comprehensive directory list
            try:
                directories = DirBrutePayloads.get_all_directories()
            except:
                directories = []
            
            # Load common directories from file
            common_dirs = PayloadLoader.load_wordlist('common_directories')
            if not common_dirs:
                # Fallback to basic directories if file not found
                common_dirs = ['admin', 'backup', 'test', 'config', 'upload']
            
            # Combine directories, avoiding duplicates
            all_directories = list(set(directories + common_dirs))
            found_directories = []
            
            # Update payload stats
            self.scan_stats['payload_stats']['dirbrute']['payloads_used'] += len(all_directories)
            
            print(f"    [DIRBRUTE] Testing {len(all_directories)} directories...")
            
            for directory in all_directories[:120]:  # Увеличиваем до 120 директорий
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
                    
                    # Update request count
                    self.request_count += 1
                    self.scan_stats['payload_stats']['dirbrute']['requests_made'] += 1
                    
                    print(f"    [DIRBRUTE] Testing directory: {directory} -> {response.status_code} ({len(response.text)} bytes)")
                    
                    is_valid, evidence = DirBruteDetector.is_valid_response(
                        response.text, response.status_code, len(response.text), baseline_404_text, baseline_404_size,
                        dict(response.headers), requests.Session(), test_url
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
                        
                        # Update successful payload count
                        self.scan_stats['payload_stats']['dirbrute']['successful_payloads'] += 1
                        self.scan_stats['total_payloads_used'] += 1
                        
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
            
            # Get comprehensive file list
            try:
                files = DirBrutePayloads.get_all_files()
            except:
                files = []
        
            # Load common sensitive files from file
            common_files = PayloadLoader.load_wordlist('common_files')
            if not common_files:
                # Fallback to basic files if file not found
                common_files = ['phpinfo.php', 'config.php', '.htaccess', 'robots.txt', '.env']
        
            # Combine files, avoiding duplicates
            all_files = list(set(files + common_files))
        
            # Update payload stats for files
            self.scan_stats['payload_stats']['dirbrute']['payloads_used'] += len(all_files)
        
            print(f"    [DIRBRUTE] Testing {len(all_files)} files...")
        
            for file in all_files[:150]:  # Увеличиваем до 150 файлов
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
                        response.text, response.status_code, len(response.text), baseline_404_text, baseline_404_size,
                        dict(response.headers), requests.Session(), test_url
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
        
        for file in files[:30]:  # Оптимизируем количество файлов
            try:
                test_url = f"{base_url}{directory}/{file}"
                
                response = requests.get(
                    test_url,
                    timeout=self.config.timeout,
                    headers=self.config.headers,
                    verify=False
                )
                
                is_valid, evidence = DirBruteDetector.is_valid_response(
                    response.text, response.status_code, len(response.text), baseline_404_text, baseline_404_size,
                    dict(response.headers), requests.Session(), test_url
                )
                
                # Оптимизированная проверка ложных срабатываний
                if is_valid and baseline_404_size > 0:
                    size_diff = abs(len(response.text) - baseline_404_size)
                    if size_diff < 50 or (size_diff / baseline_404_size < 0.05):
                        continue
                
                if is_valid and original_fingerprint:
                    response_fingerprint = Real404Detector.get_response_fingerprint(response.text)
                    if response_fingerprint == original_fingerprint:
                        continue
                
                if is_valid:
                    is_sensitive, sensitive_evidence = DirBruteDetector.detect_sensitive_file(response.text, file)
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
        """Test for exposed .git repository using specialized Git scanner"""
        from detectors.git_scanner import GitScanner
        
        # Create request counter wrapper
        class RequestCounter:
            def __init__(self, scanner):
                self.scanner = scanner
                self.count = 0
            
            def increment(self):
                self.count += 1
                self.scanner.request_count += 1
            
            def should_stop(self):
                return self.scanner._should_stop()
        
        # Initialize Git scanner
        request_counter = RequestCounter(self)
        git_scanner = GitScanner(self.config, request_counter, self.scan_stats)
        git_scanner.found_vulnerabilities = self.found_vulnerabilities
        
        # Perform Git scanning
        return git_scanner.scan_git_exposure(parsed_data)
    
    def _test_directory_traversal(self, parsed_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Test for directory traversal vulnerabilities"""
        results = []
        base_url = parsed_data['url']
        
        # Get comprehensive directory traversal payloads
        try:
            traversal_payloads = DirectoryTraversalPayloads.get_all_payloads()
        except:
            traversal_payloads = []
        
        # Load directory traversal patterns from file
        common_traversal = PayloadLoader.load_payloads('directory_traversal')
        if not common_traversal:
            # Fallback to basic patterns if file not found
            common_traversal = ['../../../etc/passwd', '..\\..\\..\\windows\\win.ini']
        
        # Combine payloads, avoiding duplicates
        traversal_payloads = list(set(traversal_payloads + common_traversal))
        
        # Test GET parameters
        for param, values in parsed_data['query_params'].items():
            print(f"    [DIRTRAVERSAL] Testing parameter: {param}")
            
            # Create deduplication key for this parameter
            param_key = f"dirtraversal_{base_url.split('?')[0]}_{param}"
            if param_key in self.found_vulnerabilities:
                print(f"    [DIRTRAVERSAL] Skipping parameter {param} - already tested")
                continue
            
            for payload in traversal_payloads[:40]:  # Увеличиваем до 40 payload
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
        """Test for missing security headers and insecure cookies with grouping"""
        results = []
        base_url = parsed_data['url']
        
        # Extract domain for deduplication
        from urllib.parse import urlparse
        parsed_url = urlparse(base_url)
        domain = parsed_url.hostname
        
        # Create deduplication key for this domain
        domain_key = f"secheaders_{domain}"
        if domain_key in self.found_vulnerabilities:
            print(f"    [SECHEADERS] Skipping security headers test for {domain} - already tested")
            return results
        
        try:
            print(f"    [SECHEADERS] Testing security headers for domain: {domain}")
            
            # Mark domain as tested
            self.found_vulnerabilities.add(domain_key)
            
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
            
            # Collect all security issues
            all_issues = []
            highest_severity = 'Info'
            
            # Check for missing security headers
            missing_headers = SecurityHeadersDetector.detect_missing_security_headers(response.headers)
            
            if missing_headers:
                print(f"    [SECHEADERS] Found {len(missing_headers)} missing security headers")
                
                for header_info in missing_headers:
                    all_issues.append({
                        'type': 'missing_header',
                        'header': header_info["header"],
                        'severity': header_info['severity'],
                        'description': header_info["description"],
                        'recommendation': header_info["recommendation"],
                        'current_value': header_info.get("current_value", "Not set")
                    })
                    
                    # Track highest severity
                    if header_info['severity'] == 'High':
                        highest_severity = 'High'
                    elif header_info['severity'] == 'Medium' and highest_severity != 'High':
                        highest_severity = 'Medium'
                    elif header_info['severity'] == 'Low' and highest_severity not in ['High', 'Medium']:
                        highest_severity = 'Low'
            else:
                print(f"    [SECHEADERS] All important security headers are present")
            
            # Check for insecure cookies
            insecure_cookies = SecurityHeadersDetector.detect_insecure_cookies(response.headers)
            
            if insecure_cookies:
                print(f"    [SECHEADERS] Found {len(insecure_cookies)} insecure cookies")
                
                for cookie_info in insecure_cookies:
                    for issue in cookie_info['issues']:
                        all_issues.append({
                            'type': 'insecure_cookie',
                            'cookie_name': cookie_info["cookie_name"],
                            'issue': issue["issue"],
                            'severity': issue['severity'],
                            'description': issue["description"],
                            'cookie_header': cookie_info['cookie_header']
                        })
                        
                        # Track highest severity
                        if issue['severity'] == 'High':
                            highest_severity = 'High'
                        elif issue['severity'] == 'Medium' and highest_severity != 'High':
                            highest_severity = 'Medium'
                        elif issue['severity'] == 'Low' and highest_severity not in ['High', 'Medium']:
                            highest_severity = 'Low'
            else:
                print(f"    [SECHEADERS] No insecure cookies found")
            
            # Create grouped vulnerability if issues found
            if all_issues:
                if len(all_issues) <= 10:  # Group if 10 or fewer issues
                    print(f"    [SECHEADERS] Grouping {len(all_issues)} security issues into single finding")
                    
                    # Build comprehensive evidence
                    issue_list = []
                    critical_issues = []
                    
                    for issue in all_issues:
                        if issue['type'] == 'missing_header':
                            issue_list.append(f"• Missing {issue['header']} header ({issue['severity']})")
                            if issue['severity'] == 'High':
                                critical_issues.append(f"Missing {issue['header']}")
                        else:  # insecure_cookie
                            issue_list.append(f"• Cookie {issue['cookie_name']}: {issue['issue']} ({issue['severity']})")
                            if issue['severity'] == 'High':
                                critical_issues.append(f"Cookie {issue['cookie_name']}")
                    
                    evidence = f"Security configuration issues found ({len(all_issues)} issues):\n" + "\n".join(issue_list)
                    if critical_issues:
                        evidence += f"\n\nCRITICAL ISSUES: {', '.join(critical_issues)}"
                    
                    # Build response snippet from most critical issues
                    response_snippets = []
                    for issue in all_issues[:5]:  # Show first 5 issues
                        if issue['type'] == 'missing_header':
                            response_snippets.append(f"{issue['header']}: {issue['current_value']}")
                        else:
                            response_snippets.append(f"Cookie {issue['cookie_name']}: {issue['issue']}")
                    
                    response_snippet = "\n".join(response_snippets)
                    if len(all_issues) > 5:
                        response_snippet += f"\n... and {len(all_issues) - 5} more issues"
                    
                    results.append({
                        'module': 'secheaders',
                        'target': base_url,
                        'vulnerability': f'Missing Security Headers ({len(all_issues)} issues)',
                        'severity': highest_severity,
                        'parameter': f'security_config: {len(all_issues)} issues',
                        'payload': 'N/A',
                        'evidence': evidence,
                        'request_url': base_url,
                        'detector': 'SecurityHeadersDetector (grouped)',
                        'response_snippet': response_snippet,
                        'security_issues': all_issues  # Keep detailed info for reports
                    })
                else:
                    # Too many issues, create individual vulnerabilities
                    print(f"    [SECHEADERS] Found {len(all_issues)} security issues - creating individual findings")
                    
                    for issue in all_issues:
                        if issue['type'] == 'missing_header':
                            results.append({
                                'module': 'secheaders',
                                'target': base_url,
                                'vulnerability': f'Missing Security Header: {issue["header"]}',
                                'severity': issue['severity'],
                                'parameter': f'header: {issue["header"]}',
                                'payload': 'N/A',
                                'evidence': f'{issue["description"]}. {issue["recommendation"]}',
                                'request_url': base_url,
                                'detector': 'SecurityHeadersDetector.detect_missing_security_headers',
                                'response_snippet': f'Current value: {issue["current_value"]}'
                            })
                        else:  # insecure_cookie
                            results.append({
                                'module': 'secheaders',
                                'target': base_url,
                                'vulnerability': f'Insecure Cookie: {issue["issue"]}',
                                'severity': issue['severity'],
                                'parameter': f'cookie: {issue["cookie_name"]}',
                                'payload': 'N/A',
                                'evidence': f'Cookie "{issue["cookie_name"]}" {issue["description"]}',
                                'request_url': base_url,
                                'detector': 'SecurityHeadersDetector.detect_insecure_cookies',
                                'response_snippet': issue['cookie_header']
                            })
                
                print(f"    [SECHEADERS] Found {len(all_issues)} security configuration issues")
            else:
                print(f"    [SECHEADERS] No security configuration issues found")
            
        except Exception as e:
            print(f"    [SECHEADERS] Error during security headers testing: {e}")
        
        return results
    
    def _test_ssrf(self, parsed_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Test for SSRF vulnerabilities with improved detection"""
        results = []
        base_url = parsed_data['url']
        
        # Get SSRF payloads
        ssrf_payloads = SSRFPayloads.get_all_payloads()
        
        # Update payload stats
        if 'ssrf' not in self.scan_stats['payload_stats']:
            self.scan_stats['payload_stats']['ssrf'] = {'payloads_used': 0, 'requests_made': 0, 'successful_payloads': 0}
        self.scan_stats['payload_stats']['ssrf']['payloads_used'] += len(ssrf_payloads)
        
        # Test GET parameters
        for param, values in parsed_data['query_params'].items():
            print(f"    [SSRF] Testing parameter: {param}")
            
            # Create deduplication key for this parameter
            param_key = f"ssrf_{base_url.split('?')[0]}_{param}"
            if param_key in self.found_vulnerabilities:
                print(f"    [SSRF] Skipping parameter {param} - already tested")
                continue
            
            payload_count = self.payload_limit if self.payload_limit > 0 else 25
            for payload in ssrf_payloads[:payload_count]:
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
                    
                    # Update request count
                    self.request_count += 1
                    self.scan_stats['payload_stats']['ssrf']['requests_made'] += 1
                    
                    print(f"    [SSRF] Response code: {response.status_code}")
                    
                    # Enhanced SSRF detection - avoid false positives from SQL errors
                    response_lower = response.text.lower()
                    
                    # Skip if this looks like a SQL error (common false positive)
                    sql_error_indicators = [
                        'you have an error in your sql syntax',
                        'mysql_fetch_array',
                        'syntax error',
                        'near \'',
                        'at line 1'
                    ]
                    
                    is_sql_error = any(indicator in response_lower for indicator in sql_error_indicators)
                    
                    if is_sql_error:
                        print(f"    [SSRF] Skipping - response appears to be SQL error, not SSRF")
                        continue
                    
                    # Use enhanced SSRF detector
                    is_vulnerable, evidence, severity = SSRFDetector.detect_ssrf(
                        response.text, response.status_code, payload
                    )
                    detection_details = {'method': 'ssrf_detection'}
                    
                    if is_vulnerable:
                        print(f"    [SSRF] VULNERABILITY FOUND! Parameter: {param}")
                        print(f"    [SSRF] Detection details: {detection_details}")
                        
                        # Mark as found to prevent duplicates
                        self.found_vulnerabilities.add(param_key)
                        
                        # Update successful payload count
                        self.scan_stats['payload_stats']['ssrf']['successful_payloads'] += 1
                        self.scan_stats['total_payloads_used'] += 1
                        
                        response_snippet = self._get_contextual_response_snippet(payload, response.text)
                        
                        results.append({
                            'module': 'ssrf',
                            'target': base_url,
                            'vulnerability': 'Server-Side Request Forgery',
                            'severity': severity,
                            'parameter': param,
                            'payload': payload,
                            'evidence': evidence,
                            'request_url': test_url,
                            'detector': 'SSRFDetector.detect_ssrf',
                            'response_snippet': response_snippet,
                            'detection_method': detection_details.get('method', 'ssrf_detection')
                        })
                        break  # Found SSRF, no need to test more payloads for this param
                    else:
                        print(f"    [SSRF] No SSRF detected for payload: {payload[:30]}...")
                        
                except Exception as e:
                    print(f"    [SSRF] Error testing payload: {e}")
                    continue
        
        # Test POST forms
        forms_data = parsed_data.get('forms', [])
        for i, form_data in enumerate(forms_data):
            form_method = form_data.get('method', 'GET').upper()
            form_action = form_data.get('action', '')
            form_inputs = form_data.get('inputs', [])
            
            if form_method in ['POST', 'PUT'] and form_inputs:
                print(f"    [SSRF] Testing {form_method} form {i+1}: {form_action}")
                
                # Build form URL
                if form_action.startswith('/'):
                    form_url = f"{parsed_data['scheme']}://{parsed_data['host']}{form_action}"
                elif form_action.startswith('http'):
                    form_url = form_action
                else:
                    form_url = f"{base_url.rstrip('/')}/{form_action}" if form_action else base_url
                
                # Test each form input
                for input_data in form_inputs:
                    input_name = input_data.get('name')
                    input_type = input_data.get('type', 'text')
                    
                    if not input_name or input_type in ['submit', 'button', 'hidden']:
                        continue
                    
                    print(f"    [SSRF] Testing form input: {input_name}")
                    
                    # Create deduplication key for this form input
                    form_key = f"ssrf_form_{form_url.split('?')[0]}_{input_name}"
                    if form_key in self.found_vulnerabilities:
                        print(f"    [SSRF] Skipping form input {input_name} - already tested")
                        continue
                    
                    payload_count = self.payload_limit if self.payload_limit > 0 else 15
                    for payload in ssrf_payloads[:payload_count]:
                        try:
                            print(f"    [SSRF] Trying form payload: {payload[:50]}...")
                            
                            # Prepare form data
                            post_data = {}
                            for inp in form_inputs:
                                inp_name = inp.get('name')
                                inp_value = inp.get('value', 'test')
                                inp_type = inp.get('type', 'text')
                                
                                if inp_name and inp_type not in ['submit', 'button']:
                                    if inp_name == input_name:
                                        post_data[inp_name] = payload
                                    else:
                                        post_data[inp_name] = inp_value
                            
                            if form_method == 'POST':
                                response = requests.post(
                                    form_url,
                                    data=post_data,
                                    timeout=self.config.timeout,
                                    headers=self.config.headers,
                                    verify=False
                                )
                            else:  # PUT
                                response = requests.put(
                                    form_url,
                                    data=post_data,
                                    timeout=self.config.timeout,
                                    headers=self.config.headers,
                                    verify=False
                                )
                            
                            # Update request count
                            self.request_count += 1
                            self.scan_stats['payload_stats']['ssrf']['requests_made'] += 1
                            
                            print(f"    [SSRF] Form response code: {response.status_code}")
                            
                            # Use SSRF detector
                            is_vulnerable, evidence, severity = SSRFDetector.detect_ssrf(
                                response.text, response.status_code, payload
                            )
                            
                            if is_vulnerable:
                                print(f"    [SSRF] FORM VULNERABILITY FOUND! Input: {input_name}")
                                
                                # Mark as found to prevent duplicates
                                self.found_vulnerabilities.add(form_key)
                                
                                response_snippet = self._get_contextual_response_snippet(payload, response.text)
                                
                                results.append({
                                    'module': 'ssrf',
                                    'target': form_url,
                                    'vulnerability': f'Server-Side Request Forgery in {form_method} Form',
                                    'severity': severity,
                                    'parameter': input_name,
                                    'payload': payload,
                                    'evidence': evidence,
                                    'request_url': form_url,
                                    'detector': 'SSRFDetector.detect_ssrf',
                                    'response_snippet': response_snippet
                                })
                                break  # Found SSRF, no need to test more payloads for this input
                                
                        except Exception as e:
                            print(f"    [SSRF] Error testing form payload: {e}")
                            continue
        
        return results
    
    def _test_rfi(self, parsed_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Test for RFI vulnerabilities with enhanced detection"""
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
            
            # Get baseline response first
            try:
                baseline_response = requests.get(
                    parsed_data['url'],
                    timeout=self.config.timeout,
                    headers=self.config.headers,
                    verify=False
                )
                baseline_content = baseline_response.text
                baseline_length = len(baseline_content)
            except:
                baseline_content = ""
                baseline_length = 0
            
            for payload in rfi_payloads[:20]:  # Уменьшаем количество payload для более точного тестирования
                try:
                    print(f"    [RFI] Trying payload: {payload[:50]}...")
                    
                    # Skip non-HTTP payloads for RFI testing
                    if not payload.startswith(('http://', 'https://', 'ftp://')):
                        continue
                    
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
                    
                    # Enhanced RFI detection with false positive filtering
                    is_rfi = self._enhanced_rfi_detection(
                        response.text, response.status_code, payload, 
                        baseline_content, baseline_length
                    )
                    
                    if is_rfi:
                        evidence = f"Remote file inclusion detected - payload: {payload}"
                        response_snippet = self._get_contextual_response_snippet(payload, response.text)
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
                            'detector': 'Enhanced RFI Detection',
                            'response_snippet': response_snippet
                        })
                        break  # Found RFI, no need to test more payloads for this param
                        
                except Exception as e:
                    print(f"    [RFI] Error testing payload: {e}")
                    continue
        
        # Test POST forms
        forms_data = parsed_data.get('forms', [])
        for i, form_data in enumerate(forms_data):
            form_method = form_data.get('method', 'GET').upper()
            form_action = form_data.get('action', '')
            form_inputs = form_data.get('inputs', [])
            
            if form_method in ['POST', 'PUT'] and form_inputs:
                print(f"    [RFI] Testing {form_method} form {i+1}: {form_action}")
                
                # Build form URL
                if form_action.startswith('/'):
                    form_url = f"{parsed_data['scheme']}://{parsed_data['host']}{form_action}"
                elif form_action.startswith('http'):
                    form_url = form_action
                else:
                    form_url = f"{base_url.rstrip('/')}/{form_action}" if form_action else base_url
                
                # Test each form input
                for input_data in form_inputs:
                    input_name = input_data.get('name')
                    input_type = input_data.get('type', 'text')
                    
                    if not input_name or input_type in ['submit', 'button', 'hidden']:
                        continue
                    
                    print(f"    [RFI] Testing form input: {input_name}")
                    
                    # Create deduplication key for this form input
                    form_key = f"rfi_form_{form_url.split('?')[0]}_{input_name}"
                    if form_key in self.found_vulnerabilities:
                        print(f"    [RFI] Skipping form input {input_name} - already tested")
                        continue
                    
                    for payload in rfi_payloads[:10]:  # Test fewer payloads for forms
                        try:
                            # Skip non-HTTP payloads for RFI testing
                            if not payload.startswith(('http://', 'https://', 'ftp://')):
                                continue
                            
                            print(f"    [RFI] Trying form payload: {payload[:50]}...")
                            
                            # Prepare form data
                            post_data = {}
                            for inp in form_inputs:
                                inp_name = inp.get('name')
                                inp_value = inp.get('value', 'test')
                                inp_type = inp.get('type', 'text')
                                
                                if inp_name and inp_type not in ['submit', 'button']:
                                    if inp_name == input_name:
                                        post_data[inp_name] = payload
                                    else:
                                        post_data[inp_name] = inp_value
                            
                            if form_method == 'POST':
                                response = requests.post(
                                    form_url,
                                    data=post_data,
                                    timeout=self.config.timeout,
                                    headers=self.config.headers,
                                    verify=False
                                )
                            else:  # PUT
                                response = requests.put(
                                    form_url,
                                    data=post_data,
                                    timeout=self.config.timeout,
                                    headers=self.config.headers,
                                    verify=False
                                )
                            
                            print(f"    [RFI] Form response code: {response.status_code}")
                            
                            # Enhanced RFI detection
                            is_rfi = self._enhanced_rfi_detection(
                                response.text, response.status_code, payload, 
                                baseline_content, baseline_length
                            )
                            
                            if is_rfi:
                                evidence = f"Remote file inclusion in {form_method} form - payload: {payload}"
                                response_snippet = self._get_contextual_response_snippet(payload, response.text)
                                print(f"    [RFI] FORM VULNERABILITY FOUND! Input: {input_name}")
                                
                                # Mark as found to prevent duplicates
                                self.found_vulnerabilities.add(form_key)
                                
                                results.append({
                                    'module': 'rfi',
                                    'target': form_url,
                                    'vulnerability': f'Remote File Inclusion in {form_method} Form',
                                    'severity': 'High',
                                    'parameter': input_name,
                                    'payload': payload,
                                    'evidence': evidence,
                                    'request_url': form_url,
                                    'detector': 'Enhanced RFI Detection',
                                    'response_snippet': response_snippet
                                })
                                break  # Found RFI, no need to test more payloads for this input
                                
                        except Exception as e:
                            print(f"    [RFI] Error testing form payload: {e}")
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
        """Test for clickjacking vulnerabilities with domain-level deduplication"""
        results = []
        base_url = parsed_data['url']
        
        # Extract domain for deduplication
        from urllib.parse import urlparse
        parsed_url = urlparse(base_url)
        domain = parsed_url.hostname
        
        # Create deduplication key for this domain
        domain_key = f"clickjacking_{domain}"
        if domain_key in self.found_vulnerabilities:
            print(f"    [CLICKJACKING] Skipping clickjacking test for {domain} - already tested")
            return results
        
        try:
            print(f"    [CLICKJACKING] Testing clickjacking protection for domain: {domain}")
            
            # Mark domain as tested
            self.found_vulnerabilities.add(domain_key)
            
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
                
                severity = 'Medium' if clickjacking_result.get('missing_headers') else 'Low'
                
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
    
    def _test_stored_xss(self, parsed_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Test for Stored XSS vulnerabilities"""
        results = []
        base_url = parsed_data['url']
        
        # Get Stored XSS payloads from payload loader
        stored_xss_payloads = StoredXSSDetector.get_stored_xss_payloads()
        
        # Test all forms for stored XSS (including GET forms that might store data)
        forms_data = parsed_data.get('forms', [])
        print(f"    [STOREDXSS] Found {len(forms_data)} forms to test for stored XSS")
        
        for i, form_data in enumerate(forms_data):
            form_method = form_data.get('method', 'GET').upper()
            form_action = form_data.get('action', '')
            form_inputs = form_data.get('inputs', [])
            
            # Test all forms that have input fields (including GET forms)
            if form_inputs:
                print(f"    [STOREDXSS] Testing {form_method} form {i+1}: {form_action}")
                
                # Build form URL
                if form_action.startswith('/'):
                    form_url = f"{parsed_data['scheme']}://{parsed_data['host']}{form_action}"
                elif form_action.startswith('http'):
                    form_url = form_action
                else:
                    form_url = f"{base_url.rstrip('/')}/{form_action}" if form_action else base_url
                
                # Test each form input
                for input_data in form_inputs:
                    input_name = input_data.get('name')
                    input_type = input_data.get('type', 'text')
                    
                    if not input_name or input_type in ['submit', 'button', 'hidden']:
                        continue
                    
                    print(f"    [STOREDXSS] Testing form input: {input_name}")
                    
                    # Create deduplication key for this form input
                    form_key = f"storedxss_form_{form_url.split('?')[0]}_{input_name}"
                    if form_key in self.found_vulnerabilities:
                        print(f"    [STOREDXSS] Skipping form input {input_name} - already tested")
                        continue
                    
                    payload_count = self.payload_limit if self.payload_limit > 0 else 5
                    for payload in stored_xss_payloads[:payload_count]:
                        try:
                            print(f"    [STOREDXSS] Trying stored payload: {payload[:50]}...")
                            
                            # Step 1: Submit payload via POST form
                            post_data = {}
                            for inp in form_inputs:
                                inp_name = inp.get('name')
                                inp_value = inp.get('value', 'test')
                                inp_type = inp.get('type', 'text')
                                
                                if inp_name and inp_type not in ['submit', 'button']:
                                    if inp_name == input_name:
                                        post_data[inp_name] = payload
                                    else:
                                        post_data[inp_name] = inp_value
                            
                            print(f"    [STOREDXSS] Submitting payload to form...")
                            
                            if form_method == 'POST':
                                submit_response = requests.post(
                                    form_url,
                                    data=post_data,
                                    timeout=self.config.timeout,
                                    headers=self.config.headers,
                                    verify=False
                                )
                            elif form_method == 'PUT':
                                submit_response = requests.put(
                                    form_url,
                                    data=post_data,
                                    timeout=self.config.timeout,
                                    headers=self.config.headers,
                                    verify=False
                                )
                            else:  # GET form - build URL with parameters
                                # Build query string for GET form
                                query_parts = []
                                for k, v in post_data.items():
                                    query_parts.append(f"{k}={v}")
                                
                                get_url = f"{form_url}?{'&'.join(query_parts)}" if query_parts else form_url
                                print(f"    [STOREDXSS] Submitting GET form to: {get_url}")
                                
                                submit_response = requests.get(
                                    get_url,
                                    timeout=self.config.timeout,
                                    headers=self.config.headers,
                                    verify=False
                                )
                            
                            print(f"    [STOREDXSS] Submit response code: {submit_response.status_code}")
                            
                            # Step 2: Check if payload is stored by visiting the same page again
                            print(f"    [STOREDXSS] Checking if payload is stored...")
                            
                            # For GET forms, check the original page URL, not just form_url
                            check_urls = [form_url]
                            if form_method == 'GET' and form_url != base_url:
                                check_urls.append(base_url)  # Also check original page
                            
                            stored_found = False
                            check_response = None
                            
                            for check_url in check_urls:
                                print(f"    [STOREDXSS] Checking URL: {check_url}")
                                check_response = requests.get(
                                    check_url,
                                    timeout=self.config.timeout,
                                    headers=self.config.headers,
                                    verify=False
                                )
                                
                                print(f"    [STOREDXSS] Check response code: {check_response.status_code}")
                                
                                # Use Stored XSS detector with proper parameters
                                is_vulnerable, evidence, severity = StoredXSSDetector.detect_stored_xss(
                                    submit_response.text, payload, check_response.text
                                )
                                
                                print(f"    [STOREDXSS] Detection result: vulnerable={is_vulnerable}, evidence='{evidence}', severity='{severity}'")
                            
                                if is_vulnerable:
                                    stored_found = True
                                    response_snippet = self._get_contextual_response_snippet(payload, check_response.text)
                                    print(f"    [STOREDXSS] STORED XSS FOUND! Input: {input_name} - {evidence}")
                                    
                                    # Mark as found to prevent duplicates
                                    self.found_vulnerabilities.add(form_key)
                                    
                                    results.append({
                                        'module': 'storedxss',
                                        'target': form_url,
                                        'vulnerability': f'Stored XSS in {form_method} Form',
                                        'severity': severity,
                                        'parameter': input_name,
                                        'payload': payload,
                                        'evidence': evidence,
                                        'request_url': form_url if form_method != 'GET' else get_url,
                                        'detector': 'StoredXSSDetector.detect_stored_xss',
                                        'response_snippet': response_snippet,
                                        'remediation': StoredXSSDetector.get_remediation_advice()
                                    })
                                    break  # Found stored XSS, no need to test more payloads for this input
                                else:
                                    print(f"    [STOREDXSS] No stored XSS detected for payload: {payload[:30]}...")
                                
                        except Exception as e:
                            print(f"    [STOREDXSS] Error testing stored payload: {e}")
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
                    cve_count = detection.get('cve_count', 0)
                    critical_cves = detection.get('critical_cves', [])
                    high_cves = detection.get('high_cves', [])
                    cve_links = detection.get('cve_links', [])
                    latest_version = detection.get('latest_version')
                    is_eol = detection.get('is_eol', False)
                    eol_date = detection.get('eol_date')
                    
                    # Create deduplication key for this software version
                    version_key = f"{software}_{version}"
                    if version_key in seen_versions:
                        print(f"    [OUTDATEDSOFTWARE] Skipping duplicate {software} {version}")
                        continue
                    
                    seen_versions.add(version_key)
                    
                    # Build evidence with CVE information
                    evidence = f"{software.upper()} version {version}"
                    if latest_version:
                        evidence += f" (Latest: {latest_version})"
                    if is_eol:
                        evidence += f" [EOL: {eol_date}]" if eol_date else " [EOL]"
                    if cve_count > 0:
                        evidence += f" - {cve_count} CVE(s) found"
                        if critical_cves:
                            evidence += f" ({len(critical_cves)} Critical)"
                        elif high_cves:
                            evidence += f" ({len(high_cves)} High)"
                    
                    # Get remediation advice
                    remediation = OutdatedSoftwareDetector.get_remediation_advice(software, version, detection)
                    
                    # Build response snippet with CVE links
                    response_snippet = f"Version: {version}"
                    if cve_links:
                        top_cves = cve_links[:3]
                        cve_list = [f"{cve['cve_id']} (CVSS: {cve.get('score', 'N/A')})" for cve in top_cves]
                        response_snippet += f" | CVEs: {', '.join(cve_list)}"
                        if len(cve_links) > 3:
                            response_snippet += f" and {len(cve_links) - 3} more"
                    
                    results.append({
                        'module': 'outdatedsoftware',
                        'target': base_url,
                        'vulnerability': f'Outdated {software.title()} Version',
                        'severity': 'Low',  # Set all outdated software to Low severity
                        'parameter': f'software: {software}',
                        'payload': 'N/A',
                        'evidence': evidence,
                        'request_url': base_url,
                        'detector': 'OutdatedSoftwareDetector.detect_outdated_software',
                        'response_snippet': response_snippet,
                        'remediation': remediation,
                        'software_name': software,
                        'software_version': version,
                        'latest_version': latest_version,
                        'cve_count': cve_count,
                        'critical_cves': critical_cves,
                        'high_cves': high_cves,
                        'cve_links': cve_links,
                        'is_eol': is_eol,
                        'eol_date': eol_date
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
            
            # Load SQL injection payloads for error detection from file
            error_payloads = PayloadLoader.load_payloads('sqli_error_detection')
            if not error_payloads:
                # Fallback to basic payloads if file not found
                error_payloads = ["'", '"', "' OR '1'='1", "%27"]
            
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
            
            for phpinfo_path in phpinfo_paths[:60]:  # Увеличиваем до 60 путей
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
                
                for param in list(parsed_data['query_params'].keys())[:10]:  # Увеличиваем до 10 параметров
                    for value in phpinfo_values[:20]:  # Увеличиваем до 20 значений
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
                
                # Set severity to Low for all SSL/TLS issues
                severity = 'Low'
                
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
        """Test for HttpOnly cookie security with grouping"""
        results = []
        base_url = parsed_data['url']
        
        # Extract domain for deduplication
        from urllib.parse import urlparse
        parsed_url = urlparse(base_url)
        domain = parsed_url.hostname
        
        # Create deduplication key for this domain
        domain_key = f"httponlycookies_{domain}"
        if domain_key in self.found_vulnerabilities:
            print(f"    [HTTPONLYCOOKIES] Skipping HttpOnly cookie test for {domain} - already tested")
            return results
        
        try:
            print(f"    [HTTPONLYCOOKIES] Testing HttpOnly cookie security for domain: {domain}")
            
            # Mark domain as tested
            self.found_vulnerabilities.add(domain_key)
            
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
                # Collect all cookie issues
                all_cookie_issues = []
                highest_severity = 'Info'
                
                for cookie_info in insecure_cookies:
                    for issue in cookie_info['issues']:
                        all_cookie_issues.append({
                            'cookie_name': cookie_info["cookie_name"],
                            'issue': issue["issue"],
                            'severity': issue['severity'],
                            'description': issue["description"],
                            'cookie_header': cookie_info['cookie_header']
                        })
                        
                        # Track highest severity
                        if issue['severity'] == 'High':
                            highest_severity = 'High'
                        elif issue['severity'] == 'Medium' and highest_severity != 'High':
                            highest_severity = 'Medium'
                        elif issue['severity'] == 'Low' and highest_severity not in ['High', 'Medium']:
                            highest_severity = 'Low'
                
                if len(all_cookie_issues) <= 8:  # Group if 8 or fewer cookie issues
                    print(f"    [HTTPONLYCOOKIES] Grouping {len(all_cookie_issues)} cookie issues into single finding")
                    
                    # Build comprehensive evidence
                    issue_list = []
                    critical_cookies = []
                    
                    for issue in all_cookie_issues:
                        issue_list.append(f"• Cookie {issue['cookie_name']}: {issue['issue']} ({issue['severity']})")
                        if issue['severity'] == 'High':
                            critical_cookies.append(issue['cookie_name'])
                    
                    evidence = f"Cookie security issues found ({len(all_cookie_issues)} issues):\n" + "\n".join(issue_list)
                    if critical_cookies:
                        evidence += f"\n\nCRITICAL COOKIES: {', '.join(critical_cookies)}"
                    
                    # Build response snippet from most critical cookies
                    response_snippets = []
                    for issue in all_cookie_issues[:4]:  # Show first 4 cookies
                        response_snippets.append(f"{issue['cookie_name']}: {issue['issue']}")
                    
                    response_snippet = "\n".join(response_snippets)
                    if len(all_cookie_issues) > 4:
                        response_snippet += f"\n... and {len(all_cookie_issues) - 4} more cookies"
                    
                    results.append({
                        'module': 'httponlycookies',
                        'target': base_url,
                        'vulnerability': f'Cookie Security Issues ({len(all_cookie_issues)} cookies)',
                        'severity': highest_severity,
                        'parameter': f'cookie_security: {len(all_cookie_issues)} issues',
                        'payload': 'N/A',
                        'evidence': evidence,
                        'request_url': base_url,
                        'detector': 'HttpOnlyCookieDetector (grouped)',
                        'response_snippet': response_snippet,
                        'cookie_issues': all_cookie_issues  # Keep detailed info for reports
                    })
                else:
                    # Too many cookie issues, create individual vulnerabilities
                    print(f"    [HTTPONLYCOOKIES] Found {len(all_cookie_issues)} cookie issues - creating individual findings")
                    
                    for issue in all_cookie_issues:
                        results.append({
                            'module': 'httponlycookies',
                            'target': base_url,
                            'vulnerability': f'Cookie Security Issue: {issue["issue"]}',
                            'severity': issue['severity'],
                            'parameter': f'cookie: {issue["cookie_name"]}',
                            'payload': 'N/A',
                            'evidence': f'Cookie "{issue["cookie_name"]}" {issue["description"]}',
                            'request_url': base_url,
                            'detector': 'HttpOnlyCookieDetector.detect_httponly_cookies',
                            'response_snippet': issue['cookie_header'],
                            'remediation': HttpOnlyCookieDetector.get_remediation_advice(issue['issue'])
                        })
                
                print(f"    [HTTPONLYCOOKIES] Found {len(all_cookie_issues)} cookie security issues")
            else:
                print(f"    [HTTPONLYCOOKIES] No insecure cookies found")
            
        except Exception as e:
            print(f"    [HTTPONLYCOOKIES] Error during HttpOnly cookie testing: {e}")
        
        return results

    def _test_technology_detection(self, parsed_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Test for technology detection using Wappalyzer with deduplication"""
        results = []
        base_url = parsed_data['url']
        
        # Extract domain for deduplication
        from urllib.parse import urlparse
        parsed_url = urlparse(base_url)
        domain = parsed_url.hostname
        
        # Create deduplication key for this domain
        domain_key = f"technology_{domain}"
        if domain_key in self.found_vulnerabilities:
            print(f"    [TECHNOLOGY] Skipping technology detection for {domain} - already tested")
            return results
        
        try:
            print(f"    [TECHNOLOGY] Detecting technologies with Wappalyzer for domain: {domain}")
            
            # Mark domain as tested
            self.found_vulnerabilities.add(domain_key)
            
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
            
            # Use Wappalyzer to detect technologies with warning suppression
            try:
                import warnings
                with warnings.catch_warnings():
                    warnings.filterwarnings("ignore", category=UserWarning, module="Wappalyzer")
                    wappalyzer = Wappalyzer.latest()
                    webpage = WebPage.new_from_response(response)
                    technologies = wappalyzer.analyze(webpage)
            except Exception as e:
                print(f"    [TECHNOLOGY] Wappalyzer error: {e}")
                technologies = []
            
            if technologies:
                print(f"    [TECHNOLOGY] Found {len(technologies)} technologies")
                
                # Store technologies in scan stats (deduplicated by domain)
                self.scan_stats['technologies'][domain] = list(technologies)
                
                # Group all technologies into single finding to avoid spam
                tech_list = list(technologies)
                if len(tech_list) <= 10:  # Group if 10 or fewer technologies
                    tech_names = ', '.join(tech_list)
                    evidence = f"Technologies detected: {tech_names}"
                    
                    results.append({
                        'module': 'technology',
                        'target': base_url,
                        'vulnerability': f'Technologies Detected ({len(tech_list)} found)',
                        'severity': 'Info',
                        'parameter': f'technologies: {len(tech_list)} found',
                        'payload': 'N/A',
                        'evidence': evidence,
                        'request_url': base_url,
                        'detector': 'Wappalyzer.analyze',
                        'response_snippet': f'Technologies: {tech_names}',
                        'technologies': tech_list  # Keep detailed list for reports
                    })
                else:
                    # Too many technologies, create individual findings for important ones
                    important_techs = ['PHP', 'Apache', 'MySQL', 'WordPress', 'Joomla', 'Drupal']
                    for tech_name in tech_list:
                        if any(important in tech_name for important in important_techs):
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
        """Test for XXE vulnerabilities with enhanced detection"""
        results = []
        base_url = parsed_data['url']
        
        # Get XXE payloads
        xxe_payloads = XXEPayloads.get_all_payloads()
        
        # Test only forms that accept XML data or parameters that might process XML
        forms_data = parsed_data.get('forms', [])
        xml_forms = []
        
        # Look for forms that might accept XML
        for form in forms_data:
            form_method = form.get('method', 'GET').upper()
            if form_method in ['POST', 'PUT']:
                # Check if form has file upload or text areas that might accept XML
                for input_field in form.get('inputs', []):
                    input_type = input_field.get('type', 'text')
                    if input_type in ['file', 'textarea'] or 'xml' in input_field.get('name', '').lower():
                        xml_forms.append(form)
                        break
        
        # Test XML-related parameters
        xml_params = [param for param in parsed_data['query_params'].keys() 
                     if any(xml_word in param.lower() for xml_word in ['xml', 'data', 'content', 'file'])]
        
        if not xml_forms and not xml_params:
            print(f"    [XXE] No XML-related forms or parameters found, skipping XXE test")
            return results
        
        # Test GET parameters that might process XML
        for param in xml_params:
            print(f"    [XXE] Testing XML parameter: {param}")
            
            # Create deduplication key for this parameter
            param_key = f"xxe_{base_url.split('?')[0]}_{param}"
            if param_key in self.found_vulnerabilities:
                print(f"    [XXE] Skipping parameter {param} - already tested")
                continue
            
            for payload in xxe_payloads[:15]:  # Уменьшаем количество payload
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
                    
                    # Enhanced XXE detection
                    is_xxe = self._enhanced_xxe_detection(response.text, response.status_code, payload)
                    
                    if is_xxe:
                        evidence = f"XXE vulnerability detected - XML entity processed: {payload[:100]}"
                        response_snippet = self._get_contextual_response_snippet(payload, response.text)
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
                            'detector': 'Enhanced XXE Detection',
                            'response_snippet': response_snippet,
                            'remediation': 'Disable external entity processing in XML parsers'
                        })
                        break  # Found XXE, no need to test more payloads for this param
                        
                except Exception as e:
                    print(f"    [XXE] Error testing payload: {e}")
                    continue
        
        # Test POST forms that might accept XML
        forms_data = parsed_data.get('forms', [])
        for i, form_data in enumerate(forms_data):
            form_method = form_data.get('method', 'GET').upper()
            form_action = form_data.get('action', '')
            form_inputs = form_data.get('inputs', [])
            
            if form_method in ['POST', 'PUT'] and form_inputs:
                # Check if form might accept XML data
                xml_form = False
                for input_field in form_inputs:
                    input_type = input_field.get('type', 'text')
                    input_name = input_field.get('name', '').lower()
                    if input_type in ['file', 'textarea'] or 'xml' in input_name or 'data' in input_name:
                        xml_form = True
                        break
                
                if xml_form:
                    print(f"    [XXE] Testing {form_method} form {i+1}: {form_action}")
                    
                    # Build form URL
                    if form_action.startswith('/'):
                        form_url = f"{parsed_data['scheme']}://{parsed_data['host']}{form_action}"
                    elif form_action.startswith('http'):
                        form_url = form_action
                    else:
                        form_url = f"{base_url.rstrip('/')}/{form_action}" if form_action else base_url
                    
                    # Test each form input that might accept XML
                    for input_data in form_inputs:
                        input_name = input_data.get('name')
                        input_type = input_data.get('type', 'text')
                        
                        if not input_name or input_type in ['submit', 'button', 'hidden']:
                            continue
                        
                        # Only test inputs that might accept XML
                        if input_type in ['file', 'textarea'] or any(xml_word in input_name.lower() for xml_word in ['xml', 'data', 'content']):
                            print(f"    [XXE] Testing form input: {input_name}")
                            
                            # Create deduplication key for this form input
                            form_key = f"xxe_form_{form_url.split('?')[0]}_{input_name}"
                            if form_key in self.found_vulnerabilities:
                                print(f"    [XXE] Skipping form input {input_name} - already tested")
                                continue
                            
                            for payload in xxe_payloads[:10]:  # Test fewer payloads for forms
                                try:
                                    print(f"    [XXE] Trying form payload: {payload[:50]}...")
                                    
                                    # Prepare form data
                                    post_data = {}
                                    for inp in form_inputs:
                                        inp_name = inp.get('name')
                                        inp_value = inp.get('value', 'test')
                                        inp_type = inp.get('type', 'text')
                                        
                                        if inp_name and inp_type not in ['submit', 'button']:
                                            if inp_name == input_name:
                                                post_data[inp_name] = payload
                                            else:
                                                post_data[inp_name] = inp_value
                                    
                                    # Set appropriate content type for XML
                                    headers = self.config.headers.copy()
                                    if input_type == 'file' or 'xml' in input_name.lower():
                                        headers['Content-Type'] = 'application/xml'
                                    
                                    if form_method == 'POST':
                                        response = requests.post(
                                            form_url,
                                            data=post_data,
                                            timeout=self.config.timeout,
                                            headers=headers,
                                            verify=False
                                        )
                                    else:  # PUT
                                        response = requests.put(
                                            form_url,
                                            data=post_data,
                                            timeout=self.config.timeout,
                                            headers=headers,
                                            verify=False
                                        )
                                    
                                    print(f"    [XXE] Form response code: {response.status_code}")
                                    
                                    # Enhanced XXE detection
                                    is_xxe = self._enhanced_xxe_detection(response.text, response.status_code, payload)
                                    
                                    if is_xxe:
                                        evidence = f"XXE vulnerability in {form_method} form - XML entity processed: {payload[:100]}"
                                        response_snippet = self._get_contextual_response_snippet(payload, response.text)
                                        print(f"    [XXE] FORM VULNERABILITY FOUND! Input: {input_name}")
                                        
                                        # Mark as found to prevent duplicates
                                        self.found_vulnerabilities.add(form_key)
                                        
                                        results.append({
                                            'module': 'xxe',
                                            'target': form_url,
                                            'vulnerability': f'XML External Entity (XXE) in {form_method} Form',
                                            'severity': 'High',
                                            'parameter': input_name,
                                            'payload': payload,
                                            'evidence': evidence,
                                            'request_url': form_url,
                                            'detector': 'Enhanced XXE Detection',
                                            'response_snippet': response_snippet,
                                            'remediation': 'Disable external entity processing in XML parsers'
                                        })
                                        break  # Found XXE, no need to test more payloads for this input
                                        
                                except Exception as e:
                                    print(f"    [XXE] Error testing form payload: {e}")
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
            
            payload_count = self.payload_limit if self.payload_limit > 0 else 35
            for payload in cmd_payloads[:payload_count]:
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
                    
                    # Enhanced Command Injection detection with false positive filtering
                    is_vulnerable, confidence, evidence = CommandInjectionDetector.detect_command_injection(
                        response.text, response.status_code, payload
                    )
                    
                    if is_vulnerable and confidence >= 0.7:  # High confidence threshold
                        response_snippet = CommandInjectionDetector.get_response_snippet(payload, response.text)
                        remediation = CommandInjectionDetector.get_remediation_advice()
                        print(f"    [CMDINJECTION] VULNERABILITY FOUND! Parameter: {param} (confidence: {confidence:.2f})")
                        
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
                            'detector': 'CommandInjectionDetector.enhanced_detection',
                            'response_snippet': response_snippet,
                            'remediation': remediation,
                            'confidence': confidence
                        })
                        break  # Found command injection, no need to test more payloads for this param
                        
                except Exception as e:
                    print(f"    [CMDINJECTION] Error testing payload: {e}")
                    continue
        
        # Test POST forms
        forms_data = parsed_data.get('forms', [])
        for i, form_data in enumerate(forms_data):
            form_method = form_data.get('method', 'GET').upper()
            form_action = form_data.get('action', '')
            form_inputs = form_data.get('inputs', [])
            
            if form_method in ['POST', 'PUT'] and form_inputs:
                print(f"    [CMDINJECTION] Testing {form_method} form {i+1}: {form_action}")
                
                # Build form URL
                if form_action.startswith('/'):
                    form_url = f"{parsed_data['scheme']}://{parsed_data['host']}{form_action}"
                elif form_action.startswith('http'):
                    form_url = form_action
                else:
                    form_url = f"{base_url.rstrip('/')}/{form_action}" if form_action else base_url
                
                # Test each form input
                for input_data in form_inputs:
                    input_name = input_data.get('name')
                    input_type = input_data.get('type', 'text')
                    
                    if not input_name or input_type in ['submit', 'button', 'hidden']:
                        continue
                    
                    print(f"    [CMDINJECTION] Testing form input: {input_name}")
                    
                    # Create deduplication key for this form input
                    form_key = f"cmdinjection_form_{form_url.split('?')[0]}_{input_name}"
                    if form_key in self.found_vulnerabilities:
                        print(f"    [CMDINJECTION] Skipping form input {input_name} - already tested")
                        continue
                    
                    payload_count = self.payload_limit if self.payload_limit > 0 else 20
                    for payload in cmd_payloads[:payload_count]:
                        try:
                            print(f"    [CMDINJECTION] Trying form payload: {payload}")
                            
                            # Prepare form data
                            post_data = {}
                            for inp in form_inputs:
                                inp_name = inp.get('name')
                                inp_value = inp.get('value', 'test')
                                inp_type = inp.get('type', 'text')
                                
                                if inp_name and inp_type not in ['submit', 'button']:
                                    if inp_name == input_name:
                                        post_data[inp_name] = payload
                                    else:
                                        post_data[inp_name] = inp_value
                            
                            if form_method == 'POST':
                                response = requests.post(
                                    form_url,
                                    data=post_data,
                                    timeout=self.config.timeout,
                                    headers=self.config.headers,
                                    verify=False
                                )
                            else:  # PUT
                                response = requests.put(
                                    form_url,
                                    data=post_data,
                                    timeout=self.config.timeout,
                                    headers=self.config.headers,
                                    verify=False
                                )
                            
                            print(f"    [CMDINJECTION] Form response code: {response.status_code}")
                            
                            # Enhanced Command Injection detection
                            is_vulnerable, confidence, evidence = CommandInjectionDetector.detect_command_injection(
                                response.text, response.status_code, payload
                            )
                            
                            if is_vulnerable and confidence >= 0.7:
                                response_snippet = CommandInjectionDetector.get_response_snippet(payload, response.text)
                                remediation = CommandInjectionDetector.get_remediation_advice()
                                print(f"    [CMDINJECTION] FORM VULNERABILITY FOUND! Input: {input_name} (confidence: {confidence:.2f})")
                                
                                # Mark as found to prevent duplicates
                                self.found_vulnerabilities.add(form_key)
                                
                                results.append({
                                    'module': 'commandinjection',
                                    'target': form_url,
                                    'vulnerability': f'Command Injection in {form_method} Form',
                                    'severity': 'High',
                                    'parameter': input_name,
                                    'payload': payload,
                                    'evidence': evidence,
                                    'request_url': form_url,
                                    'detector': 'CommandInjectionDetector.enhanced_detection',
                                    'response_snippet': response_snippet,
                                    'remediation': remediation,
                                    'confidence': confidence
                                })
                                break  # Found command injection, no need to test more payloads for this input
                                
                        except Exception as e:
                            print(f"    [CMDINJECTION] Error testing form payload: {e}")
                            continue
        
        return results

    def _test_path_traversal(self, parsed_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Test for Path Traversal vulnerabilities"""
        results = []
        base_url = parsed_data['url']
        
        # Get path traversal payloads from payload module
        try:
            from payloads.pathtraversal_payloads import PathTraversalPayloads
            path_payloads = PathTraversalPayloads.get_all_payloads()
        except ImportError:
            path_payloads = [
                '../../../etc/passwd',
                '..\\..\\..\\windows\\win.ini',
                '/etc/passwd',
                'C:\\windows\\win.ini'
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
        
        # Get LDAP injection payloads from payload module
        try:
            from payloads.ldapinjection_payloads import LDAPInjectionPayloads
            ldap_payloads = LDAPInjectionPayloads.get_all_payloads()
        except ImportError:
            ldap_payloads = [
                '*', '*)(&', '*))%00', '*()|%26',
                '*(|(mail=*))', '*(|(objectclass=*))'
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
            
            for payload in nosql_payloads[:30]:  # Увеличиваем до 30 payload
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
        
        # Get deserialization payloads from payload module
        try:
            from payloads.deserialization_payloads import DeserializationPayloads
            deser_payloads = DeserializationPayloads.get_all_payloads()
        except ImportError:
            deser_payloads = [
                'rO0ABXNyABFqYXZhLnV0aWwuSGFzaE1hcA==',  # Java serialized HashMap
                'O:8:"stdClass":0:{}',  # PHP serialized object
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
        """Test for HTTP Response Splitting vulnerabilities with enhanced detection"""
        results = []
        base_url = parsed_data['url']
        
        # Get HTTP Response Splitting payloads from payload module
        try:
            splitting_payloads = HTTPResponseSplittingDetector.get_splitting_indicators()
        except:
            splitting_payloads = [
                '%0d%0aSet-Cookie: test=injected',
                '%0d%0aLocation: http://evil.com'
            ]
        
        # Test GET parameters
        for param, values in parsed_data['query_params'].items():
            print(f"    [RESPONSESPLITTING] Testing parameter: {param}")
            
            # Create deduplication key for this parameter
            param_key = f"responsesplitting_{base_url.split('?')[0]}_{param}"
            if param_key in self.found_vulnerabilities:
                print(f"    [RESPONSESPLITTING] Skipping parameter {param} - already tested")
                continue
            
            # Get baseline response first
            try:
                baseline_response = requests.get(
                    parsed_data['url'],
                    timeout=self.config.timeout,
                    headers=self.config.headers,
                    verify=False
                )
                baseline_headers = dict(baseline_response.headers)
            except:
                baseline_headers = {}
            
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
                    
                    # Enhanced response splitting detection
                    is_splitting = self._enhanced_response_splitting_detection(
                        response.text, response.status_code, payload, 
                        dict(response.headers), baseline_headers
                    )
                    
                    if is_splitting:
                        evidence = f"HTTP Response Splitting detected - injected header found in response"
                        response_snippet = f"Headers: {dict(response.headers)}"
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
                            'detector': 'Enhanced Response Splitting Detection',
                            'response_snippet': response_snippet,
                            'remediation': 'Validate and sanitize all user inputs used in HTTP responses'
                        })
                        break  # Found response splitting, no need to test more payloads for this param
                        
                except Exception as e:
                    print(f"    [RESPONSESPLITTING] Error testing payload: {e}")
                    continue
        
        return results

    def _test_ssti(self, parsed_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Test for SSTI vulnerabilities"""
        results = []
        base_url = parsed_data['url']
        
        # Get SSTI payloads
        ssti_payloads = SSTIPayloads.get_all_payloads()
        
        # Test GET parameters
        for param, values in parsed_data['query_params'].items():
            print(f"    [SSTI] Testing parameter: {param}")
            
            # Create deduplication key for this parameter
            param_key = f"ssti_{base_url.split('?')[0]}_{param}"
            if param_key in self.found_vulnerabilities:
                print(f"    [SSTI] Skipping parameter {param} - already tested")
                continue
            
            payload_count = self.payload_limit if self.payload_limit > 0 else 40
            for payload in ssti_payloads[:payload_count]:
                try:
                    print(f"    [SSTI] Trying payload: {payload[:50]}...")
                    
                    # Create test URL
                    test_params = parsed_data['query_params'].copy()
                    test_params[param] = [payload]
                    
                    # Build query string
                    query_parts = []
                    for k, v_list in test_params.items():
                        for v in v_list:
                            query_parts.append(f"{k}={v}")
                    
                    test_url = f"{base_url.split('?')[0]}?{'&'.join(query_parts)}"
                    print(f"    [SSTI] Request URL: {test_url}")
                    
                    response = requests.get(
                        test_url,
                        timeout=self.config.timeout,
                        headers=self.config.headers,
                        verify=False
                    )
                    
                    print(f"    [SSTI] Response code: {response.status_code}")
                    
                    # Use SSTI detector
                    if SSTIDetector.detect_ssti(response.text, response.status_code, payload):
                        evidence = f"SSTI vulnerability detected - template injection: {payload}"
                        response_snippet = self._get_contextual_response_snippet(payload, response.text)
                        remediation = 'Use safe template engines. Implement proper input validation and sandboxing.'
                        print(f"    [SSTI] VULNERABILITY FOUND! Parameter: {param}")
                        
                        # Mark as found to prevent duplicates
                        self.found_vulnerabilities.add(param_key)
                        
                        results.append({
                            'module': 'ssti',
                            'target': base_url,
                            'vulnerability': 'Server-Side Template Injection',
                            'severity': 'High',
                            'parameter': param,
                            'payload': payload,
                            'evidence': evidence,
                            'request_url': test_url,
                            'detector': 'SSTIDetector.detect_ssti',
                            'response_snippet': response_snippet,
                            'remediation': remediation
                        })
                        break  # Found SSTI, no need to test more payloads for this param
                        
                except Exception as e:
                    print(f"    [SSTI] Error testing payload: {e}")
                    continue
        
        # Test POST forms
        forms_data = parsed_data.get('forms', [])
        for i, form_data in enumerate(forms_data):
            form_method = form_data.get('method', 'GET').upper()
            form_action = form_data.get('action', '')
            form_inputs = form_data.get('inputs', [])
            
            if form_method in ['POST', 'PUT'] and form_inputs:
                print(f"    [SSTI] Testing {form_method} form {i+1}: {form_action}")
                
                # Build form URL
                if form_action.startswith('/'):
                    form_url = f"{parsed_data['scheme']}://{parsed_data['host']}{form_action}"
                elif form_action.startswith('http'):
                    form_url = form_action
                else:
                    form_url = f"{base_url.rstrip('/')}/{form_action}" if form_action else base_url
                
                # Test each form input
                for input_data in form_inputs:
                    input_name = input_data.get('name')
                    input_type = input_data.get('type', 'text')
                    
                    if not input_name or input_type in ['submit', 'button', 'hidden']:
                        continue
                    
                    print(f"    [SSTI] Testing form input: {input_name}")
                    
                    # Create deduplication key for this form input
                    form_key = f"ssti_form_{form_url.split('?')[0]}_{input_name}"
                    if form_key in self.found_vulnerabilities:
                        print(f"    [SSTI] Skipping form input {input_name} - already tested")
                        continue
                    
                    payload_count = self.payload_limit if self.payload_limit > 0 else 20
                    for payload in ssti_payloads[:payload_count]:
                        try:
                            print(f"    [SSTI] Trying form payload: {payload[:50]}...")
                            
                            # Prepare form data
                            post_data = {}
                            for inp in form_inputs:
                                inp_name = inp.get('name')
                                inp_value = inp.get('value', 'test')
                                inp_type = inp.get('type', 'text')
                                
                                if inp_name and inp_type not in ['submit', 'button']:
                                    if inp_name == input_name:
                                        post_data[inp_name] = payload
                                    else:
                                        post_data[inp_name] = inp_value
                            
                            if form_method == 'POST':
                                response = requests.post(
                                    form_url,
                                    data=post_data,
                                    timeout=self.config.timeout,
                                    headers=self.config.headers,
                                    verify=False
                                )
                            else:  # PUT
                                response = requests.put(
                                    form_url,
                                    data=post_data,
                                    timeout=self.config.timeout,
                                    headers=self.config.headers,
                                    verify=False
                                )
                            
                            print(f"    [SSTI] Form response code: {response.status_code}")
                            
                            # Use SSTI detector
                            if SSTIDetector.detect_ssti(response.text, response.status_code, payload):
                                evidence = f"SSTI vulnerability in {form_method} form - template injection: {payload}"
                                response_snippet = self._get_contextual_response_snippet(payload, response.text)
                                remediation = 'Use safe template engines. Implement proper input validation and sandboxing.'
                                print(f"    [SSTI] FORM VULNERABILITY FOUND! Input: {input_name}")
                                
                                # Mark as found to prevent duplicates
                                self.found_vulnerabilities.add(form_key)
                                
                                results.append({
                                    'module': 'ssti',
                                    'target': form_url,
                                    'vulnerability': f'Server-Side Template Injection in {form_method} Form',
                                    'severity': 'High',
                                    'parameter': input_name,
                                    'payload': payload,
                                    'evidence': evidence,
                                    'request_url': form_url,
                                    'detector': 'SSTIDetector.detect_ssti',
                                    'response_snippet': response_snippet,
                                    'remediation': remediation
                                })
                                break  # Found SSTI, no need to test more payloads for this input
                                
                        except Exception as e:
                            print(f"    [SSTI] Error testing form payload: {e}")
                            continue
        
        return results
    
    def _test_crlf(self, parsed_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Test for CRLF injection vulnerabilities with enhanced detection"""
        results = []
        base_url = parsed_data['url']
        
        # Get CRLF payloads from payload module
        crlf_payloads = CRLFPayloads.get_all_payloads()
        
        # Test GET parameters
        for param, values in parsed_data['query_params'].items():
            print(f"    [CRLF] Testing parameter: {param}")
            
            # Create deduplication key for this parameter
            param_key = f"crlf_{base_url.split('?')[0]}_{param}"
            if param_key in self.found_vulnerabilities:
                print(f"    [CRLF] Skipping parameter {param} - already tested")
                continue
            
            # Get baseline response first
            try:
                baseline_response = requests.get(
                    parsed_data['url'],
                    timeout=self.config.timeout,
                    headers=self.config.headers,
                    verify=False
                )
                baseline_headers = dict(baseline_response.headers)
            except:
                baseline_headers = {}
            
            for payload in crlf_payloads:
                try:
                    print(f"    [CRLF] Trying payload: {payload[:50]}...")
                    
                    # Create test URL
                    test_params = parsed_data['query_params'].copy()
                    test_params[param] = [payload]
                    
                    # Build query string
                    query_parts = []
                    for k, v_list in test_params.items():
                        for v in v_list:
                            query_parts.append(f"{k}={v}")
                    
                    test_url = f"{base_url.split('?')[0]}?{'&'.join(query_parts)}"
                    print(f"    [CRLF] Request URL: {test_url}")
                    
                    response = requests.get(
                        test_url,
                        timeout=self.config.timeout,
                        headers=self.config.headers,
                        verify=False
                    )
                    
                    print(f"    [CRLF] Response code: {response.status_code}")
                    
                    # Enhanced CRLF detection
                    is_crlf = self._enhanced_crlf_detection(
                        response.text, response.status_code, payload, 
                        dict(response.headers), baseline_headers
                    )
                    
                    if is_crlf:
                        evidence = f"CRLF injection detected - header injection successful"
                        response_snippet = f"Injected headers found in response"
                        print(f"    [CRLF] VULNERABILITY FOUND! Parameter: {param}")
                        
                        # Mark as found to prevent duplicates
                        self.found_vulnerabilities.add(param_key)
                        
                        results.append({
                            'module': 'crlf',
                            'target': base_url,
                            'vulnerability': 'CRLF Injection',
                            'severity': 'Medium',
                            'parameter': param,
                            'payload': payload,
                            'evidence': evidence,
                            'request_url': test_url,
                            'detector': 'Enhanced CRLF Detection',
                            'response_snippet': response_snippet,
                            'remediation': 'Validate and sanitize all user inputs used in HTTP responses'
                        })
                        break  # Found CRLF, no need to test more payloads for this param
                        
                except Exception as e:
                    print(f"    [CRLF] Error testing payload: {e}")
                    continue
        
        return results

    def _test_text_injection(self, parsed_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Test for Text Injection vulnerabilities"""
        results = []
        base_url = parsed_data['url']
        
        # Get text injection payloads
        text_payloads = TextInjectionPayloads.get_all_payloads()
        
        # Update payload stats
        if 'textinjection' not in self.scan_stats['payload_stats']:
            self.scan_stats['payload_stats']['textinjection'] = {'payloads_used': 0, 'requests_made': 0, 'successful_payloads': 0}
        self.scan_stats['payload_stats']['textinjection']['payloads_used'] += len(text_payloads)
        
        # Test GET parameters
        for param, values in parsed_data['query_params'].items():
            print(f"    [TEXTINJECTION] Testing parameter: {param}")
            
            # Create deduplication key for this parameter
            param_key = f"textinjection_{base_url.split('?')[0]}_{param}"
            if param_key in self.found_vulnerabilities:
                print(f"    [TEXTINJECTION] Skipping parameter {param} - already tested")
                continue
            
            payload_count = self.payload_limit if self.payload_limit > 0 else 40
            for payload in text_payloads[:payload_count]:
                try:
                    print(f"    [TEXTINJECTION] Trying payload: {payload[:50]}...")
                    
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
                    
                    # Update request count
                    self.request_count += 1
                    self.scan_stats['payload_stats']['textinjection']['requests_made'] += 1
                    
                    print(f"    [TEXTINJECTION] Response code: {response.status_code}")
                    
                    # Use Text Injection detector
                    if TextInjectionDetector.detect_text_injection(response.text, response.status_code, payload):
                        evidence = TextInjectionDetector.get_evidence(payload, response.text)
                        response_snippet = TextInjectionDetector.get_response_snippet(payload, response.text)
                        remediation = TextInjectionDetector.get_remediation_advice()
                        print(f"    [TEXTINJECTION] VULNERABILITY FOUND! Parameter: {param}")
                        
                        # Mark as found to prevent duplicates
                        self.found_vulnerabilities.add(param_key)
                        
                        # Update successful payload count
                        self.scan_stats['payload_stats']['textinjection']['successful_payloads'] += 1
                        self.scan_stats['total_payloads_used'] += 1
                        
                        results.append({
                            'module': 'textinjection',
                            'target': base_url,
                            'vulnerability': 'Text Injection',
                            'severity': 'Medium',
                            'parameter': param,
                            'payload': payload,
                            'evidence': evidence,
                            'request_url': test_url,
                            'detector': 'TextInjectionDetector.detect_text_injection',
                            'response_snippet': response_snippet,
                            'remediation': remediation
                        })
                        break  # Found text injection, no need to test more payloads for this param
                        
                except Exception as e:
                    print(f"    [TEXTINJECTION] Error testing payload: {e}")
                    continue
        
        return results

    def _test_html_injection(self, parsed_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Test for HTML Injection vulnerabilities"""
        results = []
        base_url = parsed_data['url']
        
        # Get HTML injection payloads
        html_payloads = HTMLInjectionPayloads.get_all_payloads()
        
        # Update payload stats
        if 'htmlinjection' not in self.scan_stats['payload_stats']:
            self.scan_stats['payload_stats']['htmlinjection'] = {'payloads_used': 0, 'requests_made': 0, 'successful_payloads': 0}
        self.scan_stats['payload_stats']['htmlinjection']['payloads_used'] += len(html_payloads)
        
        # Test GET parameters
        for param, values in parsed_data['query_params'].items():
            print(f"    [HTMLINJECTION] Testing parameter: {param}")
            
            # Create deduplication key for this parameter
            param_key = f"htmlinjection_{base_url.split('?')[0]}_{param}"
            if param_key in self.found_vulnerabilities:
                print(f"    [HTMLINJECTION] Skipping parameter {param} - already tested")
                continue
            
            payload_count = self.payload_limit if self.payload_limit > 0 else 50
            for payload in html_payloads[:payload_count]:
                try:
                    print(f"    [HTMLINJECTION] Trying payload: {payload[:50]}...")
                    
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
                    
                    # Update request count
                    self.request_count += 1
                    self.scan_stats['payload_stats']['htmlinjection']['requests_made'] += 1
                    
                    print(f"    [HTMLINJECTION] Response code: {response.status_code}")
                    
                    # Use HTML Injection detector
                    if HTMLInjectionDetector.detect_html_injection(response.text, response.status_code, payload):
                        evidence = HTMLInjectionDetector.get_evidence(payload, response.text)
                        response_snippet = HTMLInjectionDetector.get_response_snippet(payload, response.text)
                        remediation = HTMLInjectionDetector.get_remediation_advice()
                        print(f"    [HTMLINJECTION] VULNERABILITY FOUND! Parameter: {param}")
                        
                        # Mark as found to prevent duplicates
                        self.found_vulnerabilities.add(param_key)
                        
                        # Update successful payload count
                        self.scan_stats['payload_stats']['htmlinjection']['successful_payloads'] += 1
                        self.scan_stats['total_payloads_used'] += 1
                        
                        results.append({
                            'module': 'htmlinjection',
                            'target': base_url,
                            'vulnerability': 'HTML Injection',
                            'severity': 'Medium',
                            'parameter': param,
                            'payload': payload,
                            'evidence': evidence,
                            'request_url': test_url,
                            'detector': 'HTMLInjectionDetector.detect_html_injection',
                            'response_snippet': response_snippet,
                            'remediation': remediation
                        })
                        break  # Found HTML injection, no need to test more payloads for this param
                        
                except Exception as e:
                    print(f"    [HTMLINJECTION] Error testing payload: {e}")
                    continue
        
        return results
    
    def _test_host_header(self, parsed_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Test for Host Header vulnerabilities"""
        results = []
        base_url = parsed_data['url']
        
        try:
            print(f"    [HOSTHEADER] Testing Host Header vulnerabilities...")
            
            is_vulnerable, evidence, severity, vulnerabilities = HostHeaderDetector.detect_host_header_injection(
                base_url, self.config.headers, self.config.timeout
            )
            
            if is_vulnerable and vulnerabilities:
                for vuln in vulnerabilities:
                    results.append({
                        'module': 'hostheader',
                        'target': base_url,
                        'vulnerability': f'Host Header {vuln["type"].replace("_", " ").title()}',
                        'severity': vuln['severity'],
                        'parameter': 'Host',
                        'payload': vuln['payload'],
                        'evidence': vuln['evidence'],
                        'request_url': base_url,
                        'detector': 'HostHeaderDetector.detect_host_header_injection',
                        'response_snippet': f'Host: {vuln["payload"]}',
                        'remediation': HostHeaderDetector.get_remediation_advice()
                    })
                
                print(f"    [HOSTHEADER] Found {len(vulnerabilities)} Host Header vulnerabilities")
            else:
                print(f"    [HOSTHEADER] No Host Header vulnerabilities found")
            
        except Exception as e:
            print(f"    [HOSTHEADER] Error during Host Header testing: {e}")
        
        return results
    
    def _test_prototype_pollution(self, parsed_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Test for Prototype Pollution vulnerabilities"""
        results = []
        base_url = parsed_data['url']
        
        try:
            print(f"    [PROTOTYPEPOLLUTION] Testing Prototype Pollution vulnerabilities...")
            
            is_vulnerable, evidence, severity, vulnerabilities = PrototypePollutionDetector.detect_prototype_pollution(
                base_url, self.config.headers, self.config.timeout
            )
            
            if is_vulnerable and vulnerabilities:
                for vuln in vulnerabilities:
                    results.append({
                        'module': 'prototypepollution',
                        'target': base_url,
                        'vulnerability': 'Prototype Pollution',
                        'severity': vuln['severity'],
                        'parameter': 'JSON/Form data',
                        'payload': vuln['payload'],
                        'evidence': vuln['evidence'],
                        'request_url': base_url,
                        'detector': 'PrototypePollutionDetector.detect_prototype_pollution',
                        'response_snippet': f'Payload: {vuln["payload"]}',
                        'remediation': PrototypePollutionDetector.get_remediation_advice()
                    })
                
                print(f"    [PROTOTYPEPOLLUTION] Found {len(vulnerabilities)} Prototype Pollution vulnerabilities")
            else:
                print(f"    [PROTOTYPEPOLLUTION] No Prototype Pollution vulnerabilities found")
            
        except Exception as e:
            print(f"    [PROTOTYPEPOLLUTION] Error during Prototype Pollution testing: {e}")
        
        return results
    
    def _test_vhost(self, parsed_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Test for Virtual Host discovery"""
        results = []
        base_url = parsed_data['url']
        
        try:
            print(f"    [VHOST] Testing Virtual Host discovery...")
            
            is_vulnerable, evidence, severity, vhosts = VHostDetector.detect_virtual_hosts(
                base_url, self.config.headers, self.config.timeout
            )
            
            if is_vulnerable and vhosts:
                for vhost in vhosts:
                    results.append({
                        'module': 'vhost',
                        'target': base_url,
                        'vulnerability': 'Virtual Host Discovered',
                        'severity': 'Medium',
                        'parameter': 'Host',
                        'payload': vhost['vhost'],
                        'evidence': vhost['evidence'],
                        'request_url': base_url,
                        'detector': 'VHostDetector.detect_virtual_hosts',
                        'response_snippet': f'Status: {vhost["status_code"]}, Length: {vhost["content_length"]}',
                        'remediation': VHostDetector.get_remediation_advice()
                    })
                
                print(f"    [VHOST] Discovered {len(vhosts)} Virtual Hosts")
            else:
                print(f"    [VHOST] No Virtual Hosts discovered")
            
        except Exception as e:
            print(f"    [VHOST] Error during Virtual Host testing: {e}")
        
        return results
    
    def _test_information_leakage(self, parsed_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Test for information leakage vulnerabilities with domain-level deduplication"""
        results = []
        base_url = parsed_data['url']
        
        # Extract domain for deduplication
        from urllib.parse import urlparse
        parsed_url = urlparse(base_url)
        domain = parsed_url.hostname
        
        # Create deduplication key for this domain
        domain_key = f"infoleak_{domain}"
        if domain_key in self.found_vulnerabilities:
            print(f"    [INFOLEAK] Skipping information leakage test for {domain} - already tested")
            return results
        
        try:
            print(f"    [INFOLEAK] Testing for information leakage on domain: {domain}")
            
            # Mark domain as tested
            self.found_vulnerabilities.add(domain_key)
            
            # Make request to get page content
            response = requests.get(
                base_url,
                timeout=self.config.timeout,
                headers=self.config.headers,
                verify=False
            )
            
            print(f"    [INFOLEAK] Response code: {response.status_code}")
            
            # Load email patterns from file and check for email addresses
            import re
            email_patterns = PayloadLoader.load_patterns('email')
            if not email_patterns:
                # Fallback to basic pattern if file not found
                email_pattern = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
            else:
                email_pattern = email_patterns[0]  # Use first pattern from file
            emails = re.findall(email_pattern, response.text)
            
            if emails:
                unique_emails = list(set(emails))
                print(f"    [INFOLEAK] Found {len(unique_emails)} unique email addresses")
                
                evidence = f"Email addresses found: {', '.join(unique_emails[:5])}"
                if len(unique_emails) > 5:
                    evidence += f" and {len(unique_emails) - 5} more"
                
                results.append({
                    'module': 'infoleak',
                    'target': base_url,
                    'vulnerability': f'Email Address Disclosure ({len(unique_emails)} addresses)',
                    'severity': 'Low',
                    'parameter': 'response_content',
                    'payload': 'N/A',
                    'evidence': evidence,
                    'request_url': base_url,
                    'detector': 'regex_email_detection',
                    'response_snippet': f'Found {len(unique_emails)} unique email addresses',
                    'email_addresses': unique_emails  # Store for detailed reporting
                })
            
            # Load IP patterns from file and check for internal IP addresses
            ip_patterns = PayloadLoader.load_patterns('internal_ip')
            if not ip_patterns:
                # Fallback to basic pattern if file not found
                ip_pattern = r'\b(?:127\.0\.0\.1|192\.168\.\d{1,3}\.\d{1,3}|10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3})\b'
            else:
                ip_pattern = ip_patterns[0]  # Use first pattern from file
            internal_ips = re.findall(ip_pattern, response.text)
            
            if internal_ips:
                unique_ips = list(set(internal_ips))
                print(f"    [INFOLEAK] Found {len(unique_ips)} internal IP addresses")
                
                evidence = f"Internal IP addresses found: {', '.join(unique_ips)}"
                
                results.append({
                    'module': 'infoleak',
                    'target': base_url,
                    'vulnerability': 'Internal IP Address Disclosure',
                    'severity': 'Medium',
                    'parameter': 'response_content',
                    'payload': 'N/A',
                    'evidence': evidence,
                    'request_url': base_url,
                    'detector': 'regex_ip_detection',
                    'response_snippet': f'Found {len(unique_ips)} internal IPs'
                })
            
            # Load debug patterns from file
            debug_patterns = PayloadLoader.load_patterns('debug')
            if not debug_patterns:
                # Fallback to basic patterns if file not found
                debug_patterns = ['debug', 'trace', 'error_reporting', 'var_dump']
            
            response_lower = response.text.lower()
            found_debug = [pattern for pattern in debug_patterns if pattern in response_lower]
            
            if found_debug:
                print(f"    [INFOLEAK] Found debug information: {found_debug}")
                
                evidence = f"Debug information found: {', '.join(found_debug)}"
                
                results.append({
                    'module': 'infoleak',
                    'target': base_url,
                    'vulnerability': 'Debug Information Disclosure',
                    'severity': 'Low',
                    'parameter': 'response_content',
                    'payload': 'N/A',
                    'evidence': evidence,
                    'request_url': base_url,
                    'detector': 'debug_pattern_detection',
                    'response_snippet': f'Debug patterns: {", ".join(found_debug)}'
                })
            
        except Exception as e:
            print(f"    [INFOLEAK] Error during information leakage testing: {e}")
        
        return results
    
    def _test_open_redirect(self, parsed_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Test for Open Redirect vulnerabilities"""
        results = []
        base_url = parsed_data['url']
        
        # Get open redirect payloads from payload module
        try:
            from payloads.openredirect_payloads import OpenRedirectPayloads
            redirect_payloads = OpenRedirectPayloads.get_all_payloads()
        except ImportError:
            redirect_payloads = [
                'http://evil.com',
                'https://attacker.com', 
                '//evil.com',
                'javascript:alert(1)'
            ]
        
        # Enhanced redirect parameters
        redirect_params = ['url', 'redirect', 'return', 'next', 'goto', 'target', 'link', 'site', 'file', 'page', 'path']
        
        # Test for HTTP Parameter Pollution (HPP) on any site with duplicate parameters
        duplicate_params = []
        for param in parsed_data['query_params'].keys():
            if len(parsed_data['query_params'][param]) > 1:
                duplicate_params.append(param)
        
        if duplicate_params:
            print(f"    [OPENREDIRECT] Testing HPP with duplicate parameters: {duplicate_params}")
            for param in duplicate_params:
                hpp_payloads = [
                    f'{param}=1&{param}=2&{param}=3',
                    f'{param}=valid&{param}=12&{param}=13',
                    f'{param}=test&{param}=evil&{param}=good'
                ]
                
                for hpp_payload in hpp_payloads:
                    try:
                        test_url = f"{base_url.split('?')[0]}?{hpp_payload}"
                        response = requests.get(
                            test_url,
                            timeout=self.config.timeout,
                            headers=self.config.headers,
                            verify=False,
                            allow_redirects=False
                        )
                        
                        if response.status_code == 200:
                            results.append({
                                'module': 'openredirect',
                                'target': base_url,
                                'vulnerability': 'HTTP Parameter Pollution (HPP)',
                                'severity': 'Medium',
                                'parameter': param,
                                'payload': hpp_payload,
                                'evidence': f'HPP detected - multiple {param} parameters processed: {hpp_payload}',
                                'request_url': test_url,
                                'detector': 'hpp_parameter_analysis',
                                'response_snippet': response.text[:200] + '...' if len(response.text) > 200 else response.text,
                                'remediation': 'Properly handle duplicate parameters and validate input'
                            })
                            break
                    except Exception as e:
                        continue
        
        for param, values in parsed_data['query_params'].items():
            # Check if parameter name suggests it might be used for redirects or file access
            if any(redirect_param in param.lower() for redirect_param in redirect_params):
                print(f"    [OPENREDIRECT] Testing parameter: {param}")
                
                # Create deduplication key for this parameter
                param_key = f"openredirect_{base_url.split('?')[0]}_{param}"
                if param_key in self.found_vulnerabilities:
                    print(f"    [OPENREDIRECT] Skipping parameter {param} - already tested")
                    continue
                
                for payload in redirect_payloads:
                    try:
                        print(f"    [OPENREDIRECT] Trying payload: {payload}")
                        
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
                            verify=False,
                            allow_redirects=False  # Don't follow redirects
                        )
                        
                        print(f"    [OPENREDIRECT] Response code: {response.status_code}")
                        
                        # Check for redirect responses
                        if response.status_code in [301, 302, 303, 307, 308]:
                            location = response.headers.get('Location', '')
                            if payload in location or 'evil.com' in location or 'attacker.com' in location:
                                print(f"    [OPENREDIRECT] VULNERABILITY FOUND! Parameter: {param}")
                                
                                # Mark as found to prevent duplicates
                                self.found_vulnerabilities.add(param_key)
                                
                                evidence = f"Open redirect detected - Location header: {location}"
                                
                                results.append({
                                    'module': 'openredirect',
                                    'target': base_url,
                                    'vulnerability': 'Open Redirect',
                                    'severity': 'Medium',
                                    'parameter': param,
                                    'payload': payload,
                                    'evidence': evidence,
                                    'request_url': test_url,
                                    'detector': 'redirect_header_analysis',
                                    'response_snippet': f'Location: {location}',
                                    'remediation': 'Validate redirect URLs against a whitelist of allowed domains'
                                })
                                break  # Found open redirect, no need to test more payloads for this param
                                
                    except Exception as e:
                        print(f"    [OPENREDIRECT] Error testing payload: {e}")
                        continue
        
        return results
    
    
    def _get_success_indicators(self) -> List[str]:
        """Get indicators that suggest a request was successful"""
        # Load success indicators from file
        success_indicators = PayloadLoader.load_indicators('success')
        if not success_indicators:
            # Fallback to basic indicators if file not found
            success_indicators = ['success', 'successful', 'completed', 'saved']
        return success_indicators
    
    def _is_likely_404_response(self, response_text: str, response_code: int) -> bool:
        """Quick check if response is likely a 404 page"""
        if response_code == 404:
            return True
        
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
    
    
    
    def _is_meaningful_404(self, response_text: str) -> bool:
        """Check if 404 response contains meaningful content that might indicate vulnerabilities"""
        if len(response_text.strip()) < 100:
            return False
        
        # Load meaningful 404 patterns from file
        meaningful_patterns = PayloadLoader.load_patterns('meaningful_404')
        if not meaningful_patterns:
            # Fallback to basic patterns if file not found
            meaningful_patterns = ['error', 'exception', 'mysql', 'sql', 'include']
        
        response_lower = response_text.lower()
        meaningful_count = sum(1 for pattern in meaningful_patterns if pattern in response_lower)
        
        return meaningful_count >= 2
    
    def _should_stop(self) -> bool:
        """Check scan stop conditions"""
        if self.stop_requested:
            print(f"[STOP] Scan stop requested")
            return True
        # Increase request limit threshold or disable for deep scanning
        if self.config.request_limit and self.request_count >= (self.config.request_limit * 2):
            print(f"[LIMIT] Request limit reached: {self.request_count}/{self.config.request_limit * 2}")
            return True
        return False
    
    def save_report(self, results: List[Dict[str, Any]], filename: str, format_type: str):
        """Save auto-report (HTML only)"""
        # Ensure all vulnerabilities have required metadata
        enhanced_results = self._ensure_vulnerability_metadata(results)
        
        if format_type == 'html':
            self.file_handler.save_html(enhanced_results, filename)
        else:
            # Force HTML format for all reports
            self.file_handler.save_html(enhanced_results, filename.replace('.txt', '.html').replace('.json', '.html').replace('.xml', '.html'))
        
    
    def _ensure_vulnerability_metadata(self, results: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Ensure all vulnerabilities have CVSS, OWASP, and CWE metadata"""
        enhanced_results = []
        
        for result in results:
            # Create a clean copy of the result to avoid reference issues
            clean_result = {}
            
            # Copy all serializable data
            for key, value in result.items():
                try:
                    # Test if value is JSON serializable
                    json.dumps(value)
                    clean_result[key] = value
                except (TypeError, ValueError):
                    # Convert non-serializable values to strings
                    if isinstance(value, (list, dict, set)):
                        try:
                            clean_result[key] = self._clean_data_structure(value)
                        except:
                            clean_result[key] = str(value)
                    else:
                        clean_result[key] = str(value)
            
            if 'vulnerability' in clean_result and clean_result.get('vulnerability'):
                # Sanitize dangerous fields to prevent XSS in reports
                clean_result = self._sanitize_vulnerability_data(clean_result)
                
                # Use PayloadLoader to get metadata from JSON file
                module_name = clean_result.get('module', 'unknown')
                severity = clean_result.get('severity', 'Medium')
                metadata = PayloadLoader.get_vulnerability_metadata(module_name, severity)
                
                # Ensure required metadata exists
                if 'cvss' not in clean_result:
                    clean_result['cvss'] = metadata.get('cvss', self._get_default_cvss(severity))
                if 'owasp' not in clean_result:
                    clean_result['owasp'] = metadata.get('owasp', self._get_default_owasp(module_name))
                if 'cwe' not in clean_result:
                    clean_result['cwe'] = metadata.get('cwe', self._get_default_cwe(module_name))
                if 'recommendation' not in clean_result:
                    clean_result['recommendation'] = metadata.get('recommendation', self._get_default_recommendation(module_name))
            
            enhanced_results.append(clean_result)
        
        return enhanced_results
    
    def _get_default_cvss(self, severity: str) -> str:
        """Get default CVSS score based on severity"""
        cvss_mapping = {
            'Critical': '9.8',
            'High': '8.8', 
            'Medium': '6.5',
            'Low': '3.1',
            'Info': '0.0'
        }
        return cvss_mapping.get(severity, '6.5')
    
    def _get_default_owasp(self, module: str) -> str:
        """Get default OWASP classification based on module"""
        owasp_mapping = {
            'xss': 'A03:2021 – Injection',
            'sqli': 'A03:2021 – Injection', 
            'lfi': 'A03:2021 – Injection',
            'rfi': 'A03:2021 – Injection',
            'xxe': 'A05:2021 – Security Misconfiguration',
            'csrf': 'A01:2021 – Broken Access Control',
            'idor': 'A01:2021 – Broken Access Control',
            'commandinjection': 'A03:2021 – Injection',
            'pathtraversal': 'A03:2021 – Injection',
            'ldapinjection': 'A03:2021 – Injection',
            'nosqlinjection': 'A03:2021 – Injection',
            'ssti': 'A03:2021 – Injection',
            'crlf': 'A03:2021 – Injection',
            'htmlinjection': 'A03:2021 – Injection',
            'textinjection': 'A03:2021 – Injection',
            'secheaders': 'A05:2021 – Security Misconfiguration',
            'httponlycookies': 'A05:2021 – Security Misconfiguration',
            'ssltls': 'A02:2021 – Cryptographic Failures',
            'cors': 'A05:2021 – Security Misconfiguration',
            'clickjacking': 'A05:2021 – Security Misconfiguration',
            'fileupload': 'A03:2021 – Injection',
            'jwt': 'A02:2021 – Cryptographic Failures',
            'deserialization': 'A08:2021 – Software and Data Integrity Failures',
            'responsesplitting': 'A03:2021 – Injection'
        }
        return owasp_mapping.get(module, 'A06:2021 – Vulnerable and Outdated Components')
    
    def _get_default_cwe(self, module: str) -> str:
        """Get default CWE classification based on module"""
        cwe_mapping = {
            'xss': 'CWE-79',
            'sqli': 'CWE-89',
            'lfi': 'CWE-22',
            'rfi': 'CWE-98', 
            'xxe': 'CWE-611',
            'csrf': 'CWE-352',
            'idor': 'CWE-639',
            'commandinjection': 'CWE-78',
            'pathtraversal': 'CWE-22',
            'ldapinjection': 'CWE-90',
            'nosqlinjection': 'CWE-943',
            'ssti': 'CWE-94',
            'crlf': 'CWE-93',
            'htmlinjection': 'CWE-79',
            'textinjection': 'CWE-74',
            'secheaders': 'CWE-16',
            'httponlycookies': 'CWE-614',
            'ssltls': 'CWE-326',
            'cors': 'CWE-346',
            'clickjacking': 'CWE-1021',
            'fileupload': 'CWE-434',
            'jwt': 'CWE-287',
            'deserialization': 'CWE-502',
            'responsesplitting': 'CWE-113'
        }
        return cwe_mapping.get(module, 'CWE-200')
    
    def _get_default_recommendation(self, module: str) -> str:
        """Get default recommendation based on module"""
        recommendations = {
            'xss': 'Implement proper input validation and output encoding. Use Content Security Policy (CSP).',
            'sqli': 'Use parameterized queries/prepared statements. Implement proper input validation.',
            'lfi': 'Validate and sanitize file paths. Use whitelisting for allowed files.',
            'rfi': 'Disable remote file inclusion. Validate and sanitize all file inputs.',
            'xxe': 'Disable external entity processing in XML parsers. Use secure XML parsing libraries.',
            'csrf': 'Implement CSRF tokens. Use SameSite cookie attributes.',
            'idor': 'Implement proper access controls and authorization checks.',
            'commandinjection': 'Avoid executing system commands with user input. Use parameterized APIs.',
            'pathtraversal': 'Validate and sanitize file paths. Use whitelisting for allowed directories.',
            'ldapinjection': 'Use parameterized LDAP queries. Implement proper input validation.',
            'nosqlinjection': 'Use parameterized queries. Implement proper input validation and sanitization.',
            'ssti': 'Use safe template engines. Implement proper input validation and sandboxing.',
            'crlf': 'Validate and sanitize all user inputs. Encode special characters.',
            'htmlinjection': 'Implement proper HTML encoding and Content Security Policy (CSP).',
            'textinjection': 'Implement proper input validation and output encoding.',
            'secheaders': 'Configure proper security headers to protect against common attacks.',
            'httponlycookies': 'Set HttpOnly, Secure, and SameSite flags on all cookies.',
            'ssltls': 'Use strong TLS configuration with modern cipher suites.',
            'cors': 'Configure CORS policy properly. Avoid using wildcard origins.',
            'clickjacking': 'Implement X-Frame-Options or CSP frame-ancestors directive.',
            'fileupload': 'Validate file types, scan for malware, and store uploads securely.',
            'jwt': 'Use strong signing algorithms and validate JWT tokens properly.',
            'deserialization': 'Avoid deserializing untrusted data. Use safe serialization formats.',
            'responsesplitting': 'Validate and sanitize all user inputs used in HTTP responses.'
        }
        return recommendations.get(module, 'Review and implement appropriate security controls.')
    
    def _get_contextual_response_snippet(self, payload: str, response_text: str, context_size: int = 30) -> str:
        """Get response snippet with context around where payload was found"""
        if not payload or not response_text:
            return response_text[:100] + "..." if len(response_text) > 100 else response_text
        
        # Find payload in response (case insensitive)
        payload_lower = payload.lower()
        response_lower = response_text.lower()
        
        # Try to find exact payload first
        pos = response_lower.find(payload_lower)
        
        if pos == -1:
            # Try to find parts of payload
            payload_parts = [part for part in payload_lower.split() if len(part) > 3]
            for part in payload_parts:
                pos = response_lower.find(part)
                if pos != -1:
                    break
        
        if pos == -1:
            # Payload not found, return beginning of response
            return response_text[:100] + "..." if len(response_text) > 100 else response_text
        
        # Calculate context boundaries
        start = max(0, pos - context_size)
        end = min(len(response_text), pos + len(payload) + context_size)
        
        # Extract context
        context = response_text[start:end]
        
        # Add ellipsis if truncated
        if start > 0:
            context = "..." + context
        if end < len(response_text):
            context = context + "..."
        
        return context
    
    def _sanitize_vulnerability_data(self, vuln_data: Dict[str, Any]) -> Dict[str, Any]:
        """Sanitize vulnerability data to prevent XSS in reports"""
        # Fields that may contain dangerous payloads
        dangerous_fields = [
            'payload', 'evidence', 'response_snippet', 'request_url',
            'vulnerability', 'parameter', 'target'
        ]
        
        sanitized = vuln_data.copy()
        
        for field in dangerous_fields:
            if field in sanitized and sanitized[field]:
                # HTML escape the content to prevent XSS
                original_value = str(sanitized[field])
                sanitized[field] = html.escape(original_value, quote=True)
                
                # Store original value for technical analysis if needed
                sanitized[f'{field}_raw'] = original_value
        
        return sanitized
    
    def _enhanced_rfi_detection(self, response_text: str, response_code: int, payload: str, 
                               baseline_content: str, baseline_length: int) -> bool:
        """Enhanced RFI detection with false positive filtering"""
        try:
            # Skip if response is error or too similar to baseline
            if response_code >= 400:
                return False
            
            # Check for significant content change
            content_diff = abs(len(response_text) - baseline_length)
            if content_diff < 100:  # Minimal content change
                return False
            
            # Load remote content indicators from file
            remote_indicators = PayloadLoader.load_indicators('remote_content')
            if not remote_indicators:
                # Fallback to basic indicators if file not found
                remote_indicators = ['<?php', '<html', '<script', 'http://', 'https://']
            
            response_lower = response_text.lower()
            baseline_lower = baseline_content.lower()
            
            # Check if new content appeared that wasn't in baseline
            new_indicators = []
            for indicator in remote_indicators:
                if indicator in response_lower and indicator not in baseline_lower:
                    new_indicators.append(indicator)
            
            # Require at least 2 new indicators for RFI
            return len(new_indicators) >= 2
            
        except Exception as e:
            print(f"    [RFI] Enhanced detection error: {e}")
            return False
    
    def _enhanced_xxe_detection(self, response_text: str, response_code: int, payload: str) -> bool:
        """Enhanced XXE detection with false positive filtering"""
        try:
            # Skip if response is error
            if response_code >= 400:
                return False
            
            # Load XXE indicators from file
            xxe_indicators = PayloadLoader.load_indicators('xxe')
            if not xxe_indicators:
                # Fallback to basic indicators if file not found
                xxe_indicators = ['root:x:0:0:root', 'ENTITY', 'DOCTYPE', 'file://']
            
            response_lower = response_text.lower()
            
            # Check for XXE-specific content
            xxe_matches = 0
            for indicator in xxe_indicators:
                if indicator.lower() in response_lower:
                    xxe_matches += 1
            
            # Also check if XML payload structure is reflected
            if '<!ENTITY' in payload and 'ENTITY' in response_text:
                xxe_matches += 1
            
            # Require multiple indicators for XXE
            return xxe_matches >= 2
            
        except Exception as e:
            print(f"    [XXE] Enhanced detection error: {e}")
            return False
    
    def _enhanced_response_splitting_detection(self, response_text: str, response_code: int, 
                                             payload: str, response_headers: dict, 
                                             baseline_headers: dict) -> bool:
        """Enhanced HTTP Response Splitting detection"""
        try:
            # Check for new headers that weren't in baseline
            new_headers = []
            for header, value in response_headers.items():
                if header.lower() not in [h.lower() for h in baseline_headers.keys()]:
                    new_headers.append(header)
            
            # Check for specific injected headers
            injected_headers = ['set-cookie', 'location', 'x-injected-header', 'content-type']
            
            for header in new_headers:
                if any(inj_header in header.lower() for inj_header in injected_headers):
                    # Verify the header value contains our payload markers
                    header_value = response_headers.get(header, '').lower()
                    if any(marker in header_value for marker in ['injected', 'test', 'evil']):
                        return True
            
            return False
            
        except Exception as e:
            print(f"    [RESPONSESPLITTING] Enhanced detection error: {e}")
            return False
    
    def _enhanced_crlf_detection(self, response_text: str, response_code: int, 
                                payload: str, response_headers: dict, 
                                baseline_headers: dict) -> bool:
        """Enhanced CRLF injection detection"""
        try:
            # Similar to response splitting but more focused on CRLF
            if '%0d%0a' not in payload and '%0a' not in payload:
                return False
            
            # Check for new headers
            new_headers = []
            for header, value in response_headers.items():
                if header.lower() not in [h.lower() for h in baseline_headers.keys()]:
                    new_headers.append((header, value))
            
            # Look for CRLF-specific injected headers
            crlf_markers = ['crlf', 'injected', 'test']
            
            for header, value in new_headers:
                if any(marker in header.lower() or marker in value.lower() for marker in crlf_markers):
                    return True
            
            return False
            
        except Exception as e:
            print(f"    [CRLF] Enhanced detection error: {e}")
            return False
    
    def _clean_data_structure(self, data):
        """Recursively clean data structures to make them JSON serializable"""
        if isinstance(data, dict):
            cleaned = {}
            for k, v in data.items():
                try:
                    json.dumps(v)
                    cleaned[str(k)] = v
                except (TypeError, ValueError):
                    if isinstance(v, (dict, list, set)):
                        cleaned[str(k)] = self._clean_data_structure(v)
                    else:
                        cleaned[str(k)] = str(v)
            return cleaned
        elif isinstance(data, list):
            cleaned = []
            for item in data:
                try:
                    json.dumps(item)
                    cleaned.append(item)
                except (TypeError, ValueError):
                    if isinstance(item, (dict, list, set)):
                        cleaned.append(self._clean_data_structure(item))
                    else:
                        cleaned.append(str(item))
            return cleaned
        elif isinstance(data, set):
            return list(data)
        else:
            return str(data)
    
    def print_results(self, results: List[Dict[str, Any]]):
        """Print results to console with safe encoding"""
        try:
            print("\n" + "="*80)
            print("SCAN RESULTS SUMMARY".center(80))
            print("="*80)
        except UnicodeEncodeError:
            print("\n" + "="*80)
            print("SCAN RESULTS SUMMARY".center(80))
            print("="*80)
        
        
        # Print scan statistics
        stats = self.scan_stats
        print(f"Scan Duration:        {stats.get('scan_duration', '0s')}")
        print(f"Total Requests:       {stats.get('total_requests', 0)}")
        print(f"URLs Discovered:      {stats.get('total_urls', 0)}")
        print(f"Parameters Tested:    {stats.get('total_params', 0)}")
        print(f"Forms Discovered:     {stats.get('total_forms', 0)}")
        print(f"AJAX Endpoints:       {stats.get('total_ajax_endpoints', 0)}")
        print(f"JavaScript Files:     {stats.get('total_js_files', 0)}")
        print(f"Total Payloads Used:  {stats.get('total_payloads_used', 0)}")
        print(f"Modules Used:         {', '.join(self.config.modules)}")
        print(f"Threads:              {self.config.threads}")
        print("-" * 80)
        
        # Print module statistics
        module_stats = stats.get('module_stats', {})
        if module_stats:
            print("MODULE TESTING STATISTICS:")
            print("-" * 80)
            for module_name, module_data in module_stats.items():
                print(f"{module_name.upper():20} | "
                      f"Pages: {module_data['pages_tested']:3} | "
                      f"Params: {module_data['parameters_tested']:3} | "
                      f"Forms: {module_data['forms_tested']:3} | "
                      f"Vulns: {module_data['vulnerabilities_found']:3}")
            print("-" * 80)
        
        # Print payload statistics
        payload_stats = stats.get('payload_stats', {})
        if payload_stats:
            print("PAYLOAD USAGE STATISTICS:")
            print("-" * 80)
            for module_name, payload_data in payload_stats.items():
                success_rate = 0
                if payload_data['payloads_used'] > 0:
                    success_rate = (payload_data['successful_payloads'] / payload_data['payloads_used']) * 100
                print(f"{module_name.upper():20} | "
                      f"Payloads: {payload_data['payloads_used']:4} | "
                      f"Requests: {payload_data['requests_made']:4} | "
                      f"Success: {payload_data['successful_payloads']:3} | "
                      f"Rate: {success_rate:5.1f}%")
            print("-" * 80)
        
        
        # Filter out scan stats and group by severity
        vulnerabilities = []
        for v in results:
            # Skip entries that are ONLY scan_stats or benchmark_analysis (no vulnerability data)
            if ('scan_stats' in v or 'benchmark_analysis' in v) and 'vulnerability' not in v:
                continue
            # Include ALL entries that have vulnerability field
            if 'vulnerability' in v and v.get('vulnerability'):
                # Create clean vulnerability object without scan_stats and benchmark_analysis for display
                clean_vuln = {k: v for k, v in v.items() if k not in ['scan_stats', 'benchmark_analysis']}
                vulnerabilities.append(clean_vuln)
        
        if not vulnerabilities:
            print("VULNERABILITY STATUS: CLEAN")
            print("No vulnerabilities found during the scan.")
            print("="*80)
            return
        
            
        # Group vulnerabilities by severity
        critical_vulns = []
        high_vulns = []
        medium_vulns = []
        low_vulns = []
        info_vulns = []
        
        for v in vulnerabilities:
            severity = str(v.get('severity', '')).strip().lower()
            
            if severity == 'critical':
                critical_vulns.append(v)
            elif severity == 'high':
                high_vulns.append(v)
            elif severity == 'medium':
                medium_vulns.append(v)
            elif severity == 'low':
                low_vulns.append(v)
            elif severity == 'info':
                info_vulns.append(v)
            else:
                high_vulns.append(v)  # Add uncategorized to high for visibility
        
        print(f"VULNERABILITY STATUS: {len(vulnerabilities)} ISSUES FOUND")
        print(f"Critical Severity:    {len(critical_vulns)}")
        print(f"High Severity:        {len(high_vulns)}")
        print(f"Medium Severity:      {len(medium_vulns)}")
        print(f"Low Severity:         {len(low_vulns)}")
        print(f"Info:                 {len(info_vulns)}")
        print("="*80)
        
        # Print vulnerability details
        if critical_vulns:
            print(f"\nCRITICAL SEVERITY VULNERABILITIES ({len(critical_vulns)} found):")
            print("-" * 50)
            for i, result in enumerate(critical_vulns, 1):
                self._print_vulnerability(i, result)
        
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
        
        if info_vulns:
            print(f"\nINFO VULNERABILITIES ({len(info_vulns)} found):")
            print("-" * 50)
            for i, result in enumerate(info_vulns, 1):
                self._print_vulnerability(i, result)
        
        # Print general vulnerability summary
        if results and any(r.get('vulnerability') for r in results):
            print(f"\nScan found {len([r for r in results if r.get('vulnerability')])} vulnerabilities")
        
        print("="*80)
    
    def _print_vulnerability(self, index: int, result: Dict[str, Any]):
        """Print single vulnerability details with safe encoding and enhanced metadata"""
        def safe_print(text):
            """Safely print text, handling encoding issues"""
            try:
                # Ensure text is properly encoded for console output
                if isinstance(text, str):
                    print(text.encode('utf-8', 'replace').decode('utf-8', 'replace'))
                else:
                    print(str(text))
            except (UnicodeEncodeError, UnicodeDecodeError):
                # Replace problematic characters with safe alternatives
                safe_text = str(text).encode('ascii', 'replace').decode('ascii')
                print(safe_text)
        
        safe_print(f"\n  {index}. {result.get('vulnerability', 'Unknown')}")
        safe_print(f"     Target: {result.get('target', '')}")
        safe_print(f"     Parameter: {result.get('parameter', '')}")
        safe_print(f"     Module: {result.get('module', '')}")
        safe_print(f"     Detector: {result.get('detector', 'Unknown')}")
        
        payload = str(result.get('payload', ''))
        payload_display = payload[:100] + ('...' if len(payload) > 100 else '')
        safe_print(f"     Payload: {payload_display}")
        safe_print(f"     Request: {result.get('request_url', '')}")
        
        # Show response snippet if available
        response_snippet = result.get('response_snippet', '')
        if response_snippet:
            snippet_display = response_snippet[:80] + ('...' if len(response_snippet) > 80 else '')
            safe_print(f"     Response: ...{snippet_display}")
        
        safe_print(f"     Evidence: {result.get('evidence', '')}")
        safe_print("     " + "-"*50)
