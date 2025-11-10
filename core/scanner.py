"""
Main vulnerability scanner class
"""

import time
import json
import re
import requests
import urllib3
import html
import threading
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
except ImportError as e:
    print(f"Warning: Could not import GitPayloads: {e}")
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
    from payloads.hpp_payloads import HPPPayloads
except ImportError as e:
    print(f"Warning: Could not import payload classes: {e}")
    # Create dummy classes to prevent crashes
    class DummyPayloads:
        @staticmethod
        def get_all_payloads():
            return ["'", '"', "<script>alert(1)</script>"]
        @staticmethod
        def get_context_specific_payloads(param):
            return [{'name': 'basic', 'values': ['test1', 'test2']}]
    
    XSSPayloads = SQLiPayloads = LFIPayloads = CSRFPayloads = DummyPayloads
    DirBrutePayloads = DirectoryTraversalPayloads = DummyPayloads
    if 'GitPayloads' not in locals():
        GitPayloads = DummyPayloads
    SSRFPayloads = RFIPayloads = BlindXSSPayloads = PHPInfoPayloads = DummyPayloads
    XXEPayloads = CommandInjectionPayloads = IDORPayloads = NoSQLInjectionPayloads = DummyPayloads
    SSTIPayloads = CRLFPayloads = TextInjectionPayloads = HTMLInjectionPayloads = DummyPayloads
    HPPPayloads = DummyPayloads

# Import detector classes with error handling
try:
    from passive_detectors.waf_detector import WAFDetector
except ImportError as e:
    print(f"Warning: Could not import WAFDetector: {e}")
    class WAFDetector:
        @staticmethod
        def analyze(headers, response_text, url): return (False, [])
        @staticmethod
        def active_detect(url, headers, timeout): return (False, [])
try:
    from detectors.xss_detector import XSSDetector
except ImportError as e:
    print(f"Warning: Could not import XSSDetector: {e}")
    class XSSDetector:
        @staticmethod
        def detect_reflected_xss(payload, response_text, response_code):
            return payload.lower() in response_text.lower()

try:
    from detectors.sqli_detector import SQLiDetector
except ImportError as e:
    print(f"Warning: Could not import SQLiDetector: {e}")
    class SQLiDetector:
        @staticmethod
        def detect_error_based_sqli(response_text, response_code):
            sql_errors = ['mysql', 'sql syntax', 'ora-', 'postgresql']
            return any(error in response_text.lower() for error in sql_errors), "SQL error detected"

try:
    from detectors.lfi_detector import LFIDetector
except ImportError as e:
    print(f"Warning: Could not import LFIDetector: {e}")
    class LFIDetector:
        @staticmethod
        def detect_lfi(response_text, response_code):
            lfi_indicators = ['root:', '[extensions]', '<?php']
            return any(indicator in response_text for indicator in lfi_indicators), "File inclusion detected"

try:
    from detectors.csrf_detector import CSRFDetector
    from detectors.hpp_detector import HPPDetector
    from detectors.reverse_tabnabbing_detector import ReverseTabnabbingDetector
    from detectors.insecure_reflected_content_detector import InsecureReflectedContentDetector
    from detectors.php_config_detector import PHPConfigDetector
    from detectors.csp_detector import CSPDetector
    from detectors.mixed_content_detector import MixedContentDetector
except ImportError as e:
    print(f"Warning: Could not import detector classes: {e}")
    class CSRFDetector:
        @staticmethod
        def get_csrf_indicators():
            return ['csrf_token', '_token', 'authenticity_token']
    
    class HPPDetector:
        @staticmethod
        def detect_hpp_vulnerability(url, response_text, response_code, original_response):
            return False, "", "", {}
    
    class ReverseTabnabbingDetector:
        @staticmethod
        def detect_reverse_tabnabbing(response_text, response_code, url):
            return False, "", "", {}
    
    class InsecureReflectedContentDetector:
        @staticmethod
        def detect_insecure_reflection(response_text, response_code, payload, parameter):
            return False, "", "", {}
    
    class PHPConfigDetector:
        @staticmethod
        def detect_php_config_issues(response_text, response_code, headers):
            return False, "", "", []
    
    class CSPDetector:
        @staticmethod
        def detect_csp_issues(response_headers, response_text):
            return False, "", "", []
    
    class MixedContentDetector:
        @staticmethod
        def detect_mixed_content(response_text, response_code, current_url):
            return False, "", "", []

try:
    from detectors.dirbrute_detector import DirBruteDetector
except ImportError as e:
    print(f"Warning: Could not import DirBruteDetector: {e}")
    class DirBruteDetector:
        @staticmethod
        def is_valid_response(response_text, response_code, content_length, baseline_404=None, baseline_size=0):
            return response_code == 200, f"HTTP {response_code}"

try:
    from detectors.real404_detector import Real404Detector
except ImportError as e:
    print(f"Warning: Could not import Real404Detector: {e}")
    class Real404Detector:
        @staticmethod
        def generate_baseline_404(base_url, session=None):
            return "", 0
        @staticmethod
        def detect_real_404(response_text, response_code, content_length, baseline_404=None, baseline_size=0):
            return response_code == 404, "404 detected", 1.0

try:
    from detectors.git_detector import GitDetector
except ImportError as e:
    print(f"Warning: Could not import GitDetector: {e}")
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
except ImportError as e:
    print(f"Warning: Could not import DirectoryTraversalDetector: {e}")
    class DirectoryTraversalDetector:
        @staticmethod
        def detect_directory_traversal(response_text, response_code, payload):
            return 'root:' in response_text or '[extensions]' in response_text

try:
    from detectors.security_headers_detector import SecurityHeadersDetector
except ImportError as e:
    print(f"Warning: Could not import SecurityHeadersDetector: {e}")
    class SecurityHeadersDetector:
        @staticmethod
        def detect_missing_security_headers(headers):
            return []
        @staticmethod
        def detect_insecure_cookies(headers):
            return []

try:
    from detectors.ssrf_detector import SSRFDetector
except ImportError as e:
    print(f"Warning: Could not import SSRFDetector: {e}")
    class SSRFDetector:
        @staticmethod
        def detect_ssrf(response_text, response_code, payload):
            return 'localhost' in response_text or '127.0.0.1' in response_text

try:
    from detectors.rfi_detector import RFIDetector
except ImportError as e:
    print(f"Warning: Could not import RFIDetector: {e}")
    class RFIDetector:
        @staticmethod
        def detect_rfi(response_text, response_code, payload):
            return 'http://' in payload and '<?php' in response_text

try:
    from detectors.version_disclosure_detector import VersionDisclosureDetector
except ImportError as e:
    print(f"Warning: Could not import VersionDisclosureDetector: {e}")
    class VersionDisclosureDetector:
        @staticmethod
        def detect_version_disclosure(response_text, headers):
            return []
        @staticmethod
        def get_severity(software, version):
            return "Medium"

try:
    from detectors.clickjacking_detector import ClickjackingDetector
except ImportError as e:
    print(f"Warning: Could not import ClickjackingDetector: {e}")
    class ClickjackingDetector:
        @staticmethod
        def detect_clickjacking(headers):
            return {'vulnerable': 'X-Frame-Options' not in headers, 'evidence': 'Missing X-Frame-Options'}

try:
    from detectors.blind_xss_detector import BlindXSSDetector
except ImportError as e:
    print(f"Warning: Could not import BlindXSSDetector: {e}")
    class BlindXSSDetector:
        @staticmethod
        def detect_blind_xss(payload, response_text, response_code, callback_received=False):
            return callback_received

try:
    from detectors.stored_xss_detector import StoredXSSDetector
except ImportError as e:
    print(f"Warning: Could not import StoredXSSDetector: {e}")
    class StoredXSSDetector:
        @staticmethod
        def get_stored_xss_indicators():
            return ['<script>alert("StoredXSS")</script>', '<img src=x onerror=alert("StoredXSS")>', 'javascript:alert("StoredXSS")']
        @staticmethod
        def detect_stored_xss(payload, response_text, response_code):
            return payload.lower() in response_text.lower()

try:
    from detectors.password_over_http_detector import PasswordOverHTTPDetector
except ImportError as e:
    print(f"Warning: Could not import PasswordOverHTTPDetector: {e}")
    class PasswordOverHTTPDetector:
        @staticmethod
        def detect_password_over_http(url, response_text, response_code):
            return url.startswith('http://') and 'password' in response_text.lower(), "HTTP password form", []

try:
    from detectors.outdated_software_detector import OutdatedSoftwareDetector
except ImportError as e:
    print(f"Warning: Could not import OutdatedSoftwareDetector: {e}")
    class OutdatedSoftwareDetector:
        @staticmethod
        def detect_outdated_software(headers, response_text):
            return []

try:
    from detectors.database_error_detector import DatabaseErrorDetector
except ImportError as e:
    print(f"Warning: Could not import DatabaseErrorDetector: {e}")
    class DatabaseErrorDetector:
        @staticmethod
        def detect_database_errors(response_text, response_code):
            return False, '', '', []

try:
    from detectors.phpinfo_detector import PHPInfoDetector
except ImportError as e:
    print(f"Warning: Could not import PHPInfoDetector: {e}")
    class PHPInfoDetector:
        @staticmethod
        def detect_phpinfo_exposure(response_text, response_code, url):
            return 'phpinfo' in response_text.lower(), "PHPInfo detected", "High"

try:
    from detectors.ssl_tls_detector import SSLTLSDetector
except ImportError as e:
    print(f"Warning: Could not import SSLTLSDetector: {e}")
    class SSLTLSDetector:
        @staticmethod
        def detect_ssl_tls_implementation(url):
            return url.startswith('https://'), "HTTPS detected", "Low", {}

try:
    from detectors.httponly_cookie_detector import HttpOnlyCookieDetector
except ImportError as e:
    print(f"Warning: Could not import HttpOnlyCookieDetector: {e}")
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
except ImportError as e:
    print(f"Warning: Could not import Wappalyzer: {e}")
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
except ImportError as e:
    print(f"Warning: Could not import XXEDetector: {e}")
    class XXEDetector:
        @staticmethod
        def detect_xxe(response_text, response_code, payload):
            return 'ENTITY' in payload and 'root:' in response_text

try:
    from detectors.idor_detector import IDORDetector
except ImportError as e:
    print(f"Warning: Could not import IDORDetector: {e}")
    class IDORDetector:
        @staticmethod
        def get_idor_parameters():
            return ['id', 'user_id', 'userid']
        @staticmethod
        def detect_idor(orig_response, mod_response, orig_code, mod_code):
            return orig_response != mod_response

try:
    from detectors.command_injection_detector import CommandInjectionDetector
except ImportError as e:
    print(f"Warning: Could not import CommandInjectionDetector: {e}")
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
except ImportError as e:
    print(f"Warning: Could not import PathTraversalDetector: {e}")
    class PathTraversalDetector:
        @staticmethod
        def detect_path_traversal(response_text, response_code, payload):
            return 'root:' in response_text or '[extensions]' in response_text

try:
    from detectors.ldap_injection_detector import LDAPInjectionDetector
except ImportError as e:
    print(f"Warning: Could not import LDAPInjectionDetector: {e}")
    class LDAPInjectionDetector:
        @staticmethod
        def detect_ldap_injection(response_text, response_code, payload):
            return 'ldap' in response_text.lower()

try:
    from detectors.nosql_injection_detector import NoSQLInjectionDetector
except ImportError as e:
    print(f"Warning: Could not import NoSQLInjectionDetector: {e}")
    class NoSQLInjectionDetector:
        @staticmethod
        def detect_nosql_injection(response_text, response_code, payload):
            return 'mongodb' in response_text.lower()

try:
    from detectors.file_upload_detector import FileUploadDetector
except ImportError as e:
    print(f"Warning: Could not import FileUploadDetector: {e}")
    class FileUploadDetector:
        @staticmethod
        def detect_file_upload_vulnerability(response_text, response_code, url):
            return 'type="file"' in response_text, "File upload form detected", "Medium"

try:
    from detectors.cors_detector import CORSDetector
except ImportError as e:
    print(f"Warning: Could not import CORSDetector: {e}")
    class CORSDetector:
        @staticmethod
        def detect_cors_misconfiguration(headers, origin=None):
            return False, "No CORS issues", "None", []

try:
    from detectors.jwt_detector import JWTDetector
except ImportError as e:
    print(f"Warning: Could not import JWTDetector: {e}")
    class JWTDetector:
        @staticmethod
        def detect_jwt_vulnerabilities(response_text, headers, url):
            return 'eyJ' in response_text, "JWT token found", "Low", []

try:
    from detectors.insecure_deserialization_detector import InsecureDeserializationDetector
except ImportError as e:
    print(f"Warning: Could not import InsecureDeserializationDetector: {e}")
    class InsecureDeserializationDetector:
        @staticmethod
        def detect_insecure_deserialization(response_text, response_code, payload):
            return False, "No deserialization detected", "None"

try:
    from detectors.http_response_splitting_detector import HTTPResponseSplittingDetector
except ImportError as e:
    print(f"Warning: Could not import HTTPResponseSplittingDetector: {e}")
    class HTTPResponseSplittingDetector:
        @staticmethod
        def detect_response_splitting(response_text, response_code, payload, headers):
            return '\r\n' in response_text

try:
    from detectors.ssti_detector import SSTIDetector
except ImportError as e:
    print(f"Warning: Could not import SSTIDetector: {e}")
    class SSTIDetector:
        @staticmethod
        def detect_ssti(response_text, response_code, payload):
            return '49' in response_text and '7*7' in payload

try:
    from detectors.crlf_detector import CRLFDetector
except ImportError as e:
    print(f"Warning: Could not import CRLFDetector: {e}")
    class CRLFDetector:
        @staticmethod
        def detect_crlf_injection(response_text, response_code, payload, headers):
            return '\r\n' in response_text or '%0d%0a' in payload

try:
    from detectors.textinjection_detector import TextInjectionDetector
except ImportError as e:
    print(f"Warning: Could not import TextInjectionDetector: {e}")
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
except ImportError as e:
    print(f"Warning: Could not import HTMLInjectionDetector: {e}")
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
except ImportError as e:
    print(f"Warning: Could not import HostHeaderDetector: {e}")
    class HostHeaderDetector:
        @staticmethod
        def detect_host_header_injection(base_url, headers, timeout=10):
            return False, "Host header detector not available", "Info", []

try:
    from detectors.prototype_pollution_detector import PrototypePollutionDetector
except ImportError as e:
    print(f"Warning: Could not import PrototypePollutionDetector: {e}")
    class PrototypePollutionDetector:
        @staticmethod
        def detect_prototype_pollution(url, headers, timeout=10):
            return False, "Prototype pollution detector not available", "Info", []

try:
    from detectors.vhost_detector import VHostDetector
except ImportError as e:
    print(f"Warning: Could not import VHostDetector: {e}")
    class VHostDetector:
        @staticmethod
        def detect_virtual_hosts(base_url, headers, timeout=10):
            return False, "VHost detector not available", "Info", []

try:
    from detectors.openredirect_detector import OpenRedirectDetector
except ImportError as e:
    print(f"Warning: Could not import OpenRedirectDetector: {e}")
    class OpenRedirectDetector:
        @staticmethod
        def get_redirect_parameters():
            return ['url', 'redirect', 'return', 'next']
        @staticmethod
        def detect_open_redirect(response_text, response_code, response_headers, payload_url, original_url):
            return False, None, None
        @staticmethod
        def get_evidence(redirect_type, redirect_target):
            return f"Open redirect detected: {redirect_target}"
        @staticmethod
        def get_response_snippet(response_text: str, redirect_target: str, max_length: int = 300) -> str:
            return response_text[:max_length]

# Disable SSL warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class VulnScanner:
    """Main vulnerability scanner class"""
    
    def __init__(self, config: Config):
        """Initialize scanner"""
        self.config = config
        self.debug = getattr(config, 'debug', False)
        self.waf = False  # Will be set from main.py or interactively
        self.waf_if_found = False  # Will be set from main.py
        self.payload_limit = getattr(config, 'payload_limit', 0)
        self.url_parser = URLParser()
        self.crawler = WebCrawler(config)
        self.file_handler = FileHandler()
        self.screenshot_handler = ScreenshotHandler()
        self.screenshot_lock = threading.Lock()
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
        self._module_map = {
            "wafdetect": self._test_waf_detection,
            "xss": self._test_xss,
            "sqli": self._test_sqli,
            "lfi": self._test_lfi,
            "csrf": self._test_csrf,
            "dirbrute": self._test_dirbrute,
            "git": self._test_git_exposed,
            "gitexposed": self._test_git_exposed,
            "dirtraversal": self._test_directory_traversal,
            "secheaders": self._test_security_headers,
            "ssrf": self._test_ssrf,
            "rfi": self._test_rfi,
            "versiondisclosure": self._test_version_disclosure,
            "clickjacking": self._test_clickjacking,
            "blindxss": self._test_blind_xss,
            "storedxss": self._test_stored_xss,
            "passwordoverhttp": self._test_password_over_http,
            "outdatedsoftware": self._test_outdated_software,
            "databaseerrors": self._test_database_errors,
            "phpinfo": self._test_phpinfo,
            "ssltls": self._test_ssl_tls,
            "httponlycookies": self._test_httponly_cookies,
            "technology": self._test_technology_detection,
            "xxe": self._test_xxe,
            "idor": self._test_idor,
            "commandinjection": self._test_command_injection,
            "pathtraversal": self._test_path_traversal,
            "ldapinjection": self._test_ldap_injection,
            "nosqlinjection": self._test_nosql_injection,
            "fileupload": self._test_file_upload,
            "cors": self._test_cors,
            "jwt": self._test_jwt,
            "deserialization": self._test_insecure_deserialization,
            "responsesplitting": self._test_http_response_splitting,
            "ssti": self._test_ssti,
            "crlf": self._test_crlf,
            "textinjection": self._test_text_injection,
            "htmlinjection": self._test_html_injection,
            "hostheader": self._test_host_header,
            "prototypepollution": self._test_prototype_pollution,
            "vhost": self._test_vhost,
            "infoleak": self._test_information_leakage,
            "openredirect": self._test_open_redirect,
            "hpp": self._test_hpp,
            "reversetabnabbing": self._test_reverse_tabnabbing,
            "insecurereflection": self._test_insecure_reflection,
            "phpconfig": self._test_php_config,
            "csp": self._test_csp,
            "mixedcontent": self._test_mixed_content,
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
                
                # Check for detected WAF and prompt user if --wafiffound is set
                if self.crawler.detected_wafs and self.waf_if_found and not self.waf:
                    waf_names = ', '.join(self.crawler.detected_wafs)
                    try:
                        prompt = input(f"  [WAF] WAFs detected: {waf_names}. Enable WAF bypass payloads? [y/N]: ")
                        if prompt.lower() == 'y':
                            self.waf = True
                            print("  [WAF] WAF bypass mode enabled for active scanning.")
                        else:
                            print("  [WAF] Continuing without WAF bypass payloads.")
                    except (EOFError, KeyboardInterrupt):
                        print("\n  [WAF] User cancelled prompt. Continuing without WAF bypass payloads.")
            
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
        
            # Run passive analysis on all discovered pages
            print(f"  [PASSIVE] Running passive analysis on {len(all_found_pages)} pages...")
            passive_results = self._run_passive_analysis(all_found_pages)
            target_results.extend(passive_results)
            
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
                # Check if this page has directory listing - skip vulnerability testing if it does
                page_url = page_data.get('url', '')
                if self._is_directory_listing_page(page_url):
                    print(f"  [DEBUG] Skipping vulnerability testing for directory listing page: {page_url}")
                    continue
                
                # Extract forms if not already done
                if 'forms' not in page_data:
                    try:
                        response = requests.get(page_data['url'], timeout=10, verify=False)
                        if response.status_code == 200:
                            # Check if response contains directory listing
                            if self._contains_directory_listing(response.text):
                                print(f"  [DEBUG] Skipping vulnerability testing - page contains directory listing: {page_url}")
                                continue
                            
                            forms = self.url_parser.extract_forms(response.text)
                            page_data['forms'] = forms
                            # Update forms count in stats
                            self.scan_stats['total_forms'] += len(forms)
                    except:
                        page_data['forms'] = []
                else:
                    # Forms already extracted, make sure stats are updated
                    if len(page_data.get('forms', [])) > 0:
                        self.scan_stats['total_forms'] += len(page_data['forms'])
            
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
                    forms_count = len(page_data.get('forms', []))
                    self.scan_stats['module_stats'][module_name]['forms_tested'] += forms_count
                    
                    # Debug stats
                    if self.debug:
                        print(f"  [DEBUG] Module {module_name}: params={len(page_data['query_params'])}, forms={forms_count}")
                
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
    
    def _run_passive_analysis(self, pages_data: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Run passive analysis on discovered pages"""
        passive_results = []
        
        # Check if passive analysis is disabled
        if getattr(self.config, 'nopassive', False):
            print(f"    [PASSIVE] Passive analysis disabled by --nopassive flag")
            return passive_results
        
        try:
            # Import passive detectors
            from passive_detectors.security_headers_detector import SecurityHeadersDetector as PassiveSecurityHeaders
            from passive_detectors.sensitive_data_detector import SensitiveDataDetector as PassiveSensitiveData
            from passive_detectors.technology_detector import TechnologyDetector as PassiveTechnology
            from passive_detectors.version_disclosure_detector import VersionDisclosureDetector as PassiveVersionDisclosure
            from passive_detectors.api_endpoints_detector import APIEndpointsDetector as PassiveAPIEndpoints
            from passive_detectors.backup_files_detector import BackupFilesDetector as PassiveBackupFiles
            from passive_detectors.debug_information_detector import DebugInformationDetector as PassiveDebugInfo
            
            print(f"    [PASSIVE] Analyzing {len(pages_data)} pages for passive vulnerabilities...")
            
            # Collect unique domains to avoid duplicate analysis
            analyzed_domains = set()
            
            for page_data in pages_data:
                url = page_data.get('url', '')
                if not url:
                    continue
                
                try:
                    from urllib.parse import urlparse
                    parsed_url = urlparse(url)
                    domain = parsed_url.hostname
                    
                    # Skip if domain already analyzed
                    if domain in analyzed_domains:
                        continue
                    analyzed_domains.add(domain)
                    
                    print(f"    [PASSIVE] Analyzing domain: {domain}")
                    
                    # Make request to get headers and content
                    response = requests.get(
                        url,
                        timeout=self.config.timeout,
                        headers=self.config.headers,
                        verify=False
                    )
                    
                    if response.status_code >= 400:
                        continue
                    
                    # Run passive security headers analysis
                    try:
                        has_issues, issues = PassiveSecurityHeaders.analyze_cookies(
                            dict(response.headers), url
                        )
                        if has_issues:
                            for issue in issues:
                                passive_results.append({
                                    'module': 'passive_security',
                                    'target': url,
                                    'vulnerability': f'Passive Security Issue: {issue["type"]}',
                                    'severity': issue['severity'],
                                    'parameter': 'headers/cookies',
                                    'payload': 'N/A',
                                    'evidence': issue['description'],
                                    'request_url': url,
                                    'detector': 'PassiveSecurityHeaders.analyze_cookies',
                                    'response_snippet': issue.get('details', ''),
                                    'method': 'GET',
                                    'passive_analysis': True
                                })
                    except Exception as e:
                        if self.debug:
                            print(f"    [PASSIVE] Security headers analysis error: {e}")
                    
                    # Run passive sensitive data detection
                    try:
                        sensitive_findings = PassiveSensitiveData._analyze_content(response.text, url)
                        for finding in sensitive_findings:
                            passive_results.append({
                                'module': 'passive_sensitive',
                                'target': url,
                                'vulnerability': f'Sensitive Data Exposure: {finding["type"]}',
                                'severity': finding['severity'],
                                'parameter': 'response_content',
                                'payload': 'N/A',
                                'evidence': finding['description'],
                                'request_url': url,
                                'detector': 'PassiveSensitiveData._analyze_content',
                                'response_snippet': finding.get('context', ''),
                                'method': 'GET',
                                'passive_analysis': True
                            })
                    except Exception as e:
                        if self.debug:
                            print(f"    [PASSIVE] Sensitive data analysis error: {e}")
                    
                    # Run passive technology detection
                    try:
                        tech_findings = PassiveTechnology._analyze_headers(dict(response.headers), url)
                        tech_findings.extend(PassiveTechnology._analyze_content(response.text, url))
                        
                        if tech_findings:
                            # Group technologies into single finding to avoid spam
                            tech_names = [finding['technology'] for finding in tech_findings]
                            passive_results.append({
                                'module': 'passive_technology',
                                'target': url,
                                'vulnerability': f'Technologies Detected ({len(tech_names)} found)',
                                'severity': 'Info',
                                'parameter': 'headers/content',
                                'payload': 'N/A',
                                'evidence': f'Technologies detected: {", ".join(tech_names)}',
                                'request_url': url,
                                'detector': 'PassiveTechnology.analyze',
                                'response_snippet': f'Found: {", ".join(tech_names)}',
                                'method': 'GET',
                                'passive_analysis': True,
                                'technologies': tech_names
                            })
                    except Exception as e:
                        if self.debug:
                            print(f"    [PASSIVE] Technology detection error: {e}")
                    
                    # Run passive version disclosure detection
                    try:
                        version_findings = PassiveVersionDisclosure._analyze_headers(dict(response.headers), url)
                        version_findings.extend(PassiveVersionDisclosure._analyze_content(response.text, url))
                        
                        for finding in version_findings:
                            passive_results.append({
                                'module': 'passive_version',
                                'target': url,
                                'vulnerability': f'Version Disclosure: {finding["software"]}',
                                'severity': finding['severity'],
                                'parameter': 'headers/content',
                                'payload': 'N/A',
                                'evidence': finding['description'],
                                'request_url': url,
                                'detector': 'PassiveVersionDisclosure.analyze',
                                'response_snippet': finding.get('context', ''),
                                'method': 'GET',
                                'passive_analysis': True
                            })
                    except Exception as e:
                        if self.debug:
                            print(f"    [PASSIVE] Version disclosure analysis error: {e}")
                    
                    # Run passive API endpoints detection
                    try:
                        has_api_findings, api_findings = PassiveAPIEndpoints.analyze(response.text, url, dict(response.headers))
                        
                        for finding in api_findings:
                            passive_results.append({
                                'module': 'passive_api',
                                'target': url,
                                'vulnerability': f'API Discovery: {finding["type"].replace("_", " ").title()}',
                                'severity': finding['severity'],
                                'parameter': finding.get('endpoint', finding.get('header', 'api_analysis')),
                                'payload': 'N/A',
                                'evidence': finding['description'],
                                'request_url': url,
                                'detector': 'PassiveAPIEndpoints.analyze',
                                'response_snippet': finding.get('endpoint', finding.get('value', '')),
                                'method': 'GET',
                                'passive_analysis': True
                            })
                    except Exception as e:
                        if self.debug:
                            print(f"    [PASSIVE] API endpoints analysis error: {e}")
                    
                    # Run passive backup files detection
                    try:
                        has_backup_findings, backup_findings = PassiveBackupFiles.analyze(response.text, url, dict(response.headers))
                        
                        for finding in backup_findings:
                            passive_results.append({
                                'module': 'passive_backup',
                                'target': url,
                                'vulnerability': f'Backup Files: {finding["type"].replace("_", " ").title()}',
                                'severity': finding['severity'],
                                'parameter': finding.get('filename', finding.get('directory', 'backup_analysis')),
                                'payload': 'N/A',
                                'evidence': finding['description'],
                                'request_url': url,
                                'detector': 'PassiveBackupFiles.analyze',
                                'response_snippet': finding.get('filename', finding.get('directory', '')),
                                'method': 'GET',
                                'passive_analysis': True
                            })
                    except Exception as e:
                        if self.debug:
                            print(f"    [PASSIVE] Backup files analysis error: {e}")
                    
                    # Run passive debug information detection
                    try:
                        has_debug_findings, debug_findings = PassiveDebugInfo.analyze(response.text, url, dict(response.headers))
                        
                        for finding in debug_findings:
                            passive_results.append({
                                'module': 'passive_debug',
                                'target': url,
                                'vulnerability': f'Debug Information: {finding["type"].replace("_", " ").title()}',
                                'severity': finding['severity'],
                                'parameter': finding.get('debug_type', finding.get('header', 'debug_analysis')),
                                'payload': 'N/A',
                                'evidence': finding['description'],
                                'request_url': url,
                                'detector': 'PassiveDebugInfo.analyze',
                                'response_snippet': str(finding.get('file_paths', finding.get('paths', finding.get('value', ''))))[:100],
                                'method': 'GET',
                                'passive_analysis': True
                            })
                    except Exception as e:
                        if self.debug:
                            print(f"    [PASSIVE] Debug information analysis error: {e}")
                    
                except Exception as e:
                    if self.debug:
                        print(f"    [PASSIVE] Error analyzing {url}: {e}")
                    continue
            
            if passive_results:
                print(f"    [PASSIVE] Found {len(passive_results)} passive vulnerabilities")
            else:
                print(f"    [PASSIVE] No passive vulnerabilities found")
            
        except ImportError as e:
            print(f"    [PASSIVE] Could not import passive detectors: {e}")
        except Exception as e:
            print(f"    [PASSIVE] Passive analysis error: {e}")
        
        return passive_results
    
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
            print(f"  [CONNECTIVITY] Successfully connected to {url} (HTTP {response.status_code})")
            return response.status_code < 500
        except requests.exceptions.ConnectionError as e:
            print(f"  [CONNECTIVITY] Connection failed to {url}")
            print(f"  [CONNECTIVITY] Possible causes: server down, wrong port (try 8082?), firewall blocking")
            print(f"  [CONNECTIVITY] Error details: Connection refused")
            return False
        except requests.exceptions.Timeout as e:
            print(f"  [CONNECTIVITY] Timeout connecting to {url}")
            print(f"  [CONNECTIVITY] Server not responding within {self.config.timeout} seconds")
            return False
        except requests.exceptions.RequestException as e:
            print(f"  [CONNECTIVITY] Request error to {url}: {str(e)[:100]}")
            return False
        except Exception as e:
            print(f"  [CONNECTIVITY] Unexpected error connecting to {url}: {str(e)[:100]}")
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
            test_func = self._module_map.get(module_name)
            if test_func:
                results.extend(test_func(parsed_data))
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
        if self.waf:
            print("    [XSS] WAF mode enabled, loading bypass payloads...")
            try:
                xss_payloads.extend(XSSPayloads.get_waf_bypass_payloads())
            except AttributeError:
                print("    [XSS] Warning: get_waf_bypass_payloads() not found in XSSPayloads.")
        
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
                    
                    # Улучшенная проверка отражения XSS payload с защитой от ложных срабатываний
                    payload_in_response = False
                    
                    # Проверяем точное отражение payload
                    if payload in response.text:
                        # Дополнительная проверка контекста - payload должен быть в опасном месте
                        payload_pos = response.text.find(payload)
                        context_start = max(0, payload_pos - 50)
                        context_end = min(len(response.text), payload_pos + len(payload) + 50)
                        context = response.text[context_start:context_end].lower()
                        
                        # Проверяем, что payload находится в HTML контексте, а не в комментариях или скриптах
                        dangerous_contexts = [
                            'value="' + payload.lower(),
                            "value='" + payload.lower(),
                            '>' + payload.lower() + '<',
                            'href="' + payload.lower(),
                            "href='" + payload.lower(),
                            'src="' + payload.lower(),
                            "src='" + payload.lower()
                        ]
                        
                        # Исключаем безопасные контексты
                        safe_contexts = [
                            '<!--' in context and '-->' in context,  # HTML комментарии
                            '<script>' in context and '</script>' in context and 'console.log' in context,  # Логирование
                            'error' in context and 'log' in context,  # Логи ошибок
                            'debug' in context,  # Отладочная информация
                        ]
                        
                        if any(safe_contexts):
                            print(f"    [XSS] Payload found in safe context, skipping")
                            payload_in_response = False
                        elif any(dangerous in context for dangerous in dangerous_contexts):
                            payload_in_response = True
                            print(f"    [XSS] Payload found in dangerous context")
                        elif '<' in payload and '>' in payload and payload.lower() in context:
                            # HTML теги должны быть в HTML контексте
                            payload_in_response = True
                            print(f"    [XSS] HTML payload found in response")
                        else:
                            print(f"    [XSS] Payload found but context unclear, checking further")
                            payload_in_response = True
                    
                    # Используем XSS детектор только как дополнительную проверку
                    xss_detected_by_detector = False
                    detection_method = "enhanced_reflection_check"
                    xss_type = "Reflected XSS"
                    confidence = 0.9 if payload_in_response else 0.0
                    
                    try:
                        xss_result = XSSDetector.detect_reflected_xss(payload, response.text, response.status_code)
                        if isinstance(xss_result, dict):
                            xss_detected_by_detector = xss_result.get('vulnerable', False)
                            if xss_detected_by_detector:
                                detection_method = xss_result.get('detection_method', 'detector_check')
                                confidence = min(confidence + 0.1, 1.0)
                    except Exception as e:
                        print(f"    [XSS] Detector error: {e}")
                    
                    # Окончательное решение: требуем высокую уверенность
                    xss_detected = payload_in_response and confidence >= 0.8
                    
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
                            'detection_method': detection_method,
                            'method': 'GET',
                            'http_method': 'GET'
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
                                with self.screenshot_lock:
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
                from urllib.parse import urljoin
                form_url = urljoin(base_url, form_action)
                
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
                            
                            # Prepare form data
                            post_data = {}
                            for inp in form_inputs:
                                inp_name = inp.get('name')
                                inp_value = inp.get('value', '')
                                inp_type = inp.get('type', 'text')
                                
                                if inp_name and inp_type not in ['submit', 'button', 'reset', 'image']:
                                    if inp_name == input_name:
                                        post_data[inp_name] = payload
                                    else:
                                        # Use existing value or simple default
                                        post_data[inp_name] = inp_value or 'test'
                            
                            print(f"    [XSS] Sending {form_method} request to {form_url}")
                            print(f"    [XSS] Form data: {post_data}")
                            
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
                            
                            # Улучшенная проверка отражения payload в форме
                            form_payload_reflected = False
                            
                            if payload in response.text:
                                # Проверяем контекст отражения в форме
                                payload_pos = response.text.find(payload)
                                context_start = max(0, payload_pos - 100)
                                context_end = min(len(response.text), payload_pos + len(payload) + 100)
                                form_context = response.text[context_start:context_end].lower()
                                
                                # Для форм проверяем, что payload не в безопасном контексте
                                safe_form_contexts = [
                                    '<!--' in form_context and '-->' in form_context,
                                    'error' in form_context and ('message' in form_context or 'log' in form_context),
                                    'debug' in form_context,
                                    'console.log' in form_context
                                ]
                                
                                if not any(safe_form_contexts):
                                    form_payload_reflected = True
                                    print(f"    [XSS] Form payload reflected in valid context")
                                else:
                                    print(f"    [XSS] Form payload found in safe context, skipping")
                            
                            # Используем XSS детектор как дополнительную проверку
                            form_xss_detected = False
                            try:
                                form_xss_result = XSSDetector.detect_reflected_xss(payload, response.text, response.status_code)
                                if isinstance(form_xss_result, dict):
                                    form_xss_detected = form_xss_result.get('vulnerable', False)
                                else:
                                    form_xss_detected = bool(form_xss_result)
                            except Exception as e:
                                print(f"    [XSS] Form detector error: {e}")
                                form_xss_detected = False
                            
                            # Окончательное решение для форм - требуем отражение И подтверждение детектора
                            if form_payload_reflected and (form_xss_detected or '<script>' in payload):
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
                                    'response_snippet': response_snippet,
                                    'method': form_method,
                                    'http_method': form_method,
                                    'form_details': {
                                        'action': form_action,
                                        'method': form_method,
                                        'input_count': len(form_inputs)
                                    }
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
        if self.waf:
            print("    [SQLI] WAF mode enabled, loading bypass payloads...")
            try:
                sqli_payloads.extend(SQLiPayloads.get_waf_bypass_payloads())
            except AttributeError:
                print("    [SQLI] Warning: get_waf_bypass_payloads() not found in SQLiPayloads.")

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
                    
                    try:
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
                    except requests.exceptions.ConnectionError as e:
                        print(f"    [SQLI] Connection failed to {test_url}")
                        print(f"    [SQLI] Server may be down or using different port (check if port 8082 needed)")
                        print(f"    [SQLI] Skipping parameter {param} - connection refused")
                        break  # Exit payload loop for this parameter
                    except requests.exceptions.Timeout as e:
                        print(f"    [SQLI] Timeout connecting to {test_url}")
                        print(f"    [SQLI] Skipping payload - server not responding")
                        continue  # Try next payload
                    except requests.exceptions.RequestException as e:
                        print(f"    [SQLI] Request error to {test_url}: {str(e)[:100]}")
                        print(f"    [SQLI] Skipping payload - network error")
                        continue
                    
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
                            'response_snippet': response_snippet,
                            'method': 'GET',
                            'http_method': 'GET'
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
                
                # Build form URL - ИСПРАВЛЕНО для правильной обработки относительных путей
                from urllib.parse import urljoin
                form_url = urljoin(base_url, form_action)
                
                # Test each form input
                for input_data in form_inputs:
                    input_name = input_data.get('name')
                    input_type = input_data.get('type', 'text')
                    
                    # Skip non-testable inputs and search fields for stored XSS
                    if not input_name or input_type in ['submit', 'button', 'hidden']:
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
                                inp_value = inp.get('value', '')
                                inp_type = inp.get('type', 'text')
                                
                                if inp_name and inp_type not in ['submit', 'button']:
                                    if inp_name == input_name:
                                        post_data[inp_name] = payload
                                    else:
                                        post_data[inp_name] = inp_value or 'test'
                            
                            try:
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
                            except requests.exceptions.ConnectionError as e:
                                print(f"    [SQLI] Connection failed to form {form_url}")
                                print(f"    [SQLI] Check if server is running on correct port (maybe 8082?)")
                                print(f"    [SQLI] Skipping form input {input_name} - connection refused")
                                break  # Exit payload loop for this input
                            except requests.exceptions.Timeout as e:
                                print(f"    [SQLI] Timeout connecting to form {form_url}")
                                print(f"    [SQLI] Skipping payload - server timeout")
                                continue  # Try next payload
                            except requests.exceptions.RequestException as e:
                                print(f"    [SQLI] Form request error: {str(e)[:100]}")
                                print(f"    [SQLI] Skipping payload - network error")
                                continue
                            
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
                                    'response_snippet': response_snippet,
                                    'method': form_method,
                                    'http_method': form_method,
                                    'form_details': {
                                        'action': form_action,
                                        'method': form_method,
                                        'input_count': len(form_inputs)
                                    }
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
        if self.waf:
            print("    [LFI] WAF mode enabled, loading bypass payloads...")
            try:
                lfi_payloads.extend(LFIPayloads.get_waf_bypass_payloads())
            except AttributeError:
                print("    [LFI] Warning: get_waf_bypass_payloads() not found in LFIPayloads.")

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
                            'response_snippet': response_snippet,
                            'method': 'GET',
                            'http_method': 'GET'
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
                
                # Build form URL with proper port handling
                from urllib.parse import urljoin
                form_url = urljoin(base_url, form_action)
                
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
                                inp_value = inp.get('value', '')
                                inp_type = inp.get('type', 'text')
                                
                                if inp_name and inp_type not in ['submit', 'button']:
                                    if inp_name == input_name:
                                        post_data[inp_name] = payload
                                    else:
                                        post_data[inp_name] = inp_value or 'test'
                            
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
                                    'response_snippet': response_snippet,
                                    'method': form_method
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
                        'response_snippet': form_snippet,
                        'method': form_info['method']
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
        found_directories = []  # Track found directories for integration
        
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
                    # Only test directories, not files
                    test_url = f"{base_dir}{directory}/"
                    
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
                        
                        # Add found directory to list for integration with other modules
                        found_directories.append({
                            'directory': directory,
                            'url': test_url,
                            'response_text': response.text,
                            'status_code': response.status_code
                        })
                        
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
                            'response_snippet': DirBruteDetector.get_response_snippet(response.text),
                            'method': 'GET'
                        })
                        
                        # If directory found, recursively test files in it
                        self._test_files_in_directory(base_dir, directory, results, baseline_404_text, baseline_404_size, original_fingerprint)
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
        
            print(f"    [DIRBRUTE] Testing {len(all_files)} files in root directory...")
        
            for file in all_files[:150]:  # Увеличиваем до 150 файлов
                try:
                    # Only test files in root directory
                    test_url = f"{base_dir}{file}"
                    
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
                            'response_snippet': DirBruteDetector.get_response_snippet(response.text),
                            'method': 'GET'
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
            
            # Integrate found directories with general testing system
            if found_directories:
                print(f"    [DIRBRUTE] Integrating {len(found_directories)} found directories with general testing")
                self._integrate_found_directories(found_directories)
                
        except Exception as e:
            print(f"    [DIRBRUTE] Error during directory bruteforce: {e}")
        
        return results
    
    def _test_files_in_directory(self, base_dir: str, directory: str, results: List[Dict[str, Any]], baseline_404_text: str = None, baseline_404_size: int = 0, original_fingerprint: str = None):
        """Test files in a found directory"""
        files = DirBrutePayloads.get_all_files()
        
        print(f"    [DIRBRUTE] Testing files in directory: {directory}/")
        
        for file in files[:30]:  # Оптимизируем количество файлов
            try:
                test_url = f"{base_dir}{directory}/{file}"
                
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
                        'response_snippet': DirBruteDetector.get_response_snippet(response.text),
                        'method': 'GET'
                    })
                    
            except Exception as e:
                continue
    
    def _integrate_found_directories(self, found_directories: List[Dict[str, Any]]):
        """Integrate found directories into general testing system"""
        print(f"    [INTEGRATION] Adding {len(found_directories)} directories to testing queue")
        
        # Add found directories to crawler's discovered URLs for comprehensive testing
        if hasattr(self.crawler, 'found_urls'):
            for dir_info in found_directories:
                dir_url = dir_info['url']
                if dir_url not in self.crawler.found_urls:
                    self.crawler.found_urls.add(dir_url)
                    print(f"    [INTEGRATION] Added directory to testing queue: {dir_url}")
        
        # Store directory information for potential use by other modules
        if not hasattr(self, 'discovered_directories'):
            self.discovered_directories = []
        
        self.discovered_directories.extend(found_directories)
        
        # Update scan stats with discovered directories
        if 'discovered_directories' not in self.scan_stats:
            self.scan_stats['discovered_directories'] = []
        
        for dir_info in found_directories:
            self.scan_stats['discovered_directories'].append({
                'directory': dir_info['directory'],
                'url': dir_info['url'],
                'status_code': dir_info['status_code']
            })
    
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
                    
                    test_url = self._build_test_url(base_url, test_params)
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
                            'response_snippet': response_snippet,
                            'method': 'GET'
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
                        'security_issues': all_issues,  # Keep detailed info for reports
                        'method': 'GET'
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
                                'response_snippet': f'Current value: {issue["current_value"]}',
                                'method': 'GET'
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
                                'response_snippet': issue['cookie_header'],
                                'method': 'GET'
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
                    
                    test_url = self._build_test_url(base_url, test_params)
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
                    try:
                        ssrf_result = SSRFDetector.detect_ssrf(response.text, response.status_code, payload)
                        if isinstance(ssrf_result, tuple) and len(ssrf_result) >= 3:
                            is_vulnerable, evidence, severity = ssrf_result[:3]
                        elif isinstance(ssrf_result, tuple) and len(ssrf_result) == 2:
                            is_vulnerable, evidence = ssrf_result
                            severity = 'Medium'
                        else:
                            is_vulnerable = bool(ssrf_result)
                            evidence = f"SSRF detected with payload: {payload}"
                            severity = 'Medium'
                    except Exception as e:
                        print(f"    [SSRF] Detector error: {e}")
                        is_vulnerable = False
                        evidence = "Detection failed"
                        severity = 'Medium'
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
                            'detection_method': detection_details.get('method', 'ssrf_detection'),
                            'method': 'GET'
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
                    # Для абсолютных путей сохраняем порт из исходного URL
                    if parsed_data.get('port'):
                        form_url = f"{parsed_data['scheme']}://{parsed_data['host']}:{parsed_data['port']}{form_action}"
                    else:
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
                            try:
                                ssrf_result = SSRFDetector.detect_ssrf(response.text, response.status_code, payload)
                                if isinstance(ssrf_result, tuple) and len(ssrf_result) >= 3:
                                    is_vulnerable, evidence, severity = ssrf_result[:3]
                                elif isinstance(ssrf_result, tuple) and len(ssrf_result) == 2:
                                    is_vulnerable, evidence = ssrf_result
                                    severity = 'Medium'
                                else:
                                    is_vulnerable = bool(ssrf_result)
                                    evidence = f"SSRF detected with payload: {payload}"
                                    severity = 'Medium'
                            except Exception as e:
                                print(f"    [SSRF] Form detector error: {e}")
                                is_vulnerable = False
                                evidence = "Detection failed"
                                severity = 'Medium'
                            
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
                                    'response_snippet': response_snippet,
                                    'method': form_method
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
                    
                    test_url = self._build_test_url(base_url, test_params)
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
                            'response_snippet': response_snippet,
                            'method': 'GET'
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
                
                # Build form URL with proper port handling
                from urllib.parse import urljoin
                form_url = urljoin(base_url, form_action)
                
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
                                    'response_snippet': response_snippet,
                                    'method': form_method
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
                        'response_snippet': f'Version: {version}',
                        'method': 'GET'
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
                    'response_snippet': 'Missing X-Frame-Options or CSP frame-ancestors',
                    'method': 'GET'
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
                    
                    test_url = self._build_test_url(base_url, test_params)
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
                            'response_snippet': response_snippet,
                            'method': 'GET'
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
        try:
            stored_xss_payloads = StoredXSSDetector.get_stored_xss_payloads()
            print(f"    [STOREDXSS] Loaded {len(stored_xss_payloads)} stored XSS payloads")
        except Exception as e:
            print(f"    [STOREDXSS] Error loading payloads: {e}")
            stored_xss_payloads = ['<script>alert("DOMINATOR777_STORED")</script>', '<img src=x onerror=alert("DOMINATOR777_STORED")>']
        
        # Test all forms for stored XSS (including GET forms that might store data)
        forms_data = parsed_data.get('forms', [])
        print(f"    [STOREDXSS] *** STARTING STORED XSS TEST ON {len(forms_data)} FORMS ***")
        
        if not forms_data:
            print(f"    [STOREDXSS] *** NO FORMS FOUND - CANNOT TEST STORED XSS ***")
            return results
        
        # ЯВНЫЙ ВЫВОД ВСЕХ ФОРМ И ИХ ПАРАМЕТРОВ
        for i, form in enumerate(forms_data):
            method = form.get('method', 'GET').upper()
            action = form.get('action', '')
            inputs = form.get('inputs', [])
            
            print(f"    [STOREDXSS] *** FORM {i+1} ANALYSIS ***")
            print(f"    [STOREDXSS] Method: {method}")
            print(f"    [STOREDXSS] Action: '{action}'")
            print(f"    [STOREDXSS] Total Inputs: {len(inputs)}")
            
            # ЯВНЫЙ ВЫВОД ПАРАМЕТРОВ ПО ТИПУ ФОРМЫ
            if method == 'GET':
                get_params = []
                for inp in inputs:
                    inp_name = inp.get('name', 'unnamed')
                    inp_type = inp.get('type', 'text')
                    if inp_name != 'unnamed':
                        get_params.append(f"{inp_name}({inp_type})")
                print(f"    [STOREDXSS] *** GET FORM PARAMS EXTRACTED: {get_params} ***")
            elif method in ['POST', 'PUT']:
                post_params = []
                for inp in inputs:
                    inp_name = inp.get('name', 'unnamed')
                    inp_type = inp.get('type', 'text')
                    if inp_name != 'unnamed':
                        post_params.append(f"{inp_name}({inp_type})")
                print(f"    [STOREDXSS] *** POST FORM PARAMS EXTRACTED: {post_params} ***")
            
            # Детальный вывод каждого input
            testable_inputs = 0
            for j, inp in enumerate(inputs):
                inp_name = inp.get('name', 'unnamed')
                inp_type = inp.get('type', 'text')
                inp_value = inp.get('value', '')
                inp_placeholder = inp.get('placeholder', '')
                
                is_testable = inp_name != 'unnamed' and inp_type not in ['submit', 'button', 'reset', 'image']
                if is_testable:
                    testable_inputs += 1
                
                print(f"    [STOREDXSS]   Input {j+1}: name='{inp_name}', type='{inp_type}', value='{inp_value[:20]}{'...' if len(str(inp_value)) > 20 else ''}', placeholder='{inp_placeholder}', testable={is_testable}")
            
            print(f"    [STOREDXSS] *** FORM {i+1} HAS {testable_inputs} TESTABLE INPUTS ***")
        
        for i, form_data in enumerate(forms_data):
            form_method = form_data.get('method', 'GET').upper()
            form_action = form_data.get('action', '')
            form_inputs = form_data.get('inputs', [])
            
            # Test all forms that have input fields (including GET forms)
            if form_inputs:
                print(f"    [STOREDXSS] Testing {form_method} form {i+1}: {form_action}")
            
                # Build form URL with proper port handling
                from urllib.parse import urljoin
                form_url = urljoin(base_url, form_action)
            
                # Test each form input - включая скрытые поля для guestbook
                for input_data in form_inputs:
                    input_name = input_data.get('name')
                    input_type = input_data.get('type', 'text')
                
                    # Для guestbook.php тестируем даже скрытые поля name
                    if not input_name or input_type in ['submit', 'button']:
                        continue
                
                    if input_type == 'hidden':
                        # Test hidden fields unless they look like CSRF tokens
                        if any(token in input_name.lower() for token in ['csrf', '_token', 'nonce', 'authenticity_token']):
                            print(f"    [STOREDXSS] Skipping CSRF-like hidden field: {input_name}")
                            continue
                        else:
                            print(f"    [STOREDXSS] Testing hidden field: {input_name}")
                    else:
                        print(f"    [STOREDXSS] Testing form input: {input_name}")
                    
                    # Create deduplication key for this form input
                    form_key = f"storedxss_form_{form_url.split('?')[0]}_{input_name}"
                    if form_key in self.found_vulnerabilities:
                        print(f"    [STOREDXSS] Skipping form input {input_name} - already tested")
                        continue
                    
                    payload_count = self.payload_limit if self.payload_limit > 0 else 5
                    for payload in stored_xss_payloads[:payload_count]:
                        try:
                            print(f"    [STOREDXSS] Trying DOMINATOR777 payload: {payload[:50]}...")
                            
                            # Step 1: Submit payload via form
                            post_data = {}
                            for inp in form_inputs:
                                inp_name = inp.get('name')
                                inp_value = inp.get('value', 'test')
                                inp_type = inp.get('type', 'text')
                                
                                if inp_name and inp_type not in ['submit', 'button']:
                                    if inp_name == input_name:
                                        post_data[inp_name] = payload
                                    else:
                                        # Use existing value or simple default
                                        post_data[inp_name] = inp_value or 'test'
                            
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
                            else:  # GET form
                                # Build query string for GET form
                                query_parts = []
                                for k, v in post_data.items():
                                    from urllib.parse import quote_plus
                                    query_parts.append(f"{quote_plus(k)}={quote_plus(str(v))}")
                                
                                get_url = f"{form_url}?{'&'.join(query_parts)}" if query_parts else form_url
                                print(f"    [STOREDXSS] Submitting GET form to: {get_url}")
                                
                                submit_response = requests.get(
                                    get_url,
                                    timeout=self.config.timeout,
                                    headers=self.config.headers,
                                    verify=False
                                )
                            
                            print(f"    [STOREDXSS] Submit response code: {submit_response.status_code}")
                            print(f"    [STOREDXSS] Submit response length: {len(submit_response.text)} chars")
                            
                            # *** STEP 1.5: ПРОВЕРЯЕМ SELF-STORED XSS В ОТВЕТЕ ФОРМЫ ***
                            print(f"    [STOREDXSS] *** STEP 1.5: CHECKING FOR SELF-STORED XSS IN FORM RESPONSE ***")
                            
                            # Проверяем payload в ответе сразу после отправки формы
                            payload_in_submit_response = payload in submit_response.text
                            payload_lower_in_submit_response = payload.lower() in submit_response.text.lower()
                            
                            print(f"    [STOREDXSS] Payload '{payload[:50]}...' found in submit response: {payload_in_submit_response}")
                            print(f"    [STOREDXSS] Payload (case-insensitive) found in submit response: {payload_lower_in_submit_response}")
                            
                            if payload_in_submit_response or payload_lower_in_submit_response:
                                # Показываем контекст где найден payload в submit response
                                if payload_in_submit_response:
                                    pos = submit_response.text.find(payload)
                                else:
                                    pos = submit_response.text.lower().find(payload.lower())
                                
                                if pos >= 0:
                                    context_start = max(0, pos - 50)
                                    context_end = min(len(submit_response.text), pos + len(payload) + 50)
                                    context = submit_response.text[context_start:context_end]
                                    print(f"    [STOREDXSS] Self-stored payload context: ...{context}...")
                                
                                # Используем детектор для подтверждения
                                try:
                                    is_self_stored, evidence, severity = StoredXSSDetector.detect_stored_xss(
                                        "", payload, submit_response.text  # Пустой submit_response.text для self-stored
                                    )
                                    print(f"    [STOREDXSS] *** SELF-STORED XSS DETECTOR RESULT: vulnerable={is_self_stored}, evidence='{evidence}', severity='{severity}' ***")
                                except Exception as detector_error:
                                    print(f"    [STOREDXSS] Self-stored detector error: {detector_error}")
                                    # Fallback detection для self-stored
                                    is_self_stored = payload_in_submit_response or payload_lower_in_submit_response
                                    evidence = f"Self-Stored XSS payload found in form response: {payload}"
                                    severity = "High"
                                    print(f"    [STOREDXSS] *** SELF-STORED FALLBACK DETECTION: vulnerable={is_self_stored} ***")
                                
                                if is_self_stored:
                                    response_snippet = self._get_contextual_response_snippet(payload, submit_response.text)
                                    print(f"    [STOREDXSS] *** SELF-STORED XSS VULNERABILITY CONFIRMED! ***")
                                    print(f"    [STOREDXSS] Input: {input_name}")
                                    print(f"    [STOREDXSS] Evidence: {evidence}")
                                    print(f"    [STOREDXSS] Severity: {severity}")
                                    
                                    # Mark as found to prevent duplicates
                                    self.found_vulnerabilities.add(form_key)
                                    
                                    results.append({
                                        'module': 'storedxss',
                                        'target': form_url,
                                        'vulnerability': f'Self-Stored XSS in {form_method} Form',
                                        'severity': severity,
                                        'parameter': input_name,
                                        'payload': payload,
                                        'evidence': evidence,
                                        'request_url': form_url,
                                        'detector': 'StoredXSSDetector.detect_stored_xss (self-stored)',
                                        'response_snippet': response_snippet,
                                        'remediation': StoredXSSDetector.get_remediation_advice(),
                                        'xss_type': 'self_stored',
                                        'method': form_method
                                    })
                                    break  # Found self-stored XSS, no need to test more payloads for this input
                            
                            # Step 2: Check if payload is persistently stored by visiting the same page again
                            # (Только если не найден self-stored XSS)
                            if form_key not in self.found_vulnerabilities:
                                print(f"    [STOREDXSS] *** STEP 2: CHECKING IF PAYLOAD IS PERSISTENTLY STORED ***")
                                
                                # Проверяем URL для обнаружения сохраненного payload
                                check_urls = [base_url]
                                
                                # Добавляем form_url только если он отличается от base_url
                                if form_url != base_url:
                                    check_urls.append(form_url)
                                
                                # Убираем дубликаты
                                check_urls = list(set(check_urls))
                                
                                print(f"    [STOREDXSS] Will check {len(check_urls)} URLs for persistently stored payload:")
                                for url in check_urls:
                                    print(f"    [STOREDXSS]   - {url}")
                                
                                print(f"    [STOREDXSS] Form details: action='{form_action}', method='{form_method}', base_url='{base_url}'")
                                print(f"    [STOREDXSS] Constructed form_url: '{form_url}'")
                                
                                stored_found = False
                                check_response = None
                                
                                for check_url in check_urls:
                                    print(f"    [STOREDXSS] *** CHECKING URL: {check_url} ***")
                                    try:
                                        check_response = requests.get(
                                            check_url,
                                            timeout=self.config.timeout,
                                            headers=self.config.headers,
                                            verify=False
                                        )
                                        
                                        print(f"    [STOREDXSS] Check response code: {check_response.status_code}")
                                        print(f"    [STOREDXSS] Check response length: {len(check_response.text)} chars")
                                        
                                        # ЯВНАЯ ПРОВЕРКА НАЛИЧИЯ PAYLOAD В ОТВЕТЕ
                                        payload_in_response = payload in check_response.text
                                        payload_lower_in_response = payload.lower() in check_response.text.lower()
                                        
                                        print(f"    [STOREDXSS] Payload '{payload[:50]}...' found in response: {payload_in_response}")
                                        print(f"    [STOREDXSS] Payload (case-insensitive) found in response: {payload_lower_in_response}")
                                        
                                        if payload_in_response or payload_lower_in_response:
                                            # Показываем контекст где найден payload
                                            if payload_in_response:
                                                pos = check_response.text.find(payload)
                                            else:
                                                pos = check_response.text.lower().find(payload.lower())
                                            
                                            if pos >= 0:
                                                context_start = max(0, pos - 50)
                                                context_end = min(len(check_response.text), pos + len(payload) + 50)
                                                context = check_response.text[context_start:context_end]
                                                print(f"    [STOREDXSS] Persistent payload context: ...{context}...")
                                        
                                        # Use Stored XSS detector with proper parameters
                                        try:
                                            is_vulnerable, evidence, severity = StoredXSSDetector.detect_stored_xss(
                                                submit_response.text, payload, check_response.text
                                            )
                                            print(f"    [STOREDXSS] *** PERSISTENT DETECTOR RESULT: vulnerable={is_vulnerable}, evidence='{evidence}', severity='{severity}' ***")
                                        except Exception as detector_error:
                                            print(f"    [STOREDXSS] Persistent detector error: {detector_error}")
                                            # Fallback detection
                                            is_vulnerable = payload_in_response or payload_lower_in_response
                                            evidence = f"Persistent Stored XSS payload found in response: {payload}"
                                            severity = "High"
                                            print(f"    [STOREDXSS] *** PERSISTENT FALLBACK DETECTION: vulnerable={is_vulnerable} ***")
                                    
                                        if is_vulnerable:
                                            stored_found = True
                                            response_snippet = self._get_contextual_response_snippet(payload, check_response.text)
                                            print(f"    [STOREDXSS] *** PERSISTENT STORED XSS VULNERABILITY CONFIRMED! ***")
                                            print(f"    [STOREDXSS] Input: {input_name}")
                                            print(f"    [STOREDXSS] Evidence: {evidence}")
                                            print(f"    [STOREDXSS] Severity: {severity}")
                                            
                                            # Mark as found to prevent duplicates
                                            self.found_vulnerabilities.add(form_key)
                                            
                                            results.append({
                                                'module': 'storedxss',
                                                'target': form_url,
                                                'vulnerability': f'Persistent Stored XSS in {form_method} Form',
                                                'severity': severity,
                                                'parameter': input_name,
                                                'payload': payload,
                                                'evidence': evidence,
                                                'request_url': form_url,
                                                'detector': 'StoredXSSDetector.detect_stored_xss (persistent)',
                                                'response_snippet': response_snippet,
                                                'remediation': StoredXSSDetector.get_remediation_advice(),
                                                'xss_type': 'persistent_stored',
                                                'method': form_method
                                            })
                                            break  # Found persistent stored XSS, no need to test more payloads for this input
                                        else:
                                            print(f"    [STOREDXSS] No persistent stored XSS detected for payload: {payload[:30]}...")
                                            
                                    except Exception as e:
                                        print(f"    [STOREDXSS] Error checking URL {check_url}: {e}")
                                        continue
                            else:
                                print(f"    [STOREDXSS] *** SKIPPING STEP 2: SELF-STORED XSS ALREADY FOUND ***")
                                
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
                    'remediation': remediation,
                    'method': 'GET'
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
                        'eol_date': eol_date,
                        'method': 'GET'
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
                    
                    test_url = self._build_test_url(base_url, test_params)
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
                            'remediation': remediation,
                            'method': 'GET'
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
                            'remediation': remediation,
                            'method': 'GET'
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
                                    'remediation': remediation,
                                    'method': 'GET'
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
                    with self.screenshot_lock:
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
                    'screenshot': screenshot_filename,
                    'method': 'GET'
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
                        'cookie_issues': all_cookie_issues,  # Keep detailed info for reports
                        'method': 'GET'
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
                            'remediation': HttpOnlyCookieDetector.get_remediation_advice(issue['issue']),
                            'method': 'GET'
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
                        'technologies': tech_list,  # Keep detailed list for reports
                        'method': 'GET'
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
                                'response_snippet': f'Technology: {tech_name}',
                                'method': 'GET'
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
                    
                    test_url = self._build_test_url(base_url, test_params)
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
                            'remediation': 'Disable external entity processing in XML parsers',
                            'method': 'GET'
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
                    from urllib.parse import urljoin
                    form_url = urljoin(base_url, form_action)
                    
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
                                            'remediation': 'Disable external entity processing in XML parsers',
                                            'method': form_method
                                        })
                                        break  # Found XXE, no need to test more payloads for this input
                                        
                                except Exception as e:
                                    print(f"    [XXE] Error testing form payload: {e}")
                                    continue

        return results

    def _test_idor(self, parsed_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Test for IDOR vulnerabilities in both GET parameters and forms"""
        results = []
        base_url = parsed_data['url']

        if 'idor' not in self.scan_stats['payload_stats']:
            self.scan_stats['payload_stats']['idor'] = {'payloads_used': 0, 'requests_made': 0, 'successful_payloads': 0}

        # --- Find ALL parameters with values (not just "ID-like" names) ---
        get_testable_params = []
        for param, values in parsed_data['query_params'].items():
            if values and len(values) > 0:
                param_value = str(values[0])
                # AGGRESSIVE: Test ALL parameters with values
                if IDORDetector.is_parameter_testable(param, base_url, "", param_value):
                    get_testable_params.append((param, param_value))
                    print(f"    [IDOR] ✓ Parameter '{param}' with value '{param_value}' marked as testable")
                else:
                    print(f"    [IDOR] ✗ Parameter '{param}' with value '{param_value}' excluded from testing")
        
        forms_with_testable_params = []
        for form_data in parsed_data.get('forms', []):
            for input_data in form_data.get('inputs', []):
                input_name = input_data.get('name')
                input_value = input_data.get('value', '')
                if input_name and IDORDetector.is_parameter_testable(input_name, base_url, form_data.get('action', ''), str(input_value)):
                    if form_data not in forms_with_testable_params:
                        forms_with_testable_params.append(form_data)

        if not get_testable_params and not forms_with_testable_params:
            print("    [IDOR] No testable parameters found in URL or forms, skipping IDOR test")
            return results
        
        print(f"    [IDOR] Found {len(get_testable_params)} testable GET parameters and {len(forms_with_testable_params)} forms with testable parameters")

        # --- Test GET parameters ---
        for param, original_value in get_testable_params:
            print(f"    [IDOR] Testing GET parameter: {param} (original value: '{original_value}')")
            param_key = f"idor_get_{base_url.split('?')[0]}_{param}"
            if param_key in self.found_vulnerabilities:
                print(f"    [IDOR] Skipping GET parameter {param} - already tested")
                continue
            
            try:
                original_response = requests.get(parsed_data['url'], timeout=self.config.timeout, headers=self.config.headers, verify=False)
                self.request_count += 1
                self.scan_stats['payload_stats']['idor']['requests_made'] += 1
                
                # Generate test values based on original value
                test_values = IDORDetector.get_idor_test_values(original_value, param)
                print(f"    [IDOR] Generated {len(test_values)} test values for parameter '{param}': {test_values[:5]}{'...' if len(test_values) > 5 else ''}")
                
                for test_value in test_values[:self.payload_limit or 20]:  # Increased from 12 to 20
                    if str(test_value) == str(original_value): 
                        continue
                    try:
                        test_params = parsed_data['query_params'].copy()
                        test_params[param] = [test_value]
                        test_url = self._build_test_url(base_url, test_params)
                        modified_response = requests.get(test_url, timeout=self.config.timeout, headers=self.config.headers, verify=False)
                        self.request_count += 1
                        self.scan_stats['payload_stats']['idor']['requests_made'] += 1
                        
                        is_vulnerable, confidence, evidence = IDORDetector.detect_idor(
                            original_response.text, modified_response.text, 
                            original_response.status_code, modified_response.status_code,
                            dict(original_response.headers), dict(modified_response.headers),
                            param, test_url, 'GET'
                        )
                        
                        if is_vulnerable:
                            evidence = f"The GET parameter '{param}' appears to be vulnerable. Accessing with ID '{test_value}' was successful (original was '{original_value}')."
                            print(f"    [IDOR] *** VULNERABILITY CONFIRMED: {param}={test_value} (was {original_value}) ***")
                            results.append(self._create_idor_vulnerability(base_url, 'GET', param, test_value, evidence, test_url, modified_response.text))
                            self.found_vulnerabilities.add(param_key)
                            self.scan_stats['payload_stats']['idor']['successful_payloads'] += 1
                            break
                    except Exception as e:
                        print(f"    [IDOR] Error testing GET payload '{test_value}': {e}")
            except Exception as e:
                print(f"    [IDOR] Error on GET parameter '{param}': {e}")

        # --- Test forms ---
        for form_data in forms_with_testable_params:
            from urllib.parse import urljoin
            form_method = form_data.get('method', 'GET').upper()
            form_action = form_data.get('action', '')
            form_url = urljoin(base_url, form_action)

            for input_data in form_data.get('inputs', []):
                param = input_data.get('name')
                original_value = input_data.get('value', '')
                
                if not param:
                    continue
                
                # Check if this specific parameter is testable
                if not IDORDetector.is_parameter_testable(param, form_url, form_action, str(original_value)):
                    print(f"    [IDOR] Skipping form parameter {param} - not suitable for IDOR testing (value: '{original_value}')")
                    continue

                print(f"    [IDOR] Testing form parameter: {param} (original value: '{original_value}') in form with action '{form_action}'")
                param_key = f"idor_form_{form_url.split('?')[0]}_{param}"
                if param_key in self.found_vulnerabilities:
                    print(f"    [IDOR] Skipping form parameter {param} - already tested")
                    continue
                
                try:
                    # Submit with original value to get a baseline
                    original_form_data = {inp.get('name'): inp.get('value', '') for inp in form_data.get('inputs', []) if inp.get('name')}
                    if form_method == 'POST':
                        original_response = requests.post(form_url, data=original_form_data, timeout=self.config.timeout, headers=self.config.headers, verify=False)
                    else: # GET
                        original_response = requests.get(form_url, params=original_form_data, timeout=self.config.timeout, headers=self.config.headers, verify=False)
                    self.request_count += 1
                    self.scan_stats['payload_stats']['idor']['requests_made'] += 1

                    # Generate test values based on original value
                    test_values = IDORDetector.get_idor_test_values(str(original_value), param)
                    print(f"    [IDOR] Generated {len(test_values)} test values for form parameter '{param}': {test_values[:5]}{'...' if len(test_values) > 5 else ''}")

                    for test_value in test_values[:self.payload_limit or 20]:  # Increased from 12 to 20
                        if str(test_value) == str(original_value): 
                            continue
                        try:
                            test_form_data = original_form_data.copy()
                            test_form_data[param] = test_value
                            
                            if form_method == 'POST':
                                modified_response = requests.post(form_url, data=test_form_data, timeout=self.config.timeout, headers=self.config.headers, verify=False)
                                test_url = form_url
                            else: # GET
                                modified_response = requests.get(form_url, params=test_form_data, timeout=self.config.timeout, headers=self.config.headers, verify=False)
                                test_url = modified_response.url
                            self.request_count += 1
                            self.scan_stats['payload_stats']['idor']['requests_made'] += 1

                            is_vulnerable, confidence, evidence = IDORDetector.detect_idor(
                                original_response.text, modified_response.text, 
                                original_response.status_code, modified_response.status_code,
                                dict(original_response.headers), dict(modified_response.headers),
                                param, test_url, form_method
                            )
                            
                            if is_vulnerable:
                                evidence = f"The form parameter '{param}' appears to be vulnerable. Accessing with ID '{test_value}' was successful (original was '{original_value}')."
                                print(f"    [IDOR] *** FORM VULNERABILITY CONFIRMED: {param}={test_value} (was {original_value}) ***")
                                results.append(self._create_idor_vulnerability(base_url, form_method, param, test_value, evidence, test_url, modified_response.text))
                                self.found_vulnerabilities.add(param_key)
                                self.scan_stats['payload_stats']['idor']['successful_payloads'] += 1
                                break
                        except Exception as e:
                            print(f"    [IDOR] Error testing form payload '{test_value}': {e}")
                except Exception as e:
                    print(f"    [IDOR] Error on form parameter '{param}': {e}")
        
        return results
    
    def _create_idor_vulnerability(self, target: str, method: str, param: str, payload: Any, evidence: str, request_url: str, response_text: str) -> Dict[str, Any]:
        """Helper to create a standardized IDOR vulnerability dictionary."""
        print(f"    [IDOR] VULNERABILITY FOUND! Parameter: {param}, Method: {method}")
        return {
            'module': 'idor',
            'target': target,
            'vulnerability': f'Insecure Direct Object Reference in {method}',
            'severity': 'High',
            'parameter': param,
            'payload': payload,
            'evidence': evidence,
            'request_url': request_url,
            'detector': 'IDORDetector.detect_idor',
            'response_snippet': IDORDetector.get_response_snippet(response_text),
            'remediation': IDORDetector.get_remediation_advice(),
            'method': method,
            'icon': 'fas fa-key'
        }

    def _test_waf_detection(self, parsed_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Run WAF detection module"""
        results = []
        base_url = parsed_data['url']
        
        print("    [WAF-DETECT] Running WAF detection...")
        
        # 1. Run passive analysis to get initial response data
        try:
            response = requests.get(
                base_url,
                timeout=self.config.timeout,
                headers=self.config.headers,
                verify=False
            )
            has_passive_waf, passive_findings = WAFDetector.analyze(response.headers, response.text, base_url)
            if has_passive_waf:
                results.extend(passive_findings)
        except Exception as e:
            print(f"    [WAF-DETECT] Error during passive check: {e}")

        # 2. Run active detection
        print("    [WAF-DETECT] Running active WAF detection probe...")
        try:
            has_active_waf, active_findings = WAFDetector.active_detect(
                base_url, self.config.headers, self.config.timeout
            )
            if has_active_waf:
                results.extend(active_findings)
        except Exception as e:
            print(f"    [WAF-DETECT] Error during active detection: {e}")

        if results:
            # Deduplicate findings
            unique_findings = []
            seen_wafs = set()
            for finding in results:
                waf_name = finding.get('waf_name', 'Generic WAF')
                if waf_name not in seen_wafs:
                    unique_findings.append(finding)
                    seen_wafs.add(waf_name)
            print(f"    [WAF-DETECT] WAF detection complete. Found: {', '.join(seen_wafs) if seen_wafs else 'None'}")
            return unique_findings
        
        print("    [WAF-DETECT] No WAF detected.")
        return []

    def _test_command_injection(self, parsed_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Test for Command Injection vulnerabilities"""
        results = []
        base_url = parsed_data['url']
        
        # Get command injection payloads
        cmd_payloads = CommandInjectionPayloads.get_all_payloads()
        if self.waf:
            print("    [CMDINJECTION] WAF mode enabled, loading bypass payloads...")
            try:
                cmd_payloads.extend(CommandInjectionPayloads.get_waf_bypass_payloads())
            except AttributeError:
                print("    [CMDINJECTION] Warning: get_waf_bypass_payloads() not found in CommandInjectionPayloads.")
        
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
                    
                    test_url = self._build_test_url(base_url, test_params)
                    print(f"    [CMDINJECTION] Request URL: {test_url}")
                    
                    response = requests.get(
                        test_url,
                        timeout=self.config.timeout,
                        headers=self.config.headers,
                        verify=False
                    )
                    
                    print(f"    [CMDINJECTION] Response code: {response.status_code}")
                    
                    # Enhanced Command Injection detection with false positive filtering
                    try:
                        cmd_result = CommandInjectionDetector.detect_command_injection(response.text, response.status_code, payload)
                        if isinstance(cmd_result, tuple) and len(cmd_result) >= 3:
                            is_vulnerable, confidence, evidence = cmd_result[:3]
                        elif isinstance(cmd_result, tuple) and len(cmd_result) == 2:
                            is_vulnerable, evidence = cmd_result
                            confidence = 0.8
                        else:
                            is_vulnerable = bool(cmd_result)
                            evidence = f"Command injection detected with payload: {payload}"
                            confidence = 0.7
                    except Exception as e:
                        print(f"    [CMDINJECTION] Detector error: {e}")
                        is_vulnerable = False
                        evidence = "Detection failed"
                        confidence = 0.0
                    
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
                            'confidence': confidence,
                            'method': 'GET'
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
                
                # Build form URL with proper port handling
                from urllib.parse import urljoin
                form_url = urljoin(base_url, form_action)
                
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
                            try:
                                cmd_result = CommandInjectionDetector.detect_command_injection(response.text, response.status_code, payload)
                                if isinstance(cmd_result, tuple) and len(cmd_result) >= 3:
                                    is_vulnerable, confidence, evidence = cmd_result[:3]
                                elif isinstance(cmd_result, tuple) and len(cmd_result) == 2:
                                    is_vulnerable, evidence = cmd_result
                                    confidence = 0.8
                                else:
                                    is_vulnerable = bool(cmd_result)
                                    evidence = f"Command injection detected with payload: {payload}"
                                    confidence = 0.7
                            except Exception as e:
                                print(f"    [CMDINJECTION] Form detector error: {e}")
                                is_vulnerable = False
                                evidence = "Detection failed"
                                confidence = 0.0
                            
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
                                    'confidence': confidence,
                                    'method': form_method
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
                    
                    test_url = self._build_test_url(base_url, test_params)
                    
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
                            'remediation': remediation,
                            'method': 'GET'
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
                    
                    test_url = self._build_test_url(base_url, test_params)
                    
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
                            'remediation': remediation,
                            'method': 'GET'
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
                    
                    test_url = self._build_test_url(base_url, test_params)
                    
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
                            'remediation': remediation,
                            'method': 'GET'
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
                    'remediation': remediation,
                    'method': 'GET'
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
                                'remediation': remediation,
                                'method': 'GET'
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
                        'remediation': remediation,
                        'method': 'GET'
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
                    'response_snippet': JWTDetector.get_response_snippet(response.text),
                    'method': 'GET'
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
                    
                    test_url = self._build_test_url(base_url, test_params)
                    
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
                            'remediation': remediation,
                            'method': 'GET'
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
                    
                    test_url = self._build_test_url(base_url, test_params)
                    
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
                            'remediation': 'Validate and sanitize all user inputs used in HTTP responses',
                            'method': 'GET'
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
        if self.waf:
            print("    [SSTI] WAF mode enabled, loading bypass payloads...")
            try:
                ssti_payloads.extend(SSTIPayloads.get_waf_bypass_payloads())
            except AttributeError:
                print("    [SSTI] Warning: get_waf_bypass_payloads() not found in SSTIPayloads.")
        
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
                    
                    test_url = self._build_test_url(base_url, test_params)
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
                            'remediation': remediation,
                            'method': 'GET'
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
                
                # Build form URL with proper port handling
                from urllib.parse import urljoin
                form_url = urljoin(base_url, form_action)
                
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
                                    'remediation': remediation,
                                    'method': form_method
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
                    
                    test_url = self._build_test_url(base_url, test_params)
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
                            'remediation': 'Validate and sanitize all user inputs used in HTTP responses',
                            'method': 'GET'
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
                    
                    test_url = self._build_test_url(base_url, test_params)
                    
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
                            'remediation': remediation,
                            'method': 'GET'
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
                            'remediation': remediation,
                            'method': 'GET'
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
                        'remediation': HostHeaderDetector.get_remediation_advice(),
                        'method': 'GET'
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
                        'remediation': PrototypePollutionDetector.get_remediation_advice(),
                        'method': 'POST'
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
                        'remediation': VHostDetector.get_remediation_advice(),
                        'method': 'GET'
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
                    'email_addresses': unique_emails,  # Store for detailed reporting
                    'method': 'GET'
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
                    'response_snippet': f'Found {len(unique_ips)} internal IPs',
                    'method': 'GET'
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
                    'response_snippet': f'Debug patterns: {", ".join(found_debug)}',
                    'method': 'GET'
                })
            
        except Exception as e:
            print(f"    [INFOLEAK] Error during information leakage testing: {e}")
        
        return results
    
    def _test_open_redirect(self, parsed_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Test for Open Redirect vulnerabilities"""
        results = []
        base_url = parsed_data['url']

        # Get open redirect payloads from payload loader
        redirect_payloads = PayloadLoader.load_payloads('openredirect')
        if not redirect_payloads:
            print("    [OPENREDIRECT] Warning: Could not load openredirect payloads.")
            redirect_payloads = ['http://evil.com', '//evil.com']  # Fallback

        # Get redirect parameters from detector
        redirect_params = OpenRedirectDetector.get_redirect_parameters()

        # Update payload stats
        if 'openredirect' not in self.scan_stats['payload_stats']:
            self.scan_stats['payload_stats']['openredirect'] = {'payloads_used': 0, 'requests_made': 0, 'successful_payloads': 0}
        self.scan_stats['payload_stats']['openredirect']['payloads_used'] += len(redirect_payloads)

        # Test GET parameters
        for param, values in parsed_data['query_params'].items():
            # Check if parameter name suggests it might be used for redirects
            if any(redirect_param.lower() in param.lower() for redirect_param in redirect_params):
                print(f"    [OPENREDIRECT] Testing parameter: {param}")

                # Create deduplication key for this parameter
                param_key = f"openredirect_{base_url.split('?')[0]}_{param}"
                if param_key in self.found_vulnerabilities:
                    print(f"    [OPENREDIRECT] Skipping parameter {param} - already tested")
                    continue

                payload_count = self.payload_limit if self.payload_limit > 0 else len(redirect_payloads)
                for payload in redirect_payloads[:payload_count]:
                    try:
                        print(f"    [OPENREDIRECT] Trying payload: {payload}")

                        # Create test URL
                        test_params = parsed_data['query_params'].copy()
                        test_params[param] = [payload]

                        test_url = self._build_test_url(base_url, test_params)

                        response = requests.get(
                            test_url,
                            timeout=self.config.timeout,
                            headers=self.config.headers,
                            verify=False,
                            allow_redirects=False  # Don't follow redirects to check headers
                        )

                        # Update request count
                        self.request_count += 1
                        self.scan_stats['payload_stats']['openredirect']['requests_made'] += 1

                        print(f"    [OPENREDIRECT] Response code: {response.status_code}")

                        # Use OpenRedirectDetector for comprehensive checks
                        is_vulnerable, details, redirect_type = OpenRedirectDetector.detect_open_redirect(
                            response.text, response.status_code, dict(response.headers), payload, base_url
                        )

                        if is_vulnerable:
                            print(f"    [OPENREDIRECT] VULNERABILITY FOUND! Parameter: {param}")

                            # Mark as found to prevent duplicates
                            self.found_vulnerabilities.add(param_key)

                            evidence = OpenRedirectDetector.get_evidence(redirect_type, details)
                            response_snippet = OpenRedirectDetector.get_response_snippet(response.text, details)

                            results.append({
                                'module': 'openredirect',
                                'target': base_url,
                                'vulnerability': 'Open Redirect',
                                'severity': 'Medium',
                                'parameter': param,
                                'payload': payload,
                                'evidence': evidence,
                                'request_url': test_url,
                                'detector': 'OpenRedirectDetector.detect_open_redirect',
                                'response_snippet': response_snippet,
                                'remediation': 'Validate redirect URLs against a whitelist of allowed domains.',
                                'method': 'GET',
                                'http_method': 'GET'
                            })

                            # Update successful payload count
                            self.scan_stats['payload_stats']['openredirect']['successful_payloads'] += 1
                            self.scan_stats['total_payloads_used'] += 1

                            break  # Found open redirect, no need to test more payloads for this param

                    except Exception as e:
                        print(f"    [OPENREDIRECT] Error testing payload: {e}")
                        continue

        return results
    
    def _test_hpp(self, parsed_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Test for HTTP Parameter Pollution vulnerabilities"""
        results = []
        base_url = parsed_data['url']
        
        # Get HPP payloads
        hpp_payloads = HPPPayloads.get_all_payloads()
        
        # Test GET parameters for HPP
        for param, values in parsed_data['query_params'].items():
            print(f"    [HPP] Testing parameter: {param}")
            
            # Create deduplication key for this parameter
            param_key = f"hpp_{base_url.split('?')[0]}_{param}"
            if param_key in self.found_vulnerabilities:
                print(f"    [HPP] Skipping parameter {param} - already tested")
                continue
            
            try:
                # Get original response
                original_response = requests.get(
                    parsed_data['url'],
                    timeout=self.config.timeout,
                    headers=self.config.headers,
                    verify=False
                )
                
                # Test context-specific payloads
                context_payloads = HPPPayloads.get_context_specific_payloads(param)
                
                for payload_info in context_payloads:
                    try:
                        print(f"    [HPP] Trying payload: {payload_info['name']}")
                        
                        # Create HPP URL with duplicate parameters
                        from urllib.parse import quote_plus
                        test_params_list = []
                        for value in payload_info['values']:
                            test_params_list.append(f"{quote_plus(param)}={quote_plus(str(value))}")
                        
                        # Add original parameters
                        for k, v_list in parsed_data['query_params'].items():
                            if k != param:
                                for v in v_list:
                                    test_params_list.append(f"{quote_plus(k)}={quote_plus(str(v))}")
                        
                        test_url = f"{base_url.split('?')[0]}?{'&'.join(test_params_list)}"
                        
                        response = requests.get(
                            test_url,
                            timeout=self.config.timeout,
                            headers=self.config.headers,
                            verify=False
                        )
                        
                        print(f"    [HPP] Response code: {response.status_code}")
                        
                        # Use HPP detector
                        is_vulnerable, evidence, severity, metadata = HPPDetector.detect_hpp_vulnerability(
                            test_url, response.text, response.status_code, original_response.text
                        )
                        
                        if is_vulnerable:
                            print(f"    [HPP] VULNERABILITY FOUND! Parameter: {param}")
                            
                            # Mark as found to prevent duplicates
                            self.found_vulnerabilities.add(param_key)
                            
                            results.append({
                                'module': 'hpp',
                                'target': base_url,
                                'vulnerability': 'HTTP Parameter Pollution',
                                'severity': severity,
                                'parameter': param,
                                'payload': str(payload_info['values']),
                                'evidence': evidence,
                                'request_url': test_url,
                                'detector': 'HPPDetector.detect_hpp_vulnerability',
                                'response_snippet': HPPDetector.get_response_snippet(response.text),
                                'remediation': HPPDetector.get_remediation_advice(),
                                'method': 'GET',
                                **metadata
                            })
                            break  # Found HPP, no need to test more payloads for this param
                            
                    except Exception as e:
                        print(f"    [HPP] Error testing payload: {e}")
                        continue
                        
            except Exception as e:
                print(f"    [HPP] Error getting original response: {e}")
                continue
        
        return results
    
    def _test_reverse_tabnabbing(self, parsed_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Test for Reverse Tabnabbing vulnerabilities"""
        results = []
        base_url = parsed_data['url']
        
        # Extract domain for deduplication
        from urllib.parse import urlparse
        parsed_url = urlparse(base_url)
        domain = parsed_url.hostname
        
        # Create deduplication key for this domain
        domain_key = f"reversetabnabbing_{domain}"
        if domain_key in self.found_vulnerabilities:
            print(f"    [REVERSETABNABBING] Skipping reverse tabnabbing test for {domain} - already tested")
            return results
        
        try:
            print(f"    [REVERSETABNABBING] Testing reverse tabnabbing for domain: {domain}")
            
            # Mark domain as tested
            self.found_vulnerabilities.add(domain_key)
            
            # Make request to get page content
            response = requests.get(
                base_url,
                timeout=self.config.timeout,
                headers=self.config.headers,
                verify=False
            )
            
            print(f"    [REVERSETABNABBING] Response code: {response.status_code}")
            
            # Use Reverse Tabnabbing detector
            is_vulnerable, evidence, severity, metadata = ReverseTabnabbingDetector.detect_reverse_tabnabbing(
                response.text, response.status_code, base_url
            )
            
            if is_vulnerable:
                print(f"    [REVERSETABNABBING] VULNERABILITY FOUND! {evidence}")
                
                vulnerable_links = metadata.get('vulnerable_links', [])
                detailed_evidence = ReverseTabnabbingDetector.get_evidence(vulnerable_links)
                response_snippet = ReverseTabnabbingDetector.get_response_snippet(vulnerable_links)
                remediation = ReverseTabnabbingDetector.get_remediation_advice()
                
                results.append({
                    'module': 'reversetabnabbing',
                    'target': base_url,
                    'vulnerability': 'Reverse Tabnabbing',
                    'severity': severity,
                    'parameter': 'external_links',
                    'payload': 'N/A',
                    'evidence': detailed_evidence,
                    'request_url': base_url,
                    'detector': 'ReverseTabnabbingDetector.detect_reverse_tabnabbing',
                    'response_snippet': response_snippet,
                    'remediation': remediation,
                    'vulnerable_links_count': len(vulnerable_links),
                    'method': 'GET',
                    **{k: v for k, v in metadata.items() if k != 'vulnerable_links'}
                })
            else:
                print(f"    [REVERSETABNABBING] No reverse tabnabbing vulnerabilities found")
            
        except Exception as e:
            print(f"    [REVERSETABNABBING] Error during reverse tabnabbing testing: {e}")
        
        return results
    
    def _test_insecure_reflection(self, parsed_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Test for Insecure Reflected Content vulnerabilities"""
        results = []
        base_url = parsed_data['url']
        
        # Get reflection test payloads
        reflection_payloads = InsecureReflectedContentDetector.get_reflection_test_payloads()
        
        # Test GET parameters
        for param, values in parsed_data['query_params'].items():
            print(f"    [INSECUREREFLECTION] Testing parameter: {param}")
            
            # Create deduplication key for this parameter
            param_key = f"insecurereflection_{base_url.split('?')[0]}_{param}"
            if param_key in self.found_vulnerabilities:
                print(f"    [INSECUREREFLECTION] Skipping parameter {param} - already tested")
                continue
            
            for payload in reflection_payloads:
                try:
                    print(f"    [INSECUREREFLECTION] Trying payload: {payload[:30]}...")
                    
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
                    
                    print(f"    [INSECUREREFLECTION] Response code: {response.status_code}")
                    
                    # Use Insecure Reflection detector
                    is_vulnerable, evidence, severity, metadata = InsecureReflectedContentDetector.detect_insecure_reflection(
                        response.text, response.status_code, payload, param
                    )
                    
                    if is_vulnerable:
                        print(f"    [INSECUREREFLECTION] VULNERABILITY FOUND! Parameter: {param}")
                        
                        # Mark as found to prevent duplicates
                        self.found_vulnerabilities.add(param_key)
                        
                        reflection_details = metadata.get('reflection_details', {})
                        response_snippet = InsecureReflectedContentDetector.get_response_snippet(
                            reflection_details.get('surrounding_content', response.text[:200])
                        )
                        remediation = InsecureReflectedContentDetector.get_remediation_advice()
                        
                        results.append({
                            'module': 'insecurereflection',
                            'target': base_url,
                            'vulnerability': 'Insecure Reflected Content',
                            'severity': severity,
                            'parameter': param,
                            'payload': payload,
                            'evidence': evidence,
                            'request_url': test_url,
                            'detector': 'InsecureReflectedContentDetector.detect_insecure_reflection',
                            'response_snippet': response_snippet,
                            'remediation': remediation,
                            'reflection_context': reflection_details.get('context', 'unknown'),
                            'reflection_encoding': reflection_details.get('encoding', 'none'),
                            'method': 'GET',
                            **{k: v for k, v in metadata.items() if k != 'reflection_details'}
                        })
                        break  # Found insecure reflection, no need to test more payloads for this param
                        
                except Exception as e:
                    print(f"    [INSECUREREFLECTION] Error testing payload: {e}")
                    continue
        
        return results
    
    def _test_php_config(self, parsed_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Test for PHP Configuration Issues"""
        results = []
        base_url = parsed_data['url']
        
        # Extract domain for deduplication
        from urllib.parse import urlparse
        parsed_url = urlparse(base_url)
        domain = parsed_url.hostname
        
        # Create deduplication key for this domain
        domain_key = f"phpconfig_{domain}"
        if domain_key in self.found_vulnerabilities:
            print(f"    [PHPCONFIG] Skipping PHP config test for {domain} - already tested")
            return results
        
        try:
            print(f"    [PHPCONFIG] Testing PHP configuration for domain: {domain}")
            
            # Mark domain as tested
            self.found_vulnerabilities.add(domain_key)
            
            # Make request to get headers and content
            response = requests.get(
                base_url,
                timeout=self.config.timeout,
                headers=self.config.headers,
                verify=False
            )
            
            print(f"    [PHPCONFIG] Response code: {response.status_code}")
            
            # Use PHP Config detector
            is_vulnerable, evidence, severity, issues = PHPConfigDetector.detect_php_config_issues(
                response.text, response.status_code, dict(response.headers)
            )
            
            if is_vulnerable and issues:
                print(f"    [PHPCONFIG] Found {len(issues)} PHP configuration issues")
                
                detailed_evidence = PHPConfigDetector.get_evidence(issues)
                response_snippet = PHPConfigDetector.get_response_snippet(issues, response.text)
                remediation = PHPConfigDetector.get_remediation_advice()
                
                # Group issues or create individual findings based on count
                if len(issues) <= 5:
                    # Group into single finding
                    results.append({
                        'module': 'phpconfig',
                        'target': base_url,
                        'vulnerability': f'PHP Configuration Issues ({len(issues)} issues)',
                        'severity': severity,
                        'parameter': f'php_config: {len(issues)} issues',
                        'payload': 'N/A',
                        'evidence': detailed_evidence,
                        'request_url': base_url,
                        'detector': 'PHPConfigDetector.detect_php_config_issues',
                        'response_snippet': response_snippet,
                        'remediation': remediation,
                        'php_issues': issues,
                        'method': 'GET'
                    })
                else:
                    # Create individual findings for each issue
                    for issue in issues:
                        results.append({
                            'module': 'phpconfig',
                            'target': base_url,
                            'vulnerability': f'PHP Configuration Issue: {issue["setting"]}',
                            'severity': issue['severity'],
                            'parameter': f'php_setting: {issue["setting"]}',
                            'payload': 'N/A',
                            'evidence': issue['description'],
                            'request_url': base_url,
                            'detector': 'PHPConfigDetector.detect_php_config_issues',
                            'response_snippet': f'{issue["setting"]}: {issue["value"]}',
                            'remediation': remediation,
                            'method': 'GET'
                        })
            else:
                print(f"    [PHPCONFIG] No PHP configuration issues found")
            
        except Exception as e:
            print(f"    [PHPCONFIG] Error during PHP config testing: {e}")
        
        return results
    
    def _test_csp(self, parsed_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Test for Content Security Policy issues"""
        results = []
        base_url = parsed_data['url']
        
        # Extract domain for deduplication
        from urllib.parse import urlparse
        parsed_url = urlparse(base_url)
        domain = parsed_url.hostname
        
        # Create deduplication key for this domain
        domain_key = f"csp_{domain}"
        if domain_key in self.found_vulnerabilities:
            print(f"    [CSP] Skipping CSP test for {domain} - already tested")
            return results
        
        try:
            print(f"    [CSP] Testing Content Security Policy for domain: {domain}")
            
            # Mark domain as tested
            self.found_vulnerabilities.add(domain_key)
            
            # Make request to get headers and content
            response = requests.get(
                base_url,
                timeout=self.config.timeout,
                headers=self.config.headers,
                verify=False
            )
            
            print(f"    [CSP] Response code: {response.status_code}")
            
            # Use CSP detector
            is_vulnerable, evidence, severity, issues = CSPDetector.detect_csp_issues(
                dict(response.headers), response.text
            )
            
            if is_vulnerable and issues:
                print(f"    [CSP] Found {len(issues)} CSP issues")
                
                csp_header = response.headers.get('Content-Security-Policy', 
                           response.headers.get('content-security-policy', ''))
                detailed_evidence = CSPDetector.get_evidence(issues, csp_header)
                response_snippet = CSPDetector.get_response_snippet(csp_header, issues)
                remediation = CSPDetector.get_remediation_advice()
                
                # Group issues or create individual findings based on count
                if len(issues) <= 8:
                    # Group into single finding
                    results.append({
                        'module': 'csp',
                        'target': base_url,
                        'vulnerability': f'Content Security Policy Issues ({len(issues)} issues)',
                        'severity': severity,
                        'parameter': f'csp_config: {len(issues)} issues',
                        'payload': 'N/A',
                        'evidence': detailed_evidence,
                        'request_url': base_url,
                        'detector': 'CSPDetector.detect_csp_issues',
                        'response_snippet': response_snippet,
                        'remediation': remediation,
                        'csp_issues': issues,
                        'method': 'GET'
                    })
                else:
                    # Create individual findings for critical issues
                    for issue in issues:
                        if issue['severity'] in ['High', 'Medium']:
                            results.append({
                                'module': 'csp',
                                'target': base_url,
                                'vulnerability': f'CSP Issue: {issue["directive"]}',
                                'severity': issue['severity'],
                                'parameter': f'csp_directive: {issue["directive"]}',
                                'payload': 'N/A',
                                'evidence': issue['description'],
                                'request_url': base_url,
                                'detector': 'CSPDetector.detect_csp_issues',
                                'response_snippet': f'{issue["directive"]}: {issue["issue"]}',
                                'remediation': remediation,
                                'method': 'GET'
                            })
            else:
                print(f"    [CSP] No CSP issues found")
            
        except Exception as e:
            print(f"    [CSP] Error during CSP testing: {e}")
        
        return results
    
    def _test_mixed_content(self, parsed_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Test for Mixed Content vulnerabilities"""
        results = []
        base_url = parsed_data['url']
        
        # Only test HTTPS pages
        if not base_url.startswith('https://'):
            print(f"    [MIXEDCONTENT] Skipping - not an HTTPS page")
            return results
        
        # Extract domain for deduplication
        from urllib.parse import urlparse
        parsed_url = urlparse(base_url)
        domain = parsed_url.hostname
        
        # Create deduplication key for this domain
        domain_key = f"mixedcontent_{domain}"
        if domain_key in self.found_vulnerabilities:
            print(f"    [MIXEDCONTENT] Skipping mixed content test for {domain} - already tested")
            return results
        
        try:
            print(f"    [MIXEDCONTENT] Testing mixed content for HTTPS domain: {domain}")
            
            # Mark domain as tested
            self.found_vulnerabilities.add(domain_key)
            
            # Make request to get page content
            response = requests.get(
                base_url,
                timeout=self.config.timeout,
                headers=self.config.headers,
                verify=False
            )
            
            print(f"    [MIXEDCONTENT] Response code: {response.status_code}")
            
            # Use Mixed Content detector
            is_vulnerable, evidence, severity, mixed_content_issues = MixedContentDetector.detect_mixed_content(
                response.text, response.status_code, base_url
            )
            
            if is_vulnerable and mixed_content_issues:
                print(f"    [MIXEDCONTENT] Found {len(mixed_content_issues)} mixed content issues")
                
                detailed_evidence = MixedContentDetector.get_evidence(mixed_content_issues)
                response_snippet = MixedContentDetector.get_response_snippet(mixed_content_issues)
                remediation = MixedContentDetector.get_remediation_advice()
                
                # Count active vs passive issues
                active_issues = [issue for issue in mixed_content_issues if issue['type'] == 'active']
                passive_issues = [issue for issue in mixed_content_issues if issue['type'] == 'passive']
                
                results.append({
                    'module': 'mixedcontent',
                    'target': base_url,
                    'vulnerability': f'Mixed Content ({len(mixed_content_issues)} issues)',
                    'severity': severity,
                    'parameter': f'mixed_content: {len(active_issues)} active, {len(passive_issues)} passive',
                    'payload': 'N/A',
                    'evidence': detailed_evidence,
                    'request_url': base_url,
                    'detector': 'MixedContentDetector.detect_mixed_content',
                    'response_snippet': response_snippet,
                    'remediation': remediation,
                    'active_issues_count': len(active_issues),
                    'passive_issues_count': len(passive_issues),
                    'mixed_content_details': mixed_content_issues,
                    'method': 'GET'
                })
            else:
                print(f"    [MIXEDCONTENT] No mixed content issues found")
            
        except Exception as e:
            print(f"    [MIXEDCONTENT] Error during mixed content testing: {e}")
        
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
                
                # Load metadata from JSON file
                module_name = clean_result.get('module', 'unknown')
                severity = clean_result.get('severity', 'Medium')
                
                # Try to get metadata from PayloadLoader first, then fallback to JSON methods
                try:
                    metadata = PayloadLoader.get_vulnerability_metadata(module_name, severity)
                except:
                    metadata = {}
                
                # Ensure required metadata exists using JSON-based methods
                if 'cvss' not in clean_result:
                    json_cvss = self._get_cvss_from_json(module_name, severity)
                    clean_result['cvss'] = metadata.get('cvss', json_cvss)
                if 'owasp' not in clean_result:
                    clean_result['owasp'] = metadata.get('owasp', self._get_default_owasp(module_name))
                if 'cwe' not in clean_result:
                    clean_result['cwe'] = metadata.get('cwe', self._get_default_cwe(module_name))
                if 'recommendation' not in clean_result:
                    clean_result['recommendation'] = metadata.get('recommendation', self._get_default_recommendation(module_name))
            
            enhanced_results.append(clean_result)
        
        return enhanced_results
    
    def _get_cvss_from_json(self, module: str, severity: str) -> str:
        """Get CVSS score from JSON based on module and severity"""
        try:
            import os
            json_path = os.path.join(os.path.dirname(__file__), '..', 'data', 'cwe_owasp_mapping.json')
            with open(json_path, 'r', encoding='utf-8') as f:
                data = json.load(f)
            
            vulnerabilities = data.get('vulnerabilities', {})
            if module in vulnerabilities:
                vuln_data = vulnerabilities[module]
                severity_mapping = vuln_data.get('severity_mapping', {})
                if severity in severity_mapping:
                    score = severity_mapping[severity]
                    # Add CVSS vector based on severity
                    vectors = {
                        'Critical': 'AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
                        'High': 'AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H',
                        'Medium': 'AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:N',
                        'Low': 'AV:N/AC:H/PR:L/UI:N/S:U/C:L/I:N/A:N',
                        'Info': 'AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N'
                    }
                    vector = vectors.get(severity, 'AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:N')
                    return f"{score} ({vector})"
                else:
                    # Use base CVSS if no severity mapping
                    base_score = vuln_data.get('cvss_base', '6.5')
                    return f"{base_score} (AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:N)"
            
        except Exception as e:
            print(f"Warning: Could not load CVSS data from JSON: {e}")
        
        # Fallback to severity-based CVSS
        return self._get_default_cvss(severity)
    
    def _get_default_cvss(self, severity: str) -> str:
        """Get default CVSS score based on severity from JSON"""
        try:
            # Load severity levels from JSON
            import os
            json_path = os.path.join(os.path.dirname(__file__), '..', 'data', 'cwe_owasp_mapping.json')
            with open(json_path, 'r', encoding='utf-8') as f:
                data = json.load(f)
            
            severity_levels = data.get('severity_levels', {})
            if severity in severity_levels:
                cvss_range = severity_levels[severity]['cvss_range']
                # Return the middle value of the range with vector
                if '-' in cvss_range:
                    min_val, max_val = cvss_range.split('-')
                    avg_score = (float(min_val) + float(max_val)) / 2
                else:
                    avg_score = float(cvss_range)
                
                # Add CVSS vector based on severity
                vectors = {
                    'Critical': 'AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
                    'High': 'AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H',
                    'Medium': 'AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:N',
                    'Low': 'AV:N/AC:H/PR:L/UI:N/S:U/C:L/I:N/A:N',
                    'Info': 'AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N'
                }
                vector = vectors.get(severity, 'AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:N')
                return f"{avg_score:.1f} ({vector})"
            
        except Exception as e:
            print(f"Warning: Could not load CVSS data from JSON: {e}")
        
        # Fallback
        return '6.5 (AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:N)'
    
    def _get_default_owasp(self, module: str) -> str:
        """Get default OWASP classification based on module from JSON"""
        try:
            # Load vulnerability data from JSON
            import os
            json_path = os.path.join(os.path.dirname(__file__), '..', 'data', 'cwe_owasp_mapping.json')
            with open(json_path, 'r', encoding='utf-8') as f:
                data = json.load(f)
            
            vulnerabilities = data.get('vulnerabilities', {})
            if module in vulnerabilities:
                return vulnerabilities[module].get('owasp', 'A06:2021 – Vulnerable and Outdated Components')
            
        except Exception as e:
            print(f"Warning: Could not load OWASP data from JSON: {e}")
        
        # Fallback
        return 'A06:2021 – Vulnerable and Outdated Components'
    
    def _get_default_cwe(self, module: str) -> str:
        """Get default CWE classification based on module from JSON"""
        try:
            # Load vulnerability data from JSON
            import os
            json_path = os.path.join(os.path.dirname(__file__), '..', 'data', 'cwe_owasp_mapping.json')
            with open(json_path, 'r', encoding='utf-8') as f:
                data = json.load(f)
            
            vulnerabilities = data.get('vulnerabilities', {})
            if module in vulnerabilities:
                return vulnerabilities[module].get('cwe', 'CWE-200')
            
        except Exception as e:
            print(f"Warning: Could not load CWE data from JSON: {e}")
        
        # Fallback
        return 'CWE-200'
    
    def _get_default_recommendation(self, module: str) -> str:
        """Get default recommendation based on module from JSON"""
        try:
            # Load vulnerability data from JSON
            import os
            json_path = os.path.join(os.path.dirname(__file__), '..', 'data', 'cwe_owasp_mapping.json')
            with open(json_path, 'r', encoding='utf-8') as f:
                data = json.load(f)
            
            vulnerabilities = data.get('vulnerabilities', {})
            if module in vulnerabilities:
                return vulnerabilities[module].get('recommendation', 'Review and implement appropriate security controls.')
            
        except Exception as e:
            print(f"Warning: Could not load recommendation data from JSON: {e}")
        
        # Fallback
        return 'Review and implement appropriate security controls.'
    
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
        import sys
        
        try:
            print("\n" + "="*80)
            print("SCAN RESULTS SUMMARY".center(80))
            print("="*80)
            sys.stdout.flush()  # Force flush output buffer
        except UnicodeEncodeError:
            print("\n" + "="*80)
            print("SCAN RESULTS SUMMARY".center(80))
            print("="*80)
            sys.stdout.flush()
        
        
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
        
        # WAF summary
        detected_wafs = set()
        for v in vulnerabilities:
            if v.get('module') == 'wafdetect' or 'WAF Detected' in v.get('vulnerability', ''):
                waf_name = v.get('waf_name')
                if waf_name:
                    detected_wafs.add(waf_name)
        
        if detected_wafs:
            print("\n" + "WAF DETECTION SUMMARY".center(60))
            print("-" * 60)
            for waf_name in sorted(list(detected_wafs)):
                print(f"  🛡️  {waf_name} was detected.")
            print("-" * 60)
        
        # Separate active and passive vulnerabilities
        active_vulns = {'critical': [], 'high': [], 'medium': [], 'low': [], 'info': []}
        passive_vulns = {'critical': [], 'high': [], 'medium': [], 'low': [], 'info': []}
        
        for vuln_list, severity in [(critical_vulns, 'critical'), (high_vulns, 'high'), 
                                   (medium_vulns, 'medium'), (low_vulns, 'low'), (info_vulns, 'info')]:
            for vuln in vuln_list:
                if vuln.get('passive_analysis', False):
                    passive_vulns[severity].append(vuln)
                else:
                    active_vulns[severity].append(vuln)
        
        # Print active vulnerabilities
        total_active = sum(len(vulns) for vulns in active_vulns.values())
        if total_active > 0:
            print(f"\nACTIVE VULNERABILITIES ({total_active} found):")
            print("="*60)
            sys.stdout.flush()
            
            vuln_counter = 1
            for severity, vulns in active_vulns.items():
                if vulns:
                    print(f"\n{severity.upper()} SEVERITY ({len(vulns)} found):")
                    print("-" * 50)
                    sys.stdout.flush()
                    
                    for result in vulns:
                        self._print_vulnerability(vuln_counter, result)
                        vuln_counter += 1
                        sys.stdout.flush()  # Flush after each vulnerability
        
        # Print passive vulnerabilities
        total_passive = sum(len(vulns) for vulns in passive_vulns.values())
        if total_passive > 0:
            print(f"\nPASSIVE VULNERABILITIES ({total_passive} found):")
            print("="*60)
            sys.stdout.flush()
            
            passive_counter = vuln_counter if total_active > 0 else 1
            
            for severity, vulns in passive_vulns.items():
                if vulns:
                    print(f"\n{severity.upper()} SEVERITY ({len(vulns)} found):")
                    print("-" * 50)
                    sys.stdout.flush()
                    
                    for result in vulns:
                        self._print_vulnerability(passive_counter, result, is_passive=True)
                        passive_counter += 1
                        sys.stdout.flush()  # Flush after each vulnerability
        
        # Print found resources summary
        found_resources = self.scan_stats.get('found_resources', {})
        if found_resources:
            total_resources = sum(len(resources) for resources in found_resources.values())
            print(f"\nFOUND RESOURCES ({total_resources} items across {len(found_resources)} categories):")
            print("="*60)
            
            # Sort categories by severity
            def get_category_severity_weight(resources):
                weight = 0
                for resource in resources:
                    severity = resource.get('severity', 'Info')
                    if severity == 'Critical':
                        weight += 10
                    elif severity == 'High':
                        weight += 7
                    elif severity == 'Medium':
                        weight += 4
                    elif severity == 'Low':
                        weight += 2
                    else:
                        weight += 1
                return weight
            
            sorted_categories = sorted(found_resources.items(), 
                                     key=lambda x: get_category_severity_weight(x[1]), 
                                     reverse=True)
            
            for category, resources in sorted_categories:
                if not resources:
                    continue
                    
                category_name = category.replace('_', ' ').title()
                print(f"\n{category_name} ({len(resources)} found):")
                print("-" * 40)
                
                # Group by severity
                by_severity = {}
                for resource in resources:
                    severity = resource.get('severity', 'Info')
                    if severity not in by_severity:
                        by_severity[severity] = []
                    by_severity[severity].append(resource)
                
                # Print by severity
                for severity in ['Critical', 'High', 'Medium', 'Low', 'Info']:
                    if severity in by_severity:
                        severity_resources = by_severity[severity]
                        print(f"  {severity} ({len(severity_resources)}):")
                        
                        # Show first 5 resources of each severity
                        for i, resource in enumerate(severity_resources[:5]):
                            value = resource.get('value', '')
                            
                            # Use masked/formatted value if available
                            if resource.get('masked_value'):
                                display_value = resource['masked_value']
                            elif resource.get('formatted_value'):
                                display_value = resource['formatted_value']
                            else:
                                display_value = value[:60] + ('...' if len(value) > 60 else '')
                            
                            print(f"    • {resource.get('name', 'Unknown')}: {display_value}")
                        
                        if len(severity_resources) > 5:
                            print(f"    ... and {len(severity_resources) - 5} more")
        
        # Print general vulnerability summary
        if vulnerabilities:
            print(f"\nScan found {len(vulnerabilities)} vulnerabilities")
            sys.stdout.flush()
        
        print("="*80)
        sys.stdout.flush()
        
        # Ensure all output is written
        try:
            sys.stdout.flush()
            sys.stderr.flush()
        except:
            pass
    
    def _is_directory_listing_page(self, url: str) -> bool:
        """Check if URL appears to be a directory listing page"""
        try:
            from urllib.parse import urlparse
            parsed = urlparse(url)
            
            # Only skip URLs with Apache directory listing sorting parameters
            if parsed.query:
                query_upper = parsed.query.upper()
                # Be more specific - only skip if it's clearly Apache directory sorting
                apache_sort_patterns = PayloadLoader.load_patterns('apache_dir_sorting')
                if not apache_sort_patterns:
                    apache_sort_patterns = ['C=N;O=D', 'C=M;O=A', 'C=S;O=A', 'C=D;O=A']

                if any(pattern in query_upper for pattern in apache_sort_patterns):
                    return True
            
            # Don't skip directories automatically - they might have vulnerable apps
            return False
        except:
            return False
    
    def _contains_directory_listing(self, response_text: str) -> bool:
        """Check if response contains directory listing"""
        response_lower = response_text.lower()
        
        # Directory listing indicators - be more strict
        directory_indicators = PayloadLoader.load_indicators('dir_listing_basic')
        if not directory_indicators:
            directory_indicators = [
                'index of /', 'directory listing', 'parent directory',
                '<title>index of', '[to parent directory]', '<pre><a href="../">../</a>',
            ]
        
        # Apache-specific indicators
        apache_indicators = PayloadLoader.load_indicators('dir_listing_apache')
        if not apache_indicators:
            apache_indicators = [
                '<a href="?c=n;o=d">name</a>',
                '<a href="?c=m;o=a">last modified</a>',
                '<a href="?c=s;o=a">size</a>'
            ]
        
        # Count indicators found
        basic_indicators = sum(1 for indicator in directory_indicators 
                             if indicator in response_lower)
        apache_indicators_found = sum(1 for indicator in apache_indicators 
                                    if indicator in response_lower)
        
        # Only skip if we have strong evidence of directory listing
        # AND it's not an application (like XVWA)
        if basic_indicators >= 2 or apache_indicators_found >= 2:
            # Don't skip if response contains application indicators
            app_indicators = PayloadLoader.load_indicators('dir_listing_app')
            if not app_indicators:
                app_indicators = ['xvwa', 'login', 'vulnerabilities', 'bootstrap', 'jquery']
            has_app_content = any(indicator in response_lower for indicator in app_indicators)
            return not has_app_content
        
        return False
    
    def _print_vulnerability(self, index: int, result: Dict[str, Any], is_passive: bool = False):
        """Print single vulnerability details with safe encoding and enhanced metadata"""
        import sys
        
        def safe_print(text):
            """Safely print text, handling encoding issues"""
            try:
                # Ensure text is properly encoded for console output
                if isinstance(text, str):
                    print(text.encode('utf-8', 'replace').decode('utf-8', 'replace'))
                else:
                    print(str(text))
                sys.stdout.flush()  # Force flush after each line
            except (UnicodeEncodeError, UnicodeDecodeError):
                # Replace problematic characters with safe alternatives
                safe_text = str(text).encode('ascii', 'replace').decode('ascii')
                print(safe_text)
                sys.stdout.flush()
        
        analysis_type = "[PASSIVE]" if is_passive else "[ACTIVE]"
        icon = ''
        if result.get('module') == 'wafdetect':
            icon = '🛡️'
        elif result.get('module') == 'idor':
            icon = '🔑'
        
        safe_print(f"\n  {index}. {icon} {analysis_type} {result.get('vulnerability', 'Unknown')}".strip())
        safe_print(f"     Target: {result.get('target', '')}")
        safe_print(f"     Parameter: {result.get('parameter', '')}")
        safe_print(f"     Module: {result.get('module', '')}")
        if not is_passive:
            safe_print(f"     HTTP Method: {result.get('http_method', result.get('method', 'Unknown'))}")
        safe_print(f"     Detector: {result.get('detector', 'Unknown')}")
        
        payload = str(result.get('payload', ''))
        payload_display = payload[:100] + ('...' if len(payload) > 100 else '')
        safe_print(f"     Payload: {payload_display}")
        safe_print(f"     Request: {result.get('request_url', '')}")
        
        if result.get('icon') and ('waf' in result.get('module', '') or 'idor' in result.get('module', '')):
            safe_print(f"     Report Icon: <i class=\"{result.get('icon')}\"></i> (example for HTML report)")
        
        # Show response snippet if available
        response_snippet = result.get('response_snippet', '')
        if response_snippet:
            snippet_display = response_snippet[:80] + ('...' if len(response_snippet) > 80 else '')
            safe_print(f"     Response: ...{snippet_display}")
        
        safe_print(f"     Evidence: {result.get('evidence', '')}")
        safe_print("     " + "-"*50)
