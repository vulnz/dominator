"""
CGI Scripts Vulnerability Scanner
Discovers and tests common CGI scripts for vulnerabilities and information disclosure
"""

from core.base_module import BaseModule
from core.logger import get_logger
from typing import List, Dict, Any
from urllib.parse import urljoin, urlparse
import re

logger = get_logger(__name__)


class CGIScanner(BaseModule):
    """Scans for vulnerable and exposed CGI scripts"""

    def __init__(self, module_path: str, payload_limit: int = None):
        super().__init__(module_path, payload_limit=payload_limit)
        self.module_name = "CGI Scanner"
        self.logger = logger

        # Vulnerable CGI patterns and their risks
        self.vulnerable_cgis = {
            # Information Disclosure
            'printenv': {'risk': 'High', 'type': 'info_disclosure', 'desc': 'Exposes server environment variables'},
            'test-cgi': {'risk': 'Medium', 'type': 'info_disclosure', 'desc': 'Apache test CGI script'},
            'php-cgi': {'risk': 'Critical', 'type': 'rce', 'desc': 'PHP CGI may allow argument injection (CVE-2012-1823)'},
            'php.cgi': {'risk': 'Critical', 'type': 'rce', 'desc': 'PHP CGI script exposure'},
            'php4': {'risk': 'High', 'type': 'outdated', 'desc': 'Outdated PHP4 CGI'},
            'php5': {'risk': 'Medium', 'type': 'info_disclosure', 'desc': 'PHP5 CGI endpoint'},

            # Classic Vulnerable CGIs
            'awstats.pl': {'risk': 'High', 'type': 'rce', 'desc': 'AWStats - multiple vulnerabilities'},
            'cgiwrap': {'risk': 'Medium', 'type': 'info_disclosure', 'desc': 'CGIWrap wrapper script'},
            'Count.cgi': {'risk': 'Medium', 'type': 'overflow', 'desc': 'WWWCount buffer overflow'},
            'finger': {'risk': 'High', 'type': 'info_disclosure', 'desc': 'Finger gateway - user enumeration'},
            'glimpse': {'risk': 'Critical', 'type': 'rce', 'desc': 'Glimpse HTTP search - command injection'},
            'handler': {'risk': 'Medium', 'type': 'info_disclosure', 'desc': 'Handler script'},
            'htmlscript': {'risk': 'High', 'type': 'rce', 'desc': 'HTMLscript - command execution'},
            'info2www': {'risk': 'High', 'type': 'rce', 'desc': 'Info2www - command injection'},
            'nph-test-cgi': {'risk': 'Medium', 'type': 'info_disclosure', 'desc': 'Non-parsed header test CGI'},
            'perl': {'risk': 'Critical', 'type': 'rce', 'desc': 'Direct Perl interpreter access'},
            'perl.exe': {'risk': 'Critical', 'type': 'rce', 'desc': 'Direct Perl interpreter access (Windows)'},
            'perlshop.cgi': {'risk': 'High', 'type': 'rce', 'desc': 'PerlShop vulnerabilities'},
            'phf': {'risk': 'Critical', 'type': 'rce', 'desc': 'PHF phone book - classic command injection'},
            'php-cgi': {'risk': 'Critical', 'type': 'rce', 'desc': 'PHP CGI argument injection'},
            'rguest.exe': {'risk': 'High', 'type': 'overflow', 'desc': 'Ranson guestbook overflow'},
            'rwwwshell.pl': {'risk': 'Critical', 'type': 'backdoor', 'desc': 'Remote WWW shell - backdoor'},
            'test.cgi': {'risk': 'Medium', 'type': 'info_disclosure', 'desc': 'Test CGI script'},
            'textcounter.pl': {'risk': 'High', 'type': 'rce', 'desc': 'TextCounter arbitrary file read'},
            'view-source': {'risk': 'High', 'type': 'info_disclosure', 'desc': 'View source CGI'},
            'webdist.cgi': {'risk': 'Critical', 'type': 'rce', 'desc': 'IRIX webdist - command execution'},
            'webgais': {'risk': 'High', 'type': 'rce', 'desc': 'WebGAIS search - command injection'},
            'websendmail': {'risk': 'High', 'type': 'rce', 'desc': 'WebSendMail - mail relay/injection'},
            'wrap': {'risk': 'Medium', 'type': 'info_disclosure', 'desc': 'Wrap CGI script'},

            # Form handlers
            'FormHandler.cgi': {'risk': 'High', 'type': 'rce', 'desc': 'FormHandler - command injection'},
            'FormMail': {'risk': 'High', 'type': 'spam', 'desc': 'FormMail - spam relay'},
            'FormMail.pl': {'risk': 'High', 'type': 'spam', 'desc': 'FormMail Perl - spam relay'},
            'formmail.pl': {'risk': 'High', 'type': 'spam', 'desc': 'FormMail - spam relay'},

            # Admin/Config CGIs
            'admin.pl': {'risk': 'High', 'type': 'admin', 'desc': 'Admin script exposure'},
            'admin.cgi': {'risk': 'High', 'type': 'admin', 'desc': 'Admin CGI exposure'},
            'administrator.cgi': {'risk': 'High', 'type': 'admin', 'desc': 'Administrator CGI'},
            'setup.cgi': {'risk': 'High', 'type': 'admin', 'desc': 'Setup/config CGI'},
            'config.cgi': {'risk': 'High', 'type': 'config', 'desc': 'Configuration CGI'},

            # Database CGIs
            'dbman': {'risk': 'Critical', 'type': 'sqli', 'desc': 'DBMan database manager'},
            'mysql.cgi': {'risk': 'Critical', 'type': 'sqli', 'desc': 'MySQL CGI interface'},
            'oracle': {'risk': 'Critical', 'type': 'sqli', 'desc': 'Oracle CGI interface'},

            # Shell/Command CGIs
            'shell.cgi': {'risk': 'Critical', 'type': 'backdoor', 'desc': 'Shell CGI - likely backdoor'},
            'cmd.cgi': {'risk': 'Critical', 'type': 'backdoor', 'desc': 'Command CGI - backdoor'},
            'cmd.exe': {'risk': 'Critical', 'type': 'backdoor', 'desc': 'Windows command execution'},
            'command.cgi': {'risk': 'Critical', 'type': 'backdoor', 'desc': 'Command CGI'},
            'bash': {'risk': 'Critical', 'type': 'rce', 'desc': 'Direct bash access'},
            'sh': {'risk': 'Critical', 'type': 'rce', 'desc': 'Direct shell access'},
        }

    def scan(self, targets: List[Dict[str, Any]], http_client: Any = None) -> List[Dict[str, Any]]:
        """Scan for vulnerable CGI scripts"""
        self.logger.info(f"Starting {self.module_name} scan on {len(targets)} targets")

        results = []
        tested_bases = set()

        for target in targets:
            url = target.get('url') if isinstance(target, dict) else target
            if not url:
                continue

            # Get base URL
            parsed = urlparse(url)
            base_url = f"{parsed.scheme}://{parsed.netloc}"

            if base_url in tested_bases:
                continue
            tested_bases.add(base_url)

            # Test CGI directories
            cgi_dirs = ['/cgi-bin/', '/cgi/', '/cgi-local/', '/cgi-win/', '/fcgi-bin/',
                        '/cgi-sys/', '/cgis/', '/cgi-mod/', '/cgi-home/', '/htbin/']

            for cgi_dir in cgi_dirs:
                # First check if CGI directory exists
                dir_url = urljoin(base_url, cgi_dir)
                dir_response = http_client.get(dir_url)

                if not dir_response:
                    continue

                # Directory exists (not 404)
                if dir_response.status_code not in [404, 400]:
                    # Test each vulnerable CGI
                    for cgi_name, cgi_info in self.vulnerable_cgis.items():
                        if self.payload_limit and len(results) >= self.payload_limit:
                            break

                        cgi_url = urljoin(dir_url, cgi_name)
                        finding = self._test_cgi(http_client, cgi_url, cgi_name, cgi_info, base_url)
                        if finding:
                            results.append(finding)

        self.logger.info(f"{self.module_name} scan complete: {len(results)} findings")
        return results

    def _test_cgi(self, http_client, cgi_url: str, cgi_name: str, cgi_info: dict, base_url: str) -> Dict[str, Any]:
        """Test a specific CGI script"""
        try:
            response = http_client.get(cgi_url)
            if not response:
                return None

            # Skip 404s and common error pages
            if response.status_code == 404:
                return None

            # Check for actual CGI response
            is_vulnerable = False
            evidence = ""
            severity = cgi_info['risk']

            if response.status_code == 200:
                content = response.text.lower()

                # Check for signs of CGI execution
                cgi_indicators = [
                    'content-type:', 'cgi', 'environment', 'server_name',
                    'document_root', 'script_name', 'query_string',
                    'remote_addr', 'http_host', 'server_software'
                ]

                for indicator in cgi_indicators:
                    if indicator in content:
                        is_vulnerable = True
                        evidence = f"CGI script accessible, contains '{indicator}'"
                        break

                # Special checks for known vulnerable CGIs
                if 'printenv' in cgi_name and 'server_name' in content:
                    is_vulnerable = True
                    evidence = "printenv CGI exposes environment variables"
                    severity = 'High'
                elif 'phf' in cgi_name:
                    is_vulnerable = True
                    evidence = "PHF phonebook CGI found - classic command injection vector"
                    severity = 'Critical'
                elif 'test-cgi' in cgi_name or 'test.cgi' in cgi_name:
                    is_vulnerable = True
                    evidence = "Test CGI script found - may expose server information"
                elif any(shell in cgi_name for shell in ['shell', 'cmd', 'bash', 'command']):
                    is_vulnerable = True
                    evidence = "Potential shell/command CGI found - possible backdoor"
                    severity = 'Critical'

                # If 200 but no specific indicator, still report as info
                if not is_vulnerable and response.status_code == 200:
                    is_vulnerable = True
                    evidence = f"CGI script accessible (HTTP 200, {len(response.text)} bytes)"
                    severity = 'Info' if cgi_info['risk'] == 'Medium' else cgi_info['risk']

            elif response.status_code == 500:
                # 500 error might indicate CGI exists but has issues
                is_vulnerable = True
                evidence = "CGI script exists but returns 500 error (may be misconfigured)"
                severity = 'Low'

            elif response.status_code == 403:
                # Forbidden but exists
                is_vulnerable = True
                evidence = "CGI script exists but access forbidden (403)"
                severity = 'Info'

            if is_vulnerable:
                return self.create_result(
                    vulnerable=True,
                    url=cgi_url,
                    parameter='CGI Script',
                    payload=cgi_name,
                    evidence=evidence,
                    severity=severity,
                    method='GET',
                    additional_info={
                        'injection_type': f'CGI {cgi_info["type"].upper()}',
                        'cgi_name': cgi_name,
                        'cgi_type': cgi_info['type'],
                        'description': cgi_info['desc'],
                        'status_code': response.status_code,
                        'cwe': self._get_cwe(cgi_info['type']),
                        'owasp': 'A05:2021',
                        'cvss': self._get_cvss(severity)
                    }
                )

        except Exception as e:
            self.logger.debug(f"Error testing CGI {cgi_url}: {e}")

        return None

    def _get_cwe(self, cgi_type: str) -> str:
        """Get CWE for CGI vulnerability type"""
        cwe_map = {
            'rce': 'CWE-78',  # OS Command Injection
            'info_disclosure': 'CWE-200',  # Information Exposure
            'backdoor': 'CWE-506',  # Embedded Malicious Code
            'sqli': 'CWE-89',  # SQL Injection
            'overflow': 'CWE-120',  # Buffer Overflow
            'spam': 'CWE-20',  # Improper Input Validation
            'admin': 'CWE-284',  # Improper Access Control
            'config': 'CWE-16',  # Configuration
            'outdated': 'CWE-1104',  # Use of Unmaintained Third Party Components
        }
        return cwe_map.get(cgi_type, 'CWE-200')

    def _get_cvss(self, severity: str) -> float:
        """Get CVSS score for severity"""
        cvss_map = {
            'Critical': 9.8,
            'High': 7.5,
            'Medium': 5.3,
            'Low': 3.1,
            'Info': 0.0
        }
        return cvss_map.get(severity, 5.0)


def get_module(module_path: str, payload_limit: int = None):
    """Factory function to create module instance"""
    return CGIScanner(module_path, payload_limit=payload_limit)
