"""
HTTP Parameter Pollution (HPP) Scanner
Detects HPP vulnerabilities with strong proof via differential response analysis

HPP occurs when the same parameter is sent multiple times and the backend
processes them differently than expected, potentially bypassing security controls.

Reference: https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/HTTP%20Parameter%20Pollution
"""

from core.base_module import BaseModule
from core.logger import get_logger
from typing import List, Dict, Any, Tuple
from urllib.parse import urlparse, parse_qs, urlencode, urljoin
import re
import hashlib

logger = get_logger(__name__)


class HPPScanner(BaseModule):
    """Scans for HTTP Parameter Pollution with differential response proof"""

    def __init__(self, module_path: str, payload_limit: int = None):
        super().__init__(module_path, payload_limit=payload_limit)
        self.module_name = "HPP Scanner"
        self.logger = logger

        # Server behaviors for duplicate parameters
        # Different servers handle duplicates differently
        self.server_behaviors = {
            'ASP.NET/IIS': 'All occurrences concatenated with comma',
            'PHP/Apache': 'Last occurrence wins',
            'JSP/Tomcat': 'First occurrence wins',
            'Python/Flask': 'First occurrence wins',
            'Python/Django': 'Last occurrence wins (QueryDict)',
            'Node.js/Express': 'Array of all values',
            'Ruby/Rails': 'Last occurrence wins',
            'Perl/CGI': 'First occurrence wins',
        }

        # Unique markers for detection
        self.marker_first = "HPP_FIRST_12345"
        self.marker_second = "HPP_SECOND_67890"
        self.marker_third = "HPP_THIRD_ABCDE"

    def scan(self, targets: List[Dict[str, Any]], http_client: Any = None) -> List[Dict[str, Any]]:
        """Scan for HPP vulnerabilities"""
        self.logger.info(f"Starting {self.module_name} scan on {len(targets)} targets")

        results = []
        tested = set()

        for target in targets:
            url = target.get('url') if isinstance(target, dict) else target
            params = target.get('params', {}) if isinstance(target, dict) else {}
            method = target.get('method', 'GET') if isinstance(target, dict) else 'GET'

            if not url or not params:
                continue

            # Test each parameter
            for param_name in params.keys():
                test_key = f"{url}:{param_name}:{method}"
                if test_key in tested:
                    continue
                tested.add(test_key)

                finding = self._test_hpp(http_client, url, param_name, params, method)
                if finding:
                    results.append(finding)

                if self.payload_limit and len(results) >= self.payload_limit:
                    break

        self.logger.info(f"{self.module_name} scan complete: {len(results)} findings")
        return results

    def _test_hpp(self, http_client, url: str, param_name: str,
                  params: dict, method: str) -> Dict[str, Any]:
        """Test a parameter for HPP vulnerability with strong proof"""

        original_value = params.get(param_name, 'test')

        # STAGE 1: Get baseline response with single parameter
        baseline_resp = self._send_request(http_client, url, params, method)
        if not baseline_resp:
            return None

        baseline_hash = self._hash_response(baseline_resp.text)

        # STAGE 2: Test duplicate parameters with different values
        # We'll use markers to prove which value the server uses
        hpp_tests = [
            # Test 1: Same param twice with markers
            {
                'type': 'duplicate',
                'params': self._build_hpp_params(params, param_name, [self.marker_first, self.marker_second]),
                'description': f'{param_name}={self.marker_first}&{param_name}={self.marker_second}'
            },
            # Test 2: Triple parameter
            {
                'type': 'triple',
                'params': self._build_hpp_params(params, param_name, [self.marker_first, self.marker_second, self.marker_third]),
                'description': f'{param_name}={self.marker_first}&{param_name}={self.marker_second}&{param_name}={self.marker_third}'
            },
            # Test 3: Empty + value (bypass validation)
            {
                'type': 'empty_bypass',
                'params': self._build_hpp_params(params, param_name, ['', self.marker_first]),
                'description': f'{param_name}=&{param_name}={self.marker_first}'
            },
            # Test 4: Array notation
            {
                'type': 'array',
                'params': self._build_array_params(params, param_name, [self.marker_first, self.marker_second]),
                'description': f'{param_name}[]={self.marker_first}&{param_name}[]={self.marker_second}'
            },
        ]

        for test in hpp_tests:
            result = self._execute_hpp_test(
                http_client, url, method, test, baseline_resp, baseline_hash, param_name, original_value
            )
            if result:
                return result

        return None

    def _execute_hpp_test(self, http_client, url: str, method: str, test: dict,
                          baseline_resp, baseline_hash: str, param_name: str,
                          original_value: str) -> Dict[str, Any]:
        """Execute a single HPP test and check for vulnerability"""

        hpp_resp = self._send_request(http_client, url, test['params'], method, raw_params=True)
        if not hpp_resp:
            return None

        hpp_hash = self._hash_response(hpp_resp.text)
        response_text = hpp_resp.text

        # Analyze which marker appears in response
        has_first = self.marker_first in response_text
        has_second = self.marker_second in response_text
        has_third = self.marker_third in response_text
        has_both_concat = f"{self.marker_first},{self.marker_second}" in response_text or \
                          f"{self.marker_first}{self.marker_second}" in response_text

        # Determine server behavior and if HPP is exploitable
        server_behavior = None
        is_vulnerable = False
        evidence_detail = ""

        if has_both_concat:
            server_behavior = "Concatenated (ASP.NET/IIS style)"
            is_vulnerable = True
            evidence_detail = f"Server concatenates values: Found both markers combined in response"
        elif has_first and has_second:
            server_behavior = "Both values processed"
            is_vulnerable = True
            evidence_detail = f"Server processes all occurrences: Both markers appear in response"
        elif has_first and not has_second:
            server_behavior = "First occurrence wins (JSP/Tomcat, Flask style)"
            is_vulnerable = True
            evidence_detail = f"First value used: '{self.marker_first}' appears, '{self.marker_second}' ignored"
        elif has_second and not has_first:
            server_behavior = "Last occurrence wins (PHP/Apache, Django style)"
            is_vulnerable = True
            evidence_detail = f"Last value used: '{self.marker_second}' appears, '{self.marker_first}' ignored"

        # Also check if response is different from baseline (indirect proof)
        if hpp_hash != baseline_hash and not is_vulnerable:
            # Response changed but markers not reflected - could still be HPP
            if test['type'] == 'empty_bypass':
                is_vulnerable = True
                server_behavior = "Validation bypass possible"
                evidence_detail = "Empty parameter + value caused different response (potential validation bypass)"

        if not is_vulnerable:
            return None

        # Strong proof: verify the behavior is consistent
        verify_resp = self._send_request(http_client, url, test['params'], method, raw_params=True)
        if verify_resp:
            verify_first = self.marker_first in verify_resp.text
            verify_second = self.marker_second in verify_resp.text
            # Behavior must be consistent
            if verify_first != has_first or verify_second != has_second:
                return None  # Inconsistent behavior, likely false positive

        # Calculate confidence based on strength of proof
        confidence = 0.70
        if has_first or has_second:
            confidence = 0.85  # Marker reflected
        if has_both_concat or (has_first and has_second):
            confidence = 0.95  # Strong proof

        return self.create_result(
            vulnerable=True,
            url=url,
            parameter=param_name,
            payload=test['description'],
            evidence=self._format_evidence(url, param_name, test, server_behavior, evidence_detail, response_text),
            severity='Medium',
            method=method,
            confidence=confidence,
            exploitation_steps=self._generate_exploit_steps(url, param_name, method, server_behavior, test),
            additional_info={
                'injection_type': 'HTTP Parameter Pollution',
                'hpp_type': test['type'],
                'server_behavior': server_behavior,
                'marker_first_found': has_first,
                'marker_second_found': has_second,
                'response_changed': hpp_hash != baseline_hash,
                'proof': evidence_detail,
                'cwe': 'CWE-235',
                'owasp': 'A03:2021',
                'impact': 'May bypass WAF, authentication, or authorization controls'
            }
        )

    def _build_hpp_params(self, original_params: dict, target_param: str, values: list) -> str:
        """Build query string with duplicate parameters"""
        parts = []
        for key, val in original_params.items():
            if key == target_param:
                for v in values:
                    parts.append(f"{key}={v}")
            else:
                parts.append(f"{key}={val}")
        return '&'.join(parts)

    def _build_array_params(self, original_params: dict, target_param: str, values: list) -> str:
        """Build query string with array notation"""
        parts = []
        for key, val in original_params.items():
            if key == target_param:
                for v in values:
                    parts.append(f"{key}[]={v}")
            else:
                parts.append(f"{key}={val}")
        return '&'.join(parts)

    def _send_request(self, http_client, url: str, params, method: str, raw_params: bool = False):
        """Send HTTP request"""
        try:
            if method.upper() == 'POST':
                if raw_params and isinstance(params, str):
                    # Send raw query string as body
                    headers = {'Content-Type': 'application/x-www-form-urlencoded'}
                    return http_client.post(url, data=params, headers=headers)
                return http_client.post(url, data=params)
            else:
                if raw_params and isinstance(params, str):
                    # Append raw query string to URL
                    separator = '&' if '?' in url else '?'
                    return http_client.get(f"{url}{separator}{params}")
                return http_client.get(url, params=params)
        except Exception as e:
            self.logger.debug(f"Request error: {e}")
            return None

    def _hash_response(self, text: str) -> str:
        """Hash response for comparison"""
        # Normalize response (remove dynamic content)
        normalized = re.sub(r'\d{10,}', '', text)  # Remove timestamps
        normalized = re.sub(r'[a-f0-9]{32}', '', normalized)  # Remove hashes
        return hashlib.md5(normalized.encode()).hexdigest()

    def _format_evidence(self, url: str, param: str, test: dict,
                         behavior: str, detail: str, response: str) -> str:
        """Format evidence for the finding"""
        evidence = f"""
{'═' * 60}
  HTTP Parameter Pollution CONFIRMED
{'═' * 60}

Target: {url}
Parameter: {param}
Test Type: {test['type']}

PROOF OF VULNERABILITY:
{'─' * 40}
Payload: {test['description']}

Server Behavior: {behavior}
{detail}

RESPONSE ANALYSIS:
{'─' * 40}"""

        # Show marker presence
        if self.marker_first in response:
            idx = response.find(self.marker_first)
            context = response[max(0, idx-30):idx+len(self.marker_first)+30]
            evidence += f"\n✓ First marker found at position {idx}:\n  ...{context}..."

        if self.marker_second in response:
            idx = response.find(self.marker_second)
            context = response[max(0, idx-30):idx+len(self.marker_second)+30]
            evidence += f"\n✓ Second marker found at position {idx}:\n  ...{context}..."

        evidence += f"""

{'═' * 60}
"""
        return evidence

    def _generate_exploit_steps(self, url: str, param: str, method: str,
                                 behavior: str, test: dict) -> List[str]:
        """Generate exploitation steps"""
        return [
            f"STEP 1: CONFIRM THE VULNERABILITY\n"
            f"──────────────────────────────────\n"
            f"Target: {url}\n"
            f"Parameter: {param}\n"
            f"Behavior: {behavior}\n\n"
            f"Replay this request:\n"
            f"curl -X {method} '{url}?{test['description']}'\n\n"
            f"Observe which value the server uses.",

            f"STEP 2: WAF/FILTER BYPASS\n"
            f"─────────────────────────\n"
            f"If a WAF blocks malicious values, try:\n\n"
            f"# Safe value first, malicious second (if last wins):\n"
            f"{param}=safe&{param}=<script>alert(1)</script>\n\n"
            f"# Malicious first, safe second (if first wins):\n"
            f"{param}=<script>alert(1)</script>&{param}=safe\n\n"
            f"The WAF may check one value while the app uses another.",

            f"STEP 3: AUTHENTICATION BYPASS\n"
            f"─────────────────────────────\n"
            f"If this is an auth parameter (user, id, role):\n\n"
            f"# Elevate privileges:\n"
            f"user=victim&user=admin\n"
            f"role=user&role=admin\n"
            f"id=123&id=456\n\n"
            f"Different parts of the app may use different values.",

            f"STEP 4: BUSINESS LOGIC ABUSE\n"
            f"────────────────────────────\n"
            f"For price/quantity parameters:\n\n"
            f"# Validation vs processing difference:\n"
            f"price=100&price=-1\n"
            f"quantity=1&quantity=999\n"
            f"discount=0&discount=100\n\n"
            f"Validation may check first value, processing uses second.",

            f"STEP 5: SSRF/REDIRECT EXPLOITATION\n"
            f"──────────────────────────────────\n"
            f"For URL parameters:\n\n"
            f"# Bypass URL validation:\n"
            f"url=https://safe.com&url=http://internal.server\n"
            f"redirect=https://example.com&redirect=http://attacker.com\n\n"
            f"Validator may whitelist first URL, redirect uses second.",

            f"AUTOMATION TOOLS\n"
            f"────────────────\n"
            f"• Burp Suite: Param Miner extension\n"
            f"• OWASP ZAP: Active scanner includes HPP\n"
            f"• Arjun: python3 arjun -u {url} --stable\n"
            f"• Manual: Repeat with different value orders"
        ]


def get_module(module_path: str, payload_limit: int = None):
    """Factory function to create module instance"""
    return HPPScanner(module_path, payload_limit=payload_limit)
