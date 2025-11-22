"""
NoSQL Injection Scanner Module
Detects NoSQL injection vulnerabilities in MongoDB, CouchDB, and other NoSQL databases
"""

import json
from typing import List, Dict, Any
from core.base_module import BaseModule
from core.logger import get_logger

logger = get_logger(__name__)


class NoSQLModule(BaseModule):
    """NoSQL Injection vulnerability scanner"""

    def __init__(self, module_path: str, payload_limit: int = None):
        """Initialize NoSQL Injection module"""
        super().__init__(module_path, payload_limit=payload_limit)
        self.mongo_operators = ['$gt', '$ne', '$lt', '$regex', '$where', '$or', '$exists']
        logger.info(f"NoSQL Injection module loaded: {len(self.payloads)} payloads")

    def scan(self, targets: List[Dict[str, Any]], http_client: Any) -> List[Dict[str, Any]]:
        """Scan for NoSQL injection vulnerabilities"""
        results = []

        for target in targets:
            url = target.get('url')
            params = target.get('params', {})
            method = target.get('method', 'GET').upper()

            if not params:
                continue

            # Get baseline response
            try:
                if method == 'POST':
                    baseline = http_client.post(url, data=params)
                else:
                    baseline = http_client.get(url, params=params)
                baseline_len = len(baseline.text) if baseline else 0
            except Exception:
                continue

            for param_name in params:
                # Test URL parameter injection
                param_results = self._test_param_injection(
                    url, params, param_name, method, http_client, baseline_len
                )
                results.extend(param_results)

                # Test JSON body injection for POST
                if method == 'POST':
                    json_results = self._test_json_injection(
                        url, params, param_name, http_client, baseline_len
                    )
                    results.extend(json_results)

        return results

    def _test_param_injection(self, url, params, param_name, method, http_client, baseline_len):
        """Test parameter-based NoSQL injection"""
        results = []
        param_payloads = [
            f'{param_name}[$ne]=', f'{param_name}[$gt]=', f'{param_name}[$regex]=.*',
            '{"$ne":""}', '{"$gt":""}', '{"$regex":".*"}',
        ]

        for payload in param_payloads[:5]:  # Limit tests
            test_params = params.copy()
            if '[$' in payload:
                # Array notation: remove original param, add new
                test_params.pop(param_name, None)
                test_params[payload] = ''
            else:
                test_params[param_name] = payload

            try:
                if method == 'POST':
                    response = http_client.post(url, data=test_params)
                else:
                    response = http_client.get(url, params=test_params)

                if self._check_nosql_indicators(response, baseline_len):
                    results.append(self.create_result(
                        vulnerable=True,
                        url=url,
                        parameter=param_name,
                        payload=payload,
                        evidence=f"NoSQL operator injection detected with: {payload}",
                        severity='High',
                        method=method,
                        additional_info={
                            'injection_type': 'NoSQL Injection',
                            'cwe': 'CWE-943',
                            'owasp': 'A03:2021',
                            'cvss': 9.8
                        }
                    ))
                    break
            except Exception:
                continue

        return results

    def _test_json_injection(self, url, params, param_name, http_client, baseline_len):
        """Test JSON body NoSQL injection"""
        results = []
        json_payloads = [
            {'$ne': ''}, {'$gt': ''}, {'$regex': '.*'}, {'$exists': True},
        ]

        for payload in json_payloads:
            test_data = params.copy()
            test_data[param_name] = payload

            try:
                response = http_client.post(url, json=test_data)

                if self._check_nosql_indicators(response, baseline_len):
                    results.append(self.create_result(
                        vulnerable=True,
                        url=url,
                        parameter=param_name,
                        payload=json.dumps(payload),
                        evidence=f"JSON NoSQL injection: {json.dumps(payload)}",
                        severity='Critical',
                        method='POST',
                        additional_info={
                            'injection_type': 'NoSQL JSON Injection',
                            'cwe': 'CWE-943',
                            'owasp': 'A03:2021',
                            'cvss': 9.8
                        }
                    ))
                    break
            except Exception:
                continue

        return results

    def _check_nosql_indicators(self, response, baseline_len):
        """Check for NoSQL injection indicators"""
        if not response:
            return False

        text = response.text.lower()

        # Error indicators
        errors = ['mongodb', 'nosql', 'syntax error', 'objectid', 'bson',
                  'mongoclient', 'couchdb', 'document', 'collection']
        if any(err in text for err in errors):
            return True

        # Behavior change indicators
        if response.status_code == 200:
            # Significant response change
            if len(response.text) > baseline_len * 1.5:
                return True
            # Auth bypass indicators
            if any(s in text for s in ['welcome', 'dashboard', 'logged in', 'success']):
                return True

        return False


def get_module(module_path: str, payload_limit: int = None):
    """Factory function to create module instance"""
    return NoSQLModule(module_path, payload_limit)
