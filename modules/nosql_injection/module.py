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

                indicator, behavior_change = self._check_nosql_indicators(response, baseline_len)
                if indicator or behavior_change:
                    # Build detailed evidence with actual proof
                    evidence_parts = [
                        "**NoSQL Injection Confirmed**\n",
                        f"**Parameter:** {param_name}",
                        f"**Injected Payload:** `{payload}`",
                        f"**Method:** {method}",
                        f"\n**Detection Method:**"
                    ]

                    if indicator:
                        evidence_parts.append(f"- NoSQL error/keyword found: `{indicator}`")
                    if behavior_change:
                        evidence_parts.append(f"- Response length changed: {baseline_len} → {len(response.text)} bytes")

                    # Add response context
                    response_preview = response.text[:500] if response.text else "No response"
                    evidence_parts.append(f"\n**Response Preview:**\n```\n{response_preview}\n```")

                    results.append(self.create_result(
                        vulnerable=True,
                        url=url,
                        parameter=param_name,
                        payload=payload,
                        evidence='\n'.join(evidence_parts),
                        severity='High',
                        method=method,
                        response=response.text[:3000] if response.text else '',
                        additional_info={
                            'injection_type': 'NoSQL Injection',
                            'cwe': 'CWE-943',
                            'owasp': 'A03:2021',
                            'cvss': 9.8,
                            'indicator_found': indicator,
                            'baseline_length': baseline_len,
                            'response_length': len(response.text) if response.text else 0
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

                indicator, behavior_change = self._check_nosql_indicators(response, baseline_len)
                if indicator or behavior_change:
                    # Build detailed evidence
                    evidence_parts = [
                        "**NoSQL JSON Injection Confirmed**\n",
                        f"**Parameter:** {param_name}",
                        f"**Injected JSON Payload:** `{json.dumps(payload)}`",
                        f"**Method:** POST (JSON Body)",
                        f"\n**Detection Method:**"
                    ]

                    if indicator:
                        evidence_parts.append(f"- NoSQL indicator found: `{indicator}`")
                    if behavior_change:
                        evidence_parts.append(f"- Response length changed: {baseline_len} → {len(response.text)} bytes")

                    response_preview = response.text[:500] if response.text else "No response"
                    evidence_parts.append(f"\n**Response Preview:**\n```\n{response_preview}\n```")

                    results.append(self.create_result(
                        vulnerable=True,
                        url=url,
                        parameter=param_name,
                        payload=json.dumps(payload),
                        evidence='\n'.join(evidence_parts),
                        severity='Critical',
                        method='POST',
                        response=response.text[:3000] if response.text else '',
                        additional_info={
                            'injection_type': 'NoSQL JSON Injection',
                            'cwe': 'CWE-943',
                            'owasp': 'A03:2021',
                            'cvss': 9.8,
                            'indicator_found': indicator
                        }
                    ))
                    break
            except Exception:
                continue

        return results

    # Class-level constants for indicator checking
    # More specific error patterns to reduce false positives
    _NOSQL_ERRORS = {
        'mongoerror', 'bsonerror', 'casterror', 'validationerror',
        'objectid', 'mongoclient', 'bson.errors', 'pymongo.errors',
        'cannot convert', 'cast to objectid failed', 'invalid objectid',
        'e11000 duplicate key', 'writeconflict', 'notmaster'
    }
    # Only trigger on SIGNIFICANT behavior changes (authentication bypass)
    _BYPASS_INDICATORS = {'logged in as', 'welcome back', 'dashboard', 'admin panel'}

    def _check_nosql_indicators(self, response, baseline_len):
        """Check for NoSQL injection indicators - STRICT validation to avoid false positives"""
        if not response:
            return None, False

        text = response.text.lower()

        # Check for specific NoSQL error messages
        indicator_found = None
        for err in self._NOSQL_ERRORS:
            if err in text:
                indicator_found = err
                break

        # Behavior change detection - MUCH stricter
        # Must be at least 2x longer AND contain new significant content
        behavior_change = False
        if response.status_code == 200 and len(response.text) > baseline_len * 2:
            # Only flag as behavior change if we see auth bypass indicators
            for ind in self._BYPASS_INDICATORS:
                if ind in text:
                    indicator_found = indicator_found or f"auth_bypass:{ind}"
                    behavior_change = True
                    break

        # Require BOTH indicator AND significant change for non-error detection
        # Error messages alone are sufficient proof
        if indicator_found and 'error' in indicator_found.lower():
            return indicator_found, True

        # For non-error indicators, require actual behavior change
        if indicator_found and behavior_change:
            return indicator_found, behavior_change

        # Just response length change is NOT enough - too many false positives
        return indicator_found, False


def get_module(module_path: str, payload_limit: int = None):
    """Factory function to create module instance"""
    return NoSQLModule(module_path, payload_limit)
