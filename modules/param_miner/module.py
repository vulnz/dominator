"""
Parameter Miner Module
Discovers hidden parameters using wordlists and response analysis
"""

import re
from typing import Dict, List, Any, Optional
from urllib.parse import urlparse, parse_qs, urlencode
from core.base_module import BaseModule


class Module(BaseModule):
    """Hidden parameter discovery scanner"""

    def __init__(self, http_client=None, config: Optional[Dict] = None):
        super().__init__(http_client, config)
        self.name = "Parameter Miner"
        self.description = "Discovers hidden parameters"
        self.params_wordlist = []
        self.max_params_to_test = 100  # Limit for efficiency

    def load_payloads(self) -> List[str]:
        """Load parameter wordlist"""
        params = []
        try:
            import os
            payload_file = os.path.join(os.path.dirname(__file__), 'payloads.txt')
            if os.path.exists(payload_file):
                with open(payload_file, 'r', encoding='utf-8') as f:
                    for line in f:
                        line = line.strip()
                        if line and not line.startswith('#'):
                            params.append(line)
        except Exception:
            pass

        if not params:
            params = ['id', 'page', 'search', 'q', 'debug', 'admin', 'test', 'token', 'callback']

        self.params_wordlist = params[:self.max_params_to_test]
        return self.params_wordlist

    def run(self, target: str, params: Optional[Dict] = None) -> List[Dict[str, Any]]:
        """Run parameter discovery"""
        results = []
        self.load_payloads()

        parsed = urlparse(target)
        base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
        existing_params = parse_qs(parsed.query)

        # Get baseline response
        try:
            baseline = self.http_client.get(target)
            if not baseline:
                return results
            baseline_length = len(baseline.text)
            baseline_words = set(baseline.text.split())
        except Exception:
            return results

        discovered_params = []

        # Test parameters in batches for efficiency
        batch_size = 10
        test_value = 'dominator_test_value_12345'

        for i in range(0, len(self.params_wordlist), batch_size):
            batch = self.params_wordlist[i:i + batch_size]

            for param in batch:
                # Skip if parameter already exists
                if param in existing_params:
                    continue

                result = self._test_parameter(base_url, existing_params, param, test_value, baseline_length, baseline_words)
                if result:
                    discovered_params.append(result)

        # Report findings
        if discovered_params:
            results.append({
                'vulnerability': True,
                'type': 'Hidden Parameters Discovered',
                'severity': 'Info',
                'url': target,
                'parameter': ', '.join([p['name'] for p in discovered_params]),
                'payload': 'Parameter wordlist scan',
                'method': 'GET',
                'injection_type': 'Parameter Discovery',
                'evidence': f"Found {len(discovered_params)} hidden parameters",
                'discovered_params': discovered_params,
                'description': f"Discovered {len(discovered_params)} hidden/undocumented parameters that affect application behavior.",
                'recommendation': 'Review discovered parameters for security implications. Hidden parameters may expose debug features, admin functions, or security bypasses.',
                'cwe': 'CWE-200',
                'owasp': 'A01:2021',
                'cvss': 3.7,
                'response': str([p['name'] for p in discovered_params])
            })

            # Check for high-value parameters
            high_value = ['debug', 'admin', 'test', 'dev', 'config', 'password', 'token', 'secret', 'api_key']
            for param_info in discovered_params:
                if param_info['name'] in high_value:
                    results.append({
                        'vulnerability': True,
                        'type': 'Sensitive Hidden Parameter',
                        'severity': 'Medium',
                        'url': target,
                        'parameter': param_info['name'],
                        'payload': test_value,
                        'method': 'GET',
                        'injection_type': 'Sensitive Parameter Exposure',
                        'evidence': f"High-value parameter '{param_info['name']}' discovered. Response diff: {param_info.get('diff_type', 'unknown')}",
                        'description': f"Sensitive hidden parameter '{param_info['name']}' found. May expose debug info, admin features, or credentials.",
                        'recommendation': 'Remove or properly secure debug/admin parameters in production.',
                        'cwe': 'CWE-200',
                        'owasp': 'A01:2021',
                        'cvss': 5.3,
                        'response': param_info.get('response_snippet', '')
                    })

        return results

    def _test_parameter(self, base_url: str, existing_params: Dict, param: str, value: str, baseline_length: int, baseline_words: set) -> Optional[Dict]:
        """Test if a parameter affects the response"""
        try:
            # Build URL with new parameter
            test_params = {k: v[0] for k, v in existing_params.items()}
            test_params[param] = value
            test_url = f"{base_url}?{urlencode(test_params)}"

            response = self.http_client.get(test_url)
            if not response:
                return None

            # Compare with baseline
            response_length = len(response.text)
            response_words = set(response.text.split())

            # Check for significant differences
            diff_type = None

            # Length difference
            length_diff = abs(response_length - baseline_length)
            if length_diff > 50:  # More than 50 chars difference
                diff_type = 'length_change'

            # New words in response
            new_words = response_words - baseline_words
            if len(new_words) > 5:
                diff_type = 'content_change'

            # Check if parameter value is reflected
            if value in response.text:
                diff_type = 'value_reflected'

            # Check for error messages triggered by parameter
            error_patterns = [
                r'invalid\s+param', r'unknown\s+param', r'error', r'exception',
                r'debug', r'stack\s*trace', r'warning'
            ]
            for pattern in error_patterns:
                if re.search(pattern, response.text, re.IGNORECASE):
                    if pattern not in str(baseline_words):
                        diff_type = 'error_triggered'
                        break

            if diff_type:
                return {
                    'name': param,
                    'diff_type': diff_type,
                    'length_diff': length_diff,
                    'response_snippet': response.text[:200] if diff_type != 'length_change' else ''
                }

        except Exception:
            pass

        return None
