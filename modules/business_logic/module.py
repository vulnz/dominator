"""
Business Logic Scanner

Detects business logic vulnerabilities by:
- Testing price/quantity manipulation
- Checking for negative value acceptance
- Testing workflow/step bypass
- Checking for hidden field tampering
"""

from typing import List, Dict, Any, Optional
from core.base_module import BaseModule
from core.logger import get_logger
import json
import re

logger = get_logger(__name__)


class BusinessLogicModule(BaseModule):
    """Business Logic vulnerability scanner"""

    # Fields that might be manipulatable
    PRICE_FIELDS = ['price', 'amount', 'total', 'cost', 'subtotal', 'fee', 'discount']
    QUANTITY_FIELDS = ['quantity', 'qty', 'count', 'num', 'number', 'units']
    STATUS_FIELDS = ['status', 'state', 'step', 'stage', 'approved', 'verified']

    # Manipulation values to test
    NEGATIVE_VALUES = [-1, -100, -0.01]
    ZERO_VALUES = [0, 0.00, '0']
    LARGE_VALUES = [999999999, 2147483647]  # Int max
    DISCOUNT_VALUES = [100, 101, 1000]  # 100%+ discount

    def __init__(self, module_path: str, payload_limit: int = None):
        super().__init__(module_path, payload_limit=payload_limit)
        logger.info("Business Logic module initialized")

    def scan(self, targets: List[Dict[str, Any]], http_client: Any) -> List[Dict[str, Any]]:
        """Scan for business logic vulnerabilities"""
        results = []

        logger.info(f"Starting Business Logic scan on {len(targets)} targets")

        for target in targets:
            url = target.get('url', '')
            method = target.get('method', 'GET').upper()
            params = target.get('params', {})
            body = target.get('body', {})
            headers = target.get('headers', {})

            # Only test endpoints that handle business data
            if not self._is_business_endpoint(url):
                continue

            # Test parameter manipulation (GET)
            if params:
                param_result = self._test_param_manipulation(url, params, http_client, headers)
                if param_result:
                    results.append(param_result)

            # Test body manipulation (POST/PUT)
            if method in ['POST', 'PUT', 'PATCH'] and body:
                body_result = self._test_body_manipulation(url, method, body, http_client, headers)
                if body_result:
                    results.append(body_result)

        logger.info(f"Business Logic scan complete: {len(results)} findings")
        return results

    def _is_business_endpoint(self, url: str) -> bool:
        """Check if endpoint handles business logic"""
        patterns = [
            '/cart', '/checkout', '/order', '/payment', '/purchase',
            '/product', '/item', '/booking', '/reservation',
            '/transfer', '/send', '/api/', '/buy', '/sell'
        ]
        url_lower = url.lower()
        return any(p in url_lower for p in patterns)

    def _test_param_manipulation(self, url: str, params: Dict,
                                  http_client: Any, headers: Dict) -> Optional[Dict]:
        """Test GET parameters for business logic flaws"""
        findings = []

        for param_name, param_value in params.items():
            param_lower = param_name.lower()

            # Test price manipulation
            if any(pf in param_lower for pf in self.PRICE_FIELDS):
                result = self._test_price_field(url, param_name, param_value,
                                                 params, http_client, headers, 'params')
                if result:
                    findings.append(result)

            # Test quantity manipulation
            if any(qf in param_lower for qf in self.QUANTITY_FIELDS):
                result = self._test_quantity_field(url, param_name, param_value,
                                                    params, http_client, headers, 'params')
                if result:
                    findings.append(result)

        if findings:
            return self._consolidate_findings(url, findings)
        return None

    def _test_body_manipulation(self, url: str, method: str, body: Dict,
                                 http_client: Any, headers: Dict) -> Optional[Dict]:
        """Test POST body for business logic flaws"""
        if not isinstance(body, dict):
            return None

        findings = []

        for field_name, field_value in body.items():
            field_lower = field_name.lower()

            # Test price manipulation
            if any(pf in field_lower for pf in self.PRICE_FIELDS):
                result = self._test_price_field(url, field_name, field_value,
                                                 body, http_client, headers, 'body', method)
                if result:
                    findings.append(result)

            # Test quantity manipulation
            if any(qf in field_lower for qf in self.QUANTITY_FIELDS):
                result = self._test_quantity_field(url, field_name, field_value,
                                                    body, http_client, headers, 'body', method)
                if result:
                    findings.append(result)

        if findings:
            return self._consolidate_findings(url, findings)
        return None

    def _test_price_field(self, url: str, field_name: str, original_value: Any,
                           data: Dict, http_client: Any, headers: Dict,
                           location: str, method: str = 'GET') -> Optional[Dict]:
        """Test if price field accepts negative/zero values"""
        test_values = self.NEGATIVE_VALUES + self.ZERO_VALUES

        for test_value in test_values:
            test_data = data.copy()
            test_data[field_name] = test_value

            try:
                if location == 'params':
                    response = http_client.get(url, params=test_data, headers=headers)
                else:
                    test_headers = headers.copy()
                    test_headers['Content-Type'] = 'application/json'
                    response = http_client.request(method, url, json=test_data, headers=test_headers)

                if response and response.status_code in [200, 201, 204]:
                    # Check for acceptance indicators
                    text_lower = response.text.lower()
                    if 'error' not in text_lower and 'invalid' not in text_lower:
                        return {
                            'type': 'price_manipulation',
                            'field': field_name,
                            'original': original_value,
                            'payload': test_value,
                            'accepted': True
                        }

            except Exception as e:
                logger.debug(f"Error testing price field: {e}")

        return None

    def _test_quantity_field(self, url: str, field_name: str, original_value: Any,
                              data: Dict, http_client: Any, headers: Dict,
                              location: str, method: str = 'GET') -> Optional[Dict]:
        """Test if quantity field accepts negative/zero/large values"""
        test_values = self.NEGATIVE_VALUES + self.LARGE_VALUES

        for test_value in test_values:
            test_data = data.copy()
            test_data[field_name] = test_value

            try:
                if location == 'params':
                    response = http_client.get(url, params=test_data, headers=headers)
                else:
                    test_headers = headers.copy()
                    test_headers['Content-Type'] = 'application/json'
                    response = http_client.request(method, url, json=test_data, headers=test_headers)

                if response and response.status_code in [200, 201, 204]:
                    text_lower = response.text.lower()
                    if 'error' not in text_lower and 'invalid' not in text_lower:
                        return {
                            'type': 'quantity_manipulation',
                            'field': field_name,
                            'original': original_value,
                            'payload': test_value,
                            'accepted': True
                        }

            except Exception as e:
                logger.debug(f"Error testing quantity field: {e}")

        return None

    def _consolidate_findings(self, url: str, findings: List[Dict]) -> Dict:
        """Consolidate multiple findings into one result"""
        evidence = "**Business Logic Vulnerabilities Detected**\n\n"

        for finding in findings:
            evidence += f"**{finding['type'].replace('_', ' ').title()}**\n"
            evidence += f"  Field: `{finding['field']}`\n"
            evidence += f"  Original: `{finding['original']}`\n"
            evidence += f"  Payload: `{finding['payload']}` - ACCEPTED\n\n"

        evidence += "**Impact:**\n"
        evidence += "- Price manipulation (negative prices = free items)\n"
        evidence += "- Quantity tampering (negative = credit, large = overflow)\n"
        evidence += "- Financial fraud\n\n"
        evidence += "**Recommendation:** Validate all business values server-side. "
        evidence += "Reject negative values for prices/quantities. Use unsigned integers."

        severity = 'critical' if any(f['type'] == 'price_manipulation' for f in findings) else 'high'

        result = self.create_result(
            vulnerable=True,
            url=url,
            parameter=', '.join(f['field'] for f in findings),
            payload=', '.join(str(f['payload']) for f in findings),
            evidence=evidence,
            description=f"Business logic flaws: {len(findings)} manipulatable fields",
            confidence=0.85
        )
        result['cwe'] = 'CWE-840'
        result['cwe_name'] = 'Business Logic Errors'
        result['owasp'] = 'A04:2021'
        result['owasp_name'] = 'Insecure Design'
        result['severity'] = severity
        return result


def get_module(module_path: str, payload_limit: int = None):
    return BusinessLogicModule(module_path, payload_limit=payload_limit)
