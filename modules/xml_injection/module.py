"""
XML Injection Scanner Module

Detects XML injection vulnerabilities where user input is incorporated
into XML documents without proper validation, allowing manipulation
of XML structure, data, and potentially leading to data exfiltration.

Note: This is different from XXE (XML External Entity) attacks.
"""

from typing import List, Dict, Any
from core.base_module import BaseModule
from core.logger import get_logger
import re
import random
import string

logger = get_logger(__name__)


class XMLInjectionModule(BaseModule):
    """XML Injection Scanner Module"""

    def __init__(self, module_path: str, payload_limit: int = None):
        """Initialize XML Injection module"""
        super().__init__(module_path, payload_limit=payload_limit)

        # Generate unique marker
        self.marker = ''.join(random.choices(string.ascii_lowercase, k=8))

        # XML Injection payloads
        self.xml_payloads = [
            # Basic XML element injection
            {
                'payload': f'<inj_{self.marker}>test</inj_{self.marker}>',
                'detect': f'<inj_{self.marker}>',
                'description': 'Direct XML element injection'
            },
            # Self-closing tag
            {
                'payload': f'<inj_{self.marker}/>',
                'detect': f'<inj_{self.marker}',
                'description': 'Self-closing XML tag injection'
            },
            # Attribute injection
            {
                'payload': f'" attr_{self.marker}="injected',
                'detect': f'attr_{self.marker}',
                'description': 'XML attribute injection'
            },
            # CDATA breakout
            {
                'payload': f']]><inj_{self.marker}>x</inj_{self.marker}><![CDATA[',
                'detect': f'<inj_{self.marker}>',
                'description': 'CDATA section breakout'
            },
            # Comment breakout
            {
                'payload': f'--><inj_{self.marker}>x</inj_{self.marker}><!--',
                'detect': f'<inj_{self.marker}>',
                'description': 'XML comment breakout'
            },
            # Node structure manipulation
            {
                'payload': f'</node><inj_{self.marker}>x</inj_{self.marker}><node>',
                'detect': f'<inj_{self.marker}>',
                'description': 'XML node structure manipulation'
            },
        ]

        logger.info(f"XML Injection module loaded: {len(self.xml_payloads)} payloads")

    def scan(self, targets: List[Dict[str, Any]], http_client: Any) -> List[Dict[str, Any]]:
        """
        Scan for XML injection vulnerabilities

        Args:
            targets: List of URLs with parameters
            http_client: HTTP client

        Returns:
            List of vulnerability results
        """
        results = []

        logger.info(f"Starting XML Injection scan on {len(targets)} targets")

        for target in targets:
            url = target.get('url')
            params = target.get('params', {})
            method = target.get('method', 'GET').upper()

            if not params:
                continue

            # Get baseline
            try:
                if method == 'POST':
                    baseline_response = http_client.post(url, data=params)
                else:
                    baseline_response = http_client.get(url, params=params)

                baseline_text = getattr(baseline_response, 'text', '') if baseline_response else ''
            except:
                baseline_text = ''

            for param_name in params:
                if self.should_stop():
                    return results

                for payload_info in self.xml_payloads:
                    payload = payload_info['payload']
                    detect_pattern = payload_info['detect']
                    description = payload_info['description']

                    try:
                        test_params = params.copy()
                        test_params[param_name] = payload

                        if method == 'POST':
                            response = http_client.post(url, data=test_params)
                        else:
                            response = http_client.get(url, params=test_params)

                        if not response:
                            continue

                        response_text = getattr(response, 'text', '')

                        # Check for injection
                        if detect_pattern not in response_text:
                            continue

                        # FALSE POSITIVE: Not in baseline
                        if detect_pattern in baseline_text:
                            continue

                        # Check if XML context
                        content_type = response.headers.get('Content-Type', '').lower() if hasattr(response, 'headers') else ''
                        is_xml = 'xml' in content_type or response_text.strip().startswith('<?xml')

                        severity = 'High' if is_xml else 'Medium'
                        confidence = 0.90 if is_xml else 0.75

                        evidence = self._build_evidence(url, param_name, payload, detect_pattern, response_text, is_xml)

                        result = self.create_result(
                            vulnerable=True,
                            url=url,
                            parameter=param_name,
                            payload=payload,
                            evidence=evidence,
                            description=f"XML Injection: {description}. User input modifies XML structure without proper encoding.",
                            confidence=confidence,
                            severity=severity,
                            method=method,
                            response=response_text[:2000]
                        )

                        result['is_xml_context'] = is_xml
                        result['verified'] = True
                        results.append(result)
                        logger.info(f"✓ XML Injection found: {description} in {param_name}")
                        break

                    except Exception as e:
                        logger.debug(f"Error testing XML injection: {e}")
                        continue

        logger.info(f"XML Injection scan complete: {len(results)} vulnerabilities found")
        return results

    def _build_evidence(self, url: str, param: str, payload: str, detect: str, response: str, is_xml: bool) -> str:
        """Build evidence string"""
        context = self.extract_response_context(response, detect, 150, 100)

        return f"""XML Injection Confirmed

**URL:** {url}
**Parameter:** {param}
**XML Context:** {'Yes' if is_xml else 'Possible'}

**Payload:**
{payload}

**Injected Pattern Found:**
{detect}

**Response Context:**
{context}

**Impact:**
- XML structure manipulation
- Data exfiltration via node injection
- Authentication bypass via attribute injection
- Denial of service via malformed XML
"""


def get_module(module_path: str, payload_limit: int = None):
    """Create module instance"""
    return XMLInjectionModule(module_path, payload_limit=payload_limit)
