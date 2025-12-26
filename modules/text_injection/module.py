"""
Text Injection Scanner Module

Detects text/content injection vulnerabilities where user input is reflected
in the response without proper validation, allowing manipulation of displayed content.
This includes content spoofing and text manipulation attacks.
"""

from typing import List, Dict, Any
from core.base_module import BaseModule
from core.logger import get_logger
import re
import random
import string

logger = get_logger(__name__)


class TextInjectionModule(BaseModule):
    """Text Injection Scanner Module"""

    def __init__(self, module_path: str, payload_limit: int = None):
        """Initialize Text Injection module"""
        super().__init__(module_path, payload_limit=payload_limit)

        # Generate unique markers for detection (prevents false positives)
        self.marker = ''.join(random.choices(string.ascii_lowercase, k=10))

        # Text injection payloads
        self.text_payloads = [
            # Basic text reflection
            {
                'payload': f'INJECTED_{self.marker}_TEXT',
                'detect': f'INJECTED_{self.marker}_TEXT',
                'description': 'Direct text reflection'
            },
            # Fake error/success messages (social engineering)
            {
                'payload': f'Error: Access Denied [{self.marker}]',
                'detect': f'Error: Access Denied [{self.marker}]',
                'description': 'Fake error message injection'
            },
            {
                'payload': f'Success! Payment confirmed [{self.marker}]',
                'detect': f'Payment confirmed [{self.marker}]',
                'description': 'Fake success message injection'
            },
            # Email/URL spoofing
            {
                'payload': f'admin@{self.marker}.com',
                'detect': f'admin@{self.marker}.com',
                'description': 'Email address injection'
            },
            {
                'payload': f'https://{self.marker}.evil.com',
                'detect': f'{self.marker}.evil.com',
                'description': 'URL injection in text'
            },
            # Price manipulation
            {
                'payload': f'$0.01_{self.marker}',
                'detect': f'$0.01_{self.marker}',
                'description': 'Price/currency injection'
            },
            # Delimiter injection
            {
                'payload': f'item1,{self.marker},item3',
                'detect': f',{self.marker},',
                'description': 'CSV delimiter injection'
            },
        ]

        logger.info(f"Text Injection module loaded: {len(self.text_payloads)} payloads")

    def scan(self, targets: List[Dict[str, Any]], http_client: Any) -> List[Dict[str, Any]]:
        """
        Scan for text injection vulnerabilities

        Args:
            targets: List of URLs with parameters
            http_client: HTTP client

        Returns:
            List of vulnerability results
        """
        results = []

        logger.info(f"Starting Text Injection scan on {len(targets)} targets")

        for target in targets:
            url = target.get('url')
            params = target.get('params', {})
            method = target.get('method', 'GET').upper()

            if not params:
                continue

            # Get baseline response
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

                for payload_info in self.text_payloads:
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

                        # Check if our unique marker is reflected
                        if detect_pattern not in response_text:
                            continue

                        # FALSE POSITIVE CHECK: Not in baseline
                        if detect_pattern in baseline_text:
                            continue

                        # FALSE POSITIVE CHECK: Not inside script/style tags
                        if not self._is_text_context(response_text, detect_pattern):
                            continue

                        evidence = self._build_evidence(url, param_name, payload, detect_pattern, response_text)

                        result = self.create_result(
                            vulnerable=True,
                            url=url,
                            parameter=param_name,
                            payload=payload,
                            evidence=evidence,
                            description=f"Text Injection: {description}. User input is reflected in visible content, allowing content spoofing attacks.",
                            confidence=0.85,
                            severity='Medium',
                            method=method,
                            response=response_text[:2000]
                        )

                        result['verified'] = True
                        results.append(result)
                        logger.info(f"✓ Text Injection found: {description} in {param_name}")
                        break

                    except Exception as e:
                        logger.debug(f"Error testing text injection: {e}")
                        continue

        logger.info(f"Text Injection scan complete: {len(results)} vulnerabilities found")
        return results

    def _is_text_context(self, response_text: str, pattern: str) -> bool:
        """Check if pattern appears in visible text context"""
        pos = response_text.find(pattern)
        if pos == -1:
            return False

        start = max(0, pos - 500)
        context = response_text[start:pos].lower()

        # Check if inside script or style
        for tag in ['<script', '<style', '<!--']:
            close_tag = '</script>' if tag == '<script' else ('</style>' if tag == '<style' else '-->')
            last_open = context.rfind(tag)
            last_close = context.rfind(close_tag)
            if last_open != -1 and last_open > last_close:
                return False

        return True

    def _build_evidence(self, url: str, param: str, payload: str, detect: str, response: str) -> str:
        """Build evidence string"""
        context = self.extract_response_context(response, detect, 100, 100)

        return f"""Text Injection Confirmed

**URL:** {url}
**Parameter:** {param}
**Payload:** {payload}

**Reflected Content:**
{context}

**Impact:**
- Content spoofing/defacement
- Social engineering attacks
- Fake messages (errors, confirmations)
- Phishing via URL/email injection
"""


def get_module(module_path: str, payload_limit: int = None):
    """Create module instance"""
    return TextInjectionModule(module_path, payload_limit=payload_limit)
