"""
Insecure Deserialization Scanner

Detects deserialization vulnerabilities by:
- Detecting Java serialized object signatures
- Detecting PHP serialized objects
- Detecting Python pickle objects
- Testing for deserialization errors/behaviors
"""

from typing import List, Dict, Any, Optional
from core.base_module import BaseModule
from core.logger import get_logger
import base64
import re

logger = get_logger(__name__)


class DeserializationModule(BaseModule):
    """Insecure Deserialization vulnerability scanner"""

    # Serialization signatures in requests/responses
    SERIALIZATION_SIGNATURES = {
        'java': [
            (b'\xac\xed\x00\x05', 'Java serialized object (raw)'),
            ('rO0AB', 'Java serialized object (base64)'),
            ('H4sIAAAA', 'Java serialized object (gzip+base64)'),
        ],
        'php': [
            ('O:1:', 'PHP serialized object'),
            ('a:1:', 'PHP serialized array'),
            ('s:1:', 'PHP serialized string'),
            ('O%3A', 'PHP serialized (URL encoded)'),
        ],
        'python': [
            (b'\x80\x04\x95', 'Python pickle (protocol 4)'),
            (b'\x80\x03', 'Python pickle (protocol 3)'),
            ('gASV', 'Python pickle (base64)'),
            ('Y29weXJlZw', 'Python copyreg (base64)'),
        ],
        'dotnet': [
            ('AAEAAAD', '.NET BinaryFormatter (base64)'),
            ('AAAAAgAAAA', '.NET ViewState pattern'),
        ],
        'ruby': [
            ('\x04\x08', 'Ruby Marshal'),
        ],
    }

    # Test payloads for triggering deserialization errors
    # These are SAFE payloads that trigger errors, not RCE
    ERROR_PAYLOADS = {
        'java_invalid': 'rO0ABXQACEludmFsaWQ=',  # Invalid Java object
        'php_invalid': 'O:99:"Invalid":0:{}',      # Invalid PHP class
        'python_invalid': 'gASVBwAAAAAAAABYBwAAAEludmFsaWSULg==',  # Invalid pickle
    }

    def __init__(self, module_path: str, payload_limit: int = None):
        super().__init__(module_path, payload_limit=payload_limit)
        logger.info("Insecure Deserialization module initialized")

    def scan(self, targets: List[Dict[str, Any]], http_client: Any) -> List[Dict[str, Any]]:
        """Scan for deserialization vulnerabilities"""
        results = []

        logger.info(f"Starting Deserialization scan on {len(targets)} targets")

        for target in targets:
            url = target.get('url', '')
            method = target.get('method', 'GET').upper()
            params = target.get('params', {})
            body = target.get('body', '')
            headers = target.get('headers', {})
            cookies = target.get('cookies', '')

            # Check for serialization signatures in parameters
            param_result = self._check_params_for_serialization(url, params)
            if param_result:
                results.append(param_result)

            # Check cookies for serialized data
            cookie_result = self._check_cookies(url, cookies, http_client, headers)
            if cookie_result:
                results.append(cookie_result)

            # Check body for serialized data
            if body:
                body_result = self._check_body(url, body)
                if body_result:
                    results.append(body_result)

            # Test POST endpoints for deserialization behavior
            if method in ['POST', 'PUT']:
                test_result = self._test_deserialization(url, method, http_client, headers)
                if test_result:
                    results.append(test_result)

        logger.info(f"Deserialization scan complete: {len(results)} vulnerabilities found")
        return results

    def _check_params_for_serialization(self, url: str, params: Dict) -> Optional[Dict]:
        """Check URL parameters for serialized object signatures"""
        for param_name, param_value in params.items():
            if not isinstance(param_value, str):
                continue

            for lang, signatures in self.SERIALIZATION_SIGNATURES.items():
                for signature, description in signatures:
                    if isinstance(signature, bytes):
                        # Try base64 decode
                        try:
                            decoded = base64.b64decode(param_value)
                            if signature in decoded:
                                return self._create_finding(
                                    url, param_name, param_value, lang, description
                                )
                        except:
                            pass
                    else:
                        if signature in param_value:
                            return self._create_finding(
                                url, param_name, param_value, lang, description
                            )

        return None

    def _check_cookies(self, url: str, cookies: str, http_client: Any,
                       headers: Dict) -> Optional[Dict]:
        """Check cookies for serialized data"""
        if not cookies:
            # Try to get cookies from a request
            try:
                response = http_client.get(url, headers=headers)
                if response and 'set-cookie' in str(response.headers).lower():
                    cookies = str(response.headers.get('set-cookie', ''))
            except:
                pass

        if not cookies:
            return None

        for lang, signatures in self.SERIALIZATION_SIGNATURES.items():
            for signature, description in signatures:
                if isinstance(signature, str) and signature in cookies:
                    evidence = f"**Serialized Object in Cookie**\n\n"
                    evidence += f"**Type:** {description}\n"
                    evidence += f"**Language:** {lang.upper()}\n"
                    evidence += f"**Location:** Cookie header\n\n"
                    evidence += f"**Risk:** If this cookie is deserialized on the server, "
                    evidence += f"it may be vulnerable to object injection attacks."

                    result = self.create_result(
                        vulnerable=True,
                        url=url,
                        parameter="Cookie",
                        payload="Serialized object detected",
                        evidence=evidence,
                        description=f"{lang.upper()} serialized object in cookie",
                        confidence=0.80
                    )
                    result['cwe'] = 'CWE-502'
                    result['severity'] = 'high'
                    return result

        return None

    def _check_body(self, url: str, body: Any) -> Optional[Dict]:
        """Check request body for serialized data"""
        body_str = str(body)

        for lang, signatures in self.SERIALIZATION_SIGNATURES.items():
            for signature, description in signatures:
                if isinstance(signature, str) and signature in body_str:
                    return self._create_finding(
                        url, "Request Body", body_str[:100], lang, description
                    )

        return None

    def _test_deserialization(self, url: str, method: str, http_client: Any,
                               headers: Dict) -> Optional[Dict]:
        """Test endpoint for deserialization behavior"""
        try:
            # Send invalid serialized data and check for revealing errors
            test_payloads = [
                ('application/x-java-serialized-object', self.ERROR_PAYLOADS['java_invalid']),
                ('application/x-php-serialized', self.ERROR_PAYLOADS['php_invalid']),
            ]

            for content_type, payload in test_payloads:
                test_headers = headers.copy()
                test_headers['Content-Type'] = content_type

                try:
                    response = http_client.request(method, url,
                                                   data=base64.b64decode(payload) if 'java' in content_type else payload,
                                                   headers=test_headers)

                    if not response:
                        continue

                    # Check for deserialization error messages
                    error_indicators = [
                        'java.io.InvalidClassException',
                        'java.io.StreamCorruptedException',
                        'ClassNotFoundException',
                        'unserialize()',
                        '__wakeup()',
                        'pickle.loads',
                        'UnpicklingError',
                        'BinaryFormatter',
                        'deserialize',
                    ]

                    response_lower = response.text.lower()
                    for indicator in error_indicators:
                        if indicator.lower() in response_lower:
                            evidence = f"**Deserialization Error Detected**\n\n"
                            evidence += f"**Content-Type:** `{content_type}`\n"
                            evidence += f"**Error Indicator:** `{indicator}`\n\n"
                            evidence += f"**Analysis:**\n"
                            evidence += f"The server attempted to deserialize the malformed payload "
                            evidence += f"and returned an error message. This confirms deserialization "
                            evidence += f"is occurring.\n\n"
                            evidence += f"**Impact:** Remote Code Execution via gadget chains"

                            result = self.create_result(
                                vulnerable=True,
                                url=url,
                                parameter="Request Body",
                                payload=f"Malformed {content_type} object",
                                evidence=evidence,
                                description=f"Deserialization endpoint found ({indicator})",
                                confidence=0.90
                            )
                            result['cwe'] = 'CWE-502'
                            result['severity'] = 'critical'
                            return result

                except Exception as e:
                    logger.debug(f"Error testing deserialization: {e}")

        except Exception as e:
            logger.debug(f"Deserialization test error: {e}")

        return None

    def _create_finding(self, url: str, param: str, value: str,
                        lang: str, description: str) -> Dict:
        """Create a deserialization finding"""
        evidence = f"**Serialized Object Detected**\n\n"
        evidence += f"**Type:** {description}\n"
        evidence += f"**Language:** {lang.upper()}\n"
        evidence += f"**Parameter:** `{param}`\n"
        evidence += f"**Value (truncated):** `{value[:80]}...`\n\n"
        evidence += f"**Risk:** Insecure deserialization can lead to:\n"
        evidence += f"- Remote Code Execution (RCE)\n"
        evidence += f"- Denial of Service (DoS)\n"
        evidence += f"- Authentication bypass\n"
        evidence += f"- Data tampering"

        result = self.create_result(
            vulnerable=True,
            url=url,
            parameter=param,
            payload=f"{lang} serialized object",
            evidence=evidence,
            description=f"Insecure {lang.upper()} deserialization detected",
            confidence=0.85
        )
        result['cwe'] = 'CWE-502'
        result['cwe_name'] = 'Deserialization of Untrusted Data'
        result['owasp'] = 'A08:2021'
        result['owasp_name'] = 'Software and Data Integrity Failures'
        result['severity'] = 'critical'
        return result


def get_module(module_path: str, payload_limit: int = None):
    return DeserializationModule(module_path, payload_limit=payload_limit)
