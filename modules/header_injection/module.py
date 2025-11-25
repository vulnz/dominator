"""
Header Injection Scanner Module

Tests for injection vulnerabilities through HTTP headers:
- User-Agent injection (XSS, SQLi, Log Injection)
- Cookie injection
- X-Forwarded-For injection (IP spoofing, SQLi)
- Referer injection
- Custom header injection

These are often overlooked attack vectors where user-controlled
header values are logged, displayed, or processed unsafely.
"""

from typing import List, Dict, Any
from core.base_module import BaseModule
from core.logger import get_logger
import re

logger = get_logger(__name__)


class HeaderInjectionModule(BaseModule):
    """Header Injection vulnerability scanner"""

    # Headers commonly vulnerable to injection
    INJECTABLE_HEADERS = [
        'User-Agent',
        'Referer',
        'X-Forwarded-For',
        'X-Real-IP',
        'X-Originating-IP',
        'X-Client-IP',
        'X-Remote-IP',
        'X-Remote-Addr',
        'X-Host',
        'X-Forwarded-Host',
        'Accept-Language',
        'Origin',
        'True-Client-IP',
        'CF-Connecting-IP',
    ]

    # Injection payloads by type
    INJECTION_PAYLOADS = {
        'xss': [
            '<script>alert("XSS")</script>',
            '"><script>alert(1)</script>',
            "'-alert(1)-'",
            '<img src=x onerror=alert(1)>',
            '{{7*7}}',  # Also tests SSTI
        ],
        'sqli': [
            "' OR '1'='1",
            "1' AND '1'='1",
            "'; DROP TABLE users--",
            "1; SELECT * FROM users--",
            "' UNION SELECT NULL--",
            "1' ORDER BY 1--",
        ],
        'log_injection': [
            'INJECTED\r\nFake-Log-Entry: Hacked',
            'test\nINJECTED LOG LINE',
            '\r\n\r\n<html>injected</html>',
            '%0d%0aInjected-Header: value',
        ],
        'ssti': [
            '{{7*7}}',
            '${7*7}',
            '<%= 7*7 %>',
            '#{7*7}',
            '*{7*7}',
            '@(7*7)',
        ],
        'cmdi': [
            '; ls -la',
            '| cat /etc/passwd',
            '`id`',
            '$(id)',
            '; ping -c 1 127.0.0.1',
        ],
    }

    # Detection patterns for successful injection
    DETECTION_PATTERNS = {
        'xss': [
            r'<script>alert',
            r'onerror=alert',
            r'<img src=x',
        ],
        'sqli': [
            r'sql syntax',
            r'mysql_fetch',
            r'sqlite3_',
            r'ORA-\d{5}',
            r'pg_query',
            r'ODBC Driver',
            r'Microsoft SQL',
            r'syntax error',
            r'unclosed quotation',
        ],
        'ssti': [
            r'\b49\b',  # 7*7=49
            r'TemplateError',
            r'Jinja2',
            r'mako',
        ],
        'log_injection': [
            r'Injected-Header',
            r'INJECTED LOG',
            r'Fake-Log-Entry',
        ],
    }

    def __init__(self, module_path: str, payload_limit: int = None):
        """Initialize Header Injection module"""
        super().__init__(module_path, payload_limit=payload_limit)
        logger.info("Header Injection module loaded")

    def scan(self, targets: List[Dict[str, Any]], http_client: Any) -> List[Dict[str, Any]]:
        """
        Scan targets for header injection vulnerabilities

        Args:
            targets: List of URLs to scan
            http_client: HTTP client

        Returns:
            List of header injection vulnerabilities
        """
        results = []
        scanned_urls = set()

        logger.info(f"Starting Header Injection scan on {len(targets)} targets")

        for target in targets:
            url = target.get('url', '')

            # Normalize URL
            from urllib.parse import urlparse
            parsed = urlparse(url)
            base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"

            if base_url in scanned_urls:
                continue
            scanned_urls.add(base_url)

            # Test each injectable header
            for header_name in self.INJECTABLE_HEADERS:
                header_results = self._test_header_injection(url, header_name, http_client)
                results.extend(header_results)

            # Test cookie injection
            cookies = target.get('cookies', {})
            if cookies:
                cookie_results = self._test_cookie_injection(url, cookies, http_client)
                results.extend(cookie_results)

        logger.info(f"Header Injection scan complete: {len(results)} vulnerabilities found")
        return results

    def _test_header_injection(self, url: str, header_name: str,
                               http_client: Any) -> List[Dict[str, Any]]:
        """Test a specific header for injection vulnerabilities"""
        results = []

        # Get baseline response
        try:
            baseline = http_client.get(url)
            if not baseline:
                return results
            baseline_text = getattr(baseline, 'text', '')
        except Exception as e:
            logger.debug(f"Baseline request failed: {e}")
            return results

        # Test each injection type
        for injection_type, payloads in self.INJECTION_PAYLOADS.items():
            for payload in payloads[:3]:  # Limit payloads per type
                try:
                    # Inject payload into header
                    test_headers = {header_name: payload}
                    response = http_client.get(url, headers=test_headers)

                    if response:
                        response_text = getattr(response, 'text', '')

                        # Check for payload reflection
                        is_reflected = payload in response_text

                        # Check for injection patterns
                        is_vulnerable = False
                        evidence_detail = ""

                        if injection_type in self.DETECTION_PATTERNS:
                            for pattern in self.DETECTION_PATTERNS[injection_type]:
                                if re.search(pattern, response_text, re.IGNORECASE):
                                    is_vulnerable = True
                                    evidence_detail = f"Pattern matched: {pattern}"
                                    break

                        # Check for SSTI (7*7=49)
                        if injection_type == 'ssti' and '{{7*7}}' in payload and '49' in response_text:
                            is_vulnerable = True
                            evidence_detail = "Template expression evaluated: 7*7=49"

                        if is_reflected or is_vulnerable:
                            severity = self._get_severity(injection_type, is_vulnerable)

                            result = self.create_result(
                                vulnerable=True,
                                url=url,
                                parameter=header_name,
                                payload=payload,
                                evidence=self._build_evidence(
                                    header_name, payload, injection_type,
                                    is_reflected, is_vulnerable, evidence_detail
                                ),
                                description=f"{injection_type.upper()} injection via {header_name} header",
                                confidence=0.90 if is_vulnerable else 0.70
                            )
                            result['injection_type'] = injection_type
                            result['header_name'] = header_name
                            result['severity'] = severity
                            result['cwe'] = self._get_cwe(injection_type)
                            result['owasp'] = 'A03:2021'
                            results.append(result)

                            logger.info(f"Found {injection_type} injection in {header_name} at {url}")
                            break  # Found vuln, move to next type

                except Exception as e:
                    logger.debug(f"Error testing {header_name} with {injection_type}: {e}")

        return results

    def _test_cookie_injection(self, url: str, cookies: Dict[str, str],
                               http_client: Any) -> List[Dict[str, Any]]:
        """Test cookie values for injection vulnerabilities"""
        results = []

        for cookie_name in list(cookies.keys())[:5]:  # Limit cookies tested
            for injection_type, payloads in self.INJECTION_PAYLOADS.items():
                for payload in payloads[:2]:  # Limit payloads
                    try:
                        # Create test cookies with injection
                        test_cookies = cookies.copy()
                        test_cookies[cookie_name] = payload

                        # Format as cookie header
                        cookie_header = '; '.join([f"{k}={v}" for k, v in test_cookies.items()])
                        headers = {'Cookie': cookie_header}

                        response = http_client.get(url, headers=headers)

                        if response:
                            response_text = getattr(response, 'text', '')

                            # Check for injection signs
                            is_vulnerable = False
                            evidence_detail = ""

                            if injection_type in self.DETECTION_PATTERNS:
                                for pattern in self.DETECTION_PATTERNS[injection_type]:
                                    if re.search(pattern, response_text, re.IGNORECASE):
                                        is_vulnerable = True
                                        evidence_detail = f"Pattern matched: {pattern}"
                                        break

                            if payload in response_text:
                                is_vulnerable = True
                                evidence_detail = "Payload reflected in response"

                            if is_vulnerable:
                                result = self.create_result(
                                    vulnerable=True,
                                    url=url,
                                    parameter=f"Cookie[{cookie_name}]",
                                    payload=payload,
                                    evidence=f"Cookie injection via {cookie_name}\n\n"
                                             f"Injection type: {injection_type}\n"
                                             f"Payload: {payload}\n"
                                             f"{evidence_detail}",
                                    description=f"{injection_type.upper()} injection via Cookie ({cookie_name})",
                                    confidence=0.80
                                )
                                result['injection_type'] = injection_type
                                result['cookie_name'] = cookie_name
                                result['severity'] = self._get_severity(injection_type, True)
                                result['cwe'] = self._get_cwe(injection_type)
                                results.append(result)
                                break

                    except Exception as e:
                        logger.debug(f"Cookie injection test error: {e}")

        return results

    def _get_severity(self, injection_type: str, confirmed: bool) -> str:
        """Get severity based on injection type"""
        severity_map = {
            'xss': 'high' if confirmed else 'medium',
            'sqli': 'critical' if confirmed else 'high',
            'ssti': 'critical' if confirmed else 'high',
            'cmdi': 'critical' if confirmed else 'high',
            'log_injection': 'medium',
        }
        return severity_map.get(injection_type, 'medium')

    def _get_cwe(self, injection_type: str) -> str:
        """Get CWE for injection type"""
        cwe_map = {
            'xss': 'CWE-79',
            'sqli': 'CWE-89',
            'ssti': 'CWE-1336',
            'cmdi': 'CWE-78',
            'log_injection': 'CWE-117',
        }
        return cwe_map.get(injection_type, 'CWE-113')

    def _build_evidence(self, header_name: str, payload: str, injection_type: str,
                        is_reflected: bool, is_vulnerable: bool, detail: str) -> str:
        """Build evidence string"""
        evidence = f"Header Injection Test Results\n"
        evidence += f"{'='*40}\n\n"
        evidence += f"Header: {header_name}\n"
        evidence += f"Injection Type: {injection_type.upper()}\n"
        evidence += f"Payload: {payload}\n\n"

        if is_reflected:
            evidence += "REFLECTED: Payload appears in response body\n"
        if is_vulnerable:
            evidence += f"VULNERABLE: {detail}\n"

        evidence += f"\nRisk: User-controlled header values should be sanitized\n"
        evidence += f"before being logged, displayed, or used in queries."

        return evidence


def get_module(module_path: str, payload_limit: int = None):
    """Create module instance"""
    return HeaderInjectionModule(module_path, payload_limit=payload_limit)
