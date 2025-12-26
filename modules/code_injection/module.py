"""
Code Injection Scanner Module

Detects server-side code injection vulnerabilities where user input
is evaluated as code by the application runtime (PHP eval, Python exec,
Ruby eval, Node.js vm, etc.). This can lead to Remote Code Execution.

Note: This is different from OS Command Injection (cmdi).
"""

from typing import List, Dict, Any
from core.base_module import BaseModule
from core.logger import get_logger
import re
import random
import string
import time

logger = get_logger(__name__)


class CodeInjectionModule(BaseModule):
    """Code Injection Scanner Module"""

    def __init__(self, module_path: str, payload_limit: int = None):
        """Initialize Code Injection module"""
        super().__init__(module_path, payload_limit=payload_limit)

        # Generate unique markers for detection (prevents false positives)
        self.marker = ''.join(random.choices(string.ascii_lowercase, k=8))
        self.marker_num = random.randint(100000, 999999)
        self.expected_result = str(self.marker_num * 2)

        # PHP code injection payloads
        self.php_payloads = [
            {
                'payload': f'{self.marker_num}*2',
                'detect': self.expected_result,
                'description': 'PHP arithmetic evaluation'
            },
            {
                'payload': f'print("{self.marker}")',
                'detect': self.marker,
                'description': 'PHP print() execution'
            },
            {
                'payload': f'echo "{self.marker}"',
                'detect': self.marker,
                'description': 'PHP echo execution'
            },
            {
                'payload': 'phpinfo()',
                'detect': r'PHP Version|php\.ini|Configuration',
                'description': 'PHP phpinfo() execution',
                'regex': True
            },
            {
                'payload': f'"{"a"*5}"."{self.marker}"',
                'detect': f'aaaaa{self.marker}',
                'description': 'PHP string concatenation'
            },
            {
                'payload': f'1 and print("{self.marker}")',
                'detect': self.marker,
                'description': 'PHP assert() injection'
            },
        ]

        # Python code injection payloads
        self.python_payloads = [
            {
                'payload': f'{self.marker_num}*2',
                'detect': self.expected_result,
                'description': 'Python arithmetic evaluation'
            },
            {
                'payload': f'"a"*5+"{self.marker}"',
                'detect': f'aaaaa{self.marker}',
                'description': 'Python string multiplication'
            },
            {
                'payload': f'str({self.marker_num}*2)',
                'detect': self.expected_result,
                'description': 'Python str() evaluation'
            },
            {
                'payload': '__import__("os").name',
                'detect': r'(nt|posix)',
                'description': 'Python os module access',
                'regex': True
            },
            {
                'payload': f'print({self.marker_num}*2)',
                'detect': self.expected_result,
                'description': 'Python print() execution'
            },
        ]

        # Ruby code injection payloads
        self.ruby_payloads = [
            {
                'payload': f'{self.marker_num}*2',
                'detect': self.expected_result,
                'description': 'Ruby arithmetic evaluation'
            },
            {
                'payload': f'"a"*5+"{self.marker}"',
                'detect': f'aaaaa{self.marker}',
                'description': 'Ruby string multiplication'
            },
            {
                'payload': 'RUBY_VERSION',
                'detect': r'[0-9]+\.[0-9]+\.[0-9]+',
                'description': 'Ruby version disclosure',
                'regex': True
            },
            {
                'payload': f'puts "{self.marker}"',
                'detect': self.marker,
                'description': 'Ruby puts execution'
            },
        ]

        # Node.js/JavaScript code injection payloads
        self.nodejs_payloads = [
            {
                'payload': f'{self.marker_num}*2',
                'detect': self.expected_result,
                'description': 'JavaScript arithmetic evaluation'
            },
            {
                'payload': f'"a".repeat(5)+"{self.marker}"',
                'detect': f'aaaaa{self.marker}',
                'description': 'JavaScript string repeat'
            },
            {
                'payload': 'process.platform',
                'detect': r'(win32|linux|darwin)',
                'description': 'Node.js process access',
                'regex': True
            },
            {
                'payload': f'[1,2,3].join("{self.marker}")',
                'detect': f'1{self.marker}2{self.marker}3',
                'description': 'JavaScript array join'
            },
            {
                'payload': 'constructor.constructor("return 1+1")()',
                'detect': '2',
                'description': 'JavaScript constructor chaining'
            },
        ]

        # Generic payloads
        self.generic_payloads = [
            {
                'payload': f'{self.marker_num}*2',
                'detect': self.expected_result,
                'description': 'Generic arithmetic evaluation'
            },
            {
                'payload': f'{self.marker_num}+{self.marker_num}',
                'detect': self.expected_result,
                'description': 'Generic addition evaluation'
            },
        ]

        # Time-based payloads for blind detection
        self.time_based_payloads = [
            {
                'payload': 'sleep(3)',
                'delay': 3,
                'description': 'Time-based code injection (sleep 3s)'
            },
            {
                'payload': 'Thread.sleep(3000)',
                'delay': 3,
                'description': 'Java Thread.sleep() (3s)'
            },
        ]

        logger.info(f"Code Injection module loaded")

    def scan(self, targets: List[Dict[str, Any]], http_client: Any) -> List[Dict[str, Any]]:
        """
        Scan for code injection vulnerabilities

        Args:
            targets: List of URLs with parameters
            http_client: HTTP client

        Returns:
            List of vulnerability results
        """
        results = []

        logger.info(f"Starting Code Injection scan on {len(targets)} targets")

        for target in targets:
            url = target.get('url')
            params = target.get('params', {})
            method = target.get('method', 'GET').upper()

            if not params:
                continue

            # Detect likely technology
            tech = self._detect_technology(url, http_client)
            logger.debug(f"Detected technology: {tech}")

            # Get baseline response for false positive detection
            try:
                if method == 'POST':
                    baseline_response = http_client.post(url, data=params)
                else:
                    baseline_response = http_client.get(url, params=params)

                baseline_text = getattr(baseline_response, 'text', '') if baseline_response else ''
            except:
                baseline_text = ''

            # Select payloads based on detected technology
            payloads = self._get_payloads_for_tech(tech)

            # Test each parameter
            for param_name in params:
                if self.should_stop():
                    return results

                for payload_info in payloads:
                    payload = payload_info['payload']
                    detect_pattern = payload_info.get('detect')
                    description = payload_info['description']
                    is_regex = payload_info.get('regex', False)

                    try:
                        test_params = params.copy()
                        test_params[param_name] = payload

                        # Test via current method
                        if method == 'POST':
                            response = http_client.post(url, data=test_params, timeout=10)
                        else:
                            response = http_client.get(url, params=test_params, timeout=10)

                        if not response:
                            continue

                        response_text = getattr(response, 'text', '')

                        # Check for detection pattern
                        if is_regex:
                            match = re.search(detect_pattern, response_text, re.IGNORECASE)
                            if not match:
                                continue
                            matched_value = match.group(0)

                            # FALSE POSITIVE CHECK
                            if re.search(detect_pattern, baseline_text, re.IGNORECASE):
                                continue
                        else:
                            if detect_pattern not in response_text:
                                continue
                            matched_value = detect_pattern

                            # FALSE POSITIVE CHECK
                            if detect_pattern in baseline_text:
                                continue

                        # CONFIRMED VULNERABILITY
                        evidence = self._build_evidence(
                            url, param_name, payload, description,
                            matched_value, response_text, tech, method
                        )

                        result = self.create_result(
                            vulnerable=True,
                            url=url,
                            parameter=param_name,
                            payload=payload,
                            evidence=evidence,
                            description=f"Code Injection: {description}. User input is evaluated as code, allowing arbitrary code execution.",
                            confidence=0.90,
                            severity='Critical',
                            method=method,
                            response=response_text[:3000]
                        )

                        result['technology'] = tech
                        result['matched_value'] = matched_value
                        result['verified'] = True

                        results.append(result)
                        logger.warning(f"Code Injection found: {description} in {param_name}")

                        # Found vuln in this param, move to next
                        break

                    except Exception as e:
                        logger.debug(f"Error testing code injection: {e}")
                        continue

                # Test time-based detection if no vuln found yet
                if not any(r.get('parameter') == param_name for r in results):
                    time_result = self._test_time_based(url, param_name, params, method, http_client)
                    if time_result:
                        results.append(time_result)

        logger.info(f"Code Injection scan complete: {len(results)} vulnerabilities found")
        return results

    def _detect_technology(self, url: str, http_client: Any) -> str:
        """Detect backend technology"""
        url_lower = url.lower()

        # URL-based detection
        if '.php' in url_lower:
            return 'php'
        elif '.py' in url_lower or 'django' in url_lower or 'flask' in url_lower:
            return 'python'
        elif '.rb' in url_lower or 'rails' in url_lower:
            return 'ruby'
        elif '.js' in url_lower or 'node' in url_lower or 'express' in url_lower:
            return 'nodejs'

        # Try header-based detection
        try:
            response = http_client.get(url)
            if response:
                powered_by = response.headers.get('X-Powered-By', '').lower()
                server = response.headers.get('Server', '').lower()

                if 'php' in powered_by:
                    return 'php'
                elif 'express' in powered_by or 'node' in server:
                    return 'nodejs'
                elif 'python' in powered_by or 'django' in powered_by:
                    return 'python'
        except:
            pass

        return 'unknown'

    def _get_payloads_for_tech(self, tech: str) -> List[Dict]:
        """Get appropriate payloads for detected technology"""
        if tech == 'php':
            return self.php_payloads + self.generic_payloads
        elif tech == 'python':
            return self.python_payloads + self.generic_payloads
        elif tech == 'ruby':
            return self.ruby_payloads + self.generic_payloads
        elif tech == 'nodejs':
            return self.nodejs_payloads + self.generic_payloads
        else:
            # Unknown - try common payloads from each
            return (self.generic_payloads +
                    self.php_payloads[:3] +
                    self.python_payloads[:3] +
                    self.nodejs_payloads[:3])

    def _test_time_based(self, url: str, param_name: str, params: Dict,
                          method: str, http_client: Any) -> Dict:
        """Test for time-based blind code injection"""
        # Get baseline timing
        try:
            start = time.time()
            if method == 'POST':
                http_client.post(url, data=params, timeout=10)
            else:
                http_client.get(url, params=params, timeout=10)
            baseline_time = time.time() - start
        except:
            baseline_time = 1.0

        for payload_info in self.time_based_payloads:
            try:
                payload = payload_info['payload']
                expected_delay = payload_info['delay']

                test_params = params.copy()
                test_params[param_name] = payload

                start = time.time()
                if method == 'POST':
                    response = http_client.post(url, data=test_params, timeout=15)
                else:
                    response = http_client.get(url, params=test_params, timeout=15)
                elapsed = time.time() - start

                # Check if response was significantly delayed
                if elapsed >= expected_delay - 0.5 and elapsed > baseline_time + 2:
                    evidence = f"""Time-Based Code Injection Detected

**URL:** {url}
**Parameter:** {param_name}
**Payload:** {payload}

**Timing Analysis:**
- Baseline response time: {baseline_time:.2f}s
- Payload response time: {elapsed:.2f}s
- Expected delay: {expected_delay}s

**Conclusion:**
The server delayed its response when the sleep payload was injected,
indicating code evaluation is occurring.

**Security Impact:**
- Remote Code Execution
- Complete server compromise
- Data theft
"""

                    result = self.create_result(
                        vulnerable=True,
                        url=url,
                        parameter=param_name,
                        payload=payload,
                        evidence=evidence,
                        description=f"Time-based Code Injection: {payload_info['description']}",
                        confidence=0.80,
                        severity='Critical',
                        method=method,
                        response=f"Response delayed by {elapsed:.2f}s"
                    )

                    result['detection_method'] = 'time-based'
                    result['baseline_time'] = baseline_time
                    result['response_time'] = elapsed
                    result['verified'] = True

                    logger.warning(f"Time-based code injection found in {param_name}")
                    return result

            except Exception as e:
                if 'timeout' in str(e).lower():
                    # Timeout might indicate sleep worked
                    logger.debug(f"Timeout on time-based test - possible code injection")
                continue

        return None

    def _build_evidence(self, url: str, param: str, payload: str, desc: str,
                         match: str, response: str, tech: str, method: str) -> str:
        """Build detailed evidence string"""
        context = self.extract_response_context(response, match, 150, 100)

        evidence = f"""Code Injection Confirmed

**Vulnerable URL:** {url}
**Vulnerable Parameter:** {param}
**Method:** {method}
**Detected Technology:** {tech}
**Attack Type:** {desc}

**Injected Payload:**
{payload}

**Matched Value in Response:**
{match}

**Response Context:**
{context}

**Security Impact:**
- Arbitrary code execution on the server
- Complete server compromise possible
- Data theft and manipulation
- Potential for lateral movement

**Remediation:**
- Never use eval(), exec(), or similar functions with user input
- Implement strict input validation
- Use parameterized queries and safe APIs
- Apply the principle of least privilege
"""
        return evidence


def get_module(module_path: str, payload_limit: int = None):
    """Create module instance"""
    return CodeInjectionModule(module_path, payload_limit=payload_limit)
