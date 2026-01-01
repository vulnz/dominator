"""
Remote Code Execution (RCE) Scanner Module

Comprehensive RCE detection covering multiple attack vectors:
- Expression Language injection (Spring SpEL, JSP EL)
- Log4Shell (CVE-2021-44228) and JNDI injection
- Template engines leading to RCE (Freemarker, Velocity, Thymeleaf)
- Framework-specific RCE vectors
- Time-based blind RCE detection
"""

from typing import List, Dict, Any
from core.base_module import BaseModule
from core.logger import get_logger
import re
import random
import string
import time

logger = get_logger(__name__)


class RCEModule(BaseModule):
    """Remote Code Execution Scanner Module"""

    def __init__(self, module_path: str, payload_limit: int = None):
        """Initialize RCE module"""
        super().__init__(module_path, payload_limit=payload_limit)

        # Generate unique markers using MATH - the expected result is NEVER in the payload
        # This prevents false positives from payload reflection in error messages
        self.num1 = random.randint(10000, 99999)
        self.num2 = random.randint(10000, 99999)
        self.expected_math = str(self.num1 * self.num2)  # e.g., "1234567890"

        # For string-based tests, use a marker that won't be reflected
        self.marker_base = ''.join(random.choices(string.ascii_lowercase, k=6))

        # Canary domain for OOB detection (placeholder)
        self.canary_domain = f"{self.marker_base}.oob.example.com"

        # Initialize payload categories
        self._init_payloads()

        logger.info(f"RCE module loaded: math check {self.num1}*{self.num2}={self.expected_math}")

    def _init_payloads(self):
        """Initialize all RCE payload categories

        CRITICAL: All payloads use MATH expressions where the expected result
        is NEVER contained in the payload itself. This prevents false positives
        when payloads are reflected in error messages.
        """

        # Spring Expression Language (SpEL) payloads - MATH ONLY
        self.spel_payloads = [
            {
                'payload': f'${{{self.num1}*{self.num2}}}',
                'detect': self.expected_math,
                'description': 'Spring SpEL arithmetic evaluation',
                'severity': 'Critical'
            },
            {
                'payload': f'*{{{self.num1}*{self.num2}}}',
                'detect': self.expected_math,
                'description': 'Spring SpEL (asterisk syntax)',
                'severity': 'Critical'
            },
        ]

        # JSP Expression Language payloads - MATH ONLY
        self.el_payloads = [
            {
                'payload': f'${{{self.num1}*{self.num2}}}',
                'detect': self.expected_math,
                'description': 'JSP EL arithmetic evaluation',
                'severity': 'Critical'
            },
        ]

        # Freemarker SSTI -> RCE - MATH ONLY
        self.freemarker_payloads = [
            {
                'payload': f'${{{self.num1}*{self.num2}}}',
                'detect': self.expected_math,
                'description': 'Freemarker expression evaluation',
                'severity': 'Critical'
            },
        ]

        # Thymeleaf SSTI -> RCE - MATH ONLY
        self.thymeleaf_payloads = [
            {
                'payload': f'__${{{self.num1}*{self.num2}}}__::.x',
                'detect': self.expected_math,
                'description': 'Thymeleaf preprocessor RCE',
                'severity': 'Critical'
            },
        ]

        # Log4Shell / JNDI injection (error-based detection only)
        # STRICT: Only match very specific error messages
        self.log4shell_payloads = [
            {
                'payload': '${jndi:ldap://127.0.0.1/test}',
                'detect': r'javax\.naming\.NameNotFoundException|javax\.naming\.NamingException',
                'description': 'Log4Shell JNDI (error-based)',
                'severity': 'High',
                'regex': True
            },
        ]

        # PHP-specific RCE - MATH ONLY (no echo with markers!)
        # The key insight: <?php echo 7*7 ?> outputs "49" NOT "<?php echo 7*7 ?>"
        self.php_payloads = [
            {
                'payload': f'<?php echo {self.num1}*{self.num2}; ?>',
                'detect': self.expected_math,
                'description': 'PHP code injection (math)',
                'severity': 'Critical'
            },
            {
                'payload': f'<?={self.num1}*{self.num2}?>',
                'detect': self.expected_math,
                'description': 'PHP short tag injection (math)',
                'severity': 'Critical'
            },
            {
                'payload': 'phpinfo()',
                'detect': r'<title>phpinfo\(\)</title>|PHP Version \d+\.\d+',
                'description': 'PHP phpinfo() execution',
                'severity': 'Critical',
                'regex': True
            },
        ]

        # Node.js RCE - MATH ONLY
        self.nodejs_payloads = [
            {
                'payload': f'{self.num1}*{self.num2}',
                'detect': self.expected_math,
                'description': 'Node.js arithmetic evaluation',
                'severity': 'Critical'
            },
            {
                'payload': f'eval({self.num1}*{self.num2})',
                'detect': self.expected_math,
                'description': 'Node.js eval() execution',
                'severity': 'Critical'
            },
        ]

        # Time-based RCE detection (separate - no reflection issue)
        self.time_based_payloads = [
            {
                'payload': '${T(java.lang.Thread).sleep(5000)}',
                'delay': 5,
                'description': 'Java Thread.sleep() time-based'
            },
            {
                'payload': '__${T(java.lang.Thread).sleep(5000)}__::.x',
                'delay': 5,
                'description': 'Thymeleaf Thread.sleep()'
            },
            {
                'payload': '<?php sleep(5); ?>',
                'delay': 5,
                'description': 'PHP sleep() time-based'
            },
        ]

    def scan(self, targets: List[Dict[str, Any]], http_client: Any) -> List[Dict[str, Any]]:
        """
        Scan for RCE vulnerabilities

        Args:
            targets: List of URLs with parameters
            http_client: HTTP client

        Returns:
            List of vulnerability results
        """
        results = []

        logger.info(f"Starting RCE scan on {len(targets)} targets")

        for target in targets:
            url = target.get('url')
            params = target.get('params', {})
            method = target.get('method', 'GET').upper()

            if not params:
                continue

            # Detect technology for targeted testing
            tech = self._detect_technology(url, http_client)
            logger.debug(f"Detected technology: {tech}")

            # Get baseline response
            try:
                if method == 'POST':
                    baseline_response = http_client.post(url, data=params)
                else:
                    baseline_response = http_client.get(url, params=params)

                baseline_text = getattr(baseline_response, 'text', '') if baseline_response else ''
            except:
                baseline_text = ''

            # Select payloads based on technology
            payloads = self._get_payloads_for_tech(tech)

            # Test each parameter
            for param_name in params:
                if self.should_stop():
                    return results

                for payload_info in payloads:
                    payload = payload_info['payload']
                    detect_pattern = payload_info.get('detect')
                    description = payload_info['description']
                    severity = payload_info.get('severity', 'Critical')
                    is_regex = payload_info.get('regex', False)

                    try:
                        test_params = params.copy()
                        test_params[param_name] = payload

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

                            # FALSE POSITIVE CHECK - not in baseline
                            if re.search(detect_pattern, baseline_text, re.IGNORECASE):
                                continue
                        else:
                            if detect_pattern not in response_text:
                                continue
                            matched_value = detect_pattern

                            # FALSE POSITIVE CHECK - not in baseline
                            if detect_pattern in baseline_text:
                                continue

                        # CRITICAL: Check if payload is reflected in response (error message)
                        # If payload appears in response, the "detection" might just be reflection
                        if self._is_payload_reflected(payload, response_text):
                            logger.debug(f"RCE: Payload reflected - skipping false positive")
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
                            payload=payload[:200],
                            evidence=evidence,
                            description=f"Remote Code Execution: {description}. Arbitrary code can be executed on the server.",
                            confidence=0.92,
                            severity=severity,
                            method=method,
                            response=response_text[:3000]
                        )

                        result['technology'] = tech
                        result['matched_value'] = matched_value
                        result['verified'] = True

                        results.append(result)
                        logger.warning(f"RCE found: {description} in {param_name}")

                        # Found vuln, move to next param
                        break

                    except Exception as e:
                        logger.debug(f"Error testing RCE payload: {e}")
                        continue

                # Test time-based if no vuln found
                if not any(r.get('parameter') == param_name for r in results):
                    time_result = self._test_time_based(url, param_name, params, method, http_client)
                    if time_result:
                        results.append(time_result)

            # Test headers for Log4Shell
            header_results = self._test_log4shell_headers(url, http_client)
            results.extend(header_results)

        logger.info(f"RCE scan complete: {len(results)} vulnerabilities found")
        return results

    def _detect_technology(self, url: str, http_client: Any) -> str:
        """Detect backend technology"""
        url_lower = url.lower()

        # URL-based detection
        if '.jsp' in url_lower or '.do' in url_lower or '.action' in url_lower:
            return 'java'
        elif '.php' in url_lower:
            return 'php'
        elif '.aspx' in url_lower or '.asp' in url_lower:
            return 'dotnet'
        elif '.js' in url_lower or 'node' in url_lower:
            return 'nodejs'

        # Header-based detection
        try:
            response = http_client.get(url)
            if response:
                server = response.headers.get('Server', '').lower()
                powered = response.headers.get('X-Powered-By', '').lower()

                if 'tomcat' in server or 'java' in powered or 'jsp' in powered:
                    return 'java'
                elif 'php' in powered:
                    return 'php'
                elif 'asp.net' in powered or 'iis' in server:
                    return 'dotnet'
                elif 'express' in powered or 'node' in powered:
                    return 'nodejs'
        except:
            pass

        return 'unknown'

    def _get_payloads_for_tech(self, tech: str) -> List[Dict]:
        """Get payloads for detected technology"""
        if tech == 'java':
            return (self.spel_payloads + self.el_payloads +
                    self.freemarker_payloads + self.thymeleaf_payloads +
                    self.log4shell_payloads)
        elif tech == 'php':
            return self.php_payloads
        elif tech == 'nodejs':
            return self.nodejs_payloads
        else:
            # Unknown - test common vectors
            return (self.spel_payloads[:3] + self.log4shell_payloads[:3] +
                    self.php_payloads[:2] + self.nodejs_payloads[:2])

    def _test_time_based(self, url: str, param_name: str, params: Dict,
                          method: str, http_client: Any) -> Dict:
        """Test for time-based blind RCE"""
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

                # Check for significant delay - STRICT: must be at least expected_delay AND 4s more than baseline
                # This reduces false positives from slow servers
                if elapsed >= expected_delay - 0.5 and elapsed > baseline_time + 4:
                    evidence = f"""Time-Based RCE Detected

**URL:** {url}
**Parameter:** {param_name}
**Payload:** {payload}

**Timing Analysis:**
- Baseline response time: {baseline_time:.2f}s
- Payload response time: {elapsed:.2f}s
- Expected delay: {expected_delay}s

**Conclusion:**
The server delayed its response when the sleep payload was injected,
confirming code execution on the server.

**Security Impact:**
- Remote Code Execution
- Complete server compromise
- Data exfiltration
- Lateral movement
"""

                    result = self.create_result(
                        vulnerable=True,
                        url=url,
                        parameter=param_name,
                        payload=payload,
                        evidence=evidence,
                        description=f"Time-based RCE: {payload_info['description']}",
                        confidence=0.85,
                        severity='Critical',
                        method=method,
                        response=f"Response delayed by {elapsed:.2f}s"
                    )

                    result['detection_method'] = 'time-based'
                    result['baseline_time'] = baseline_time
                    result['response_time'] = elapsed
                    result['verified'] = True

                    logger.warning(f"Time-based RCE found in {param_name}")
                    return result

            except Exception as e:
                if 'timeout' in str(e).lower():
                    logger.debug(f"Timeout on time-based test - possible RCE")
                continue

        return None

    def _test_log4shell_headers(self, url: str, http_client: Any) -> List[Dict[str, Any]]:
        """Test HTTP headers for Log4Shell vulnerability - STRICT detection"""
        results = []

        # Only test critical headers, and use very specific error patterns
        headers_to_test = ['User-Agent', 'X-Api-Version']

        # Get baseline first to check for pre-existing error messages
        try:
            baseline_response = http_client.get(url, timeout=5)
            baseline_text = baseline_response.text.lower() if baseline_response else ''
        except:
            baseline_text = ''

        for payload_info in self.log4shell_payloads[:1]:  # Only test first payload
            payload = payload_info['payload']
            description = payload_info['description']

            for header_name in headers_to_test:
                try:
                    custom_headers = {header_name: payload}
                    response = http_client.get(url, headers=custom_headers, timeout=5)

                    if response and response.text:
                        response_lower = response.text.lower()

                        # STRICT: Only match very specific Log4j error patterns
                        # Generic words like "jndi" or "lookup" cause too many false positives
                        strict_indicators = [
                            'javax.naming.namenotfoundexception',
                            'javax.naming.namingexception',
                            'jndilookup',
                            'log4j2.formatmsgnolookups',
                            'log4j jndi',
                            'invalid jndi'
                        ]

                        for indicator in strict_indicators:
                            # Must be NEW in response (not in baseline)
                            if indicator in response_lower and indicator not in baseline_text:
                                evidence = f"""Possible Log4Shell Vulnerability

**URL:** {url}
**Injection Point:** {header_name} header
**Payload:** {payload}

**Detection:** Error-based - Log4j/JNDI error in response
**Matched Pattern:** {indicator}

**Note:** For full confirmation, use an out-of-band callback server
to verify JNDI lookups are being made. This is error-based detection only.

**Security Impact:**
- Remote Code Execution
- CVE-2021-44228 (Log4Shell)
"""

                                result = self.create_result(
                                    vulnerable=True,
                                    url=url,
                                    parameter=f'{header_name} header',
                                    payload=payload,
                                    evidence=evidence,
                                    description=f"Possible Log4Shell: {description}",
                                    confidence=0.70,
                                    severity='High',  # Downgraded from Critical - needs OOB confirmation
                                    method='GET (Header)',
                                    response=response.text[:2000]
                                )

                                result['cve'] = 'CVE-2021-44228'
                                result['detection_method'] = 'error-based'
                                result['verified'] = False

                                results.append(result)
                                logger.warning(f"Possible Log4Shell in {header_name}")
                                return results  # One finding is enough

                except Exception as e:
                    logger.debug(f"Error testing Log4Shell header: {e}")
                    continue

        return results

    def _is_payload_reflected(self, payload: str, response_text: str) -> bool:
        """
        Check if the payload is reflected in the response (e.g., in error messages)

        Returns True if payload appears to be reflected (false positive risk)
        """
        import html
        import urllib.parse

        # Check raw payload
        if payload in response_text:
            return True

        # Check URL-encoded payload
        if urllib.parse.quote(payload) in response_text:
            return True

        # Check HTML-encoded payload
        if html.escape(payload) in response_text:
            return True

        # Check partial payload - the distinctive math expression
        # For "${12345*67890}" check if "12345*67890" appears
        math_match = re.search(r'(\d{4,})\s*\*\s*(\d{4,})', payload)
        if math_match:
            math_expr = f"{math_match.group(1)}*{math_match.group(2)}"
            if math_expr in response_text:
                return True

        return False

    def _build_evidence(self, url: str, param: str, payload: str, desc: str,
                         match: str, response: str, tech: str, method: str) -> str:
        """Build detailed evidence string"""
        context = self.extract_response_context(response, match, 150, 100)

        evidence = f"""Remote Code Execution Confirmed

**Vulnerable URL:** {url}
**Vulnerable Parameter:** {param}
**Method:** {method}
**Detected Technology:** {tech}
**Attack Type:** {desc}

**Injected Payload:**
{payload[:300]}

**Matched Value in Response:**
{match}

**Response Context:**
{context}

**Security Impact:**
- Arbitrary code execution on the server
- Complete server compromise
- Data theft and exfiltration
- Lateral movement in the network
- Potential for ransomware deployment

**Remediation:**
- Update all frameworks and libraries to latest versions
- Disable dangerous features (eval, SpEL, JNDI lookups)
- Implement strict input validation
- Use Web Application Firewall (WAF)
- Apply principle of least privilege
"""
        return evidence


def get_module(module_path: str, payload_limit: int = None):
    """Create module instance"""
    return RCEModule(module_path, payload_limit=payload_limit)
