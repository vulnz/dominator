"""
Java/J2EE Technology and Vulnerability Passive Detector

Passively detects Java technologies, frameworks, and potential vulnerabilities
in HTTP responses.

Inspired by J2EEScan (80+ checks for J2EE applications).

Detects:
- Java application servers (Tomcat, JBoss, WebLogic, WebSphere, Jetty, etc.)
- Java frameworks (Spring, Struts, JSF, Wicket, etc.)
- Serialization indicators
- Expression Language (EL) contexts
- Known CVE indicators
- Debug/development modes
- Version information disclosure
"""

import re
from typing import Dict, List, Tuple, Any, Optional
from urllib.parse import urlparse


class JavaDetector:
    """
    Java/J2EE Technology and Vulnerability Passive Detector

    Identifies Java technologies and potential security issues.
    """

    # Java Server Detection Patterns
    SERVER_PATTERNS = {
        'Apache Tomcat': [
            re.compile(r'Apache[- ]Tomcat/?([0-9.]+)?', re.IGNORECASE),
            re.compile(r'Coyote/?([0-9.]+)?', re.IGNORECASE),
            re.compile(r'org\.apache\.catalina', re.IGNORECASE),
            re.compile(r'<h3>Apache Tomcat', re.IGNORECASE),
        ],
        'JBoss/WildFly': [
            re.compile(r'JBoss(?:AS)?/?([0-9.]+)?', re.IGNORECASE),
            re.compile(r'WildFly/?([0-9.]+)?', re.IGNORECASE),
            re.compile(r'org\.jboss', re.IGNORECASE),
            re.compile(r'X-Powered-By:\s*(?:JBoss|Undertow)', re.IGNORECASE),
        ],
        'Oracle WebLogic': [
            re.compile(r'WebLogic/?([0-9.]+)?', re.IGNORECASE),
            re.compile(r'weblogic\.', re.IGNORECASE),
            re.compile(r'bea\.com', re.IGNORECASE),
        ],
        'IBM WebSphere': [
            re.compile(r'WebSphere/?([0-9.]+)?', re.IGNORECASE),
            re.compile(r'was\.', re.IGNORECASE),
            re.compile(r'IBM-http', re.IGNORECASE),
        ],
        'Jetty': [
            re.compile(r'Jetty/?([0-9.]+)?', re.IGNORECASE),
            re.compile(r'org\.eclipse\.jetty', re.IGNORECASE),
            re.compile(r'org\.mortbay\.jetty', re.IGNORECASE),
        ],
        'GlassFish': [
            re.compile(r'GlassFish/?([0-9.]+)?', re.IGNORECASE),
            re.compile(r'Payara/?([0-9.]+)?', re.IGNORECASE),
            re.compile(r'Sun Java System', re.IGNORECASE),
        ],
        'Resin': [
            re.compile(r'Resin/?([0-9.]+)?', re.IGNORECASE),
            re.compile(r'Caucho', re.IGNORECASE),
        ],
    }

    # Framework Detection Patterns
    FRAMEWORK_PATTERNS = {
        'Spring Framework': [
            re.compile(r'org\.springframework', re.IGNORECASE),
            re.compile(r'spring[.-](?:boot|mvc|web|security)', re.IGNORECASE),
            re.compile(r'SpringMVC', re.IGNORECASE),
            re.compile(r'spring\.', re.IGNORECASE),
        ],
        'Spring Boot': [
            re.compile(r'spring-boot', re.IGNORECASE),
            re.compile(r'Whitelabel Error Page', re.IGNORECASE),
            re.compile(r'/actuator/', re.IGNORECASE),
            re.compile(r'management\.endpoint', re.IGNORECASE),
        ],
        'Apache Struts': [
            re.compile(r'org\.apache\.struts', re.IGNORECASE),
            re.compile(r'struts2?-', re.IGNORECASE),
            re.compile(r'\.action(?:\?|$)', re.IGNORECASE),
            re.compile(r'S2-\d{3}', re.IGNORECASE),
        ],
        'JavaServer Faces (JSF)': [
            re.compile(r'javax\.faces', re.IGNORECASE),
            re.compile(r'\.jsf(?:\?|$)', re.IGNORECASE),
            re.compile(r'\.xhtml(?:\?|$)', re.IGNORECASE),
            re.compile(r'PrimeFaces', re.IGNORECASE),
            re.compile(r'RichFaces', re.IGNORECASE),
            re.compile(r'ICEfaces', re.IGNORECASE),
            re.compile(r'Mojarra', re.IGNORECASE),
        ],
        'Apache Wicket': [
            re.compile(r'org\.apache\.wicket', re.IGNORECASE),
            re.compile(r'wicket:', re.IGNORECASE),
        ],
        'Play Framework': [
            re.compile(r'play\.api\.', re.IGNORECASE),
            re.compile(r'playframework', re.IGNORECASE),
        ],
        'Vaadin': [
            re.compile(r'vaadin', re.IGNORECASE),
            re.compile(r'v-loading-indicator', re.IGNORECASE),
        ],
        'GWT (Google Web Toolkit)': [
            re.compile(r'com\.google\.gwt', re.IGNORECASE),
            re.compile(r'\.nocache\.js', re.IGNORECASE),
            re.compile(r'gwt\.xml', re.IGNORECASE),
        ],
        'Apache CXF': [
            re.compile(r'org\.apache\.cxf', re.IGNORECASE),
            re.compile(r'CXF', re.IGNORECASE),
        ],
    }

    # Vulnerable Version Patterns (known CVEs)
    VULNERABLE_PATTERNS = {
        'Apache Struts RCE (S2-045/CVE-2017-5638)': {
            'patterns': [
                re.compile(r'struts2?-core-2\.(?:3\.[0-9]|3\.[12][0-9]|3\.3[0-2]|5\.[0-9]|5\.10(?:\.[0-2])?)(?:\.jar)?', re.IGNORECASE),
            ],
            'severity': 'Critical',
            'cve': 'CVE-2017-5638',
            'description': 'Apache Struts 2.3.5-2.3.31, 2.5-2.5.10 vulnerable to RCE via Content-Type header',
        },
        'Log4Shell (CVE-2021-44228)': {
            'patterns': [
                re.compile(r'log4j-core-2\.(?:[0-9]|1[0-4])(?:\.[0-9]+)?(?:\.jar)?', re.IGNORECASE),
                re.compile(r'org\.apache\.logging\.log4j', re.IGNORECASE),
            ],
            'severity': 'Critical',
            'cve': 'CVE-2021-44228',
            'description': 'Log4j 2.0-2.14.1 vulnerable to RCE via JNDI lookup',
        },
        'Spring4Shell (CVE-2022-22965)': {
            'patterns': [
                re.compile(r'spring-(?:beans|webmvc)-5\.(?:[0-2]\.[0-9]+|3\.[0-9]+|3\.1[0-7])(?:\.jar)?', re.IGNORECASE),
            ],
            'severity': 'Critical',
            'cve': 'CVE-2022-22965',
            'description': 'Spring Framework RCE via data binding with JDK9+',
        },
        'Apache Tomcat GhostCat (CVE-2020-1938)': {
            'patterns': [
                re.compile(r'Apache Tomcat/?(?:7\.[0-9]{1,2}|8\.5\.[0-9]{1,2}|9\.0\.[0-9]{1,2})', re.IGNORECASE),
            ],
            'severity': 'High',
            'cve': 'CVE-2020-1938',
            'description': 'Apache Tomcat AJP connector vulnerability allows file read/RCE',
        },
        'Jackson Deserialization (CVE-2017-7525)': {
            'patterns': [
                re.compile(r'jackson-databind-2\.(?:[0-7]\.[0-9]+|8\.[0-8])(?:\.jar)?', re.IGNORECASE),
            ],
            'severity': 'High',
            'cve': 'CVE-2017-7525',
            'description': 'Jackson-databind vulnerable to deserialization RCE',
        },
        'Fastjson RCE': {
            'patterns': [
                re.compile(r'fastjson-1\.2\.(?:[0-9]|[1-5][0-9]|6[0-7])(?:\.jar)?', re.IGNORECASE),
            ],
            'severity': 'Critical',
            'cve': 'CVE-2019-16866',
            'description': 'Fastjson versions <1.2.68 vulnerable to RCE',
        },
        'Apache Shiro Deserialization (CVE-2016-4437)': {
            'patterns': [
                re.compile(r'rememberMe=', re.IGNORECASE),
                re.compile(r'shiro', re.IGNORECASE),
            ],
            'severity': 'Critical',
            'cve': 'CVE-2016-4437',
            'description': 'Apache Shiro RememberMe deserialization vulnerability',
        },
    }

    # Java Serialization Indicators
    SERIALIZATION_PATTERNS = [
        (re.compile(rb'\xac\xed\x00\x05', re.IGNORECASE), 'Java Serialized Object (raw bytes)'),
        (re.compile(r'rO0AB', re.IGNORECASE), 'Java Serialized Object (Base64)'),
        (re.compile(r'application/x-java-serialized-object', re.IGNORECASE), 'Java Serialization Content-Type'),
        (re.compile(r'java\.io\.Serializable', re.IGNORECASE), 'Java Serializable interface'),
        (re.compile(r'ObjectInputStream', re.IGNORECASE), 'Java ObjectInputStream usage'),
    ]

    # Expression Language (EL) Injection Indicators
    EL_PATTERNS = [
        (re.compile(r'\$\{[^}]+\}'), 'JSP/EL Expression'),
        (re.compile(r'#\{[^}]+\}'), 'JSF EL Expression'),
        (re.compile(r'\%\{[^}]+\}'), 'OGNL Expression (Struts)'),
        (re.compile(r'\*\{[^}]+\}'), 'Thymeleaf Expression'),
        (re.compile(r'T\([^)]+\)'), 'SpEL Type Expression'),
    ]

    # Debug/Development Mode Indicators
    DEBUG_PATTERNS = [
        re.compile(r'javax\.faces\.PROJECT_STAGE.*Development', re.IGNORECASE),
        re.compile(r'struts\.devMode.*true', re.IGNORECASE),
        re.compile(r'DEBUG.*true', re.IGNORECASE),
        re.compile(r'spring\.profiles\.active.*dev', re.IGNORECASE),
        re.compile(r'/actuator(?:/|$)', re.IGNORECASE),
        re.compile(r'__debug__', re.IGNORECASE),
    ]

    # Sensitive Endpoints
    SENSITIVE_ENDPOINTS = [
        (r'/manager/html', 'Tomcat Manager'),
        (r'/jmx-console', 'JBoss JMX Console'),
        (r'/admin-console', 'JBoss Admin Console'),
        (r'/web-console', 'JBoss Web Console'),
        (r'/status', 'Status Page'),
        (r'/console', 'WebLogic Console'),
        (r'/ibm/console', 'WebSphere Console'),
        (r'/actuator', 'Spring Boot Actuator'),
        (r'/jolokia', 'Jolokia (JMX over HTTP)'),
        (r'/probe', 'PSI Probe'),
        (r'/swagger', 'Swagger API Docs'),
        (r'/api-docs', 'API Documentation'),
    ]

    @classmethod
    def detect(cls, response_text: str, url: str, headers: Dict[str, str] = None) -> Tuple[bool, List[Dict[str, Any]]]:
        """
        Detect Java technologies and vulnerabilities.

        Args:
            response_text: HTTP response body
            url: URL being analyzed
            headers: HTTP response headers

        Returns:
            Tuple of (found_java, list_of_findings)
        """
        findings = []

        headers = headers or {}

        # Combine headers and body for analysis
        full_content = response_text
        for key, value in headers.items():
            full_content += f"\n{key}: {value}"

        # Detect servers
        server_findings = cls._detect_servers(full_content, url, headers)
        findings.extend(server_findings)

        # Detect frameworks
        framework_findings = cls._detect_frameworks(full_content, url)
        findings.extend(framework_findings)

        # Check for vulnerable versions
        vuln_findings = cls._check_vulnerabilities(full_content, url)
        findings.extend(vuln_findings)

        # Check for serialization indicators
        serial_findings = cls._check_serialization(response_text, url)
        findings.extend(serial_findings)

        # Check for EL injection contexts
        el_findings = cls._check_el_contexts(response_text, url)
        findings.extend(el_findings)

        # Check for debug mode
        debug_findings = cls._check_debug_mode(full_content, url)
        findings.extend(debug_findings)

        # Check for sensitive endpoints
        endpoint_findings = cls._check_sensitive_endpoints(url, response_text)
        findings.extend(endpoint_findings)

        return len(findings) > 0, findings

    @classmethod
    def _detect_servers(cls, content: str, url: str, headers: Dict[str, str]) -> List[Dict[str, Any]]:
        """Detect Java application servers"""
        findings = []

        for server_name, patterns in cls.SERVER_PATTERNS.items():
            for pattern in patterns:
                match = pattern.search(content)
                if match:
                    version = match.group(1) if match.lastindex else 'unknown'

                    findings.append({
                        'type': 'Java Application Server Detected',
                        'severity': 'Info',
                        'url': url,
                        'server': server_name,
                        'version': version,
                        'description': f'{server_name} application server detected{" (version: " + version + ")" if version != "unknown" else ""}',
                        'category': 'java_server',
                        'location': 'Response Headers/Body',
                        'recommendation': 'Ensure server is up-to-date. Remove version information from production.'
                    })
                    break

        return findings

    @classmethod
    def _detect_frameworks(cls, content: str, url: str) -> List[Dict[str, Any]]:
        """Detect Java frameworks"""
        findings = []

        for framework_name, patterns in cls.FRAMEWORK_PATTERNS.items():
            for pattern in patterns:
                if pattern.search(content):
                    findings.append({
                        'type': 'Java Framework Detected',
                        'severity': 'Info',
                        'url': url,
                        'framework': framework_name,
                        'description': f'{framework_name} detected',
                        'category': 'java_framework',
                        'location': 'Response Body',
                        'recommendation': f'Ensure {framework_name} is updated to latest version. '
                                         f'Check for known vulnerabilities.'
                    })
                    break

        return findings

    @classmethod
    def _check_vulnerabilities(cls, content: str, url: str) -> List[Dict[str, Any]]:
        """Check for known vulnerable versions"""
        findings = []

        for vuln_name, vuln_info in cls.VULNERABLE_PATTERNS.items():
            for pattern in vuln_info['patterns']:
                match = pattern.search(content)
                if match:
                    findings.append({
                        'type': 'Potential Vulnerable Version',
                        'severity': vuln_info['severity'],
                        'url': url,
                        'vulnerability': vuln_name,
                        'cve': vuln_info['cve'],
                        'matched': match.group(0),
                        'description': vuln_info['description'],
                        'category': 'java_cve',
                        'location': 'Response Body',
                        'recommendation': f'Verify version and update immediately if vulnerable. '
                                         f'Check {vuln_info["cve"]} for details.'
                    })
                    break

        return findings

    @classmethod
    def _check_serialization(cls, content: str, url: str) -> List[Dict[str, Any]]:
        """Check for Java serialization indicators"""
        findings = []

        for pattern, desc in cls.SERIALIZATION_PATTERNS:
            if pattern.search(content.encode() if isinstance(content, str) else content):
                findings.append({
                    'type': 'Java Serialization Detected',
                    'severity': 'Medium',
                    'url': url,
                    'indicator': desc,
                    'description': f'{desc} detected. Java deserialization vulnerabilities may be present.',
                    'category': 'java_serialization',
                    'location': 'Response Body',
                    'recommendation': 'Test for Java deserialization vulnerabilities. '
                                     'Use ysoserial for exploitation testing.'
                })
                break

        return findings

    @classmethod
    def _check_el_contexts(cls, content: str, url: str) -> List[Dict[str, Any]]:
        """Check for Expression Language injection contexts"""
        findings = []

        for pattern, desc in cls.EL_PATTERNS:
            matches = pattern.findall(content)
            if matches:
                findings.append({
                    'type': 'Expression Language Context',
                    'severity': 'Low',
                    'url': url,
                    'el_type': desc,
                    'examples': matches[:3],
                    'description': f'{desc} detected. Test for Expression Language Injection.',
                    'category': 'java_el',
                    'location': 'Response Body',
                    'recommendation': 'Test for EL injection by injecting expressions like ${7*7}.'
                })
                break

        return findings

    @classmethod
    def _check_debug_mode(cls, content: str, url: str) -> List[Dict[str, Any]]:
        """Check for debug/development mode indicators"""
        findings = []

        for pattern in cls.DEBUG_PATTERNS:
            match = pattern.search(content)
            if match:
                findings.append({
                    'type': 'Debug/Development Mode',
                    'severity': 'Medium',
                    'url': url,
                    'indicator': match.group(0)[:100],
                    'description': 'Application appears to be in debug/development mode. '
                                  'May expose sensitive information or enable additional attack vectors.',
                    'category': 'java_debug',
                    'location': 'Response Body',
                    'recommendation': 'Disable debug mode in production. '
                                     'Review configuration for development settings.'
                })
                break

        return findings

    @classmethod
    def _check_sensitive_endpoints(cls, url: str, content: str) -> List[Dict[str, Any]]:
        """Check for sensitive administrative endpoints"""
        findings = []

        parsed = urlparse(url)
        path = parsed.path.lower()

        for endpoint_pattern, endpoint_name in cls.SENSITIVE_ENDPOINTS:
            if re.search(endpoint_pattern, path, re.IGNORECASE):
                # Check if endpoint returned content (not 404)
                if not re.search(r'404|not found|error', content[:500], re.IGNORECASE):
                    findings.append({
                        'type': 'Sensitive Endpoint Accessible',
                        'severity': 'High',
                        'url': url,
                        'endpoint': endpoint_name,
                        'description': f'{endpoint_name} endpoint is accessible. '
                                      f'May allow administrative access or information disclosure.',
                        'category': 'java_admin_endpoint',
                        'location': 'URL Path',
                        'recommendation': f'Restrict access to {endpoint_name}. '
                                         f'Implement authentication and IP whitelisting.'
                    })

        return findings


def detect_java(response_text: str, url: str, headers: Dict[str, str] = None) -> Tuple[bool, List[Dict[str, Any]]]:
    """Convenience function for Java/J2EE detection"""
    return JavaDetector.detect(response_text, url, headers)
