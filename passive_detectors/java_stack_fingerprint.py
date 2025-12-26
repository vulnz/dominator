"""
Java Stack Trace Fingerprinting Module

Passively analyzes Java stack traces to fingerprint:
- Java version and vendor (Oracle, OpenJDK, IBM, etc.)
- Application server version (Tomcat, JBoss, WebLogic, etc.)
- Framework versions (Spring, Struts, Hibernate, etc.)
- Library versions from package names
- Internal application structure

Stack traces reveal significant information about the application:
- Package names indicate frameworks and libraries
- Line numbers can help identify specific versions
- Class names reveal architecture patterns
- Method names expose business logic

Reference: OWASP Information Disclosure
"""

import re
from typing import Dict, List, Tuple, Any, Optional, Set
from dataclasses import dataclass


@dataclass
class JavaVersion:
    """Parsed Java version information"""
    major: int
    minor: int = 0
    patch: int = 0
    vendor: str = "Unknown"
    full_string: str = ""


class JavaStackFingerprint:
    """
    Java Stack Trace Fingerprinting Engine

    Extracts technology and version information from Java stack traces.
    """

    # Stack trace detection patterns
    STACK_TRACE_PATTERNS = [
        re.compile(r'at\s+[\w.$]+\([\w.]+:\d+\)', re.MULTILINE),
        re.compile(r'(?:java|javax|org|com)\.[\w.]+Exception', re.IGNORECASE),
        re.compile(r'Caused by:\s*[\w.]+Exception', re.IGNORECASE),
        re.compile(r'^\s+at\s+[\w.$]+\.[\w$]+\([^)]+\)', re.MULTILINE),
    ]

    # Java version patterns in stack traces and headers
    JAVA_VERSION_PATTERNS = [
        # From X-Powered-By or Server headers
        re.compile(r'Java[/\s]*([\d._]+)', re.IGNORECASE),
        re.compile(r'JRE[/\s]*([\d._]+)', re.IGNORECASE),
        re.compile(r'JDK[/\s]*([\d._]+)', re.IGNORECASE),
        # From stack traces
        re.compile(r'java\.version[=:\s]*([\d._]+)', re.IGNORECASE),
        re.compile(r'Java\(TM\)\s+SE\s+Runtime\s+Environment[^(]*\(([\d._]+)', re.IGNORECASE),
        re.compile(r'OpenJDK\s+Runtime\s+Environment[^(]*\(([\d._]+)', re.IGNORECASE),
        re.compile(r'java\.runtime\.version[=:\s]*([\d._\-+]+)', re.IGNORECASE),
    ]

    # JVM vendor patterns
    JVM_VENDOR_PATTERNS = {
        'Oracle': [
            re.compile(r'Oracle\s+Corporation', re.IGNORECASE),
            re.compile(r'Java\(TM\)\s+SE', re.IGNORECASE),
            re.compile(r'HotSpot\(TM\)', re.IGNORECASE),
        ],
        'OpenJDK': [
            re.compile(r'OpenJDK', re.IGNORECASE),
            re.compile(r'AdoptOpenJDK', re.IGNORECASE),
            re.compile(r'Eclipse\s+Adoptium', re.IGNORECASE),
            re.compile(r'Temurin', re.IGNORECASE),
        ],
        'IBM': [
            re.compile(r'IBM\s+Corporation', re.IGNORECASE),
            re.compile(r'IBM\s+J9', re.IGNORECASE),
            re.compile(r'com\.ibm\.', re.IGNORECASE),
        ],
        'Amazon Corretto': [
            re.compile(r'Amazon\.com', re.IGNORECASE),
            re.compile(r'Corretto', re.IGNORECASE),
        ],
        'Azul Zulu': [
            re.compile(r'Azul\s+Systems', re.IGNORECASE),
            re.compile(r'Zulu', re.IGNORECASE),
        ],
        'Red Hat': [
            re.compile(r'Red\s+Hat', re.IGNORECASE),
        ],
        'SAP': [
            re.compile(r'SAP\s+AG', re.IGNORECASE),
            re.compile(r'SapMachine', re.IGNORECASE),
        ],
        'GraalVM': [
            re.compile(r'GraalVM', re.IGNORECASE),
            re.compile(r'org\.graalvm', re.IGNORECASE),
        ],
    }

    # Application server fingerprints from stack traces
    APP_SERVER_FINGERPRINTS = {
        'Apache Tomcat': {
            'packages': ['org.apache.catalina', 'org.apache.coyote', 'org.apache.tomcat'],
            'version_patterns': [
                re.compile(r'Apache\s+Tomcat[/\s]*([\d.]+)', re.IGNORECASE),
                re.compile(r'Tomcat[/\s]*([\d.]+)', re.IGNORECASE),
                re.compile(r'catalina\.home[=:\s]*[^\s]*tomcat[^\s]*([\d.]+)', re.IGNORECASE),
            ],
            'class_hints': ['CoyoteAdapter', 'StandardWrapper', 'ApplicationFilterChain'],
        },
        'JBoss/WildFly': {
            'packages': ['org.jboss', 'io.undertow', 'org.wildfly'],
            'version_patterns': [
                re.compile(r'JBoss[/\s]*([\d.]+)', re.IGNORECASE),
                re.compile(r'WildFly[/\s]*([\d.]+)', re.IGNORECASE),
                re.compile(r'Undertow[/\s]*([\d.]+)', re.IGNORECASE),
            ],
            'class_hints': ['DeploymentManager', 'WeldContainer'],
        },
        'Oracle WebLogic': {
            'packages': ['weblogic.', 'com.bea.', 'oracle.weblogic'],
            'version_patterns': [
                re.compile(r'WebLogic\s+Server[/\s]*([\d.]+)', re.IGNORECASE),
                re.compile(r'weblogic[/\s]*([\d.]+)', re.IGNORECASE),
            ],
            'class_hints': ['ServerRuntime', 'WebLogicCluster'],
        },
        'IBM WebSphere': {
            'packages': ['com.ibm.ws', 'com.ibm.websphere'],
            'version_patterns': [
                re.compile(r'WebSphere[/\s]*([\d.]+)', re.IGNORECASE),
            ],
            'class_hints': ['WsServerImpl', 'WASLoaderImpl'],
        },
        'Oracle GlassFish': {
            'packages': ['org.glassfish', 'com.sun.enterprise'],
            'version_patterns': [
                re.compile(r'GlassFish[/\s]*([\d.]+)', re.IGNORECASE),
            ],
            'class_hints': ['ApplicationLifecycle', 'GlassFishRuntime'],
        },
        'Jetty': {
            'packages': ['org.eclipse.jetty', 'org.mortbay.jetty'],
            'version_patterns': [
                re.compile(r'Jetty[/\s]*([\d.]+)', re.IGNORECASE),
            ],
            'class_hints': ['ServletHandler', 'JettyServer'],
        },
        'Payara': {
            'packages': ['fish.payara'],
            'version_patterns': [
                re.compile(r'Payara[/\s]*([\d.]+)', re.IGNORECASE),
            ],
            'class_hints': ['PayaraExecutorService'],
        },
        'Resin': {
            'packages': ['com.caucho'],
            'version_patterns': [
                re.compile(r'Resin[/\s]*([\d.]+)', re.IGNORECASE),
            ],
            'class_hints': ['ResinServer'],
        },
    }

    # Framework fingerprints
    FRAMEWORK_FINGERPRINTS = {
        'Spring Framework': {
            'packages': ['org.springframework'],
            'version_patterns': [
                re.compile(r'spring-(?:core|web|webmvc)[/\-]*([\d.]+)', re.IGNORECASE),
                re.compile(r'org\.springframework\..*\s+([\d.]+\.RELEASE)', re.IGNORECASE),
            ],
            'class_hints': ['DispatcherServlet', 'ApplicationContext', 'BeanFactory'],
            'cves': {
                '5.3.0-5.3.17': 'CVE-2022-22965 (Spring4Shell)',
                '5.2.0-5.2.19': 'CVE-2022-22965 (Spring4Shell)',
            }
        },
        'Spring Boot': {
            'packages': ['org.springframework.boot'],
            'version_patterns': [
                re.compile(r'spring-boot[/\-]*([\d.]+)', re.IGNORECASE),
            ],
            'class_hints': ['SpringApplication', 'AutoConfiguration'],
        },
        'Spring Security': {
            'packages': ['org.springframework.security'],
            'version_patterns': [
                re.compile(r'spring-security[/\-]*([\d.]+)', re.IGNORECASE),
            ],
            'class_hints': ['SecurityFilterChain', 'AuthenticationManager'],
        },
        'Apache Struts': {
            'packages': ['org.apache.struts', 'org.apache.struts2'],
            'version_patterns': [
                re.compile(r'struts[/\-]*([\d.]+)', re.IGNORECASE),
                re.compile(r'Struts[/\s]*([\d.]+)', re.IGNORECASE),
            ],
            'class_hints': ['ActionSupport', 'StrutsActionProxy', 'OgnlValueStack'],
            'cves': {
                '2.0.0-2.3.31': 'CVE-2017-5638 (S2-045 RCE)',
                '2.3.0-2.3.34': 'CVE-2017-9805 (S2-052 RCE)',
                '2.0.0-2.5.12': 'CVE-2018-11776 (S2-057 RCE)',
            }
        },
        'Hibernate': {
            'packages': ['org.hibernate'],
            'version_patterns': [
                re.compile(r'hibernate[/\-]*([\d.]+)', re.IGNORECASE),
            ],
            'class_hints': ['SessionFactory', 'EntityManager', 'HibernateProxy'],
        },
        'MyBatis': {
            'packages': ['org.apache.ibatis', 'org.mybatis'],
            'version_patterns': [
                re.compile(r'mybatis[/\-]*([\d.]+)', re.IGNORECASE),
            ],
            'class_hints': ['SqlSession', 'MappedStatement'],
        },
        'Apache CXF': {
            'packages': ['org.apache.cxf'],
            'version_patterns': [
                re.compile(r'cxf[/\-]*([\d.]+)', re.IGNORECASE),
            ],
            'class_hints': ['CXFServlet', 'JAXRSServerFactoryBean'],
        },
        'Jersey (JAX-RS)': {
            'packages': ['org.glassfish.jersey', 'com.sun.jersey'],
            'version_patterns': [
                re.compile(r'jersey[/\-]*([\d.]+)', re.IGNORECASE),
            ],
            'class_hints': ['ResourceConfig', 'ContainerRequest'],
        },
        'Apache Wicket': {
            'packages': ['org.apache.wicket'],
            'version_patterns': [
                re.compile(r'wicket[/\-]*([\d.]+)', re.IGNORECASE),
            ],
            'class_hints': ['WicketFilter', 'WebApplication'],
        },
        'Vaadin': {
            'packages': ['com.vaadin'],
            'version_patterns': [
                re.compile(r'vaadin[/\-]*([\d.]+)', re.IGNORECASE),
            ],
            'class_hints': ['VaadinServlet', 'VaadinSession'],
        },
        'JSF (JavaServer Faces)': {
            'packages': ['javax.faces', 'jakarta.faces', 'com.sun.faces'],
            'version_patterns': [
                re.compile(r'jsf[/\-]*([\d.]+)', re.IGNORECASE),
                re.compile(r'mojarra[/\-]*([\d.]+)', re.IGNORECASE),
            ],
            'class_hints': ['FacesServlet', 'UIViewRoot'],
        },
        'Primefaces': {
            'packages': ['org.primefaces'],
            'version_patterns': [
                re.compile(r'primefaces[/\-]*([\d.]+)', re.IGNORECASE),
            ],
            'class_hints': ['PrimeFacesContext'],
        },
        'Apache Shiro': {
            'packages': ['org.apache.shiro'],
            'version_patterns': [
                re.compile(r'shiro[/\-]*([\d.]+)', re.IGNORECASE),
            ],
            'class_hints': ['SecurityManager', 'ShiroFilter'],
            'cves': {
                '1.0.0-1.5.3': 'CVE-2020-1957 (Auth Bypass)',
                '1.0.0-1.7.0': 'CVE-2020-11989 (Path Traversal)',
            }
        },
        'Log4j': {
            'packages': ['org.apache.logging.log4j', 'org.apache.log4j'],
            'version_patterns': [
                re.compile(r'log4j[/\-]*([\d.]+)', re.IGNORECASE),
            ],
            'class_hints': ['LogManager', 'Logger', 'PatternLayout'],
            'cves': {
                '2.0-2.14.1': 'CVE-2021-44228 (Log4Shell RCE)',
                '2.0-2.16.0': 'CVE-2021-45046 (Log4Shell Bypass)',
            }
        },
        'Jackson': {
            'packages': ['com.fasterxml.jackson'],
            'version_patterns': [
                re.compile(r'jackson[/\-]*([\d.]+)', re.IGNORECASE),
            ],
            'class_hints': ['ObjectMapper', 'JsonParser'],
            'cves': {
                '2.0.0-2.9.10.7': 'Multiple deserialization CVEs',
            }
        },
        'XStream': {
            'packages': ['com.thoughtworks.xstream'],
            'version_patterns': [
                re.compile(r'xstream[/\-]*([\d.]+)', re.IGNORECASE),
            ],
            'class_hints': ['XStream'],
            'cves': {
                '1.4.0-1.4.17': 'CVE-2021-39144 (RCE)',
            }
        },
        'Fastjson': {
            'packages': ['com.alibaba.fastjson'],
            'version_patterns': [
                re.compile(r'fastjson[/\-]*([\d.]+)', re.IGNORECASE),
            ],
            'class_hints': ['JSON', 'JSONObject'],
            'cves': {
                '1.2.0-1.2.80': 'Multiple RCE vulnerabilities',
            }
        },
    }

    # Library fingerprints from package names
    LIBRARY_FINGERPRINTS = {
        'Apache Commons Collections': {
            'packages': ['org.apache.commons.collections'],
            'cves': {'3.0-3.2.1': 'Deserialization RCE (ysoserial)'}
        },
        'Apache Commons BeanUtils': {
            'packages': ['org.apache.commons.beanutils'],
        },
        'Apache Commons IO': {
            'packages': ['org.apache.commons.io'],
        },
        'Apache Commons Lang': {
            'packages': ['org.apache.commons.lang'],
        },
        'Apache Commons FileUpload': {
            'packages': ['org.apache.commons.fileupload'],
        },
        'Apache POI': {
            'packages': ['org.apache.poi'],
        },
        'iText PDF': {
            'packages': ['com.itextpdf', 'com.lowagie.text'],
        },
        'Bouncy Castle': {
            'packages': ['org.bouncycastle'],
        },
        'Apache HttpClient': {
            'packages': ['org.apache.http.client', 'org.apache.commons.httpclient'],
        },
        'OkHttp': {
            'packages': ['okhttp3', 'com.squareup.okhttp'],
        },
        'Gson': {
            'packages': ['com.google.gson'],
        },
        'Guava': {
            'packages': ['com.google.common'],
        },
        'Lombok': {
            'packages': ['lombok'],
        },
        'SLF4J': {
            'packages': ['org.slf4j'],
        },
        'Logback': {
            'packages': ['ch.qos.logback'],
        },
        'Quartz Scheduler': {
            'packages': ['org.quartz'],
        },
        'Ehcache': {
            'packages': ['net.sf.ehcache', 'org.ehcache'],
        },
        'JUnit': {
            'packages': ['org.junit', 'junit.framework'],
        },
        'TestNG': {
            'packages': ['org.testng'],
        },
        'Mockito': {
            'packages': ['org.mockito'],
        },
        'AspectJ': {
            'packages': ['org.aspectj'],
        },
        'CGLib': {
            'packages': ['net.sf.cglib', 'cglib'],
        },
        'Javassist': {
            'packages': ['javassist'],
        },
        'OGNL': {
            'packages': ['ognl'],
        },
        'Velocity': {
            'packages': ['org.apache.velocity'],
        },
        'FreeMarker': {
            'packages': ['freemarker'],
        },
        'Thymeleaf': {
            'packages': ['org.thymeleaf'],
        },
        'JSTL': {
            'packages': ['javax.servlet.jsp.jstl', 'org.apache.taglibs'],
        },
    }

    # Exception types that reveal information
    EXCEPTION_FINGERPRINTS = {
        'SQL/Database': [
            'java.sql.SQLException',
            'org.hibernate.exception',
            'javax.persistence.PersistenceException',
            'com.mysql.jdbc',
            'org.postgresql',
            'oracle.jdbc',
            'com.microsoft.sqlserver',
        ],
        'Authentication/Authorization': [
            'org.springframework.security.authentication',
            'org.apache.shiro.authc',
            'javax.security.auth',
            'java.security.AccessControlException',
        ],
        'Serialization': [
            'java.io.NotSerializableException',
            'java.io.InvalidClassException',
            'java.io.StreamCorruptedException',
            'com.fasterxml.jackson',
            'org.codehaus.jackson',
        ],
        'XML Processing': [
            'javax.xml.parsers',
            'org.xml.sax.SAXException',
            'javax.xml.transform',
            'org.w3c.dom.DOMException',
        ],
        'JNDI/RMI': [
            'javax.naming.NamingException',
            'java.rmi.RemoteException',
            'javax.naming.directory',
        ],
        'Class Loading': [
            'java.lang.ClassNotFoundException',
            'java.lang.NoClassDefFoundError',
            'java.lang.NoSuchMethodError',
        ],
        'File Operations': [
            'java.io.FileNotFoundException',
            'java.nio.file.NoSuchFileException',
            'java.io.IOException',
        ],
        'Network': [
            'java.net.ConnectException',
            'java.net.UnknownHostException',
            'java.net.SocketException',
        ],
    }

    @classmethod
    def detect(cls, response_text: str, url: str,
               headers: Dict[str, str] = None) -> Tuple[bool, List[Dict[str, Any]]]:
        """
        Analyze response for Java stack traces and fingerprint technologies.

        Args:
            response_text: HTTP response body
            url: URL being analyzed
            headers: HTTP response headers

        Returns:
            Tuple of (found_fingerprints, list_of_findings)
        """
        findings = []

        if not response_text:
            return False, findings

        headers = headers or {}

        # First check if there's a stack trace
        stack_traces = cls._extract_stack_traces(response_text)

        if not stack_traces:
            # Also check headers for Java indicators
            header_findings = cls._analyze_headers(headers, url)
            if header_findings:
                findings.extend(header_findings)
                return len(findings) > 0, findings
            return False, findings

        # Analyze each stack trace
        for trace in stack_traces:
            # Extract Java version
            java_version = cls._extract_java_version(trace, headers)
            if java_version:
                findings.append(cls._create_java_version_finding(java_version, url))

            # Extract JVM vendor
            vendor = cls._extract_jvm_vendor(trace, headers)
            if vendor:
                findings.append(cls._create_vendor_finding(vendor, url))

            # Extract packages from stack trace
            packages = cls._extract_packages(trace)

            # Identify application server
            app_server = cls._identify_app_server(trace, packages, headers)
            if app_server:
                findings.append(app_server)

            # Identify frameworks
            framework_findings = cls._identify_frameworks(trace, packages, url)
            findings.extend(framework_findings)

            # Identify libraries
            library_findings = cls._identify_libraries(packages, url)
            findings.extend(library_findings)

            # Analyze exception types
            exception_findings = cls._analyze_exceptions(trace, url)
            findings.extend(exception_findings)

            # Extract internal package structure
            internal_findings = cls._analyze_internal_structure(packages, url)
            if internal_findings:
                findings.extend(internal_findings)

        # Add stack trace disclosure finding
        if stack_traces:
            findings.insert(0, {
                'type': 'Java Stack Trace Disclosure',
                'severity': 'Medium',
                'url': url,
                'stack_trace_count': len(stack_traces),
                'sample': stack_traces[0][:500] if stack_traces else '',
                'description': f'{len(stack_traces)} Java stack trace(s) found. '
                              f'Stack traces reveal internal application structure.',
                'category': 'java_stack_disclosure',
                'location': 'Response Body',
                'recommendation': 'Configure error handling to suppress stack traces in production. '
                                 'Use custom error pages. Set appropriate debug flags.'
            })

        # Deduplicate findings
        seen = set()
        unique_findings = []
        for finding in findings:
            key = f"{finding['type']}:{finding.get('technology', finding.get('version', ''))}"
            if key not in seen:
                seen.add(key)
                unique_findings.append(finding)

        return len(unique_findings) > 0, unique_findings

    @classmethod
    def _extract_stack_traces(cls, content: str) -> List[str]:
        """Extract Java stack traces from content"""
        traces = []

        # Pattern for full stack trace blocks
        full_trace = re.compile(
            r'(?:Exception|Error|Throwable)[^\n]*\n(?:\s+at\s+[\w.$]+\([^)]+\)\n?)+',
            re.MULTILINE
        )

        for match in full_trace.finditer(content):
            traces.append(match.group(0))

        # Also check for partial traces
        if not traces:
            for pattern in cls.STACK_TRACE_PATTERNS:
                if pattern.search(content):
                    # Extract surrounding context
                    matches = pattern.findall(content)
                    if matches:
                        # Try to get more context
                        start = content.find(matches[0])
                        if start != -1:
                            end = min(start + 2000, len(content))
                            traces.append(content[start:end])
                        break

        return traces

    @classmethod
    def _extract_java_version(cls, trace: str, headers: Dict[str, str]) -> Optional[JavaVersion]:
        """Extract Java version from trace or headers"""
        # Check headers first
        header_text = ' '.join(f"{k}: {v}" for k, v in headers.items())
        combined = f"{header_text}\n{trace}"

        for pattern in cls.JAVA_VERSION_PATTERNS:
            match = pattern.search(combined)
            if match:
                version_str = match.group(1)
                return cls._parse_java_version(version_str)

        return None

    @classmethod
    def _parse_java_version(cls, version_str: str) -> JavaVersion:
        """Parse Java version string into components"""
        # Handle various formats: 1.8.0_292, 11.0.11, 17.0.1+12, etc.
        version_str = version_str.replace('_', '.')
        parts = re.split(r'[.\-+]', version_str)

        try:
            if parts[0] == '1':
                # Old format (1.8.0 = Java 8)
                major = int(parts[1]) if len(parts) > 1 else 0
                minor = int(parts[2]) if len(parts) > 2 else 0
                patch = int(parts[3]) if len(parts) > 3 else 0
            else:
                # New format (11.0.11 = Java 11)
                major = int(parts[0])
                minor = int(parts[1]) if len(parts) > 1 else 0
                patch = int(parts[2]) if len(parts) > 2 else 0

            return JavaVersion(
                major=major,
                minor=minor,
                patch=patch,
                full_string=version_str
            )
        except (ValueError, IndexError):
            return JavaVersion(major=0, full_string=version_str)

    @classmethod
    def _extract_jvm_vendor(cls, trace: str, headers: Dict[str, str]) -> Optional[str]:
        """Extract JVM vendor from trace or headers"""
        header_text = ' '.join(f"{k}: {v}" for k, v in headers.items())
        combined = f"{header_text}\n{trace}"

        for vendor, patterns in cls.JVM_VENDOR_PATTERNS.items():
            for pattern in patterns:
                if pattern.search(combined):
                    return vendor

        return None

    @classmethod
    def _extract_packages(cls, trace: str) -> Set[str]:
        """Extract package names from stack trace"""
        packages = set()

        # Match "at com.example.ClassName.method(File.java:123)"
        at_pattern = re.compile(r'at\s+([\w.$]+)\.[A-Z][\w$]*\.[^(]+\(')

        for match in at_pattern.finditer(trace):
            full_path = match.group(1)
            # Get package (everything before last component which is class name)
            parts = full_path.rsplit('.', 1)
            if len(parts) > 1:
                packages.add(parts[0])
            packages.add(full_path)

        # Also extract from exception class names
        exception_pattern = re.compile(r'([\w.]+(?:Exception|Error))')
        for match in exception_pattern.finditer(trace):
            exc_class = match.group(1)
            parts = exc_class.rsplit('.', 1)
            if len(parts) > 1:
                packages.add(parts[0])

        return packages

    @classmethod
    def _identify_app_server(cls, trace: str, packages: Set[str],
                            headers: Dict[str, str]) -> Optional[Dict[str, Any]]:
        """Identify application server from stack trace"""
        header_text = ' '.join(f"{k}: {v}" for k, v in headers.items())
        combined = f"{header_text}\n{trace}"

        for server_name, config in cls.APP_SERVER_FINGERPRINTS.items():
            # Check packages
            for pkg in config['packages']:
                if any(p.startswith(pkg) or pkg in p for p in packages):
                    version = None

                    # Try to extract version
                    for pattern in config.get('version_patterns', []):
                        match = pattern.search(combined)
                        if match:
                            version = match.group(1)
                            break

                    return {
                        'type': 'Application Server Identified',
                        'severity': 'Info',
                        'url': '',  # Will be set by caller
                        'technology': server_name,
                        'version': version or 'Unknown',
                        'description': f'{server_name} detected' +
                                      (f' version {version}' if version else ''),
                        'category': 'java_app_server',
                        'location': 'Stack Trace',
                        'recommendation': 'Verify application server is up to date. '
                                         'Check for known vulnerabilities in detected version.'
                    }

            # Check class hints
            for hint in config.get('class_hints', []):
                if hint in trace:
                    return {
                        'type': 'Application Server Identified',
                        'severity': 'Info',
                        'url': '',
                        'technology': server_name,
                        'version': 'Unknown',
                        'description': f'{server_name} detected (from class: {hint})',
                        'category': 'java_app_server',
                        'location': 'Stack Trace',
                        'recommendation': 'Verify application server is up to date.'
                    }

        return None

    @classmethod
    def _identify_frameworks(cls, trace: str, packages: Set[str],
                            url: str) -> List[Dict[str, Any]]:
        """Identify frameworks from stack trace"""
        findings = []
        detected = set()

        for framework_name, config in cls.FRAMEWORK_FINGERPRINTS.items():
            if framework_name in detected:
                continue

            # Check packages
            for pkg in config['packages']:
                if any(p.startswith(pkg) or pkg in p for p in packages):
                    detected.add(framework_name)
                    version = None

                    # Try to extract version
                    for pattern in config.get('version_patterns', []):
                        match = pattern.search(trace)
                        if match:
                            version = match.group(1)
                            break

                    # Check for known CVEs
                    cve_warning = None
                    if version and 'cves' in config:
                        for version_range, cve_info in config['cves'].items():
                            if cls._version_in_range(version, version_range):
                                cve_warning = cve_info
                                break

                    finding = {
                        'type': 'Framework Identified',
                        'severity': 'High' if cve_warning else 'Low',
                        'url': url,
                        'technology': framework_name,
                        'version': version or 'Unknown',
                        'description': f'{framework_name} detected' +
                                      (f' version {version}' if version else ''),
                        'category': 'java_framework',
                        'location': 'Stack Trace',
                        'recommendation': 'Keep framework updated to latest stable version.'
                    }

                    if cve_warning:
                        finding['cve'] = cve_warning
                        finding['description'] += f'. VULNERABLE: {cve_warning}'
                        finding['recommendation'] = f'URGENT: Update {framework_name}! {cve_warning}'

                    findings.append(finding)
                    break

            # Check class hints if not already detected
            if framework_name not in detected:
                for hint in config.get('class_hints', []):
                    if hint in trace:
                        detected.add(framework_name)
                        findings.append({
                            'type': 'Framework Identified',
                            'severity': 'Low',
                            'url': url,
                            'technology': framework_name,
                            'version': 'Unknown',
                            'description': f'{framework_name} detected (from class: {hint})',
                            'category': 'java_framework',
                            'location': 'Stack Trace',
                            'recommendation': 'Keep framework updated.'
                        })
                        break

        return findings

    @classmethod
    def _identify_libraries(cls, packages: Set[str], url: str) -> List[Dict[str, Any]]:
        """Identify libraries from package names"""
        findings = []
        detected = set()

        for lib_name, config in cls.LIBRARY_FINGERPRINTS.items():
            if lib_name in detected:
                continue

            for pkg in config['packages']:
                if any(p.startswith(pkg) or pkg in p for p in packages):
                    detected.add(lib_name)

                    cve_warning = None
                    if 'cves' in config:
                        # Without version, just note potential vulnerability
                        cve_warning = list(config['cves'].values())[0]

                    finding = {
                        'type': 'Library Identified',
                        'severity': 'Medium' if cve_warning else 'Info',
                        'url': url,
                        'technology': lib_name,
                        'description': f'{lib_name} detected in stack trace',
                        'category': 'java_library',
                        'location': 'Stack Trace',
                        'recommendation': 'Verify library version is not vulnerable.'
                    }

                    if cve_warning:
                        finding['potential_cve'] = cve_warning
                        finding['description'] += f'. Check for: {cve_warning}'

                    findings.append(finding)
                    break

        return findings

    @classmethod
    def _analyze_exceptions(cls, trace: str, url: str) -> List[Dict[str, Any]]:
        """Analyze exception types in stack trace"""
        findings = []
        detected_categories = set()

        for category, exception_patterns in cls.EXCEPTION_FINGERPRINTS.items():
            if category in detected_categories:
                continue

            for pattern in exception_patterns:
                if pattern in trace:
                    detected_categories.add(category)

                    severity = 'Low'
                    if category in ['SQL/Database', 'Authentication/Authorization',
                                   'Serialization', 'JNDI/RMI']:
                        severity = 'Medium'

                    findings.append({
                        'type': f'{category} Exception Disclosed',
                        'severity': severity,
                        'url': url,
                        'exception_category': category,
                        'exception_type': pattern,
                        'description': f'{category} related exception exposed. '
                                      f'May reveal sensitive information about {category.lower()} operations.',
                        'category': 'java_exception_disclosure',
                        'location': 'Stack Trace',
                        'recommendation': f'Handle {category.lower()} exceptions gracefully. '
                                         f'Do not expose internal error details.'
                    })
                    break

        return findings

    @classmethod
    def _analyze_internal_structure(cls, packages: Set[str],
                                    url: str) -> List[Dict[str, Any]]:
        """Analyze internal package structure from stack trace"""
        findings = []

        # Look for internal/custom package names (not standard libraries)
        internal_packages = set()

        for pkg in packages:
            # Skip known libraries
            is_known = False
            for framework in cls.FRAMEWORK_FINGERPRINTS.values():
                if any(pkg.startswith(p) for p in framework['packages']):
                    is_known = True
                    break

            if not is_known:
                for lib in cls.LIBRARY_FINGERPRINTS.values():
                    if any(pkg.startswith(p) for p in lib['packages']):
                        is_known = True
                        break

            # Skip standard packages
            standard_prefixes = ['java.', 'javax.', 'jakarta.', 'sun.', 'com.sun.']
            if any(pkg.startswith(p) for p in standard_prefixes):
                is_known = True

            if not is_known and '.' in pkg:
                # This is likely an internal/custom package
                internal_packages.add(pkg)

        if internal_packages:
            # Extract likely organization/domain from packages
            domains = set()
            for pkg in internal_packages:
                parts = pkg.split('.')
                if len(parts) >= 2:
                    if parts[0] in ['com', 'org', 'net', 'io']:
                        domains.add('.'.join(parts[:2]))
                    else:
                        domains.add(parts[0])

            findings.append({
                'type': 'Internal Package Structure Disclosed',
                'severity': 'Low',
                'url': url,
                'internal_packages': list(internal_packages)[:10],
                'possible_domains': list(domains),
                'description': f'Internal package structure revealed: {", ".join(list(internal_packages)[:5])}...',
                'category': 'java_internal_structure',
                'location': 'Stack Trace',
                'recommendation': 'Internal package names can reveal organization structure '
                                 'and help attackers understand application architecture.'
            })

        return findings

    @classmethod
    def _analyze_headers(cls, headers: Dict[str, str], url: str) -> List[Dict[str, Any]]:
        """Analyze headers for Java indicators without stack trace"""
        findings = []

        # Check X-Powered-By
        powered_by = headers.get('X-Powered-By', '') or headers.get('x-powered-by', '')
        if 'java' in powered_by.lower() or 'servlet' in powered_by.lower():
            findings.append({
                'type': 'Java Technology in Headers',
                'severity': 'Info',
                'url': url,
                'header': powered_by,
                'description': f'Java technology disclosed in X-Powered-By: {powered_by}',
                'category': 'java_header_disclosure',
                'location': 'Response Header',
                'recommendation': 'Remove X-Powered-By header to reduce information disclosure.'
            })

        # Check Server header
        server = headers.get('Server', '') or headers.get('server', '')
        java_servers = ['tomcat', 'jboss', 'wildfly', 'weblogic', 'websphere',
                       'glassfish', 'jetty', 'resin', 'payara']
        for srv in java_servers:
            if srv in server.lower():
                findings.append({
                    'type': 'Java Server in Headers',
                    'severity': 'Info',
                    'url': url,
                    'header': server,
                    'description': f'Java application server in Server header: {server}',
                    'category': 'java_server_disclosure',
                    'location': 'Response Header',
                    'recommendation': 'Consider masking Server header to reduce fingerprinting.'
                })
                break

        return findings

    @classmethod
    def _create_java_version_finding(cls, version: JavaVersion, url: str) -> Dict[str, Any]:
        """Create finding for Java version disclosure"""
        severity = 'Low'
        recommendation = 'Keep Java runtime updated.'

        # Check for EOL versions
        eol_versions = {8: 'LTS but check patch level', 7: 'End of Life',
                       6: 'End of Life', 5: 'End of Life'}

        if version.major in eol_versions:
            if version.major <= 7:
                severity = 'Medium'
                recommendation = f'Java {version.major} is End of Life. Upgrade to supported version.'

        return {
            'type': 'Java Version Identified',
            'severity': severity,
            'url': url,
            'version': f'{version.major}.{version.minor}.{version.patch}',
            'full_version': version.full_string,
            'description': f'Java version {version.full_string} detected',
            'category': 'java_version',
            'location': 'Stack Trace/Headers',
            'recommendation': recommendation
        }

    @classmethod
    def _create_vendor_finding(cls, vendor: str, url: str) -> Dict[str, Any]:
        """Create finding for JVM vendor disclosure"""
        return {
            'type': 'JVM Vendor Identified',
            'severity': 'Info',
            'url': url,
            'vendor': vendor,
            'description': f'JVM vendor detected: {vendor}',
            'category': 'java_vendor',
            'location': 'Stack Trace/Headers',
            'recommendation': 'JVM vendor information can help attackers target specific vulnerabilities.'
        }

    @classmethod
    def _version_in_range(cls, version: str, range_str: str) -> bool:
        """Check if version falls within vulnerable range"""
        # Simple range check (format: "start-end")
        try:
            parts = range_str.split('-')
            if len(parts) != 2:
                return False

            start, end = parts

            # Normalize versions for comparison
            def normalize(v):
                return [int(x) for x in re.findall(r'\d+', v)]

            v = normalize(version)
            s = normalize(start)
            e = normalize(end)

            # Pad to same length
            max_len = max(len(v), len(s), len(e))
            v.extend([0] * (max_len - len(v)))
            s.extend([0] * (max_len - len(s)))
            e.extend([0] * (max_len - len(e)))

            return s <= v <= e
        except:
            return False


def fingerprint_java_stack(response_text: str, url: str,
                           headers: Dict[str, str] = None) -> Tuple[bool, List[Dict[str, Any]]]:
    """Convenience function for Java stack trace fingerprinting"""
    return JavaStackFingerprint.detect(response_text, url, headers)
