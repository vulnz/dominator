"""
Prototype Pollution Scanner Module

Detects client-side and server-side prototype pollution vulnerabilities:
1. Identifies vulnerable JavaScript libraries (jQuery BBQ, deparam, etc.)
2. Tests prototype pollution payloads via query/hash/JSON
3. Detects pollution through response analysis

Based on BlackFan's client-side-prototype-pollution research:
https://github.com/BlackFan/client-side-prototype-pollution
"""

from typing import List, Dict, Any, Set
from core.base_module import BaseModule
from core.logger import get_logger
from urllib.parse import urlparse, urlencode, parse_qs
import re
import json

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

    def __init__(self, module_path: str, payload_limit: int = None):
        """Initialize Prototype Pollution module"""
        super().__init__(module_path, payload_limit=payload_limit)
        self.tested_urls: Set[str] = set()
        logger.info(f"Prototype Pollution module loaded: {len(self.payloads)} payloads")

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

            # Test prototype pollution payloads
            payload_findings = self._test_pollution_payloads(url, http_client)
            results.extend(payload_findings)

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
                return self.create_result(
                    vulnerable=True,
                    url=url,
                    parameter='__proto__',
                    payload=payload,
                    evidence=evidence,
                    description=f"Prototype pollution via query parameter: {payload.split('=')[0]}",
                    confidence=0.80
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
                return self.create_result(
                    vulnerable=True,
                    url=url,
                    parameter='JSON Body',
                    payload=payload,
                    evidence=evidence,
                    description="Prototype pollution via JSON body",
                    confidence=0.75
                )

        except json.JSONDecodeError:
            pass
        except Exception as e:
            logger.debug(f"Error testing JSON pollution: {e}")

        return None

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
