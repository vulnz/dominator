"""
DOM XSS (Client-Side Cross-Site Scripting) Scanner Module

Detects DOM-based XSS vulnerabilities by:
1. Analyzing JavaScript code for dangerous sinks (innerHTML, document.write, eval, etc.)
2. Testing if URL parameters flow into these sinks
3. Detecting client-side execution without server reflection
"""

from typing import List, Dict, Any
from core.base_module import BaseModule
from core.logger import get_logger
import re

logger = get_logger(__name__)


class DOMXSSModule(BaseModule):
    """DOM-based XSS vulnerability scanner module"""

    def __init__(self, module_path: str):
        """Initialize DOM XSS module"""
        super().__init__(module_path)

        # Dangerous JavaScript sinks that can execute code
        self.dangerous_sinks = [
            # Direct execution
            'eval(',
            'setTimeout(',
            'setInterval(',
            'Function(',
            'execScript(',

            # DOM manipulation
            'innerHTML',
            'outerHTML',
            'document.write(',
            'document.writeln(',

            # Location manipulation
            'location.href',
            'location.assign(',
            'location.replace(',
            'window.location',

            # Script creation
            'createElement("script")',
            'createElement(\'script\')',

            # jQuery sinks
            '.html(',
            '.append(',
            '.after(',
            '.before(',

            # Other dangerous operations
            'insertAdjacentHTML(',
            'setAttribute(',
        ]

        # URL parameter sources that can be user-controlled
        self.url_sources = [
            'location.hash',
            'location.search',
            'document.URL',
            'document.documentURI',
            'document.URLUnencoded',
            'document.baseURI',
            'document.referrer',
            'window.name',
        ]

        logger.info(f"DOM XSS module loaded: {len(self.payloads)} payloads, "
                   f"{len(self.dangerous_sinks)} sinks, {len(self.url_sources)} sources")

    def scan(self, targets: List[Dict[str, Any]], http_client: Any) -> List[Dict[str, Any]]:
        """
        Scan for DOM XSS vulnerabilities

        Args:
            targets: List of URLs with parameters
            http_client: HTTP client

        Returns:
            List of results
        """
        results = []

        logger.info(f"Starting DOM XSS scan on {len(targets)} targets")

        # Collect JavaScript files from responses
        js_files = set()

        for target in targets[:50]:  # Analyze first 50 pages
            url = target.get('url')

            try:
                # Get page to extract JavaScript
                response = http_client.get(url)
                if not response:
                    continue

                response_text = getattr(response, 'text', '')

                # STAGE 1: Extract inline JavaScript
                inline_scripts = self._extract_inline_javascript(response_text)

                # STAGE 2: Extract external JavaScript file references
                external_js = self._extract_external_js_urls(response_text, url)
                js_files.update(external_js)

                # STAGE 3: Analyze inline JavaScript for DOM XSS patterns
                for script_content in inline_scripts:
                    detected, confidence, evidence, payload = self._analyze_javascript_for_dom_xss(
                        script_content, url, target.get('params', {})
                    )

                    if detected:
                        result = self.create_result(
                            vulnerable=True,
                            url=url,
                            parameter="DOM",
                            payload=payload,
                            evidence=evidence,
                            description="DOM-based Cross-Site Scripting (XSS) vulnerability detected. "
                                      "Client-side JavaScript uses user-controlled input in dangerous sink.",
                            confidence=confidence
                        )

                        result['cwe'] = self.config.get('cwe', 'CWE-79')
                        result['owasp'] = self.config.get('owasp', 'A03:2021')
                        result['cvss'] = self.config.get('cvss', '7.3')
                        result['xss_type'] = 'dom'

                        results.append(result)
                        logger.info(f"✓ DOM XSS found in {url} (confidence: {confidence:.2f})")

                        # Only report one DOM XSS per page
                        break

            except Exception as e:
                logger.debug(f"Error analyzing {url} for DOM XSS: {e}")
                continue

        # STAGE 4: Fetch and analyze external JavaScript files
        logger.info(f"Found {len(js_files)} external JS files to analyze")

        for js_url in list(js_files)[:20]:  # Analyze first 20 JS files
            try:
                js_response = http_client.get(js_url)
                if not js_response:
                    continue

                js_content = getattr(js_response, 'text', '')

                detected, confidence, evidence, payload = self._analyze_javascript_for_dom_xss(
                    js_content, js_url, {}
                )

                if detected:
                    result = self.create_result(
                        vulnerable=True,
                        url=js_url,
                        parameter="DOM",
                        payload=payload,
                        evidence=evidence,
                        description="DOM-based XSS vulnerability in external JavaScript file. "
                                  "Script uses user-controlled input in dangerous sink.",
                        confidence=confidence
                    )

                    result['cwe'] = 'CWE-79'
                    result['owasp'] = 'A03:2021'
                    result['cvss'] = '7.3'
                    result['xss_type'] = 'dom'

                    results.append(result)
                    logger.info(f"✓ DOM XSS found in JS file {js_url} (confidence: {confidence:.2f})")

            except Exception as e:
                logger.debug(f"Error analyzing JS file {js_url}: {e}")
                continue

        logger.info(f"DOM XSS scan complete: {len(results)} vulnerabilities found")
        return results

    def _extract_inline_javascript(self, html: str) -> List[str]:
        """
        Extract inline JavaScript from HTML

        Args:
            html: HTML content

        Returns:
            List of JavaScript code blocks
        """
        scripts = []

        # Extract <script> tags
        script_pattern = r'<script[^>]*>(.*?)</script>'
        matches = re.findall(script_pattern, html, re.DOTALL | re.IGNORECASE)
        scripts.extend(matches)

        # Extract inline event handlers
        event_pattern = r'on\w+\s*=\s*["\']([^"\']+)["\']'
        event_matches = re.findall(event_pattern, html, re.IGNORECASE)
        scripts.extend(event_matches)

        return scripts

    def _extract_external_js_urls(self, html: str, base_url: str) -> List[str]:
        """
        Extract external JavaScript file URLs

        Args:
            html: HTML content
            base_url: Base URL for relative paths

        Returns:
            List of JavaScript file URLs
        """
        js_urls = []

        # Extract <script src="...">
        src_pattern = r'<script[^>]+src\s*=\s*["\']([^"\']+)["\']'
        matches = re.findall(src_pattern, html, re.IGNORECASE)

        for match in matches:
            # Convert relative URLs to absolute
            if match.startswith('http'):
                js_urls.append(match)
            elif match.startswith('//'):
                js_urls.append('http:' + match)
            elif match.startswith('/'):
                # Extract domain from base_url
                domain_match = re.match(r'(https?://[^/]+)', base_url)
                if domain_match:
                    js_urls.append(domain_match.group(1) + match)
            else:
                # Relative path
                base_dir = base_url.rsplit('/', 1)[0]
                js_urls.append(base_dir + '/' + match)

        return js_urls

    def _analyze_javascript_for_dom_xss(self, js_code: str, url: str,
                                       params: Dict[str, Any]) -> tuple:
        """
        Analyze JavaScript code for DOM XSS patterns

        Returns:
            (detected: bool, confidence: float, evidence: str, payload: str)
        """
        if not js_code or len(js_code) < 10:
            return False, 0.0, "", ""

        # DETECTION METHOD 1: Source → Sink flow
        # Check if code reads from URL source AND writes to dangerous sink

        found_source = None
        found_sink = None

        for source in self.url_sources:
            if source in js_code:
                found_source = source
                break

        for sink in self.dangerous_sinks:
            if sink in js_code:
                found_sink = sink
                break

        if found_source and found_sink:
            # Check if there's a flow between source and sink
            # Look for patterns like: var x = location.hash; element.innerHTML = x;

            # Basic pattern: source assignment followed by sink usage
            source_assignment_pattern = rf'\w+\s*=\s*.*{re.escape(found_source)}'
            source_match = re.search(source_assignment_pattern, js_code)

            if source_match:
                # Variable that holds source data
                var_match = re.match(r'(\w+)\s*=', source_match.group(0))
                if var_match:
                    var_name = var_match.group(1)

                    # Check if this variable is used in sink
                    if var_name in js_code[js_code.find(found_sink):]:
                        confidence = 0.75

                        # Higher confidence if no sanitization detected
                        if not self._has_sanitization(js_code, var_name):
                            confidence = 0.85

                        evidence = f"DOM XSS pattern detected: {found_source} → {var_name} → {found_sink}. "
                        evidence += f"User-controlled data from '{found_source}' flows into dangerous sink '{found_sink}' "
                        evidence += f"via variable '{var_name}' without proper sanitization."

                        payload = self._generate_payload_for_sink(found_sink)

                        return True, confidence, evidence, payload

            # Even without variable tracking, source + sink is suspicious
            confidence = 0.60

            # Check if they're close together in code
            source_pos = js_code.find(found_source)
            sink_pos = js_code.find(found_sink)

            if abs(source_pos - sink_pos) < 500:  # Within 500 chars
                confidence = 0.70

            evidence = f"Potential DOM XSS: Code reads from '{found_source}' and uses '{found_sink}'. "
            evidence += f"This pattern may allow user-controlled data to flow into dangerous sink."

            payload = self._generate_payload_for_sink(found_sink)

            return True, confidence, evidence, payload

        # DETECTION METHOD 2: Direct dangerous patterns
        # Check for obviously dangerous code
        dangerous_patterns = [
            (r'eval\s*\(\s*location\.', 'eval(location...) - direct code execution', 0.90),
            (r'document\.write\s*\(\s*location\.', 'document.write(location...) - unfiltered output', 0.85),
            (r'innerHTML\s*=\s*location\.', 'innerHTML = location... - unfiltered HTML injection', 0.85),
            (r'\.html\s*\(\s*location\.', '.html(location...) - jQuery unfiltered injection', 0.85),
        ]

        for pattern, description, conf in dangerous_patterns:
            if re.search(pattern, js_code, re.IGNORECASE):
                evidence = f"Dangerous DOM XSS pattern: {description}"
                payload = "<script>alert('DOM_XSS')</script>"
                return True, conf, evidence, payload

        return False, 0.0, "", ""

    def _has_sanitization(self, js_code: str, var_name: str) -> bool:
        """
        Check if variable is sanitized before use

        Args:
            js_code: JavaScript code
            var_name: Variable name to check

        Returns:
            True if sanitization detected
        """
        sanitization_functions = [
            'encodeURIComponent',
            'encodeURI',
            'escape',
            'textContent',  # textContent doesn't execute HTML
            'innerText',    # innerText doesn't execute HTML
            'setAttribute',  # safer than innerHTML
            'DOMPurify',
            'sanitize',
            'htmlspecialchars',
            'strip_tags',
        ]

        # Check if variable is passed through sanitization function
        for func in sanitization_functions:
            if f"{func}({var_name}" in js_code or f"{func}( {var_name}" in js_code:
                return True

        return False

    def _generate_payload_for_sink(self, sink: str) -> str:
        """
        Generate appropriate payload for the detected sink

        Args:
            sink: Dangerous sink function

        Returns:
            Payload string
        """
        if 'eval' in sink or 'Function' in sink:
            return "alert(1)"
        elif 'innerHTML' in sink or 'outerHTML' in sink:
            return "<img src=x onerror=alert(1)>"
        elif 'document.write' in sink:
            return "<script>alert(1)</script>"
        elif 'location' in sink:
            return "javascript:alert(1)"
        elif '.html(' in sink:
            return "<img src=x onerror=alert(1)>"
        else:
            return "<script>alert(1)</script>"


def get_module(module_path: str):
    """Create module instance"""
    return DOMXSSModule(module_path)
