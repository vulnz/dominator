"""
Base64 Detection Scanner
Detects Base64 encoded data (excluding images) that may contain sensitive information
"""

from core.base_module import BaseModule
from core.logger import get_logger
from typing import List, Dict, Any
from urllib.parse import urlparse
import re
import base64

logger = get_logger(__name__)


class Base64Detector(BaseModule):
    """Scans for Base64 encoded data that may expose sensitive information"""

    def __init__(self, module_path: str, payload_limit: int = None):
        super().__init__(module_path, payload_limit=payload_limit)
        self.module_name = "Base64 Detector"
        self.logger = logger

        # Minimum length for base64 strings to check (shorter ones are usually not interesting)
        self.min_length = 20

        # Patterns to exclude (legitimate uses of base64)
        self.exclude_patterns = [
            # Data URLs for images
            r'data:image/[^;]+;base64,',
            r'data:img/[^;]+;base64,',
            # Font data URLs
            r'data:font/[^;]+;base64,',
            r'data:application/font[^;]*;base64,',
            # Audio/Video
            r'data:audio/[^;]+;base64,',
            r'data:video/[^;]+;base64,',
            # SRI hashes
            r'integrity\s*=\s*[\'"]sha',
            # CSS/SVG inline
            r'data:image/svg\+xml;base64,',
            # Source maps
            r'sourceMappingURL=data:',
        ]

        # Sensitive patterns to look for in decoded content
        self.sensitive_indicators = [
            'password', 'passwd', 'secret', 'api_key', 'apikey', 'token',
            'private', 'credential', 'auth', 'session', 'cookie',
            'username', 'user', 'admin', 'root', 'config', 'database',
            'mysql', 'postgres', 'mongodb', 'redis', 'connection',
            'BEGIN RSA', 'BEGIN PRIVATE', 'BEGIN CERTIFICATE',
            'aws_access', 'aws_secret', 'bearer', 'basic ',
        ]

    def scan(self, targets: List[Dict[str, Any]], http_client: Any = None) -> List[Dict[str, Any]]:
        """Scan for Base64 encoded data"""
        self.logger.info(f"Starting {self.module_name} scan on {len(targets)} targets")

        results = []
        tested_urls = set()

        for target in targets:
            url = target.get('url') if isinstance(target, dict) else target
            if not url:
                continue

            if url in tested_urls:
                continue
            tested_urls.add(url)

            findings = self._scan_page(http_client, url)
            results.extend(findings)

            if self.payload_limit and len(results) >= self.payload_limit:
                break

        self.logger.info(f"{self.module_name} scan complete: {len(results)} findings")
        return results

    def _scan_page(self, http_client, url: str) -> List[Dict[str, Any]]:
        """Scan a single page for Base64 encoded data"""
        results = []

        try:
            response = http_client.get(url)
            if not response or response.status_code != 200:
                return results

            content = response.text
            if not content or len(content) < 50:
                return results

            # Remove excluded patterns (images, fonts, etc.)
            clean_content = content
            for pattern in self.exclude_patterns:
                clean_content = re.sub(pattern + r'[A-Za-z0-9+/=]+', '', clean_content, flags=re.IGNORECASE)

            # Find all potential base64 strings
            # Base64 pattern: at least min_length chars, ends with 0-2 = padding
            base64_pattern = r'[A-Za-z0-9+/]{' + str(self.min_length) + r',}={0,2}'
            matches = re.findall(base64_pattern, clean_content)

            # Deduplicate and filter
            unique_b64 = []
            seen = set()
            for match in matches:
                if match not in seen and self._is_valid_base64(match):
                    seen.add(match)
                    unique_b64.append(match)

            if not unique_b64:
                return results

            # Analyze each base64 string
            sensitive_findings = []
            generic_findings = []

            for b64_string in unique_b64[:50]:  # Limit analysis
                decoded, is_sensitive, decoded_preview = self._analyze_base64(b64_string)

                if decoded:
                    finding = {
                        'encoded': b64_string[:80] + ('...' if len(b64_string) > 80 else ''),
                        'decoded_preview': decoded_preview,
                        'length': len(b64_string),
                        'is_sensitive': is_sensitive
                    }

                    if is_sensitive:
                        sensitive_findings.append(finding)
                    else:
                        generic_findings.append(finding)

            # Report sensitive findings with higher severity - WITH ACTUAL PROOF
            if sensitive_findings:
                # Build detailed evidence with actual decoded content
                evidence_parts = [f"Found {len(sensitive_findings)} Base64 strings containing sensitive data:\n"]
                for i, finding in enumerate(sensitive_findings[:5], 1):
                    evidence_parts.append(f"\n[{i}] Encoded: {finding['encoded']}")
                    evidence_parts.append(f"    Decoded: {finding['decoded_preview']}")

                results.append(self.create_result(
                    vulnerable=True,
                    url=url,
                    parameter='Response Body',
                    payload=sensitive_findings[0]['encoded'][:50] if sensitive_findings else 'Base64',
                    evidence='\n'.join(evidence_parts),
                    severity='Medium',
                    method='GET',
                    additional_info={
                        'injection_type': 'Sensitive Data in Base64',
                        'count': len(sensitive_findings),
                        'findings': sensitive_findings[:10],
                        'description': 'Base64 encoded strings contain potentially sensitive information',
                        'cwe': 'CWE-200',
                        'owasp': 'A01:2021',
                        'recommendation': 'Review Base64 encoded data for sensitive information exposure'
                    }
                ))

            # Only report generic base64 if there's actual meaningful content
            # Skip generic findings - they don't provide actionable security value
            # Only sensitive base64 with decoded proof is reported

            # Also check for base64 in URL parameters
            parsed = urlparse(url)
            if parsed.query:
                param_b64_findings = self._check_url_params(url, parsed.query)
                results.extend(param_b64_findings)

        except Exception as e:
            self.logger.debug(f"Error scanning {url}: {e}")

        return results

    def _is_valid_base64(self, s: str) -> bool:
        """Check if string is valid base64 - STRICT validation to reduce false positives"""
        # Must be multiple of 4 (with padding)
        if len(s) % 4 != 0:
            # Try adding padding
            s += '=' * (4 - len(s) % 4)

        # Must have reasonable entropy (not all same char)
        unique_chars = len(set(s.replace('=', '')))
        if unique_chars < 15:  # Increased from 10 - stricter
            return False

        # Skip if looks like a hash (all hex chars)
        hex_chars = set('0123456789abcdefABCDEF')
        if all(c in hex_chars for c in s.replace('=', '')):
            return False

        # Skip common patterns that look like base64 but aren't
        if s.startswith('AAAA') or s.endswith('AAAA'):
            return False

        # Try to decode
        try:
            decoded = base64.b64decode(s)
            # Must decode to meaningful length
            if len(decoded) < 10:
                return False

            # Check if decoded content is reasonable
            # If it's mostly printable or valid UTF-8, it's likely real base64
            try:
                text = decoded.decode('utf-8')
                # Must have high printable ratio AND look like real text
                printable_ratio = sum(1 for c in text if c.isprintable() or c in '\n\r\t') / len(text)
                if printable_ratio < 0.8:  # Increased from 0.7 - stricter
                    return False
                # Must have some word-like content (spaces or common chars)
                if len(text) > 20 and ' ' not in text and '=' not in text and ':' not in text:
                    return False
                return True
            except:
                # Not UTF-8 - only accept if it looks like meaningful binary
                # Skip random-looking binary data
                return False
        except:
            return False

    def _analyze_base64(self, b64_string: str) -> tuple:
        """Analyze a base64 string for sensitive content"""
        try:
            # Ensure proper padding
            padded = b64_string
            if len(padded) % 4 != 0:
                padded += '=' * (4 - len(padded) % 4)

            decoded = base64.b64decode(padded)

            # Try to decode as text
            try:
                text = decoded.decode('utf-8')
            except:
                try:
                    text = decoded.decode('latin-1')
                except:
                    return None, False, None

            # Check for sensitive indicators
            text_lower = text.lower()
            is_sensitive = any(indicator in text_lower for indicator in self.sensitive_indicators)

            # Create preview (truncated and sanitized)
            preview = text[:100].replace('\n', ' ').replace('\r', ' ')
            if len(text) > 100:
                preview += '...'

            return text, is_sensitive, preview

        except Exception as e:
            return None, False, None

    def _check_url_params(self, url: str, query: str) -> List[Dict[str, Any]]:
        """Check URL parameters for base64 encoded values"""
        results = []

        try:
            from urllib.parse import parse_qs, unquote

            params = parse_qs(query)
            for param_name, values in params.items():
                for value in values:
                    decoded_value = unquote(value)
                    if len(decoded_value) >= self.min_length and self._is_valid_base64(decoded_value):
                        text, is_sensitive, preview = self._analyze_base64(decoded_value)
                        if text:
                            severity = 'Medium' if is_sensitive else 'Info'
                            results.append(self.create_result(
                                vulnerable=True,
                                url=url,
                                parameter=param_name,
                                payload=decoded_value[:50] + '...',
                                evidence=f"URL parameter '{param_name}' contains Base64 data: {preview}",
                                severity=severity,
                                method='GET',
                                additional_info={
                                    'injection_type': 'Base64 in URL Parameter',
                                    'parameter': param_name,
                                    'decoded_preview': preview,
                                    'is_sensitive': is_sensitive,
                                    'cwe': 'CWE-200',
                                    'owasp': 'A01:2021'
                                }
                            ))

        except Exception as e:
            self.logger.debug(f"Error checking URL params: {e}")

        return results


def get_module(module_path: str, payload_limit: int = None):
    """Factory function to create module instance"""
    return Base64Detector(module_path, payload_limit=payload_limit)
