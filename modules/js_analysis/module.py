"""
JavaScript Analysis Module

Analyzes JavaScript files for:
- API keys, secrets, tokens leaked in JS
- Hardcoded credentials
- Internal endpoints/URLs
- Cloud bucket references (S3, Azure, GCP)
- Source maps exposure
- Vue.js/React debug mode detection
- Sensitive data in webpack/build artifacts

Based on SecretFinder patterns.
"""

from typing import List, Dict, Any, Set
from core.base_module import BaseModule
from core.logger import get_logger
from urllib.parse import urlparse, urljoin
import re

logger = get_logger(__name__)


class JSAnalysisModule(BaseModule):
    """JavaScript file analyzer for secrets and misconfigurations"""

    # Regex patterns for secrets/sensitive data
    # IMPORTANT: Patterns must be specific to avoid false positives
    SECRET_PATTERNS = {
        # API Keys - HIGH CONFIDENCE patterns only
        'AWS Access Key': r'(?<![A-Z0-9])AKIA[0-9A-Z]{16}(?![A-Z0-9])',
        'Google API Key': r'AIza[0-9A-Za-z\-_]{35}',
        'Slack Token': r'xox[baprs]-[0-9a-zA-Z]{10,48}',
        'Slack Webhook': r'https://hooks\.slack\.com/services/T[a-zA-Z0-9_]{8}/B[a-zA-Z0-9_]{8}/[a-zA-Z0-9_]{24}',
        'GitHub Token': r'gh[pousr]_[A-Za-z0-9_]{36,}',
        'Stripe Secret Key': r'sk_live_[0-9a-zA-Z]{24,}',
        'Stripe Publishable': r'pk_live_[0-9a-zA-Z]{24,}',
        'Twilio API Key': r'SK[0-9a-fA-F]{32}',
        'SendGrid API Key': r'SG\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9_-]{43}',
        'JWT Token': r'eyJ[A-Za-z0-9-_]{10,}\.eyJ[A-Za-z0-9-_]{10,}\.[A-Za-z0-9-_.+/=]{10,}',
        'Private Key': r'-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----',

        # Cloud Storage - specific patterns
        'S3 Bucket': r'[a-z0-9][a-z0-9.-]{2,62}\.s3\.amazonaws\.com',
        'Azure Blob': r'[a-z0-9]{3,24}\.blob\.core\.windows\.net',
        'Firebase DB': r'[a-z0-9-]+\.firebaseio\.com',

        # Database connection strings with credentials
        'MongoDB URI with Auth': r'mongodb(?:\+srv)?://[^:]+:[^@]+@[^\s"\']+',
        'MySQL URI with Auth': r'mysql://[^:]+:[^@]+@[^\s"\']+',
        'PostgreSQL URI with Auth': r'postgres(?:ql)?://[^:]+:[^@]+@[^\s"\']+',

        # REMOVED patterns that cause false positives:
        # - 'AWS Secret Key' - too generic (40 chars alphanumeric)
        # - 'GitHub OAuth' - too generic (40 hex chars)
        # - 'Heroku API Key' - matches UUIDs
        # - 'Password Field' - matches form fields, not actual passwords
        # - 'API Key Generic' - matches configuration keys
        # - 'Internal IP' - matches legitimate internal references
        # - 'Localhost URL' - development environments
    }

    # Debug mode indicators
    DEBUG_INDICATORS = {
        'React DevTools': [
            '__REACT_DEVTOOLS_GLOBAL_HOOK__',
            'ReactDevtoolsExtension',
            '__REDUX_DEVTOOLS_EXTENSION__',
        ],
        'Vue DevTools': [
            '__VUE_DEVTOOLS_GLOBAL_HOOK__',
            'Vue.config.devtools',
            '__VUE__',
        ],
        'Angular Debug': [
            'ng.probe',
            'angular.reloadWithDebugInfo',
            'ng-reflect-',
        ],
        'Source Maps': [
            '//# sourceMappingURL=',
            '//@ sourceMappingURL=',
            '.map',
        ],
        'Debug Console': [
            'console.log(',
            'console.debug(',
            'console.trace(',
            'debugger;',
        ],
        'Webpack DevServer': [
            'webpack-dev-server',
            'hot-update.json',
            '__webpack_hmr',
        ],
    }

    def __init__(self, module_path: str, payload_limit: int = None):
        """Initialize JS Analysis module"""
        super().__init__(module_path, payload_limit=payload_limit)
        logger.info("JS Analysis module loaded")

    def scan(self, targets: List[Dict[str, Any]], http_client: Any) -> List[Dict[str, Any]]:
        """
        Analyze JavaScript files for secrets and misconfigurations

        Args:
            targets: List of URLs (will find and analyze JS files)
            http_client: HTTP client

        Returns:
            List of findings
        """
        results = []
        analyzed_js = set()

        logger.info(f"Starting JS Analysis on {len(targets)} targets")

        for target in targets:
            url = target.get('url', '')

            # Get the page and find JS files
            try:
                response = http_client.get(url)
                if not response:
                    continue

                html = getattr(response, 'text', '')

                # Find JS file URLs
                js_files = self._find_js_files(url, html)
                logger.debug(f"Found {len(js_files)} JS files on {url}")

                # Also check inline scripts
                inline_results = self._analyze_inline_scripts(url, html)
                results.extend(inline_results)

                # Analyze each external JS file
                for js_url in js_files:
                    if js_url in analyzed_js:
                        continue
                    analyzed_js.add(js_url)

                    js_results = self._analyze_js_file(js_url, http_client)
                    results.extend(js_results)

                    # Check for source maps
                    sourcemap_results = self._check_source_maps(js_url, http_client)
                    results.extend(sourcemap_results)

            except Exception as e:
                logger.debug(f"Error analyzing {url}: {e}")

        logger.info(f"JS Analysis complete: {len(results)} issues found")
        return results

    def _find_js_files(self, base_url: str, html: str) -> Set[str]:
        """Extract JavaScript file URLs from HTML"""
        js_files = set()

        # Find script src attributes
        script_pattern = r'<script[^>]+src=["\']([^"\']+)["\']'
        for match in re.finditer(script_pattern, html, re.IGNORECASE):
            src = match.group(1)
            if src.endswith('.js') or '.js?' in src:
                full_url = urljoin(base_url, src)
                js_files.add(full_url)

        return js_files

    def _analyze_js_file(self, js_url: str, http_client: Any) -> List[Dict]:
        """Analyze a JavaScript file for secrets"""
        results = []

        try:
            response = http_client.get(js_url, timeout=10)
            if not response or response.status_code != 200:
                return results

            js_content = getattr(response, 'text', '')
            if not js_content:
                return results

            # Check for secrets
            for secret_type, pattern in self.SECRET_PATTERNS.items():
                matches = re.findall(pattern, js_content)
                for match in matches[:3]:  # Limit to 3 matches per type
                    # Skip false positives
                    if self._is_false_positive(secret_type, match):
                        continue

                    severity = self._get_severity(secret_type)
                    result = self.create_result(
                        vulnerable=True,
                        url=js_url,
                        parameter='JavaScript',
                        payload=f"{secret_type}: {match[:50]}...",
                        evidence=f"Sensitive data found in JavaScript!\n\n"
                                f"Type: {secret_type}\n"
                                f"File: {js_url}\n"
                                f"Match: {match[:100]}...\n",
                        description=f"{secret_type} exposed in JavaScript file",
                        confidence=0.90
                    )
                    result['severity'] = severity
                    result['cwe'] = 'CWE-200'
                    result['owasp'] = 'A01:2021'
                    result['secret_type'] = secret_type
                    results.append(result)
                    logger.info(f"Found {secret_type} in {js_url}")

            # Check for debug indicators
            for debug_type, indicators in self.DEBUG_INDICATORS.items():
                for indicator in indicators:
                    if indicator in js_content:
                        result = self.create_result(
                            vulnerable=True,
                            url=js_url,
                            parameter='JavaScript',
                            payload=f"{debug_type}: {indicator}",
                            evidence=f"Debug mode indicator found!\n\n"
                                    f"Type: {debug_type}\n"
                                    f"Indicator: {indicator}\n"
                                    f"File: {js_url}",
                            description=f"{debug_type} detected - may expose source code or debug info",
                            confidence=0.85
                        )
                        result['severity'] = 'medium' if 'Source Map' in debug_type else 'low'
                        result['cwe'] = 'CWE-489'
                        result['owasp'] = 'A05:2021'
                        results.append(result)
                        break  # One indicator per type is enough

        except Exception as e:
            logger.debug(f"Error analyzing JS file {js_url}: {e}")

        return results

    def _analyze_inline_scripts(self, url: str, html: str) -> List[Dict]:
        """Analyze inline JavaScript for secrets"""
        results = []

        # Extract inline script content
        inline_pattern = r'<script[^>]*>([^<]+)</script>'
        for match in re.finditer(inline_pattern, html, re.IGNORECASE | re.DOTALL):
            script_content = match.group(1)

            # Check for secrets in inline scripts
            for secret_type, pattern in self.SECRET_PATTERNS.items():
                matches = re.findall(pattern, script_content)
                for secret_match in matches[:2]:
                    if self._is_false_positive(secret_type, secret_match):
                        continue

                    result = self.create_result(
                        vulnerable=True,
                        url=url,
                        parameter='Inline JavaScript',
                        payload=f"{secret_type}: {secret_match[:50]}...",
                        evidence=f"Sensitive data in inline JavaScript!\n\n"
                                f"Type: {secret_type}\n"
                                f"Page: {url}\n"
                                f"Match: {secret_match[:100]}...",
                        description=f"{secret_type} exposed in inline JavaScript",
                        confidence=0.90
                    )
                    result['severity'] = self._get_severity(secret_type)
                    result['cwe'] = 'CWE-200'
                    results.append(result)

        return results

    def _check_source_maps(self, js_url: str, http_client: Any) -> List[Dict]:
        """Check if source maps are exposed"""
        results = []

        # Try common source map URLs
        map_urls = [
            f"{js_url}.map",
            js_url.replace('.js', '.js.map'),
            js_url.replace('.min.js', '.js.map'),
        ]

        for map_url in map_urls:
            try:
                response = http_client.get(map_url, timeout=5)
                if response and response.status_code == 200:
                    content = getattr(response, 'text', '')
                    if '"sources"' in content or '"mappings"' in content:
                        result = self.create_result(
                            vulnerable=True,
                            url=map_url,
                            parameter='Source Map',
                            payload=map_url,
                            evidence=f"Source map file exposed!\n\n"
                                    f"URL: {map_url}\n"
                                    f"Original JS: {js_url}\n\n"
                                    f"Source maps expose original source code!",
                            description="JavaScript source map exposed - original source code accessible",
                            confidence=0.95
                        )
                        result['severity'] = 'medium'
                        result['cwe'] = 'CWE-540'
                        result['owasp'] = 'A05:2021'
                        results.append(result)
                        logger.info(f"Found source map: {map_url}")
                        break
            except:
                pass

        return results

    def _is_false_positive(self, secret_type: str, match: str) -> bool:
        """Check for common false positives - ENHANCED"""
        # Skip example/placeholder values
        false_positive_patterns = [
            'example', 'test', 'demo', 'placeholder', 'your-', 'your_',
            'xxx', 'XXXX', '000000', '123456', 'sample', 'dummy',
            'fake', 'mock', 'stub', 'replace', 'insert', 'enter',
            'xxxxxxxx', 'abcdefgh', 'qwertyui', 'asdfghjk',
            'changeme', 'password123', 'admin123', 'secret123',
        ]

        match_lower = match.lower()
        for fp in false_positive_patterns:
            if fp in match_lower:
                return True

        # Skip very short matches
        if len(match) < 12:
            return True

        # Skip if it's all the same character repeated
        if len(set(match.replace('-', '').replace('_', ''))) < 6:
            return True

        # Skip Google Maps API keys (they are public/client-side by design)
        if secret_type == 'Google API Key' and match.startswith('AIzaSy'):
            # Google Maps API keys are intended to be public in client-side code
            return True

        # Skip publishable Stripe keys (they are designed to be public)
        if secret_type == 'Stripe Publishable':
            return True  # pk_live_* keys are meant to be exposed

        # Skip common CDN/vendor patterns
        cdn_patterns = ['cloudflare', 'challenge', 'captcha', 'recaptcha']
        for cdn in cdn_patterns:
            if cdn in match_lower:
                return True

        return False

    def _get_severity(self, secret_type: str) -> str:
        """Determine severity based on secret type"""
        high_risk = ['AWS', 'Private Key', 'Password', 'Stripe', 'MongoDB', 'MySQL', 'PostgreSQL']
        medium_risk = ['API Key', 'Token', 'S3', 'Azure', 'Firebase']

        for pattern in high_risk:
            if pattern in secret_type:
                return 'high'

        for pattern in medium_risk:
            if pattern in secret_type:
                return 'medium'

        return 'low'


def get_module(module_path: str, payload_limit: int = None):
    """Create module instance"""
    return JSAnalysisModule(module_path, payload_limit=payload_limit)
