"""
JavaScript Framework Debug Mode Detection Module

Detects JavaScript frameworks running in development/debug mode:
- Vue.js DevTools enabled
- React DevTools / Development build
- Angular debug mode
- Next.js development mode
- Source maps exposed
- Webpack DevServer artifacts
- Hot Module Replacement (HMR) enabled

These misconfigurations can expose:
- Original source code via source maps
- Internal application state
- Debug information and stack traces
"""

from typing import List, Dict, Any, Set
from core.base_module import BaseModule
from core.logger import get_logger
from urllib.parse import urljoin, urlparse
import re
import json

logger = get_logger(__name__)


class JSFrameworkDebugModule(BaseModule):
    """JavaScript Framework Debug Mode Detection Module"""

    def __init__(self, module_path: str, payload_limit: int = None):
        """Initialize JS Framework Debug module"""
        super().__init__(module_path, payload_limit=payload_limit)

        self.checked_urls: Set[str] = set()

        # Initialize detection patterns
        self._init_patterns()

        logger.info(f"JS Framework Debug module loaded")

    def _init_patterns(self):
        """Initialize debug mode detection patterns"""

        # Vue.js debug indicators
        self.vue_patterns = {
            'Vue DevTools Hook': {
                'patterns': [r'__VUE_DEVTOOLS_GLOBAL_HOOK__', r'__VUE_DEVTOOLS_HOOK__'],
                'severity': 'Medium',
                'description': 'Vue DevTools global hook detected. Component state accessible.',
            },
            'Vue Development Mode': {
                'patterns': [r'Vue\.config\.devtools\s*=\s*true', r'You are running Vue in development mode'],
                'severity': 'Medium',
                'description': 'Vue.js running in development mode.',
            },
        }

        # React debug indicators
        self.react_patterns = {
            'React DevTools Hook': {
                'patterns': [r'__REACT_DEVTOOLS_GLOBAL_HOOK__', r'__REACT_DEVTOOLS_ATTACH__'],
                'severity': 'Medium',
                'description': 'React DevTools hook detected. Component tree accessible.',
            },
            'React Development Build': {
                'patterns': [r'react\.development\.js', r'react-dom\.development\.js', r'Download the React DevTools'],
                'severity': 'Medium',
                'description': 'React development build detected.',
            },
            'Redux DevTools': {
                'patterns': [r'__REDUX_DEVTOOLS_EXTENSION__', r'__REDUX_DEVTOOLS_EXTENSION_COMPOSE__'],
                'severity': 'High',
                'description': 'Redux DevTools enabled. Full application state visible.',
            },
        }

        # Angular debug indicators
        self.angular_patterns = {
            'Angular Debug Mode': {
                'patterns': [r'ng\.probe', r'ng\.getComponent', r'getAllAngularTestabilities'],
                'severity': 'Medium',
                'description': 'Angular debug mode enabled.',
            },
            'Angular Development Build': {
                'patterns': [r'ng-reflect-', r'NG_DEV_MODE'],
                'severity': 'Medium',
                'description': 'Angular development build with debug bindings.',
            },
        }

        # Next.js debug indicators
        self.nextjs_patterns = {
            'Next.js Development Mode': {
                'patterns': [r'/_next/static/development/', r'"buildId":\s*"development"', r'/_next/webpack-hmr'],
                'severity': 'Medium',
                'description': 'Next.js running in development mode.',
            },
        }

        # Generic debug patterns
        self.generic_patterns = {
            'Source Maps Exposed': {
                'patterns': [r'//[#@]\s*sourceMappingURL=([^\s]+\.map)'],
                'severity': 'High',
                'description': 'JavaScript source maps exposed. Original source code downloadable.',
                'check_source_map': True,
            },
            'Webpack DevServer': {
                'patterns': [r'webpack-dev-server', r'__webpack_hmr', r'webpack/hot/'],
                'severity': 'High',
                'description': 'Webpack DevServer artifacts detected.',
            },
            'Hot Module Replacement': {
                'patterns': [r'hot-update\.json', r'module\.hot\.accept', r'import\.meta\.hot'],
                'severity': 'Medium',
                'description': 'Hot Module Replacement (HMR) enabled.',
            },
            'Console Debug Statements': {
                'patterns': [r'console\.debug\s*\(', r'debugger\s*;'],
                'severity': 'Low',
                'description': 'Debug console statements in production code.',
            },
            'Vite Development': {
                'patterns': [r'/@vite/client', r'__VITE_IS_MODERN__'],
                'severity': 'Medium',
                'description': 'Vite development server detected.',
            },
        }

    def scan(self, targets: List[Dict[str, Any]], http_client: Any) -> List[Dict[str, Any]]:
        """
        Scan for JavaScript framework debug mode

        Args:
            targets: List of URLs
            http_client: HTTP client

        Returns:
            List of vulnerability results
        """
        results = []
        self.checked_urls = set()

        # Get unique base URLs
        base_urls = set()
        for target in targets:
            url = target.get('url', '')
            if url:
                parsed = urlparse(url)
                base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
                base_urls.add(base_url)

        logger.info(f"Scanning {len(base_urls)} URLs for JS framework debug mode")

        for url in base_urls:
            if self.should_stop():
                break

            try:
                response = http_client.get(url)
                if not response:
                    continue

                html = getattr(response, 'text', '') or ''

                # Check main page HTML
                page_results = self._check_content(url, html, 'HTML')
                results.extend(page_results)

                # Find and check JS files
                js_files = self._find_js_files(url, html)

                for js_url in js_files[:20]:
                    if js_url in self.checked_urls:
                        continue
                    self.checked_urls.add(js_url)

                    js_results = self._check_js_file(js_url, http_client)
                    results.extend(js_results)

                # Check for source maps
                sourcemap_results = self._check_source_maps(url, html, js_files, http_client)
                results.extend(sourcemap_results)

            except Exception as e:
                logger.debug(f"Error scanning {url}: {e}")

        logger.info(f"JS Framework Debug scan complete: {len(results)} issues found")
        return results

    def _find_js_files(self, base_url: str, html: str) -> List[str]:
        """Extract JavaScript file URLs from HTML"""
        js_files = []

        pattern = r'<script[^>]+src=["\']([^"\']+)["\']'
        for match in re.finditer(pattern, html, re.IGNORECASE):
            src = match.group(1)
            if src:
                full_url = urljoin(base_url, src)
                if full_url not in js_files:
                    js_files.append(full_url)

        return js_files

    def _check_js_file(self, js_url: str, http_client: Any) -> List[Dict[str, Any]]:
        """Check a JavaScript file for debug indicators"""
        results = []

        try:
            response = http_client.get(js_url, timeout=10)
            if not response or response.status_code != 200:
                return results

            content = getattr(response, 'text', '') or ''
            if not content:
                return results

            results = self._check_content(js_url, content, 'JavaScript')

        except Exception as e:
            logger.debug(f"Error checking {js_url}: {e}")

        return results

    def _check_content(self, url: str, content: str, content_type: str) -> List[Dict[str, Any]]:
        """Check content for all debug patterns"""
        results = []

        all_patterns = {
            'Vue.js': self.vue_patterns,
            'React': self.react_patterns,
            'Angular': self.angular_patterns,
            'Next.js': self.nextjs_patterns,
            'Generic': self.generic_patterns,
        }

        for framework, categories in all_patterns.items():
            for category_name, category_data in categories.items():
                # Skip source map check here (handled separately)
                if category_data.get('check_source_map'):
                    continue

                for pattern in category_data['patterns']:
                    try:
                        if re.search(pattern, content, re.IGNORECASE):
                            result = self._create_finding(
                                url=url,
                                framework=framework,
                                category=category_name,
                                severity=category_data['severity'],
                                description=category_data['description'],
                                pattern=pattern,
                                content_type=content_type
                            )
                            results.append(result)
                            break  # One match per category
                    except:
                        pass

        return results

    def _check_source_maps(self, base_url: str, html: str, js_files: List[str],
                            http_client: Any) -> List[Dict[str, Any]]:
        """Check for accessible source maps"""
        results = []

        # Extract source map URLs from content
        sourcemap_pattern = r'//[#@]\s*sourceMappingURL=([^\s\'"]+)'

        # Check main HTML
        for match in re.finditer(sourcemap_pattern, html):
            map_url = match.group(1)
            if not map_url.startswith('data:'):
                full_url = urljoin(base_url, map_url)
                result = self._verify_source_map(full_url, base_url, http_client)
                if result:
                    results.append(result)

        # Check JS files for source map references
        for js_url in js_files[:15]:
            try:
                # Try common source map extensions
                map_urls = [
                    js_url + '.map',
                    js_url.replace('.js', '.js.map'),
                    js_url.replace('.min.js', '.js.map'),
                ]

                for map_url in map_urls:
                    if map_url not in self.checked_urls:
                        self.checked_urls.add(map_url)
                        result = self._verify_source_map(map_url, js_url, http_client)
                        if result:
                            results.append(result)
                            break  # Found map for this file

            except Exception as e:
                logger.debug(f"Error checking source maps: {e}")

        return results

    def _verify_source_map(self, map_url: str, source_url: str, http_client: Any) -> Dict:
        """Verify if a source map is accessible"""
        try:
            response = http_client.get(map_url, timeout=5)
            if response and response.status_code == 200:
                content = getattr(response, 'text', '') or ''

                # Verify it's a valid source map
                if '"version"' in content and ('"sources"' in content or '"mappings"' in content):
                    # Extract source file names
                    sources = []
                    try:
                        data = json.loads(content)
                        sources = data.get('sources', [])[:5]
                    except:
                        pass

                    sources_str = ', '.join(sources) if sources else 'original source files'

                    evidence = f"""Source Map Exposed

**Source Map URL:** {map_url}
**Referenced from:** {source_url}
**Sources included:** {sources_str}

**Security Impact:**
Source maps expose the original, unminified source code including:
- Original variable and function names
- Comments and documentation
- File structure and paths
- Potential sensitive logic and algorithms

**Remediation:**
Remove source map files from production deployment. Configure build
tools to not generate source maps for production, or ensure they
are not publicly accessible.
"""

                    result = self.create_result(
                        vulnerable=True,
                        url=map_url,
                        parameter='Source Map',
                        payload=map_url,
                        evidence=evidence,
                        description="JavaScript source map file is publicly accessible. Original source code can be downloaded.",
                        confidence=0.95,
                        severity='High',
                        method='GET',
                        response=f"Valid source map found at {map_url}"
                    )

                    result['framework'] = 'JavaScript'
                    result['category'] = 'Source Map Exposure'
                    result['source_files'] = sources
                    result['verified'] = True

                    logger.warning(f"Source map exposed: {map_url}")
                    return result

        except Exception as e:
            logger.debug(f"Error verifying source map {map_url}: {e}")

        return None

    def _create_finding(self, url: str, framework: str, category: str,
                        severity: str, description: str, pattern: str,
                        content_type: str) -> Dict[str, Any]:
        """Create a debug mode finding"""

        evidence = f"""JavaScript Framework Debug Mode Detected

**Framework:** {framework}
**Issue:** {category}
**Found in:** {content_type}
**URL:** {url}
**Pattern matched:** {pattern[:80]}...

**Description:**
{description}

**Security Impact:**
- Exposure of internal application state
- Debug information leakage
- Potential source code exposure
- Development endpoints accessible

**Remediation:**
- Disable debug mode in production builds
- Use production builds of frameworks
- Remove DevTools hooks
- Strip console.debug and debugger statements
"""

        result = self.create_result(
            vulnerable=True,
            url=url,
            parameter=f'{framework} - {category}',
            payload=pattern[:100],
            evidence=evidence,
            description=f"{framework} {category}: {description}",
            confidence=0.90,
            severity=severity,
            method='GET',
            response=f"Debug mode detected: {category}"
        )

        result['framework'] = framework
        result['category'] = category
        result['content_type'] = content_type
        result['verified'] = True

        logger.info(f"Found {framework} debug mode: {category}")
        return result


def get_module(module_path: str, payload_limit: int = None):
    """Create module instance"""
    return JSFrameworkDebugModule(module_path, payload_limit=payload_limit)
