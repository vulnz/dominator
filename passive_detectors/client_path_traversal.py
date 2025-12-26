"""
Client-Side Path Traversal (CSPT) Detection Module

Passively detects potential Client-Side Path Traversal vulnerabilities.

Client-Side Path Traversal occurs when:
- JavaScript uses user-controlled input to construct file paths
- fetch/XMLHttpRequest URLs are built from user input
- Dynamic imports use unsanitized paths
- URL parameters are used in API endpoint construction

This can lead to:
- Accessing unintended API endpoints
- Reading sensitive files via client-side requests
- Bypassing client-side access controls
- SSRF via client-side requests

Reference: https://portswigger.net/web-security/client-side-path-traversal
"""

import re
from typing import Dict, List, Tuple, Any


class ClientPathTraversalDetector:
    """
    Client-Side Path Traversal Vulnerability Detector

    Identifies JavaScript patterns that may lead to CSPT vulnerabilities.
    """

    # Patterns for URL/path construction from user input
    URL_CONSTRUCTION_PATTERNS = [
        # Direct path concatenation with variables
        re.compile(r'fetch\s*\(\s*["\'][^"\']*["\']\s*\+\s*\w+', re.IGNORECASE),
        re.compile(r'fetch\s*\(\s*`[^`]*\$\{[^}]+\}', re.IGNORECASE),  # Template literals
        re.compile(r'XMLHttpRequest[^;]*\.open\s*\([^,]+,\s*["\'][^"\']*["\']\s*\+', re.IGNORECASE),

        # URL object with variable path
        re.compile(r'new\s+URL\s*\(\s*["\'][^"\']*["\']\s*\+\s*\w+', re.IGNORECASE),
        re.compile(r'new\s+URL\s*\(\s*`[^`]*\$\{', re.IGNORECASE),

        # axios/jQuery with path variables
        re.compile(r'axios\s*\.\s*(?:get|post|put|delete|patch)\s*\(\s*["\'][^"\']*["\']\s*\+', re.IGNORECASE),
        re.compile(r'\$\s*\.\s*(?:get|post|ajax)\s*\(\s*["\'][^"\']*["\']\s*\+', re.IGNORECASE),

        # Dynamic API endpoint construction
        re.compile(r'(?:api|endpoint|url|path|href)\s*[=:]\s*["\'][^"\']*["\']\s*\+\s*(?:params|query|input|data|id|name)', re.IGNORECASE),
        re.compile(r'(?:api|endpoint|url|path)\s*[=:]\s*`[^`]*\$\{(?:params|query|input|data|id|name)', re.IGNORECASE),
    ]

    # Patterns for unsanitized path parameters
    UNSANITIZED_PATH_PATTERNS = [
        # Using location/URL parameters directly in paths
        re.compile(r'location\s*\.\s*(?:search|hash|pathname)[^;]*(?:fetch|XMLHttpRequest|axios|\$\.)', re.IGNORECASE),
        re.compile(r'URLSearchParams[^;]*(?:get|getAll)[^;]*(?:fetch|axios|url)', re.IGNORECASE),
        re.compile(r'(?:params|query)\s*\[\s*["\'][^"\']+["\']\s*\][^;]*(?:fetch|url|endpoint|api)', re.IGNORECASE),

        # document.location in fetch calls
        re.compile(r'fetch\s*\([^)]*document\.location', re.IGNORECASE),
        re.compile(r'fetch\s*\([^)]*window\.location', re.IGNORECASE),
    ]

    # Patterns for dynamic import with user input
    DYNAMIC_IMPORT_PATTERNS = [
        re.compile(r'import\s*\(\s*["\'][^"\']*["\']\s*\+\s*\w+', re.IGNORECASE),
        re.compile(r'import\s*\(\s*`[^`]*\$\{', re.IGNORECASE),
        re.compile(r'require\s*\(\s*["\'][^"\']*["\']\s*\+', re.IGNORECASE),
        re.compile(r'require\s*\(\s*`[^`]*\$\{', re.IGNORECASE),
    ]

    # Patterns for path traversal sequences that might be client-side
    TRAVERSAL_SEQUENCE_PATTERNS = [
        re.compile(r'\.\./', re.IGNORECASE),
        re.compile(r'\.\.%2[fF]', re.IGNORECASE),
        re.compile(r'%2[eE]%2[eE]/', re.IGNORECASE),
        re.compile(r'%252e%252e/', re.IGNORECASE),
    ]

    # Patterns for potentially vulnerable routing
    CLIENT_ROUTING_PATTERNS = [
        # React Router, Vue Router, etc. with dynamic segments
        re.compile(r'(?:path|route)\s*:\s*["\'][^"\']*:[^"\']+["\']', re.IGNORECASE),
        re.compile(r'useParams\s*\(\s*\)', re.IGNORECASE),
        re.compile(r'\$route\.params', re.IGNORECASE),

        # History API with user input
        re.compile(r'history\s*\.\s*(?:push|replace)State\s*\([^)]*\+', re.IGNORECASE),
        re.compile(r'history\s*\.\s*(?:push|replace)\s*\([^)]*\+', re.IGNORECASE),
    ]

    # Patterns that indicate missing path sanitization
    MISSING_SANITIZATION_PATTERNS = [
        # Direct use of URL params without validation
        re.compile(r'(?:get|post|put|delete|fetch)\s*\([^)]*(?:req\.params|req\.query|req\.body)\s*\.', re.IGNORECASE),
        # No path.normalize or path.resolve before use
        re.compile(r'(?:readFile|writeFile|createReadStream)\s*\([^)]*\+\s*(?:params|query|input)', re.IGNORECASE),
    ]

    # Patterns for file path in client-side code
    FILE_PATH_PATTERNS = [
        re.compile(r'(?:src|href|action)\s*=\s*["\'][^"\']*\.\.[^"\']*["\']', re.IGNORECASE),
        re.compile(r'(?:src|href|action)\s*=\s*`[^`]*\.\.[^`]*`', re.IGNORECASE),
        re.compile(r'\.(?:src|href)\s*=\s*[^;]*\.\./', re.IGNORECASE),
    ]

    @classmethod
    def detect(cls, response_text: str, url: str, headers: Dict[str, str] = None) -> Tuple[bool, List[Dict[str, Any]]]:
        """
        Detect potential Client-Side Path Traversal vulnerabilities.

        Args:
            response_text: HTTP response body
            url: URL being analyzed
            headers: HTTP response headers

        Returns:
            Tuple of (found_cspt, list_of_findings)
        """
        findings = []

        if not response_text:
            return False, findings

        # Check for URL construction patterns
        url_findings = cls._check_url_construction(response_text, url)
        findings.extend(url_findings)

        # Check for unsanitized path parameters
        param_findings = cls._check_unsanitized_params(response_text, url)
        findings.extend(param_findings)

        # Check for dynamic imports
        import_findings = cls._check_dynamic_imports(response_text, url)
        findings.extend(import_findings)

        # Check for traversal sequences in response
        traversal_findings = cls._check_traversal_sequences(response_text, url)
        findings.extend(traversal_findings)

        # Check for vulnerable routing patterns
        routing_findings = cls._check_client_routing(response_text, url)
        findings.extend(routing_findings)

        # Check for file path manipulation
        file_findings = cls._check_file_paths(response_text, url)
        findings.extend(file_findings)

        # Deduplicate
        seen = set()
        unique_findings = []
        for finding in findings:
            key = f"{finding['type']}:{finding.get('pattern', '')[:50]}"
            if key not in seen:
                seen.add(key)
                unique_findings.append(finding)

        return len(unique_findings) > 0, unique_findings

    @classmethod
    def _check_url_construction(cls, content: str, url: str) -> List[Dict[str, Any]]:
        """Check for insecure URL construction patterns"""
        findings = []

        for pattern in cls.URL_CONSTRUCTION_PATTERNS:
            match = pattern.search(content)
            if match:
                context = cls._get_context(content, match.start(), 100)

                findings.append({
                    'type': 'Insecure URL Construction',
                    'severity': 'Medium',
                    'url': url,
                    'pattern': match.group(0)[:150],
                    'context': context,
                    'description': 'URL/path is constructed using string concatenation with variables. '
                                  'If user-controlled, this may allow path traversal.',
                    'category': 'cspt_url_construction',
                    'location': 'Response Body (JavaScript)',
                    'recommendation': 'Validate and sanitize path components. '
                                     'Use URL API for safe URL construction. '
                                     'Implement allowlist for valid path segments.'
                })
                break  # One finding per category

        return findings

    @classmethod
    def _check_unsanitized_params(cls, content: str, url: str) -> List[Dict[str, Any]]:
        """Check for unsanitized path parameters"""
        findings = []

        for pattern in cls.UNSANITIZED_PATH_PATTERNS:
            match = pattern.search(content)
            if match:
                context = cls._get_context(content, match.start(), 100)

                findings.append({
                    'type': 'Unsanitized Path Parameter',
                    'severity': 'High',
                    'url': url,
                    'pattern': match.group(0)[:150],
                    'context': context,
                    'description': 'URL parameters or location data used directly in path construction '
                                  'without visible sanitization. High risk of path traversal.',
                    'category': 'cspt_unsanitized_param',
                    'location': 'Response Body (JavaScript)',
                    'recommendation': 'Never use URL parameters directly in paths. '
                                     'Validate against allowlist of expected values. '
                                     'Remove or encode path traversal characters (../, etc.).'
                })
                break

        return findings

    @classmethod
    def _check_dynamic_imports(cls, content: str, url: str) -> List[Dict[str, Any]]:
        """Check for dynamic imports with user input"""
        findings = []

        for pattern in cls.DYNAMIC_IMPORT_PATTERNS:
            match = pattern.search(content)
            if match:
                context = cls._get_context(content, match.start(), 100)

                findings.append({
                    'type': 'Dynamic Import with Variable Path',
                    'severity': 'High',
                    'url': url,
                    'pattern': match.group(0)[:150],
                    'context': context,
                    'description': 'Dynamic import/require uses variable in path. '
                                  'May allow loading arbitrary modules via path traversal.',
                    'category': 'cspt_dynamic_import',
                    'location': 'Response Body (JavaScript)',
                    'recommendation': 'Avoid dynamic imports with user input. '
                                     'Use static imports or validate against module allowlist. '
                                     'Implement strict CSP to limit script sources.'
                })
                break

        return findings

    @classmethod
    def _check_traversal_sequences(cls, content: str, url: str) -> List[Dict[str, Any]]:
        """Check for path traversal sequences in JavaScript"""
        findings = []

        # Check if traversal sequences are in JavaScript context (not just HTML)
        js_contexts = [
            (r'<script[^>]*>', r'</script>'),
            (r'\.js["\'\s>]', None),  # Indicate this might be a JS file
        ]

        is_js_context = any(re.search(ctx[0], content, re.IGNORECASE) for ctx in js_contexts)
        is_js_file = url.endswith('.js')

        if is_js_context or is_js_file:
            for pattern in cls.TRAVERSAL_SEQUENCE_PATTERNS:
                matches = list(pattern.finditer(content))
                if matches:
                    # Check context around traversal
                    for match in matches[:3]:  # Limit to first 3
                        context = cls._get_context(content, match.start(), 80)

                        # Only report if in a suspicious context
                        suspicious_keywords = ['fetch', 'url', 'path', 'api', 'endpoint', 'src', 'href', 'import', 'require']
                        if any(kw in context.lower() for kw in suspicious_keywords):
                            findings.append({
                                'type': 'Path Traversal Sequence in JavaScript',
                                'severity': 'Medium',
                                'url': url,
                                'sequence': match.group(0),
                                'context': context,
                                'description': 'Path traversal sequence (../) found in JavaScript context. '
                                              'May indicate intentional or vulnerable path manipulation.',
                                'category': 'cspt_traversal_sequence',
                                'location': 'Response Body (JavaScript)',
                                'recommendation': 'Review if traversal is intentional. '
                                                 'If processing user input, implement path sanitization.'
                            })
                            break

        return findings

    @classmethod
    def _check_client_routing(cls, content: str, url: str) -> List[Dict[str, Any]]:
        """Check for vulnerable client-side routing patterns"""
        findings = []

        for pattern in cls.CLIENT_ROUTING_PATTERNS:
            match = pattern.search(content)
            if match:
                context = cls._get_context(content, match.start(), 100)

                findings.append({
                    'type': 'Client-Side Routing with Dynamic Params',
                    'severity': 'Low',
                    'url': url,
                    'pattern': match.group(0)[:100],
                    'context': context,
                    'description': 'Client-side routing uses dynamic parameters. '
                                  'If these params are used in API calls, path traversal may be possible.',
                    'category': 'cspt_client_routing',
                    'location': 'Response Body (JavaScript)',
                    'recommendation': 'Validate route parameters before using in API calls. '
                                     'Implement server-side validation as primary defense.'
                })
                break

        return findings

    @classmethod
    def _check_file_paths(cls, content: str, url: str) -> List[Dict[str, Any]]:
        """Check for file path manipulation in HTML/JS"""
        findings = []

        for pattern in cls.FILE_PATH_PATTERNS:
            match = pattern.search(content)
            if match:
                findings.append({
                    'type': 'File Path with Traversal',
                    'severity': 'Medium',
                    'url': url,
                    'pattern': match.group(0)[:100],
                    'description': 'HTML attribute contains path traversal sequence. '
                                  'May be intentional or indicate vulnerability.',
                    'category': 'cspt_file_path',
                    'location': 'Response Body',
                    'recommendation': 'Review if path traversal is intentional. '
                                     'Ensure server validates requested resources.'
                })
                break

        return findings

    @classmethod
    def _get_context(cls, content: str, position: int, chars: int = 100) -> str:
        """Get context around a position in content"""
        start = max(0, position - chars // 2)
        end = min(len(content), position + chars)
        context = content[start:end]
        # Clean up whitespace
        context = ' '.join(context.split())
        return context[:200]


def detect_client_path_traversal(response_text: str, url: str,
                                  headers: Dict[str, str] = None) -> Tuple[bool, List[Dict[str, Any]]]:
    """Convenience function for Client-Side Path Traversal detection"""
    return ClientPathTraversalDetector.detect(response_text, url, headers)
