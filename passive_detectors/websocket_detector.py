"""
WebSocket Detection and Vulnerability Analysis Module

Passively detects WebSocket endpoints and analyzes them for security issues.

Detects:
- WebSocket connection URLs (ws://, wss://)
- JavaScript WebSocket instantiations
- Socket.IO / Engine.IO endpoints
- SockJS endpoints
- SignalR endpoints

Security checks:
- Unencrypted WebSocket (ws:// vs wss://)
- Missing authentication patterns
- Hardcoded credentials in WebSocket URLs
- CSWSH (Cross-Site WebSocket Hijacking) indicators
- Debug/verbose mode enabled
"""

import re
from typing import Dict, List, Tuple, Any, Optional
from urllib.parse import urlparse


class WebSocketDetector:
    """
    WebSocket Detection and Security Analysis

    Passively detects and analyzes WebSocket usage for security issues.
    """

    # WebSocket URL patterns
    WS_URL_PATTERNS = [
        # Standard WebSocket URLs
        re.compile(r'(wss?://[^\s"\'<>]+)', re.IGNORECASE),
        # JavaScript WebSocket constructor
        re.compile(r'new\s+WebSocket\s*\(\s*["\']([^"\']+)["\']', re.IGNORECASE),
        re.compile(r'new\s+WebSocket\s*\(\s*`([^`]+)`', re.IGNORECASE),
        # WebSocket variable assignment
        re.compile(r'WebSocket\s*\(\s*["\']([^"\']+)["\']', re.IGNORECASE),
    ]

    # Socket.IO patterns
    SOCKETIO_PATTERNS = [
        re.compile(r'io\s*\(\s*["\']([^"\']+)["\']', re.IGNORECASE),
        re.compile(r'io\.connect\s*\(\s*["\']([^"\']+)["\']', re.IGNORECASE),
        re.compile(r'/socket\.io/\?', re.IGNORECASE),
        re.compile(r'socket\.io\.js', re.IGNORECASE),
        re.compile(r'engine\.io', re.IGNORECASE),
    ]

    # SockJS patterns
    SOCKJS_PATTERNS = [
        re.compile(r'new\s+SockJS\s*\(\s*["\']([^"\']+)["\']', re.IGNORECASE),
        re.compile(r'/sockjs/', re.IGNORECASE),
        re.compile(r'sockjs\.js', re.IGNORECASE),
    ]

    # SignalR patterns (ASP.NET)
    SIGNALR_PATTERNS = [
        re.compile(r'\.hubConnection\s*\(', re.IGNORECASE),
        re.compile(r'/signalr/', re.IGNORECASE),
        re.compile(r'signalr\.js', re.IGNORECASE),
        re.compile(r'\.connection\s*=\s*\$\.hubConnection', re.IGNORECASE),
    ]

    # STOMP over WebSocket patterns
    STOMP_PATTERNS = [
        re.compile(r'Stomp\.over\s*\(', re.IGNORECASE),
        re.compile(r'Stomp\.client\s*\(\s*["\']([^"\']+)["\']', re.IGNORECASE),
        re.compile(r'stomp\.js', re.IGNORECASE),
    ]

    # Authentication patterns in WebSocket code
    AUTH_PATTERNS = [
        re.compile(r'(?:token|auth|key|bearer|jwt|session)[:=]\s*["\']?[^"\']+', re.IGNORECASE),
        re.compile(r'Authorization[:=]\s*["\']', re.IGNORECASE),
        re.compile(r'ws[s]?://[^"\']*(?:token|key|auth)=', re.IGNORECASE),
    ]

    # Credential patterns in WebSocket URLs
    CREDENTIAL_PATTERNS = [
        re.compile(r'wss?://[^:]+:[^@]+@', re.IGNORECASE),  # Basic auth in URL
        re.compile(r'(?:password|pwd|pass|secret)[:=]\s*["\'][^"\']+["\']', re.IGNORECASE),
        re.compile(r'apikey[:=]\s*["\'][^"\']+["\']', re.IGNORECASE),
    ]

    # Debug/verbose patterns
    DEBUG_PATTERNS = [
        re.compile(r'debug\s*[:=]\s*true', re.IGNORECASE),
        re.compile(r'verbose\s*[:=]\s*true', re.IGNORECASE),
        re.compile(r'logLevel\s*[:=]\s*["\']?debug', re.IGNORECASE),
        re.compile(r'\.on\s*\(\s*["\'](?:connect_error|error|disconnect)["\']', re.IGNORECASE),
    ]

    @classmethod
    def detect(cls, response_text: str, url: str, headers: Dict[str, str] = None) -> Tuple[bool, List[Dict[str, Any]]]:
        """
        Detect WebSocket usage and analyze for security issues.

        Args:
            response_text: HTTP response body
            url: URL being analyzed
            headers: HTTP response headers

        Returns:
            Tuple of (found_websocket, list_of_findings)
        """
        findings = []

        if not response_text:
            return False, findings

        # Detect WebSocket URLs
        ws_urls = cls._find_websocket_urls(response_text)
        for ws_url in ws_urls:
            findings.extend(cls._analyze_websocket_url(ws_url, url))

        # Detect Socket.IO usage
        socketio_findings = cls._detect_socketio(response_text, url)
        findings.extend(socketio_findings)

        # Detect SockJS usage
        sockjs_findings = cls._detect_sockjs(response_text, url)
        findings.extend(sockjs_findings)

        # Detect SignalR usage
        signalr_findings = cls._detect_signalr(response_text, url)
        findings.extend(signalr_findings)

        # Detect STOMP usage
        stomp_findings = cls._detect_stomp(response_text, url)
        findings.extend(stomp_findings)

        # Check for CSWSH indicators
        cswsh_findings = cls._check_cswsh_indicators(response_text, url, headers)
        findings.extend(cswsh_findings)

        # Check for credentials in WebSocket code
        credential_findings = cls._check_credentials(response_text, url)
        findings.extend(credential_findings)

        # Check for debug mode
        debug_findings = cls._check_debug_mode(response_text, url)
        findings.extend(debug_findings)

        # Check response headers for WebSocket upgrade
        if headers:
            header_findings = cls._check_headers(headers, url)
            findings.extend(header_findings)

        # Deduplicate findings
        seen = set()
        unique_findings = []
        for finding in findings:
            key = f"{finding['type']}:{finding.get('endpoint', '')}:{finding.get('description', '')[:50]}"
            if key not in seen:
                seen.add(key)
                unique_findings.append(finding)

        return len(unique_findings) > 0, unique_findings

    @classmethod
    def _find_websocket_urls(cls, response_text: str) -> List[str]:
        """Find all WebSocket URLs in response"""
        urls = set()

        for pattern in cls.WS_URL_PATTERNS:
            matches = pattern.finditer(response_text)
            for match in matches:
                ws_url = match.group(1)
                # Clean up URL
                ws_url = ws_url.strip().rstrip('\'";,)')
                if ws_url.startswith(('ws://', 'wss://')):
                    urls.add(ws_url)

        return list(urls)

    @classmethod
    def _analyze_websocket_url(cls, ws_url: str, page_url: str) -> List[Dict[str, Any]]:
        """Analyze a WebSocket URL for security issues"""
        findings = []

        # Parse URL
        try:
            parsed = urlparse(ws_url)
        except Exception:
            return findings

        # Check for unencrypted WebSocket
        if ws_url.startswith('ws://'):
            # Check if page is HTTPS but WebSocket is not
            if page_url.startswith('https://'):
                severity = 'High'
                description = 'Unencrypted WebSocket (ws://) used on HTTPS page. This exposes WebSocket traffic to interception.'
            else:
                severity = 'Medium'
                description = 'Unencrypted WebSocket (ws://) detected. Consider using wss:// for secure communication.'

            findings.append({
                'type': 'Unencrypted WebSocket',
                'severity': severity,
                'url': page_url,
                'endpoint': ws_url,
                'description': description,
                'category': 'websocket_unencrypted',
                'location': 'Response Body',
                'recommendation': 'Use wss:// (WebSocket Secure) instead of ws:// to encrypt WebSocket traffic. '
                                 'Ensure SSL/TLS certificates are valid.'
            })

        # Check for credentials in URL
        if '@' in ws_url or any(p in ws_url.lower() for p in ['token=', 'key=', 'auth=', 'password=']):
            findings.append({
                'type': 'Credentials in WebSocket URL',
                'severity': 'High',
                'url': page_url,
                'endpoint': cls._redact_url(ws_url),
                'description': 'WebSocket URL contains potential credentials or tokens. These may be logged or exposed.',
                'category': 'websocket_credentials',
                'location': 'Response Body',
                'recommendation': 'Move authentication to WebSocket handshake headers or initial message. '
                                 'Never include credentials in URLs as they may be logged.'
            })

        # Report WebSocket endpoint found (info level)
        findings.append({
            'type': 'WebSocket Endpoint',
            'severity': 'Info',
            'url': page_url,
            'endpoint': cls._redact_url(ws_url),
            'description': f'WebSocket endpoint discovered: {parsed.netloc}{parsed.path}',
            'category': 'websocket_endpoint',
            'location': 'Response Body',
            'recommendation': 'Verify WebSocket endpoint implements proper authentication and authorization. '
                             'Test for CSWSH vulnerabilities.'
        })

        return findings

    @classmethod
    def _detect_socketio(cls, response_text: str, url: str) -> List[Dict[str, Any]]:
        """Detect Socket.IO usage"""
        findings = []

        for pattern in cls.SOCKETIO_PATTERNS:
            if pattern.search(response_text):
                findings.append({
                    'type': 'Socket.IO Detected',
                    'severity': 'Info',
                    'url': url,
                    'description': 'Socket.IO library is being used for WebSocket communication. '
                                  'Test for Cross-Site WebSocket Hijacking (CSWSH).',
                    'category': 'socketio',
                    'location': 'Response Body',
                    'recommendation': 'Verify Socket.IO is configured with proper CORS settings. '
                                     'Implement origin validation. Use authentication middleware.'
                })
                break

        return findings

    @classmethod
    def _detect_sockjs(cls, response_text: str, url: str) -> List[Dict[str, Any]]:
        """Detect SockJS usage"""
        findings = []

        for pattern in cls.SOCKJS_PATTERNS:
            match = pattern.search(response_text)
            if match:
                endpoint = match.group(1) if match.lastindex else ''

                findings.append({
                    'type': 'SockJS Detected',
                    'severity': 'Info',
                    'url': url,
                    'endpoint': endpoint,
                    'description': 'SockJS library detected. This provides WebSocket emulation with fallback transports.',
                    'category': 'sockjs',
                    'location': 'Response Body',
                    'recommendation': 'Verify SockJS origin checks are configured. Test all transport methods for vulnerabilities.'
                })
                break

        return findings

    @classmethod
    def _detect_signalr(cls, response_text: str, url: str) -> List[Dict[str, Any]]:
        """Detect SignalR usage"""
        findings = []

        for pattern in cls.SIGNALR_PATTERNS:
            if pattern.search(response_text):
                findings.append({
                    'type': 'SignalR Detected',
                    'severity': 'Info',
                    'url': url,
                    'description': 'ASP.NET SignalR library detected for real-time communication.',
                    'category': 'signalr',
                    'location': 'Response Body',
                    'recommendation': 'Verify SignalR hub methods have proper authorization attributes. '
                                     'Test for unauthorized method invocation.'
                })
                break

        return findings

    @classmethod
    def _detect_stomp(cls, response_text: str, url: str) -> List[Dict[str, Any]]:
        """Detect STOMP over WebSocket usage"""
        findings = []

        for pattern in cls.STOMP_PATTERNS:
            match = pattern.search(response_text)
            if match:
                endpoint = match.group(1) if match.lastindex else ''

                findings.append({
                    'type': 'STOMP WebSocket Detected',
                    'severity': 'Info',
                    'url': url,
                    'endpoint': endpoint,
                    'description': 'STOMP protocol over WebSocket detected. Common with Spring WebSocket.',
                    'category': 'stomp',
                    'location': 'Response Body',
                    'recommendation': 'Verify STOMP destination security. Check subscription restrictions. '
                                     'Test for message injection vulnerabilities.'
                })
                break

        return findings

    @classmethod
    def _check_cswsh_indicators(cls, response_text: str, url: str,
                                 headers: Dict[str, str] = None) -> List[Dict[str, Any]]:
        """Check for Cross-Site WebSocket Hijacking (CSWSH) indicators"""
        findings = []

        # Check for missing origin validation patterns in code
        no_origin_check_patterns = [
            re.compile(r'new\s+WebSocket\s*\([^)]*\)', re.IGNORECASE),
            re.compile(r'io\s*\(\s*["\'][^"\']+["\'](?:\s*,\s*\{\s*\})?\s*\)', re.IGNORECASE),
        ]

        has_websocket = any(p.search(response_text) for p in no_origin_check_patterns)

        # Check for explicit origin validation
        origin_check_patterns = [
            re.compile(r'origin\s*(?:==|===|!=|!==|\.includes|\.indexOf)', re.IGNORECASE),
            re.compile(r'checkOrigin|validateOrigin|verifyOrigin', re.IGNORECASE),
            re.compile(r'allowedOrigins|cors\.origin', re.IGNORECASE),
        ]

        has_origin_check = any(p.search(response_text) for p in origin_check_patterns)

        if has_websocket and not has_origin_check:
            findings.append({
                'type': 'Potential CSWSH Vulnerability',
                'severity': 'Medium',
                'url': url,
                'description': 'WebSocket connection found without visible origin validation. '
                              'May be vulnerable to Cross-Site WebSocket Hijacking.',
                'category': 'cswsh',
                'location': 'Response Body',
                'recommendation': 'Implement server-side Origin header validation. '
                                 'Only accept WebSocket connections from trusted origins. '
                                 'Use CSRF tokens in WebSocket handshake.'
            })

        return findings

    @classmethod
    def _check_credentials(cls, response_text: str, url: str) -> List[Dict[str, Any]]:
        """Check for hardcoded credentials in WebSocket code"""
        findings = []

        for pattern in cls.CREDENTIAL_PATTERNS:
            match = pattern.search(response_text)
            if match:
                # Get context around match
                start = max(0, match.start() - 50)
                end = min(len(response_text), match.end() + 50)
                context = response_text[start:end]

                findings.append({
                    'type': 'Hardcoded Credentials in WebSocket Code',
                    'severity': 'High',
                    'url': url,
                    'description': 'Potential hardcoded credentials found in WebSocket-related code.',
                    'context': context[:200],
                    'category': 'websocket_hardcoded_creds',
                    'location': 'Response Body',
                    'recommendation': 'Remove hardcoded credentials. Use secure token exchange during handshake. '
                                     'Store credentials server-side and use session-based authentication.'
                })
                break

        return findings

    @classmethod
    def _check_debug_mode(cls, response_text: str, url: str) -> List[Dict[str, Any]]:
        """Check for debug mode in WebSocket code"""
        findings = []

        for pattern in cls.DEBUG_PATTERNS:
            if pattern.search(response_text):
                findings.append({
                    'type': 'WebSocket Debug Mode',
                    'severity': 'Low',
                    'url': url,
                    'description': 'Debug or verbose mode appears to be enabled in WebSocket code. '
                                  'May expose sensitive information in production.',
                    'category': 'websocket_debug',
                    'location': 'Response Body',
                    'recommendation': 'Disable debug mode in production. Remove verbose logging. '
                                     'Ensure error handlers don\'t leak sensitive information.'
                })
                break

        return findings

    @classmethod
    def _check_headers(cls, headers: Dict[str, str], url: str) -> List[Dict[str, Any]]:
        """Check response headers for WebSocket-related information"""
        findings = []

        headers_lower = {k.lower(): v for k, v in headers.items()}

        # Check for WebSocket upgrade response
        if headers_lower.get('upgrade', '').lower() == 'websocket':
            findings.append({
                'type': 'WebSocket Upgrade Response',
                'severity': 'Info',
                'url': url,
                'description': 'Server responded with WebSocket upgrade. Endpoint accepts WebSocket connections.',
                'category': 'websocket_upgrade',
                'location': 'Response Headers',
                'recommendation': 'Test WebSocket endpoint for authentication and authorization issues.'
            })

        return findings

    @classmethod
    def _redact_url(cls, url: str) -> str:
        """Redact sensitive parts of URL"""
        # Redact basic auth credentials
        url = re.sub(r'://([^:]+):([^@]+)@', r'://***:***@', url)
        # Redact token/key parameters
        url = re.sub(r'(token|key|auth|password|secret)=([^&]+)', r'\1=***', url, flags=re.IGNORECASE)
        return url


def detect_websocket(response_text: str, url: str, headers: Dict[str, str] = None) -> Tuple[bool, List[Dict[str, Any]]]:
    """Convenience function for WebSocket detection"""
    return WebSocketDetector.detect(response_text, url, headers)
