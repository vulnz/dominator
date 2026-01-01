"""
WebSocket Security Scanner Module
Detects WebSocket endpoints and checks for vulnerabilities
"""

import re
from typing import List, Dict, Any
from urllib.parse import urlparse
from core.base_module import BaseModule
from core.logger import get_logger

logger = get_logger(__name__)


class WebSocketModule(BaseModule):
    """WebSocket detection and security scanner"""

    def __init__(self, module_path: str, payload_limit: int = None):
        """Initialize WebSocket module"""
        super().__init__(module_path, payload_limit=payload_limit)

        self.ws_paths = [
            '/ws', '/websocket', '/socket', '/socket.io/', '/sockjs/',
            '/cable', '/realtime', '/live', '/stream', '/push',
            '/notifications', '/chat', '/signalr', '/hub', '/graphql',
        ]

        logger.info("WebSocket Security Scanner module loaded")

    def scan(self, targets: List[Dict[str, Any]], http_client: Any) -> List[Dict[str, Any]]:
        """Scan for WebSocket endpoints and vulnerabilities"""
        results = []
        tested_hosts = set()

        for target in targets:
            url = target.get('url')
            parsed = urlparse(url)
            host_key = parsed.netloc

            if host_key in tested_hosts:
                continue
            tested_hosts.add(host_key)

            # Passive: Check page content for WebSocket references
            passive_results = self._passive_scan(url, http_client)
            results.extend(passive_results)

            # Active: Probe for WebSocket endpoints
            active_results = self._discover_websockets(url, http_client)
            results.extend(active_results)

        return results

    def _passive_scan(self, url: str, http_client) -> List[Dict]:
        """Passively scan for WebSocket references"""
        results = []

        try:
            response = http_client.get(url)
            if not response:
                return results

            text = response.text

            # Find WebSocket URLs
            ws_urls = re.findall(r'["\']?(wss?://[^"\'>\\s]+)["\']?', text)

            # Detect WebSocket libraries using dict
            text_lower = text.lower()
            lib_patterns = {'socket.io': 'Socket.IO', 'sockjs': 'SockJS', 'signalr': 'SignalR'}
            libraries = [name for pattern, name in lib_patterns.items() if pattern in text_lower]

            for ws_url in set(ws_urls):
                analysis = self._analyze_websocket(ws_url, url)
                severity = 'Medium' if analysis['issues'] else 'Info'

                results.append(self.create_result(
                    vulnerable=True,
                    url=url,
                    parameter='websocket',
                    payload=ws_url,
                    evidence=f"WebSocket: {ws_url}. Libraries: {', '.join(libraries) or 'Native'}. Issues: {len(analysis['issues'])}",
                    severity=severity,
                    method='Passive',
                    additional_info={
                        'injection_type': 'WebSocket Discovery',
                        'websocket_url': ws_url,
                        'libraries': libraries,
                        'issues': analysis['issues'],
                        'cwe': 'CWE-1385',
                        'owasp': 'A07:2021',
                        'cvss': 6.5 if analysis['issues'] else 3.7
                    }
                ))

            # Report libraries even if no URLs found - with context
            if libraries and not ws_urls:
                evidence_parts = [
                    "**WebSocket Libraries Detected**\n",
                    f"**Page URL:** {url}",
                    f"\n**Libraries Found:**"
                ]

                for lib in libraries:
                    evidence_parts.append(f"  - `{lib}`")

                evidence_parts.append("\n**Security Note:**")
                evidence_parts.append("  WebSocket usage detected - review for:")
                evidence_parts.append("  - Origin validation (CSRF)")
                evidence_parts.append("  - Authentication requirements")
                evidence_parts.append("  - Message input validation")

                results.append(self.create_result(
                    vulnerable=True,
                    url=url,
                    parameter='library',
                    payload=', '.join(libraries),
                    evidence='\n'.join(evidence_parts),
                    severity='Info',
                    method='Passive',
                    additional_info={
                        'injection_type': 'Library Detection',
                        'libraries': libraries,
                        'cwe': 'CWE-200',
                        'owasp': 'A05:2021',
                        'cvss': 0
                    }
                ))

        except Exception:
            pass

        return results

    def _discover_websockets(self, url: str, http_client) -> List[Dict]:
        """Actively discover WebSocket endpoints"""
        results = []
        parsed = urlparse(url)
        base = f"{parsed.scheme}://{parsed.netloc}"

        for path in self.ws_paths[:5]:  # Limit tests
            test_url = base + path

            try:
                headers = {
                    'Upgrade': 'websocket',
                    'Connection': 'Upgrade',
                    'Sec-WebSocket-Key': 'dGhlIHNhbXBsZSBub25jZQ==',
                    'Sec-WebSocket-Version': '13',
                }

                response = http_client.get(test_url, headers=headers)

                if response:
                    if response.status_code == 101:
                        results.append(self._create_ws_finding(test_url, path, 'WebSocket upgrade successful'))
                        break
                    elif response.status_code == 426:
                        results.append(self._create_ws_finding(test_url, path, 'WebSocket endpoint exists (426)'))
                        break
                    elif '/socket.io/' in path and response.status_code == 200:
                        if 'sid' in response.text:
                            results.append(self._create_ws_finding(test_url, path, 'Socket.IO endpoint'))
                            break

            except Exception:
                continue

        return results

    def _analyze_websocket(self, ws_url: str, origin_url: str) -> Dict:
        """Analyze WebSocket URL for security issues"""
        issues = []

        # Check for insecure WebSocket
        if ws_url.startswith('ws://') and origin_url.startswith('https://'):
            issues.append('Mixed Content - Insecure ws:// on HTTPS page')

        # Check for cross-origin
        ws_parsed = urlparse(ws_url)
        origin_parsed = urlparse(origin_url)
        if ws_parsed.netloc != origin_parsed.netloc:
            issues.append(f'Cross-origin WebSocket to {ws_parsed.netloc}')

        # Check for credentials in URL
        if any(x in ws_url for x in ['token=', 'key=', 'auth=']):
            issues.append('Credentials visible in WebSocket URL')

        return {'issues': issues}

    def _create_ws_finding(self, url: str, path: str, description: str) -> Dict:
        """Create WebSocket finding"""
        return self.create_result(
            vulnerable=True,
            url=url,
            parameter='path',
            payload=path,
            evidence=description,
            severity='Info',
            method='GET',
            additional_info={
                'injection_type': 'Active Discovery',
                'cwe': 'CWE-1385',
                'owasp': 'A07:2021',
                'cvss': 3.7
            }
        )


def get_module(module_path: str, payload_limit: int = None):
    """Factory function to create module instance"""
    return WebSocketModule(module_path, payload_limit)
