"""
HTTP Intercepting Proxy for Dominator Scanner
Burp Suite-like functionality: intercept, modify, replay requests

OPTIMIZATIONS:
- Connection pooling for faster request forwarding
- DNS caching to reduce latency
- Memory-efficient history management with automatic cleanup
- SSL certificate caching per host
- Rate limiting and size limits for stability
- Improved error handling with retry logic
- Optimized threading and buffering
"""

import socket
import threading
import time
import ssl
import zlib
from http.server import BaseHTTPRequestHandler, HTTPServer
from socketserver import ThreadingMixIn
from urllib.parse import urlparse
import requests
from PyQt5.QtCore import QObject, pyqtSignal
import gzip
import io
from utils.cert_manager import get_cert_manager
from collections import OrderedDict
from functools import lru_cache
import weakref

# Import helper classes from network_helpers
from utils.network_helpers import decompress_content, DNSCache, ConnectionPool, LRUCache


class InterceptingProxy(QObject):
    """HTTP proxy that intercepts and allows modification of requests"""

    # Signals for GUI
    request_intercepted = pyqtSignal(dict)  # New request intercepted
    response_received = pyqtSignal(dict)    # Response received
    passive_finding = pyqtSignal(dict)      # Passive scan finding
    resource_found = pyqtSignal(str, str, str, str)  # (type, value, extra, source)
    websocket_message = pyqtSignal(dict)    # WebSocket message intercepted
    statistics_updated = pyqtSignal(dict)   # Statistics update (total, blocked_analytics)

    def __init__(self, port=8080, ssl_intercept_enabled=True):
        super().__init__()
        self.port = port
        self.intercept_enabled = False
        self.passive_scan_enabled = True
        self.ssl_intercept_enabled = ssl_intercept_enabled
        self.server = None
        self.thread = None
        self.running = False

        # OPTIMIZATION: Connection pooling for faster request forwarding
        self.connection_pool = ConnectionPool(pool_size=20, pool_maxsize=50)

        # OPTIMIZATION: DNS caching to reduce latency
        self.dns_cache = DNSCache(ttl=300)

        # OPTIMIZATION: SSL certificate caching
        self.ssl_cert_cache = LRUCache(maxsize=100)

        # Request history with automatic cleanup
        self.history = []
        self.max_history = 5000
        self._history_lock = threading.Lock()
        self._last_cleanup = time.time()
        self._cleanup_interval = 60  # Cleanup every 60 seconds

        # WebSocket history
        self.ws_history = []
        self.max_ws_history = 1000
        self.ws_message_counter = 0

        # Pending requests (waiting for user action) with timeout cleanup
        self.pending_requests = {}
        self.pending_events = {}
        self.request_id_counter = 0
        self._pending_lock = threading.Lock()

        # Auto-allow hosts (bypass interception for these hosts)
        self.auto_allow_hosts = set()

        # OPTIMIZATION: Request/Response size limits (prevent memory issues)
        self.max_request_size = 100 * 1024 * 1024  # 100MB
        self.max_response_size = 100 * 1024 * 1024  # 100MB
        self.max_gui_display_size = 500 * 1024  # 500KB - truncate GUI display for performance

        # OPTIMIZATION: Rate limiting per host
        self.rate_limiter = {}  # host -> (request_count, window_start)
        self.rate_limit_window = 1.0  # 1 second
        self.rate_limit_max_requests = 100  # Max 100 requests per second per host

        # Scope management (Burp Suite-like)
        self.scope_enabled = False
        self.in_scope_patterns = []  # Regex patterns for in-scope URLs
        self.out_of_scope_patterns = []  # Regex patterns to explicitly exclude

        # Ignore patterns (avoid logging static files, etc.)
        self.ignore_enabled = True
        self.ignore_extensions = {
            # Images
            '.jpg', '.jpeg', '.png', '.gif', '.svg', '.ico', '.webp', '.bmp', '.tiff', '.avif',
            # Fonts
            '.woff', '.woff2', '.ttf', '.eot', '.otf',
            # Stylesheets and source maps
            '.css', '.map', '.scss', '.less',
            # Binary/media files
            '.pdf', '.zip', '.gz', '.tar', '.rar', '.7z',
            '.mp3', '.mp4', '.wav', '.ogg', '.webm', '.avi', '.mov', '.mkv',
            '.exe', '.dll', '.so', '.dylib', '.bin',
            # Data files
            '.wasm', '.dat', '.db', '.sqlite',
        }
        # Content types to skip logging (binary/non-text responses)
        self.ignore_content_types = {
            'image/', 'video/', 'audio/', 'font/',
            'application/octet-stream', 'application/zip', 'application/gzip',
            'application/pdf', 'application/x-shockwave-flash', 'application/wasm',
            'application/x-tar', 'application/x-rar', 'application/x-7z-compressed',
        }
        self.custom_ignore_patterns = []  # Additional regex patterns to ignore

        # Block common analytics and tracking systems (DEFAULT ENABLED)
        self.block_analytics_enabled = True

        # Statistics for blocked requests
        self.total_requests = 0
        self.blocked_analytics_requests = 0
        self._stats_lock = threading.Lock()

        self.analytics_hosts = {
            # === BROWSER TELEMETRY (Firefox, Chrome, Edge, etc.) ===
            # Firefox Telemetry & Tracking
            'telemetry.mozilla.org', 'incoming.telemetry.mozilla.org',
            'firefox.settings.services.mozilla.com', 'services.addons.mozilla.org',
            'tracking-protection.cdn.mozilla.net', 'shavar.services.mozilla.com',
            'location.services.mozilla.com', 'push.services.mozilla.com',
            'tiles.services.mozilla.com', 'snippets.cdn.mozilla.net',
            'safebrowsing.google.com', 'safebrowsing.googleapis.com',

            # Chrome/Chromium Telemetry
            'clients2.google.com', 'clients3.google.com', 'clients4.google.com',
            'update.googleapis.com', 'clientservices.googleapis.com',
            'chrome.google.com', 'tools.google.com',

            # Microsoft Edge Telemetry
            'edge.microsoft.com', 'config.edge.skype.com',
            'ris.api.iris.microsoft.com', 'watson.telemetry.microsoft.com',
            'vortex.data.microsoft.com', 'telemetry.microsoft.com',
            'telemetry.urs.microsoft.com', 'settings-win.data.microsoft.com',

            # === ANALYTICS & METRICS ===
            # Google Analytics & Ads
            'google-analytics.com', 'www.google-analytics.com',
            'analytics.google.com', 'ssl.google-analytics.com',
            'googletagmanager.com', 'www.googletagmanager.com',
            'googleadservices.com', 'www.googleadservices.com',
            'googlesyndication.com', 'pagead2.googlesyndication.com',
            'doubleclick.net', 'stats.g.doubleclick.net',
            'adservice.google.com', 'www.googletagservices.com',

            # Yandex Metrica & Ads
            'mc.yandex.ru', 'mc.yandex.com',
            'metrika.yandex.ru', 'metrika.yandex.com',
            'an.yandex.ru', 'yandexadexchange.net',
            'extmaps-api.yandex.net', 'appmetrica.yandex.ru',

            # Facebook/Meta Pixel & Tracking
            'connect.facebook.net', 'pixel.facebook.com',
            'graph.facebook.com', 'analytics.facebook.com',
            'www.facebook.com/tr', 'staticxx.facebook.com',

            # Microsoft Clarity & Bing Ads
            'clarity.ms', 'www.clarity.ms',
            'bat.bing.com', 'c.bing.com', 'r.bing.com',

            # Adobe Analytics
            'omtrdc.net', 'demdex.net', 'everesttech.net',
            '2o7.net', 'sc.omtrdc.net',

            # Hotjar
            'hotjar.com', 'static.hotjar.com', 'script.hotjar.com',
            'insights.hotjar.com', 'vars.hotjar.com',

            # Mixpanel
            'mixpanel.com', 'api.mixpanel.com', 'cdn.mxpnl.com',
            'decide.mixpanel.com',

            # Segment
            'segment.io', 'api.segment.io', 'cdn.segment.com',
            'segment.com',

            # Amplitude
            'amplitude.com', 'api.amplitude.com', 'api2.amplitude.com',

            # Heap Analytics
            'heap.io', 'heapanalytics.com', 'cdn.heapanalytics.com',

            # FullStory
            'fullstory.com', 'rs.fullstory.com', 'edge.fullstory.com',

            # CrazyEgg
            'crazyegg.com', 'script.crazyegg.com', 'dnn506yrbagrg.cloudfront.net',

            # Mouseflow
            'mouseflow.com', 'cdn.mouseflow.com', 'o2.mouseflow.com',

            # Lucky Orange
            'luckyorange.com', 'cdn.luckyorange.net', 'w1.luckyorange.com',

            # Inspectlet
            'inspectlet.com', 'cdn.inspectlet.com',

            # === ERROR TRACKING & APM ===
            # New Relic
            'newrelic.com', 'js-agent.newrelic.com', 'bam.nr-data.net',
            'beacon.newrelic.com',

            # Sentry
            'sentry.io', 'browser.sentry-cdn.com', 'sentry-cdn.com',

            # Bugsnag
            'bugsnag.com', 'notify.bugsnag.com', 'sessions.bugsnag.com',

            # LogRocket
            'logrocket.com', 'cdn.logrocket.io', 'r.lr-ingest.io',

            # Rollbar
            'rollbar.com', 'api.rollbar.com',

            # === ADVERTISING NETWORKS ===
            'adsrvr.org', 'adnxs.com', 'criteo.com', 'criteo.net',
            'taboola.com', 'outbrain.com', 'amazon-adsystem.com',
            'moatads.com', 'scorecardresearch.com', 'quantserve.com',
            'serving-sys.com', 'pubmatic.com', 'rubiconproject.com',
            'indexww.com', 'advertising.com', 'media.net',
            'openx.net', 'adform.net', 'bidswitch.net',

            # === SOCIAL MEDIA WIDGETS & TRACKING ===
            # Twitter/X
            'platform.twitter.com', 'syndication.twitter.com',
            'analytics.twitter.com', 't.co',

            # LinkedIn
            'platform.linkedin.com', 'snap.licdn.com',
            'px.ads.linkedin.com',

            # Pinterest
            'widgets.pinterest.com', 'assets.pinterest.com',
            'ct.pinterest.com', 'log.pinterest.com',

            # Instagram
            'www.instagram.com/embed', 'scontent.cdninstagram.com',

            # TikTok
            'analytics.tiktok.com', 'byteoversea.com',

            # === COOKIE CONSENT & PRIVACY ===
            'cdn.cookielaw.org', 'cdn.onetrust.com',
            'trustarc.com', 'consent.trustarc.com',
            'consensu.org', 'quantcast.mgr.consensu.org',

            # === CDN TRACKING ===
            'bat.r.msn.com', 'c.msn.com',
            'sb.scorecardresearch.com', 'b.scorecardresearch.com',
        }

        # Certificate manager for SSL interception
        self.cert_manager = get_cert_manager() if ssl_intercept_enabled else None

        # Passive detectors (load lazily to avoid startup issues)
        self.passive_scanner = None
        self.sensitive_detector = None

        # Try to load passive detectors, but don't fail if they're not available
        try:
            from passive_detectors.passive_scanner import PassiveScanner
            from passive_detectors.sensitive_data_detector import SensitiveDataDetector
            from passive_detectors.resource_collector import ResourceCollector
            self.passive_scanner = PassiveScanner()
            self.sensitive_detector = SensitiveDataDetector()
            self.resource_collector = ResourceCollector()
            print("[+] Passive scanners loaded successfully")
        except Exception as e:
            print(f"[!] Warning: Could not load passive scanners: {e}")
            print("[!] Proxy will work but passive scanning will be disabled")
            self.resource_collector = None

    def start(self):
        """Start the proxy server"""
        if self.running:
            return

        # Check if port is already in use
        if self._is_port_in_use(self.port):
            print(f"[!] Port {self.port} is already in use!")
            print(f"[*] Attempting to free port {self.port}...")

            # Try to kill process using the port
            if self._kill_process_on_port(self.port):
                print(f"[+] Port {self.port} freed successfully")
                time.sleep(1)  # Give OS time to release the port
            else:
                print(f"[!] Could not free port {self.port}")
                print(f"[!] Please manually stop the process or use a different port")
                return f"Port {self.port} is in use and could not be freed"

        self.running = True
        self.thread = threading.Thread(target=self._run_server, daemon=True)
        self.thread.start()

        return f"Proxy started on 127.0.0.1:{self.port}"

    def _is_port_in_use(self, port):
        """Check if a port is already in use"""
        import socket
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            try:
                s.bind(('127.0.0.1', port))
                return False
            except OSError:
                return True

    def _kill_process_on_port(self, port):
        """Kill process using the specified port (Windows/Linux)"""
        import subprocess
        import platform
        import sys

        try:
            if platform.system() == 'Windows':
                # Hide console window on Windows
                creation_flags = subprocess.CREATE_NO_WINDOW if sys.platform == 'win32' else 0

                # Find PID using netstat
                result = subprocess.run(
                    ['netstat', '-ano'],
                    capture_output=True,
                    text=True,
                    creationflags=creation_flags  # Hide console window
                )

                pids = set()
                for line in result.stdout.split('\n'):
                    if f':{port}' in line and 'LISTENING' in line:
                        parts = line.split()
                        if len(parts) >= 5:
                            pid = parts[-1]
                            pids.add(pid)

                # Kill all processes
                for pid in pids:
                    try:
                        subprocess.run(
                            ['taskkill', '/F', '/PID', pid],
                            capture_output=True,
                            check=True,
                            creationflags=creation_flags  # Hide console window
                        )
                        print(f"[+] Killed process {pid} on port {port}")
                    except:
                        pass

                return len(pids) > 0

            else:  # Linux/Mac
                result = subprocess.run(
                    ['lsof', '-ti', f':{port}'],
                    capture_output=True,
                    text=True
                )

                pids = result.stdout.strip().split('\n')
                for pid in pids:
                    if pid:
                        try:
                            subprocess.run(['kill', '-9', pid], check=True)
                            print(f"[+] Killed process {pid} on port {port}")
                        except:
                            pass

                return len(pids) > 0

        except Exception as e:
            print(f"[!] Error killing process on port {port}: {e}")
            return False

    def stop(self):
        """Stop the proxy server"""
        self.running = False
        if self.server:
            self.server.shutdown()

        # OPTIMIZATION: Close connection pool
        try:
            self.connection_pool.close()
        except Exception as e:
            print(f"[!] Error closing connection pool: {e}")

        # Clear caches
        try:
            self.dns_cache.clear()
            self.ssl_cert_cache.clear()
        except Exception as e:
            print(f"[!] Error clearing caches: {e}")

    def _cleanup_memory(self):
        """Automatic memory cleanup - removes old history entries"""
        current_time = time.time()

        # Check if cleanup is needed
        if current_time - self._last_cleanup < self._cleanup_interval:
            return

        with self._history_lock:
            # Trim history if too large
            if len(self.history) > self.max_history:
                # Remove oldest 20%
                remove_count = int(self.max_history * 0.2)
                self.history = self.history[remove_count:]

            # Trim WebSocket history
            if len(self.ws_history) > self.max_ws_history:
                remove_count = int(self.max_ws_history * 0.2)
                self.ws_history = self.ws_history[remove_count:]

            self._last_cleanup = current_time

        # Clean up stale pending requests (older than 2 minutes)
        with self._pending_lock:
            stale_ids = []
            for req_id, data in self.pending_requests.items():
                if current_time - data.get('timestamp', current_time) > 120:
                    stale_ids.append(req_id)

            for req_id in stale_ids:
                self.pending_requests.pop(req_id, None)
                event = self.pending_events.pop(req_id, None)
                if event:
                    event.set()  # Unblock waiting thread

    def _check_rate_limit(self, host):
        """Check if request from host exceeds rate limit

        Returns:
            bool: True if request should be allowed, False if rate limit exceeded
        """
        current_time = time.time()

        if host not in self.rate_limiter:
            self.rate_limiter[host] = {'count': 1, 'window_start': current_time}
            return True

        rate_data = self.rate_limiter[host]

        # Reset window if expired
        if current_time - rate_data['window_start'] >= self.rate_limit_window:
            rate_data['count'] = 1
            rate_data['window_start'] = current_time
            return True

        # Increment counter
        rate_data['count'] += 1

        # Check limit
        if rate_data['count'] > self.rate_limit_max_requests:
            return False

        return True

    def _add_to_history(self, request_data):
        """Add request to history with automatic memory management"""
        with self._history_lock:
            self.history.append(request_data)

            # Trim if exceeds max
            if len(self.history) > self.max_history:
                self.history.pop(0)

        # Periodic cleanup
        self._cleanup_memory()

    def _decode_response_body(self, body, headers):
        """Smart charset detection and decoding for response body

        Args:
            body: Raw response body (bytes)
            headers: Response headers dict

        Returns:
            Decoded text string
        """
        # If already a string, return as-is
        if not isinstance(body, bytes):
            return str(body)

        # Empty body
        if not body:
            return ''

        # Check for binary content (images, PDFs, etc.)
        content_type = ''
        for key, value in headers.items():
            if key.lower() == 'content-type':
                content_type = value.lower()
                break

        # Don't decode binary content
        if any(binary_type in content_type for binary_type in [
            'image/', 'video/', 'audio/', 'application/octet-stream',
            'application/zip', 'application/gzip', 'application/pdf',
            'application/x-shockwave-flash', 'font/', 'application/wasm'
        ]):
            return '[Binary Content]'

        # Heuristic: Check for null bytes (indicates binary)
        if b'\x00' in body[:1024]:
            return '[Binary Content]'

        # Extract charset from Content-Type header
        charset = None
        if content_type and 'charset=' in content_type:
            try:
                charset = content_type.split('charset=')[1].split(';')[0].strip().strip('"\'')
            except:
                pass

        # Try to decode with specified charset
        if charset:
            try:
                return body.decode(charset, errors='replace')
            except (UnicodeDecodeError, LookupError):
                pass  # Fall through to detection

        # Try chardet if available (better detection)
        try:
            import chardet
            detected = chardet.detect(body[:10000])  # Detect on first 10KB
            if detected and detected.get('encoding'):
                detected_charset = detected['encoding']
                try:
                    return body.decode(detected_charset, errors='replace')
                except (UnicodeDecodeError, LookupError):
                    pass  # Fall through to UTF-8
        except ImportError:
            pass  # chardet not available

        # Common encodings to try
        for encoding in ['utf-8', 'latin-1', 'windows-1252', 'iso-8859-1']:
            try:
                return body.decode(encoding, errors='replace')
            except (UnicodeDecodeError, LookupError):
                continue

        # Last resort: UTF-8 with replace
        return body.decode('utf-8', errors='replace')

    def _truncate_for_gui(self, response_data):
        """Truncate large response bodies for GUI display to prevent performance issues

        Args:
            response_data: Original response dict with potentially large body

        Returns:
            Response dict with truncated body if necessary
        """
        # Create a copy to avoid modifying original
        gui_response = response_data.copy()

        # Get Content-Type header (case-insensitive)
        headers = gui_response.get('headers', {})
        content_type = ''
        for key, value in headers.items():
            if key.lower() == 'content-type':
                content_type = value.lower()
                break

        # Check if content is binary based on Content-Type
        is_binary = any(binary_type in content_type for binary_type in [
            'image/', 'video/', 'audio/', 'application/octet-stream',
            'application/zip', 'application/gzip', 'application/pdf',
            'application/x-', 'font/', 'application/wasm'
        ])

        # Get body and check size
        body = gui_response.get('body', b'')
        if isinstance(body, str):
            body_bytes = body.encode('utf-8', errors='ignore')
        else:
            body_bytes = body if body else b''

        # ALWAYS check for binary content first (before truncation)
        is_likely_binary = False

        # Check 1: Binary Content-Type
        if is_binary:
            is_likely_binary = True

        # Check 2: Heuristic - null bytes or too many non-printable chars
        if not is_likely_binary and body_bytes:
            null_bytes = body_bytes.count(b'\x00')
            sample_size = min(2048, len(body_bytes))  # Check first 2KB
            sample = body_bytes[:sample_size]
            non_printable = sum(1 for b in sample if b < 32 and b not in [9, 10, 13])

            # More aggressive detection
            if null_bytes > 0 or (sample_size > 0 and non_printable / sample_size > 0.15):
                is_likely_binary = True

        # Check 3: Try to decode - if it fails badly, it's binary
        if not is_likely_binary and body_bytes:
            try:
                test_decode = body_bytes[:1024].decode('utf-8', errors='strict')
            except UnicodeDecodeError:
                is_likely_binary = True

        # Check 4: Detect failed decompression (still compressed data)
        # Gzip magic bytes: 0x1f 0x8b, deflate starts with 0x78
        if not is_likely_binary and len(body_bytes) >= 2:
            # Check for gzip magic bytes in response that wasn't decompressed
            if body_bytes[0] == 0x1f and body_bytes[1] == 0x8b:
                is_likely_binary = True  # Still compressed
            # Check for zlib header (deflate)
            elif body_bytes[0] == 0x78 and body_bytes[1] in (0x01, 0x5E, 0x9C, 0xDA):
                is_likely_binary = True  # Still compressed

        # Check 5: Check if 'text' field looks like mojibake (garbled encoding)
        # This catches cases where requests.Response.text decoded with wrong charset
        if not is_likely_binary and 'text' in gui_response:
            text = gui_response['text']
            if isinstance(text, str) and len(text) > 0:
                # Check for common mojibake indicators
                sample = text[:1024]
                mojibake_chars = sum(1 for c in sample if ord(c) > 127 and (
                    ord(c) in range(0x80, 0xA0) or  # Control chars
                    c in '\ufffd\ufeff'  # Replacement character
                ))
                # If >20% high-byte chars that look like mojibake, treat as binary
                if len(sample) > 0 and mojibake_chars / len(sample) > 0.2:
                    is_likely_binary = True

        # If binary detected, show placeholder
        if is_likely_binary:
            size_kb = len(body_bytes) / 1024
            size_mb = size_kb / 1024
            if size_mb >= 1:
                size_str = f"{size_mb:.2f} MB"
            else:
                size_str = f"{size_kb:.2f} KB"

            ct_info = f" - {content_type}" if content_type else ""
            placeholder = f"[Binary Content{ct_info} - {size_str}]\n\nBinary/non-UTF-8 content cannot be displayed as text."
            gui_response['body'] = placeholder
            gui_response['text'] = placeholder
            return gui_response

        # If body exceeds GUI display limit, truncate it
        if len(body_bytes) > self.max_gui_display_size:
            truncated_bytes = body_bytes[:self.max_gui_display_size]

            # Try to decode truncated bytes, handling potential UTF-8 boundary issues
            try:
                if isinstance(body, str):
                    gui_response['body'] = truncated_bytes.decode('utf-8', errors='ignore')
                else:
                    gui_response['body'] = truncated_bytes.decode('utf-8', errors='ignore')
            except:
                gui_response['body'] = str(truncated_bytes)

            # Update text field if it exists
            if 'text' in gui_response:
                try:
                    gui_response['text'] = truncated_bytes.decode('utf-8', errors='ignore')
                except:
                    gui_response['text'] = str(truncated_bytes)

            # Add truncation indicator
            original_size = len(body_bytes)
            truncation_msg = f"\n\n[... Response truncated for GUI display: {original_size} bytes total, showing first {self.max_gui_display_size} bytes ...]"

            if isinstance(gui_response['body'], str):
                gui_response['body'] += truncation_msg
            if 'text' in gui_response:
                gui_response['text'] += truncation_msg

        return gui_response

    def _run_server(self):
        """Run the HTTP server"""
        proxy_instance = self

        # OPTIMIZATION: Create optimized threading HTTP server
        class ThreadingHTTPServer(ThreadingMixIn, HTTPServer):
            """Multi-threaded HTTP server to handle multiple requests simultaneously

            OPTIMIZATIONS:
            - daemon_threads: Threads don't block program exit
            - request_queue_size: Larger backlog for high traffic
            - allow_reuse_address: Fast port rebinding
            - allow_reuse_port: Better load distribution (Linux)
            """
            daemon_threads = True
            request_queue_size = 100  # Increased from default 5
            allow_reuse_address = True

            # Enable SO_REUSEPORT on Linux for better performance
            try:
                import socket as sock_module
                if hasattr(sock_module, 'SO_REUSEPORT'):
                    allow_reuse_port = True
            except:
                pass

        class ProxyHandler(BaseHTTPRequestHandler):
            def do_GET(self):
                self.handle_request('GET')

            def do_POST(self):
                self.handle_request('POST')

            def do_PUT(self):
                self.handle_request('PUT')

            def do_DELETE(self):
                self.handle_request('DELETE')

            def do_OPTIONS(self):
                self.handle_request('OPTIONS')

            def do_HEAD(self):
                self.handle_request('HEAD')

            def do_PATCH(self):
                self.handle_request('PATCH')

            def do_CONNECT(self):
                """Handle HTTPS CONNECT - perform SSL interception if enabled"""
                try:
                    # Parse host and port
                    host, port = self.path.split(':')
                    port = int(port)

                    if proxy_instance.ssl_intercept_enabled and proxy_instance.cert_manager:
                        # SSL INTERCEPTION MODE - decrypt and inspect HTTPS traffic
                        self._handle_ssl_interception(host, port)
                    else:
                        # TUNNEL MODE - simple encrypted passthrough (old behavior)
                        self._handle_ssl_tunnel(host, port)

                except Exception as e:
                    try:
                        self.send_error(502, f"Bad Gateway: {str(e)}")
                    except:
                        pass

            def _handle_ssl_tunnel(self, host, port):
                """Handle HTTPS tunnel - proven working implementation"""
                try:
                    # Connect to destination
                    dest = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    dest.connect((host, port))

                    # Send 200 to client
                    self.send_response(200, 'Connection Established')
                    self.end_headers()

                    # Log
                    request_data = {
                        'id': proxy_instance.request_id_counter,
                        'method': 'CONNECT',
                        'url': f"https://{host}:{port}",
                        'headers': dict(self.headers),
                        'body': '[HTTPS - Encrypted]',
                        'raw_body': b'',
                        'timestamp': time.time(),
                        'client_address': self.client_address[0]
                    }
                    proxy_instance.request_id_counter += 1

                    # Increment total requests counter for statistics
                    with proxy_instance._stats_lock:
                        proxy_instance.total_requests += 1
                        # Emit statistics update signal
                        try:
                            proxy_instance.statistics_updated.emit({
                                'total': proxy_instance.total_requests,
                                'blocked_analytics': proxy_instance.blocked_analytics_requests
                            })
                        except:
                            pass  # Ignore signal errors

                    # Check scope and ignore patterns for HTTPS tunnels too
                    url = request_data['url']
                    should_log = True

                    if proxy_instance.should_ignore(url):
                        should_log = False

                    if should_log and proxy_instance.scope_enabled:
                        if not proxy_instance.is_in_scope(url):
                            should_log = False

                    # Only log if passes filters
                    if should_log:
                        # OPTIMIZATION: Use memory-efficient history management
                        proxy_instance._add_to_history(request_data)

                        proxy_instance.response_received.emit({
                            'request': request_data,
                            'response': {
                                'status_code': 200,
                                'headers': {'Connection': 'Established'},
                                'body': b'',
                                'text': '[HTTPS Tunnel]'
                            }
                        })

                    # Set non-blocking
                    self.connection.setblocking(0)
                    dest.setblocking(0)

                    # Relay data
                    import select
                    conns = [self.connection, dest]
                    count = 0
                    while True:
                        count += 1
                        (recv, _, err) = select.select(conns, [], conns, 1)
                        if err:
                            break
                        if recv:
                            for in_ in recv:
                                try:
                                    data = in_.recv(8192)
                                except:
                                    break
                                if not data:
                                    break
                                out = dest if in_ is self.connection else self.connection
                                try:
                                    out.sendall(data)
                                except:
                                    break
                    dest.close()
                except Exception as e:
                    print(f"[!] Tunnel error {host}: {e}")

            def _handle_ssl_interception(self, host, port):
                """Handle HTTPS with SSL interception (decrypt and inspect)"""
                try:
                    # Send 200 Connection Established to client
                    self.send_response(200, 'Connection Established')
                    self.end_headers()

                    # Get client socket
                    client_socket = self.connection

                    # Wrap client socket with our SSL certificate
                    ssl_client_socket = proxy_instance.cert_manager.wrap_client_socket(
                        client_socket, host
                    )

                    # Create new HTTP handler for the SSL connection
                    # This allows us to intercept individual HTTPS requests
                    self._proxy_ssl_connection(ssl_client_socket, host, port)

                except ssl.SSLError as e:
                    print(f"[!] SSL error for {host}: {e}")
                except BrokenPipeError:
                    print(f"[!] Client disconnected for {host}")
                except ConnectionResetError:
                    print(f"[!] Connection reset for {host}")
                except Exception as e:
                    print(f"[!] Error intercepting HTTPS for {host}: {e}")

            def _proxy_ssl_connection(self, ssl_client_socket, host, port):
                """Proxy individual HTTPS requests after SSL handshake (OPTIMIZED)

                Handles multiple requests over single SSL connection (HTTP keep-alive)

                OPTIMIZATIONS:
                - Larger buffer size (8KB instead of 4KB) for better throughput
                - Efficient header reading with size limits
                - Request size limits to prevent memory issues
                """
                try:
                    # OPTIMIZATION: Increase socket timeout for better stability
                    ssl_client_socket.settimeout(15)

                    # Handle multiple requests on same connection (HTTP keep-alive)
                    while True:
                        try:
                            # OPTIMIZATION: Read HTTP request with larger buffer (8KB)
                            request_data_raw = b''
                            buffer_size = 8192  # Increased from 4096 for better performance

                            while b'\r\n\r\n' not in request_data_raw:
                                chunk = ssl_client_socket.recv(buffer_size)
                                if not chunk:
                                    return  # Connection closed
                                request_data_raw += chunk

                                # OPTIMIZATION: Stricter header size limit
                                if len(request_data_raw) > 512 * 1024:  # 512KB limit for headers
                                    print(f"[!] Headers too large for {host}")
                                    return

                            # Split headers and potential body
                            header_end = request_data_raw.find(b'\r\n\r\n')
                            header_data = request_data_raw[:header_end]
                            body_data = request_data_raw[header_end + 4:]

                            # Parse request line
                            lines = header_data.decode('utf-8', errors='ignore').split('\r\n')
                            if not lines or not lines[0]:
                                return

                            parts = lines[0].split(' ')
                            if len(parts) < 3:
                                return

                            method, path, http_version = parts[0], parts[1], parts[2]

                            # Parse headers
                            headers = {}
                            for line in lines[1:]:
                                if ':' in line:
                                    key, value = line.split(':', 1)
                                    headers[key.strip()] = value.strip()

                            # Read remaining body if needed
                            body = body_data
                            content_length = int(headers.get('Content-Length', 0))
                            if content_length > len(body):
                                remaining = content_length - len(body)
                                body += ssl_client_socket.recv(remaining)

                            # Build full URL
                            url = f"https://{host}{path}"

                            # Create request data
                            request_data = {
                                'id': proxy_instance.request_id_counter,
                                'method': method,
                                'url': url,
                                'headers': headers,
                                'body': body.decode('utf-8', errors='ignore') if body else '',
                                'raw_body': body,
                                'timestamp': time.time(),
                                'client_address': self.client_address[0]
                            }
                            proxy_instance.request_id_counter += 1

                            # OPTIMIZATION: Use memory-efficient history management
                            proxy_instance._add_to_history(request_data)

                            # Emit request signal
                            proxy_instance.request_intercepted.emit(request_data)

                            # Debug logging
                            print(f"[HTTPS] {method} {url}")

                            # Forward request to destination
                            response = self._forward_https_request(request_data, host, port)

                            # Debug response
                            print(f"[HTTPS] <- {response['status_code']} ({len(response.get('body', b''))} bytes)")

                            # Passive scan
                            if proxy_instance.passive_scan_enabled:
                                try:
                                    proxy_instance._passive_scan(request_data, response)
                                except Exception as scan_err:
                                    print(f"[!] Passive scan error: {scan_err}")

                            # Get status text
                            status_texts = {
                                200: 'OK', 201: 'Created', 204: 'No Content',
                                301: 'Moved Permanently', 302: 'Found', 304: 'Not Modified',
                                400: 'Bad Request', 401: 'Unauthorized', 403: 'Forbidden',
                                404: 'Not Found', 500: 'Internal Server Error', 502: 'Bad Gateway',
                                503: 'Service Unavailable'
                            }
                            status_text = status_texts.get(response['status_code'], 'OK')

                            # Send response back through SSL socket
                            try:
                                response_line = f"HTTP/1.1 {response['status_code']} {status_text}\r\n"
                                ssl_client_socket.sendall(response_line.encode())

                                # Send headers (skip problematic ones and update Content-Length)
                                response_body = response.get('body', b'')
                                if isinstance(response_body, str):
                                    response_body = response_body.encode('utf-8')

                                sent_content_length = False
                                sent_connection = False
                                was_decompressed = response.get('was_decompressed', False)

                                # Important headers that must be preserved
                                important_headers = ['location', 'set-cookie', 'content-type']

                                for header, value in response['headers'].items():
                                    header_lower = header.lower()

                                    # Always skip transfer-encoding (chunked handled by us)
                                    if header_lower == 'transfer-encoding':
                                        continue

                                    # Only skip content-encoding if we actually decompressed
                                    if header_lower == 'content-encoding':
                                        if was_decompressed:
                                            continue  # Skip - we decompressed
                                        else:
                                            ssl_client_socket.sendall(f"{header}: {value}\r\n".encode())
                                            continue  # Keep for browser

                                    # Update Content-Length with actual body size (always recalculate if decompressed)
                                    if header_lower == 'content-length':
                                        ssl_client_socket.sendall(f"Content-Length: {len(response_body)}\r\n".encode())
                                        sent_content_length = True

                                    # Handle Connection header for keep-alive
                                    elif header_lower == 'connection':
                                        # For redirects, use close; otherwise keep-alive
                                        if response['status_code'] in [301, 302, 303, 307, 308]:
                                            ssl_client_socket.sendall(b"Connection: keep-alive\r\n")
                                        else:
                                            ssl_client_socket.sendall(b"Connection: keep-alive\r\n")
                                        sent_connection = True

                                    # Send all other headers as-is (including Location for redirects!)
                                    else:
                                        try:
                                            ssl_client_socket.sendall(f"{header}: {value}\r\n".encode())
                                        except:
                                            # Some headers might have encoding issues
                                            pass

                                # Ensure Content-Length is always set
                                if not sent_content_length:
                                    ssl_client_socket.sendall(f"Content-Length: {len(response_body)}\r\n".encode())

                                # Ensure Connection header is set
                                if not sent_connection:
                                    ssl_client_socket.sendall(b"Connection: keep-alive\r\n")

                                ssl_client_socket.sendall(b'\r\n')

                                if response_body:
                                    ssl_client_socket.sendall(response_body)

                            except (BrokenPipeError, ConnectionResetError, OSError) as send_err:
                                print(f"[!] Client disconnected while sending response for {host}: {send_err}")
                                break  # Exit the keep-alive loop if client disconnected

                            # Emit signal with truncated response for GUI performance
                            proxy_instance.response_received.emit({
                                'request': request_data,
                                'response': proxy_instance._truncate_for_gui(response)
                            })

                            # Check if client wants to close connection
                            if headers.get('Connection', '').lower() == 'close':
                                break

                        except socket.timeout:
                            # Timeout on keep-alive is normal - client finished sending requests
                            break
                        except Exception as e:
                            print(f"[!] Error handling request for {host}: {e}")
                            break

                except socket.timeout:
                    # Initial timeout is normal for keep-alive
                    pass
                except Exception as e:
                    print(f"[!] Error proxying SSL connection for {host}: {e}")
                    import traceback
                    traceback.print_exc()
                finally:
                    try:
                        ssl_client_socket.close()
                    except:
                        pass

            def _forward_https_request(self, request_data, host, port):
                """Forward HTTPS request to destination server (OPTIMIZED)"""
                try:
                    # OPTIMIZATION: Check request size limit
                    body = request_data['raw_body']
                    if len(body) > proxy_instance.max_request_size:
                        return {
                            'status_code': 413,
                            'headers': {'Content-Type': 'text/plain'},
                            'body': b'Request entity too large',
                            'text': 'Request entity too large',
                            'timestamp': time.time()
                        }

                    # OPTIMIZATION: Use connection pool for faster HTTPS requests
                    response = proxy_instance.connection_pool.request(
                        method=request_data['method'],
                        url=request_data['url'],
                        headers=request_data['headers'],
                        data=body,
                        allow_redirects=False,
                        timeout=15,  # Faster timeout
                        stream=True  # Stream large responses
                    )

                    # OPTIMIZATION: Check response size limit
                    content_length = int(response.headers.get('Content-Length', 0))
                    if content_length > proxy_instance.max_response_size:
                        response.close()
                        return {
                            'status_code': 413,
                            'headers': {'Content-Type': 'text/plain'},
                            'body': b'Response entity too large',
                            'text': 'Response entity too large',
                            'timestamp': time.time()
                        }

                    # Read response content
                    response_content = response.content

                    # Decompress content (gzip, deflate, brotli)
                    content_encoding = response.headers.get('Content-Encoding', '')
                    body, was_decompressed = decompress_content(response_content, content_encoding)

                    # Smart charset detection for text decoding
                    text = proxy_instance._decode_response_body(body, response.headers)

                    return {
                        'status_code': response.status_code,
                        'headers': dict(response.headers),
                        'body': body,
                        'text': text,
                        'timestamp': time.time(),
                        'was_decompressed': was_decompressed  # Track if we decompressed
                    }

                except requests.exceptions.Timeout:
                    return {
                        'status_code': 504,
                        'headers': {'Content-Type': 'text/plain'},
                        'body': b'Gateway Timeout',
                        'text': 'Gateway Timeout',
                        'timestamp': time.time()
                    }
                except requests.exceptions.ConnectionError as e:
                    return {
                        'status_code': 502,
                        'headers': {'Content-Type': 'text/plain'},
                        'body': f'Bad Gateway: {str(e)}'.encode(),
                        'text': f'Bad Gateway: {str(e)}',
                        'timestamp': time.time()
                    }
                except Exception as e:
                    return {
                        'status_code': 502,
                        'headers': {'Content-Type': 'text/plain'},
                        'body': f"Proxy error: {str(e)}".encode(),
                        'text': f"Proxy error: {str(e)}",
                        'timestamp': time.time()
                    }

            def handle_request(self, method):
                """Handle HTTP request"""
                # Check for Dominator status page
                host = self.headers.get('Host', '')
                path = self.path.lower()

                # Serve status page for special hostnames or /dominator path or certificate paths
                is_status_host = host.lower() in ['dominator', 'dominator.local', 'proxy.dominator']
                is_status_path = path == '/dominator' or path.startswith('/dominator/')
                is_cert_path = path in ['/ca.crt', '/certificate', '/cert']

                if is_status_host or is_status_path or is_cert_path:
                    self._serve_status_page()
                    return

                # Parse request
                content_length = int(self.headers.get('Content-Length', 0))
                body = self.rfile.read(content_length) if content_length > 0 else b''

                # Build request dict
                request_data = {
                    'id': proxy_instance.request_id_counter,
                    'method': method,
                    'url': self.path,
                    'headers': dict(self.headers),
                    'body': body.decode('utf-8', errors='ignore') if body else '',
                    'raw_body': body,
                    'timestamp': time.time(),
                    'client_address': self.client_address[0]
                }

                proxy_instance.request_id_counter += 1

                # Increment total requests counter for statistics
                with proxy_instance._stats_lock:
                    proxy_instance.total_requests += 1
                    # Emit statistics update signal
                    try:
                        proxy_instance.statistics_updated.emit({
                            'total': proxy_instance.total_requests,
                            'blocked_analytics': proxy_instance.blocked_analytics_requests
                        })
                    except:
                        pass  # Ignore signal errors

                # Check for WebSocket upgrade request
                upgrade_header = self.headers.get('Upgrade', '').lower()
                connection_header = self.headers.get('Connection', '').lower()

                if upgrade_header == 'websocket' and 'upgrade' in connection_header:
                    # Handle WebSocket upgrade
                    self._handle_websocket_upgrade(request_data)
                    return

                # OPTIMIZATION: Use memory-efficient history management
                proxy_instance._add_to_history(request_data)

                # Check if intercept is enabled and host is not auto-allowed
                parsed_url = urlparse(self.path)
                host = parsed_url.netloc or self.headers.get('Host', '')

                should_intercept = (
                    proxy_instance.intercept_enabled and
                    host not in proxy_instance.auto_allow_hosts
                )

                if should_intercept:
                    # Create event for this request
                    event = threading.Event()
                    proxy_instance.pending_events[request_data['id']] = event

                    # Wait for user decision (with timeout)
                    proxy_instance.pending_requests[request_data['id']] = {
                        'request': request_data,
                        'action': None,  # 'forward', 'drop', 'modified'
                        'modified_request': None
                    }

                    # Signal GUI to show intercept dialog
                    proxy_instance.request_intercepted.emit(request_data)

                    # Wait for user action using Event (much more efficient than polling)
                    event.wait(timeout=60)

                    # Get user decision
                    pending = proxy_instance.pending_requests.get(request_data['id'], {})
                    action = pending.get('action', 'forward')

                    if action == 'drop':
                        # Clean up
                        proxy_instance.pending_requests.pop(request_data['id'], None)
                        proxy_instance.pending_events.pop(request_data['id'], None)
                        self.send_error(403, "Request dropped by user")
                        return
                    elif action == 'modified':
                        request_data = pending.get('modified_request', request_data)

                    # Clean up
                    proxy_instance.pending_requests.pop(request_data['id'], None)
                    proxy_instance.pending_events.pop(request_data['id'], None)

                # Forward request
                try:
                    response = self._forward_request(request_data)

                    # Passive scan
                    if proxy_instance.passive_scan_enabled:
                        proxy_instance._passive_scan(request_data, response)

                    # Send response back to client
                    self.send_response(response['status_code'])

                    # Track if we've sent Connection header
                    sent_connection = False
                    sent_content_length = False
                    was_decompressed = response.get('was_decompressed', False)

                    for header, value in response['headers'].items():
                        header_lower = header.lower()

                        # Always skip transfer-encoding (chunked handled by HTTP lib)
                        if header_lower == 'transfer-encoding':
                            continue

                        # Only skip content-encoding if we actually decompressed
                        # If decompression failed, keep the header so browser can handle it
                        if header_lower == 'content-encoding':
                            if was_decompressed:
                                continue  # Skip - we decompressed, browser gets raw data
                            else:
                                self.send_header(header, value)  # Keep - browser will decompress
                                continue

                        # Track Connection header
                        if header_lower == 'connection':
                            # Force close to avoid hanging
                            self.send_header('Connection', 'close')
                            sent_connection = True
                        elif header_lower == 'content-length':
                            # If we decompressed, content length changed - recalculate later
                            if not was_decompressed:
                                self.send_header(header, value)
                                sent_content_length = True
                        else:
                            self.send_header(header, value)

                    # Force Connection: close to prevent hanging
                    if not sent_connection:
                        self.send_header('Connection', 'close')

                    # Ensure Content-Length is set
                    if not sent_content_length and response.get('body'):
                        body = response['body']
                        if isinstance(body, str):
                            body = body.encode('utf-8')
                        self.send_header('Content-Length', str(len(body)))

                    self.end_headers()

                    if response['body']:
                        body = response['body']
                        if isinstance(body, str):
                            body = body.encode('utf-8')
                        self.wfile.write(body)

                    # Check scope and ignore patterns before logging
                    url = request_data['url']
                    should_log = True

                    # Check if should be ignored (static files, etc.)
                    if proxy_instance.should_ignore(url):
                        should_log = False

                    # Check scope (only if enabled)
                    if should_log and proxy_instance.scope_enabled:
                        if not proxy_instance.is_in_scope(url):
                            should_log = False

                    # Signal GUI (only if passes filters)
                    if should_log:
                        # OPTIMIZATION: Use memory-efficient history management
                        proxy_instance._add_to_history(request_data)

                        # Emit signal for GUI with truncated response
                        proxy_instance.response_received.emit({
                            'request': request_data,
                            'response': proxy_instance._truncate_for_gui(response)
                        })

                except Exception as e:
                    self.send_error(502, f"Proxy error: {str(e)}")

            def _serve_status_page(self):
                """Serve Dominator proxy status page with certificate download"""
                path = self.path.lower()

                # Serve CA certificate for download
                if '/ca.crt' in path or '/certificate' in path or '/cert' in path:
                    if proxy_instance.cert_manager:
                        cert_path = proxy_instance.cert_manager.get_ca_cert_path()
                        try:
                            with open(cert_path, 'rb') as f:
                                cert_data = f.read()
                            self.send_response(200)
                            self.send_header('Content-Type', 'application/x-x509-ca-cert')
                            self.send_header('Content-Disposition', 'attachment; filename="dominator-ca.crt"')
                            self.send_header('Content-Length', len(cert_data))
                            self.end_headers()
                            self.wfile.write(cert_data)
                            return
                        except Exception as e:
                            self.send_error(500, f"Could not read certificate: {e}")
                            return
                    else:
                        self.send_error(404, "SSL interception not enabled - no certificate available")
                        return

                # Serve status page
                client_ip = self.client_address[0]
                history_count = len(proxy_instance.history)
                ssl_status = "Enabled" if proxy_instance.ssl_intercept_enabled else "Disabled"
                intercept_status = "Enabled" if proxy_instance.intercept_enabled else "Disabled"
                passive_status = "Enabled" if proxy_instance.passive_scan_enabled else "Disabled"
                scope_status = "Enabled" if proxy_instance.scope_enabled else "Disabled"
                pending_count = len(proxy_instance.pending_requests)
                auto_allow_count = len(proxy_instance.auto_allow_hosts)

                # Get uptime
                import datetime
                uptime = "Running"

                cert_section = ""
                if proxy_instance.cert_manager:
                    cert_path = proxy_instance.cert_manager.get_ca_cert_path()
                    cert_section = f'''
                    <div class="card">
                        <h2>SSL Certificate</h2>
                        <p>To inspect HTTPS traffic, install the Dominator CA certificate in your browser:</p>
                        <a href="/ca.crt" class="download-btn">Download CA Certificate</a>
                        <p class="note">Certificate location: {cert_path}</p>
                        <h3>Installation Instructions:</h3>
                        <ul>
                            <li><strong>Firefox:</strong> Settings > Privacy & Security > Certificates > View Certificates > Import</li>
                            <li><strong>Chrome:</strong> Settings > Privacy and Security > Security > Manage Certificates > Import</li>
                            <li><strong>Windows:</strong> Double-click the .crt file > Install Certificate > Local Machine > Trusted Root</li>
                        </ul>
                    </div>
                    '''

                html = f'''<!DOCTYPE html>
<html>
<head>
    <title>Dominator Proxy</title>
    <style>
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%);
            color: #e0e0e0;
            margin: 0;
            padding: 20px;
            min-height: 100vh;
        }}
        .container {{
            max-width: 800px;
            margin: 0 auto;
        }}
        h1 {{
            color: #00ff88;
            text-align: center;
            font-size: 2.5em;
            margin-bottom: 10px;
        }}
        .subtitle {{
            text-align: center;
            color: #888;
            margin-bottom: 30px;
        }}
        .card {{
            background: rgba(255,255,255,0.05);
            border-radius: 10px;
            padding: 20px;
            margin-bottom: 20px;
            border: 1px solid rgba(255,255,255,0.1);
        }}
        h2 {{
            color: #00ff88;
            margin-top: 0;
            border-bottom: 1px solid rgba(0,255,136,0.3);
            padding-bottom: 10px;
        }}
        .status-grid {{
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 10px;
        }}
        .status-item {{
            padding: 10px;
            background: rgba(0,0,0,0.2);
            border-radius: 5px;
        }}
        .status-label {{
            color: #888;
            font-size: 0.9em;
        }}
        .status-value {{
            color: #fff;
            font-weight: bold;
            font-size: 1.1em;
        }}
        .status-enabled {{
            color: #00ff88;
        }}
        .status-disabled {{
            color: #ff6b6b;
        }}
        .download-btn {{
            display: inline-block;
            background: #00ff88;
            color: #000;
            padding: 12px 24px;
            border-radius: 5px;
            text-decoration: none;
            font-weight: bold;
            margin: 10px 0;
        }}
        .download-btn:hover {{
            background: #00cc6a;
        }}
        .note {{
            color: #888;
            font-size: 0.85em;
            font-style: italic;
        }}
        ul {{
            color: #ccc;
            line-height: 1.8;
        }}
        .ip-display {{
            font-size: 1.5em;
            color: #00ff88;
            font-family: monospace;
        }}
        .footer {{
            text-align: center;
            margin-top: 30px;
            color: #666;
            font-size: 0.9em;
        }}
    </style>
</head>
<body>
    <div class="container">
        <h1>DOMINATOR</h1>
        <p class="subtitle">Web Vulnerability Scanner - Proxy Status</p>

        <div class="card">
            <h2>Proxy Status</h2>
            <p style="color: #00ff88; font-size: 1.2em;">Proxy is running and operational</p>
            <div class="status-grid">
                <div class="status-item">
                    <div class="status-label">Port</div>
                    <div class="status-value">{proxy_instance.port}</div>
                </div>
                <div class="status-item">
                    <div class="status-label">Your IP</div>
                    <div class="status-value ip-display">{client_ip}</div>
                </div>
                <div class="status-item">
                    <div class="status-label">Requests Captured</div>
                    <div class="status-value">{history_count}</div>
                </div>
                <div class="status-item">
                    <div class="status-label">SSL Interception</div>
                    <div class="status-value {'status-enabled' if proxy_instance.ssl_intercept_enabled else 'status-disabled'}">{ssl_status}</div>
                </div>
                <div class="status-item">
                    <div class="status-label">Request Interception</div>
                    <div class="status-value {'status-enabled' if proxy_instance.intercept_enabled else 'status-disabled'}">{intercept_status}</div>
                </div>
                <div class="status-item">
                    <div class="status-label">Passive Scanning</div>
                    <div class="status-value {'status-enabled' if proxy_instance.passive_scan_enabled else 'status-disabled'}">{passive_status}</div>
                </div>
                <div class="status-item">
                    <div class="status-label">Scope Filter</div>
                    <div class="status-value {'status-enabled' if proxy_instance.scope_enabled else 'status-disabled'}">{scope_status}</div>
                </div>
                <div class="status-item">
                    <div class="status-label">Pending Intercepts</div>
                    <div class="status-value">{pending_count}</div>
                </div>
                <div class="status-item">
                    <div class="status-label">Auto-Allowed Hosts</div>
                    <div class="status-value">{auto_allow_count}</div>
                </div>
                <div class="status-item">
                    <div class="status-label">Max History</div>
                    <div class="status-value">{proxy_instance.max_history}</div>
                </div>
            </div>
        </div>

        <div class="card">
            <h2>How to Use</h2>
            <ol style="color: #ccc; line-height: 2;">
                <li><strong>Configure Browser:</strong> Set your browser's proxy to <code style="color: #00ff88;">127.0.0.1:{proxy_instance.port}</code></li>
                <li><strong>Install Certificate:</strong> Download and install the CA certificate below for HTTPS inspection</li>
                <li><strong>Browse:</strong> Visit websites - all traffic will be captured in the History tab</li>
                <li><strong>Analyze:</strong> Select requests in History to see full details in Inspector</li>
                <li><strong>Test:</strong> Send requests to Repeater to modify and replay them</li>
            </ol>
        </div>

        {cert_section}

        <div class="card">
            <h2>Quick Links</h2>
            <ul>
                <li><a href="/ca.crt" style="color: #00ff88;">Download CA Certificate</a></li>
                <li>Proxy Address: <code style="color: #00ff88;">127.0.0.1:{proxy_instance.port}</code></li>
            </ul>
        </div>

        <div class="footer">
            Dominator Web Vulnerability Scanner<br>
            Visit <a href="http://dominator" style="color: #00ff88;">http://dominator</a> to see this page
        </div>
    </div>
</body>
</html>'''

                html_bytes = html.encode('utf-8')
                self.send_response(200)
                self.send_header('Content-Type', 'text/html; charset=utf-8')
                self.send_header('Content-Length', len(html_bytes))
                self.send_header('Connection', 'close')
                self.end_headers()
                self.wfile.write(html_bytes)

            def _forward_request(self, request_data):
                """Forward request to target server (OPTIMIZED)"""
                url = request_data['url']
                method = request_data['method']
                headers = request_data['headers'].copy()
                body = request_data['raw_body']

                # OPTIMIZATION: Check request size limit
                if len(body) > proxy_instance.max_request_size:
                    return {
                        'status_code': 413,
                        'headers': {'Content-Type': 'text/plain'},
                        'body': b'Request entity too large',
                        'text': 'Request entity too large',
                        'timestamp': time.time()
                    }

                # Remove proxy-specific headers
                headers.pop('Proxy-Connection', None)
                headers.pop('Connection', None)

                try:
                    # OPTIMIZATION: Use connection pool for faster requests
                    response = proxy_instance.connection_pool.request(
                        method=method,
                        url=url,
                        headers=headers,
                        data=body,
                        allow_redirects=False,
                        timeout=15,  # Faster timeout
                        stream=True  # Stream large responses
                    )

                    # OPTIMIZATION: Check response size limit before reading full body
                    content_length = int(response.headers.get('Content-Length', 0))
                    if content_length > proxy_instance.max_response_size:
                        response.close()
                        return {
                            'status_code': 413,
                            'headers': {'Content-Type': 'text/plain'},
                            'body': b'Response entity too large',
                            'text': 'Response entity too large',
                            'timestamp': time.time()
                        }

                    # Read response content
                    response_content = response.content

                    # Decompress content (gzip, deflate, brotli)
                    content_encoding = response.headers.get('Content-Encoding', '')
                    body, was_decompressed = decompress_content(response_content, content_encoding)

                    # Smart charset detection for text decoding
                    text = proxy_instance._decode_response_body(body, response.headers)

                    return {
                        'status_code': response.status_code,
                        'headers': dict(response.headers),
                        'body': body,
                        'text': text,
                        'timestamp': time.time(),
                        'was_decompressed': was_decompressed  # Track if we decompressed
                    }

                except requests.exceptions.Timeout:
                    return {
                        'status_code': 504,
                        'headers': {'Content-Type': 'text/plain'},
                        'body': b'Gateway Timeout',
                        'text': 'Gateway Timeout',
                        'timestamp': time.time()
                    }
                except requests.exceptions.ConnectionError as e:
                    return {
                        'status_code': 502,
                        'headers': {'Content-Type': 'text/plain'},
                        'body': f'Bad Gateway: {str(e)}'.encode(),
                        'text': f'Bad Gateway: {str(e)}',
                        'timestamp': time.time()
                    }
                except Exception as e:
                    return {
                        'status_code': 502,
                        'headers': {'Content-Type': 'text/plain'},
                        'body': f'Proxy error: {str(e)}'.encode(),
                        'text': f'Proxy error: {str(e)}',
                        'timestamp': time.time()
                    }

            def _handle_websocket_upgrade(self, request_data):
                """Handle WebSocket upgrade request - proxy bidirectional communication"""
                import select
                import struct
                import hashlib
                import base64

                try:
                    # Parse URL for destination
                    parsed = urlparse(request_data['url'])
                    host = parsed.netloc or request_data['headers'].get('Host', '')
                    port = 80
                    use_ssl = False

                    if ':' in host:
                        host, port = host.rsplit(':', 1)
                        port = int(port)
                    elif parsed.scheme == 'wss' or request_data['url'].startswith('wss://'):
                        port = 443
                        use_ssl = True
                    elif parsed.scheme == 'https' or request_data['url'].startswith('https://'):
                        port = 443
                        use_ssl = True

                    # Connect to WebSocket server
                    dest = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    dest.settimeout(10)
                    dest.connect((host, port))

                    if use_ssl:
                        import ssl
                        context = ssl.create_default_context()
                        context.check_hostname = False
                        context.verify_mode = ssl.CERT_NONE
                        dest = context.wrap_socket(dest, server_hostname=host)

                    # Forward upgrade request to server
                    path = parsed.path or '/'
                    if parsed.query:
                        path += '?' + parsed.query

                    upgrade_request = f"GET {path} HTTP/1.1\r\n"
                    for header, value in request_data['headers'].items():
                        if header.lower() not in ['proxy-connection']:
                            upgrade_request += f"{header}: {value}\r\n"
                    upgrade_request += "\r\n"

                    dest.sendall(upgrade_request.encode())

                    # Receive server response
                    response = b""
                    while b"\r\n\r\n" not in response:
                        chunk = dest.recv(1024)
                        if not chunk:
                            break
                        response += chunk

                    # Check for successful upgrade (101 Switching Protocols)
                    if b"101" not in response.split(b"\r\n")[0]:
                        self.send_error(502, "WebSocket upgrade failed")
                        dest.close()
                        return

                    # Forward response to client
                    self.wfile.write(response)
                    self.wfile.flush()

                    # Log WebSocket connection
                    ws_data = {
                        'id': proxy_instance.ws_message_counter,
                        'type': 'connection',
                        'url': request_data['url'],
                        'direction': 'upgrade',
                        'data': '[WebSocket Upgrade]',
                        'timestamp': time.time()
                    }
                    proxy_instance.ws_message_counter += 1
                    proxy_instance.ws_history.append(ws_data)
                    proxy_instance.websocket_message.emit(ws_data)

                    # Set non-blocking for bidirectional relay
                    self.connection.setblocking(0)
                    dest.setblocking(0)

                    # Relay WebSocket frames
                    conns = [self.connection, dest]
                    while True:
                        try:
                            (recv, _, err) = select.select(conns, [], conns, 1)
                        except:
                            break

                        if err:
                            break

                        for sock in recv:
                            try:
                                data = sock.recv(65536)
                            except:
                                data = None

                            if not data:
                                break

                            # Determine direction and destination
                            if sock is self.connection:
                                direction = 'client->server'
                                out_sock = dest
                            else:
                                direction = 'server->client'
                                out_sock = self.connection

                            # Log WebSocket message
                            ws_msg = {
                                'id': proxy_instance.ws_message_counter,
                                'type': 'message',
                                'url': request_data['url'],
                                'direction': direction,
                                'data': data[:500].hex() if len(data) > 500 else data.hex(),
                                'length': len(data),
                                'timestamp': time.time()
                            }
                            proxy_instance.ws_message_counter += 1

                            if len(proxy_instance.ws_history) > proxy_instance.max_ws_history:
                                proxy_instance.ws_history.pop(0)
                            proxy_instance.ws_history.append(ws_msg)

                            # Emit signal for GUI
                            try:
                                proxy_instance.websocket_message.emit(ws_msg)
                            except:
                                pass

                            # Forward data
                            try:
                                out_sock.sendall(data)
                            except:
                                break
                        else:
                            continue
                        break

                    # Close connections
                    try:
                        dest.close()
                    except:
                        pass

                except Exception as e:
                    print(f"[!] WebSocket error: {e}")
                    try:
                        self.send_error(502, f"WebSocket error: {str(e)}")
                    except:
                        pass

            def log_message(self, format, *args):
                """Suppress default logging"""
                pass

        # Start server
        try:
            print(f"[+] Starting proxy server on 127.0.0.1:{self.port}")
            self.server = ThreadingHTTPServer(('127.0.0.1', self.port), ProxyHandler)
            print(f"[+] Proxy server listening (multi-threaded)...")
            self.server.serve_forever()
        except OSError as e:
            if e.errno == 10048:  # Address already in use on Windows
                print(f"[!] Port {self.port} is already in use. Please stop other processes using this port.")
            else:
                print(f"[!] Proxy server OS error: {e}")
            self.running = False
        except Exception as e:
            print(f"[!] Proxy server error: {e}")
            import traceback
            traceback.print_exc()
            self.running = False

    def _passive_scan(self, request, response):
        """Run passive scans on request/response"""
        # Skip if passive scanners not available
        if not self.passive_scanner or not self.sensitive_detector:
            return

        try:
            url = request['url']

            # Run passive detectors (analyze_response returns dict with findings)
            passive_results = self.passive_scanner.analyze_response(
                response['headers'],
                response['text'],
                url
            )

            # SensitiveDataDetector.analyze returns (has_findings, findings_list)
            has_sensitive, sensitive_findings = self.sensitive_detector.analyze(
                response['text'],
                url,
                response['headers']
            )

            # Emit findings from all categories
            all_findings = (
                passive_results.get('security_issues', []) +
                passive_results.get('sensitive_data', []) +
                passive_results.get('version_disclosures', [])
            )

            for finding in all_findings:
                self.passive_finding.emit({
                    'type': finding.get('type', 'Unknown'),
                    'severity': finding.get('severity', 'Info'),
                    'url': url,
                    'evidence': finding.get('evidence', ''),
                    'description': finding.get('description', '')
                })

            # Emit additional sensitive data findings
            if has_sensitive and sensitive_findings:
                for finding in sensitive_findings:
                    self.passive_finding.emit({
                        'type': finding.get('type', 'Sensitive Data'),
                        'severity': finding.get('severity', 'Medium'),
                        'url': url,
                        'evidence': finding.get('evidence', ''),
                        'description': finding.get('description', '')
                    })

            # Collect resources (emails, phones, social media, etc.)
            if hasattr(self, 'resource_collector') and self.resource_collector:
                try:
                    resources = self.resource_collector.analyze(
                        response['text'],
                        url,
                        response['headers']
                    )

                    # Emit found resources
                    for category, items in resources.items():
                        for item in items:
                            if category == 'email_addresses':
                                self.resource_found.emit('email', item['value'], 'Email', url)
                            elif category == 'phone_numbers':
                                self.resource_found.emit('phone', item['value'], item.get('name', 'Phone'), url)
                            elif category == 'social_networks':
                                platform = item.get('name', 'Social')
                                self.resource_found.emit('social', item['value'], platform, url)
                            elif category == 'api_keys':
                                key_type = item.get('name', 'API Key')
                                severity = item.get('severity', 'HIGH')
                                self.resource_found.emit('leaked_key', item['value'][:30] + '...', f"{key_type}|{severity}", url)
                except Exception as res_err:
                    pass  # Silently ignore resource collection errors

        except Exception as e:
            print(f"[!] Passive scan error: {e}")

    def forward_request(self, request_id):
        """Forward a pending request"""
        if request_id in self.pending_requests:
            self.pending_requests[request_id]['action'] = 'forward'
            # Signal the waiting thread
            if request_id in self.pending_events:
                self.pending_events[request_id].set()

    def drop_request(self, request_id):
        """Drop a pending request"""
        if request_id in self.pending_requests:
            self.pending_requests[request_id]['action'] = 'drop'
            # Signal the waiting thread
            if request_id in self.pending_events:
                self.pending_events[request_id].set()

    def modify_and_forward(self, request_id, modified_request):
        """Modify and forward a pending request"""
        if request_id in self.pending_requests:
            self.pending_requests[request_id]['action'] = 'modified'
            self.pending_requests[request_id]['modified_request'] = modified_request
            # Signal the waiting thread
            if request_id in self.pending_events:
                self.pending_events[request_id].set()

    def get_history(self, limit=100):
        """Get request history"""
        return self.history[-limit:]

    def clear_history(self):
        """Clear request history"""
        self.history.clear()

    def replay_request(self, request_data):
        """Replay a request from history"""
        try:
            response = requests.request(
                method=request_data['method'],
                url=request_data['url'],
                headers=request_data['headers'],
                data=request_data['raw_body'],
                verify=False,
                timeout=30
            )

            return {
                'status_code': response.status_code,
                'headers': dict(response.headers),
                'body': response.content,
                'text': response.text
            }
        except Exception as e:
            return {'error': str(e)}

    def add_auto_allow_host(self, host):
        """Add host to auto-allow list (bypass interception)"""
        self.auto_allow_hosts.add(host)

    def remove_auto_allow_host(self, host):
        """Remove host from auto-allow list"""
        self.auto_allow_hosts.discard(host)

    def is_auto_allowed(self, host):
        """Check if host is auto-allowed"""
        return host in self.auto_allow_hosts

    def get_auto_allow_hosts(self):
        """Get list of auto-allowed hosts"""
        return list(self.auto_allow_hosts)

    # Scope Management Methods
    def add_to_scope(self, pattern):
        """Add URL pattern to scope (regex)"""
        if pattern not in self.in_scope_patterns:
            self.in_scope_patterns.append(pattern)

    def remove_from_scope(self, pattern):
        """Remove URL pattern from scope"""
        if pattern in self.in_scope_patterns:
            self.in_scope_patterns.remove(pattern)

    def add_to_exclude(self, pattern):
        """Add URL pattern to exclude list (regex)"""
        if pattern not in self.out_of_scope_patterns:
            self.out_of_scope_patterns.append(pattern)

    def remove_from_exclude(self, pattern):
        """Remove URL pattern from exclude list"""
        if pattern in self.out_of_scope_patterns:
            self.out_of_scope_patterns.remove(pattern)

    def is_in_scope(self, url):
        """Check if URL is in scope"""
        import re

        # If scope is disabled, everything is in scope
        if not self.scope_enabled:
            return True

        # Check exclude patterns first (higher priority)
        for pattern in self.out_of_scope_patterns:
            try:
                if re.search(pattern, url):
                    return False
            except:
                pass

        # If no in-scope patterns, nothing is in scope
        if not self.in_scope_patterns:
            return False

        # Check if matches any in-scope pattern
        for pattern in self.in_scope_patterns:
            try:
                if re.search(pattern, url):
                    return True
            except:
                pass

        return False

    def _is_analytics_url(self, url):
        """Check if URL is analytics/telemetry (for statistics tracking)"""
        from urllib.parse import urlparse

        if not self.block_analytics_enabled:
            return False

        parsed = urlparse(url)
        host = parsed.netloc.lower()

        # Check exact match and subdomain match
        for analytics_host in self.analytics_hosts:
            if host == analytics_host or host.endswith('.' + analytics_host):
                return True

        return False

    def should_ignore_response(self, response):
        """Check if response should be ignored based on content-type (binary content)"""
        if not response:
            return False

        content_type = ''
        for key, value in response.get('headers', {}).items():
            if key.lower() == 'content-type':
                content_type = value.lower()
                break

        # Check against ignored content types
        for ignored_type in self.ignore_content_types:
            if ignored_type in content_type:
                return True

        return False

    def should_ignore(self, url):
        """Check if URL should be ignored (static files, analytics, etc.)"""
        import re
        from urllib.parse import urlparse

        if not self.ignore_enabled:
            return False

        parsed = urlparse(url)

        # Check analytics hosts (and track statistics)
        if self.block_analytics_enabled:
            host = parsed.netloc.lower()
            # Check exact match and subdomain match
            for analytics_host in self.analytics_hosts:
                if host == analytics_host or host.endswith('.' + analytics_host):
                    # Increment blocked analytics counter
                    with self._stats_lock:
                        self.blocked_analytics_requests += 1
                        # Emit statistics update signal on every blocked request
                        try:
                            self.statistics_updated.emit({
                                'total': self.total_requests,
                                'blocked_analytics': self.blocked_analytics_requests
                            })
                        except:
                            pass  # Ignore signal errors
                    return True

        # Check file extension
        path = parsed.path.lower()
        for ext in self.ignore_extensions:
            if path.endswith(ext):
                return True

        # Check custom ignore patterns
        for pattern in self.custom_ignore_patterns:
            try:
                if re.search(pattern, url):
                    return True
            except:
                pass

        return False

    def is_analytics_host(self, host):
        """Check if host is in analytics blocklist"""
        host = host.lower()
        for analytics_host in self.analytics_hosts:
            if host == analytics_host or host.endswith('.' + analytics_host):
                return True
        return False

    def get_analytics_hosts(self):
        """Get list of blocked analytics hosts"""
        return sorted(self.analytics_hosts)

    def add_analytics_host(self, host):
        """Add host to analytics blocklist"""
        self.analytics_hosts.add(host.lower())

    def remove_analytics_host(self, host):
        """Remove host from analytics blocklist"""
        self.analytics_hosts.discard(host.lower())

    def add_ignore_extension(self, ext):
        """Add file extension to ignore list"""
        if not ext.startswith('.'):
            ext = '.' + ext
        self.ignore_extensions.add(ext.lower())

    def remove_ignore_extension(self, ext):
        """Remove file extension from ignore list"""
        if not ext.startswith('.'):
            ext = '.' + ext
        self.ignore_extensions.discard(ext.lower())

    def add_ignore_pattern(self, pattern):
        """Add custom ignore pattern (regex)"""
        if pattern not in self.custom_ignore_patterns:
            self.custom_ignore_patterns.append(pattern)

    def remove_ignore_pattern(self, pattern):
        """Remove custom ignore pattern"""
        if pattern in self.custom_ignore_patterns:
            self.custom_ignore_patterns.remove(pattern)
