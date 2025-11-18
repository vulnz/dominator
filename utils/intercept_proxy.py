"""
HTTP Intercepting Proxy for Dominator Scanner
Burp Suite-like functionality: intercept, modify, replay requests
"""

import socket
import threading
import time
import ssl
from http.server import BaseHTTPRequestHandler, HTTPServer
from socketserver import ThreadingMixIn
from urllib.parse import urlparse
import requests
from PyQt5.QtCore import QObject, pyqtSignal
import gzip
import io
from utils.cert_manager import get_cert_manager


class InterceptingProxy(QObject):
    """HTTP proxy that intercepts and allows modification of requests"""

    # Signals for GUI
    request_intercepted = pyqtSignal(dict)  # New request intercepted
    response_received = pyqtSignal(dict)    # Response received
    passive_finding = pyqtSignal(dict)      # Passive scan finding

    def __init__(self, port=8080, ssl_intercept_enabled=True):
        super().__init__()
        self.port = port
        self.intercept_enabled = False
        self.passive_scan_enabled = True
        self.ssl_intercept_enabled = ssl_intercept_enabled
        self.server = None
        self.thread = None
        self.running = False

        # Request history
        self.history = []
        self.max_history = 5000  # Increased limit for better history

        # Pending requests (waiting for user action)
        self.pending_requests = {}
        self.request_id_counter = 0

        # Auto-allow hosts (bypass interception for these hosts)
        self.auto_allow_hosts = set()

        # Scope management (Burp Suite-like)
        self.scope_enabled = False
        self.in_scope_patterns = []  # Regex patterns for in-scope URLs
        self.out_of_scope_patterns = []  # Regex patterns to explicitly exclude

        # Ignore patterns (avoid logging static files, etc.)
        self.ignore_enabled = True
        self.ignore_extensions = {
            '.css', '.js', '.jpg', '.jpeg', '.png', '.gif', '.svg', '.ico',
            '.woff', '.woff2', '.ttf', '.eot', '.map', '.webp', '.bmp'
        }
        self.custom_ignore_patterns = []  # Additional regex patterns to ignore

        # Certificate manager for SSL interception
        self.cert_manager = get_cert_manager() if ssl_intercept_enabled else None

        # Passive detectors (load lazily to avoid startup issues)
        self.passive_scanner = None
        self.sensitive_detector = None

        # Try to load passive detectors, but don't fail if they're not available
        try:
            from passive_detectors.passive_scanner import PassiveScanner
            from passive_detectors.sensitive_data_detector import SensitiveDataDetector
            self.passive_scanner = PassiveScanner()
            self.sensitive_detector = SensitiveDataDetector()
            print("[+] Passive scanners loaded successfully")
        except Exception as e:
            print(f"[!] Warning: Could not load passive scanners: {e}")
            print("[!] Proxy will work but passive scanning will be disabled")

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

        try:
            if platform.system() == 'Windows':
                # Find PID using netstat
                result = subprocess.run(
                    ['netstat', '-ano'],
                    capture_output=True,
                    text=True
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
                            check=True
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

    def _run_server(self):
        """Run the HTTP server"""
        proxy_instance = self

        # Create a threading HTTP server for concurrent request handling
        class ThreadingHTTPServer(ThreadingMixIn, HTTPServer):
            """Multi-threaded HTTP server to handle multiple requests simultaneously"""
            daemon_threads = True  # Threads will not prevent program exit
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
                        proxy_instance.history.append(request_data)
                        if len(proxy_instance.history) > proxy_instance.max_history:
                            proxy_instance.history.pop(0)

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
                """Proxy individual HTTPS requests after SSL handshake

                Handles multiple requests over single SSL connection (HTTP keep-alive)
                """
                try:
                    # Set socket timeout to prevent hanging
                    ssl_client_socket.settimeout(10)

                    # Handle multiple requests on same connection (HTTP keep-alive)
                    while True:
                        try:
                            # Read HTTP request from SSL socket (buffered read for performance)
                            request_data_raw = b''
                            while b'\r\n\r\n' not in request_data_raw:
                                chunk = ssl_client_socket.recv(4096)
                                if not chunk:
                                    return  # Connection closed
                                request_data_raw += chunk
                                if len(request_data_raw) > 1024 * 1024:  # 1MB limit for headers
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

                            # Add to history
                            proxy_instance.history.append(request_data)
                            if len(proxy_instance.history) > proxy_instance.max_history:
                                proxy_instance.history.pop(0)

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

                                # Important headers that must be preserved
                                important_headers = ['location', 'set-cookie', 'content-type']

                                for header, value in response['headers'].items():
                                    header_lower = header.lower()

                                    # Skip problematic headers
                                    if header_lower in ['transfer-encoding', 'content-encoding']:
                                        continue

                                    # Update Content-Length with actual body size
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

                            # Emit signal
                            proxy_instance.response_received.emit({
                                'request': request_data,
                                'response': response
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
                """Forward HTTPS request to destination server"""
                try:
                    # Make HTTPS request to real server
                    response = requests.request(
                        method=request_data['method'],
                        url=request_data['url'],
                        headers=request_data['headers'],
                        data=request_data['raw_body'],
                        allow_redirects=False,
                        verify=False,
                        timeout=30
                    )

                    # Decompress if needed
                    body = response.content
                    if response.headers.get('Content-Encoding') == 'gzip':
                        try:
                            body = gzip.decompress(body)
                        except:
                            pass

                    return {
                        'status_code': response.status_code,
                        'headers': dict(response.headers),
                        'body': body,
                        'text': response.text,
                        'timestamp': time.time()
                    }

                except Exception as e:
                    return {
                        'status_code': 502,
                        'headers': {},
                        'body': f"Proxy error: {str(e)}".encode(),
                        'text': f"Proxy error: {str(e)}",
                        'timestamp': time.time()
                    }

            def handle_request(self, method):
                """Handle HTTP request"""
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

                # Add to history
                proxy_instance.history.append(request_data)
                if len(proxy_instance.history) > proxy_instance.max_history:
                    proxy_instance.history.pop(0)

                # Check if intercept is enabled and host is not auto-allowed
                parsed_url = urlparse(self.path)
                host = parsed_url.netloc or self.headers.get('Host', '')

                should_intercept = (
                    proxy_instance.intercept_enabled and
                    host not in proxy_instance.auto_allow_hosts
                )

                if should_intercept:
                    # Signal GUI to show intercept dialog
                    proxy_instance.request_intercepted.emit(request_data)

                    # Wait for user decision (with timeout)
                    proxy_instance.pending_requests[request_data['id']] = {
                        'request': request_data,
                        'action': None,  # 'forward', 'drop', 'modified'
                        'modified_request': None
                    }

                    # Wait for user action (max 60 seconds)
                    timeout = 60
                    waited = 0
                    while waited < timeout:
                        pending = proxy_instance.pending_requests.get(request_data['id'])
                        if pending and pending['action']:
                            break
                        time.sleep(0.1)
                        waited += 0.1

                    # Get user decision
                    pending = proxy_instance.pending_requests.get(request_data['id'], {})
                    action = pending.get('action', 'forward')

                    if action == 'drop':
                        self.send_error(403, "Request dropped by user")
                        return
                    elif action == 'modified':
                        request_data = pending.get('modified_request', request_data)

                    # Clean up
                    if request_data['id'] in proxy_instance.pending_requests:
                        del proxy_instance.pending_requests[request_data['id']]

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

                    for header, value in response['headers'].items():
                        header_lower = header.lower()

                        # Skip problematic headers
                        if header_lower in ['transfer-encoding', 'content-encoding']:
                            continue

                        # Track Connection header
                        if header_lower == 'connection':
                            # Force close to avoid hanging
                            self.send_header('Connection', 'close')
                            sent_connection = True
                        elif header_lower == 'content-length':
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
                        # Add to history
                        proxy_instance.history.append(request_data)
                        if len(proxy_instance.history) > proxy_instance.max_history:
                            proxy_instance.history.pop(0)

                        # Emit signal for GUI
                        proxy_instance.response_received.emit({
                            'request': request_data,
                            'response': response
                        })

                except Exception as e:
                    self.send_error(502, f"Proxy error: {str(e)}")

            def _forward_request(self, request_data):
                """Forward request to target server"""
                url = request_data['url']
                method = request_data['method']
                headers = request_data['headers'].copy()
                body = request_data['raw_body']

                # Remove proxy-specific headers
                headers.pop('Proxy-Connection', None)
                headers.pop('Connection', None)

                # Make request
                response = requests.request(
                    method=method,
                    url=url,
                    headers=headers,
                    data=body,
                    allow_redirects=False,
                    verify=False,
                    timeout=30
                )

                # Decompress if needed
                body = response.content
                if response.headers.get('Content-Encoding') == 'gzip':
                    try:
                        body = gzip.decompress(body)
                    except:
                        pass

                return {
                    'status_code': response.status_code,
                    'headers': dict(response.headers),
                    'body': body,
                    'text': response.text,
                    'timestamp': time.time()
                }

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
        except Exception as e:
            print(f"[!] Passive scan error: {e}")

    def forward_request(self, request_id):
        """Forward a pending request"""
        if request_id in self.pending_requests:
            self.pending_requests[request_id]['action'] = 'forward'

    def drop_request(self, request_id):
        """Drop a pending request"""
        if request_id in self.pending_requests:
            self.pending_requests[request_id]['action'] = 'drop'

    def modify_and_forward(self, request_id, modified_request):
        """Modify and forward a pending request"""
        if request_id in self.pending_requests:
            self.pending_requests[request_id]['action'] = 'modified'
            self.pending_requests[request_id]['modified_request'] = modified_request

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

    def should_ignore(self, url):
        """Check if URL should be ignored (static files, etc.)"""
        import re
        from urllib.parse import urlparse

        if not self.ignore_enabled:
            return False

        # Check file extension
        parsed = urlparse(url)
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
