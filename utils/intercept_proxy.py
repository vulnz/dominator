"""
HTTP Intercepting Proxy for Dominator Scanner
Burp Suite-like functionality: intercept, modify, replay requests
"""

import socket
import threading
import time
import ssl
from http.server import BaseHTTPRequestHandler, HTTPServer
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
        self.max_history = 1000

        # Pending requests (waiting for user action)
        self.pending_requests = {}
        self.request_id_counter = 0

        # Auto-allow hosts (bypass interception for these hosts)
        self.auto_allow_hosts = set()

        # Certificate manager for SSL interception
        self.cert_manager = get_cert_manager() if ssl_intercept_enabled else None

        # Passive detectors
        from passive_detectors.passive_scanner import PassiveScanner
        from passive_detectors.sensitive_data_detector import SensitiveDataDetector
        self.passive_scanner = PassiveScanner()
        self.sensitive_detector = SensitiveDataDetector()

    def start(self):
        """Start the proxy server"""
        if self.running:
            return

        self.running = True
        self.thread = threading.Thread(target=self._run_server, daemon=True)
        self.thread.start()

        return f"Proxy started on 127.0.0.1:{self.port}"

    def stop(self):
        """Stop the proxy server"""
        self.running = False
        if self.server:
            self.server.shutdown()

    def _run_server(self):
        """Run the HTTP server"""
        proxy_instance = self

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
                """Handle HTTPS as encrypted tunnel (no inspection)"""
                # Log HTTPS connection attempt
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

                # Add to history
                proxy_instance.history.append(request_data)
                if len(proxy_instance.history) > proxy_instance.max_history:
                    proxy_instance.history.pop(0)

                # Connect to destination server
                dest_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                dest_socket.settimeout(30)
                dest_socket.connect((host, port))

                # Send 200 Connection Established to client
                self.send_response(200, 'Connection Established')
                self.end_headers()

                # Emit response signal (showing tunnel established)
                response_data = {
                    'request': request_data,
                    'response': {
                        'status_code': 200,
                        'headers': {'Connection': 'Established'},
                        'body': b'',
                        'text': '[HTTPS Tunnel - Content Encrypted]'
                    }
                }
                proxy_instance.response_received.emit(response_data)

                # Bidirectional tunnel
                client_socket = self.connection
                client_socket.setblocking(False)
                dest_socket.setblocking(False)

                def forward_data(source, destination, name):
                    try:
                        while True:
                            try:
                                data = source.recv(8192)
                                if not data:
                                    break
                                destination.sendall(data)
                            except socket.error as e:
                                if e.errno in (10035, 11):
                                    time.sleep(0.01)
                                    continue
                                break
                    except:
                        pass
                    finally:
                        try:
                            source.close()
                            destination.close()
                        except:
                            pass

                client_to_server = threading.Thread(
                    target=forward_data,
                    args=(client_socket, dest_socket, "client->server"),
                    daemon=True
                )
                server_to_client = threading.Thread(
                    target=forward_data,
                    args=(dest_socket, client_socket, "server->client"),
                    daemon=True
                )

                client_to_server.start()
                server_to_client.start()
                client_to_server.join()
                server_to_client.join()

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
                    for header, value in response['headers'].items():
                        # Skip headers that cause issues
                        if header.lower() not in ['transfer-encoding', 'content-encoding']:
                            self.send_header(header, value)
                    self.end_headers()

                    if response['body']:
                        self.wfile.write(response['body'])

                    # Signal GUI
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
            self.server = HTTPServer(('127.0.0.1', self.port), ProxyHandler)
            print(f"[+] Proxy server listening...")
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
