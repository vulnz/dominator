"""
HTTP Intercepting Proxy for Dominator Scanner
Burp Suite-like functionality: intercept, modify, replay requests
"""

import socket
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse
import requests
from PyQt5.QtCore import QObject, pyqtSignal
import gzip
import io


class InterceptingProxy(QObject):
    """HTTP proxy that intercepts and allows modification of requests"""

    # Signals for GUI
    request_intercepted = pyqtSignal(dict)  # New request intercepted
    response_received = pyqtSignal(dict)    # Response received
    passive_finding = pyqtSignal(dict)      # Passive scan finding

    def __init__(self, port=8080):
        super().__init__()
        self.port = port
        self.intercept_enabled = False
        self.passive_scan_enabled = True
        self.server = None
        self.thread = None
        self.running = False

        # Request history
        self.history = []
        self.max_history = 1000

        # Pending requests (waiting for user action)
        self.pending_requests = {}
        self.request_id_counter = 0

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
                """Handle HTTPS CONNECT tunnel for HTTPS traffic"""
                # For HTTPS, we establish a tunnel
                # Note: Full SSL interception requires certificate generation
                # For now, we just tunnel the connection (can see URL but not content)

                try:
                    # Parse host and port
                    host, port = self.path.split(':')
                    port = int(port)

                    # Log HTTPS connection attempt
                    request_data = {
                        'id': proxy_instance.request_id_counter,
                        'method': 'CONNECT',
                        'url': f"https://{self.path}",
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

                    # Connect to destination
                    dest_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    dest_socket.connect((host, port))

                    # Send 200 Connection Established
                    self.send_response(200, 'Connection Established')
                    self.end_headers()

                    # Tunnel data between client and server
                    # This is a simple pass-through - encrypted data flows through
                    import select

                    client_socket = self.connection
                    sockets = [client_socket, dest_socket]

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

                    # Simple bidirectional tunnel
                    while True:
                        readable, _, exceptional = select.select(sockets, [], sockets, 1)

                        if exceptional:
                            break

                        for sock in readable:
                            try:
                                data = sock.recv(8192)
                                if not data:
                                    return

                                if sock is client_socket:
                                    dest_socket.sendall(data)
                                else:
                                    client_socket.sendall(data)
                            except:
                                return

                except Exception as e:
                    self.send_error(502, f"Bad Gateway: {str(e)}")

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

                # Check if intercept is enabled
                if proxy_instance.intercept_enabled:
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
            self.server = HTTPServer(('127.0.0.1', self.port), ProxyHandler)
            self.server.serve_forever()
        except Exception as e:
            print(f"Proxy server error: {e}")

    def _passive_scan(self, request, response):
        """Run passive scans on request/response"""
        url = request['url']

        # Run passive detectors
        passive_results = self.passive_scanner.scan_response(
            url,
            response['text'],
            response['headers']
        )

        sensitive_results = self.sensitive_detector.detect(
            response['text'],
            url
        )

        # Emit findings
        for finding in passive_results:
            self.passive_finding.emit({
                'type': finding['type'],
                'severity': finding['severity'],
                'url': url,
                'evidence': finding['evidence'],
                'description': finding['description']
            })

        for finding in sensitive_results:
            self.passive_finding.emit({
                'type': 'Sensitive Data',
                'severity': 'Medium',
                'url': url,
                'evidence': finding['value'],
                'description': f"{finding['type']} detected"
            })

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
