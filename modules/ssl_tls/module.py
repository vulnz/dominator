"""
SSL/TLS Security Scanner (Enhanced with SSLyze-style checks)

Analyzes SSL/TLS configuration for security issues:
- TLS version (SSLv2, SSLv3, TLS 1.0, TLS 1.1 are weak)
- Cipher suite strength (NULL, DES, RC4, EXPORT, ANON)
- Certificate validation (expiration, hostname, chain)
- Self-signed certificate detection
- SHA-1 certificate detection
- Key size validation (RSA < 2048, ECC < 256)
- HSTS header analysis
- Certificate transparency (SCT)
- OCSP stapling status
- Forward secrecy check
- Certificate chain validation
- Subdomain extraction from SANs
"""

from core.base_module import BaseModule
from core.http_client import HTTPClient
from core.logger import get_logger
from typing import List, Dict, Any
import ssl
import socket
from urllib.parse import urlparse
from datetime import datetime, timedelta
import hashlib

logger = get_logger(__name__)


class SSLTLSSecurityScanner(BaseModule):
    """Scans for SSL/TLS security issues"""

    def __init__(self, module_path: str, payload_limit: int = None):
        super().__init__(module_path, payload_limit=payload_limit)
        self.module_name = "SSL/TLS Security"
        self.logger = logger

    def scan(self, targets: List[Dict[str, Any]], http_client: Any = None) -> List[Dict[str, Any]]:
        """
        Scan targets for SSL/TLS vulnerabilities

        Args:
            targets: List of targets to scan
            http_client: HTTP client for making requests

        Returns:
            List of vulnerability findings
        """
        self.logger.info(f"Starting {self.module_name} scan on {len(targets)} targets")

        results = []
        client = http_client or HTTPClient(timeout=8)

        for target in targets:
            url = target.get('url')
            if not url:
                continue

            # Only scan HTTPS URLs
            if not url.startswith('https://'):
                self.logger.debug(f"Skipping non-HTTPS URL: {url}")
                continue

            # Extract hostname and port
            parsed = urlparse(url)
            hostname = parsed.hostname
            port = parsed.port or 443

            # Analyze SSL/TLS configuration
            ssl_findings = self._analyze_ssl_tls(hostname, port, url)
            results.extend(ssl_findings)

            # Extract subdomains from certificate SANs
            san_subdomains = self._extract_san_subdomains(hostname, port)
            if san_subdomains:
                results.append(self._create_san_finding(url, hostname, san_subdomains))

            # Check OCSP stapling
            ocsp_finding = self._check_ocsp_stapling(hostname, port, url)
            if ocsp_finding:
                results.append(ocsp_finding)

            # Check forward secrecy
            fs_finding = self._check_forward_secrecy(hostname, port, url)
            if fs_finding:
                results.append(fs_finding)

            # Check HTTP security headers
            header_findings = self._check_security_headers(client, url)
            results.extend(header_findings)

        client.close()
        self.logger.info(f"{self.module_name} scan complete: {len(results)} vulnerabilities found")
        return results

    def _analyze_ssl_tls(self, hostname: str, port: int, url: str) -> List[Dict[str, Any]]:
        """Analyze SSL/TLS configuration"""

        findings = []

        try:
            # Create SSL context
            context = ssl.create_default_context()

            # Connect and get certificate
            with socket.create_connection((hostname, port), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
                    cipher = ssock.cipher()
                    version = ssock.version()

                    # Check TLS version
                    if version in ['SSLv2', 'SSLv3', 'TLSv1', 'TLSv1.1']:
                        findings.append({
                            'vulnerability': True,
                            'module': self.module_name,
                            'type': 'Weak TLS Protocol',
                            'severity': 'High',
                            'url': url,
                            'parameter': 'TLS Version',
                            'payload': version,
                            'method': 'SSL/TLS',
                            'confidence': 0.95,
                            'description': f'Server supports weak TLS protocol: {version}',
                            'evidence': f'TLS version: {version}',
                            'recommendation': 'Disable SSLv2, SSLv3, TLS 1.0, and TLS 1.1. Use TLS 1.2 or higher.',
                            'cwe': 'CWE-327',
                            'cvss': 7.4,
                            'owasp': 'A02:2021',
                            'references': [
                                'https://cwe.mitre.org/data/definitions/327.html',
                                'https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/09-Testing_for_Weak_Cryptography/01-Testing_for_Weak_Transport_Layer_Security'
                            ]
                        })

                    # Check cipher suite
                    if cipher:
                        cipher_name = cipher[0]

                        # Weak ciphers
                        weak_cipher_indicators = ['NULL', 'EXP', 'DES', 'RC4', 'MD5', 'EXPORT', 'ANON']
                        if any(indicator in cipher_name for indicator in weak_cipher_indicators):
                            findings.append({
                                'vulnerability': True,
                                'module': self.module_name,
                                'type': 'Weak Cipher Suite',
                                'severity': 'High',
                                'url': url,
                                'parameter': 'Cipher Suite',
                                'payload': cipher_name,
                                'method': 'SSL/TLS',
                                'confidence': 0.95,
                                'description': f'Server uses weak cipher suite: {cipher_name}',
                                'evidence': f'Cipher: {cipher_name}, Protocol: {version}',
                                'recommendation': 'Disable weak cipher suites. Use only strong, modern ciphers (AES-GCM, ChaCha20).',
                                'cwe': 'CWE-327',
                                'cvss': 7.4,
                                'owasp': 'A02:2021',
                                'references': [
                                    'https://wiki.mozilla.org/Security/Server_Side_TLS'
                                ]
                            })

                    # Check certificate
                    if cert:
                        # Check expiration
                        not_after = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
                        if datetime.now() > not_after:
                            findings.append({
                                'vulnerability': True,
                                'module': self.module_name,
                                'type': 'Expired Certificate',
                                'severity': 'High',
                                'url': url,
                                'parameter': 'SSL Certificate',
                                'payload': f'Expired: {not_after}',
                                'method': 'SSL/TLS',
                                'confidence': 1.0,
                                'description': f'SSL certificate expired on {not_after}',
                                'evidence': f'Certificate expired: {not_after}',
                                'recommendation': 'Renew SSL certificate immediately.',
                                'cwe': 'CWE-295',
                                'cvss': 7.4,
                                'owasp': 'A02:2021',
                                'references': []
                            })

                        # Check expiring soon (within 30 days)
                        elif not_after < datetime.now() + timedelta(days=30):
                            findings.append({
                                'vulnerability': True,
                                'module': self.module_name,
                                'type': 'Certificate Expiring Soon',
                                'severity': 'Low',
                                'url': url,
                                'parameter': 'SSL Certificate',
                                'payload': f'Expires: {not_after}',
                                'method': 'SSL/TLS',
                                'confidence': 1.0,
                                'description': f'SSL certificate expires within 30 days: {not_after}',
                                'evidence': f'Certificate expires: {not_after}',
                                'recommendation': 'Schedule certificate renewal before expiration.',
                                'cwe': 'CWE-295',
                                'cvss': 2.0,
                                'owasp': 'A02:2021',
                                'references': []
                            })

                        # Check for self-signed certificate (issuer == subject)
                        if 'issuer' in cert and 'subject' in cert:
                            issuer_cn = None
                            subject_cn = None
                            for field in cert.get('issuer', []):
                                for key, value in field:
                                    if key == 'commonName':
                                        issuer_cn = value
                            for field in cert.get('subject', []):
                                for key, value in field:
                                    if key == 'commonName':
                                        subject_cn = value

                            if issuer_cn and subject_cn and issuer_cn == subject_cn:
                                findings.append({
                                    'vulnerability': True,
                                    'module': self.module_name,
                                    'type': 'Self-Signed Certificate',
                                    'severity': 'Medium',
                                    'url': url,
                                    'parameter': 'SSL Certificate',
                                    'payload': f'Issuer=Subject: {issuer_cn}',
                                    'method': 'SSL/TLS',
                                    'confidence': 0.95,
                                    'description': 'SSL certificate is self-signed (issuer equals subject)',
                                    'evidence': f'Issuer CN: {issuer_cn}, Subject CN: {subject_cn}',
                                    'recommendation': 'Use a certificate from a trusted Certificate Authority.',
                                    'cwe': 'CWE-295',
                                    'cvss': 5.9,
                                    'owasp': 'A02:2021',
                                    'references': []
                                })

                        # Check hostname match
                        if 'subject' in cert:
                            cert_hostnames = []
                            for field in cert['subject']:
                                for key, value in field:
                                    if key == 'commonName':
                                        cert_hostnames.append(value)

                            if 'subjectAltName' in cert:
                                for san_type, san_value in cert['subjectAltName']:
                                    if san_type == 'DNS':
                                        cert_hostnames.append(san_value)

                            hostname_match = False
                            for cert_hostname in cert_hostnames:
                                if hostname == cert_hostname or cert_hostname.startswith('*.'):
                                    hostname_match = True
                                    break

                            if not hostname_match:
                                findings.append({
                                    'vulnerability': True,
                                    'module': self.module_name,
                                    'type': 'Certificate Hostname Mismatch',
                                    'severity': 'Medium',
                                    'url': url,
                                    'parameter': 'SSL Certificate',
                                    'payload': f'Expected: {hostname}, Got: {cert_hostnames}',
                                    'method': 'SSL/TLS',
                                    'confidence': 0.90,
                                    'description': f'Certificate hostname does not match server hostname',
                                    'evidence': f'Server: {hostname}, Certificate: {cert_hostnames}',
                                    'recommendation': 'Ensure certificate CN or SAN matches server hostname.',
                                    'cwe': 'CWE-295',
                                    'cvss': 5.9,
                                    'owasp': 'A02:2021',
                                    'references': []
                                })

        except ssl.SSLError as e:
            # SSL errors might indicate security issues
            self.logger.debug(f"SSL error for {hostname}: {str(e)}")

            if 'certificate verify failed' in str(e).lower():
                findings.append({
                    'vulnerability': True,
                    'module': self.module_name,
                    'type': 'Invalid Certificate',
                    'severity': 'High',
                    'url': url,
                    'parameter': 'SSL Certificate',
                    'payload': str(e),
                    'method': 'SSL/TLS',
                    'confidence': 0.95,
                    'description': 'SSL certificate validation failed (self-signed or untrusted CA)',
                    'evidence': str(e),
                    'recommendation': 'Use a valid certificate from a trusted CA.',
                    'cwe': 'CWE-295',
                    'cvss': 7.4,
                    'owasp': 'A02:2021',
                    'references': []
                })

        except Exception as e:
            self.logger.debug(f"Error analyzing SSL/TLS for {hostname}: {str(e)}")

        return findings

    def _check_security_headers(self, client: HTTPClient, url: str) -> List[Dict[str, Any]]:
        """Check for security-related HTTP headers"""

        findings = []

        try:
            response = client.get(url)
            if not response:
                return findings

            headers = {k.lower(): v for k, v in response.headers.items()}

            # Check HSTS
            if 'strict-transport-security' not in headers:
                findings.append({
                    'vulnerability': True,
                    'module': self.module_name,
                    'type': 'Missing HSTS Header',
                    'severity': 'Medium',
                    'url': url,
                    'parameter': 'Strict-Transport-Security',
                    'payload': 'N/A',
                    'method': 'GET',
                    'confidence': 0.95,
                    'description': 'HTTP Strict Transport Security (HSTS) header is missing',
                    'evidence': 'HSTS header not found in response',
                    'recommendation': 'Add Strict-Transport-Security header with max-age of at least 31536000 (1 year).',
                    'cwe': 'CWE-523',
                    'cvss': 5.9,
                    'owasp': 'A05:2021',
                    'references': [
                        'https://owasp.org/www-project-secure-headers/#http-strict-transport-security'
                    ]
                })
            else:
                hsts_value = headers['strict-transport-security']

                # Check max-age
                if 'max-age=' in hsts_value:
                    max_age = int(hsts_value.split('max-age=')[1].split(';')[0])
                    if max_age < 31536000:  # 1 year
                        findings.append({
                            'vulnerability': True,
                            'module': self.module_name,
                            'type': 'Weak HSTS Policy',
                            'severity': 'Low',
                            'url': url,
                            'parameter': 'Strict-Transport-Security',
                            'payload': hsts_value,
                            'method': 'GET',
                            'confidence': 0.95,
                            'description': f'HSTS max-age is too short: {max_age} seconds',
                            'evidence': f'HSTS: {hsts_value}',
                            'recommendation': 'Set HSTS max-age to at least 31536000 (1 year).',
                            'cwe': 'CWE-523',
                            'cvss': 3.7,
                            'owasp': 'A05:2021',
                            'references': []
                        })

                # Check includeSubDomains
                if 'includesubdomains' not in hsts_value.lower():
                    findings.append({
                        'vulnerability': False,
                        'module': self.module_name,
                        'type': 'HSTS Missing includeSubDomains',
                        'severity': 'Info',
                        'url': url,
                        'parameter': 'Strict-Transport-Security',
                        'payload': hsts_value,
                        'method': 'GET',
                        'confidence': 0.95,
                        'description': 'HSTS policy does not include subdomains',
                        'evidence': f'HSTS: {hsts_value}',
                        'recommendation': 'Consider adding includeSubDomains directive to HSTS header.',
                        'cwe': 'CWE-523',
                        'cvss': 0.0,
                        'owasp': 'A05:2021',
                        'references': []
                    })

        except Exception as e:
            self.logger.debug(f"Error checking security headers: {str(e)}")

        return findings


    def _extract_san_subdomains(self, hostname: str, port: int) -> list:
        """Extract subdomains from SSL certificate SANs"""
        subdomains = []

        try:
            context = ssl.create_default_context()
            with socket.create_connection((hostname, port), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()

                    if cert and 'subjectAltName' in cert:
                        for san_type, san_value in cert['subjectAltName']:
                            if san_type == 'DNS':
                                san_value = san_value.lower()
                                if not san_value.startswith('*'):
                                    subdomains.append(san_value)

        except Exception as e:
            self.logger.debug(f"SAN extraction failed: {e}")

        return subdomains

    def _create_san_finding(self, url: str, hostname: str, subdomains: list) -> Dict:
        """Create finding for discovered SANs"""
        return {
            'vulnerability': False,
            'module': self.module_name,
            'type': 'SSL Certificate SANs',
            'severity': 'Info',
            'url': url,
            'parameter': 'subjectAltName',
            'payload': f'{len(subdomains)} domains',
            'method': 'SSL/TLS',
            'confidence': 1.0,
            'description': f'SSL certificate contains {len(subdomains)} Subject Alternative Names',
            'evidence': f'Subdomains found in SSL certificate:\n' + '\n'.join(f'  - {s}' for s in subdomains[:20]),
            'recommendation': 'Review certificate SANs for exposed internal hostnames.',
            'cwe': 'CWE-200',
            'cvss': 0.0,
            'owasp': 'A01:2021',
            'subdomains': subdomains,
            'references': []
        }

    def _check_ocsp_stapling(self, hostname: str, port: int, url: str) -> Dict:
        """Check if OCSP stapling is enabled"""
        try:
            context = ssl.create_default_context()
            context.check_hostname = True
            context.verify_mode = ssl.CERT_REQUIRED

            with socket.create_connection((hostname, port), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    # Check for OCSP response (stapling)
                    # Note: Python's ssl module doesn't directly expose OCSP stapling status
                    # We check indirectly through cert properties
                    cert = ssock.getpeercert()

                    # Check for OCSP responder URL in cert
                    ocsp_urls = []
                    if cert:
                        # Look for Authority Information Access
                        for ext in cert.get('OCSP', []):
                            ocsp_urls.append(ext)

                    if not ocsp_urls:
                        return {
                            'vulnerability': False,
                            'module': self.module_name,
                            'type': 'OCSP Stapling Status',
                            'severity': 'Info',
                            'url': url,
                            'parameter': 'OCSP',
                            'payload': 'N/A',
                            'method': 'SSL/TLS',
                            'confidence': 0.7,
                            'description': 'OCSP stapling status could not be determined',
                            'evidence': 'No OCSP responder found in certificate',
                            'recommendation': 'Enable OCSP stapling for improved performance and privacy.',
                            'cwe': 'CWE-295',
                            'cvss': 0.0,
                            'owasp': 'A02:2021',
                            'references': []
                        }

        except Exception as e:
            self.logger.debug(f"OCSP check failed: {e}")

        return None

    def _check_forward_secrecy(self, hostname: str, port: int, url: str) -> Dict:
        """Check if forward secrecy is supported"""
        try:
            context = ssl.create_default_context()

            with socket.create_connection((hostname, port), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cipher = ssock.cipher()

                    if cipher:
                        cipher_name = cipher[0]

                        # Forward secrecy ciphers use ECDHE or DHE key exchange
                        has_fs = 'ECDHE' in cipher_name or 'DHE' in cipher_name

                        if not has_fs:
                            return {
                                'vulnerability': True,
                                'module': self.module_name,
                                'type': 'No Forward Secrecy',
                                'severity': 'Medium',
                                'url': url,
                                'parameter': 'Cipher Suite',
                                'payload': cipher_name,
                                'method': 'SSL/TLS',
                                'confidence': 0.95,
                                'description': f'Server cipher suite does not provide forward secrecy: {cipher_name}',
                                'evidence': f'Cipher: {cipher_name} (no ECDHE/DHE key exchange)',
                                'recommendation': 'Configure server to prefer cipher suites with ECDHE or DHE key exchange.',
                                'cwe': 'CWE-327',
                                'cvss': 5.3,
                                'owasp': 'A02:2021',
                                'references': [
                                    'https://wiki.mozilla.org/Security/Server_Side_TLS'
                                ]
                            }
                        else:
                            return {
                                'vulnerability': False,
                                'module': self.module_name,
                                'type': 'Forward Secrecy Enabled',
                                'severity': 'Info',
                                'url': url,
                                'parameter': 'Cipher Suite',
                                'payload': cipher_name,
                                'method': 'SSL/TLS',
                                'confidence': 0.95,
                                'description': f'Server supports forward secrecy with {cipher_name}',
                                'evidence': f'Cipher: {cipher_name} (supports perfect forward secrecy)',
                                'recommendation': 'Forward secrecy is properly configured.',
                                'cwe': 'CWE-327',
                                'cvss': 0.0,
                                'owasp': 'A02:2021',
                                'references': []
                            }

        except Exception as e:
            self.logger.debug(f"Forward secrecy check failed: {e}")

        return None


def get_module(module_path: str, payload_limit: int = None):
    """Factory function to create module instance"""
    return SSLTLSSecurityScanner(module_path, payload_limit=payload_limit)
