"""
SSL/TLS implementation detection logic
"""

import ssl
import socket
from urllib.parse import urlparse
from typing import Tuple, List, Dict, Any

class SSLTLSDetector:
    """SSL/TLS implementation detection logic"""
    
    @staticmethod
    def detect_ssl_tls_implementation(url: str) -> Tuple[bool, str, str, Dict[str, Any]]:
        """
        Detect SSL/TLS implementation
        Returns: (has_ssl, evidence, severity, details)
        """
        parsed_url = urlparse(url)
        hostname = parsed_url.hostname
        
        if not hostname:
            return False, "Invalid hostname", "None", {}
        
        # Check if URL uses HTTPS
        if parsed_url.scheme.lower() == 'https':
            return SSLTLSDetector._check_ssl_configuration(hostname, parsed_url.port or 443)
        
        # Check if HTTP site has HTTPS available
        https_available = SSLTLSDetector._check_https_availability(hostname)
        
        if not https_available:
            return False, "SSL/TLS not implemented - HTTPS not available", "High", {
                'issue': 'no_ssl',
                'description': 'Website does not support HTTPS encryption'
            }
        else:
            return False, "SSL/TLS available but not enforced - HTTP used instead of HTTPS", "Medium", {
                'issue': 'ssl_not_enforced',
                'description': 'HTTPS is available but HTTP is being used'
            }
    
    @staticmethod
    def _check_https_availability(hostname: str, port: int = 443) -> bool:
        """Check if HTTPS is available on the hostname"""
        try:
            context = ssl.create_default_context()
            with socket.create_connection((hostname, port), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    return True
        except:
            return False
    
    @staticmethod
    def _check_ssl_configuration(hostname: str, port: int = 443) -> Tuple[bool, str, str, Dict[str, Any]]:
        """Check SSL/TLS configuration details"""
        try:
            context = ssl.create_default_context()
            
            with socket.create_connection((hostname, port), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
                    cipher = ssock.cipher()
                    version = ssock.version()
                    
                    issues = []
                    severity = "Low"
                    
                    # Check TLS version
                    if version in ['SSLv2', 'SSLv3', 'TLSv1', 'TLSv1.1']:
                        issues.append(f"Weak TLS version: {version}")
                        severity = "High"
                    
                    # Check cipher strength
                    if cipher:
                        cipher_name = cipher[0]
                        if any(weak in cipher_name.upper() for weak in ['RC4', 'DES', 'MD5', 'NULL']):
                            issues.append(f"Weak cipher: {cipher_name}")
                            severity = "High"
                    
                    # Check certificate
                    if cert:
                        # Check if certificate is expired (basic check)
                        import datetime
                        not_after = cert.get('notAfter')
                        if not_after:
                            try:
                                expiry_date = datetime.datetime.strptime(not_after, '%b %d %H:%M:%S %Y %Z')
                                if expiry_date < datetime.datetime.now():
                                    issues.append("Certificate expired")
                                    severity = "High"
                            except:
                                pass
                    
                    if issues:
                        evidence = f"SSL/TLS implemented with issues: {', '.join(issues)}"
                    else:
                        evidence = f"SSL/TLS properly implemented (TLS {version})"
                    
                    details = {
                        'tls_version': version,
                        'cipher': cipher[0] if cipher else 'Unknown',
                        'issues': issues,
                        'certificate_info': cert.get('subject', []) if cert else []
                    }
                    
                    return True, evidence, severity, details
                    
        except ssl.SSLError as e:
            return False, f"SSL/TLS error: {str(e)}", "High", {'issue': 'ssl_error', 'error': str(e)}
        except Exception as e:
            return False, f"Connection error: {str(e)}", "Medium", {'issue': 'connection_error', 'error': str(e)}
    
    @staticmethod
    def get_remediation_advice(issue_type: str) -> str:
        """Get remediation advice for SSL/TLS issues"""
        advice = {
            'no_ssl': (
                "Implement SSL/TLS encryption by obtaining and installing an SSL certificate. "
                "Configure your web server to support HTTPS and redirect HTTP traffic to HTTPS."
            ),
            'ssl_not_enforced': (
                "Enforce HTTPS by redirecting all HTTP traffic to HTTPS. "
                "Implement HTTP Strict Transport Security (HSTS) headers."
            ),
            'weak_tls': (
                "Disable weak TLS versions (SSLv2, SSLv3, TLSv1.0, TLSv1.1) and "
                "configure your server to use only TLS 1.2 or higher."
            ),
            'weak_cipher': (
                "Disable weak cipher suites and configure strong encryption algorithms. "
                "Use cipher suites that support Perfect Forward Secrecy (PFS)."
            ),
            'expired_cert': (
                "Renew the SSL certificate immediately. "
                "Set up automatic certificate renewal to prevent future expirations."
            )
        }
        
        return advice.get(issue_type, "Review and improve SSL/TLS configuration according to security best practices.")
