"""
SSL Certificate Manager for HTTPS Interception
Generates CA certificate and per-domain certificates for man-in-the-middle inspection
"""

import os
import socket
import ssl
from pathlib import Path
from datetime import datetime, timedelta
from cryptography import x509
from cryptography.x509.oid import NameOID, ExtensionOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend


class CertificateManager:
    """Manages SSL certificates for HTTPS interception"""

    def __init__(self, cert_dir=None):
        """Initialize certificate manager

        Args:
            cert_dir: Directory to store certificates (default: ./certs)
        """
        if cert_dir is None:
            cert_dir = Path(__file__).parent.parent / 'certs'

        self.cert_dir = Path(cert_dir)
        self.cert_dir.mkdir(exist_ok=True, parents=True)

        self.ca_cert_path = self.cert_dir / 'dominator_ca.crt'
        self.ca_key_path = self.cert_dir / 'dominator_ca.key'

        # Cache for generated certificates
        self.cert_cache = {}

        # Ensure CA certificate exists
        if not self.ca_exists():
            self.generate_ca_certificate()

    def ca_exists(self):
        """Check if CA certificate exists"""
        return self.ca_cert_path.exists() and self.ca_key_path.exists()

    def generate_ca_certificate(self):
        """Generate root CA certificate for signing domain certificates"""
        print("[*] Generating Dominator CA certificate...")

        # Generate private key
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )

        # Create certificate subject
        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Security"),
            x509.NameAttribute(NameOID.LOCALITY_NAME, "Testing"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Dominator Security Scanner"),
            x509.NameAttribute(NameOID.COMMON_NAME, "Dominator CA"),
        ])

        # Build certificate
        cert = x509.CertificateBuilder().subject_name(
            subject
        ).issuer_name(
            issuer
        ).public_key(
            private_key.public_key()
        ).serial_number(
            x509.random_serial_number()
        ).not_valid_before(
            datetime.utcnow()
        ).not_valid_after(
            datetime.utcnow() + timedelta(days=3650)  # 10 years
        ).add_extension(
            x509.BasicConstraints(ca=True, path_length=0),
            critical=True,
        ).add_extension(
            x509.KeyUsage(
                digital_signature=True,
                key_cert_sign=True,
                crl_sign=True,
                key_encipherment=False,
                content_commitment=False,
                data_encipherment=False,
                key_agreement=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        ).add_extension(
            x509.SubjectKeyIdentifier.from_public_key(private_key.public_key()),
            critical=False,
        ).sign(private_key, hashes.SHA256(), default_backend())

        # Save certificate
        with open(self.ca_cert_path, 'wb') as f:
            f.write(cert.public_bytes(serialization.Encoding.PEM))

        # Save private key
        with open(self.ca_key_path, 'wb') as f:
            f.write(private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption()
            ))

        print(f"[+] CA certificate generated: {self.ca_cert_path}")
        print(f"[+] CA private key generated: {self.ca_key_path}")

        return cert, private_key

    def load_ca_certificate(self):
        """Load CA certificate and private key"""
        with open(self.ca_cert_path, 'rb') as f:
            ca_cert = x509.load_pem_x509_certificate(f.read(), default_backend())

        with open(self.ca_key_path, 'rb') as f:
            ca_key = serialization.load_pem_private_key(
                f.read(),
                password=None,
                backend=default_backend()
            )

        return ca_cert, ca_key

    def generate_domain_certificate(self, domain):
        """Generate certificate for specific domain signed by our CA

        Args:
            domain: Domain name (e.g., 'google.com')

        Returns:
            tuple: (cert_path, key_path)
        """
        # Check cache
        if domain in self.cert_cache:
            return self.cert_cache[domain]

        # Load CA certificate and key
        ca_cert, ca_key = self.load_ca_certificate()

        # Generate private key for domain
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )

        # Create certificate subject
        subject = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Security"),
            x509.NameAttribute(NameOID.LOCALITY_NAME, "Testing"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Dominator Proxy"),
            x509.NameAttribute(NameOID.COMMON_NAME, domain),
        ])

        # Build certificate
        cert = x509.CertificateBuilder().subject_name(
            subject
        ).issuer_name(
            ca_cert.subject
        ).public_key(
            private_key.public_key()
        ).serial_number(
            x509.random_serial_number()
        ).not_valid_before(
            datetime.utcnow()
        ).not_valid_after(
            datetime.utcnow() + timedelta(days=365)  # 1 year
        ).add_extension(
            x509.SubjectAlternativeName([
                x509.DNSName(domain),
                x509.DNSName(f"*.{domain}"),  # Wildcard for subdomains
            ]),
            critical=False,
        ).add_extension(
            x509.BasicConstraints(ca=False, path_length=None),
            critical=True,
        ).add_extension(
            x509.KeyUsage(
                digital_signature=True,
                key_encipherment=True,
                key_cert_sign=False,
                crl_sign=False,
                content_commitment=False,
                data_encipherment=False,
                key_agreement=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        ).add_extension(
            x509.ExtendedKeyUsage([
                x509.oid.ExtendedKeyUsageOID.SERVER_AUTH,
            ]),
            critical=True,
        ).sign(ca_key, hashes.SHA256(), default_backend())

        # Save certificate and key
        cert_path = self.cert_dir / f"{domain}.crt"
        key_path = self.cert_dir / f"{domain}.key"

        with open(cert_path, 'wb') as f:
            f.write(cert.public_bytes(serialization.Encoding.PEM))

        with open(key_path, 'wb') as f:
            f.write(private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption()
            ))

        # Cache paths
        self.cert_cache[domain] = (str(cert_path), str(key_path))

        return str(cert_path), str(key_path)

    def get_ca_cert_path(self):
        """Get path to CA certificate for browser installation"""
        return str(self.ca_cert_path)

    def get_ca_cert_for_chromium(self):
        """Get CA certificate path formatted for Chromium installation

        Returns:
            str: Path to CA certificate that can be installed in Chromium
        """
        # Convert to DER format for Windows certificate installation
        der_path = self.cert_dir / 'dominator_ca.der'

        with open(self.ca_cert_path, 'rb') as f:
            ca_cert = x509.load_pem_x509_certificate(f.read(), default_backend())

        with open(der_path, 'wb') as f:
            f.write(ca_cert.public_bytes(serialization.Encoding.DER))

        return str(der_path)

    def install_ca_in_chromium(self, chromium_user_data_dir):
        """Install CA certificate in Chromium's certificate store

        Args:
            chromium_user_data_dir: Path to Chromium user data directory

        Returns:
            bool: True if successful, False otherwise
        """
        import platform

        if platform.system() == 'Windows':
            return self._install_ca_windows()
        elif platform.system() == 'Linux':
            return self._install_ca_linux()
        elif platform.system() == 'Darwin':
            return self._install_ca_macos()

        return False

    def _install_ca_windows(self):
        """Install CA certificate in Windows certificate store"""
        import subprocess

        try:
            # Get DER format certificate
            der_path = self.get_ca_cert_for_chromium()

            # Use certutil to install certificate
            subprocess.run([
                'certutil',
                '-addstore',
                '-user',
                'ROOT',
                der_path
            ], check=True, capture_output=True)

            print(f"[+] CA certificate installed in Windows certificate store")
            return True

        except Exception as e:
            print(f"[!] Failed to install CA certificate: {e}")
            return False

    def _install_ca_linux(self):
        """Install CA certificate in Linux certificate store"""
        import subprocess
        import shutil

        try:
            # Copy to system certificate directory
            cert_dest = '/usr/local/share/ca-certificates/dominator_ca.crt'
            shutil.copy(self.ca_cert_path, cert_dest)

            # Update certificate store
            subprocess.run(['update-ca-certificates'], check=True)

            print(f"[+] CA certificate installed in Linux certificate store")
            return True

        except Exception as e:
            print(f"[!] Failed to install CA certificate: {e}")
            print("[!] You may need to run with sudo/root privileges")
            return False

    def _install_ca_macos(self):
        """Install CA certificate in macOS Keychain"""
        import subprocess

        try:
            # Add certificate to System keychain
            subprocess.run([
                'security',
                'add-trusted-cert',
                '-d',
                '-r', 'trustRoot',
                '-k', '/Library/Keychains/System.keychain',
                str(self.ca_cert_path)
            ], check=True)

            print(f"[+] CA certificate installed in macOS Keychain")
            return True

        except Exception as e:
            print(f"[!] Failed to install CA certificate: {e}")
            print("[!] You may need to run with sudo privileges")
            return False

    def create_ssl_context(self, domain):
        """Create SSL context for wrapping sockets

        Args:
            domain: Domain name

        Returns:
            ssl.SSLContext: Configured SSL context
        """
        cert_path, key_path = self.generate_domain_certificate(domain)

        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(cert_path, key_path)

        # Disable hostname checking (we're a proxy)
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE

        return context

    def wrap_client_socket(self, client_socket, domain):
        """Wrap client socket with SSL for HTTPS interception

        Args:
            client_socket: Client socket to wrap
            domain: Domain name for certificate generation

        Returns:
            ssl.SSLSocket: Wrapped socket
        """
        context = self.create_ssl_context(domain)

        return context.wrap_socket(
            client_socket,
            server_side=True,
            do_handshake_on_connect=True
        )


# Singleton instance
_cert_manager = None

def get_cert_manager():
    """Get global certificate manager instance"""
    global _cert_manager
    if _cert_manager is None:
        _cert_manager = CertificateManager()
    return _cert_manager
