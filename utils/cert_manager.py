"""
SSL Certificate Manager for HTTPS Interception
Generates CA certificate and in-memory per-domain certificates for man-in-the-middle inspection

OPTIMIZED: Like Burp Suite, certificates are generated in memory with a shared key.
Only the CA certificate is stored on disk.
"""

import os
import sys
import ssl
import threading
import tempfile
from pathlib import Path
from datetime import datetime, timedelta
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend


class CertificateManager:
    """Manages SSL certificates for HTTPS interception - Burp-style in-memory approach"""

    def __init__(self, cert_dir=None):
        """Initialize certificate manager

        Args:
            cert_dir: Directory to store CA certificate (default: ./certs)
        """
        if cert_dir is None:
            cert_dir = Path(__file__).parent.parent / 'certs'

        self.cert_dir = Path(cert_dir)
        self.cert_dir.mkdir(exist_ok=True, parents=True)

        self.ca_cert_path = self.cert_dir / 'dominator_ca.crt'
        self.ca_key_path = self.cert_dir / 'dominator_ca.key'

        # In-memory cache: domain -> (cert_pem_bytes, key_pem_bytes)
        self.cert_cache = {}

        # Single shared private key for all domain certificates (like Burp)
        # Generated once at startup, reused for all certs
        self._domain_key = None
        self._domain_key_pem = None

        # Thread lock for certificate generation
        self._cert_lock = threading.Lock()

        # Per-domain locks to allow parallel generation
        self._domain_locks = {}
        self._domain_locks_lock = threading.Lock()

        # Ensure CA certificate exists
        if not self.ca_exists():
            self.generate_ca_certificate()

        # Generate shared domain key
        self._init_domain_key()

    def _init_domain_key(self):
        """Initialize single shared private key for all domain certificates"""
        self._domain_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        self._domain_key_pem = self._domain_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        )

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

    def _get_domain_lock(self, domain):
        """Get or create a lock for a specific domain"""
        with self._domain_locks_lock:
            if domain not in self._domain_locks:
                self._domain_locks[domain] = threading.Lock()
            return self._domain_locks[domain]

    def _get_base_domain(self, domain):
        """Extract base domain from full domain (e.g., api.google.com -> google.com)

        This allows reusing wildcard certificates for all subdomains.
        """
        parts = domain.lower().split('.')

        # Handle special cases
        if len(parts) <= 2:
            return domain  # Already base domain (e.g., google.com)

        # Handle .co.uk, .com.au style TLDs
        common_second_level = {'co', 'com', 'net', 'org', 'gov', 'edu', 'ac'}
        if len(parts) >= 3 and parts[-2] in common_second_level:
            # e.g., api.example.co.uk -> example.co.uk
            return '.'.join(parts[-3:])

        # Standard case: api.google.com -> google.com
        return '.'.join(parts[-2:])

    def generate_domain_certificate(self, domain):
        """Generate certificate for specific domain signed by our CA

        OPTIMIZED: Certificates are generated in-memory using shared key.
        No files are written to disk for domain certificates.

        Args:
            domain: Domain name (e.g., 'api.google.com')

        Returns:
            tuple: (cert_pem_bytes, key_pem_bytes)
        """
        # Extract base domain for certificate reuse
        base_domain = self._get_base_domain(domain)

        # Quick check cache first (without lock)
        if base_domain in self.cert_cache:
            return self.cert_cache[base_domain]

        # Get per-domain lock
        domain_lock = self._get_domain_lock(base_domain)

        with domain_lock:
            # Double-check cache after acquiring lock
            if base_domain in self.cert_cache:
                return self.cert_cache[base_domain]

            # Load CA certificate and key
            ca_cert, ca_key = self.load_ca_certificate()

            # Create certificate subject with base domain
            subject = x509.Name([
                x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
                x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Security"),
                x509.NameAttribute(NameOID.LOCALITY_NAME, "Testing"),
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Dominator Proxy"),
                x509.NameAttribute(NameOID.COMMON_NAME, base_domain),
            ])

            # Build certificate with wildcard SAN using SHARED key
            cert = x509.CertificateBuilder().subject_name(
                subject
            ).issuer_name(
                ca_cert.subject
            ).public_key(
                self._domain_key.public_key()  # Use shared key
            ).serial_number(
                x509.random_serial_number()
            ).not_valid_before(
                datetime.utcnow()
            ).not_valid_after(
                datetime.utcnow() + timedelta(days=365)  # 1 year
            ).add_extension(
                x509.SubjectAlternativeName([
                    x509.DNSName(base_domain),
                    x509.DNSName(f"*.{base_domain}"),  # Wildcard covers all subdomains
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

            # Get PEM bytes (in-memory only, no disk write)
            cert_pem = cert.public_bytes(serialization.Encoding.PEM)

            # Cache in memory
            self.cert_cache[base_domain] = (cert_pem, self._domain_key_pem)

            return cert_pem, self._domain_key_pem

    def get_ca_cert_path(self):
        """Get path to CA certificate for browser installation"""
        return str(self.ca_cert_path)

    def is_ca_installed(self):
        """Check if CA certificate is installed in system/browser certificate store

        Returns:
            bool: True if installed, False otherwise
        """
        import platform
        import subprocess

        if platform.system() == 'Windows':
            try:
                # Hide console window on Windows
                creation_flags = subprocess.CREATE_NO_WINDOW if sys.platform == 'win32' else 0
                result = subprocess.run([
                    'certutil', '-store', '-user', 'ROOT'
                ], capture_output=True, text=True, creationflags=creation_flags)
                return 'Dominator CA' in result.stdout
            except:
                return False

        elif platform.system() == 'Linux':
            # Check NSS database for Chrome/Chromium
            home = os.path.expanduser("~")
            nss_db = os.path.join(home, ".pki/nssdb")
            if os.path.exists(nss_db):
                try:
                    result = subprocess.run([
                        'certutil', '-d', f'sql:{nss_db}', '-L'
                    ], capture_output=True, text=True)
                    return 'Dominator CA' in result.stdout
                except:
                    pass
            return False

        elif platform.system() == 'Darwin':
            try:
                result = subprocess.run([
                    'security', 'find-certificate', '-c', 'Dominator CA'
                ], capture_output=True, text=True)
                return result.returncode == 0
            except:
                return False

        return False

    def ensure_ca_installed(self):
        """Ensure CA certificate is installed, install if not

        Returns:
            bool: True if installed (or already was), False if installation failed
        """
        if self.is_ca_installed():
            print("[+] CA certificate already installed")
            return True

        import platform
        system = platform.system()

        if system == 'Windows':
            return self._install_ca_windows()
        elif system == 'Linux':
            return self._install_ca_linux()
        elif system == 'Darwin':
            return self._install_ca_macos()

        return False

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

            # Hide console window on Windows
            creation_flags = subprocess.CREATE_NO_WINDOW if sys.platform == 'win32' else 0

            # Use certutil to install certificate
            subprocess.run([
                'certutil',
                '-addstore',
                '-user',
                'ROOT',
                der_path
            ], check=True, capture_output=True, creationflags=creation_flags)

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
            home = os.path.expanduser("~")
            installed = False

            # Install in NSS database for Chrome/Chromium (user-level)
            nss_db = os.path.join(home, ".pki/nssdb")
            if os.path.exists(nss_db):
                try:
                    subprocess.run([
                        'certutil', '-d', f'sql:{nss_db}',
                        '-A', '-t', 'C,,',
                        '-n', 'Dominator CA',
                        '-i', str(self.ca_cert_path)
                    ], check=True, capture_output=True)
                    print(f"[+] CA certificate installed in Chrome/Chromium NSS database")
                    installed = True
                except FileNotFoundError:
                    print("[!] certutil not found. Install libnss3-tools: sudo apt install libnss3-tools")
                except Exception as e:
                    print(f"[!] Failed to install in NSS database: {e}")

            # Also try system-wide installation if we have permissions
            try:
                cert_dest = '/usr/local/share/ca-certificates/dominator_ca.crt'
                shutil.copy(self.ca_cert_path, cert_dest)
                subprocess.run(['update-ca-certificates'], check=True, capture_output=True)
                print(f"[+] CA certificate installed system-wide")
                installed = True
            except PermissionError:
                if not installed:
                    print("[!] Cannot install system-wide without sudo.")
            except Exception as e:
                if not installed:
                    print(f"[!] System-wide installation failed: {e}")

            return installed

        except Exception as e:
            print(f"[!] Failed to install CA certificate: {e}")
            return False

    def _install_ca_macos(self):
        """Install CA certificate in macOS Keychain"""
        import subprocess

        try:
            home = os.path.expanduser("~")
            login_keychain = os.path.join(home, "Library/Keychains/login.keychain-db")

            # Try login keychain first
            try:
                subprocess.run([
                    'security',
                    'add-trusted-cert',
                    '-r', 'trustRoot',
                    '-k', login_keychain,
                    str(self.ca_cert_path)
                ], check=True, capture_output=True)
                print(f"[+] CA certificate installed in macOS login Keychain")
                return True
            except subprocess.CalledProcessError:
                try:
                    subprocess.run([
                        'security',
                        'add-trusted-cert',
                        '-r', 'trustRoot',
                        str(self.ca_cert_path)
                    ], check=True, capture_output=True)
                    print(f"[+] CA certificate installed in macOS default Keychain")
                    return True
                except subprocess.CalledProcessError:
                    pass

            # Try System keychain (requires sudo)
            try:
                subprocess.run([
                    'security',
                    'add-trusted-cert',
                    '-d',
                    '-r', 'trustRoot',
                    '-k', '/Library/Keychains/System.keychain',
                    str(self.ca_cert_path)
                ], check=True, capture_output=True)
                print(f"[+] CA certificate installed in macOS System Keychain")
                return True
            except subprocess.CalledProcessError as e:
                print(f"[!] Failed to install in System Keychain (may need sudo): {e}")
                return False

        except Exception as e:
            print(f"[!] Failed to install CA certificate: {e}")
            return False

    def create_ssl_context(self, domain):
        """Create SSL context for wrapping sockets

        Uses temporary files to load in-memory certificates into SSL context.

        Args:
            domain: Domain name

        Returns:
            ssl.SSLContext: Configured SSL context
        """
        cert_pem, key_pem = self.generate_domain_certificate(domain)

        # Python's SSL requires files, so use temp files
        # These are deleted immediately after loading
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)

        # Write temp files, load, delete
        with tempfile.NamedTemporaryFile(mode='wb', suffix='.crt', delete=False) as cert_file:
            cert_file.write(cert_pem)
            cert_path = cert_file.name

        with tempfile.NamedTemporaryFile(mode='wb', suffix='.key', delete=False) as key_file:
            key_file.write(key_pem)
            key_path = key_file.name

        try:
            context.load_cert_chain(cert_path, key_path)
        finally:
            # Clean up temp files immediately
            try:
                os.unlink(cert_path)
            except:
                pass
            try:
                os.unlink(key_path)
            except:
                pass

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
