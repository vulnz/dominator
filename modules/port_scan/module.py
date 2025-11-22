"""
Port Scanner Module (Recon)

Scans for open ports and identifies services:
- Common web ports (80, 443, 8080, 8443, etc.)
- Database ports (3306, 5432, 27017, 6379)
- Service banner grabbing
- HTTP service detection

Use with --recon flag to auto-scan discovered HTTP services.
"""

from typing import List, Dict, Any, Tuple
from core.base_module import BaseModule
from core.logger import get_logger
from urllib.parse import urlparse
import socket
import ssl
import concurrent.futures

logger = get_logger(__name__)


class PortScanModule(BaseModule):
    """Port scanner with banner detection"""

    # Common ports to scan with service names
    COMMON_PORTS = {
        # Web services
        80: 'HTTP',
        443: 'HTTPS',
        8080: 'HTTP-ALT',
        8443: 'HTTPS-ALT',
        8000: 'HTTP-ALT',
        8888: 'HTTP-ALT',
        3000: 'Node.js',
        5000: 'Flask/Python',
        4443: 'HTTPS-ALT',

        # Databases
        3306: 'MySQL',
        5432: 'PostgreSQL',
        1433: 'MSSQL',
        1521: 'Oracle',
        27017: 'MongoDB',
        6379: 'Redis',
        9200: 'Elasticsearch',
        5984: 'CouchDB',

        # Mail
        25: 'SMTP',
        465: 'SMTPS',
        587: 'Submission',
        110: 'POP3',
        995: 'POP3S',
        143: 'IMAP',
        993: 'IMAPS',

        # Remote access
        21: 'FTP',
        22: 'SSH',
        23: 'Telnet',
        3389: 'RDP',
        5900: 'VNC',

        # Other
        53: 'DNS',
        389: 'LDAP',
        636: 'LDAPS',
        161: 'SNMP',
        445: 'SMB',
        139: 'NetBIOS',
    }

    # HTTP-capable ports (will try HTTP connection)
    HTTP_PORTS = [80, 8080, 8000, 8888, 3000, 5000, 8001, 8008, 9000, 9090]
    HTTPS_PORTS = [443, 8443, 4443, 9443]

    def __init__(self, module_path: str, payload_limit: int = None):
        """Initialize Port Scanner module"""
        super().__init__(module_path, payload_limit=payload_limit)
        logger.info("Port Scanner module loaded")

    def scan(self, targets: List[Dict[str, Any]], http_client: Any) -> List[Dict[str, Any]]:
        """
        Scan targets for open ports and services

        Args:
            targets: List of URLs (will extract host from each)
            http_client: HTTP client

        Returns:
            List of discovered open ports with service info
        """
        results = []
        scanned_hosts = set()

        logger.info(f"Starting Port scan on {len(targets)} targets")

        for target in targets:
            url = target.get('url', '')

            # Extract hostname
            parsed = urlparse(url)
            hostname = parsed.hostname

            if not hostname or hostname in scanned_hosts:
                continue
            scanned_hosts.add(hostname)

            logger.info(f"Scanning ports on: {hostname}")

            # Scan common ports
            open_ports = self._scan_ports(hostname)

            for port, info in open_ports.items():
                is_http = port in self.HTTP_PORTS or port in self.HTTPS_PORTS

                result = self.create_result(
                    vulnerable=False,  # This is recon, not vulnerability
                    url=f"{'https' if port in self.HTTPS_PORTS else 'http'}://{hostname}:{port}" if is_http else f"{hostname}:{port}",
                    parameter='Port',
                    payload=str(port),
                    evidence=info['evidence'],
                    description=f"Open port {port} ({info['service']})",
                    confidence=1.0
                )
                result['severity'] = 'info'
                result['type'] = 'recon'
                result['port'] = port
                result['service'] = info['service']
                result['banner'] = info.get('banner', '')
                result['is_http'] = is_http

                results.append(result)
                logger.info(f"Found open port: {hostname}:{port} ({info['service']})")

        logger.info(f"Port scan complete: {len(results)} open ports found")
        return results

    def _scan_ports(self, hostname: str) -> Dict[int, Dict]:
        """Scan common ports on hostname"""
        open_ports = {}

        def check_port(port: int) -> Tuple[int, Dict]:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(2)
                result = sock.connect_ex((hostname, port))

                if result == 0:
                    # Port is open - try to grab banner
                    banner = self._grab_banner(sock, hostname, port)
                    service = self._identify_service(port, banner)

                    return port, {
                        'service': service,
                        'banner': banner,
                        'evidence': f"Port {port} is open\n"
                                   f"Service: {service}\n"
                                   f"Banner: {banner[:200] if banner else 'N/A'}"
                    }
                sock.close()
            except Exception:
                pass
            return None, None

        # Use thread pool for faster scanning
        with concurrent.futures.ThreadPoolExecutor(max_workers=50) as executor:
            futures = {executor.submit(check_port, port): port
                      for port in self.COMMON_PORTS.keys()}

            for future in concurrent.futures.as_completed(futures, timeout=120):
                try:
                    port, info = future.result()
                    if port and info:
                        open_ports[port] = info
                except Exception:
                    pass

        return open_ports

    def _grab_banner(self, sock: socket.socket, hostname: str, port: int) -> str:
        """Attempt to grab service banner"""
        banner = ""

        try:
            # For HTTPS ports, try SSL handshake
            if port in self.HTTPS_PORTS:
                context = ssl.create_default_context()
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                sock = context.wrap_socket(sock, server_hostname=hostname)

            # For HTTP ports, send HTTP request
            if port in self.HTTP_PORTS or port in self.HTTPS_PORTS:
                sock.send(b"HEAD / HTTP/1.1\r\nHost: %s\r\n\r\n" % hostname.encode())
                banner = sock.recv(1024).decode('utf-8', errors='ignore')
            else:
                # Generic banner grab
                sock.settimeout(2)
                try:
                    # Try to receive without sending
                    banner = sock.recv(1024).decode('utf-8', errors='ignore')
                except:
                    # Send probe
                    sock.send(b"\r\n")
                    banner = sock.recv(1024).decode('utf-8', errors='ignore')

        except Exception as e:
            logger.debug(f"Banner grab failed for {hostname}:{port}: {e}")

        return banner.strip()

    def _identify_service(self, port: int, banner: str) -> str:
        """Identify service from port and banner"""
        # Start with known port service
        service = self.COMMON_PORTS.get(port, 'Unknown')

        # Enhance with banner analysis
        if banner:
            banner_lower = banner.lower()

            # HTTP signatures
            if 'http/' in banner_lower:
                if 'nginx' in banner_lower:
                    service = 'nginx'
                elif 'apache' in banner_lower:
                    service = 'Apache'
                elif 'iis' in banner_lower:
                    service = 'IIS'
                elif 'express' in banner_lower:
                    service = 'Express.js'
                else:
                    service = 'HTTP'

            # Database signatures
            elif 'mysql' in banner_lower:
                service = 'MySQL'
            elif 'postgresql' in banner_lower:
                service = 'PostgreSQL'
            elif 'mongodb' in banner_lower:
                service = 'MongoDB'
            elif 'redis' in banner_lower:
                service = 'Redis'

            # SSH
            elif 'ssh' in banner_lower:
                service = 'SSH'

            # FTP
            elif 'ftp' in banner_lower or '220 ' in banner:
                service = 'FTP'

            # SMTP
            elif 'smtp' in banner_lower or '220 ' in banner and 'mail' in banner_lower:
                service = 'SMTP'

        return service


def get_module(module_path: str, payload_limit: int = None):
    """Create module instance"""
    return PortScanModule(module_path, payload_limit=payload_limit)
