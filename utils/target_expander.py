"""
Target expansion utility for IP subnets, ranges, and multiple formats
"""

import ipaddress
import re
from typing import List


class TargetExpander:
    """
    Expands various target formats into individual targets

    Supported formats:
    - Domain: example.com
    - Domain + port: example.com:8080
    - URL: http://example.com
    - URL + port: http://example.com:8080
    - IP: 192.168.1.1
    - IP + port: 192.168.1.1:8080
    - IP subnet (CIDR): 192.168.1.0/24
    - IP range: 192.168.1.1-192.168.1.50
    """

    @staticmethod
    def expand_target(target: str) -> List[str]:
        """
        Expand a single target into multiple targets if it's a subnet or range

        Args:
            target: Target string (domain, IP, subnet, range, URL)

        Returns:
            List of expanded targets
        """
        target = target.strip()

        # Check if it's a CIDR subnet (e.g., 192.168.1.0/24)
        if '/' in target and not target.startswith(('http://', 'https://')):
            return TargetExpander._expand_cidr(target)

        # Check if it's an IP range (e.g., 192.168.1.1-192.168.1.50)
        if '-' in target and not target.startswith(('http://', 'https://')):
            # Make sure it's not a domain with hyphen (like my-domain.com)
            if TargetExpander._looks_like_ip_range(target):
                return TargetExpander._expand_ip_range(target)

        # Single target (domain, IP, URL, etc.)
        return [target]

    @staticmethod
    def expand_targets(targets: List[str]) -> List[str]:
        """
        Expand a list of targets

        Args:
            targets: List of target strings

        Returns:
            List of expanded targets
        """
        expanded = []
        for target in targets:
            expanded.extend(TargetExpander.expand_target(target))
        return expanded

    @staticmethod
    def _expand_cidr(cidr: str) -> List[str]:
        """
        Expand CIDR notation to individual IPs

        Args:
            cidr: CIDR notation (e.g., 192.168.1.0/24)

        Returns:
            List of IP addresses
        """
        try:
            # Extract port if present
            port = None
            if ':' in cidr:
                parts = cidr.rsplit(':', 1)
                if parts[1].isdigit():
                    cidr = parts[0]
                    port = parts[1]

            network = ipaddress.ip_network(cidr, strict=False)

            # Limit to reasonable size (prevent /8 or /16 expansion)
            if network.num_addresses > 1024:
                print(f"[WARNING] Subnet {cidr} contains {network.num_addresses} IPs. Limiting to first 1024.")
                ips = [str(ip) for ip in list(network.hosts())[:1024]]
            else:
                # Skip network and broadcast addresses for /24 and smaller
                if network.prefixlen >= 24:
                    ips = [str(ip) for ip in network.hosts()]
                else:
                    # For larger subnets, include all IPs
                    ips = [str(ip) for ip in network]

            # Add port if present
            if port:
                ips = [f"{ip}:{port}" for ip in ips]

            print(f"[INFO] Expanded {cidr} to {len(ips)} targets")
            return ips

        except ValueError as e:
            print(f"[ERROR] Invalid CIDR notation '{cidr}': {e}")
            return [cidr]  # Return original if invalid

    @staticmethod
    def _expand_ip_range(ip_range: str) -> List[str]:
        """
        Expand IP range to individual IPs

        Formats supported:
        - 192.168.1.1-50 (last octet range)
        - 192.168.1.1-192.168.1.50 (full range)

        Args:
            ip_range: IP range string

        Returns:
            List of IP addresses
        """
        try:
            # Extract port if present
            port = None
            if ':' in ip_range:
                parts = ip_range.rsplit(':', 1)
                if parts[1].isdigit():
                    ip_range = parts[0]
                    port = parts[1]

            # Split by hyphen
            parts = ip_range.split('-')
            if len(parts) != 2:
                return [ip_range]

            start_ip = parts[0].strip()
            end_part = parts[1].strip()

            # Check if end_part is just a number (last octet)
            if end_part.isdigit():
                # Format: 192.168.1.1-50
                ip_parts = start_ip.split('.')
                if len(ip_parts) != 4:
                    return [ip_range]

                start_last = int(ip_parts[3])
                end_last = int(end_part)

                if end_last > 255 or start_last > end_last:
                    print(f"[ERROR] Invalid IP range '{ip_range}'")
                    return [ip_range]

                base = '.'.join(ip_parts[:3])
                ips = [f"{base}.{i}" for i in range(start_last, end_last + 1)]

            else:
                # Format: 192.168.1.1-192.168.1.50
                try:
                    start = ipaddress.IPv4Address(start_ip)
                    end = ipaddress.IPv4Address(end_part)

                    if end < start:
                        print(f"[ERROR] End IP is less than start IP in '{ip_range}'")
                        return [ip_range]

                    # Limit range size
                    diff = int(end) - int(start)
                    if diff > 1024:
                        print(f"[WARNING] IP range {ip_range} contains {diff + 1} IPs. Limiting to first 1024.")
                        diff = 1023

                    ips = [str(ipaddress.IPv4Address(int(start) + i)) for i in range(diff + 1)]

                except ValueError as e:
                    print(f"[ERROR] Invalid IP range '{ip_range}': {e}")
                    return [ip_range]

            # Add port if present
            if port:
                ips = [f"{ip}:{port}" for ip in ips]

            print(f"[INFO] Expanded {ip_range} to {len(ips)} targets")
            return ips

        except Exception as e:
            print(f"[ERROR] Failed to expand IP range '{ip_range}': {e}")
            return [ip_range]

    @staticmethod
    def _looks_like_ip_range(target: str) -> bool:
        """
        Check if target looks like an IP range

        Args:
            target: Target string

        Returns:
            True if looks like IP range
        """
        # Remove port if present
        if ':' in target:
            target = target.rsplit(':', 1)[0]

        # Check if starts with IP-like pattern
        if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}-', target):
            return True

        return False


def expand_targets_from_file(filename: str) -> List[str]:
    """
    Read targets from file and expand subnets/ranges

    Args:
        filename: Path to file with targets (one per line)

    Returns:
        List of expanded targets
    """
    try:
        with open(filename, 'r', encoding='utf-8') as f:
            lines = f.readlines()

        targets = []
        for line in lines:
            line = line.strip()
            # Skip empty lines and comments
            if not line or line.startswith('#'):
                continue
            targets.append(line)

        # Expand all targets
        expanded = TargetExpander.expand_targets(targets)
        print(f"[INFO] Loaded {len(targets)} targets from file, expanded to {len(expanded)} targets")
        return expanded

    except FileNotFoundError:
        print(f"[ERROR] File not found: {filename}")
        return []
    except Exception as e:
        print(f"[ERROR] Failed to read file '{filename}': {e}")
        return []


# Example usage
if __name__ == "__main__":
    expander = TargetExpander()

    # Test CIDR
    print("Testing CIDR:")
    print(expander.expand_target("192.168.1.0/29"))  # 6 hosts
    print()

    # Test IP range (last octet)
    print("Testing IP range (last octet):")
    print(expander.expand_target("192.168.1.1-5"))
    print()

    # Test IP range (full)
    print("Testing IP range (full):")
    print(expander.expand_target("192.168.1.1-192.168.1.5"))
    print()

    # Test with port
    print("Testing with port:")
    print(expander.expand_target("192.168.1.0/29:8080"))
    print()

    # Test regular targets
    print("Testing regular targets:")
    print(expander.expand_target("example.com"))
    print(expander.expand_target("192.168.1.1:8080"))
    print(expander.expand_target("http://example.com/path"))
