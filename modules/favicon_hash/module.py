"""
Favicon Hash Fingerprinting Module
Identifies web technologies by computing MMH3 hash of favicon
Compatible with Shodan's favicon search: http.favicon.hash:<hash>
"""

import re
import json
import base64
import struct
import os
from typing import List, Dict, Any
from urllib.parse import urlparse, urljoin
from core.base_module import BaseModule
from core.logger import get_logger

logger = get_logger(__name__)


class FaviconHashModule(BaseModule):
    """Favicon hash fingerprinting scanner"""

    def __init__(self, module_path: str, payload_limit: int = None):
        """Initialize Favicon Hash module"""
        super().__init__(module_path, payload_limit=payload_limit)
        self.fingerprints = self._load_fingerprints()
        logger.info(f"Favicon Hash module loaded: {len(self.fingerprints)} fingerprints")

    def _load_fingerprints(self) -> Dict[str, str]:
        """Load known favicon fingerprints"""
        # Common fingerprints
        fingerprints = {
            "-1839543708": "Spring Boot",
            "81586312": "Jenkins",
            "-130889530": "GitLab",
            "1485257654": "Apache Tomcat",
            "-1407891097": "WordPress",
            "116323821": "Apache",
            "-1166125415": "Nginx",
            "442749392": "Microsoft IIS",
            "-244067125": "Jira",
            "-1293291548": "Confluence",
            "1616866378": "Grafana",
            "-305179312": "Kibana",
            "99395752": "Elasticsearch",
            "1279780123": "phpMyAdmin",
            "876876147": "cPanel",
            "-674048714": "Plesk",
            "1697506441": "Webmin",
            "-1999872975": "Zabbix",
            "1848946384": "Nagios",
            "-1003792272": "SonarQube",
        }

        # Try to load from file
        try:
            fp_file = os.path.join(os.path.dirname(__file__), 'fingerprints.json')
            if os.path.exists(fp_file):
                with open(fp_file, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                    fingerprints.update(data.get('fingerprints', {}))
        except Exception:
            pass

        return fingerprints

    def scan(self, targets: List[Dict[str, Any]], http_client: Any) -> List[Dict[str, Any]]:
        """Scan for favicon and identify technology"""
        results = []
        tested_hosts = set()

        for target in targets:
            url = target.get('url')
            parsed = urlparse(url)
            host_key = parsed.netloc

            if host_key in tested_hosts:
                continue
            tested_hosts.add(host_key)

            # Get favicon
            favicon_data = self._get_favicon(url, http_client)
            if not favicon_data:
                continue

            # Calculate MMH3 hash
            favicon_hash = self._mmh3_hash(favicon_data)
            hash_str = str(favicon_hash)

            # Check fingerprints
            technology = self.fingerprints.get(hash_str)

            if technology:
                results.append(self.create_result(
                    vulnerable=True,
                    url=url,
                    parameter='favicon',
                    payload=hash_str,
                    evidence=f"Identified: {technology} (hash: {favicon_hash})",
                    severity='Info',
                    method='GET',
                    additional_info={
                        'injection_type': 'Technology Fingerprint',
                        'technology': technology,
                        'favicon_hash': favicon_hash,
                        'shodan_query': f'http.favicon.hash:{favicon_hash}',
                        'cwe': 'CWE-200',
                        'owasp': 'A05:2021',
                        'cvss': 0
                    }
                ))
            else:
                # Report unknown hash for manual lookup
                results.append(self.create_result(
                    vulnerable=True,
                    url=url,
                    parameter='favicon',
                    payload=hash_str,
                    evidence=f"Favicon hash: {favicon_hash}. Use Shodan: http.favicon.hash:{favicon_hash}",
                    severity='Info',
                    method='GET',
                    additional_info={
                        'injection_type': 'Favicon Hash',
                        'favicon_hash': favicon_hash,
                        'shodan_query': f'http.favicon.hash:{favicon_hash}',
                        'cwe': 'CWE-200',
                        'owasp': 'A05:2021',
                        'cvss': 0
                    }
                ))

        return results

    def _get_favicon(self, url: str, http_client) -> bytes:
        """Get favicon data from URL"""
        parsed = urlparse(url)
        base = f"{parsed.scheme}://{parsed.netloc}"

        # Try common favicon locations
        favicon_paths = [
            '/favicon.ico',
            '/favicon.png',
            '/assets/favicon.ico',
            '/static/favicon.ico',
        ]

        # First check page for favicon link
        try:
            response = http_client.get(url)
            if response and response.status_code == 200:
                match = re.search(r'<link[^>]+rel=["\'](?:shortcut )?icon["\'][^>]+href=["\']([^"\']+)["\']',
                                  response.text, re.IGNORECASE)
                if match:
                    favicon_url = urljoin(url, match.group(1))
                    favicon_paths.insert(0, favicon_url.replace(base, ''))
        except Exception:
            pass

        # Try each path
        for path in favicon_paths:
            try:
                favicon_url = base + path if not path.startswith('http') else path
                response = http_client.get(favicon_url)

                if response and response.status_code == 200:
                    content_type = response.headers.get('Content-Type', '')
                    if 'image' in content_type or 'icon' in content_type or path.endswith('.ico'):
                        return response.content
            except Exception:
                continue

        return None

    def _mmh3_hash(self, data: bytes) -> int:
        """Calculate MMH3 hash compatible with Shodan"""
        # Encode to base64 first (Shodan's method)
        b64_data = base64.encodebytes(data)
        return self._murmurhash3_32(b64_data)

    def _murmurhash3_32(self, data: bytes, seed: int = 0) -> int:
        """Pure Python implementation of MurmurHash3 32-bit"""
        c1 = 0xcc9e2d51
        c2 = 0x1b873593

        length = len(data)
        h1 = seed
        roundedEnd = (length & 0xfffffffc)

        for i in range(0, roundedEnd, 4):
            k1 = (data[i] & 0xff) | ((data[i + 1] & 0xff) << 8) | \
                 ((data[i + 2] & 0xff) << 16) | (data[i + 3] << 24)

            k1 = (k1 * c1) & 0xffffffff
            k1 = ((k1 << 15) | (k1 >> 17)) & 0xffffffff
            k1 = (k1 * c2) & 0xffffffff

            h1 ^= k1
            h1 = ((h1 << 13) | (h1 >> 19)) & 0xffffffff
            h1 = ((h1 * 5) + 0xe6546b64) & 0xffffffff

        k1 = 0
        val = length & 0x03

        if val == 3:
            k1 = (data[roundedEnd + 2] & 0xff) << 16
        if val >= 2:
            k1 |= (data[roundedEnd + 1] & 0xff) << 8
        if val >= 1:
            k1 |= data[roundedEnd] & 0xff
            k1 = (k1 * c1) & 0xffffffff
            k1 = ((k1 << 15) | (k1 >> 17)) & 0xffffffff
            k1 = (k1 * c2) & 0xffffffff
            h1 ^= k1

        h1 ^= length
        h1 ^= (h1 >> 16)
        h1 = (h1 * 0x85ebca6b) & 0xffffffff
        h1 ^= (h1 >> 13)
        h1 = (h1 * 0xc2b2ae35) & 0xffffffff
        h1 ^= (h1 >> 16)

        # Convert to signed 32-bit
        if h1 >= 0x80000000:
            h1 -= 0x100000000

        return h1


def get_module(module_path: str, payload_limit: int = None):
    """Factory function to create module instance"""
    return FaviconHashModule(module_path, payload_limit)
