"""
Favicon Hash Fingerprinting Module
Identifies web technologies by computing MMH3 hash of favicon
Compatible with Shodan's favicon search: http.favicon.hash:<hash>
"""

import re
import json
import base64
import struct
from typing import Dict, List, Any, Optional
from urllib.parse import urlparse, urljoin
from core.base_module import BaseModule


class Module(BaseModule):
    """Favicon hash fingerprinting scanner"""

    def __init__(self, http_client=None, config: Optional[Dict] = None):
        super().__init__(http_client, config)
        self.name = "Favicon Hash Fingerprinter"
        self.description = "Identifies technologies via favicon MMH3 hash"
        self.fingerprints = {}
        self._load_fingerprints()

    def _load_fingerprints(self):
        """Load known favicon fingerprints"""
        try:
            import os
            fp_file = os.path.join(os.path.dirname(__file__), 'fingerprints.json')
            if os.path.exists(fp_file):
                with open(fp_file, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                    self.fingerprints = data.get('fingerprints', {})
        except Exception:
            # Fallback fingerprints
            self.fingerprints = {
                "-1839543708": "Spring Boot",
                "81586312": "Jenkins",
                "-130889530": "GitLab",
                "1485257654": "Apache Tomcat",
                "-1407891097": "WordPress",
            }

    def run(self, target: str, params: Optional[Dict] = None) -> List[Dict[str, Any]]:
        """Run favicon hash fingerprinting"""
        results = []

        # Find and fetch favicon
        favicon_data = self._get_favicon(target)

        if not favicon_data:
            return results

        # Compute MMH3 hash
        favicon_hash = self._compute_mmh3_hash(favicon_data)

        if favicon_hash is None:
            return results

        # Look up in fingerprint database
        hash_str = str(favicon_hash)
        technology = self.fingerprints.get(hash_str)

        result = {
            'vulnerability': False,
            'type': 'Favicon Fingerprint',
            'severity': 'Info',
            'url': target,
            'parameter': 'favicon',
            'payload': f'MMH3: {favicon_hash}',
            'method': 'GET',
            'injection_type': 'Technology Detection',
            'favicon_hash': favicon_hash,
            'shodan_query': f'http.favicon.hash:{favicon_hash}',
            'cwe': 'CWE-200',
            'owasp': 'A05:2021',
            'cvss': 0,
        }

        if technology:
            result['vulnerability'] = True
            result['technology'] = technology
            result['evidence'] = f"Favicon hash {favicon_hash} matches known fingerprint for {technology}"
            result['description'] = f"Identified technology: {technology} (via favicon hash). Use Shodan query: http.favicon.hash:{favicon_hash}"
            result['recommendation'] = 'Consider if technology exposure reveals attack surface. Remove unnecessary metadata.'
            result['response'] = f"Technology: {technology}, Hash: {favicon_hash}"
        else:
            result['evidence'] = f"Favicon hash: {favicon_hash} (unknown technology)"
            result['description'] = f"Favicon hash computed: {favicon_hash}. Search Shodan with: http.favicon.hash:{favicon_hash}"
            result['recommendation'] = 'Use the hash to find similar servers on Shodan or other reconnaissance tools.'
            result['response'] = f"Unknown technology, Hash: {favicon_hash}"

        results.append(result)
        return results

    def _get_favicon(self, url: str) -> Optional[bytes]:
        """Find and fetch the favicon from a website"""
        parsed = urlparse(url)
        base_url = f"{parsed.scheme}://{parsed.netloc}"

        # Common favicon locations
        favicon_paths = [
            '/favicon.ico',
            '/favicon.png',
            '/assets/favicon.ico',
            '/static/favicon.ico',
            '/images/favicon.ico',
            '/img/favicon.ico',
        ]

        # First, try to find favicon link in HTML
        try:
            response = self.http_client.get(url)
            if response and response.text:
                # Look for <link rel="icon" or <link rel="shortcut icon"
                patterns = [
                    r'<link[^>]+rel=["\'](?:shortcut )?icon["\'][^>]+href=["\']([^"\']+)["\']',
                    r'<link[^>]+href=["\']([^"\']+)["\'][^>]+rel=["\'](?:shortcut )?icon["\']',
                    r'<link[^>]+rel=["\']apple-touch-icon["\'][^>]+href=["\']([^"\']+)["\']',
                ]

                for pattern in patterns:
                    match = re.search(pattern, response.text, re.IGNORECASE)
                    if match:
                        favicon_url = match.group(1)
                        if not favicon_url.startswith('http'):
                            favicon_url = urljoin(base_url, favicon_url)

                        favicon_resp = self.http_client.get(favicon_url)
                        if favicon_resp and favicon_resp.status_code == 200:
                            return favicon_resp.content
        except Exception:
            pass

        # Try common paths
        for path in favicon_paths:
            try:
                favicon_url = base_url + path
                response = self.http_client.get(favicon_url)

                if response and response.status_code == 200:
                    content_type = response.headers.get('Content-Type', '').lower()
                    # Verify it's an image
                    if 'image' in content_type or 'icon' in content_type or path.endswith('.ico'):
                        if len(response.content) > 0:
                            return response.content
            except Exception:
                continue

        return None

    def _compute_mmh3_hash(self, data: bytes) -> Optional[int]:
        """
        Compute MurmurHash3 (32-bit) of favicon data
        This matches Shodan's favicon hashing method
        """
        try:
            # Base64 encode the favicon (Shodan's method)
            encoded = base64.b64encode(data)

            # Compute MMH3 hash
            return self._mmh3_hash32(encoded)
        except Exception:
            return None

    def _mmh3_hash32(self, data: bytes, seed: int = 0) -> int:
        """
        Pure Python implementation of MurmurHash3 32-bit
        """
        def fmix32(h):
            h ^= h >> 16
            h = (h * 0x85ebca6b) & 0xFFFFFFFF
            h ^= h >> 13
            h = (h * 0xc2b2ae35) & 0xFFFFFFFF
            h ^= h >> 16
            return h

        def rotate32(x, r):
            return ((x << r) | (x >> (32 - r))) & 0xFFFFFFFF

        length = len(data)
        nblocks = length // 4

        h1 = seed & 0xFFFFFFFF

        c1 = 0xcc9e2d51
        c2 = 0x1b873593

        # Body
        for i in range(nblocks):
            k1 = struct.unpack('<I', data[i*4:(i+1)*4])[0]

            k1 = (k1 * c1) & 0xFFFFFFFF
            k1 = rotate32(k1, 15)
            k1 = (k1 * c2) & 0xFFFFFFFF

            h1 ^= k1
            h1 = rotate32(h1, 13)
            h1 = ((h1 * 5) + 0xe6546b64) & 0xFFFFFFFF

        # Tail
        tail = data[nblocks * 4:]
        k1 = 0

        if len(tail) >= 3:
            k1 ^= tail[2] << 16
        if len(tail) >= 2:
            k1 ^= tail[1] << 8
        if len(tail) >= 1:
            k1 ^= tail[0]
            k1 = (k1 * c1) & 0xFFFFFFFF
            k1 = rotate32(k1, 15)
            k1 = (k1 * c2) & 0xFFFFFFFF
            h1 ^= k1

        # Finalization
        h1 ^= length
        h1 = fmix32(h1)

        # Convert to signed 32-bit integer (to match Shodan's format)
        if h1 >= 0x80000000:
            h1 -= 0x100000000

        return h1


def compute_favicon_hash(url_or_data, http_client=None) -> Optional[int]:
    """
    Utility function to compute favicon hash from URL or raw data
    Can be used independently of the scanner
    """
    module = Module(http_client)

    if isinstance(url_or_data, bytes):
        return module._compute_mmh3_hash(url_or_data)
    elif isinstance(url_or_data, str):
        if url_or_data.startswith('http'):
            data = module._get_favicon(url_or_data)
            if data:
                return module._compute_mmh3_hash(data)

    return None
