"""
Network helper classes for HTTP proxy operations
Extracted from intercept_proxy.py for better modularity
"""

import socket
import threading
import time
import zlib
import gzip
from collections import OrderedDict
from functools import lru_cache
import requests

# Try to import brotli for br compression support
try:
    import brotli
    HAS_BROTLI = True
except ImportError:
    HAS_BROTLI = False


def decompress_content(body, content_encoding):
    """
    Decompress HTTP response body based on Content-Encoding header.
    Supports gzip, deflate, and brotli (br) compression.

    Args:
        body: Raw response body bytes
        content_encoding: Value of Content-Encoding header

    Returns:
        tuple: (decompressed_body, was_decompressed) - was_decompressed indicates if
               decompression actually occurred (affects whether to strip Content-Encoding header)
    """
    if not content_encoding or not body:
        return body, False

    # Normalize encoding string
    encoding = content_encoding.lower().strip()

    try:
        if encoding == 'gzip' or encoding == 'x-gzip':
            # Check for gzip magic bytes (0x1f 0x8b) before attempting decompression
            if len(body) >= 2 and body[0] == 0x1f and body[1] == 0x8b:
                return gzip.decompress(body), True
            else:
                # Not actually gzip despite header claim, return as-is
                return body, False

        elif encoding == 'deflate':
            # Try zlib first (with header), then raw deflate
            try:
                return zlib.decompress(body), True
            except zlib.error:
                try:
                    # Try raw deflate (no zlib header)
                    return zlib.decompress(body, -zlib.MAX_WBITS), True
                except zlib.error:
                    # Not deflate data, return as-is
                    return body, False

        elif encoding == 'br':
            if HAS_BROTLI:
                return brotli.decompress(body), True
            else:
                # Brotli not installed, return as-is
                return body, False

        elif ',' in encoding:
            # Multiple encodings (e.g., "gzip, br") - decompress in reverse order
            encodings = [e.strip() for e in encoding.split(',')]
            was_decompressed = False
            for enc in reversed(encodings):
                body, decompressed = decompress_content(body, enc)
                if decompressed:
                    was_decompressed = True
            return body, was_decompressed

        else:
            # Unknown encoding, return as-is
            return body, False

    except Exception:
        # Decompression failed, return original body (not decompressed)
        return body, False


class DNSCache:
    """Thread-safe DNS cache with TTL"""

    def __init__(self, ttl=300):
        self.cache = {}
        self.ttl = ttl
        self.lock = threading.Lock()

    @lru_cache(maxsize=1000)
    def resolve(self, hostname):
        """Resolve hostname to IP with caching"""
        try:
            with self.lock:
                if hostname in self.cache:
                    ip, timestamp = self.cache[hostname]
                    if time.time() - timestamp < self.ttl:
                        return ip

                # Resolve DNS
                ip = socket.gethostbyname(hostname)
                self.cache[hostname] = (ip, time.time())
                return ip
        except Exception:
            return hostname  # Fallback to hostname

    def clear(self):
        """Clear DNS cache"""
        with self.lock:
            self.cache.clear()
            self.resolve.cache_clear()


class ConnectionPool:
    """Connection pool for HTTP requests - reduces latency significantly"""

    def __init__(self, pool_size=10, pool_maxsize=20):
        self.session = requests.Session()

        # Configure connection pooling
        adapter = requests.adapters.HTTPAdapter(
            pool_connections=pool_size,
            pool_maxsize=pool_maxsize,
            max_retries=2,  # Retry on connection errors
            pool_block=False
        )

        self.session.mount('http://', adapter)
        self.session.mount('https://', adapter)

        # Disable SSL warnings
        import urllib3
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

        # Default timeout
        self.default_timeout = 15

    def request(self, method, url, **kwargs):
        """Make HTTP request using pooled connection"""
        # Set default timeout if not specified
        if 'timeout' not in kwargs:
            kwargs['timeout'] = self.default_timeout

        # Ensure SSL verification is disabled
        kwargs['verify'] = False

        return self.session.request(method, url, **kwargs)

    def close(self):
        """Close all pooled connections"""
        self.session.close()


class LRUCache:
    """LRU Cache for SSL certificates and other data"""

    def __init__(self, maxsize=100):
        self.cache = OrderedDict()
        self.maxsize = maxsize
        self.lock = threading.Lock()

    def get(self, key):
        """Get value from cache"""
        with self.lock:
            if key in self.cache:
                # Move to end (most recently used)
                self.cache.move_to_end(key)
                return self.cache[key]
            return None

    def put(self, key, value):
        """Put value in cache"""
        with self.lock:
            if key in self.cache:
                # Update and move to end
                self.cache.move_to_end(key)
            self.cache[key] = value

            # Remove oldest if cache is full
            if len(self.cache) > self.maxsize:
                self.cache.popitem(last=False)

    def clear(self):
        """Clear cache"""
        with self.lock:
            self.cache.clear()
