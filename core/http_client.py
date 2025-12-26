"""
Centralized HTTP client for all scanner requests

Features:
- Connection pooling for performance
- Configurable retry logic with exponential backoff
- Detailed exception hierarchy for better error handling
- Request/response logging for debugging
- Rate limiting with token bucket algorithm
"""

import requests
import urllib3
from urllib3.util.retry import Retry
from requests.adapters import HTTPAdapter
from typing import Dict, Optional, Any, Tuple
from dataclasses import dataclass, field
from enum import Enum
import time
import logging
import gzip
import zlib
from utils.user_agents import UserAgentRotator  # ROTATION 9

# Try to import brotli for br compression support
try:
    import brotli
    BROTLI_AVAILABLE = True
except ImportError:
    BROTLI_AVAILABLE = False

# Disable SSL warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

logger = logging.getLogger(__name__)


# =============================================================================
# EXCEPTION HIERARCHY - Better error handling for callers
# =============================================================================

class HTTPClientError(Exception):
    """Base exception for HTTP client errors"""
    pass


class TimeoutError(HTTPClientError):
    """Request timed out"""
    pass


class ConnectionError(HTTPClientError):
    """Connection failed (DNS, network, refused)"""
    pass


class SSLError(HTTPClientError):
    """SSL/TLS error"""
    pass


class TooManyRedirectsError(HTTPClientError):
    """Too many redirects"""
    pass


class RateLimitError(HTTPClientError):
    """Rate limit exceeded (429)"""
    pass


class ErrorType(Enum):
    """Error type classification for metrics"""
    TIMEOUT = "timeout"
    CONNECTION = "connection"
    SSL = "ssl"
    REDIRECTS = "redirects"
    RATE_LIMIT = "rate_limit"
    HTTP_ERROR = "http_error"
    UNKNOWN = "unknown"


@dataclass
class HTTPResponse:
    """Standardized HTTP response with enhanced metadata"""
    url: str
    status_code: int
    text: str
    headers: Dict[str, str]
    response_time: float
    content_length: int
    # Enhanced fields for debugging/evidence
    request_method: str = "GET"
    request_headers: Dict[str, str] = field(default_factory=dict)
    request_body: str = ""
    error_type: Optional[ErrorType] = None

    @property
    def ok(self) -> bool:
        """Check if response is successful"""
        return 200 <= self.status_code < 300

    @property
    def is_redirect(self) -> bool:
        """Check if response is a redirect"""
        return 300 <= self.status_code < 400

    @property
    def is_client_error(self) -> bool:
        """Check if response is a client error"""
        return 400 <= self.status_code < 500

    @property
    def is_server_error(self) -> bool:
        """Check if response is a server error"""
        return 500 <= self.status_code < 600

    def get_request_string(self) -> str:
        """Build HTTP request string for evidence/logging"""
        from urllib.parse import urlparse
        parsed = urlparse(self.url)
        path = parsed.path or '/'
        if parsed.query:
            path += f"?{parsed.query}"

        lines = [f"{self.request_method} {path} HTTP/1.1"]
        lines.append(f"Host: {parsed.netloc}")

        for key, value in self.request_headers.items():
            if key.lower() != 'host':
                lines.append(f"{key}: {value}")

        if self.request_body:
            lines.append("")
            lines.append(self.request_body)

        return "\n".join(lines)


class HTTPClient:
    """
    Centralized HTTP client with:
    - Connection pooling for performance (10x connections per host)
    - Configurable retry with exponential backoff
    - Rate limiting with token bucket algorithm
    - Detailed error classification
    - Request/response logging for debugging
    """

    # Default connection pool settings for performance
    POOL_CONNECTIONS = 100  # Total connections to keep in pool
    POOL_MAXSIZE = 20       # Max connections per host
    MAX_RETRIES = 2         # Default retry count

    def __init__(self, timeout: int = 15, headers: Optional[Dict[str, str]] = None,
                 cookies: Optional[Dict[str, str]] = None, rate_limit: Optional[int] = None,
                 rotate_agent: bool = False, proxy: Optional[str] = None,
                 max_retries: int = 2, pool_connections: int = 100,
                 pool_maxsize: int = 20, debug_logging: bool = False):
        """
        Initialize HTTP client with enhanced configuration

        Args:
            timeout: Request timeout in seconds (default 15)
            headers: Default headers for all requests
            cookies: Default cookies for all requests
            rate_limit: Max requests per second (None = no limit)
            rotate_agent: Enable User-Agent rotation
            proxy: Proxy URL (e.g., http://127.0.0.1:8080 for Burp/ZAP)
            max_retries: Number of retries on connection errors (default 2)
            pool_connections: Total connections to keep in pool (default 100)
            pool_maxsize: Max connections per host (default 20)
            debug_logging: Enable detailed request/response logging
        """
        # Validate and clamp timeout
        self.timeout = max(5, min(timeout or 15, 300))
        self.default_headers = headers or {}
        self.default_cookies = cookies or {}
        self.rate_limit = rate_limit
        self.last_request_time = 0
        self.debug_logging = debug_logging

        # Token bucket for rate limiting (more efficient than sleep)
        self._tokens = rate_limit if rate_limit else float('inf')
        self._token_time = time.time()

        # Proxy configuration
        self.proxies = None
        if proxy:
            self.proxies = {
                'http': proxy,
                'https': proxy
            }

        # User-Agent rotation
        self.user_agent_rotator = UserAgentRotator(rotate=rotate_agent)

        # Create session with connection pooling
        self.session = requests.Session()
        self.session.verify = False
        self.session.headers.update(self.default_headers)

        # Configure connection pooling with retry strategy
        retry_strategy = Retry(
            total=max_retries,
            backoff_factor=0.5,  # 0.5, 1.0, 2.0 seconds between retries
            status_forcelist=[429, 500, 502, 503, 504],
            allowed_methods=["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"]
        )

        # Mount adapters with connection pooling
        adapter = HTTPAdapter(
            pool_connections=pool_connections,
            pool_maxsize=pool_maxsize,
            max_retries=retry_strategy
        )
        self.session.mount('http://', adapter)
        self.session.mount('https://', adapter)

        # Apply proxy to session if specified
        if self.proxies:
            self.session.proxies.update(self.proxies)

        # Statistics tracking
        self.request_count = 0
        self.error_counts: Dict[ErrorType, int] = {e: 0 for e in ErrorType}
        self.total_response_time = 0.0

    def _apply_rate_limit(self):
        """Apply rate limiting using token bucket algorithm (more efficient)"""
        if not self.rate_limit:
            return

        current_time = time.time()
        elapsed = current_time - self._token_time

        # Refill tokens based on elapsed time
        self._tokens = min(self.rate_limit, self._tokens + elapsed * self.rate_limit)
        self._token_time = current_time

        if self._tokens < 1:
            # Wait for token to be available
            sleep_time = (1 - self._tokens) / self.rate_limit
            time.sleep(sleep_time)
            self._tokens = 0
            self._token_time = time.time()
        else:
            self._tokens -= 1

    def get(self, url: str, params: Optional[Dict[str, Any]] = None,
            headers: Optional[Dict[str, str]] = None,
            allow_redirects: bool = True, **kwargs) -> Optional[HTTPResponse]:
        """
        Send GET request

        Args:
            url: Target URL
            params: Query parameters
            headers: Additional headers (merged with defaults)
            allow_redirects: Follow redirects
            **kwargs: Additional requests arguments

        Returns:
            HTTPResponse object or None on error
        """
        return self._request('GET', url, params=params, headers=headers,
                           allow_redirects=allow_redirects, **kwargs)

    def post(self, url: str, data: Optional[Dict[str, Any]] = None,
             json: Optional[Dict[str, Any]] = None,
             headers: Optional[Dict[str, str]] = None,
             allow_redirects: bool = True, **kwargs) -> Optional[HTTPResponse]:
        """
        Send POST request

        Args:
            url: Target URL
            data: Form data
            json: JSON data
            headers: Additional headers (merged with defaults)
            allow_redirects: Follow redirects
            **kwargs: Additional requests arguments

        Returns:
            HTTPResponse object or None on error
        """
        return self._request('POST', url, data=data, json=json, headers=headers,
                           allow_redirects=allow_redirects, **kwargs)

    def request(self, method: str, url: str, data: Optional[Dict[str, Any]] = None,
                json: Optional[Dict[str, Any]] = None, params: Optional[Dict[str, Any]] = None,
                headers: Optional[Dict[str, str]] = None,
                allow_redirects: bool = True, **kwargs) -> Optional[HTTPResponse]:
        """
        Send HTTP request with arbitrary method

        Args:
            method: HTTP method (GET, POST, PUT, DELETE, PATCH, etc.)
            url: Target URL
            data: Form data (for POST/PUT/PATCH)
            json: JSON data (for POST/PUT/PATCH)
            params: Query parameters (for GET)
            headers: Additional headers
            allow_redirects: Follow redirects
            **kwargs: Additional requests arguments

        Returns:
            HTTPResponse object or None on error
        """
        return self._request(method.upper(), url, data=data, json=json, params=params,
                           headers=headers, allow_redirects=allow_redirects, **kwargs)

    def _request(self, method: str, url: str, **kwargs) -> Optional[HTTPResponse]:
        """
        Internal method to send HTTP request with enhanced error handling

        Args:
            method: HTTP method
            url: Target URL
            **kwargs: Request arguments

        Returns:
            HTTPResponse object or None on error
        """
        self._apply_rate_limit()
        self.request_count += 1

        # Merge headers
        headers = self.default_headers.copy()
        if kwargs.get('headers'):
            custom_headers = kwargs['headers']
            if isinstance(custom_headers, dict):
                headers.update(custom_headers)
            elif custom_headers is not None:
                logger.warning(f"Invalid headers type: {type(custom_headers)}, expected dict")

        # Apply User-Agent rotation (if not already set)
        if 'User-Agent' not in headers and 'user-agent' not in headers:
            headers['User-Agent'] = self.user_agent_rotator.get()

        # Add browser-like headers to avoid WAF/bot detection (if not already set)
        browser_headers = {
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.9',
            'Accept-Encoding': 'gzip, deflate, br',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1',
            'Sec-Fetch-Dest': 'document',
            'Sec-Fetch-Mode': 'navigate',
            'Sec-Fetch-Site': 'none',
            'Sec-Fetch-User': '?1',
            'Cache-Control': 'max-age=0',
        }
        for key, value in browser_headers.items():
            if key not in headers and key.lower() not in [h.lower() for h in headers]:
                headers[key] = value

        kwargs['headers'] = headers

        # Set timeout
        if 'timeout' not in kwargs:
            kwargs['timeout'] = self.timeout

        # Set verify=False for SSL
        kwargs['verify'] = False

        # Add cookies
        if self.default_cookies and 'cookies' not in kwargs:
            kwargs['cookies'] = self.default_cookies

        # Build request body string for logging
        request_body = ""
        if kwargs.get('data'):
            if isinstance(kwargs['data'], dict):
                request_body = "&".join(f"{k}={v}" for k, v in kwargs['data'].items())
            else:
                request_body = str(kwargs['data'])
        elif kwargs.get('json'):
            import json as json_module
            request_body = json_module.dumps(kwargs['json'])

        error_type = None
        start_time = time.time()

        try:
            response = self.session.request(method, url, **kwargs)
            response_time = time.time() - start_time
            self.total_response_time += response_time

            # Debug logging if enabled
            if self.debug_logging:
                logger.debug(f"[HTTP] {method} {url} -> {response.status_code} ({response_time:.2f}s)")

            # Handle compressed responses
            text = self._decompress_response(response)

            # Safely convert headers to dict
            try:
                resp_headers = dict(response.headers) if response.headers else {}
            except (TypeError, ValueError):
                resp_headers = {}

            return HTTPResponse(
                url=str(response.url),
                status_code=response.status_code,
                text=text,
                headers=resp_headers,
                response_time=response_time,
                content_length=len(response.content) if response.content else 0,
                request_method=method,
                request_headers=headers.copy(),
                request_body=request_body,
                error_type=None
            )

        except requests.exceptions.Timeout as e:
            error_type = ErrorType.TIMEOUT
            self.error_counts[error_type] += 1
            logger.warning(f"Request timeout ({self.timeout}s): {url}")
            if self.debug_logging:
                logger.debug(f"Timeout details: {e}")
            return None

        except requests.exceptions.SSLError as e:
            error_type = ErrorType.SSL
            self.error_counts[error_type] += 1
            logger.warning(f"SSL error: {url} - {str(e)[:100]}")
            return None

        except requests.exceptions.ConnectionError as e:
            error_type = ErrorType.CONNECTION
            self.error_counts[error_type] += 1
            # Provide more context for connection errors
            error_msg = str(e)
            if 'Name or service not known' in error_msg or 'getaddrinfo failed' in error_msg:
                logger.warning(f"DNS resolution failed: {url}")
            elif 'Connection refused' in error_msg:
                logger.warning(f"Connection refused: {url}")
            elif 'Connection reset' in error_msg:
                logger.warning(f"Connection reset by peer: {url}")
            else:
                logger.warning(f"Connection error: {url}")
            if self.debug_logging:
                logger.debug(f"Connection error details: {e}")
            return None

        except requests.exceptions.TooManyRedirects as e:
            error_type = ErrorType.REDIRECTS
            self.error_counts[error_type] += 1
            logger.warning(f"Too many redirects (>30): {url}")
            return None

        except requests.exceptions.RequestException as e:
            error_type = ErrorType.HTTP_ERROR
            self.error_counts[error_type] += 1
            logger.error(f"HTTP request error for {url}: {type(e).__name__}: {str(e)[:100]}")
            return None

        except Exception as e:
            error_type = ErrorType.UNKNOWN
            self.error_counts[error_type] += 1
            logger.error(f"Unexpected error for {url}: {type(e).__name__}: {str(e)[:100]}")
            if self.debug_logging:
                import traceback
                logger.debug(f"Full traceback:\n{traceback.format_exc()}")
            return None

    def _decompress_response(self, response) -> str:
        """Decompress HTTP response based on Content-Encoding"""
        content_encoding = response.headers.get('Content-Encoding', '').lower()

        if not content_encoding:
            return response.text

        try:
            if content_encoding in ['gzip', 'x-gzip']:
                # Check if content is actually gzipped (magic bytes: 1f 8b)
                if len(response.content) >= 2 and response.content[:2] == b'\x1f\x8b':
                    decompressed = gzip.decompress(response.content)
                else:
                    decompressed = response.content

            elif content_encoding == 'deflate':
                try:
                    decompressed = zlib.decompress(response.content)
                except zlib.error:
                    try:
                        decompressed = zlib.decompress(response.content, -zlib.MAX_WBITS)
                    except zlib.error:
                        decompressed = response.content

            elif content_encoding == 'br' and BROTLI_AVAILABLE:
                decompressed = brotli.decompress(response.content)
            else:
                decompressed = response.content

            return decompressed.decode('utf-8', errors='ignore')

        except Exception as e:
            logger.debug(f"Decompression failed ({content_encoding}): {e}")
            return response.text

    def close(self):
        """Close HTTP session"""
        if self.session:
            self.session.close()

    def get_stats(self) -> Dict[str, Any]:
        """Get comprehensive request statistics"""
        avg_response_time = (self.total_response_time / self.request_count
                            if self.request_count > 0 else 0)

        return {
            'total_requests': self.request_count,
            'total_response_time': round(self.total_response_time, 2),
            'avg_response_time': round(avg_response_time, 3),
            'errors': {
                error_type.value: count
                for error_type, count in self.error_counts.items()
                if count > 0
            },
            'total_errors': sum(self.error_counts.values()),
            'success_rate': round(
                (self.request_count - sum(self.error_counts.values())) / self.request_count * 100
                if self.request_count > 0 else 0, 1
            )
        }

    def reset_stats(self):
        """Reset all statistics"""
        self.request_count = 0
        self.error_counts = {e: 0 for e in ErrorType}
        self.total_response_time = 0.0
