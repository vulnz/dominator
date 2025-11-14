"""
Centralized HTTP client for all scanner requests
"""

import requests
import urllib3
from typing import Dict, Optional, Any
from dataclasses import dataclass
import time
import logging
from utils.user_agents import UserAgentRotator  # ROTATION 9

# Disable SSL warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

logger = logging.getLogger(__name__)


@dataclass
class HTTPResponse:
    """Standardized HTTP response"""
    url: str
    status_code: int
    text: str
    headers: Dict[str, str]
    response_time: float
    content_length: int

    @property
    def ok(self) -> bool:
        """Check if response is successful"""
        return 200 <= self.status_code < 300


class HTTPClient:
    """Centralized HTTP client with rate limiting and error handling"""

    def __init__(self, timeout: int = 20, headers: Optional[Dict[str, str]] = None,
                 cookies: Optional[Dict[str, str]] = None, rate_limit: Optional[int] = None,
                 rotate_agent: bool = False):
        """
        Initialize HTTP client

        Args:
            timeout: Request timeout in seconds
            headers: Default headers for all requests
            cookies: Default cookies for all requests
            rate_limit: Max requests per second (None = no limit)
            rotate_agent: Enable User-Agent rotation (ROTATION 9)
        """
        self.timeout = timeout
        self.default_headers = headers or {}
        self.default_cookies = cookies or {}
        self.rate_limit = rate_limit
        self.last_request_time = 0

        # ROTATION 9: User-Agent rotation
        self.user_agent_rotator = UserAgentRotator(rotate=rotate_agent)

        # Create session for connection pooling
        self.session = requests.Session()
        self.session.verify = False
        self.session.headers.update(self.default_headers)

        # Request counter
        self.request_count = 0

    def _apply_rate_limit(self):
        """Apply rate limiting between requests"""
        if self.rate_limit:
            elapsed = time.time() - self.last_request_time
            min_interval = 1.0 / self.rate_limit
            if elapsed < min_interval:
                time.sleep(min_interval - elapsed)
        self.last_request_time = time.time()

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

    def _request(self, method: str, url: str, **kwargs) -> Optional[HTTPResponse]:
        """
        Internal method to send HTTP request

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
            headers.update(kwargs['headers'])

        # ROTATION 9: Apply User-Agent rotation (if not already set by user)
        if 'User-Agent' not in headers and 'user-agent' not in headers:
            headers['User-Agent'] = self.user_agent_rotator.get()

        kwargs['headers'] = headers

        # Set timeout
        if 'timeout' not in kwargs:
            kwargs['timeout'] = self.timeout

        # Set verify=False for SSL
        kwargs['verify'] = False

        # Add cookies
        if self.default_cookies and 'cookies' not in kwargs:
            kwargs['cookies'] = self.default_cookies

        try:
            start_time = time.time()
            response = self.session.request(method, url, **kwargs)
            response_time = time.time() - start_time

            return HTTPResponse(
                url=response.url,
                status_code=response.status_code,
                text=response.text,
                headers=dict(response.headers),
                response_time=response_time,
                content_length=len(response.content)
            )

        except requests.exceptions.Timeout:
            logger.warning(f"Request timeout: {url}")
            return None
        except requests.exceptions.ConnectionError:
            logger.warning(f"Connection error: {url}")
            return None
        except requests.exceptions.TooManyRedirects:
            logger.warning(f"Too many redirects: {url}")
            return None
        except Exception as e:
            logger.error(f"Request error for {url}: {e}")
            return None

    def close(self):
        """Close HTTP session"""
        if self.session:
            self.session.close()

    def get_stats(self) -> Dict[str, int]:
        """Get request statistics"""
        return {
            'total_requests': self.request_count
        }
