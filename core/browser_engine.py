"""
Headless Browser Engine for WAF/Cloudflare Bypass

This module provides a headless browser-based HTTP client that can:
- Execute JavaScript and pass Cloudflare challenges
- Handle cookie-based authentication
- Render JavaScript-heavy pages
- Extract content after JS execution

Requirements:
    pip install playwright
    playwright install chromium
"""

import asyncio
import logging
from typing import Optional, Dict, Any, List
from dataclasses import dataclass, field
from urllib.parse import urlparse
import time

logger = logging.getLogger(__name__)

# Try to import playwright
PLAYWRIGHT_AVAILABLE = False
try:
    from playwright.async_api import async_playwright, Browser, Page, BrowserContext
    from playwright.async_api import TimeoutError as PlaywrightTimeout
    PLAYWRIGHT_AVAILABLE = True
except ImportError:
    logger.debug("Playwright not installed. Headless browser features unavailable.")
    logger.debug("Install with: pip install playwright && playwright install chromium")


@dataclass
class BrowserResponse:
    """Response from headless browser request"""
    url: str
    status_code: int
    text: str
    headers: Dict[str, str]
    cookies: List[Dict[str, str]]
    response_time: float
    final_url: str  # URL after redirects
    title: str = ""

    @property
    def ok(self) -> bool:
        return 200 <= self.status_code < 400


class HeadlessBrowser:
    """
    Headless browser client using Playwright for WAF bypass

    Usage:
        browser = HeadlessBrowser()
        await browser.start()
        response = await browser.get("https://cloudflare-protected-site.com")
        await browser.stop()

    Or with context manager:
        async with HeadlessBrowser() as browser:
            response = await browser.get(url)
    """

    def __init__(self,
                 headless: bool = True,
                 timeout: int = 30000,
                 user_agent: Optional[str] = None,
                 proxy: Optional[str] = None,
                 wait_for_cloudflare: bool = True):
        """
        Initialize headless browser

        Args:
            headless: Run browser in headless mode (no GUI)
            timeout: Default timeout in milliseconds
            user_agent: Custom user agent (uses realistic default if None)
            proxy: Proxy URL (e.g., http://127.0.0.1:8080)
            wait_for_cloudflare: Wait for Cloudflare challenge to complete
        """
        if not PLAYWRIGHT_AVAILABLE:
            raise ImportError(
                "Playwright is required for headless browser features.\n"
                "Install with: pip install playwright && playwright install chromium"
            )

        self.headless = headless
        self.timeout = timeout
        self.wait_for_cloudflare = wait_for_cloudflare
        self.proxy = proxy

        # Realistic user agent
        self.user_agent = user_agent or (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
            "AppleWebKit/537.36 (KHTML, like Gecko) "
            "Chrome/120.0.0.0 Safari/537.36"
        )

        self._playwright = None
        self._browser: Optional[Browser] = None
        self._context: Optional[BrowserContext] = None
        self._page: Optional[Page] = None
        self._started = False

    async def start(self):
        """Start the browser"""
        if self._started:
            return

        self._playwright = await async_playwright().start()

        # Browser launch options
        launch_options = {
            "headless": self.headless,
            "args": [
                "--disable-blink-features=AutomationControlled",
                "--disable-dev-shm-usage",
                "--no-sandbox",
            ]
        }

        # Add proxy if configured
        if self.proxy:
            launch_options["proxy"] = {"server": self.proxy}

        self._browser = await self._playwright.chromium.launch(**launch_options)

        # Create context with realistic settings
        context_options = {
            "user_agent": self.user_agent,
            "viewport": {"width": 1920, "height": 1080},
            "locale": "en-US",
            "timezone_id": "America/New_York",
            "ignore_https_errors": True,
            "java_script_enabled": True,
        }

        self._context = await self._browser.new_context(**context_options)

        # Add stealth scripts to avoid detection
        await self._context.add_init_script("""
            // Override navigator.webdriver
            Object.defineProperty(navigator, 'webdriver', {
                get: () => undefined
            });

            // Override chrome runtime
            window.chrome = {
                runtime: {}
            };

            // Override permissions
            const originalQuery = window.navigator.permissions.query;
            window.navigator.permissions.query = (parameters) => (
                parameters.name === 'notifications' ?
                    Promise.resolve({ state: Notification.permission }) :
                    originalQuery(parameters)
            );

            // Override plugins
            Object.defineProperty(navigator, 'plugins', {
                get: () => [1, 2, 3, 4, 5]
            });

            // Override languages
            Object.defineProperty(navigator, 'languages', {
                get: () => ['en-US', 'en']
            });
        """)

        self._page = await self._context.new_page()
        self._started = True
        logger.info("Headless browser started")

    async def stop(self):
        """Stop the browser"""
        if self._page:
            await self._page.close()
        if self._context:
            await self._context.close()
        if self._browser:
            await self._browser.close()
        if self._playwright:
            await self._playwright.stop()
        self._started = False
        logger.info("Headless browser stopped")

    async def __aenter__(self):
        await self.start()
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        await self.stop()

    async def get(self, url: str, wait_until: str = "networkidle") -> Optional[BrowserResponse]:
        """
        Navigate to URL and get page content

        Args:
            url: URL to navigate to
            wait_until: When to consider navigation done
                       ("load", "domcontentloaded", "networkidle")

        Returns:
            BrowserResponse or None on error
        """
        if not self._started:
            await self.start()

        start_time = time.time()

        try:
            # Navigate to URL
            response = await self._page.goto(
                url,
                wait_until=wait_until,
                timeout=self.timeout
            )

            # Wait for Cloudflare challenge if needed
            if self.wait_for_cloudflare:
                await self._wait_for_cloudflare_challenge()

            # Get final content after JS execution
            content = await self._page.content()
            title = await self._page.title()
            final_url = self._page.url

            # Get cookies
            cookies = await self._context.cookies()

            # Build response
            response_time = time.time() - start_time

            return BrowserResponse(
                url=url,
                status_code=response.status if response else 200,
                text=content,
                headers=dict(response.headers) if response else {},
                cookies=cookies,
                response_time=response_time,
                final_url=final_url,
                title=title
            )

        except PlaywrightTimeout:
            logger.warning(f"Timeout loading {url}")
            return None
        except Exception as e:
            logger.error(f"Error loading {url}: {e}")
            return None

    async def _wait_for_cloudflare_challenge(self, max_wait: int = 15):
        """Wait for Cloudflare challenge to complete"""
        cloudflare_selectors = [
            "#challenge-running",
            "#challenge-stage",
            ".cf-browser-verification",
            "#cf-spinner-please-wait",
            "div.cf-turnstile",
        ]

        try:
            # Check if any Cloudflare challenge is present
            for selector in cloudflare_selectors:
                element = await self._page.query_selector(selector)
                if element:
                    logger.info("Cloudflare challenge detected, waiting...")
                    # Wait for challenge to disappear
                    await self._page.wait_for_selector(
                        selector,
                        state="hidden",
                        timeout=max_wait * 1000
                    )
                    # Wait a bit more for page to fully load
                    await self._page.wait_for_load_state("networkidle")
                    logger.info("Cloudflare challenge completed")
                    break
        except Exception as e:
            logger.debug(f"Cloudflare wait: {e}")

    async def get_with_interaction(self, url: str,
                                   clicks: List[str] = None,
                                   fills: Dict[str, str] = None,
                                   wait_after: int = 1000) -> Optional[BrowserResponse]:
        """
        Navigate and interact with page

        Args:
            url: URL to navigate to
            clicks: List of selectors to click
            fills: Dict of selector -> value to fill
            wait_after: Milliseconds to wait after interactions

        Returns:
            BrowserResponse after interactions
        """
        if not self._started:
            await self.start()

        start_time = time.time()

        try:
            await self._page.goto(url, wait_until="networkidle", timeout=self.timeout)

            if self.wait_for_cloudflare:
                await self._wait_for_cloudflare_challenge()

            # Perform fills
            if fills:
                for selector, value in fills.items():
                    await self._page.fill(selector, value)

            # Perform clicks
            if clicks:
                for selector in clicks:
                    await self._page.click(selector)

            # Wait after interactions
            if wait_after:
                await self._page.wait_for_timeout(wait_after)

            # Get content
            content = await self._page.content()
            title = await self._page.title()
            cookies = await self._context.cookies()

            return BrowserResponse(
                url=url,
                status_code=200,
                text=content,
                headers={},
                cookies=cookies,
                response_time=time.time() - start_time,
                final_url=self._page.url,
                title=title
            )

        except Exception as e:
            logger.error(f"Error during interaction: {e}")
            return None

    async def extract_forms(self, url: str) -> List[Dict[str, Any]]:
        """Extract all forms from a page after JS execution"""
        response = await self.get(url)
        if not response:
            return []

        # Extract forms using page evaluate
        forms = await self._page.evaluate("""
            () => {
                const forms = [];
                document.querySelectorAll('form').forEach(form => {
                    const inputs = [];
                    form.querySelectorAll('input, select, textarea').forEach(input => {
                        inputs.push({
                            name: input.name || '',
                            type: input.type || 'text',
                            value: input.value || '',
                            required: input.required || false
                        });
                    });
                    forms.push({
                        action: form.action || window.location.href,
                        method: (form.method || 'GET').toUpperCase(),
                        inputs: inputs
                    });
                });
                return forms;
            }
        """)

        return forms

    async def extract_links(self, url: str) -> List[str]:
        """Extract all links from a page after JS execution"""
        response = await self.get(url)
        if not response:
            return []

        links = await self._page.evaluate("""
            () => {
                const links = [];
                document.querySelectorAll('a[href]').forEach(a => {
                    if (a.href && !a.href.startsWith('javascript:')) {
                        links.push(a.href);
                    }
                });
                return [...new Set(links)];
            }
        """)

        return links

    def get_cookies_dict(self, cookies: List[Dict]) -> Dict[str, str]:
        """Convert cookie list to simple dict"""
        return {c['name']: c['value'] for c in cookies}


class SyncHeadlessBrowser:
    """
    Synchronous wrapper for HeadlessBrowser

    Usage:
        browser = SyncHeadlessBrowser()
        response = browser.get("https://example.com")
        browser.close()
    """

    def __init__(self, **kwargs):
        self._browser = HeadlessBrowser(**kwargs)
        self._loop = None

    def _get_loop(self):
        if self._loop is None or self._loop.is_closed():
            try:
                self._loop = asyncio.get_event_loop()
            except RuntimeError:
                self._loop = asyncio.new_event_loop()
                asyncio.set_event_loop(self._loop)
        return self._loop

    def get(self, url: str, **kwargs) -> Optional[BrowserResponse]:
        """Synchronous get request"""
        loop = self._get_loop()
        return loop.run_until_complete(self._browser.get(url, **kwargs))

    def extract_forms(self, url: str) -> List[Dict[str, Any]]:
        """Synchronous form extraction"""
        loop = self._get_loop()
        return loop.run_until_complete(self._browser.extract_forms(url))

    def extract_links(self, url: str) -> List[str]:
        """Synchronous link extraction"""
        loop = self._get_loop()
        return loop.run_until_complete(self._browser.extract_links(url))

    def close(self):
        """Close browser"""
        loop = self._get_loop()
        loop.run_until_complete(self._browser.stop())

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()


def is_browser_available() -> bool:
    """Check if headless browser is available"""
    return PLAYWRIGHT_AVAILABLE


def get_install_instructions() -> str:
    """Get installation instructions for headless browser"""
    return """
Headless browser requires Playwright:

1. Install Playwright:
   pip install playwright

2. Install browser binaries:
   playwright install chromium

After installation, use --browser flag to enable headless browser mode.
"""
