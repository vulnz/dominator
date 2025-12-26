"""
Screenshot Capture Module

Captures screenshots of target websites for visual inspection.
Supports multiple backends:
1. Playwright (preferred - headless Chrome)
2. Selenium (fallback)
3. External API (if no browser available)
"""

import os
import base64
import hashlib
from typing import Optional, Tuple
from pathlib import Path
from datetime import datetime
from core.logger import get_logger

logger = get_logger(__name__)


class ScreenshotCapture:
    """Capture website screenshots"""

    def __init__(self, output_dir: str = "screenshots"):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.backend = self._detect_backend()

    def _detect_backend(self) -> str:
        """Detect available screenshot backend"""
        # Try Playwright first
        try:
            from playwright.sync_api import sync_playwright
            return "playwright"
        except ImportError:
            pass

        # Try Selenium
        try:
            from selenium import webdriver
            return "selenium"
        except ImportError:
            pass

        # No browser backend available
        logger.warning("No browser backend available for screenshots. Install playwright or selenium.")
        return "none"

    def capture(self, url: str, filename: str = None, full_page: bool = False,
                width: int = 1920, height: int = 1080) -> Optional[str]:
        """
        Capture screenshot of URL

        Args:
            url: URL to capture
            filename: Optional output filename
            full_page: Capture full page (scroll)
            width: Viewport width
            height: Viewport height

        Returns:
            Path to saved screenshot or None
        """
        if not filename:
            # Generate filename from URL
            url_hash = hashlib.md5(url.encode()).hexdigest()[:8]
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"screenshot_{url_hash}_{timestamp}.png"

        output_path = self.output_dir / filename

        if self.backend == "playwright":
            return self._capture_playwright(url, output_path, full_page, width, height)
        elif self.backend == "selenium":
            return self._capture_selenium(url, output_path, full_page, width, height)
        else:
            logger.warning("No screenshot backend available")
            return None

    def _capture_playwright(self, url: str, output_path: Path,
                            full_page: bool, width: int, height: int) -> Optional[str]:
        """Capture using Playwright"""
        try:
            from playwright.sync_api import sync_playwright

            with sync_playwright() as p:
                browser = p.chromium.launch(headless=True)
                context = browser.new_context(
                    viewport={'width': width, 'height': height},
                    ignore_https_errors=True,
                )
                page = context.new_page()

                # Set timeout
                page.set_default_timeout(30000)

                try:
                    page.goto(url, wait_until='networkidle')
                except Exception:
                    # Try with domcontentloaded if networkidle fails
                    page.goto(url, wait_until='domcontentloaded')

                # Wait a bit for any lazy-loaded content
                page.wait_for_timeout(1000)

                # Capture screenshot
                page.screenshot(path=str(output_path), full_page=full_page)

                browser.close()

            logger.info(f"Screenshot saved: {output_path}")
            return str(output_path)

        except Exception as e:
            logger.error(f"Playwright screenshot failed: {e}")
            return None

    def _capture_selenium(self, url: str, output_path: Path,
                          full_page: bool, width: int, height: int) -> Optional[str]:
        """Capture using Selenium"""
        try:
            from selenium import webdriver
            from selenium.webdriver.chrome.options import Options
            from selenium.webdriver.chrome.service import Service

            options = Options()
            options.add_argument('--headless')
            options.add_argument('--no-sandbox')
            options.add_argument('--disable-dev-shm-usage')
            options.add_argument('--disable-gpu')
            options.add_argument(f'--window-size={width},{height}')
            options.add_argument('--ignore-certificate-errors')

            driver = webdriver.Chrome(options=options)

            try:
                driver.get(url)

                # Wait for page load
                driver.implicitly_wait(5)

                if full_page:
                    # Get full page height
                    total_height = driver.execute_script("return document.body.scrollHeight")
                    driver.set_window_size(width, total_height)

                driver.save_screenshot(str(output_path))

            finally:
                driver.quit()

            logger.info(f"Screenshot saved: {output_path}")
            return str(output_path)

        except Exception as e:
            logger.error(f"Selenium screenshot failed: {e}")
            return None

    def capture_to_base64(self, url: str, width: int = 1920, height: int = 1080) -> Optional[str]:
        """
        Capture screenshot and return as base64

        Args:
            url: URL to capture
            width: Viewport width
            height: Viewport height

        Returns:
            Base64 encoded PNG or None
        """
        # Capture to temp file
        temp_path = self.capture(url, "temp_screenshot.png", False, width, height)

        if temp_path and os.path.exists(temp_path):
            try:
                with open(temp_path, 'rb') as f:
                    data = base64.b64encode(f.read()).decode('utf-8')

                # Clean up temp file
                os.remove(temp_path)

                return data
            except Exception as e:
                logger.error(f"Failed to encode screenshot: {e}")

        return None

    def capture_multiple(self, urls: list, prefix: str = "target") -> dict:
        """
        Capture screenshots of multiple URLs

        Args:
            urls: List of URLs to capture
            prefix: Filename prefix

        Returns:
            Dict mapping URL to screenshot path
        """
        results = {}

        for i, url in enumerate(urls):
            filename = f"{prefix}_{i+1}.png"
            path = self.capture(url, filename)
            if path:
                results[url] = path

        return results


class ThumbnailGenerator:
    """Generate thumbnails from screenshots"""

    def __init__(self, output_dir: str = "thumbnails"):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)

    def generate(self, image_path: str, size: Tuple[int, int] = (400, 300)) -> Optional[str]:
        """
        Generate thumbnail from image

        Args:
            image_path: Path to source image
            size: Thumbnail size (width, height)

        Returns:
            Path to thumbnail or None
        """
        try:
            from PIL import Image

            img = Image.open(image_path)
            img.thumbnail(size, Image.Resampling.LANCZOS)

            # Generate output path
            source_name = Path(image_path).stem
            thumb_path = self.output_dir / f"{source_name}_thumb.png"

            img.save(str(thumb_path), "PNG")

            return str(thumb_path)

        except ImportError:
            logger.warning("PIL not available for thumbnail generation")
            return None
        except Exception as e:
            logger.error(f"Thumbnail generation failed: {e}")
            return None


def capture_screenshot(url: str, output_dir: str = "screenshots") -> Optional[str]:
    """Convenience function to capture a screenshot"""
    capturer = ScreenshotCapture(output_dir)
    return capturer.capture(url)
