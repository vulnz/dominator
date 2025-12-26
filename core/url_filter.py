"""
URL Filtering and Deduplication Module

This module provides intelligent URL filtering to:
1. Skip static files that can't have injection vulnerabilities (.jpg, .css, etc.)
2. Deduplicate similar URLs (e.g., /123.jpg and /456.jpg are the same pattern)
3. Prioritize URLs with query parameters (more likely to be injectable)

Performance optimization: Reduces unnecessary requests to static resources.
"""

import re
from typing import List, Dict, Any, Set, Tuple, Optional
from urllib.parse import urlparse, parse_qs
from core.constants import (
    STATIC_FILE_EXTENSIONS,
    INJECTABLE_EXTENSIONS,
    RE_NUMERIC_ID,
    RE_HASH_LIKE,
    RE_UUID,
    RE_DATE,
    RE_NUMERIC_FILENAME,
    NUMERIC_PATTERN_PLACEHOLDER,
    HASH_PATTERN_PLACEHOLDER,
    UUID_PATTERN_PLACEHOLDER,
    DATE_PATTERN_PLACEHOLDER,
    FILENAME_PATTERN_PLACEHOLDER,
    MAX_URLS_PER_PATTERN,
)
from core.logger import get_logger

logger = get_logger(__name__)


class URLFilter:
    """
    Intelligent URL filtering and deduplication for vulnerability scanning.

    Key features:
    - Skips static files (.jpg, .css, .pdf, etc.) that cannot have injections
    - Deduplicates similar URLs to avoid redundant testing
    - Prioritizes URLs with query parameters
    - Configurable strictness levels
    """

    def __init__(self, strict: bool = True, max_per_pattern: int = MAX_URLS_PER_PATTERN):
        """
        Initialize URL filter.

        Args:
            strict: If True, aggressively filter static files even with params
            max_per_pattern: Max URLs to keep per URL pattern (for dedup)
        """
        self.strict = strict
        self.max_per_pattern = max_per_pattern

        # Track patterns we've seen for deduplication
        self.seen_patterns: Dict[str, List[str]] = {}

        # Statistics
        self.stats = {
            'total_input': 0,
            'filtered_static': 0,
            'filtered_duplicate': 0,
            'total_output': 0,
        }

    def filter_urls(self, urls: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Filter and deduplicate URL list for vulnerability scanning.

        Args:
            urls: List of URL dicts with 'url' and optionally 'params' keys

        Returns:
            Filtered list of URLs suitable for testing
        """
        self.stats['total_input'] = len(urls)
        logger.info(f"[URL_FILTER] Filtering {len(urls)} URLs...")

        filtered = []

        for url_dict in urls:
            url = url_dict.get('url', '')
            if not url:
                continue

            # Step 1: Check if static file
            if self.is_static_file(url):
                # Exception: If it has query params, it might be dynamic
                params = url_dict.get('params', {})
                if not params or self.strict:
                    self.stats['filtered_static'] += 1
                    logger.debug(f"[URL_FILTER] Skipping static file: {url}")
                    continue

            # Step 2: Check for duplicate pattern
            pattern = self.get_url_pattern(url)
            if self._is_duplicate_pattern(pattern, url):
                self.stats['filtered_duplicate'] += 1
                logger.debug(f"[URL_FILTER] Skipping duplicate pattern: {url}")
                continue

            # Step 3: Add to filtered list
            filtered.append(url_dict)

        self.stats['total_output'] = len(filtered)
        self._print_stats()

        return filtered

    def filter_url_strings(self, urls: List[str]) -> List[str]:
        """
        Filter and deduplicate a list of URL strings.

        Args:
            urls: List of URL strings

        Returns:
            Filtered list of URLs
        """
        # Convert to dict format and filter
        url_dicts = [{'url': url, 'params': self._extract_params(url)} for url in urls]
        filtered_dicts = self.filter_urls(url_dicts)
        return [d['url'] for d in filtered_dicts]

    def is_static_file(self, url: str) -> bool:
        """
        Check if URL points to a static file that shouldn't be tested.

        Static files include images, fonts, stylesheets, videos, archives, etc.
        These files cannot contain server-side injection vulnerabilities.

        Args:
            url: URL to check

        Returns:
            True if URL is a static file
        """
        try:
            parsed = urlparse(url)
            path = parsed.path.lower()

            # Get file extension
            if '.' in path:
                # Handle paths like /image.jpg?v=123
                path_without_query = path.split('?')[0]
                ext = '.' + path_without_query.rsplit('.', 1)[-1]

                if ext in STATIC_FILE_EXTENSIONS:
                    return True

            return False

        except Exception:
            return False

    def is_injectable_url(self, url: str) -> bool:
        """
        Check if URL points to a potentially injectable resource.

        Injectable URLs include:
        - URLs with query parameters
        - URLs with dynamic extensions (.php, .asp, etc.)
        - URLs without extensions (likely dynamic routes)

        Args:
            url: URL to check

        Returns:
            True if URL might have injection points
        """
        try:
            parsed = urlparse(url)

            # URLs with query params are potentially injectable
            if parsed.query:
                return True

            path = parsed.path.lower()

            # No extension = likely dynamic route
            if '.' not in path.split('/')[-1]:
                return True

            # Check for injectable extensions
            if '.' in path:
                ext = '.' + path.rsplit('.', 1)[-1]
                if ext in INJECTABLE_EXTENSIONS:
                    return True

            return False

        except Exception:
            return False

    def get_url_pattern(self, url: str) -> str:
        """
        Get normalized URL pattern for deduplication.

        Replaces variable parts with placeholders:
        - Numeric IDs -> [NUM]
        - Hash strings -> [HASH]
        - UUIDs -> [UUID]
        - Dates -> [DATE]
        - Numeric filenames -> [FILE]

        Examples:
            /products/123 -> /products/[NUM]
            /image/12345.jpg -> /image/[FILE]
            /users/abc123def456 -> /users/[HASH]

        Args:
            url: URL to normalize

        Returns:
            Normalized URL pattern
        """
        try:
            parsed = urlparse(url)
            path_parts = parsed.path.split('/')

            normalized_parts = []
            for part in path_parts:
                if not part:
                    normalized_parts.append(part)
                    continue

                # Check patterns in order of specificity
                if RE_UUID.match(part):
                    normalized_parts.append(UUID_PATTERN_PLACEHOLDER)
                elif RE_DATE.match(part):
                    normalized_parts.append(DATE_PATTERN_PLACEHOLDER)
                elif RE_NUMERIC_FILENAME.match(part):
                    # e.g., 12345.jpg -> [FILE].jpg
                    ext = '.' + part.rsplit('.', 1)[-1]
                    normalized_parts.append(FILENAME_PATTERN_PLACEHOLDER + ext)
                elif RE_HASH_LIKE.match(part):
                    normalized_parts.append(HASH_PATTERN_PLACEHOLDER)
                elif RE_NUMERIC_ID.match(part):
                    normalized_parts.append(NUMERIC_PATTERN_PLACEHOLDER)
                else:
                    normalized_parts.append(part)

            normalized_path = '/'.join(normalized_parts)

            # Include query param KEYS (not values) in pattern
            if parsed.query:
                params = parse_qs(parsed.query)
                param_pattern = ','.join(sorted(params.keys()))
                normalized_path += f"?{param_pattern}"

            return f"{parsed.netloc}{normalized_path}"

        except Exception as e:
            logger.debug(f"Error normalizing URL pattern: {e}")
            return url

    def _is_duplicate_pattern(self, pattern: str, url: str) -> bool:
        """
        Check if we've already seen enough URLs with this pattern.

        Args:
            pattern: Normalized URL pattern
            url: Original URL

        Returns:
            True if pattern has hit the max limit
        """
        if pattern not in self.seen_patterns:
            self.seen_patterns[pattern] = [url]
            return False

        # Check if we've hit the limit for this pattern
        if len(self.seen_patterns[pattern]) >= self.max_per_pattern:
            return True

        # Add this URL to the pattern list
        if url not in self.seen_patterns[pattern]:
            self.seen_patterns[pattern].append(url)

        return False

    def _extract_params(self, url: str) -> Dict[str, str]:
        """Extract query parameters from URL."""
        try:
            parsed = urlparse(url)
            params = parse_qs(parsed.query)
            return {k: v[0] if v else '' for k, v in params.items()}
        except Exception:
            return {}

    def _print_stats(self):
        """Print filtering statistics."""
        logger.info(f"[URL_FILTER] Results:")
        logger.info(f"  Input URLs: {self.stats['total_input']}")
        logger.info(f"  Filtered (static files): {self.stats['filtered_static']}")
        logger.info(f"  Filtered (duplicates): {self.stats['filtered_duplicate']}")
        logger.info(f"  Output URLs: {self.stats['total_output']}")

        reduction = 0
        if self.stats['total_input'] > 0:
            reduction = (1 - self.stats['total_output'] / self.stats['total_input']) * 100
        logger.info(f"  Reduction: {reduction:.1f}%")

    def reset(self):
        """Reset filter state for new scan."""
        self.seen_patterns.clear()
        self.stats = {
            'total_input': 0,
            'filtered_static': 0,
            'filtered_duplicate': 0,
            'total_output': 0,
        }


def filter_targets_for_module(targets: List[Dict[str, Any]], module_name: str = "") -> List[Dict[str, Any]]:
    """
    Convenience function to filter targets before module scanning.

    Args:
        targets: List of target dicts with 'url' key
        module_name: Name of module for logging

    Returns:
        Filtered targets suitable for the module
    """
    url_filter = URLFilter(strict=True)

    if module_name:
        logger.info(f"[{module_name}] Filtering targets before scan...")

    return url_filter.filter_urls(targets)


def is_static_file(url: str) -> bool:
    """Quick check if URL is a static file."""
    try:
        parsed = urlparse(url)
        path = parsed.path.lower()
        if '.' in path:
            ext = '.' + path.rsplit('.', 1)[-1]
            return ext in STATIC_FILE_EXTENSIONS
        return False
    except Exception:
        return False
