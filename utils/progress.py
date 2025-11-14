"""
Progress bar and ETA calculation for scanner
"""

import time
import sys
from typing import Optional


class ProgressBar:
    """
    Progress bar with ETA calculation

    Usage:
        progress = ProgressBar(total=100, desc="Scanning")
        for i in range(100):
            progress.update(1)
        progress.close()
    """

    def __init__(self, total: int, desc: str = "Progress", width: int = 50, enabled: bool = True):
        """
        Initialize progress bar

        Args:
            total: Total number of items
            desc: Description to show
            width: Width of progress bar in characters
            enabled: Whether to show progress bar
        """
        self.total = total
        self.desc = desc
        self.width = width
        self.enabled = enabled
        self.current = 0
        self.start_time = time.time()
        self.last_update = 0

    def update(self, n: int = 1):
        """Update progress by n items"""
        if not self.enabled:
            return

        self.current += n

        # Update every 0.1 seconds to avoid too frequent updates
        now = time.time()
        if now - self.last_update < 0.1 and self.current < self.total:
            return
        self.last_update = now

        self._render()

    def _render(self):
        """Render progress bar"""
        if not self.enabled or self.total == 0:
            return

        # Calculate progress
        progress = min(1.0, self.current / self.total)
        filled = int(self.width * progress)
        bar = '█' * filled + '░' * (self.width - filled)

        # Calculate ETA
        elapsed = time.time() - self.start_time
        if self.current > 0:
            rate = self.current / elapsed
            remaining = (self.total - self.current) / rate if rate > 0 else 0
            eta_str = self._format_time(remaining)
        else:
            eta_str = "calculating..."

        # Calculate percentage
        percent = progress * 100

        # Format output
        output = f"\r{self.desc}: |{bar}| {self.current}/{self.total} ({percent:.1f}%) ETA: {eta_str}"

        # Write to stderr to avoid interfering with stdout
        sys.stderr.write(output)
        sys.stderr.flush()

    def _format_time(self, seconds: float) -> str:
        """Format seconds into human-readable time"""
        if seconds < 0:
            return "00:00"

        hours = int(seconds // 3600)
        minutes = int((seconds % 3600) // 60)
        secs = int(seconds % 60)

        if hours > 0:
            return f"{hours:02d}:{minutes:02d}:{secs:02d}"
        else:
            return f"{minutes:02d}:{secs:02d}"

    def close(self):
        """Close progress bar"""
        if not self.enabled:
            return

        # Final render
        self._render()
        sys.stderr.write("\n")
        sys.stderr.flush()

    def set_description(self, desc: str):
        """Update description"""
        self.desc = desc
        self._render()


class ScanProgress:
    """
    High-level progress tracker for scanner

    Tracks:
    - Crawling progress
    - Module progress
    - Overall scan progress
    """

    def __init__(self, enabled: bool = True):
        """Initialize scan progress tracker"""
        self.enabled = enabled
        self.current_bar: Optional[ProgressBar] = None
        self.total_requests = 0
        self.completed_requests = 0
        self.start_time = time.time()

    def start_crawling(self, total_urls: int):
        """Start crawling progress"""
        if self.current_bar:
            self.current_bar.close()

        self.current_bar = ProgressBar(
            total=total_urls,
            desc="Crawling",
            enabled=self.enabled
        )

    def update_crawling(self, n: int = 1):
        """Update crawling progress"""
        if self.current_bar:
            self.current_bar.update(n)

    def start_module(self, module_name: str, total_targets: int):
        """Start module scan progress"""
        if self.current_bar:
            self.current_bar.close()

        self.current_bar = ProgressBar(
            total=total_targets,
            desc=f"Module: {module_name}",
            enabled=self.enabled
        )

    def update_module(self, n: int = 1):
        """Update module progress"""
        if self.current_bar:
            self.current_bar.update(n)

    def start_overall(self, total_requests: int):
        """Start overall scan progress"""
        if self.current_bar:
            self.current_bar.close()

        self.total_requests = total_requests
        self.completed_requests = 0

        self.current_bar = ProgressBar(
            total=total_requests,
            desc="Overall scan",
            enabled=self.enabled
        )

    def update_overall(self, n: int = 1):
        """Update overall progress"""
        self.completed_requests += n
        if self.current_bar:
            self.current_bar.update(n)

    def close(self):
        """Close all progress bars"""
        if self.current_bar:
            self.current_bar.close()
            self.current_bar = None

    def get_stats(self) -> dict:
        """Get scan statistics"""
        elapsed = time.time() - self.start_time
        rate = self.completed_requests / elapsed if elapsed > 0 else 0

        return {
            'total_requests': self.total_requests,
            'completed_requests': self.completed_requests,
            'elapsed_time': elapsed,
            'requests_per_second': rate
        }
