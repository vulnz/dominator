#!/usr/bin/env python3
"""
Simple HTTP server to serve live scan reports
Run this in the directory where live_report.html is located
"""

import http.server
import socketserver
import os
import sys
import webbrowser
from pathlib import Path

PORT = 8888


class NoCacheHTTPRequestHandler(http.server.SimpleHTTPRequestHandler):
    """HTTP handler that disables caching for JSON files"""

    def end_headers(self):
        # Disable caching for JSON files (live data)
        if self.path.endswith('.json'):
            self.send_header('Cache-Control', 'no-store, no-cache, must-revalidate')
            self.send_header('Pragma', 'no-cache')
            self.send_header('Expires', '0')
        super().end_headers()

    def log_message(self, format, *args):
        # Reduce logging noise
        if not self.path.endswith('.json'):
            super().log_message(format, *args)


def main():
    # Change to dominator directory if running from subdirectory
    if not Path("live_report.html").exists():
        print("Error: live_report.html not found in current directory")
        print("Please run this from the Dominator root directory")
        sys.exit(1)

    Handler = NoCacheHTTPRequestHandler

    with socketserver.TCPServer(("", PORT), Handler) as httpd:
        url = f"http://localhost:{PORT}/live_report.html"
        print("="*70)
        print(f"🚀 Live Report Server Started")
        print("="*70)
        print(f"\n📊 Open this URL in your browser:")
        print(f"   {url}\n")
        print(f"Press Ctrl+C to stop the server\n")
        print("="*70)

        # Try to open browser automatically
        try:
            webbrowser.open(url)
        except:
            pass

        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            print("\n\n✓ Server stopped")


if __name__ == "__main__":
    main()
