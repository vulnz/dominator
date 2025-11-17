"""
Firefox Manager - Launch Firefox with proxy configuration
Much simpler than Chromium - Firefox respects system proxy settings
"""
import os
import subprocess
import platform
from pathlib import Path


class FirefoxManager:
    """Manages Firefox browser for proxy integration"""

    def __init__(self):
        self.firefox_path = self._find_firefox()

    def _find_firefox(self):
        """Find Firefox installation"""
        if platform.system() == 'Windows':
            paths = [
                r"C:\Program Files\Mozilla Firefox\firefox.exe",
                r"C:\Program Files (x86)\Mozilla Firefox\firefox.exe",
                os.path.expandvars(r"%LOCALAPPDATA%\Mozilla Firefox\firefox.exe"),
                os.path.expandvars(r"%PROGRAMFILES%\Mozilla Firefox\firefox.exe"),
            ]
        elif platform.system() == 'Linux':
            paths = [
                "/usr/bin/firefox",
                "/usr/local/bin/firefox",
                "/snap/bin/firefox",
            ]
        else:  # macOS
            paths = [
                "/Applications/Firefox.app/Contents/MacOS/firefox",
                os.path.expanduser("~/Applications/Firefox.app/Contents/MacOS/firefox"),
            ]

        for path in paths:
            if os.path.exists(path):
                return path
        return None

    def is_installed(self):
        """Check if Firefox is installed"""
        return self.firefox_path is not None

    def launch(self, proxy_host='127.0.0.1', proxy_port=8080, url=None):
        """Launch Firefox with proxy configuration

        Args:
            proxy_host: Proxy host address
            proxy_port: Proxy port number
            url: Optional URL to open

        Returns:
            subprocess.Popen: Firefox process
        """
        if not self.firefox_path:
            raise Exception("Firefox not installed")

        # Create profile directory for proxy settings
        profile_dir = Path(__file__).parent.parent / "firefox_profile"
        profile_dir.mkdir(exist_ok=True)

        # Create prefs.js with proxy settings
        prefs_file = profile_dir / "prefs.js"
        with open(prefs_file, 'w') as f:
            f.write(f'''
// Firefox proxy configuration for Dominator
user_pref("network.proxy.type", 1);
user_pref("network.proxy.http", "{proxy_host}");
user_pref("network.proxy.http_port", {proxy_port});
user_pref("network.proxy.ssl", "{proxy_host}");
user_pref("network.proxy.ssl_port", {proxy_port});
user_pref("network.proxy.no_proxies_on", "localhost, 127.0.0.1");

// Disable certificate warnings for testing
user_pref("security.enterprise_roots.enabled", true);
user_pref("security.cert_pinning.enforcement_level", 0);

// Disable Firefox's own security warnings
user_pref("browser.safebrowsing.malware.enabled", false);
user_pref("browser.safebrowsing.phishing.enabled", false);

// Disable auto-updates during testing
user_pref("app.update.auto", false);
user_pref("app.update.enabled", false);

// Start page
user_pref("browser.startup.homepage", "about:blank");
''')

        # Build command
        cmd = [
            self.firefox_path,
            "-profile", str(profile_dir),
            "-no-remote",  # Don't use existing Firefox instance
        ]

        if url:
            cmd.append(url)

        # Launch
        print(f"[+] Launching Firefox with proxy: {proxy_host}:{proxy_port}")
        print(f"[+] Firefox path: {self.firefox_path}")
        print(f"[+] Profile directory: {profile_dir}")

        process = subprocess.Popen(
            cmd,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )

        return process


# Singleton instance
_firefox_manager = None


def get_firefox_manager():
    """Get singleton FirefoxManager instance"""
    global _firefox_manager
    if _firefox_manager is None:
        _firefox_manager = FirefoxManager()
    return _firefox_manager


if __name__ == "__main__":
    # Test script
    manager = get_firefox_manager()

    print(f"Firefox installed: {manager.is_installed()}")
    print(f"Firefox path: {manager.firefox_path}")

    if manager.is_installed():
        print("\nLaunching Firefox with proxy...")
        manager.launch(url="http://example.com")
