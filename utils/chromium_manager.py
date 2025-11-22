"""
Chromium Manager - Download and manage portable Chromium browser
Ensures browser availability without relying on system installation
"""

import os
import sys
import zipfile
import tarfile
import platform
import subprocess
from pathlib import Path
import urllib.request
import shutil


class ChromiumManager:
    """Manages portable Chromium browser for proxy integration"""

    def __init__(self):
        self.base_dir = Path(__file__).parent.parent / "chromium_portable"
        self.base_dir.mkdir(exist_ok=True)

        # Chromium download URLs - Latest stable versions
        # Using direct download links from chromium.woolyss.com (trusted mirror)
        self.download_urls = {
            'win32': 'https://download-chromium.appspot.com/dl/Win?type=snapshots',
            'win64': 'https://download-chromium.appspot.com/dl/Win_x64?type=snapshots',
            'linux': 'https://download-chromium.appspot.com/dl/Linux_x64?type=snapshots',
            'darwin': 'https://download-chromium.appspot.com/dl/Mac?type=snapshots',
        }

        # Detect platform
        self.platform = self._detect_platform()

        # Set paths
        self.chromium_dir = self.base_dir / self.platform
        self.executable_path = self._get_executable_path()

    def _detect_platform(self):
        """Detect current platform"""
        system = platform.system().lower()
        if system == 'windows':
            return 'win64' if sys.maxsize > 2**32 else 'win32'
        elif system == 'linux':
            return 'linux'
        elif system == 'darwin':
            return 'darwin'
        else:
            raise Exception(f"Unsupported platform: {system}")

    def _get_executable_path(self):
        """Get path to Chromium executable"""
        if self.platform.startswith('win'):
            # Try different possible locations
            paths = [
                self.chromium_dir / "chrome-win" / "chrome.exe",
                self.chromium_dir / "chrome-win64" / "chrome.exe",
                self.chromium_dir / "chrome.exe",
            ]
            for p in paths:
                if p.exists():
                    return p
            return paths[0]  # Return first as default
        elif self.platform == 'linux':
            paths = [
                self.chromium_dir / "chrome-linux" / "chrome",
                self.chromium_dir / "chrome-linux64" / "chrome",
                self.chromium_dir / "chrome",
            ]
            for p in paths:
                if p.exists():
                    return p
            return paths[0]
        elif self.platform == 'darwin':
            return self.chromium_dir / "Chromium.app" / "Contents" / "MacOS" / "Chromium"
        return None

    def is_installed(self):
        """Check if Chromium is already downloaded"""
        if not self.executable_path:
            return False
        return self.executable_path.exists()

    def download(self, progress_callback=None):
        """Download and extract Chromium"""
        if self.is_installed():
            return str(self.executable_path)

        url = self.download_urls.get(self.platform)
        if not url:
            raise Exception(f"No download URL for platform: {self.platform}")

        # Download
        download_path = self.base_dir / f"chromium_{self.platform}.zip"

        if progress_callback:
            progress_callback("Downloading Chromium (this may take a few minutes)...", 0)

        try:
            # Download with progress
            def report_hook(block_num, block_size, total_size):
                if total_size > 0 and progress_callback:
                    percent = min(100, int((block_num * block_size * 100) / total_size))
                    progress_callback(f"Downloading Chromium: {percent}%", percent)

            urllib.request.urlretrieve(url, download_path, reporthook=report_hook)

            if progress_callback:
                progress_callback("Extracting Chromium...", 90)

            # Extract
            self.chromium_dir.mkdir(exist_ok=True)

            with zipfile.ZipFile(download_path, 'r') as zip_ref:
                zip_ref.extractall(self.chromium_dir)

            # Clean up zip
            download_path.unlink()

            # Make executable on Unix-like systems
            if self.platform in ['linux', 'darwin']:
                os.chmod(self.executable_path, 0o755)

            if progress_callback:
                progress_callback("Chromium ready!", 100)

            return str(self.executable_path)

        except Exception as e:
            # Clean up on error
            if download_path.exists():
                download_path.unlink()
            if self.chromium_dir.exists():
                shutil.rmtree(self.chromium_dir)
            raise Exception(f"Failed to download Chromium: {str(e)}")

    def get_executable(self):
        """Get path to Chromium executable, download if needed"""
        if not self.is_installed():
            return None
        return str(self.executable_path)

    def install_ca_certificate(self):
        """Install CA certificate for HTTPS interception

        Returns:
            bool: True if successful, False otherwise
        """
        try:
            # Import here to avoid circular import
            from utils.cert_manager import get_cert_manager
            cert_mgr = get_cert_manager()

            # Install in system certificate store
            if cert_mgr.install_ca_in_chromium(str(self.base_dir / "user_data")):
                print("[+] CA certificate installed successfully")
                return True
            else:
                print("[!] Failed to install CA certificate")
                return False

        except Exception as e:
            print(f"[!] Error installing CA certificate: {e}")
            return False

    def get_ca_cert_path(self):
        """Get path to CA certificate for manual installation

        Returns:
            str: Path to CA certificate file
        """
        # Import here to avoid circular import
        from utils.cert_manager import get_cert_manager
        cert_mgr = get_cert_manager()
        return cert_mgr.get_ca_cert_path()

    def launch(self, proxy_host='127.0.0.1', proxy_port=8080, additional_args=None, ssl_intercept=True):
        """Launch Chromium with proxy configuration

        Args:
            proxy_host: Proxy host address
            proxy_port: Proxy port number
            additional_args: Additional command line arguments
            ssl_intercept: Enable SSL certificate warnings bypass for interception

        Returns:
            subprocess.Popen: Chromium process
        """
        executable = self.get_executable()
        if not executable:
            raise Exception("Chromium not installed. Please download first.")

        # Create user data directory
        user_data_dir = self.base_dir / "user_data"
        user_data_dir.mkdir(exist_ok=True)

        # Build command
        cmd = [
            executable,
            f"--proxy-server={proxy_host}:{proxy_port}",
            f"--user-data-dir={user_data_dir}",
            "--no-first-run",
            "--no-default-browser-check",
            "--disable-background-networking",
            "--disable-sync",
            "--metrics-recording-only",
            "--disable-default-apps",
            "--mute-audio",
        ]

        print(f"[DEBUG] Launching Chromium with proxy: {proxy_host}:{proxy_port}")
        print(f"[DEBUG] Executable: {executable}")

        # Add SSL interception flags if enabled
        if ssl_intercept:
            cmd.extend([
                "--ignore-certificate-errors",  # Ignore SSL errors from our certs
                "--ignore-certificate-errors-spki-list",  # Allow self-signed certs
                "--allow-insecure-localhost",  # Allow local HTTPS
                "--disable-web-security",  # Disable web security features that may interfere
                "--reduce-security-for-testing",  # Reduce security checks for testing
                "--allow-running-insecure-content",  # Allow insecure content on HTTPS pages
            ])

        # Add additional arguments
        if additional_args:
            cmd.extend(additional_args)

        # Launch - hide console window on Windows
        creation_flags = 0
        if sys.platform == 'win32':
            # CREATE_NO_WINDOW hides the console window
            creation_flags = subprocess.CREATE_NO_WINDOW | subprocess.CREATE_NEW_PROCESS_GROUP

        process = subprocess.Popen(
            cmd,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            creationflags=creation_flags
        )

        return process

    def get_installed_chrome(self):
        """Try to find system-installed Chrome/Chromium as fallback"""
        chrome_paths = [
            # Windows
            r"C:\Program Files\Google\Chrome\Application\chrome.exe",
            r"C:\Program Files (x86)\Google\Chrome\Application\chrome.exe",
            os.path.expandvars(r"%LOCALAPPDATA%\Google\Chrome\Application\chrome.exe"),

            # Linux
            "/usr/bin/google-chrome",
            "/usr/bin/chromium",
            "/usr/bin/chromium-browser",
            "/snap/bin/chromium",

            # macOS
            "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
            "/Applications/Chromium.app/Contents/MacOS/Chromium",
            os.path.expanduser("~/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"),
        ]

        for path in chrome_paths:
            if os.path.exists(path):
                return path

        return None

    def launch_with_fallback(self, proxy_host='127.0.0.1', proxy_port=8080):
        """Launch Chromium, falling back to system Chrome if needed"""
        try:
            # Try portable Chromium first
            if self.is_installed():
                return self.launch(proxy_host, proxy_port)
        except Exception as e:
            print(f"Portable Chromium launch failed: {e}")

        # Fallback to system Chrome
        chrome_path = self.get_installed_chrome()
        if chrome_path:
            user_data_dir = self.base_dir / "user_data"
            user_data_dir.mkdir(exist_ok=True)

            cmd = [
                chrome_path,
                f"--proxy-server={proxy_host}:{proxy_port}",
                f"--user-data-dir={user_data_dir}",
                "--no-first-run",
                "--new-window"
            ]

            # Hide console window on Windows
            creation_flags = 0
            if sys.platform == 'win32':
                creation_flags = subprocess.CREATE_NO_WINDOW | subprocess.CREATE_NEW_PROCESS_GROUP

            process = subprocess.Popen(
                cmd,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                creationflags=creation_flags
            )

            return process

        raise Exception("No Chrome/Chromium installation found")

    def get_download_size_mb(self):
        """Get approximate download size for current platform"""
        sizes = {
            'win32': 150,
            'win64': 150,
            'linux': 140,
            'darwin': 160,
        }
        return sizes.get(self.platform, 150)

    def remove(self):
        """Remove downloaded Chromium"""
        if self.base_dir.exists():
            shutil.rmtree(self.base_dir)


# Singleton instance
_chromium_manager = None


def get_chromium_manager():
    """Get singleton ChromiumManager instance"""
    global _chromium_manager
    if _chromium_manager is None:
        _chromium_manager = ChromiumManager()
    return _chromium_manager


if __name__ == "__main__":
    # Test script
    manager = get_chromium_manager()

    print(f"Platform: {manager.platform}")
    print(f"Chromium installed: {manager.is_installed()}")

    if not manager.is_installed():
        print(f"Download size: ~{manager.get_download_size_mb()} MB")
        print("Downloading Chromium...")

        def progress(msg, percent):
            print(f"[{percent}%] {msg}")

        manager.download(progress_callback=progress)

    print(f"Executable path: {manager.get_executable()}")
    print("\nLaunching Chromium with proxy...")
    manager.launch_with_fallback()
