"""
Firefox Manager - Launch Firefox with proxy configuration
Much simpler than Chromium - Firefox respects system proxy settings
"""
import os
import sys
import subprocess
import platform
from pathlib import Path


class FirefoxManager:
    """Manages Firefox browser for proxy integration"""

    def __init__(self):
        self.firefox_path = self._find_firefox()

    def _find_firefox(self):
        """Find Firefox installation"""
        # First, check for portable Firefox in project directory
        project_root = Path(__file__).parent.parent
        portable_exe = project_root / "firefox_portable_app" / "FirefoxPortable.exe"

        if portable_exe.exists():
            print(f"[+] Found portable Firefox: {portable_exe}")
            return str(portable_exe)

        # Fall back to system Firefox
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
                print(f"[+] Found system Firefox: {path}")
                return path

        print("[!] Firefox not found (neither portable nor system)")
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

        # Check if this is Firefox Portable
        is_portable = "FirefoxPortable.exe" in self.firefox_path

        if is_portable:
            # For Firefox Portable, modify the built-in profile
            project_root = Path(__file__).parent.parent
            profile_dir = project_root / "firefox_portable_app" / "Data" / "profile"
            profile_dir.mkdir(parents=True, exist_ok=True)
            prefs_file = profile_dir / "prefs.js"
        else:
            # For system Firefox, create custom profile
            profile_dir = Path(__file__).parent.parent / "firefox_profile"
            profile_dir.mkdir(exist_ok=True)
            prefs_file = profile_dir / "prefs.js"

        # Update proxy configuration in prefs.js
        # For Firefox Portable, we need to update existing prefs.js without destroying it
        # For system Firefox, we create a fresh profile

        if is_portable and prefs_file.exists():
            # Read existing prefs.js
            with open(prefs_file, 'r', encoding='utf-8') as f:
                existing_prefs = f.read()

            # Define our proxy preferences
            proxy_prefs = {
                "network.proxy.type": "1",
                "network.proxy.http": f'"{proxy_host}"',
                "network.proxy.http_port": str(proxy_port),
                "network.proxy.ssl": f'"{proxy_host}"',
                "network.proxy.ssl_port": str(proxy_port),
                "network.proxy.no_proxies_on": '"localhost, 127.0.0.1"',
                "security.enterprise_roots.enabled": "true",
                "security.cert_pinning.enforcement_level": "0",
                "browser.safebrowsing.malware.enabled": "false",
                "browser.safebrowsing.phishing.enabled": "false",
                "app.update.auto": "false",
                "app.update.enabled": "false",
                "browser.startup.homepage": '"about:blank"',

                # KILL ALL MOZILLA TELEMETRY AND TRACKING
                "datareporting.healthreport.uploadEnabled": "false",
                "datareporting.policy.dataSubmissionEnabled": "false",
                "toolkit.telemetry.enabled": "false",
                "toolkit.telemetry.unified": "false",
                "toolkit.telemetry.archive.enabled": "false",
                "toolkit.telemetry.newProfilePing.enabled": "false",
                "toolkit.telemetry.updatePing.enabled": "false",
                "toolkit.telemetry.bhrPing.enabled": "false",
                "toolkit.telemetry.firstShutdownPing.enabled": "false",
                "toolkit.telemetry.coverage.opt-out": "true",
                "toolkit.coverage.opt-out": "true",
                "toolkit.coverage.endpoint.base": '""',
                "browser.ping-centre.telemetry": "false",
                "browser.newtabpage.activity-stream.feeds.telemetry": "false",
                "browser.newtabpage.activity-stream.telemetry": "false",
                "app.shield.optoutstudies.enabled": "false",
                "app.normandy.enabled": "false",
                "app.normandy.api_url": '""',
                "extensions.shield-recipe-client.enabled": "false",
                "browser.discovery.enabled": "false",
                "browser.tabs.crashReporting.sendReport": "false",
                "breakpad.reportURL": '""',
                "browser.crashReports.unsubmittedCheck.enabled": "false",
                "browser.crashReports.unsubmittedCheck.autoSubmit2": "false",

                # Block all Mozilla domains (mozilla.org, mozilla.com, mozilla.net, etc.)
                "network.dns.blockDotOnion": "false",
                "permissions.default.telemetry": "2",
                "security.onecrl.via.amo": "false",
                "extensions.getAddons.showPane": "false",
                "extensions.webservice.discoverURL": '""',
                "browser.selfsupport.url": '""',
                "services.sync.prefs.sync.browser.startup.homepage": "false",
            }

            # Update or add each preference
            import re
            lines = existing_prefs.split('\n')
            updated_prefs = []
            modified_keys = set()

            for line in lines:
                # Check if this line contains a preference we want to modify
                matched = False
                for pref_name, pref_value in proxy_prefs.items():
                    if f'user_pref("{pref_name}"' in line:
                        # Replace this line with our value
                        updated_prefs.append(f'user_pref("{pref_name}", {pref_value});')
                        modified_keys.add(pref_name)
                        matched = True
                        break

                if not matched:
                    updated_prefs.append(line)

            # Add any preferences that weren't found in the file
            for pref_name, pref_value in proxy_prefs.items():
                if pref_name not in modified_keys:
                    updated_prefs.append(f'user_pref("{pref_name}", {pref_value});')

            # Write back to file
            with open(prefs_file, 'w', encoding='utf-8') as f:
                f.write('\n'.join(updated_prefs))
        else:
            # For system Firefox or if no prefs.js exists, create new profile
            with open(prefs_file, 'w', encoding='utf-8') as f:
                f.write(f'''// Firefox proxy configuration for Dominator
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

// ==========================================
// KILL ALL MOZILLA TELEMETRY AND TRACKING
// Block mozilla.org, mozilla.com, mozilla.net and all subdomains
// ==========================================

// Disable all telemetry
user_pref("datareporting.healthreport.uploadEnabled", false);
user_pref("datareporting.policy.dataSubmissionEnabled", false);
user_pref("toolkit.telemetry.enabled", false);
user_pref("toolkit.telemetry.unified", false);
user_pref("toolkit.telemetry.archive.enabled", false);
user_pref("toolkit.telemetry.newProfilePing.enabled", false);
user_pref("toolkit.telemetry.updatePing.enabled", false);
user_pref("toolkit.telemetry.bhrPing.enabled", false);
user_pref("toolkit.telemetry.firstShutdownPing.enabled", false);
user_pref("toolkit.telemetry.coverage.opt-out", true);
user_pref("toolkit.coverage.opt-out", true);
user_pref("toolkit.coverage.endpoint.base", "");

// Disable activity stream telemetry
user_pref("browser.ping-centre.telemetry", false);
user_pref("browser.newtabpage.activity-stream.feeds.telemetry", false);
user_pref("browser.newtabpage.activity-stream.telemetry", false);

// Disable experiments and studies
user_pref("app.shield.optoutstudies.enabled", false);
user_pref("app.normandy.enabled", false);
user_pref("app.normandy.api_url", "");
user_pref("extensions.shield-recipe-client.enabled", false);

// Disable discovery
user_pref("browser.discovery.enabled", false);

// Disable crash reports
user_pref("browser.tabs.crashReporting.sendReport", false);
user_pref("breakpad.reportURL", "");
user_pref("browser.crashReports.unsubmittedCheck.enabled", false);
user_pref("browser.crashReports.unsubmittedCheck.autoSubmit2", false);

// Disable Mozilla services
user_pref("permissions.default.telemetry", 2);
user_pref("security.onecrl.via.amo", false);
user_pref("extensions.getAddons.showPane", false);
user_pref("extensions.webservice.discoverURL", "");
user_pref("browser.selfsupport.url", "");
user_pref("services.sync.prefs.sync.browser.startup.homepage", false);

// Block pocket (getpocket.com)
user_pref("extensions.pocket.enabled", false);
user_pref("extensions.pocket.api", "");
user_pref("extensions.pocket.site", "");

// Additional privacy settings
user_pref("privacy.trackingprotection.enabled", true);
user_pref("privacy.trackingprotection.fingerprinting.enabled", true);
user_pref("privacy.trackingprotection.cryptomining.enabled", true);
user_pref("privacy.firstparty.isolate", true);
user_pref("privacy.resistFingerprinting", true);
user_pref("beacon.enabled", false);
user_pref("browser.send_pings", false);
''')

        # Build command
        if is_portable:
            # FirefoxPortable.exe doesn't support -profile parameter
            # It automatically uses Data/profile
            cmd = [self.firefox_path]
        else:
            # System Firefox with custom profile
            cmd = [
                self.firefox_path,
                "-profile", str(profile_dir),
                "-no-remote",
            ]

        if url:
            cmd.append(url)

        # Launch
        print(f"[+] Launching Firefox with proxy: {proxy_host}:{proxy_port}")
        print(f"[+] Firefox path: {self.firefox_path}")
        print(f"[+] Profile directory: {profile_dir}")

        # Hide console window on Windows
        creation_flags = 0
        if sys.platform == 'win32':
            creation_flags = subprocess.CREATE_NO_WINDOW

        process = subprocess.Popen(
            cmd,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            creationflags=creation_flags
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
