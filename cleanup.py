#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Cleanup script for Dominator
Removes debug data, test files, and cache
"""

import os
import sys
import shutil
from pathlib import Path

# Fix Windows console encoding
if sys.platform == 'win32':
    import codecs
    sys.stdout = codecs.getwriter('utf-8')(sys.stdout.buffer, 'strict')
    sys.stderr = codecs.getwriter('utf-8')(sys.stderr.buffer, 'strict')

def cleanup():
    """Clean up debug data and temporary files"""
    root = Path(__file__).parent
    print("=" * 60)
    print("Dominator Cleanup Script")
    print("=" * 60)
    print()

    deleted_count = 0
    deleted_size = 0

    # 1. Remove __pycache__ directories
    print("[+] Removing Python cache directories...")
    for pycache in root.rglob("__pycache__"):
        try:
            size = sum(f.stat().st_size for f in pycache.rglob('*') if f.is_file())
            shutil.rmtree(pycache)
            deleted_count += 1
            deleted_size += size
            print(f"    [OK] Deleted: {pycache.relative_to(root)}")
        except Exception as e:
            print(f"    [ERR] Error: {e}")

    # 2. Remove .pyc files
    print("\n[+] Removing .pyc files...")
    for pyc in root.rglob("*.pyc"):
        try:
            size = pyc.stat().st_size
            pyc.unlink()
            deleted_count += 1
            deleted_size += size
            print(f"    ✓ Deleted: {pyc.relative_to(root)}")
        except Exception as e:
            print(f"    ✗ Error: {e}")

    # 3. Remove .spec files
    print("\n[+] Removing PyInstaller spec files...")
    for spec in root.glob("*.spec"):
        try:
            size = spec.stat().st_size
            spec.unlink()
            deleted_count += 1
            deleted_size += size
            print(f"    ✓ Deleted: {spec.name}")
        except Exception as e:
            print(f"    ✗ Error: {e}")

    # 4. Remove test HTML reports
    print("\n[+] Removing test HTML reports...")
    for html in list(root.glob("scan_report_*.html")) + list((root / "GUI").glob("scan_report_*.html")):
        try:
            size = html.stat().st_size
            html.unlink()
            deleted_count += 1
            deleted_size += size
            print(f"    ✓ Deleted: {html.relative_to(root)}")
        except Exception as e:
            print(f"    ✗ Error: {e}")

    # 5. Remove test JSON reports
    print("\n[+] Removing test JSON reports...")
    for json_file in root.glob("scan_report_*.json"):
        try:
            size = json_file.stat().st_size
            json_file.unlink()
            deleted_count += 1
            deleted_size += size
            print(f"    ✓ Deleted: {json_file.name}")
        except Exception as e:
            print(f"    ✗ Error: {e}")

    # 6. Remove debug HTML files
    print("\n[+] Removing debug HTML documentation...")
    debug_files = ["ARCHITECTURE.html", "TESTING_GUIDE.html", "BROWSER_INTEGRATION_QUICKSTART.html"]
    for filename in debug_files:
        filepath = root / filename
        if filepath.exists():
            try:
                size = filepath.stat().st_size
                filepath.unlink()
                deleted_count += 1
                deleted_size += size
                print(f"    ✓ Deleted: {filename}")
            except Exception as e:
                print(f"    ✗ Error: {e}")

    # 7. Remove log files
    print("\n[+] Removing log files...")
    for log in root.glob("*.log"):
        try:
            size = log.stat().st_size
            log.unlink()
            deleted_count += 1
            deleted_size += size
            print(f"    ✓ Deleted: {log.name}")
        except Exception as e:
            print(f"    ✗ Error: {e}")

    # 8. Remove build directory
    print("\n[+] Removing build artifacts...")
    build_dir = root / "build"
    if build_dir.exists():
        try:
            size = sum(f.stat().st_size for f in build_dir.rglob('*') if f.is_file())
            shutil.rmtree(build_dir)
            deleted_count += 1
            deleted_size += size
            print(f"    ✓ Deleted: build/")
        except Exception as e:
            print(f"    ✗ Error: {e}")

    # 9. Remove dist directory
    dist_dir = root / "dist"
    if dist_dir.exists():
        try:
            size = sum(f.stat().st_size for f in dist_dir.rglob('*') if f.is_file())
            shutil.rmtree(dist_dir)
            deleted_count += 1
            deleted_size += size
            print(f"    ✓ Deleted: dist/")
        except Exception as e:
            print(f"    ✗ Error: {e}")

    # 10. Remove chrome_profile
    print("\n[+] Removing old Chrome profile...")
    chrome_profile = root / "chrome_profile"
    if chrome_profile.exists():
        try:
            size = sum(f.stat().st_size for f in chrome_profile.rglob('*') if f.is_file())
            shutil.rmtree(chrome_profile)
            deleted_count += 1
            deleted_size += size
            print(f"    ✓ Deleted: chrome_profile/")
        except Exception as e:
            print(f"    ✗ Error: {e}")

    # 11. Clean Chromium portable user data
    print("\n[+] Cleaning Chromium portable user data...")
    chromium_user_data = root / "chromium_portable" / "user_data"
    if chromium_user_data.exists():
        try:
            size = sum(f.stat().st_size for f in chromium_user_data.rglob('*') if f.is_file())
            shutil.rmtree(chromium_user_data)
            deleted_count += 1
            deleted_size += size
            print(f"    ✓ Deleted: chromium_portable/user_data/")
        except Exception as e:
            print(f"    ✗ Error: {e}")

    # 12. Remove test files
    print("\n[+] Removing test files...")
    tests_dir = root / "tests"
    if tests_dir.exists():
        for test_file in tests_dir.glob("test_*.py"):
            try:
                size = test_file.stat().st_size
                test_file.unlink()
                deleted_count += 1
                deleted_size += size
                print(f"    ✓ Deleted: {test_file.relative_to(root)}")
            except Exception as e:
                print(f"    ✗ Error: {e}")

    # 13. Remove Firefox portable help.html
    firefox_help = root / "firefox_portable_app" / "help.html"
    if firefox_help.exists():
        try:
            size = firefox_help.stat().st_size
            firefox_help.unlink()
            deleted_count += 1
            deleted_size += size
            print(f"    ✓ Deleted: firefox_portable_app/help.html")
        except Exception as e:
            print(f"    ✗ Error: {e}")

    # Summary
    print()
    print("=" * 60)
    print("[+] Cleanup Complete!")
    print("=" * 60)
    print(f"Files/Folders Removed: {deleted_count}")
    print(f"Space Freed: {deleted_size / (1024*1024):.2f} MB")
    print()
    print("The repository is now clean.")
    print("Browser user data will be regenerated on next use.")

if __name__ == "__main__":
    cleanup()
