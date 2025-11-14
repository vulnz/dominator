#!/usr/bin/env python3
"""
Open the most recent scan report in browser
"""
import os
import webbrowser
import sys

def main():
    # Find most recent multi-target report or regular report
    reports = []

    # Priority 1: Multi-target reports
    for f in os.listdir('.'):
        if f.startswith('multi_target_report_') and f.endswith('.html'):
            reports.append(('multi', f, os.path.getmtime(f)))

    # Priority 2: Individual scan reports
    for f in os.listdir('.'):
        if f.startswith('scan_report_') and f.endswith('.html'):
            reports.append(('single', f, os.path.getmtime(f)))

    if not reports:
        print("No HTML reports found!")
        return

    # Sort by modification time (newest first)
    reports.sort(key=lambda x: x[2], reverse=True)

    # Show options
    print("Available reports:")
    for idx, (rtype, fname, mtime) in enumerate(reports[:10], 1):
        size_kb = os.path.getsize(fname) / 1024
        report_type = "MULTI-TARGET" if rtype == 'multi' else "Single Target"
        print(f"{idx}. [{report_type}] {fname} ({size_kb:.1f} KB)")

    # Open most recent if no argument
    if len(sys.argv) == 1:
        report_to_open = reports[0][1]
        print(f"\nOpening most recent report: {report_to_open}")
    else:
        try:
            idx = int(sys.argv[1]) - 1
            report_to_open = reports[idx][1]
            print(f"\nOpening: {report_to_open}")
        except (ValueError, IndexError):
            print("Invalid selection!")
            return

    # Open in browser
    abs_path = os.path.abspath(report_to_open)
    webbrowser.open(f'file://{abs_path}')
    print(f"Opened in browser: {abs_path}")

if __name__ == '__main__':
    main()
