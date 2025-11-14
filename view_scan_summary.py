#!/usr/bin/env python3
"""
Quick scan report summary viewer
"""
import os
import sys
import re
from datetime import datetime

def parse_html_report(filepath):
    """Parse HTML report and extract summary"""
    with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
        content = f.read()

    summary = {
        'file': os.path.basename(filepath),
        'size_kb': os.path.getsize(filepath) / 1024,
        'modified': datetime.fromtimestamp(os.path.getmtime(filepath)).strftime('%Y-%m-%d %H:%M:%S')
    }

    # Extract target URL
    target_match = re.search(r'<h2>Target:\s*(.*?)</h2>', content)
    if target_match:
        summary['target'] = target_match.group(1).strip()

    # Extract vulnerability counts
    vuln_match = re.search(r'Total Vulnerabilities:</strong>\s*(\d+)', content)
    if vuln_match:
        summary['total_vulns'] = int(vuln_match.group(1))

    # Extract severity counts
    critical_match = re.search(r'Critical:</span>\s*(\d+)', content)
    high_match = re.search(r'High:</span>\s*(\d+)', content)
    medium_match = re.search(r'Medium:</span>\s*(\d+)', content)
    low_match = re.search(r'Low:</span>\s*(\d+)', content)

    if critical_match:
        summary['critical'] = int(critical_match.group(1))
    if high_match:
        summary['high'] = int(high_match.group(1))
    if medium_match:
        summary['medium'] = int(medium_match.group(1))
    if low_match:
        summary['low'] = int(low_match.group(1))

    # Extract module results
    module_pattern = r'<div class="module-result">\s*<h3>(.*?)</h3>.*?<div class="vulnerability-item.*?severity-(.*?)"'
    modules = re.findall(module_pattern, content, re.DOTALL)
    summary['modules'] = len(set([m[0] for m in modules]))

    return summary

def parse_txt_report(filepath):
    """Parse TXT report and extract summary"""
    with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
        content = f.read()

    summary = {
        'file': os.path.basename(filepath),
        'size_kb': os.path.getsize(filepath) / 1024,
        'modified': datetime.fromtimestamp(os.path.getmtime(filepath)).strftime('%Y-%m-%d %H:%M:%S')
    }

    # Extract target
    target_match = re.search(r'Target:\s*(.+)', content)
    if target_match:
        summary['target'] = target_match.group(1).strip()

    # Extract vulnerability counts
    vuln_match = re.search(r'Total Vulnerabilities:\s*(\d+)', content)
    if vuln_match:
        summary['total_vulns'] = int(vuln_match.group(1))

    # Extract severity counts
    critical_match = re.search(r'Critical:\s*(\d+)', content)
    high_match = re.search(r'High:\s*(\d+)', content)
    medium_match = re.search(r'Medium:\s*(\d+)', content)
    low_match = re.search(r'Low:\s*(\d+)', content)

    if critical_match:
        summary['critical'] = int(critical_match.group(1))
    if high_match:
        summary['high'] = int(high_match.group(1))
    if medium_match:
        summary['medium'] = int(medium_match.group(1))
    if low_match:
        summary['low'] = int(low_match.group(1))

    return summary

def main():
    # Get all scan report files
    files = [f for f in os.listdir('.') if f.startswith('scan_report_') and f.endswith(('.html', '.txt'))]

    if not files:
        print("No scan reports found in current directory")
        return

    # Sort by modification time (newest first)
    files.sort(key=lambda x: os.path.getmtime(x), reverse=True)

    print("="*100)
    print("SCAN REPORTS SUMMARY")
    print("="*100)
    print()

    # Parse and display each report
    for idx, file in enumerate(files[:10], 1):  # Show top 10 most recent
        try:
            if file.endswith('.html'):
                summary = parse_html_report(file)
            else:
                summary = parse_txt_report(file)

            print(f"{idx}. {summary.get('target', 'Unknown Target')}")
            print(f"   File: {summary['file']}")
            print(f"   Modified: {summary['modified']} | Size: {summary['size_kb']:.1f} KB")

            if 'total_vulns' in summary:
                print(f"   Vulnerabilities: {summary['total_vulns']} total", end='')
                if 'critical' in summary:
                    print(f" | Critical: {summary.get('critical', 0)}", end='')
                if 'high' in summary:
                    print(f" | High: {summary.get('high', 0)}", end='')
                if 'medium' in summary:
                    print(f" | Medium: {summary.get('medium', 0)}", end='')
                if 'low' in summary:
                    print(f" | Low: {summary.get('low', 0)}", end='')
                print()

            print()
        except Exception as e:
            print(f"Error parsing {file}: {e}")
            print()

    print("="*100)

if __name__ == '__main__':
    main()
