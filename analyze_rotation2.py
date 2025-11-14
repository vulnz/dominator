#!/usr/bin/env python3
"""
Analyze ROTATION 2 results and compare with ROTATION 1
"""

import re
import sys
from pathlib import Path

print("[+] ROTATION 2 ANALYSIS")
print("=" * 80)

# Parse reports
reports = {
    'xvwa': 'scan_report_http___127.0.0.1_xvwa__20251113_074624.html',
    'testphp': 'scan_report_http___testphp.vulnweb.com__20251113_071703.html',
    'testasp': 'scan_report_http___testasp.vulnweb.com__20251113_070530.html',
}

def parse_report(filename):
    """Extract vulnerability counts from HTML report"""
    try:
        with open(filename, 'r', encoding='utf-8') as f:
            content = f.read()

        # Find summary cards
        critical = re.search(r'<div class="summary-card critical">.*?<h3>(\d+)</h3>', content, re.DOTALL)
        high = re.search(r'<div class="summary-card high">.*?<h3>(\d+)</h3>', content, re.DOTALL)
        medium = re.search(r'<div class="summary-card medium">.*?<h3>(\d+)</h3>', content, re.DOTALL)
        low = re.search(r'<div class="summary-card low">.*?<h3>(\d+)</h3>', content, re.DOTALL)
        info = re.search(r'<div class="summary-card info">.*?<h3>(\d+)</h3>', content, re.DOTALL)

        return {
            'critical': int(critical.group(1)) if critical else 0,
            'high': int(high.group(1)) if high else 0,
            'medium': int(medium.group(1)) if medium else 0,
            'low': int(low.group(1)) if low else 0,
            'info': int(info.group(1)) if info else 0,
        }
    except Exception as e:
        print(f"[!] Error parsing {filename}: {e}")
        return None

# Analyze each target
results = {}
for target, report_file in reports.items():
    if Path(report_file).exists():
        stats = parse_report(report_file)
        if stats:
            results[target] = stats
            total = sum(stats.values())
            print(f"\n[{target.upper()}]")
            print(f"  Critical: {stats['critical']}")
            print(f"  High: {stats['high']}")
            print(f"  Medium: {stats['medium']}")
            print(f"  Low: {stats['low']}")
            print(f"  Info: {stats['info']}")
            print(f"  TOTAL: {total}")
    else:
        print(f"\n[{target.upper()}] - Report not found: {report_file}")

# Compare with Rotation 1
print("\n" + "=" * 80)
print("COMPARISON WITH ROTATION 1")
print("=" * 80)

rotation1_xvwa = {
    'critical': 2,
    'high': 7,
    'medium': 30,
    'low': 5,
    'info': 0,
    'total': 44
}

if 'xvwa' in results:
    r2 = results['xvwa']
    r2_total = sum(r2.values())
    r1_total = rotation1_xvwa['total']

    print(f"\nXVWA Comparison:")
    print(f"  ROTATION 1: {r1_total} vulnerabilities")
    print(f"  ROTATION 2: {r2_total} vulnerabilities")
    print(f"  Change: {r2_total - r1_total:+d} ({((r2_total - r1_total) / r1_total * 100):+.1f}%)")

    print(f"\n  By Severity:")
    for sev in ['critical', 'high', 'medium', 'low']:
        r1_val = rotation1_xvwa.get(sev, 0)
        r2_val = r2.get(sev, 0)
        change = r2_val - r1_val
        print(f"    {sev.capitalize()}: {r1_val} -> {r2_val} ({change:+d})")

# Check for specific issues from ROTATION 1
print("\n" + "=" * 80)
print("KNOWN ISSUES CHECK")
print("=" * 80)

issues_to_check = [
    "Weak Credentials (xvwa:xvwa)",
    "File Upload (/fileupload/)",
    "SQLi Blind (/sqli_blind/)",
    "PHP Object Injection false positives",
]

print("\nIssues that need manual verification in reports:")
for issue in issues_to_check:
    print(f"  [ ] {issue}")

print("\n" + "=" * 80)
print("ACTION ITEMS FOR ROTATION 3")
print("=" * 80)
print("""
1. Review PHP Object Injection detections for false positives
2. Check if xvwa:xvwa weak credential was found
3. Verify file upload detection on /fileupload/
4. Check OOB detection for blind vulnerabilities
5. Add OOB proof URLs to evidence (requestbin/pipedream)
""")
