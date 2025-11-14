#!/usr/bin/env python3
"""
Master Script: Analyze Scan Results & Auto-Generate Fixes
Полный анализ репортов с автоматическими фиксами
"""

import json
import sys
from pathlib import Path
from utils.false_positive_analyzer import fp_analyzer
from collections import defaultdict

print("="*80)
print("  DOMINATOR - FALSE POSITIVE ANALYZER & AUTO-FIX GENERATOR")
print("="*80)

# Find all scan result files
scan_dir = Path('.')
result_files = list(scan_dir.glob('scan_report_*.html'))

if not result_files:
    print("\n[!] No scan reports found!")
    print("    Run scans first: python main.py -t <target>")
    sys.exit(1)

print(f"\n[+] Found {len(result_files)} scan reports")
for rf in result_files:
    print(f"    - {rf.name}")

# Попробуем найти JSON результаты (если есть)
json_files = list(scan_dir.glob('scan_results_*.json'))

if not json_files:
    print("\n[!] No JSON results found. Analyzing HTML reports...")
    # TODO: Parse HTML reports if needed
else:
    print(f"\n[+] Found {len(json_files)} JSON result files")

# Analyze each result file
all_reports = []
total_findings = 0
total_fps = 0

for json_file in json_files:
    print(f"\n[+] Analyzing: {json_file.name}")

    try:
        report = fp_analyzer.analyze_scan_results(str(json_file))
        all_reports.append({
            'file': json_file.name,
            'report': report
        })

        total_findings += report['total_findings']
        total_fps += report['false_positives']

        print(f"    Total findings: {report['total_findings']}")
        print(f"    False positives: {report['false_positives']}")
        print(f"    FP rate: {report['false_positive_rate']:.1f}%")

        if report['false_positives'] > 0:
            print(f"\n    False positives by module:")
            for module, count in report['by_module'].items():
                print(f"      - {module}: {count}")

    except Exception as e:
        print(f"    [!] Error analyzing {json_file.name}: {e}")

# Generate consolidated report
print("\n" + "="*80)
print("  CONSOLIDATED ANALYSIS")
print("="*80)
print(f"\nTotal findings across all scans: {total_findings}")
print(f"Total false positives: {total_fps}")
print(f"Overall FP rate: {(total_fps/total_findings*100) if total_findings > 0 else 0:.1f}%")

# Aggregate fixes needed
all_fixes = defaultdict(set)
for ar in all_reports:
    for module, fixes in ar['report']['fixes_needed'].items():
        all_fixes[module].update(fixes)

if all_fixes:
    print(f"\n[+] Fixes needed for {len(all_fixes)} modules:")
    for module, fixes in all_fixes.items():
        print(f"\n  {module}:")
        for fix in fixes:
            print(f"    - {fix}")

    # Generate fix script
    print("\n[+] Generating auto-fix script...")

    # Create combined report for fix generation
    combined_report = {
        'total_findings': total_findings,
        'false_positives': total_fps,
        'false_positive_rate': (total_fps/total_findings*100) if total_findings > 0 else 0,
        'fixes_needed': {k: list(v) for k, v in all_fixes.items()},
    }

    fix_script = fp_analyzer.generate_fixes(combined_report)

    # Save fix script
    fix_file = 'auto_generated_fixes.py'
    with open(fix_file, 'w', encoding='utf-8') as f:
        f.write(fix_script)

    print(f"  [OK] Fix script saved to: {fix_file}")
    print(f"\n[+] To apply fixes, run:")
    print(f"    python {fix_file}")

else:
    print("\n[+] No false positives detected! Scanner is working well.")

# Save detailed analysis report
analysis_file = 'false_positive_analysis.json'
with open(analysis_file, 'w', encoding='utf-8') as f:
    json.dump({
        'summary': {
            'total_findings': total_findings,
            'total_false_positives': total_fps,
            'fp_rate': (total_fps/total_findings*100) if total_findings > 0 else 0,
        },
        'by_scan': [
            {
                'file': ar['file'],
                'findings': ar['report']['total_findings'],
                'false_positives': ar['report']['false_positives'],
                'fp_rate': ar['report']['false_positive_rate'],
                'by_module': ar['report']['by_module'],
            }
            for ar in all_reports
        ],
        'fixes_needed': {k: list(v) for k, v in all_fixes.items()},
    }, f, indent=2)

print(f"\n[+] Detailed analysis saved to: {analysis_file}")

print("\n" + "="*80)
print("  ANALYSIS COMPLETE")
print("="*80)
