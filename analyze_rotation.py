#!/usr/bin/env python3
"""
Analyze scan results to identify:
1. Missed vulnerabilities (false negatives)
2. False positives
3. Detection accuracy
4. Module performance
"""

import json
import os
from collections import defaultdict
from typing import Dict, List, Any

# Known vulnerabilities in test applications
KNOWN_VULNS = {
    'xvwa': {
        'SQL Injection': ['http://127.0.0.1/xvwa/vulnerabilities/sqli/', 'http://127.0.0.1/xvwa/vulnerabilities/sqli_blind/'],
        'XSS': ['http://127.0.0.1/xvwa/vulnerabilities/xss/', 'http://127.0.0.1/xvwa/vulnerabilities/xss_r/', 'http://127.0.0.1/xvwa/vulnerabilities/xss_d/'],
        'Command Injection': ['http://127.0.0.1/xvwa/vulnerabilities/cmdi/'],
        'CSRF': ['http://127.0.0.1/xvwa/vulnerabilities/csrf/'],
        'File Upload': ['http://127.0.0.1/xvwa/vulnerabilities/fileupload/'],
        'LFI': ['http://127.0.0.1/xvwa/vulnerabilities/lfi/'],
        'RFI': ['http://127.0.0.1/xvwa/vulnerabilities/rfi/'],
        'Weak Credentials': ['http://127.0.0.1/xvwa/login.php'],
        'PHP Object Injection': ['http://127.0.0.1/xvwa/vulnerabilities/php_object_injection/'],
        'SSRF': ['http://127.0.0.1/xvwa/vulnerabilities/ssrf/'],
        'SSTI': ['http://127.0.0.1/xvwa/vulnerabilities/ssti/'],
        'Open Redirect': ['http://127.0.0.1/xvwa/vulnerabilities/redirect/'],
        'XXE': ['http://127.0.0.1/xvwa/vulnerabilities/xxe/'],
    },
    'testphp': {
        'SQL Injection': ['http://testphp.vulnweb.com/listproducts.php', 'http://testphp.vulnweb.com/artists.php'],
        'XSS': ['http://testphp.vulnweb.com/search.php', 'http://testphp.vulnweb.com/comment.php'],
        'LFI': ['http://testphp.vulnweb.com/'],
        'Weak Credentials': ['http://testphp.vulnweb.com/login.php'],
    },
    'testasp': {
        'SQL Injection': ['http://testasp.vulnweb.com/showthread.asp', 'http://testasp.vulnweb.com/Login.asp'],
        'XSS': ['http://testasp.vulnweb.com/search.asp'],
        'Weak Credentials': ['http://testasp.vulnweb.com/Login.asp'],
    }
}


def load_scan_results(report_file: str) -> List[Dict[str, Any]]:
    """Load scan results from HTML or JSON report"""
    results = []

    if not os.path.exists(report_file):
        return results

    # Try to find JSON report
    json_file = report_file.replace('.html', '.json')
    if os.path.exists(json_file):
        try:
            with open(json_file, 'r', encoding='utf-8') as f:
                data = json.load(f)
                results = data.get('vulnerabilities', [])
        except:
            pass

    return results


def analyze_coverage(app: str, results: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Analyze vulnerability detection coverage"""

    known = KNOWN_VULNS.get(app, {})

    detected = defaultdict(list)
    for result in results:
        if not result.get('vulnerability'):
            continue

        url = result.get('url', '')
        module = result.get('module', '').lower()

        # Map module to vulnerability type
        vuln_type = map_module_to_vuln_type(module)
        if vuln_type:
            detected[vuln_type].append(url)

    analysis = {
        'total_known': sum(len(urls) for urls in known.values()),
        'total_detected': len([r for r in results if r.get('vulnerability')]),
        'detected_by_type': {},
        'missed_by_type': {},
        'false_positives': [],
        'coverage_percent': 0
    }

    # Check each known vulnerability type
    for vuln_type, urls in known.items():
        detected_urls = detected.get(vuln_type, [])

        # Count how many known URLs were detected
        detected_count = 0
        for known_url in urls:
            for detected_url in detected_urls:
                if known_url in detected_url or detected_url in known_url:
                    detected_count += 1
                    break

        analysis['detected_by_type'][vuln_type] = {
            'known': len(urls),
            'detected': detected_count,
            'missed': len(urls) - detected_count
        }

        if detected_count < len(urls):
            analysis['missed_by_type'][vuln_type] = urls

    # Calculate coverage
    total_detected = sum(v['detected'] for v in analysis['detected_by_type'].values())
    if analysis['total_known'] > 0:
        analysis['coverage_percent'] = (total_detected / analysis['total_known']) * 100

    return analysis


def map_module_to_vuln_type(module: str) -> str:
    """Map scanner module name to vulnerability type"""
    mapping = {
        'sqli': 'SQL Injection',
        'sql': 'SQL Injection',
        'xss': 'XSS',
        'cmdi': 'Command Injection',
        'command': 'Command Injection',
        'csrf': 'CSRF',
        'file_upload': 'File Upload',
        'upload': 'File Upload',
        'lfi': 'LFI',
        'rfi': 'RFI',
        'weak_credentials': 'Weak Credentials',
        'weak': 'Weak Credentials',
        'php_object_injection': 'PHP Object Injection',
        'object': 'PHP Object Injection',
        'ssrf': 'SSRF',
        'ssti': 'SSTI',
        'template': 'SSTI',
        'redirect': 'Open Redirect',
        'xxe': 'XXE',
    }

    module_lower = module.lower()
    for key, value in mapping.items():
        if key in module_lower:
            return value

    return module


def identify_false_positives(results: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Identify potential false positives"""
    false_positives = []

    for result in results:
        if not result.get('vulnerability'):
            continue

        url = result.get('url', '')
        confidence = result.get('confidence', 0)
        evidence = result.get('evidence', '')

        # Low confidence findings are more likely to be false positives
        if confidence < 0.5:
            false_positives.append({
                'url': url,
                'module': result.get('module'),
                'confidence': confidence,
                'reason': 'Low confidence (<50%)'
            })

        # Check for generic error messages that might be misinterpreted
        generic_errors = ['404', '403', '500', 'error', 'not found', 'access denied']
        if any(err in evidence.lower() for err in generic_errors) and confidence < 0.8:
            false_positives.append({
                'url': url,
                'module': result.get('module'),
                'confidence': confidence,
                'reason': 'Generic error message detected'
            })

    return false_positives


def generate_analysis_report(rotation: int, app: str, report_file: str) -> str:
    """Generate analysis report for scan results"""

    results = load_scan_results(report_file)
    coverage = analyze_coverage(app, results)
    false_positives = identify_false_positives(results)

    report = f"""
================================================================================
ROTATION {rotation} ANALYSIS: {app.upper()}
================================================================================

## SCAN RESULTS
Total Vulnerabilities Found: {coverage['total_detected']}
Total Known Vulnerabilities: {coverage['total_known']}
Coverage: {coverage['coverage_percent']:.1f}%

## DETECTION BY TYPE
"""

    for vuln_type, stats in coverage['detected_by_type'].items():
        status = "✅" if stats['missed'] == 0 else "⚠️" if stats['detected'] > 0 else "❌"
        report += f"\n{status} {vuln_type}:\n"
        report += f"   Known: {stats['known']} | Detected: {stats['detected']} | Missed: {stats['missed']}\n"

    report += "\n## MISSED VULNERABILITIES (FALSE NEGATIVES)\n"
    if coverage['missed_by_type']:
        for vuln_type, urls in coverage['missed_by_type'].items():
            report += f"\n❌ {vuln_type}:\n"
            for url in urls:
                report += f"   - {url}\n"
    else:
        report += "✅ None - all known vulnerabilities detected!\n"

    report += "\n## POTENTIAL FALSE POSITIVES\n"
    if false_positives:
        for fp in false_positives[:10]:  # Show top 10
            report += f"\n⚠️  {fp['module']} - {fp['url']}\n"
            report += f"   Confidence: {fp['confidence']*100:.0f}% | Reason: {fp['reason']}\n"
    else:
        report += "✅ None identified\n"

    report += "\n## ISSUES TO FIX\n"

    issues = []

    # Identify modules that missed vulnerabilities
    for vuln_type, stats in coverage['detected_by_type'].items():
        if stats['missed'] > 0:
            issues.append(f"• {vuln_type} module: Missing {stats['missed']}/{stats['known']} detections")

    # Add false positives
    if len(false_positives) > 0:
        issues.append(f"• False positives: {len(false_positives)} potential FPs need review")

    if issues:
        for issue in issues:
            report += f"\n{issue}"
    else:
        report += "\n✅ No major issues identified!"

    report += "\n\n================================================================================\n"

    return report


if __name__ == '__main__':
    import sys

    if len(sys.argv) < 4:
        print("Usage: python analyze_rotation.py <rotation_num> <app> <report_file>")
        print("Example: python analyze_rotation.py 1 xvwa rotation1_xvwa_127.0.0.1.html")
        sys.exit(1)

    rotation = int(sys.argv[1])
    app = sys.argv[2]
    report_file = sys.argv[3]

    report = generate_analysis_report(rotation, app, report_file)
    print(report)

    # Save to file
    output_file = f"rotation{rotation}_{app}_analysis.txt"
    with open(output_file, 'w', encoding='utf-8') as f:
        f.write(report)

    print(f"\nAnalysis saved to: {output_file}")
