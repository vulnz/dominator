#!/usr/bin/env python3
"""
Create a consolidated multi-target scan report
"""
import os
import re
from datetime import datetime
from collections import defaultdict

def parse_html_report(filepath):
    """Parse HTML report and extract all findings"""
    with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
        content = f.read()

    # Extract target
    target = 'Unknown'
    target_match = re.search(r'<h2>Target:\s*(.*?)</h2>', content)
    if not target_match:
        # Try to extract from filename
        filename = os.path.basename(filepath)
        if 'xvwa' in filename:
            target = 'http://127.0.0.1/xvwa/'
        elif 'testphp' in filename:
            target = 'http://testphp.vulnweb.com/'
        elif 'testasp' in filename:
            target = 'http://testasp.vulnweb.com/'
    else:
        target = target_match.group(1).strip()

    # Extract severity counts
    critical = int(re.search(r'<h3>(\d+)</h3>\s*<p>Critical</p>', content).group(1)) if re.search(r'<h3>(\d+)</h3>\s*<p>Critical</p>', content) else 0
    high = int(re.search(r'<h3>(\d+)</h3>\s*<p>High</p>', content).group(1)) if re.search(r'<h3>(\d+)</h3>\s*<p>High</p>', content) else 0
    medium = int(re.search(r'<h3>(\d+)</h3>\s*<p>Medium</p>', content).group(1)) if re.search(r'<h3>(\d+)</h3>\s*<p>Medium</p>', content) else 0
    low = int(re.search(r'<h3>(\d+)</h3>\s*<p>Low</p>', content).group(1)) if re.search(r'<h3>(\d+)</h3>\s*<p>Low</p>', content) else 0

    # Extract vulnerability types
    vuln_pattern = r'<div class="vulnerability (critical|high|medium|low)">\s*<h3>(.*?)</h3>'
    vulns = re.findall(vuln_pattern, content, re.DOTALL)

    vuln_types = defaultdict(int)
    for severity, vtype in vulns:
        vtype_clean = re.sub(r'<[^>]+>', '', vtype).strip()
        if vtype_clean:
            vuln_types[vtype_clean] += 1

    return {
        'target': target,
        'critical': critical,
        'high': high,
        'medium': medium,
        'low': low,
        'total': critical + high + medium + low,
        'types': dict(vuln_types)
    }

def create_html_report(reports, output_file):
    """Create consolidated HTML report"""
    html = """
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>Multi-Target Scan Report</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; background: #f5f5f5; }
        .container { max-width: 1400px; margin: 0 auto; background: white; padding: 30px; box-shadow: 0 0 10px rgba(0,0,0,0.1); }
        h1 { color: #333; border-bottom: 3px solid #007bff; padding-bottom: 10px; }
        h2 { color: #555; margin-top: 30px; border-bottom: 2px solid #17a2b8; padding-bottom: 8px; }
        .overview { display: grid; grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); gap: 20px; margin: 30px 0; }
        .overview-card { padding: 20px; border-radius: 8px; color: white; text-align: center; box-shadow: 0 4px 6px rgba(0,0,0,0.1); }
        .overview-card h3 { font-size: 36px; margin: 10px 0; }
        .overview-card p { margin: 5px 0; font-size: 16px; }
        .critical-bg { background: linear-gradient(135deg, #d32f2f 0%, #b71c1c 100%); }
        .high-bg { background: linear-gradient(135deg, #f57c00 0%, #e65100 100%); }
        .medium-bg { background: linear-gradient(135deg, #ffa726 0%, #fb8c00 100%); }
        .low-bg { background: linear-gradient(135deg, #66bb6a 0%, #43a047 100%); }
        .info-bg { background: linear-gradient(135deg, #29b6f6 0%, #0288d1 100%); }
        table { width: 100%; border-collapse: collapse; margin: 20px 0; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
        th { background: #007bff; color: white; padding: 12px; text-align: left; font-weight: 600; }
        td { padding: 12px; border-bottom: 1px solid #ddd; }
        tr:hover { background: #f5f5f5; }
        .severity-critical { color: #d32f2f; font-weight: bold; }
        .severity-high { color: #f57c00; font-weight: bold; }
        .severity-medium { color: #ffa726; font-weight: bold; }
        .severity-low { color: #66bb6a; font-weight: bold; }
        .target-section { margin: 30px 0; padding: 20px; background: #f9f9f9; border-left: 4px solid #007bff; }
        .vuln-type { margin: 5px 0; padding: 8px; background: white; border-radius: 4px; }
        .timestamp { color: #888; font-size: 14px; }
    </style>
</head>
<body>
<div class="container">
    <h1>🔍 Multi-Target Vulnerability Scan Report</h1>
    <p class="timestamp">Generated: """ + datetime.now().strftime("%Y-%m-%d %H:%M:%S") + """</p>

    <h2>📊 Overall Summary</h2>
    <div class="overview">
"""

    # Calculate totals
    total_critical = sum(r['critical'] for r in reports)
    total_high = sum(r['high'] for r in reports)
    total_medium = sum(r['medium'] for r in reports)
    total_low = sum(r['low'] for r in reports)
    total_vulns = sum(r['total'] for r in reports)

    html += f"""
        <div class="overview-card critical-bg">
            <h3>{total_critical}</h3>
            <p>Critical Vulnerabilities</p>
        </div>
        <div class="overview-card high-bg">
            <h3>{total_high}</h3>
            <p>High Vulnerabilities</p>
        </div>
        <div class="overview-card medium-bg">
            <h3>{total_medium}</h3>
            <p>Medium Vulnerabilities</p>
        </div>
        <div class="overview-card low-bg">
            <h3>{total_low}</h3>
            <p>Low Vulnerabilities</p>
        </div>
        <div class="overview-card info-bg">
            <h3>{total_vulns}</h3>
            <p>Total Vulnerabilities</p>
        </div>
        <div class="overview-card info-bg">
            <h3>{len(reports)}</h3>
            <p>Targets Scanned</p>
        </div>
    </div>

    <h2>🎯 Per-Target Breakdown</h2>
    <table>
        <tr>
            <th>Target</th>
            <th>Critical</th>
            <th>High</th>
            <th>Medium</th>
            <th>Low</th>
            <th>Total</th>
        </tr>
"""

    for report in reports:
        html += f"""
        <tr>
            <td><strong>{report['target']}</strong></td>
            <td class="severity-critical">{report['critical']}</td>
            <td class="severity-high">{report['high']}</td>
            <td class="severity-medium">{report['medium']}</td>
            <td class="severity-low">{report['low']}</td>
            <td><strong>{report['total']}</strong></td>
        </tr>
"""

    html += """
    </table>

    <h2>🔬 Vulnerability Types by Target</h2>
"""

    for report in reports:
        html += f"""
    <div class="target-section">
        <h3>{report['target']}</h3>
        <p><strong>Total Vulnerabilities:</strong> {report['total']}</p>
"""
        if report['types']:
            html += "<div style='margin-top: 15px;'>"
            for vtype, count in sorted(report['types'].items(), key=lambda x: x[1], reverse=True)[:10]:
                html += f"<div class='vuln-type'>• <strong>{vtype}</strong>: {count} finding(s)</div>"
            html += "</div>"
        html += """
    </div>
"""

    html += """
</div>
</body>
</html>
"""

    with open(output_file, 'w', encoding='utf-8') as f:
        f.write(html)

    return output_file

def main():
    print("Analyzing scan reports...")

    # Find most recent HTML report for each target
    target_reports = {}

    for file in os.listdir('.'):
        if file.startswith('scan_report_') and file.endswith('.html'):
            target_key = None
            if 'xvwa' in file:
                target_key = 'xvwa'
            elif 'testphp' in file:
                target_key = 'testphp'
            elif 'testasp' in file:
                target_key = 'testasp'

            if target_key:
                mtime = os.path.getmtime(file)
                if target_key not in target_reports or mtime > target_reports[target_key][1]:
                    target_reports[target_key] = (file, mtime)

    if not target_reports:
        print("No scan reports found!")
        return

    # Parse reports
    reports = []
    for target_key, (filepath, _) in target_reports.items():
        print(f"Parsing {filepath}...")
        report = parse_html_report(filepath)
        reports.append(report)

    # Create consolidated report
    output_file = f"multi_target_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html"
    create_html_report(reports, output_file)

    print(f"\n✓ Multi-target report created: {output_file}")
    print(f"\n=== SUMMARY ===")
    print(f"Targets scanned: {len(reports)}")
    total_vulns = sum(r['total'] for r in reports)
    print(f"Total vulnerabilities: {total_vulns}")
    print(f"  - Critical: {sum(r['critical'] for r in reports)}")
    print(f"  - High: {sum(r['high'] for r in reports)}")
    print(f"  - Medium: {sum(r['medium'] for r in reports)}")
    print(f"  - Low: {sum(r['low'] for r in reports)}")

    print(f"\nPer-target results:")
    for report in reports:
        print(f"  {report['target']}: {report['total']} vulnerabilities")

if __name__ == '__main__':
    main()
