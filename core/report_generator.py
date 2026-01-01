"""
Unified report generator for all output formats
"""

import json
import datetime
import html
from typing import List, Dict, Any
from core.logger import get_logger

logger = get_logger(__name__)


def _escape_html_sequences(s):
    """Common HTML escape sequences for script safety"""
    return s.replace('</', '<\\/').replace('<!--', '<\\!--').replace('-->', '--\\>')

def safe_json_for_html(data):
    """Safely embed JSON in HTML <script> tags"""
    return _escape_html_sequences(json.dumps(data, default=str, ensure_ascii=False))

def safe_js_string(s):
    """Safely escape a string for use in JavaScript string literals"""
    if s is None:
        return ''
    s = str(s)
    for old, new in [('\\', '\\\\'), ("'", "\\'"), ('"', '\\"'), ('`', '\\`'),
                     ('\n', '\\n'), ('\r', '\\r'), ('<', '&lt;'), ('>', '&gt;')]:
        s = s.replace(old, new)
    return s


class ReportGenerator:
    """Generates scan reports in various formats"""

    def __init__(self):
        """Initialize report generator"""
        self.supported_formats = ['html', 'html-advanced', 'json', 'xml', 'txt']

    def generate(self, results: List[Dict[str, Any]], output_file: str,
                 format: str = 'html', scan_info: Dict[str, Any] = None) -> bool:
        """
        Generate report in specified format

        Args:
            results: List of scan results
            output_file: Output file path
            format: Report format (html, json, xml, txt)
            scan_info: Additional scan information

        Returns:
            True if successful, False otherwise
        """
        format = format.lower()

        if format not in self.supported_formats:
            logger.error(f"Unsupported format: {format}")
            return False

        try:
            if format == 'html':
                return self._generate_html(results, output_file, scan_info, simple=True)
            elif format == 'html-advanced':
                return self._generate_html(results, output_file, scan_info, simple=False)
            elif format == 'json':
                return self._generate_json(results, output_file, scan_info)
            elif format == 'xml':
                return self._generate_xml(results, output_file, scan_info)
            elif format == 'txt':
                return self._generate_txt(results, output_file, scan_info)
        except Exception as e:
            logger.error(f"Error generating {format} report: {e}")
            return False

    def _generate_json(self, results: List[Dict[str, Any]], output_file: str,
                      scan_info: Dict[str, Any] = None) -> bool:
        """Generate JSON report"""
        report_data = {
            'scan_info': scan_info or {},
            'generated_at': datetime.datetime.now().isoformat(),
            'total_results': len(results),
            'vulnerabilities': sum(1 for r in results if r.get('vulnerability')),
            'results': results
        }

        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(report_data, f, indent=2, ensure_ascii=False)

        logger.info(f"JSON report saved to {output_file}")
        return True

    def _generate_txt(self, results: List[Dict[str, Any]], output_file: str,
                     scan_info: Dict[str, Any] = None) -> bool:
        """Generate detailed plain text report matching HTML format"""
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write("╔" + "═"*78 + "╗\n")
            f.write("║" + " "*20 + "VULNERABILITY SCAN REPORT" + " "*33 + "║\n")
            f.write("╚" + "═"*78 + "╝\n\n")

            if scan_info:
                f.write("┌─ Scan Information ─────────────────────────────────────────────────────────┐\n")
                f.write(f"│ Date: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S'):<71}│\n")
                if scan_info.get('targets'):
                    targets_str = ', '.join(scan_info['targets'][:3])
                    if len(scan_info['targets']) > 3:
                        targets_str += f" (+{len(scan_info['targets'])-3} more)"
                    f.write(f"│ Targets: {targets_str:<68}│\n")
                if scan_info.get('duration'):
                    f.write(f"│ Duration: {scan_info['duration']:.2f}s{' '*65}│\n")
                f.write("└───────────────────────────────────────────────────────────────────────────────┘\n\n")

            # Statistics Summary
            # Include vulnerabilities AND recon/info findings
            vulnerabilities = [r for r in results if r.get('vulnerability') or
                              r.get('type') == 'recon' or r.get('severity', '').lower() == 'info']
            severity_counts = {
                'Critical': len([r for r in vulnerabilities if r.get('severity') == 'Critical']),
                'High': len([r for r in vulnerabilities if r.get('severity') == 'High']),
                'Medium': len([r for r in vulnerabilities if r.get('severity') == 'Medium']),
                'Low': len([r for r in vulnerabilities if r.get('severity') == 'Low']),
                'Info': len([r for r in vulnerabilities if r.get('severity') == 'Info']),
            }

            f.write("┌─ Summary ──────────────────────────────────────────────────────────────────────┐\n")
            f.write(f"│  [CRITICAL] {severity_counts['Critical']:<5}  [HIGH] {severity_counts['High']:<5}  [MEDIUM] {severity_counts['Medium']:<5}  [LOW] {severity_counts['Low']:<5}  [INFO] {severity_counts['Info']:<5}│\n")
            f.write(f"│  Total Vulnerabilities: {len(vulnerabilities):<53}│\n")
            f.write("└───────────────────────────────────────────────────────────────────────────────┘\n\n")

            # Detailed findings by severity
            severity_order = ['Critical', 'High', 'Medium', 'Low', 'Info']
            severity_markers = {
                'Critical': '🔴',
                'High': '🟠',
                'Medium': '🟡',
                'Low': '🟢',
                'Info': '🔵'
            }

            for severity in severity_order:
                severity_results = [r for r in vulnerabilities if r.get('severity') == severity]
                if severity_results:
                    marker = severity_markers.get(severity, '•')
                    f.write(f"\n{'='*80}\n")
                    f.write(f"{marker} {severity.upper()} SEVERITY ({len(severity_results)} findings)\n")
                    f.write(f"{'='*80}\n")

                    for i, result in enumerate(severity_results, 1):
                        module_name = result.get('module', result.get('type', 'Unknown'))
                        f.write(f"\n┌─ [{i}] {module_name} {'─'*(60-len(module_name)-len(str(i)))}┐\n")

                        # URL
                        url = result.get('url', 'N/A')
                        f.write(f"│ URL: {url}\n")

                        # Method and Test command
                        method = result.get('method', 'GET').upper()
                        f.write(f"│ Method: {method}\n")

                        # Parameter and Payload
                        if result.get('parameter'):
                            f.write(f"│ Parameter: {result.get('parameter')}\n")
                        if result.get('payload'):
                            payload = result.get('payload')
                            if len(payload) > 70:
                                f.write(f"│ Payload: {payload[:70]}...\n")
                            else:
                                f.write(f"│ Payload: {payload}\n")

                        # Confidence
                        if result.get('confidence'):
                            conf = float(result.get('confidence', 0)) * 100
                            f.write(f"│ Confidence: {conf:.0f}%\n")

                        # Classification (CWE, OWASP, CVSS)
                        f.write("│\n│ ─── Classification ───\n")
                        if result.get('cwe'):
                            cwe_str = f"{result.get('cwe')}"
                            if result.get('cwe_name'):
                                cwe_str += f" - {result.get('cwe_name')}"
                            f.write(f"│ CWE: {cwe_str}\n")

                        if result.get('owasp'):
                            owasp_str = f"{result.get('owasp')}"
                            if result.get('owasp_name'):
                                owasp_str += f" - {result.get('owasp_name')}"
                            f.write(f"│ OWASP: {owasp_str}\n")

                        if result.get('cvss'):
                            cvss_str = f"{result.get('cvss')}"
                            if result.get('cvss_vector'):
                                cvss_str += f" ({result.get('cvss_vector')})"
                            f.write(f"│ CVSS: {cvss_str}\n")

                        # Evidence (CRITICAL - always show)
                        if result.get('evidence'):
                            f.write("│\n│ ─── Evidence (Proof) ───\n")
                            evidence = result.get('evidence')
                            # Wrap evidence to fit console
                            evidence_lines = self._wrap_text(evidence, 75)
                            for line in evidence_lines:
                                f.write(f"│ {line}\n")
                        else:
                            f.write("│\n│ ─── Evidence ───\n")
                            f.write("│ [!] No evidence captured - manual verification required\n")

                        # Description
                        if result.get('description'):
                            f.write("│\n│ ─── Description ───\n")
                            desc_lines = self._wrap_text(result.get('description'), 75)
                            for line in desc_lines:
                                f.write(f"│ {line}\n")

                        # Reproduction Commands
                        f.write("│\n│ ─── Reproduction ───\n")
                        if method == 'GET' and result.get('parameter') and result.get('payload'):
                            param = result.get('parameter')
                            payload = result.get('payload')
                            if '?' in url:
                                test_url = f"{url}&{param}={payload}"
                            else:
                                test_url = f"{url}?{param}={payload}"
                            f.write(f"│ Test URL:\n│   {test_url}\n")
                            f.write(f"│\n│ curl command:\n")
                            f.write(f"│   curl '{test_url}'\n")
                        elif method == 'POST':
                            f.write(f"│ curl command:\n")
                            if result.get('parameter') and result.get('payload'):
                                param = result.get('parameter')
                                payload = result.get('payload', '').replace("'", "'\\''")
                                f.write(f"│   curl -X POST '{url}' \\\n")
                                f.write(f"│     -d '{param}={payload}'\n")
                            else:
                                f.write(f"│   curl -X POST '{url}'\n")

                        # Remediation/Solution
                        f.write("│\n│ ─── Solution / Remediation ───\n")
                        remediation = result.get('remediation', 'Review and fix according to security best practices.')
                        rem_lines = self._wrap_text(remediation, 75)
                        for line in rem_lines:
                            f.write(f"│ {line}\n")

                        # HTTP Request
                        if result.get('request'):
                            f.write("│\n│ ─── HTTP Request ───\n")
                            request_text = result.get('request', '')[:1000]
                            for line in request_text.split('\n')[:15]:
                                f.write(f"│ {line[:75]}\n")
                            if len(request_text) > 1000:
                                f.write("│ ... (truncated)\n")

                        # HTTP Response
                        if result.get('response'):
                            f.write("│\n│ ─── HTTP Response (relevant part) ───\n")
                            response_text = result.get('response', '')[:1500]
                            for line in response_text.split('\n')[:20]:
                                f.write(f"│ {line[:75]}\n")
                            if len(response_text) > 1500:
                                f.write("│ ... (truncated)\n")

                        f.write(f"└{'─'*79}┘\n")

            # End of report
            f.write(f"\n{'='*80}\n")
            f.write(f" END OF REPORT - {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"{'='*80}\n")

        logger.info(f"TXT report saved to {output_file}")
        return True

    def _wrap_text(self, text: str, width: int) -> List[str]:
        """Wrap text to fit within specified width"""
        import textwrap
        return textwrap.wrap(text.replace('\n', ' '), width=width) or [""]

    def _generate_xml(self, results: List[Dict[str, Any]], output_file: str,
                     scan_info: Dict[str, Any] = None) -> bool:
        """Generate XML report"""
        import xml.etree.ElementTree as ET

        root = ET.Element('scan_report')

        # Metadata
        metadata = ET.SubElement(root, 'metadata')
        ET.SubElement(metadata, 'generated_at').text = datetime.datetime.now().isoformat()
        ET.SubElement(metadata, 'total_results').text = str(len(results))
        ET.SubElement(metadata, 'vulnerabilities').text = str(sum(1 for r in results if r.get('vulnerability')))

        # Scan info
        if scan_info:
            info_elem = ET.SubElement(root, 'scan_info')
            for key, value in scan_info.items():
                if isinstance(value, (str, int, float, bool)):
                    ET.SubElement(info_elem, key).text = str(value)

        # Results
        results_elem = ET.SubElement(root, 'results')
        for result in results:
            result_elem = ET.SubElement(results_elem, 'result')
            for key, value in result.items():
                if isinstance(value, (str, int, float, bool)):
                    elem = ET.SubElement(result_elem, key)
                    elem.text = str(value)

        # Write to file
        tree = ET.ElementTree(root)
        tree.write(output_file, encoding='utf-8', xml_declaration=True)

        logger.info(f"XML report saved to {output_file}")
        return True

    def _generate_html(self, results: List[Dict[str, Any]], output_file: str,
                      scan_info: Dict[str, Any] = None, simple: bool = False) -> bool:
        """Generate HTML report - Nessus-style design

        Args:
            results: Scan results
            output_file: Output file path
            scan_info: Scan information
            simple: True for simple summary, False for full detailed report (default)
        """
        from urllib.parse import urlparse

        # Check report_mode from scan_info
        report_mode = scan_info.get('report_mode', 'full') if scan_info else 'full'
        simple = (report_mode == 'simple')

        if simple:
            return self._generate_html_simple(results, output_file, scan_info)

        # FULL detailed HTML report (default)
        raw_vulns = [r for r in results if r.get('vulnerability') or
                     r.get('type') == 'recon' or r.get('severity', '').lower() == 'info']
        vulnerabilities = self._preprocess_findings(raw_vulns)

        # Count by severity (case-insensitive)
        severity_counts = {
            'Critical': len([r for r in vulnerabilities if r.get('severity', '').lower() == 'critical']),
            'High': len([r for r in vulnerabilities if r.get('severity', '').lower() == 'high']),
            'Medium': len([r for r in vulnerabilities if r.get('severity', '').lower() == 'medium']),
            'Low': len([r for r in vulnerabilities if r.get('severity', '').lower() == 'low']),
            'Info': len([r for r in vulnerabilities if r.get('severity', '').lower() == 'info']),
        }

        # Group vulnerabilities by host
        hosts_data = {}
        for vuln in vulnerabilities:
            url = vuln.get('url', 'Unknown')
            try:
                parsed = urlparse(url)
                host = parsed.netloc or url
            except:
                host = url

            if host not in hosts_data:
                hosts_data[host] = {'vulns': [], 'counts': {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0}}
            hosts_data[host]['vulns'].append(vuln)
            sev = vuln.get('severity', 'info').lower()
            if sev in hosts_data[host]['counts']:
                hosts_data[host]['counts'][sev] += 1

        total_vulns = len(vulnerabilities)
        total_hosts = len(hosts_data)

        html_content = f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Dominator Scan Report</title>
    <style>
        * {{ box-sizing: border-box; margin: 0; padding: 0; }}
        body {{ font-family: 'Segoe UI', Arial, sans-serif; background: #1a1a2e; color: #eee; min-height: 100vh; }}
        .header {{ background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%); padding: 20px 30px; border-bottom: 3px solid #e94560; }}
        .header h1 {{ color: #e94560; font-size: 28px; font-weight: 600; }}
        .header .subtitle {{ color: #888; font-size: 14px; margin-top: 5px; }}
        .container {{ display: flex; min-height: calc(100vh - 80px); }}
        .sidebar {{ width: 280px; background: #16213e; padding: 20px; border-right: 1px solid #333; }}
        .main {{ flex: 1; padding: 20px 30px; overflow-y: auto; }}

        /* Summary Cards */
        .summary-row {{ display: flex; gap: 0; margin-bottom: 25px; }}
        .summary-card {{ flex: 1; padding: 20px 15px; text-align: center; color: white; }}
        .summary-card h2 {{ font-size: 42px; font-weight: 300; margin-bottom: 5px; }}
        .summary-card p {{ font-size: 12px; text-transform: uppercase; letter-spacing: 1px; }}
        .summary-card.critical {{ background: #9b2335; }}
        .summary-card.high {{ background: #d35400; }}
        .summary-card.medium {{ background: #c9a227; color: #333; }}
        .summary-card.low {{ background: #27ae60; }}
        .summary-card.info {{ background: #2980b9; }}

        /* Tabs */
        .tabs {{ display: flex; gap: 5px; margin-bottom: 20px; }}
        .tab {{ padding: 10px 20px; background: #2a2a4a; color: #aaa; border: none; cursor: pointer; border-radius: 5px 5px 0 0; font-size: 14px; }}
        .tab.active {{ background: #e94560; color: white; }}
        .tab:hover {{ background: #3a3a5a; }}
        .tab.active:hover {{ background: #e94560; }}
        .tab-badge {{ background: rgba(255,255,255,0.2); padding: 2px 8px; border-radius: 10px; margin-left: 8px; font-size: 12px; }}

        /* Host List with Stacked Bars */
        .host-item {{ background: #1e1e3f; margin-bottom: 10px; border-radius: 5px; overflow: hidden; cursor: pointer; }}
        .host-item:hover {{ background: #2a2a4a; }}
        .host-header {{ display: flex; align-items: center; padding: 12px 15px; }}
        .host-name {{ flex: 1; font-weight: 500; color: #fff; }}
        .host-bar {{ display: flex; height: 20px; flex: 2; border-radius: 3px; overflow: hidden; }}
        .bar-segment {{ height: 100%; display: flex; align-items: center; justify-content: center; font-size: 11px; font-weight: bold; color: white; min-width: 25px; }}
        .bar-critical {{ background: #9b2335; }}
        .bar-high {{ background: #d35400; }}
        .bar-medium {{ background: #c9a227; color: #333; }}
        .bar-low {{ background: #27ae60; }}
        .bar-info {{ background: #2980b9; }}

        /* Vulnerability Table */
        .vuln-table {{ width: 100%; border-collapse: collapse; }}
        .vuln-table th {{ background: #2a2a4a; padding: 12px 15px; text-align: left; font-weight: 500; color: #aaa; font-size: 12px; text-transform: uppercase; }}
        .vuln-table td {{ padding: 12px 15px; border-bottom: 1px solid #333; }}
        .vuln-table tr:hover {{ background: #2a2a4a; }}

        /* Severity Badges */
        .sev-badge {{ display: inline-block; padding: 4px 12px; border-radius: 3px; font-size: 11px; font-weight: bold; text-transform: uppercase; }}
        .sev-critical {{ background: #9b2335; color: white; }}
        .sev-high {{ background: #d35400; color: white; }}
        .sev-medium {{ background: #c9a227; color: #333; }}
        .sev-low {{ background: #27ae60; color: white; }}
        .sev-info {{ background: #2980b9; color: white; }}

        /* Sidebar Stats */
        .sidebar-section {{ margin-bottom: 25px; }}
        .sidebar-title {{ color: #888; font-size: 12px; text-transform: uppercase; margin-bottom: 10px; letter-spacing: 1px; }}
        .stat-row {{ display: flex; justify-content: space-between; padding: 8px 0; border-bottom: 1px solid #333; }}
        .stat-label {{ color: #aaa; }}
        .stat-value {{ color: #fff; font-weight: 500; }}

        /* Pie Chart - Fixed aspect ratio for perfect circle */
        .pie-container {{ width: 150px; height: 150px; margin: 20px auto; position: relative; aspect-ratio: 1; }}
        .pie-chart {{ width: 150px; height: 150px; border-radius: 50%; cursor: pointer; }}
        .pie-legend {{ margin-top: 15px; }}
        .legend-item {{ display: flex; align-items: center; margin-bottom: 8px; font-size: 13px; }}
        .legend-dot {{ width: 12px; height: 12px; border-radius: 50%; margin-right: 8px; }}

        /* Controls */
        .controls {{ display: flex; justify-content: space-between; align-items: center; margin-bottom: 20px; }}
        .control-group {{ display: flex; gap: 10px; align-items: center; }}
        .btn {{ padding: 8px 16px; border: none; border-radius: 4px; cursor: pointer; font-size: 13px; }}
        .btn-primary {{ background: #e94560; color: white; }}
        .btn-secondary {{ background: #2a2a4a; color: #aaa; }}
        .btn:hover {{ opacity: 0.9; }}
        select {{ padding: 8px 12px; background: #2a2a4a; border: 1px solid #444; color: #fff; border-radius: 4px; }}

        /* Expandable Details */
        .vuln-details {{ max-height: 0; overflow: hidden; background: #1a1a2e; padding: 0 20px; border-left: 3px solid #e94560; margin: 10px 0; transition: max-height 0.3s ease, padding 0.3s ease; }}
        .vuln-details.show {{ max-height: none; overflow: visible; padding: 15px 20px; }}
        @media print {{ .vuln-details {{ max-height: none !important; overflow: visible !important; padding: 15px 20px !important; }} }}
        .detail-grid {{ display: grid; grid-template-columns: repeat(2, 1fr); gap: 15px; }}
        .detail-item label {{ display: block; color: #888; font-size: 11px; text-transform: uppercase; margin-bottom: 3px; }}
        .detail-item span {{ color: #fff; }}
        .evidence-box {{ background: #0d0d1a; padding: 15px; border-radius: 5px; font-family: 'Consolas', monospace; font-size: 12px; margin-top: 15px; overflow-x: auto; white-space: pre-wrap; word-break: break-all; }}
        .clickable {{ cursor: pointer; }}
        .clickable:hover {{ color: #e94560; }}

        /* Host view / Vuln view toggle */
        .view-content {{ display: none; }}
        .view-content.active {{ display: block; }}

        /* Host details panel */
        .host-details-panel {{ background: #1e1e3f; border-radius: 5px; padding: 15px; margin-bottom: 20px; }}
        .host-vuln-list {{ max-height: 500px; overflow-y: auto; }}
    </style>
</head>
<body>
    <div class="header">
        <h1>DOMINATOR</h1>
        <div class="subtitle">Vulnerability Scan Report - {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</div>
    </div>

    <div class="container">
        <div class="sidebar">
            <div class="sidebar-section">
                <div class="sidebar-title">Scan Details</div>
                <div class="stat-row"><span class="stat-label">Total Hosts</span><span class="stat-value">{total_hosts}</span></div>
                <div class="stat-row"><span class="stat-label">Vulnerabilities</span><span class="stat-value">{total_vulns}</span></div>
                <div class="stat-row"><span class="stat-label">Generated</span><span class="stat-value">{datetime.datetime.now().strftime('%H:%M')}</span></div>
            </div>

            <div class="sidebar-section">
                <div class="sidebar-title">Vulnerabilities</div>
                <div class="pie-container">
                    <canvas id="pieChart" class="pie-chart"></canvas>
                </div>
                <div class="pie-legend">
                    <div class="legend-item"><span class="legend-dot" style="background:#9b2335"></span>Critical ({severity_counts['Critical']})</div>
                    <div class="legend-item"><span class="legend-dot" style="background:#d35400"></span>High ({severity_counts['High']})</div>
                    <div class="legend-item"><span class="legend-dot" style="background:#c9a227"></span>Medium ({severity_counts['Medium']})</div>
                    <div class="legend-item"><span class="legend-dot" style="background:#27ae60"></span>Low ({severity_counts['Low']})</div>
                    <div class="legend-item"><span class="legend-dot" style="background:#2980b9"></span>Info ({severity_counts['Info']})</div>
                </div>
            </div>
        </div>

        <div class="main">
            <!-- Summary Cards -->
            <div class="summary-row">
                <div class="summary-card critical"><h2>{severity_counts['Critical']}</h2><p>Critical</p></div>
                <div class="summary-card high"><h2>{severity_counts['High']}</h2><p>High</p></div>
                <div class="summary-card medium"><h2>{severity_counts['Medium']}</h2><p>Medium</p></div>
                <div class="summary-card low"><h2>{severity_counts['Low']}</h2><p>Low</p></div>
                <div class="summary-card info"><h2>{severity_counts['Info']}</h2><p>Info</p></div>
            </div>

            <!-- Tabs -->
            <div class="tabs">
                <button class="tab active" onclick="showView('hosts')" id="tab-hosts">Hosts<span class="tab-badge">{total_hosts}</span></button>
                <button class="tab" onclick="showView('vulns')" id="tab-vulns">Vulnerabilities<span class="tab-badge">{total_vulns}</span></button>
            </div>

            <!-- Active Filter Indicator -->
            <div id="activeFilter" style="display:none;margin-bottom:15px;padding:10px 15px;background:#2a2a4a;border-radius:5px;display:none;align-items:center;justify-content:space-between;">
                <span>Filtering by: <strong id="filterName" style="color:#e94560;"></strong></span>
                <button onclick="clearFilter()" style="background:none;border:none;color:#e94560;cursor:pointer;font-size:18px;padding:0 5px;">&times;</button>
            </div>

            <!-- Controls -->
            <div class="controls">
                <div class="control-group">
                    <select id="severityFilter" onchange="filterBySeverity()">
                        <option value="all">All Severities</option>
                        <option value="critical">Critical</option>
                        <option value="high">High</option>
                        <option value="medium">Medium</option>
                        <option value="low">Low</option>
                        <option value="info">Info</option>
                    </select>
                </div>
                <div class="control-group">
                    <button class="btn btn-secondary" onclick="collapseAll()">Collapse All</button>
                    <button class="btn btn-secondary" onclick="expandAll()">Expand All</button>
                </div>
            </div>

            <!-- HOSTS VIEW -->
            <div id="hostsView" class="view-content active">
"""

        # Generate host list with stacked bars
        for host, data in sorted(hosts_data.items(), key=lambda x: sum(x[1]['counts'].values()), reverse=True):
            counts = data['counts']
            total = sum(counts.values())
            if total == 0:
                continue

            html_content += f"""
                <div class="host-item" onclick="toggleHostDetails('{html.escape(host)}')">
                    <div class="host-header">
                        <span class="host-name">{html.escape(host)}</span>
                        <div class="host-bar">
"""
            # Add bar segments
            for sev, color in [('critical', 'critical'), ('high', 'high'), ('medium', 'medium'), ('low', 'low'), ('info', 'info')]:
                if counts[sev] > 0:
                    width = (counts[sev] / total) * 100
                    html_content += f'                            <div class="bar-segment bar-{color}" style="width:{width}%">{counts[sev]}</div>\n'

            html_content += f"""
                        </div>
                    </div>
                    <div id="host-{html.escape(host).replace('.', '-').replace(':', '-')}" class="vuln-details">
                        <table class="vuln-table">
                            <thead><tr><th>Severity</th><th>CVSS</th><th>Module</th><th>Name</th></tr></thead>
                            <tbody>
"""
            # Add vulnerabilities for this host
            for vuln in sorted(data['vulns'], key=lambda x: ['critical', 'high', 'medium', 'low', 'info'].index(x.get('severity', 'info').lower())):
                sev = vuln.get('severity', 'Info').lower()
                cvss = vuln.get('cvss', 'N/A')
                module = html.escape(vuln.get('module', vuln.get('type', 'Unknown')))
                name = html.escape(vuln.get('type', vuln.get('module', 'Unknown')).replace('_', ' ').title())

                html_content += f"""
                                <tr class="clickable" onclick="event.stopPropagation(); toggleVulnDetail('vuln-{id(vuln)}')" data-severity="{sev}">
                                    <td><span class="sev-badge sev-{sev}">{sev.upper()}</span></td>
                                    <td>{cvss}</td>
                                    <td>{module}</td>
                                    <td>{name}</td>
                                </tr>
                                <tr id="vuln-{id(vuln)}" class="vuln-detail-row" style="display:none;">
                                    <td colspan="4">
                                        <div class="detail-grid">
                                            <div class="detail-item"><label>URL</label><span>{html.escape(vuln.get('url', 'N/A'))}</span></div>
                                            <div class="detail-item"><label>Method</label><span style="background:#e94560;color:white;padding:2px 8px;border-radius:3px;">{html.escape(str(vuln.get('method', 'GET')))}</span></div>
                                            <div class="detail-item"><label>Parameter</label><span style="color:#e94560;font-weight:bold;">{html.escape(str(vuln.get('parameter', 'N/A')))}</span></div>
                                            <div class="detail-item"><label>Confidence</label><span>{float(vuln.get('confidence', 0.8))*100:.0f}%</span></div>
                                            <div class="detail-item"><label>CWE</label><span>{html.escape(str(vuln.get('cwe', 'N/A')))}</span></div>
                                            <div class="detail-item"><label>OWASP</label><span>{html.escape(str(vuln.get('owasp', 'N/A')))}</span></div>
                                        </div>
                                        <div style="margin-top:10px;"><label style="color:#888;font-size:11px;">PAYLOAD</label>
                                            <div style="background:#1a1a2e;padding:10px;border-radius:4px;margin-top:5px;font-family:monospace;color:#e94560;word-break:break-all;">{html.escape(str(vuln.get('payload', 'N/A'))[:500])}</div>
                                        </div>
                                        <div style="margin-top:10px;"><label style="color:#888;font-size:11px;">EVIDENCE / PROOF</label>
                                            <div class="evidence-box">{html.escape(str(vuln.get('evidence', vuln.get('description', 'No evidence')))[:1500])}</div>
                                        </div>
                                        <div style="margin-top:10px;"><label style="color:#888;font-size:11px;">SOLUTION / REMEDIATION</label>
                                            <div style="background:#1a3a1a;padding:10px;border-radius:4px;margin-top:5px;color:#90EE90;border-left:3px solid #27ae60;">{html.escape(str(vuln.get('remediation', 'Review and fix according to security best practices.')))}</div>
                                        </div>
                                        <details style="margin-top:10px;" onclick="event.stopPropagation()">
                                            <summary style="cursor:pointer;color:#e94560;font-weight:bold;padding:5px;background:#2a2a4a;border-radius:3px;">🔧 Reproduce with cURL</summary>
                                            <div style="margin-top:5px;">
                                                <div class="evidence-box" id="curl-{id(vuln)}">{html.escape(self._generate_curl_command(vuln.get('url', ''), vuln.get('method', 'GET'), vuln.get('parameter', ''), vuln.get('payload', '')))}</div>
                                                <button onclick="event.stopPropagation(); copyCurl('curl-{id(vuln)}')" class="btn btn-secondary" style="font-size:11px;margin-top:5px;">📋 Copy cURL</button>
                                            </div>
                                        </details>
                                        <details style="margin-top:10px;" onclick="event.stopPropagation()">
                                            <summary style="cursor:pointer;color:#e94560;font-weight:bold;padding:5px;background:#2a2a4a;border-radius:3px;">📤 HTTP Request</summary>
                                            <div class="evidence-box" style="margin-top:5px;">{html.escape(str(vuln.get('request', 'No request captured'))[:2000])}</div>
                                        </details>
                                        <details style="margin-top:10px;" onclick="event.stopPropagation()">
                                            <summary style="cursor:pointer;color:#e94560;font-weight:bold;padding:5px;background:#2a2a4a;border-radius:3px;">📥 HTTP Response</summary>
                                            <div class="evidence-box" style="margin-top:5px;max-height:300px;overflow-y:auto;">{html.escape(str(vuln.get('response', 'No response captured'))[:3000])}</div>
                                        </details>
                                        <div style="margin-top:10px;display:flex;gap:10px;">
                                            <button onclick="event.stopPropagation(); copyToClipboard('{safe_js_string(vuln.get('url', ''))}')" class="btn btn-secondary" style="font-size:11px;">📋 Copy URL</button>
                                            <button onclick="event.stopPropagation(); copyToClipboard('{safe_js_string(vuln.get('payload', ''))}')" class="btn btn-secondary" style="font-size:11px;">📋 Copy Payload</button>
                                            <button onclick="event.stopPropagation(); copyFinding('{id(vuln)}')" class="btn btn-primary" style="font-size:11px;">📋 Copy Full Finding</button>
                                        </div>
                                        <script>window.findingData_{id(vuln)} = {safe_json_for_html({k:str(v)[:500] if isinstance(v,str) else v for k,v in vuln.items() if k not in ['response']})};</script>
                                    </td>
                                </tr>
"""

            html_content += """
                            </tbody>
                        </table>
                    </div>
                </div>
"""

        html_content += """
            </div>

            <!-- VULNERABILITIES VIEW -->
            <div id="vulnsView" class="view-content">
                <table class="vuln-table">
                    <thead><tr><th>Severity</th><th>CVSS</th><th>Host</th><th>Module</th><th>Name</th></tr></thead>
                    <tbody>
"""

        # Add all vulnerabilities sorted by severity
        for vuln in sorted(vulnerabilities, key=lambda x: ['critical', 'high', 'medium', 'low', 'info'].index(x.get('severity', 'info').lower())):
            sev = vuln.get('severity', 'Info').lower()
            cvss = vuln.get('cvss', 'N/A')
            url = vuln.get('url', 'Unknown')
            try:
                parsed = urlparse(url)
                host = parsed.netloc or url
            except:
                host = url
            module = html.escape(vuln.get('module', vuln.get('type', 'Unknown')))
            name = html.escape(vuln.get('type', vuln.get('module', 'Unknown')).replace('_', ' ').title())

            html_content += f"""
                        <tr class="clickable" onclick="toggleVulnDetail('vuln-all-{id(vuln)}')" data-severity="{sev}">
                            <td><span class="sev-badge sev-{sev}">{sev.upper()}</span></td>
                            <td>{cvss}</td>
                            <td>{html.escape(host)}</td>
                            <td>{module}</td>
                            <td>{name}</td>
                        </tr>
                        <tr id="vuln-all-{id(vuln)}" class="vuln-detail-row" style="display:none;">
                            <td colspan="5">
                                <div class="detail-grid">
                                    <div class="detail-item"><label>Full URL</label><span>{html.escape(vuln.get('url', 'N/A'))}</span></div>
                                    <div class="detail-item"><label>Method</label><span style="background:#e94560;color:white;padding:2px 8px;border-radius:3px;">{html.escape(str(vuln.get('method', 'GET')))}</span></div>
                                    <div class="detail-item"><label>Parameter</label><span style="color:#e94560;font-weight:bold;">{html.escape(str(vuln.get('parameter', 'N/A')))}</span></div>
                                    <div class="detail-item"><label>Confidence</label><span>{float(vuln.get('confidence', 0.8))*100:.0f}%</span></div>
                                    <div class="detail-item"><label>CWE</label><span>{html.escape(str(vuln.get('cwe', 'N/A')))}</span></div>
                                    <div class="detail-item"><label>OWASP</label><span>{html.escape(str(vuln.get('owasp', 'N/A')))}</span></div>
                                </div>
                                <div style="margin-top:10px;"><label style="color:#888;font-size:11px;">PAYLOAD</label>
                                    <div style="background:#1a1a2e;padding:10px;border-radius:4px;margin-top:5px;font-family:monospace;color:#e94560;word-break:break-all;">{html.escape(str(vuln.get('payload', 'N/A'))[:500])}</div>
                                </div>
                                <div style="margin-top:10px;"><label style="color:#888;font-size:11px;">EVIDENCE / PROOF</label>
                                    <div class="evidence-box">{html.escape(str(vuln.get('evidence', vuln.get('description', 'No evidence')))[:1500])}</div>
                                </div>
                                <div style="margin-top:10px;"><label style="color:#888;font-size:11px;">SOLUTION / REMEDIATION</label>
                                    <div style="background:#1a3a1a;padding:10px;border-radius:4px;margin-top:5px;color:#90EE90;border-left:3px solid #27ae60;">{html.escape(str(vuln.get('remediation', 'Review and fix according to security best practices.')))}</div>
                                </div>
                                <details style="margin-top:10px;" onclick="event.stopPropagation()">
                                    <summary style="cursor:pointer;color:#e94560;font-weight:bold;padding:5px;background:#2a2a4a;border-radius:3px;">🔧 Reproduce with cURL</summary>
                                    <div style="margin-top:5px;">
                                        <div class="evidence-box" id="curl-all-{id(vuln)}">{html.escape(self._generate_curl_command(vuln.get('url', ''), vuln.get('method', 'GET'), vuln.get('parameter', ''), vuln.get('payload', '')))}</div>
                                        <button onclick="event.stopPropagation(); copyCurl('curl-all-{id(vuln)}')" class="btn btn-secondary" style="font-size:11px;margin-top:5px;">📋 Copy cURL</button>
                                    </div>
                                </details>
                                <details style="margin-top:10px;" onclick="event.stopPropagation()">
                                    <summary style="cursor:pointer;color:#e94560;font-weight:bold;padding:5px;background:#2a2a4a;border-radius:3px;">📤 HTTP Request</summary>
                                    <div class="evidence-box" style="margin-top:5px;">{html.escape(str(vuln.get('request', 'No request captured'))[:2000])}</div>
                                </details>
                                <details style="margin-top:10px;" onclick="event.stopPropagation()">
                                    <summary style="cursor:pointer;color:#e94560;font-weight:bold;padding:5px;background:#2a2a4a;border-radius:3px;">📥 HTTP Response</summary>
                                    <div class="evidence-box" style="margin-top:5px;max-height:300px;overflow-y:auto;">{html.escape(str(vuln.get('response', 'No response captured'))[:3000])}</div>
                                </details>
                                <div style="margin-top:10px;display:flex;gap:10px;">
                                    <button onclick="event.stopPropagation(); copyToClipboard('{safe_js_string(vuln.get('url', ''))}')" class="btn btn-secondary" style="font-size:11px;">📋 Copy URL</button>
                                    <button onclick="event.stopPropagation(); copyToClipboard('{safe_js_string(vuln.get('payload', ''))}')" class="btn btn-secondary" style="font-size:11px;">📋 Copy Payload</button>
                                    <button onclick="event.stopPropagation(); copyFinding('all-{id(vuln)}')" class="btn btn-primary" style="font-size:11px;">📋 Copy Full Finding</button>
                                </div>
                                <script>window.findingData_all_{id(vuln)} = {safe_json_for_html({k:str(v)[:500] if isinstance(v,str) else v for k,v in vuln.items() if k not in ['response']})};</script>
                            </td>
                        </tr>
"""

        html_content += f"""
                    </tbody>
                </table>
            </div>
        </div>
    </div>

    <script>
        // Pie chart data and segments stored globally for click detection
        const pieData = [{severity_counts['Critical']}, {severity_counts['High']}, {severity_counts['Medium']}, {severity_counts['Low']}, {severity_counts['Info']}];
        const pieLabels = ['critical', 'high', 'medium', 'low', 'info'];
        const pieColors = ['#9b2335', '#d35400', '#c9a227', '#27ae60', '#2980b9'];
        let pieSegments = [];

        // Draw pie chart
        function drawPieChart() {{
            const canvas = document.getElementById('pieChart');
            if (!canvas) return;

            // Set canvas dimensions explicitly for proper circle
            canvas.width = 150;
            canvas.height = 150;

            const ctx = canvas.getContext('2d');
            const total = pieData.reduce((a, b) => a + b, 0);
            if (total === 0) return;

            let startAngle = -Math.PI / 2;
            const centerX = 75;
            const centerY = 75;
            const radius = 70;
            pieSegments = [];

            pieData.forEach((value, i) => {{
                if (value === 0) return;
                const sliceAngle = (value / total) * 2 * Math.PI;
                const endAngle = startAngle + sliceAngle;

                // Store segment for click detection
                pieSegments.push({{ startAngle, endAngle, label: pieLabels[i], color: pieColors[i] }});

                ctx.beginPath();
                ctx.moveTo(centerX, centerY);
                ctx.arc(centerX, centerY, radius, startAngle, endAngle);
                ctx.fillStyle = pieColors[i];
                ctx.fill();
                startAngle = endAngle;
            }});

            // Draw center hole for donut effect
            ctx.beginPath();
            ctx.arc(centerX, centerY, radius * 0.55, 0, 2 * Math.PI);
            ctx.fillStyle = '#16213e';
            ctx.fill();

            // Add click handler
            canvas.onclick = handlePieClick;
        }}

        // Handle pie chart click
        function handlePieClick(e) {{
            const canvas = e.target;
            const rect = canvas.getBoundingClientRect();
            const x = e.clientX - rect.left - 75;
            const y = e.clientY - rect.top - 75;
            const distance = Math.sqrt(x*x + y*y);

            // Check if click is within donut (between inner and outer radius)
            if (distance < 38 || distance > 70) return;

            // Calculate angle
            let angle = Math.atan2(y, x);
            if (angle < -Math.PI/2) angle += 2 * Math.PI;

            // Find which segment was clicked
            for (const seg of pieSegments) {{
                let start = seg.startAngle;
                let end = seg.endAngle;
                if (start < -Math.PI/2) start += 2 * Math.PI;
                if (end < -Math.PI/2) end += 2 * Math.PI;

                if (angle >= start && angle < end) {{
                    filterBySeverityValue(seg.label);
                    return;
                }}
            }}
        }}

        // Filter by severity (called from pie click)
        function filterBySeverityValue(severity) {{
            document.getElementById('severityFilter').value = severity;
            filterBySeverity();
            // Show filter indicator
            document.getElementById('activeFilter').style.display = 'flex';
            document.getElementById('filterName').textContent = severity.toUpperCase();
        }}

        // Clear filter
        function clearFilter() {{
            document.getElementById('severityFilter').value = 'all';
            filterBySeverity();
            document.getElementById('activeFilter').style.display = 'none';
        }}

        // View switching
        function showView(view) {{
            document.querySelectorAll('.view-content').forEach(el => el.classList.remove('active'));
            document.querySelectorAll('.tab').forEach(el => el.classList.remove('active'));
            document.getElementById(view + 'View').classList.add('active');
            document.getElementById('tab-' + view).classList.add('active');
        }}

        // Toggle host details
        function toggleHostDetails(host) {{
            const id = 'host-' + host.replace(/\\./g, '-').replace(/:/g, '-');
            const el = document.getElementById(id);
            if (el) el.classList.toggle('show');
        }}

        // Toggle vulnerability detail
        function toggleVulnDetail(id) {{
            const el = document.getElementById(id);
            if (el) el.style.display = el.style.display === 'none' ? 'table-row' : 'none';
        }}

        // Filter by severity
        function filterBySeverity() {{
            const filter = document.getElementById('severityFilter').value;
            document.querySelectorAll('tr[data-severity]').forEach(row => {{
                if (filter === 'all' || row.dataset.severity === filter) {{
                    row.style.display = '';
                }} else {{
                    row.style.display = 'none';
                }}
            }});
        }}

        // Collapse/Expand all
        function collapseAll() {{
            document.querySelectorAll('.vuln-details').forEach(el => el.classList.remove('show'));
            document.querySelectorAll('.vuln-detail-row').forEach(el => el.style.display = 'none');
        }}

        function expandAll() {{
            document.querySelectorAll('.vuln-details').forEach(el => el.classList.add('show'));
            document.querySelectorAll('.vuln-detail-row').forEach(el => el.style.display = 'table-row');
        }}

        // Copy to clipboard function
        function copyToClipboard(text) {{
            navigator.clipboard.writeText(text).then(() => {{
                showToast('Copied to clipboard!');
            }}).catch(() => {{
                // Fallback for older browsers
                const ta = document.createElement('textarea');
                ta.value = text;
                document.body.appendChild(ta);
                ta.select();
                document.execCommand('copy');
                document.body.removeChild(ta);
                showToast('Copied to clipboard!');
            }});
        }}

        // Copy full finding as JSON
        function copyFinding(id) {{
            const dataKey = 'findingData_' + id.replace('-', '_');
            const data = window[dataKey];
            if (data) {{
                const text = JSON.stringify(data, null, 2);
                copyToClipboard(text);
            }}
        }}

        // Copy cURL command from element
        function copyCurl(elementId) {{
            const el = document.getElementById(elementId);
            if (el) {{
                copyToClipboard(el.textContent);
            }}
        }}

        // Toast notification
        function showToast(msg) {{
            const toast = document.createElement('div');
            toast.textContent = msg;
            toast.style.cssText = 'position:fixed;bottom:20px;right:20px;background:#27ae60;color:white;padding:12px 24px;border-radius:4px;z-index:9999;animation:fadeIn 0.3s';
            document.body.appendChild(toast);
            setTimeout(() => toast.remove(), 2000);
        }}

        // Initialize
        document.addEventListener('DOMContentLoaded', drawPieChart);
    </script>
    <style>@keyframes fadeIn {{ from {{ opacity: 0; }} to {{ opacity: 1; }} }}</style>
</body>
</html>
"""

        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(html_content)

        logger.info(f"HTML report saved to {output_file}")
        return True

    def _generate_html_simple(self, results: List[Dict[str, Any]], output_file: str,
                             scan_info: Dict[str, Any] = None) -> bool:
        """Generate simple summary-only HTML report"""
        # Include vulnerabilities AND recon/info findings
        vulnerabilities = [r for r in results if r.get('vulnerability') or
                          r.get('type') == 'recon' or r.get('severity', '').lower() == 'info']

        severity_counts = {
            'Critical': len([r for r in vulnerabilities if r.get('severity') == 'Critical']),
            'High': len([r for r in vulnerabilities if r.get('severity') == 'High']),
            'Medium': len([r for r in vulnerabilities if r.get('severity') == 'Medium']),
            'Low': len([r for r in vulnerabilities if r.get('severity') == 'Low']),
            'Info': len([r for r in vulnerabilities if r.get('severity') == 'Info']),
        }

        html_content = f"""<!DOCTYPE html>
<html><head><meta charset="UTF-8"><title>Scan Summary</title>
<style>body{{font-family:Arial;margin:20px;background:#f5f5f5}}
.container{{max-width:800px;margin:0 auto;background:white;padding:20px}}
.summary{{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:15px;margin:20px 0}}
.card{{padding:15px;border-radius:5px;color:white;text-align:center}}
.critical{{background:#dc3545}}.high{{background:#fd7e14}}.medium{{background:#ffc107;color:#333}}
.low{{background:#28a745}}.info{{background:#17a2b8}}</style></head><body>
<div class="container"><h1>Vulnerability Scan Summary</h1>
<p>Generated: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
<div class="summary">
<div class="card critical"><h2>{severity_counts['Critical']}</h2><p>Critical</p></div>
<div class="card high"><h2>{severity_counts['High']}</h2><p>High</p></div>
<div class="card medium"><h2>{severity_counts['Medium']}</h2><p>Medium</p></div>
<div class="card low"><h2>{severity_counts['Low']}</h2><p>Low</p></div>
<div class="card info"><h2>{severity_counts['Info']}</h2><p>Info</p></div>
</div><h3>Total: {len(vulnerabilities)} vulnerabilities found</h3>
</div></body></html>"""

        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(html_content)

        logger.info(f"Simple HTML report saved to {output_file}")
        return True

    def _generate_html_advanced(self, results: List[Dict[str, Any]], output_file: str,
                               scan_info: Dict[str, Any] = None) -> bool:
        """Generate advanced HTML report using Russian template"""
        import os

        # Load template
        template_path = os.path.join(os.path.dirname(__file__), '..', 'report', 'templates', 'html_template.html')

        try:
            with open(template_path, 'r', encoding='utf-8') as f:
                template = f.read()
        except Exception as e:
            logger.error(f"Error loading template: {e}")
            return False

        # Include vulnerabilities AND recon/info findings
        vulnerabilities = [r for r in results if r.get('vulnerability') or
                          r.get('type') == 'recon' or r.get('severity', '').lower() == 'info']

        # Count by severity (case-insensitive)
        severity_counts = {
            'Critical': len([r for r in vulnerabilities if r.get('severity', '').lower() == 'critical']),
            'High': len([r for r in vulnerabilities if r.get('severity', '').lower() == 'high']),
            'Medium': len([r for r in vulnerabilities if r.get('severity', '').lower() == 'medium']),
            'Low': len([r for r in vulnerabilities if r.get('severity', '').lower() == 'low']),
            'Info': len([r for r in vulnerabilities if r.get('severity', '').lower() == 'info']),
        }

        # Build vulnerability sections HTML
        sections_html = ""
        severity_order = ['Critical', 'High', 'Medium', 'Low', 'Info']

        for severity in severity_order:
            severity_results = [r for r in vulnerabilities if r.get('severity') == severity]
            if not severity_results:
                continue

            sections_html += f'<h3>{severity} ({len(severity_results)})</h3>\n'

            for result in severity_results:
                vuln_class = severity.lower()
                sections_html += f'<div class="vulnerability {vuln_class}">\n'
                sections_html += f'  <h3>{html.escape(result.get("module", "Unknown"))}</h3>\n'
                sections_html += f'  <div class="detail"><span class="label">URL:</span> {html.escape(result.get("url", ""))}</div>\n'

                if result.get('parameter'):
                    sections_html += f'  <div class="detail"><span class="label">Parameter:</span> {html.escape(result.get("parameter", ""))}</div>\n'
                if result.get('payload'):
                    sections_html += f'  <div class="detail"><span class="label">Payload:</span> <code>{html.escape(result.get("payload", ""))}</code></div>\n'

                sections_html += f'  <div class="detail"><span class="label">Description:</span> {html.escape(result.get("description", ""))}</div>\n'

                if result.get('evidence'):
                    sections_html += f'  <div class="detail"><span class="label">Evidence:</span></div>\n'
                    # HTML escape and convert newlines to <br> for proper display
                    evidence_text = html.escape(result.get("evidence", "")).replace('\n', '<br>')
                    sections_html += f'  <div class="evidence">{evidence_text}</div>\n'

                sections_html += '</div>\n'

        # Replace template placeholders
        html_content = template.format(
            timestamp=datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            critical_count=severity_counts['Critical'],
            high_count=severity_counts['High'],
            medium_count=severity_counts['Medium'],
            low_count=severity_counts['Low'],
            info_count=severity_counts['Info'],
            total_vulns=len(vulnerabilities),
            vulnerability_sections=sections_html
        )

        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(html_content)

        logger.info(f"Advanced HTML report saved to {output_file}")
        return True

    def _generate_http_details_section(self, result: Dict[str, Any]) -> str:
        """Generate HTTP details section with curl, request, and response"""
        from urllib.parse import urlencode, quote, urlparse

        url = result.get('url', '')
        method = result.get('method', 'GET').upper()
        parameter = result.get('parameter', '')
        payload = result.get('payload', '')

        if not url:
            return ""

        # Make URL clickable
        clickable_url = f'<a href="{html.escape(url)}" target="_blank" style="color:#667eea; text-decoration:underline;">{html.escape(url)}</a>'

        # Generate curl command
        curl_cmd = self._generate_curl_command(url, method, parameter, payload)

        # Generate HTTP request
        http_request = self._generate_http_request(url, method, parameter, payload)

        # Get response preview (from evidence or create placeholder)
        # Handle empty strings - use 'or' to fall through to next option
        # Also check 'description' and 'value' for passive scanner findings
        response_preview = (result.get('response') or result.get('evidence') or
                           result.get('description') or result.get('value') or
                           'Response data not captured')
        if len(response_preview) > 2000:
            response_preview = response_preview[:2000] + '\n\n... (truncated, showing first 2000 chars)'

        html_section = f"""
            <div class="http-details" style="margin-top:20px; padding:15px; background:#f8f9fa; border-radius:8px; border-left:4px solid #667eea;">
                <h4 style="margin-top:0; color:#667eea; font-size:16px;">🔧 Technical Details</h4>

                <div style="margin-bottom:10px;">
                    <strong>HTTP Method:</strong> <span style="background:#667eea; color:white; padding:2px 8px; border-radius:3px; font-size:12px;">{method}</span>
                </div>

                <div style="margin-bottom:10px;">
                    <strong>Target URL:</strong> {clickable_url}
                </div>

                <details style="margin-top:15px;">
                    <summary style="cursor:pointer; color:#667eea; font-weight:bold; padding:8px; background:#fff; border:1px solid #667eea; border-radius:4px; display:inline-block;">
                        📋 Show Curl Command
                    </summary>
                    <div style="margin-top:10px;">
                        <pre style="background:#2d2d2d; color:#f8f8f2; padding:15px; border-radius:5px; overflow-x:auto; font-size:13px; line-height:1.5;"><code>{html.escape(curl_cmd)}</code></pre>
                        <button onclick="navigator.clipboard.writeText(`{html.escape(curl_cmd).replace('`', '\\`')}`); this.textContent='✓ Copied!'; setTimeout(()=>this.textContent='📋 Copy to Clipboard', 2000);" style="margin-top:5px; padding:5px 10px; background:#667eea; color:white; border:none; border-radius:3px; cursor:pointer; font-size:12px;">📋 Copy to Clipboard</button>
                    </div>
                </details>

                <details style="margin-top:10px;" onclick="event.stopPropagation()">
                    <summary style="cursor:pointer; color:#667eea; font-weight:bold; padding:8px; background:#fff; border:1px solid #667eea; border-radius:4px; display:inline-block;">
                        📤 Show HTTP Request
                    </summary>
                    <div style="margin-top:10px;">
                        <pre style="background:#2d2d2d; color:#f8f8f2; padding:15px; border-radius:5px; overflow-x:auto; font-size:13px; line-height:1.5;"><code>{html.escape(http_request)}</code></pre>
                    </div>
                </details>

                <details style="margin-top:10px;" onclick="event.stopPropagation()">
                    <summary style="cursor:pointer; color:#667eea; font-weight:bold; padding:8px; background:#fff; border:1px solid #667eea; border-radius:4px; display:inline-block;">
                        📥 Show HTTP Response Preview
                    </summary>
                    <div style="margin-top:10px;">
                        <pre style="background:#2d2d2d; color:#f8f8f2; padding:15px; border-radius:5px; overflow-x:auto; max-height:400px; overflow-y:auto; font-size:13px; line-height:1.5;"><code>{html.escape(response_preview)}</code></pre>
                    </div>
                </details>
            </div>
"""

        return html_section

    def _generate_curl_command(self, url: str, method: str, parameter: str, payload: str) -> str:
        """Generate curl command for reproducing the vulnerability"""
        from urllib.parse import urlparse, parse_qs, urlencode, quote

        parsed = urlparse(url)

        if method == 'GET':
            # Build URL with parameter
            if parameter and payload:
                # Parse existing query params
                params = parse_qs(parsed.query)
                params[parameter] = [payload]

                # Rebuild URL
                new_query = urlencode(params, doseq=True)
                full_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{new_query}"
            else:
                full_url = url

            curl = f"curl -X GET '{full_url}' \\\n  -H 'User-Agent: Dominator-Scanner/1.0'"

        elif method == 'POST':
            curl = f"curl -X POST '{url}' \\\n  -H 'User-Agent: Dominator-Scanner/1.0' \\\n  -H 'Content-Type: application/x-www-form-urlencoded'"

            if parameter and payload:
                curl += f" \\\n  --data-urlencode '{parameter}={payload}'"

        else:
            curl = f"curl -X {method} '{url}' \\\n  -H 'User-Agent: Dominator-Scanner/1.0'"

        return curl

    def _generate_http_request(self, url: str, method: str, parameter: str, payload: str) -> str:
        """Generate HTTP request representation"""
        from urllib.parse import urlparse, parse_qs, urlencode

        parsed = urlparse(url)

        if method == 'GET':
            if parameter and payload:
                params = parse_qs(parsed.query)
                params[parameter] = [payload]
                query = urlencode(params, doseq=True)
                path = f"{parsed.path}?{query}"
            else:
                path = parsed.path + (f"?{parsed.query}" if parsed.query else "")

            request = f"{method} {path} HTTP/1.1\n"
            request += f"Host: {parsed.netloc}\n"
            request += "User-Agent: Dominator-Scanner/1.0\n"
            request += "Accept: */*\n"
            request += "Connection: close\n"

        elif method == 'POST':
            request = f"{method} {parsed.path} HTTP/1.1\n"
            request += f"Host: {parsed.netloc}\n"
            request += "User-Agent: Dominator-Scanner/1.0\n"
            request += "Content-Type: application/x-www-form-urlencoded\n"
            request += "Accept: */*\n"

            if parameter and payload:
                body = f"{parameter}={payload}"
                request += f"Content-Length: {len(body)}\n"
                request += "Connection: close\n\n"
                request += body
            else:
                request += "Connection: close\n"

        else:
            request = f"{method} {parsed.path} HTTP/1.1\n"
            request += f"Host: {parsed.netloc}\n"
            request += "User-Agent: Dominator-Scanner/1.0\n"
            request += "Connection: close\n"

        return request

    def _make_urls_clickable(self, text: str) -> str:
        """Convert URLs in text to clickable links while preserving HTML escaping for non-URL content"""
        import re

        # First, HTML escape the entire text to prevent XSS
        escaped_text = html.escape(text)

        # URL regex pattern - matches http:// and https:// URLs
        url_pattern = re.compile(
            r'(https?://[^\s<>"{}|\\^`\[\]]+)',
            re.IGNORECASE
        )

        # Find all URLs in the escaped text
        def make_link(match):
            url = match.group(1)
            # The URL is already HTML-escaped, but we need to unescape it for the href attribute
            # and keep it escaped for display
            import html as html_module
            url_unescaped = html_module.unescape(url)
            return f'<a href="{url_unescaped}" target="_blank" style="color:#007bff; text-decoration:underline; word-break:break-all;">{url}</a>'

        # Replace URLs with clickable links
        clickable_text = url_pattern.sub(make_link, escaped_text)

        # Convert newlines to <br> tags for proper HTML display
        clickable_text = clickable_text.replace('\n', '<br>')

        return clickable_text

    def _preprocess_findings(self, findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Preprocess findings:
        1. Filter out false positives and invalid data
        2. Group similar findings (phones, emails, etc.) into ONE finding with all locations
        3. Group security headers per URL into single finding
        4. Enhance vulnerability names
        5. Fix CVSS scores and confidence
        6. Fix "Unknown" module names
        """
        import re

        processed = []
        security_headers_by_url = {}

        def is_valid_url(url: str) -> bool:
            """Check if URL is valid (not JS code snippet)"""
            if not url or not isinstance(url, str):
                return False
            # Check for common JS patterns that indicate it's not a URL
            js_patterns = [
                r'\{.*\}',           # Contains curly braces (JS code)
                r'\(.*\)',           # Contains function calls
                r'function\s*\(',    # Function declaration
                r'\.removeChild',    # DOM manipulation
                r'\.parentNode',     # DOM manipulation
                r'\.getElementsBy',  # DOM manipulation
                r'=>',               # Arrow function
                r'\breturn\b',       # return keyword
                r'\bvar\b',          # var keyword
                r'\blet\b',          # let keyword
                r'\bconst\b',        # const keyword
                r';$',               # Ends with semicolon
            ]
            for pattern in js_patterns:
                if re.search(pattern, url):
                    return False
            # Must start with http:// or https://
            if not url.startswith(('http://', 'https://')):
                return False
            return True

        def is_false_positive(finding: Dict[str, Any]) -> bool:
            """Filter out known false positives"""
            vuln_type = finding.get('type', '').lower()
            url = finding.get('url', '')
            evidence = finding.get('evidence', '')
            description = finding.get('description', '')

            # Filter Cloudflare challenge scripts - always false positive
            if 'cdn-cgi/challenge-platform' in url:
                return True

            # Filter CSS files for secret detection
            if url.endswith('.css') and vuln_type in ['base58_key', 'aws_access_key', 'telegram_bot_token']:
                return True

            # Filter "Potential Base58 encoded key" with low evidence
            if vuln_type == 'base58_key' and 'forEachF' in str(evidence):
                return True  # This is JavaScript forEach, not a key

            # Filter generic "hardcoded_password" without actual password evidence
            if vuln_type == 'hardcoded_password':
                # Check if evidence contains actual password-like data
                if 'password' not in evidence.lower() or 'Hardcoded password found' == evidence:
                    return True

            # Filter "Telegram bot token" in challenge scripts
            if 'telegram' in vuln_type.lower() and 'challenge' in url.lower():
                return True

            # Filter base58_key false positives (JavaScript variable names)
            if vuln_type == 'base58_key':
                # Check for common false positive patterns
                value = finding.get('value', '')
                if any(fp in value.lower() for fp in ['foreach', 'function', 'return', 'coordinate', 'feature']):
                    return True

            # Filter findings with "No evidence captured" or empty evidence
            if not evidence or evidence in ['No evidence captured', 'No evidence', 'N/A', '']:
                # Only filter if it's a passive/info finding, not injection vulns or security findings
                # Keep: injection vulns, security header issues, WAF findings, info disclosure
                keep_types = ['xss', 'sqli', 'cmdi', 'ssti', 'lfi', 'rfi', 'xxe', 'ssrf',
                              'missing_security_header', 'information_disclosure', 'insecure_cookie',
                              'accessible_cookie', 'waf_detected', 'technology_detected']
                if vuln_type not in keep_types:
                    return True

            return False

        # Groups for aggregating similar passive findings
        aggregated = {
            'phone_disclosure': {'urls': [], 'data': [], 'severity': 'Medium', 'cwe': 'CWE-200', 'module': 'Sensitive Data Scanner'},
            'email_disclosure': {'urls': [], 'data': [], 'severity': 'Low', 'cwe': 'CWE-200', 'module': 'Sensitive Data Scanner'},
            'internal_ip': {'urls': [], 'data': [], 'severity': 'Low', 'cwe': 'CWE-200', 'module': 'Sensitive Data Scanner'},
            'development_comment': {'urls': [], 'data': [], 'severity': 'Low', 'cwe': 'CWE-615', 'module': 'JS Analysis'},
            'version_disclosure': {'urls': [], 'data': [], 'severity': 'Low', 'cwe': 'CWE-200', 'module': 'JS Analysis'},
            'information_disclosure': {'urls': [], 'data': [], 'severity': 'Low', 'cwe': 'CWE-200', 'module': 'Passive Analysis'},
            'hardcoded_password': {'urls': [], 'data': [], 'severity': 'High', 'cwe': 'CWE-798', 'module': 'JS Analysis'},
            'hardcoded_username': {'urls': [], 'data': [], 'severity': 'Medium', 'cwe': 'CWE-798', 'module': 'JS Analysis'},
        }

        # CVSS scores by severity
        cvss_map = {'critical': 9.8, 'high': 7.5, 'medium': 5.3, 'low': 3.1, 'info': 0.0}

        # Complete module name mapping (lowercase -> proper name)
        module_fixes = {
            # Generic/Unknown scanners - fix to proper names
            'scanner': 'Passive Analysis',
            'unknown': 'Passive Analysis',
            '': 'Passive Analysis',
            # Passive scanners
            'phone_disclosure': 'Sensitive Data Scanner',
            'email_disclosure': 'Sensitive Data Scanner',
            'development_comment': 'JavaScript Analysis',
            'version_disclosure': 'JavaScript Analysis',
            'information_disclosure': 'Passive Analysis',
            'hardcoded_password': 'JavaScript Analysis',
            'hardcoded_username': 'JavaScript Analysis',
            'hardcoded_credential': 'JavaScript Analysis',
            'tabnabbing': 'Tabnabbing Scanner',
            'base64_detect': 'Base64 Detector',
            'sensitive_data': 'Sensitive Data Scanner',
            'js_analysis': 'JavaScript Analysis',
            'security_headers': 'Security Headers Analysis',
            # Injection scanners
            'xss': 'Cross-Site Scripting Scanner',
            'sqli': 'SQL Injection Scanner',
            'cmdi': 'Command Injection Scanner',
            'ssti': 'Server-Side Template Injection Scanner',
            'lfi': 'Local File Inclusion Scanner',
            'rfi': 'Remote File Inclusion Scanner',
            'xxe': 'XML External Entity Scanner',
            'ssrf': 'Server-Side Request Forgery Scanner',
            'ssi': 'Server-Side Include Injection Scanner',
            'nosql_injection': 'NoSQL Injection Scanner',
            'xpath': 'XPath Injection Scanner',
            'crlf': 'CRLF Injection Scanner',
            'crlf_injection': 'CRLF Injection Scanner',
            'header_injection': 'Header Injection Scanner',
            # Auth & Session
            'csrf': 'CSRF Scanner',
            'idor': 'IDOR Scanner',
            'session': 'Session Security Scanner',
            'jwt_analysis': 'JWT Analysis Scanner',
            'weak_credentials': 'Weak Credentials Scanner',
            'type_juggling': 'PHP Type Juggling Scanner',
            # Discovery
            'dirbrute': 'Directory Brute Force Scanner',
            'backup_files': 'Backup Files Scanner',
            'git': 'Git Exposure Scanner',
            'env_secrets': 'Environment Secrets Scanner',
            'robots_txt': 'Robots.txt Analyzer',
            'cgi_scanner': 'CGI Scripts Scanner',
            'iis_config': 'IIS Configuration Scanner',
            'package_files': 'Package Files Scanner',
            'subdomain': 'Subdomain Discovery',
            'param_miner': 'Parameter Miner',
            # API
            'api_security': 'API Security Scanner',
            'api_bola': 'API BOLA Scanner',
            'api_rate_limit': 'API Rate Limit Scanner',
            'api_mass_assignment': 'API Mass Assignment Scanner',
            'api_excessive_data': 'API Excessive Data Scanner',
            'graphql': 'GraphQL Security Scanner',
            # Protocol
            'request_smuggling': 'Request Smuggling Scanner',
            'http_smuggling': 'HTTP Smuggling Scanner',
            'http_methods': 'HTTP Methods Scanner',
            'host_header': 'Host Header Injection Scanner',
            'hpp': 'HTTP Parameter Pollution Scanner',
            'prototype_pollution': 'Prototype Pollution Scanner',
            # Config
            'cors': 'CORS Misconfiguration Scanner',
            'csp_bypass': 'CSP Bypass Scanner',
            'ssl_tls': 'SSL/TLS Security Scanner',
            # Client-side
            'cspt': 'Client-Side Path Traversal Scanner',
            'dom_xss': 'DOM XSS Scanner',
            # Other
            'file_upload': 'File Upload Scanner',
            'redirect': 'Open Redirect Scanner',
            'cloud_storage': 'Cloud Storage Scanner',
            'oob_detection': 'Out-of-Band Detection Scanner',
            'php_object_injection': 'PHP Object Injection Scanner',
            'forbidden_bypass': 'Forbidden Bypass Scanner',
            'websocket': 'WebSocket Scanner',
            'soap_wsdl': 'SOAP/WSDL Scanner',
            'favicon_hash': 'Favicon Hash Scanner',
            'port_scan': 'Port Scanner',
            'formula_injection': 'Formula Injection Scanner',
        }

        # Vulnerability name mappings
        vuln_names = {
            'XSS': 'Cross-Site Scripting (XSS)', 'xss': 'Cross-Site Scripting (XSS)',
            'SQLi': 'SQL Injection', 'sqli': 'SQL Injection',
            'CMDi': 'Command Injection', 'cmdi': 'Command Injection',
            'LFI': 'Local File Inclusion (LFI)', 'lfi': 'Local File Inclusion (LFI)',
            'RFI': 'Remote File Inclusion (RFI)', 'rfi': 'Remote File Inclusion (RFI)',
            'SSRF': 'Server-Side Request Forgery (SSRF)', 'ssrf': 'Server-Side Request Forgery (SSRF)',
            'SSTI': 'Server-Side Template Injection (SSTI)', 'ssti': 'Server-Side Template Injection (SSTI)',
            'XXE': 'XML External Entity (XXE)', 'xxe': 'XML External Entity (XXE)',
            'IDOR': 'Insecure Direct Object Reference (IDOR)', 'idor': 'Insecure Direct Object Reference (IDOR)',
            'CSRF': 'Cross-Site Request Forgery (CSRF)', 'csrf': 'Cross-Site Request Forgery (CSRF)',
            'redirect': 'Open Redirect', 'hpp': 'HTTP Parameter Pollution',
        }

        for finding in findings:
            # Skip findings with invalid URLs (but allow site-level findings with N/A or empty URL)
            url = finding.get('url', '')
            vuln_type_check = finding.get('type', '').lower()
            module_check = finding.get('module', '').lower()

            # Site-level findings don't need a valid URL
            site_level_types = ['waf_detected', 'wafdetect', 'technology_detected']
            is_site_level = vuln_type_check in site_level_types or module_check in site_level_types

            if not is_valid_url(url) and not is_site_level:
                continue

            # Skip known false positives
            if is_false_positive(finding):
                continue

            vuln_type = finding.get('type', finding.get('module', '')).lower().replace(' ', '_')

            # Aggregate similar passive findings
            if vuln_type in aggregated:
                finding_url = finding.get('url', 'unknown')
                # Only add valid URLs to aggregation
                if is_valid_url(finding_url) and finding_url not in aggregated[vuln_type]['urls']:
                    aggregated[vuln_type]['urls'].append(finding_url)
                evidence = finding.get('evidence', finding.get('description', ''))
                if evidence and evidence not in aggregated[vuln_type]['data']:
                    aggregated[vuln_type]['data'].append(evidence[:200])
                continue

            # Group security headers by URL
            if vuln_type in ['missing_security_header', 'security_header']:
                url = finding.get('url', 'unknown')
                if url not in security_headers_by_url:
                    security_headers_by_url[url] = {
                        'url': url, 'type': 'Missing Security Headers', 'module': 'Security Headers',
                        'severity': 'Medium', 'vulnerability': True, 'headers': [],
                        'cvss': 5.3, 'confidence': 0.95, 'cwe': 'CWE-693',
                    }
                security_headers_by_url[url]['headers'].append(finding.get('description', ''))
                continue

            # Fix module name - always use proper capitalized name
            module_key = finding.get('module', '').lower().replace(' ', '_').replace('-', '_')
            type_key = finding.get('type', '').lower().replace(' ', '_').replace('-', '_')

            if module_key in module_fixes:
                finding['module'] = module_fixes[module_key]
            elif type_key in module_fixes:
                finding['module'] = module_fixes[type_key]
            elif vuln_type in module_fixes:
                finding['module'] = module_fixes[vuln_type]
            elif not finding.get('module') or finding.get('module') in ['Unknown', '', None]:
                # Capitalize existing name if no mapping found
                finding['module'] = finding.get('module', 'Scanner').replace('_', ' ').title()

            # Enhance vulnerability names
            if vuln_type in vuln_names:
                finding['type'] = vuln_names[vuln_type]
            elif vuln_type.upper() == 'XSS' or 'xss' in vuln_type:
                finding['type'] = 'Cross-Site Scripting (XSS)'

            # Fix CVSS if missing or zero (modules may return "0.0" or 0.0)
            cvss_val = finding.get('cvss')
            if not cvss_val or cvss_val == 'N/A' or cvss_val == '0.0' or cvss_val == 0 or cvss_val == 0.0 or str(cvss_val) == '0.0':
                sev = finding.get('severity', 'medium').lower()
                finding['cvss'] = cvss_map.get(sev, 5.0)

            # Fix confidence if missing or 0
            if not finding.get('confidence') or finding.get('confidence') == 0:
                # Set default confidence based on evidence
                if finding.get('evidence'):
                    finding['confidence'] = 0.80
                else:
                    finding['confidence'] = 0.60

            # Ensure response exists
            if not finding.get('response') and finding.get('evidence'):
                finding['response'] = finding.get('evidence')

            processed.append(finding)

        # Create aggregated findings
        for vuln_type, data in aggregated.items():
            if data['urls']:
                # Show top 10 URLs
                urls_list = data['urls'][:10]
                more_count = len(data['urls']) - 10 if len(data['urls']) > 10 else 0

                processed.append({
                    'url': urls_list[0],
                    'type': vuln_type.replace('_', ' ').title(),
                    'module': data['module'],
                    'severity': data['severity'],
                    'vulnerability': True,
                    'cvss': cvss_map.get(data['severity'].lower(), 3.1),
                    'confidence': 0.90,
                    'cwe': data['cwe'],
                    'parameter': 'Multiple Locations',
                    'evidence': f"Found in {len(data['urls'])} locations:\n" + '\n'.join(f"  • {u}" for u in urls_list) + (f"\n  ... and {more_count} more" if more_count else ''),
                    'description': f"{vuln_type.replace('_', ' ').title()} detected across {len(data['urls'])} pages",
                    'all_urls': data['urls'],
                    'samples': data['data'][:5],
                })

        # Add grouped security headers
        for url, hdr in security_headers_by_url.items():
            hdr['evidence'] = f"Missing {len(hdr['headers'])} headers:\n" + '\n'.join(f"  • {h}" for h in hdr['headers'])
            hdr['description'] = f"{len(hdr['headers'])} security headers missing"
            processed.append(hdr)

        return processed

    def _get_full_vuln_title(self, result: Dict[str, Any]) -> str:
        """Get full vulnerability title with type specification"""
        vuln_type = result.get('type', result.get('module', 'Unknown Vulnerability'))

        # Already enhanced by preprocessor
        if 'Cross-Site Scripting' in vuln_type or 'Injection' in vuln_type:
            return vuln_type

        # Fallback mappings
        title_map = {
            'XSS': 'Cross-Site Scripting (XSS)',
            'SQLi': 'SQL Injection',
            'CMDi': 'Command Injection',
            'LFI': 'Local File Inclusion (LFI)',
            'SSRF': 'Server-Side Request Forgery (SSRF)',
            'SSTI': 'Server-Side Template Injection (SSTI)',
            'XXE': 'XML External Entity (XXE)',
            'IDOR': 'Insecure Direct Object Reference (IDOR)',
        }

        return title_map.get(vuln_type.upper(), vuln_type)
