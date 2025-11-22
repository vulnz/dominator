"""
Unified report generator for all output formats
"""

import json
import datetime
import html
from typing import List, Dict, Any
from core.logger import get_logger

logger = get_logger(__name__)


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
            vulnerabilities = [r for r in results if r.get('vulnerability')]
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

                        # Remediation
                        if result.get('remediation'):
                            f.write("│\n│ ─── Remediation ───\n")
                            rem_lines = self._wrap_text(result.get('remediation'), 75)
                            for line in rem_lines:
                                f.write(f"│ {line}\n")

                        f.write(f"└{'─'*79}┘\n")

            # End of report
            f.write(f"\n{'='*80}\n")
            f.write(f" END OF REPORT - {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"{'='*80}\n")

        logger.info(f"TXT report saved to {output_file}")
        return True

    def _wrap_text(self, text: str, width: int) -> List[str]:
        """Wrap text to fit within specified width"""
        words = text.replace('\n', ' ').split()
        lines = []
        current_line = ""

        for word in words:
            if len(current_line) + len(word) + 1 <= width:
                current_line += (" " if current_line else "") + word
            else:
                if current_line:
                    lines.append(current_line)
                current_line = word

        if current_line:
            lines.append(current_line)

        return lines if lines else [""]

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
        """Generate HTML report

        Args:
            results: Scan results
            output_file: Output file path
            scan_info: Scan information
            simple: True for simple summary, False for full detailed report (default)
        """
        # Check report_mode from scan_info
        report_mode = scan_info.get('report_mode', 'full') if scan_info else 'full'
        simple = (report_mode == 'simple')

        if simple:
            return self._generate_html_simple(results, output_file, scan_info)

        # FULL detailed HTML report (default)
        vulnerabilities = [r for r in results if r.get('vulnerability')]

        # Count by severity
        severity_counts = {
            'Critical': len([r for r in vulnerabilities if r.get('severity') == 'Critical']),
            'High': len([r for r in vulnerabilities if r.get('severity') == 'High']),
            'Medium': len([r for r in vulnerabilities if r.get('severity') == 'Medium']),
            'Low': len([r for r in vulnerabilities if r.get('severity') == 'Low']),
            'Info': len([r for r in vulnerabilities if r.get('severity') == 'Info']),
        }

        html_content = f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Vulnerability Scan Report</title>
    <style>
        body {{
            font-family: Arial, sans-serif;
            margin: 20px;
            background-color: #f5f5f5;
        }}
        .container {{
            max-width: 1200px;
            margin: 0 auto;
            background-color: white;
            padding: 20px;
            box-shadow: 0 0 10px rgba(0,0,0,0.1);
        }}
        h1 {{
            color: #333;
            border-bottom: 3px solid #007bff;
            padding-bottom: 10px;
        }}
        .summary {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 15px;
            margin: 20px 0;
        }}
        .summary-card {{
            padding: 15px;
            border-radius: 5px;
            color: white;
            text-align: center;
        }}
        .critical {{ background-color: #dc3545; }}
        .high {{ background-color: #fd7e14; }}
        .medium {{ background-color: #ffc107; color: #333; }}
        .low {{ background-color: #28a745; }}
        .info {{ background-color: #17a2b8; }}
        .vulnerability {{
            margin: 15px 0;
            padding: 15px;
            border-left: 4px solid #ccc;
            background-color: #f9f9f9;
        }}
        .vulnerability.critical {{ border-left-color: #dc3545; }}
        .vulnerability.high {{ border-left-color: #fd7e14; }}
        .vulnerability.medium {{ border-left-color: #ffc107; }}
        .vulnerability.low {{ border-left-color: #28a745; }}
        .vulnerability h3 {{
            margin-top: 0;
            color: #333;
        }}
        .detail {{
            margin: 5px 0;
        }}
        .label {{
            font-weight: bold;
            color: #555;
        }}
        .evidence {{
            background-color: #f4f4f4;
            padding: 10px;
            border-radius: 3px;
            font-family: monospace;
            font-size: 12px;
            overflow-x: auto;
        }}
        .timestamp {{
            color: #888;
            font-size: 14px;
        }}
        .retest-badge {{
            display: inline-block;
            padding: 4px 10px;
            border-radius: 4px;
            font-size: 12px;
            font-weight: bold;
            margin-left: 10px;
            vertical-align: middle;
        }}
        .retest-fixed {{
            background-color: #28a745;
            color: white;
        }}
        .retest-new {{
            background-color: #ffc107;
            color: #333;
        }}
        .retest-still {{
            background-color: #dc3545;
            color: white;
        }}
        /* NEW: Collapsible functionality */
        .finding-header {{
            cursor: pointer;
            user-select: none;
            position: relative;
            padding-right: 30px;
        }}
        .finding-header:hover {{
            opacity: 0.8;
        }}
        .finding-header::after {{
            content: "▼";
            position: absolute;
            right: 10px;
            top: 5px;
            font-size: 14px;
            transition: transform 0.3s;
        }}
        .finding-header.collapsed::after {{
            transform: rotate(-90deg);
        }}
        .finding-details {{
            display: block;
            margin-top: 10px;
        }}
        .finding-details.collapsed {{
            display: none;
        }}
        /* NEW: Filter controls */
        .controls {{
            background-color: #f0f0f0;
            padding: 15px;
            border-radius: 5px;
            margin: 20px 0;
            display: flex;
            gap: 15px;
            align-items: center;
            flex-wrap: wrap;
        }}
        .controls label {{
            font-weight: bold;
            margin-right: 5px;
        }}
        .controls select {{
            padding: 5px 10px;
            border-radius: 3px;
            border: 1px solid #ccc;
        }}
        .controls button {{
            padding: 5px 15px;
            border-radius: 3px;
            border: none;
            background-color: #007bff;
            color: white;
            cursor: pointer;
            font-weight: bold;
        }}
        .controls button:hover {{
            background-color: #0056b3;
        }}
        .hidden {{
            display: none !important;
        }}
    </style>
</head>
<body>
    <div class="container">
        <h1>Vulnerability Scan Report</h1>
        <p class="timestamp">Generated: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>

        <h2>Summary</h2>
        <div class="summary">
            <div class="summary-card critical">
                <h3>{severity_counts['Critical']}</h3>
                <p>Critical</p>
            </div>
            <div class="summary-card high">
                <h3>{severity_counts['High']}</h3>
                <p>High</p>
            </div>
            <div class="summary-card medium">
                <h3>{severity_counts['Medium']}</h3>
                <p>Medium</p>
            </div>
            <div class="summary-card low">
                <h3>{severity_counts['Low']}</h3>
                <p>Low</p>
            </div>
            <div class="summary-card info">
                <h3>{severity_counts['Info']}</h3>
                <p>Info</p>
            </div>
        </div>

        <!-- NEW: Filter and collapse controls -->
        <div class="controls">
            <div>
                <label for="severityFilter">Filter by Severity:</label>
                <select id="severityFilter" onchange="filterBySeverity()">
                    <option value="all">All ({len(vulnerabilities)})</option>
                    <option value="critical">Critical ({severity_counts['Critical']})</option>
                    <option value="high">High ({severity_counts['High']})</option>
                    <option value="medium">Medium ({severity_counts['Medium']})</option>
                    <option value="low">Low ({severity_counts['Low']})</option>
                    <option value="info">Info ({severity_counts['Info']})</option>
                </select>
            </div>
            <div>
                <button onclick="expandAll()">Expand All</button>
                <button onclick="collapseAll()">Collapse All</button>
            </div>
        </div>

        <h2>Vulnerabilities (<span id="visibleCount">{len(vulnerabilities)}</span>)</h2>
"""

        # Add vulnerabilities grouped by severity
        for severity in ['Critical', 'High', 'Medium', 'Low', 'Info']:
            severity_results = [r for r in vulnerabilities if r.get('severity') == severity]
            if severity_results:
                html_content += f"<h3>{severity} ({len(severity_results)})</h3>\n"

                for result in severity_results:
                    # HTML escape all user-controlled data to prevent XSS payloads from breaking the report
                    vuln_type = html.escape(result.get('type', result.get('module', 'Unknown Vulnerability')))
                    raw_url = result.get('url', 'N/A')

                    # Make URL clickable
                    if raw_url != 'N/A' and raw_url.startswith('http'):
                        clickable_url = f'<a href="{html.escape(raw_url)}" target="_blank" style="color:#007bff; text-decoration:none; border-bottom:1px dashed #007bff;">{html.escape(raw_url)}</a>'
                    else:
                        clickable_url = html.escape(raw_url)

                    # Get severity color
                    sev_colors = {'Critical':'#dc3545','High':'#fd7e14','Medium':'#ffc107','Low':'#28a745','Info':'#17a2b8'}
                    sev_color = sev_colors.get(severity, '#333')

                    # Generate retest status badge if present
                    retest_badge = ""
                    retest_status = result.get('retest_status', '')
                    if retest_status == 'FIXED':
                        retest_badge = '<span class="retest-badge retest-fixed">✅ FIXED</span>'
                    elif retest_status == 'NEW':
                        retest_badge = '<span class="retest-badge retest-new">🆕 NEW</span>'
                    elif retest_status == 'STILL_VULNERABLE':
                        retest_badge = '<span class="retest-badge retest-still">⚠️ STILL VULNERABLE</span>'

                    # Generate unique ID for this finding
                    finding_id = f"finding_{severity.lower()}_{result.get('module', 'unknown').replace(' ', '_')}_{vulnerabilities.index(result)}"

                    html_content += f"""
        <div class="vulnerability {severity.lower()}" data-severity="{severity.lower()}">
            <h3 class="finding-header" onclick="toggleFinding('{finding_id}')">{vuln_type}{retest_badge}</h3>
            <div id="{finding_id}" class="finding-details">
                <div class="detail"><span class="label">Severity:</span> <strong style="color: {sev_color}">{severity}</strong></div>
                <div class="detail"><span class="label">URL:</span> {clickable_url}</div>
"""
                    # Show ALL available fields
                    fields_to_show = [
                        ('method', 'HTTP Method'),
                        ('parameter', 'Parameter'),
                        ('payload', 'Payload'),
                        ('module', 'Module'),
                        ('confidence', 'Confidence'),
                        ('cwe', 'CWE'),
                        ('cwe_name', 'CWE Name'),
                        ('owasp', 'OWASP'),
                        ('owasp_name', 'OWASP Name'),
                        ('cvss', 'CVSS Score'),
                        ('detection_method', 'Detection Method'),
                        ('vuln_type', 'Vulnerability Type'),
                    ]

                    for field, label in fields_to_show:
                        if result.get(field):
                            value = html.escape(str(result.get(field)))
                            if field == 'payload':
                                html_content += f"            <div class=\"detail\"><span class=\"label\">{label}:</span> <code>{value}</code></div>\n"
                            elif field == 'confidence':
                                conf_pct = float(value) * 100
                                html_content += f"            <div class=\"detail\"><span class=\"label\">{label}:</span> {conf_pct:.0f}%</div>\n"
                            else:
                                html_content += f"            <div class=\"detail\"><span class=\"label\">{label}:</span> {value}</div>\n"

                    # Add retest tracking timestamps if present
                    if result.get('first_seen'):
                        html_content += f"            <div class=\"detail\"><span class=\"label\">First Seen:</span> {html.escape(result.get('first_seen'))}</div>\n"
                    if result.get('last_seen'):
                        html_content += f"            <div class=\"detail\"><span class=\"label\">Last Seen:</span> {html.escape(result.get('last_seen'))}</div>\n"
                    if result.get('fixed_date'):
                        html_content += f"            <div class=\"detail\"><span class=\"label\">Fixed Date:</span> {html.escape(result.get('fixed_date'))}</div>\n"

                    if result.get('description'):
                        description = html.escape(result.get('description'))
                        html_content += f"            <div class=\"detail\"><span class=\"label\">Description:</span> {description}</div>\n"

                    if result.get('evidence'):
                        evidence = result.get('evidence')
                        # Make URLs in evidence clickable
                        evidence_html = self._make_urls_clickable(evidence)
                        html_content += f"            <div class=\"detail\"><span class=\"label\">Evidence:</span></div>\n"
                        html_content += f"            <div class=\"evidence\">{evidence_html}</div>\n"

                    if result.get('recommendation') or result.get('remediation'):
                        rec = html.escape(result.get('recommendation') or result.get('remediation'))
                        html_content += f"            <div class=\"detail\"><span class=\"label\">Recommendation:</span> {rec}</div>\n"

                    # Add HTTP details section (curl, request, response)
                    html_content += self._generate_http_details_section(result)

                    # Show references if available
                    if result.get('references'):
                        refs = result.get('references')
                        if isinstance(refs, list):
                            html_content += f"            <div class=\"detail\"><span class=\"label\">References:</span></div>\n"
                            for ref in refs:
                                ref_escaped = html.escape(str(ref))
                                html_content += f"            <div class=\"detail\" style=\"margin-left: 20px;\">• {ref_escaped}</div>\n"

                    html_content += "            </div>\n"  # Close finding-details
                    html_content += "        </div>\n"  # Close vulnerability

        html_content += """
    </div>

    <script>
        // Toggle single finding collapse/expand
        function toggleFinding(id) {{
            const details = document.getElementById(id);
            const header = details.previousElementSibling;

            if (details.classList.contains('collapsed')) {{
                details.classList.remove('collapsed');
                header.classList.remove('collapsed');
            }} else {{
                details.classList.add('collapsed');
                header.classList.add('collapsed');
            }}
        }}

        // Expand all findings
        function expandAll() {{
            document.querySelectorAll('.finding-details').forEach(el => {{
                el.classList.remove('collapsed');
            }});
            document.querySelectorAll('.finding-header').forEach(el => {{
                el.classList.remove('collapsed');
            }});
        }}

        // Collapse all findings
        function collapseAll() {{
            document.querySelectorAll('.finding-details').forEach(el => {{
                el.classList.add('collapsed');
            }});
            document.querySelectorAll('.finding-header').forEach(el => {{
                el.classList.add('collapsed');
            }});
        }}

        // Filter by severity
        function filterBySeverity() {{
            const filter = document.getElementById('severityFilter').value;
            const findings = document.querySelectorAll('.vulnerability');
            let visibleCount = 0;

            findings.forEach(finding => {{
                const severity = finding.getAttribute('data-severity');
                if (filter === 'all' || severity === filter) {{
                    finding.style.display = 'block';
                    visibleCount++;
                }} else {{
                    finding.style.display = 'none';
                }}
            }});

            document.getElementById('visibleCount').textContent = visibleCount;
        }}

        // Initialize: Start with all findings expanded
        document.addEventListener('DOMContentLoaded', function() {{
            // All findings are expanded by default (no collapsed class)
        }});
    </script>
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
        vulnerabilities = [r for r in results if r.get('vulnerability')]

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

        vulnerabilities = [r for r in results if r.get('vulnerability')]

        # Count by severity
        severity_counts = {
            'Critical': len([r for r in vulnerabilities if r.get('severity') == 'Critical']),
            'High': len([r for r in vulnerabilities if r.get('severity') == 'High']),
            'Medium': len([r for r in vulnerabilities if r.get('severity') == 'Medium']),
            'Low': len([r for r in vulnerabilities if r.get('severity') == 'Low']),
            'Info': len([r for r in vulnerabilities if r.get('severity') == 'Info']),
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
                    sections_html += f'  <div class="evidence">{html.escape(result.get("evidence", ""))}</div>\n'

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
        response_preview = result.get('response', result.get('evidence', 'Response data not captured'))
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

                <details style="margin-top:10px;">
                    <summary style="cursor:pointer; color:#667eea; font-weight:bold; padding:8px; background:#fff; border:1px solid #667eea; border-radius:4px; display:inline-block;">
                        📤 Show HTTP Request
                    </summary>
                    <div style="margin-top:10px;">
                        <pre style="background:#2d2d2d; color:#f8f8f2; padding:15px; border-radius:5px; overflow-x:auto; font-size:13px; line-height:1.5;"><code>{html.escape(http_request)}</code></pre>
                    </div>
                </details>

                <details style="margin-top:10px;">
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

        return clickable_text
