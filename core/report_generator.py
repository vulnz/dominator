"""
Unified report generator for all output formats
"""

import json
import datetime
from typing import List, Dict, Any
from core.logger import get_logger

logger = get_logger(__name__)


class ReportGenerator:
    """Generates scan reports in various formats"""

    def __init__(self):
        """Initialize report generator"""
        self.supported_formats = ['html', 'json', 'xml', 'txt']

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
                return self._generate_html(results, output_file, scan_info)
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
        """Generate plain text report"""
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write("="*80 + "\n")
            f.write("VULNERABILITY SCAN REPORT\n")
            f.write("="*80 + "\n\n")

            if scan_info:
                f.write("Scan Information:\n")
                f.write(f"  Date: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                if scan_info.get('targets'):
                    f.write(f"  Targets: {', '.join(scan_info['targets'])}\n")
                if scan_info.get('duration'):
                    f.write(f"  Duration: {scan_info['duration']:.2f}s\n")
                f.write("\n")

            # Statistics
            vulnerabilities = [r for r in results if r.get('vulnerability')]
            f.write(f"Total Findings: {len(results)}\n")
            f.write(f"Vulnerabilities: {len(vulnerabilities)}\n\n")

            # Group by severity
            severity_order = ['Critical', 'High', 'Medium', 'Low', 'Info']
            for severity in severity_order:
                severity_results = [r for r in vulnerabilities if r.get('severity') == severity]
                if severity_results:
                    f.write(f"\n{severity} Severity ({len(severity_results)}):\n")
                    f.write("-"*80 + "\n\n")

                    for i, result in enumerate(severity_results, 1):
                        f.write(f"{i}. {result.get('type', 'Unknown')}\n")
                        f.write(f"   URL: {result.get('url', 'N/A')}\n")
                        if result.get('parameter'):
                            f.write(f"   Parameter: {result.get('parameter')}\n")
                        if result.get('payload'):
                            f.write(f"   Payload: {result.get('payload')}\n")
                        if result.get('evidence'):
                            f.write(f"   Evidence: {result.get('evidence')}\n")
                        if result.get('description'):
                            f.write(f"   Description: {result.get('description')}\n")
                        f.write("\n")

            f.write("="*80 + "\n")
            f.write("End of Report\n")
            f.write("="*80 + "\n")

        logger.info(f"TXT report saved to {output_file}")
        return True

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
                      scan_info: Dict[str, Any] = None) -> bool:
        """Generate HTML report"""
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

        <h2>Vulnerabilities ({len(vulnerabilities)})</h2>
"""

        # Add vulnerabilities grouped by severity
        for severity in ['Critical', 'High', 'Medium', 'Low', 'Info']:
            severity_results = [r for r in vulnerabilities if r.get('severity') == severity]
            if severity_results:
                html_content += f"<h3>{severity} ({len(severity_results)})</h3>\n"

                for result in severity_results:
                    html_content += f"""
        <div class="vulnerability {severity.lower()}">
            <h3>{result.get('type', 'Unknown Vulnerability')}</h3>
            <div class="detail"><span class="label">URL:</span> {result.get('url', 'N/A')}</div>
"""
                    if result.get('parameter'):
                        html_content += f"            <div class=\"detail\"><span class=\"label\">Parameter:</span> {result.get('parameter')}</div>\n"
                    if result.get('payload'):
                        html_content += f"            <div class=\"detail\"><span class=\"label\">Payload:</span> <code>{result.get('payload')}</code></div>\n"
                    if result.get('description'):
                        html_content += f"            <div class=\"detail\"><span class=\"label\">Description:</span> {result.get('description')}</div>\n"
                    if result.get('evidence'):
                        html_content += f"            <div class=\"detail\"><span class=\"label\">Evidence:</span></div>\n"
                        html_content += f"            <div class=\"evidence\">{result.get('evidence')}</div>\n"
                    if result.get('recommendation'):
                        html_content += f"            <div class=\"detail\"><span class=\"label\">Recommendation:</span> {result.get('recommendation')}</div>\n"

                    html_content += "        </div>\n"

        html_content += """
    </div>
</body>
</html>
"""

        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(html_content)

        logger.info(f"HTML report saved to {output_file}")
        return True
