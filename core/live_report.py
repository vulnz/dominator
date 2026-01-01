"""
Unified Report Generator - Works for both live (auto-refresh) and final (static) reports
Uses the same template as the main report generator for consistency
"""

import json
import os
import datetime
import threading
import html
from typing import List, Dict, Any
from pathlib import Path


def _escape_html_sequences(s):
    """Common HTML escape sequences for script safety"""
    return s.replace('</', '<\\/').replace('<!--', '<\\!--').replace('-->', '--\\>')


def safe_json_for_html(data):
    """Safely embed JSON in HTML <script> tags"""
    return _escape_html_sequences(json.dumps(data, default=str, ensure_ascii=False))


def safe_js_string(s):
    """Safely escape a string for use in JavaScript"""
    if s is None:
        return ''
    s = str(s)
    for old, new in [('\\', '\\\\'), ("'", "\\'"), ('"', '\\"'), ('`', '\\`'),
                     ('\n', '\\n'), ('\r', '\\r'), ('<', '&lt;'), ('>', '&gt;')]:
        s = s.replace(old, new)
    return s


class LiveReportGenerator:
    """
    Unified Report Generator - generates reports in live (auto-refresh) or final (static) mode.
    Uses the same HTML template for consistency.
    """

    def __init__(self, output_dir: str = ".", live_mode: bool = True):
        """
        Initialize report generator

        Args:
            output_dir: Directory to save reports
            live_mode: If True, generates auto-refreshing report; if False, generates static report
        """
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)

        self.json_file = self.output_dir / "scan_data.json"
        self.html_file = self.output_dir / "report.html"
        self.live_mode = live_mode

        self.scan_data = {
            "scan_info": {
                "start_time": datetime.datetime.now().isoformat(),
                "status": "running" if live_mode else "completed",
                "targets": [],
                "modules_completed": 0,
                "modules_total": 0
            },
            "results": [],
            "stats": {
                "total_findings": 0,
                "vulnerabilities": 0,
                "critical": 0,
                "high": 0,
                "medium": 0,
                "low": 0,
                "info": 0
            }
        }

        self.lock = threading.Lock()

    def initialize(self, targets: List[str], modules: List[str]):
        """Initialize report with scan info"""
        with self.lock:
            self.scan_data["scan_info"]["targets"] = targets
            self.scan_data["scan_info"]["modules_total"] = len(modules)
            self._write_json()
            self._generate_html()

    def add_result(self, result: Dict[str, Any]):
        """Add a new scan result"""
        with self.lock:
            self.scan_data["results"].append(result)
            self._update_stats(result)
            self._write_json()

    def module_completed(self, module_name: str, findings_count: int):
        """Mark a module as completed"""
        with self.lock:
            self.scan_data["scan_info"]["modules_completed"] += 1
            self._write_json()

    def finalize(self, duration: float = 0):
        """Finalize the scan report - converts to static mode"""
        with self.lock:
            self.scan_data["scan_info"]["status"] = "completed"
            self.scan_data["scan_info"]["end_time"] = datetime.datetime.now().isoformat()
            self.scan_data["scan_info"]["duration"] = duration
            self.live_mode = False  # Switch to static mode
            self._write_json()
            self._generate_html()  # Regenerate HTML in static mode

    def _update_stats(self, result: Dict[str, Any]):
        """Update statistics based on new result"""
        self.scan_data["stats"]["total_findings"] += 1

        if result.get("vulnerability"):
            self.scan_data["stats"]["vulnerabilities"] += 1
            severity = result.get("severity", "").lower()
            if severity in self.scan_data["stats"]:
                self.scan_data["stats"][severity] += 1

    def _write_json(self):
        """Write scan data to JSON file"""
        with open(self.json_file, 'w', encoding='utf-8') as f:
            json.dump(self.scan_data, f, indent=2, ensure_ascii=False)

    def _generate_curl_command(self, url: str, method: str, parameter: str, payload: str) -> str:
        """Generate curl command for reproducing the vulnerability"""
        from urllib.parse import urlparse, parse_qs, urlencode

        if not url:
            return "curl 'URL_NOT_AVAILABLE'"

        parsed = urlparse(url)

        if method == 'GET':
            if parameter and payload:
                params = parse_qs(parsed.query)
                params[parameter] = [payload]
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

    def _generate_html(self):
        """Generate unified HTML report - same style in live and static mode"""
        from urllib.parse import urlparse

        # Get all vulnerabilities
        vulnerabilities = [r for r in self.scan_data["results"] if r.get('vulnerability') or
                         r.get('type') == 'recon' or r.get('severity', '').lower() == 'info']

        # Count by severity
        severity_counts = {
            'critical': len([r for r in vulnerabilities if r.get('severity', '').lower() == 'critical']),
            'high': len([r for r in vulnerabilities if r.get('severity', '').lower() == 'high']),
            'medium': len([r for r in vulnerabilities if r.get('severity', '').lower() == 'medium']),
            'low': len([r for r in vulnerabilities if r.get('severity', '').lower() == 'low']),
            'info': len([r for r in vulnerabilities if r.get('severity', '').lower() == 'info']),
        }

        # Group by host
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
        scan_status = self.scan_data["scan_info"]["status"]
        is_live = self.live_mode and scan_status == "running"

        # Auto-refresh script for live mode
        auto_refresh_script = """
        // Auto-refresh every 2 seconds in live mode
        setInterval(loadData, 2000);
        loadData();

        function loadData() {
            fetch('scan_data.json?' + new Date().getTime())
                .then(response => response.json())
                .then(data => {
                    updateFromJson(data);
                })
                .catch(error => {
                    console.log('Waiting for scan data...');
                });
        }

        function updateFromJson(data) {
            // Update status badge
            const status = data.scan_info.status;
            const badge = document.getElementById('statusBadge');
            if (status === 'completed') {
                badge.className = 'status-badge status-completed';
                badge.textContent = 'Scan Completed';
            } else {
                badge.className = 'status-badge status-running';
                badge.textContent = 'Scanning...';
            }

            // Update stats
            const stats = data.stats;
            document.getElementById('criticalCount').textContent = stats.critical;
            document.getElementById('highCount').textContent = stats.high;
            document.getElementById('mediumCount').textContent = stats.medium;
            document.getElementById('lowCount').textContent = stats.low;
            document.getElementById('infoCount').textContent = stats.info;
            document.getElementById('totalVulns').textContent = stats.vulnerabilities;

            // Update legend
            document.getElementById('legendCritical').textContent = stats.critical;
            document.getElementById('legendHigh').textContent = stats.high;
            document.getElementById('legendMedium').textContent = stats.medium;
            document.getElementById('legendLow').textContent = stats.low;
            document.getElementById('legendInfo').textContent = stats.info;

            // Update progress
            const info = data.scan_info;
            const total = info.modules_total || 1;
            const completed = info.modules_completed || 0;
            const percentage = Math.round((completed / total) * 100);
            document.getElementById('progressFill').style.width = percentage + '%';
            document.getElementById('progressFill').textContent = percentage + '%';
            document.getElementById('progressText').textContent = `${completed}/${total} modules completed`;
            document.getElementById('modulesDone').textContent = `${completed}/${total}`;

            // Update pie chart
            drawPieChart([stats.critical, stats.high, stats.medium, stats.low, stats.info]);

            // Update last update time
            document.getElementById('lastUpdate').textContent = 'Last updated: ' + new Date().toLocaleTimeString();
        }
        """ if is_live else "// Static report - no auto-refresh"

        html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Dominator Scan Report</title>
    <style>
        * {{ box-sizing: border-box; margin: 0; padding: 0; }}
        body {{ font-family: 'Segoe UI', Arial, sans-serif; background: #1a1a2e; color: #eee; min-height: 100vh; }}
        .header {{ background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%); padding: 20px 30px; border-bottom: 3px solid #e94560; display: flex; justify-content: space-between; align-items: center; }}
        .header h1 {{ color: #e94560; font-size: 28px; font-weight: 600; }}
        .header .subtitle {{ color: #bbb; font-size: 14px; margin-top: 5px; }}
        .status-badge {{ padding: 8px 20px; border-radius: 20px; font-weight: bold; font-size: 14px; }}
        .status-running {{ background: #ffc107; color: #333; animation: pulse 2s infinite; }}
        .status-completed {{ background: #27ae60; color: white; }}
        @keyframes pulse {{ 0%, 100% {{ opacity: 1; }} 50% {{ opacity: 0.7; }} }}

        .container {{ display: flex; min-height: calc(100vh - 80px); }}
        .sidebar {{ width: 280px; background: #16213e; padding: 20px; border-right: 1px solid #333; }}
        .main {{ flex: 1; padding: 20px 30px; overflow-y: auto; }}

        /* Summary Cards */
        .summary-row {{ display: flex; gap: 0; margin-bottom: 25px; }}
        .summary-card {{ flex: 1; min-width: 0; padding: 20px 15px; text-align: center; color: white; }}
        .summary-card h2 {{ font-size: 42px; font-weight: 300; margin-bottom: 5px; }}
        .summary-card p {{ font-size: 12px; text-transform: uppercase; letter-spacing: 1px; }}
        .summary-card.critical {{ background: #9b2335; }}
        .summary-card.high {{ background: #d35400; }}
        .summary-card.medium {{ background: #c9a227; color: #333; }}
        .summary-card.low {{ background: #27ae60; }}
        .summary-card.info {{ background: #2980b9; }}

        /* Progress Section */
        .progress-section {{ background: #1e1e3f; border-radius: 8px; padding: 20px; margin-bottom: 25px; }}
        .progress-bar {{ height: 30px; background: #2a2a4a; border-radius: 15px; overflow: hidden; margin-top: 10px; }}
        .progress-fill {{ height: 100%; background: linear-gradient(90deg, #e94560, #764ba2); transition: width 0.5s ease; display: flex; align-items: center; justify-content: center; color: white; font-weight: bold; }}

        /* Tabs */
        .tabs {{ display: flex; gap: 5px; margin-bottom: 20px; }}
        .tab {{ padding: 10px 20px; background: #2a2a4a; color: #ddd; border: none; cursor: pointer; border-radius: 5px 5px 0 0; font-size: 14px; }}
        .tab.active {{ background: #e94560; color: white; }}
        .tab:hover {{ background: #3a3a5a; color: #fff; }}
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
        .vuln-table th {{ background: #2a2a4a; padding: 12px 15px; text-align: left; font-weight: 600; color: #fff; font-size: 12px; text-transform: uppercase; }}
        .vuln-table td {{ padding: 12px 15px; border-bottom: 1px solid #333; color: #eee; }}
        .vuln-table tr:hover {{ background: #2a2a4a; }}
        .vuln-table tr.clickable {{ cursor: pointer; }}

        /* Severity Badges */
        .sev-badge {{ display: inline-block; padding: 4px 12px; border-radius: 3px; font-size: 11px; font-weight: bold; text-transform: uppercase; }}
        .sev-critical {{ background: #9b2335; color: white; }}
        .sev-high {{ background: #d35400; color: white; }}
        .sev-medium {{ background: #c9a227; color: #333; }}
        .sev-low {{ background: #27ae60; color: white; }}
        .sev-info {{ background: #2980b9; color: white; }}

        /* Sidebar Stats */
        .sidebar-section {{ margin-bottom: 25px; }}
        .sidebar-title {{ color: #e94560; font-size: 12px; text-transform: uppercase; margin-bottom: 10px; letter-spacing: 1px; font-weight: bold; }}
        .stat-row {{ display: flex; justify-content: space-between; padding: 8px 0; border-bottom: 1px solid #333; }}
        .stat-label {{ color: #ddd; }}
        .stat-value {{ color: #fff; font-weight: 500; }}

        /* Pie Chart */
        .pie-container {{ width: 150px; height: 150px; margin: 20px auto; position: relative; }}
        .pie-chart {{ width: 150px; height: 150px; border-radius: 50%; cursor: pointer; }}
        .pie-legend {{ margin-top: 15px; }}
        .legend-item {{ display: flex; align-items: center; margin-bottom: 8px; font-size: 13px; }}
        .legend-dot {{ width: 12px; height: 12px; border-radius: 50%; margin-right: 8px; }}

        /* Controls */
        .controls {{ display: flex; justify-content: space-between; align-items: center; margin-bottom: 20px; }}
        .control-group {{ display: flex; gap: 10px; align-items: center; }}
        .btn {{ padding: 8px 16px; border: none; border-radius: 4px; cursor: pointer; font-size: 13px; }}
        .btn-primary {{ background: #e94560; color: white; }}
        .btn-secondary {{ background: #2a2a4a; color: #ddd; }}
        .btn:hover {{ opacity: 0.9; }}
        select {{ padding: 8px 12px; background: #2a2a4a; border: 1px solid #444; color: #fff; border-radius: 4px; }}

        /* Expandable Details */
        .vuln-details {{ display: none; background: #1a1a2e; border-left: 3px solid #e94560; margin: 0; }}
        .vuln-details.show {{ display: table-row; }}
        .detail-grid {{ display: grid; grid-template-columns: repeat(2, 1fr); gap: 15px; padding: 15px 20px; }}
        .detail-item label {{ display: block; color: #e94560; font-size: 11px; text-transform: uppercase; margin-bottom: 3px; font-weight: bold; }}
        .detail-item span {{ color: #fff; }}
        .evidence-box {{ background: #0d0d1a; padding: 15px; border-radius: 5px; font-family: 'Consolas', monospace; font-size: 12px; margin-top: 15px; overflow-x: auto; white-space: pre-wrap; word-break: break-all; }}

        /* Last update indicator */
        .last-update {{ text-align: center; color: #bbb; margin-top: 20px; font-size: 12px; padding: 10px; }}
        .refresh-indicator {{ display: inline-block; width: 8px; height: 8px; background: #27ae60; border-radius: 50%; margin-right: 8px; animation: blink 2s infinite; }}
        @keyframes blink {{ 0%, 100% {{ opacity: 1; }} 50% {{ opacity: 0.3; }} }}

        /* View toggle */
        .view-content {{ display: none; }}
        .view-content.active {{ display: block; }}
        .no-results {{ text-align: center; padding: 60px; color: #bbb; font-style: italic; }}
    </style>
</head>
<body>
    <div class="header">
        <div>
            <h1>DOMINATOR</h1>
            <div class="subtitle">{'Live Scan Report - Auto-refreshing every 2 seconds' if is_live else f'Vulnerability Scan Report - {datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")}'}</div>
        </div>
        <div id="statusBadge" class="status-badge {'status-running' if is_live else 'status-completed'}">
            {'Scanning...' if is_live else 'Scan Completed'}
        </div>
    </div>

    <div class="container">
        <div class="sidebar">
            {'<div class="sidebar-section"><div class="sidebar-title">Scan Progress</div><div class="progress-bar"><div id="progressFill" class="progress-fill" style="width: ' + str(int((self.scan_data["scan_info"]["modules_completed"] / max(self.scan_data["scan_info"]["modules_total"], 1)) * 100)) + '%;">' + str(int((self.scan_data["scan_info"]["modules_completed"] / max(self.scan_data["scan_info"]["modules_total"], 1)) * 100)) + '%</div></div><p style="margin-top: 10px; color: #ddd; font-size: 12px;" id="progressText">' + str(self.scan_data["scan_info"]["modules_completed"]) + '/' + str(self.scan_data["scan_info"]["modules_total"]) + ' modules completed</p></div>' if is_live else ''}

            <div class="sidebar-section">
                <div class="sidebar-title">Scan Details</div>
                <div class="stat-row"><span class="stat-label">Total Hosts</span><span class="stat-value">{total_hosts}</span></div>
                <div class="stat-row"><span class="stat-label">Vulnerabilities</span><span class="stat-value" id="totalVulns">{total_vulns}</span></div>
                <div class="stat-row"><span class="stat-label">Modules Done</span><span class="stat-value" id="modulesDone">{self.scan_data["scan_info"]["modules_completed"]}/{self.scan_data["scan_info"]["modules_total"]}</span></div>
                <div class="stat-row"><span class="stat-label">Generated</span><span class="stat-value">{datetime.datetime.now().strftime('%H:%M:%S')}</span></div>
            </div>

            <div class="sidebar-section">
                <div class="sidebar-title">Severity Distribution</div>
                <div class="pie-container">
                    <canvas id="pieChart" class="pie-chart"></canvas>
                </div>
                <div class="pie-legend">
                    <div class="legend-item"><span class="legend-dot" style="background:#9b2335"></span>Critical (<span id="legendCritical">{severity_counts['critical']}</span>)</div>
                    <div class="legend-item"><span class="legend-dot" style="background:#d35400"></span>High (<span id="legendHigh">{severity_counts['high']}</span>)</div>
                    <div class="legend-item"><span class="legend-dot" style="background:#c9a227"></span>Medium (<span id="legendMedium">{severity_counts['medium']}</span>)</div>
                    <div class="legend-item"><span class="legend-dot" style="background:#27ae60"></span>Low (<span id="legendLow">{severity_counts['low']}</span>)</div>
                    <div class="legend-item"><span class="legend-dot" style="background:#2980b9"></span>Info (<span id="legendInfo">{severity_counts['info']}</span>)</div>
                </div>
            </div>
        </div>

        <div class="main">
            <!-- Summary Cards -->
            <div class="summary-row">
                <div class="summary-card critical"><h2 id="criticalCount">{severity_counts['critical']}</h2><p>Critical</p></div>
                <div class="summary-card high"><h2 id="highCount">{severity_counts['high']}</h2><p>High</p></div>
                <div class="summary-card medium"><h2 id="mediumCount">{severity_counts['medium']}</h2><p>Medium</p></div>
                <div class="summary-card low"><h2 id="lowCount">{severity_counts['low']}</h2><p>Low</p></div>
                <div class="summary-card info"><h2 id="infoCount">{severity_counts['info']}</h2><p>Info</p></div>
            </div>

            <!-- Tabs -->
            <div class="tabs">
                <button class="tab active" onclick="showView('hosts')" id="tab-hosts">Hosts<span class="tab-badge">{total_hosts}</span></button>
                <button class="tab" onclick="showView('vulns')" id="tab-vulns">Vulnerabilities<span class="tab-badge">{total_vulns}</span></button>
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
        if hosts_data:
            for host, data in sorted(hosts_data.items(), key=lambda x: sum(x[1]['counts'].values()), reverse=True):
                counts = data['counts']
                total = sum(counts.values())
                if total == 0:
                    continue

                host_id = html.escape(host).replace('.', '-').replace(':', '-')
                html_content += f"""
                <div class="host-item" onclick="toggleHostDetails('{host_id}')">
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
                    <div id="host-{host_id}" class="vuln-details">
                        <table class="vuln-table">
                            <thead><tr><th>Severity</th><th>CVSS</th><th>Module</th><th>Parameter</th></tr></thead>
                            <tbody>
"""
                # Add vulnerabilities for this host
                for vuln in sorted(data['vulns'], key=lambda x: ['critical', 'high', 'medium', 'low', 'info'].index(x.get('severity', 'info').lower())):
                    sev = vuln.get('severity', 'Info').lower()
                    cvss = vuln.get('cvss', 'N/A')
                    module = html.escape(str(vuln.get('module', vuln.get('type', 'Unknown'))))
                    param = html.escape(str(vuln.get('parameter', '-'))[:50])
                    vuln_id = id(vuln)

                    html_content += f"""
                                <tr class="clickable" onclick="event.stopPropagation(); toggleVulnDetail('vuln-{vuln_id}')" data-severity="{sev}">
                                    <td><span class="sev-badge sev-{sev}">{sev.upper()}</span></td>
                                    <td>{cvss}</td>
                                    <td>{module}</td>
                                    <td>{param}</td>
                                </tr>
                                <tr id="vuln-{vuln_id}" class="vuln-details" data-severity="{sev}">
                                    <td colspan="4" style="padding:0;">
                                        <div class="detail-grid">
                                            <div class="detail-item"><label>Full URL</label><span>{html.escape(str(vuln.get('url', 'N/A')))}</span></div>
                                            <div class="detail-item"><label>Method</label><span style="background:#e94560;color:white;padding:2px 8px;border-radius:3px;">{html.escape(str(vuln.get('method', 'GET')))}</span></div>
                                            <div class="detail-item"><label>Parameter</label><span style="color:#e94560;font-weight:bold;">{html.escape(str(vuln.get('parameter', 'N/A')))}</span></div>
                                            <div class="detail-item"><label>Confidence</label><span>{float(vuln.get('confidence', 0.8))*100:.0f}%</span></div>
                                            <div class="detail-item"><label>CWE</label><span>{html.escape(str(vuln.get('cwe', 'N/A')))}</span></div>
                                            <div class="detail-item"><label>OWASP</label><span>{html.escape(str(vuln.get('owasp', 'N/A')))}</span></div>
                                        </div>
                                        <div style="padding:0 20px 15px 20px;">
                                            <div style="margin-top:10px;"><label style="color:#ccc;font-size:11px;font-weight:bold;">PAYLOAD</label>
                                                <div style="background:#1a1a2e;padding:10px;border-radius:4px;margin-top:5px;font-family:monospace;color:#e94560;word-break:break-all;">{html.escape(str(vuln.get('payload', 'N/A'))[:500])}</div>
                                            </div>
                                            <div style="margin-top:10px;"><label style="color:#ccc;font-size:11px;font-weight:bold;">EVIDENCE / PROOF</label>
                                                <div class="evidence-box">{html.escape(str(vuln.get('evidence', vuln.get('description', 'No evidence')))[:1500])}</div>
                                            </div>
                                            <div style="margin-top:10px;"><label style="color:#ccc;font-size:11px;font-weight:bold;">SOLUTION / REMEDIATION</label>
                                                <div style="background:#1a3a1a;padding:10px;border-radius:4px;margin-top:5px;color:#90EE90;border-left:3px solid #27ae60;">{html.escape(str(vuln.get('remediation', 'Review and fix according to security best practices.')))}</div>
                                            </div>
                                            <details style="margin-top:10px;">
                                                <summary style="cursor:pointer;color:#e94560;font-weight:bold;padding:5px;background:#2a2a4a;border-radius:3px;">HTTP Request</summary>
                                                <div class="evidence-box" style="margin-top:5px;">{html.escape(str(vuln.get('request', 'No request captured'))[:2000])}</div>
                                            </details>
                                            <details style="margin-top:10px;">
                                                <summary style="cursor:pointer;color:#e94560;font-weight:bold;padding:5px;background:#2a2a4a;border-radius:3px;">HTTP Response</summary>
                                                <div class="evidence-box" style="margin-top:5px;max-height:300px;overflow-y:auto;">{html.escape(str(vuln.get('response', 'No response captured'))[:3000])}</div>
                                            </details>
                                            <div style="margin-top:15px;display:flex;gap:10px;">
                                                <button onclick="event.stopPropagation(); copyToClipboard('{safe_js_string(vuln.get('url', ''))}')" class="btn btn-secondary" style="font-size:11px;">Copy URL</button>
                                                <button onclick="event.stopPropagation(); copyToClipboard('{safe_js_string(vuln.get('payload', ''))}')" class="btn btn-secondary" style="font-size:11px;">Copy Payload</button>
                                            </div>
                                        </div>
                                    </td>
                                </tr>
"""

                html_content += """
                            </tbody>
                        </table>
                    </div>
                </div>
"""
        else:
            html_content += '<div class="no-results">No vulnerabilities found yet...</div>'

        html_content += """
            </div>

            <!-- VULNERABILITIES VIEW -->
            <div id="vulnsView" class="view-content">
                <table class="vuln-table">
                    <thead><tr><th>Severity</th><th>CVSS</th><th>Host</th><th>Module</th><th>Parameter</th></tr></thead>
                    <tbody>
"""

        # Add all vulnerabilities sorted by severity
        if vulnerabilities:
            for vuln in sorted(vulnerabilities, key=lambda x: ['critical', 'high', 'medium', 'low', 'info'].index(x.get('severity', 'info').lower())):
                sev = vuln.get('severity', 'Info').lower()
                cvss = vuln.get('cvss', 'N/A')
                url = vuln.get('url', 'Unknown')
                try:
                    parsed = urlparse(url)
                    host = parsed.netloc or url
                except:
                    host = url
                module = html.escape(str(vuln.get('module', vuln.get('type', 'Unknown'))))
                param = html.escape(str(vuln.get('parameter', '-'))[:50])
                vuln_id = f"all-{id(vuln)}"

                html_content += f"""
                        <tr class="clickable" onclick="toggleVulnDetail('vuln-{vuln_id}')" data-severity="{sev}">
                            <td><span class="sev-badge sev-{sev}">{sev.upper()}</span></td>
                            <td>{cvss}</td>
                            <td>{html.escape(host)}</td>
                            <td>{module}</td>
                            <td>{param}</td>
                        </tr>
                        <tr id="vuln-{vuln_id}" class="vuln-details" data-severity="{sev}">
                            <td colspan="5" style="padding:0;">
                                <div class="detail-grid">
                                    <div class="detail-item"><label>Full URL</label><span>{html.escape(str(vuln.get('url', 'N/A')))}</span></div>
                                    <div class="detail-item"><label>Method</label><span style="background:#e94560;color:white;padding:2px 8px;border-radius:3px;">{html.escape(str(vuln.get('method', 'GET')))}</span></div>
                                    <div class="detail-item"><label>Parameter</label><span style="color:#e94560;font-weight:bold;">{html.escape(str(vuln.get('parameter', 'N/A')))}</span></div>
                                    <div class="detail-item"><label>Confidence</label><span>{float(vuln.get('confidence', 0.8))*100:.0f}%</span></div>
                                    <div class="detail-item"><label>CWE</label><span>{html.escape(str(vuln.get('cwe', 'N/A')))}</span></div>
                                    <div class="detail-item"><label>OWASP</label><span>{html.escape(str(vuln.get('owasp', 'N/A')))}</span></div>
                                </div>
                                <div style="padding:0 20px 15px 20px;">
                                    <div style="margin-top:10px;"><label style="color:#ccc;font-size:11px;font-weight:bold;">PAYLOAD</label>
                                        <div style="background:#1a1a2e;padding:10px;border-radius:4px;margin-top:5px;font-family:monospace;color:#e94560;word-break:break-all;">{html.escape(str(vuln.get('payload', 'N/A'))[:500])}</div>
                                    </div>
                                    <div style="margin-top:10px;"><label style="color:#ccc;font-size:11px;font-weight:bold;">EVIDENCE / PROOF</label>
                                        <div class="evidence-box">{html.escape(str(vuln.get('evidence', vuln.get('description', 'No evidence')))[:1500])}</div>
                                    </div>
                                    <div style="margin-top:10px;"><label style="color:#ccc;font-size:11px;font-weight:bold;">SOLUTION / REMEDIATION</label>
                                        <div style="background:#1a3a1a;padding:10px;border-radius:4px;margin-top:5px;color:#90EE90;border-left:3px solid #27ae60;">{html.escape(str(vuln.get('remediation', 'Review and fix according to security best practices.')))}</div>
                                    </div>
                                    <details style="margin-top:10px;">
                                        <summary style="cursor:pointer;color:#e94560;font-weight:bold;padding:5px;background:#2a2a4a;border-radius:3px;">HTTP Request</summary>
                                        <div class="evidence-box" style="margin-top:5px;">{html.escape(str(vuln.get('request', 'No request captured'))[:2000])}</div>
                                    </details>
                                    <details style="margin-top:10px;">
                                        <summary style="cursor:pointer;color:#e94560;font-weight:bold;padding:5px;background:#2a2a4a;border-radius:3px;">HTTP Response</summary>
                                        <div class="evidence-box" style="margin-top:5px;max-height:300px;overflow-y:auto;">{html.escape(str(vuln.get('response', 'No response captured'))[:3000])}</div>
                                    </details>
                                    <div style="margin-top:15px;display:flex;gap:10px;">
                                        <button onclick="event.stopPropagation(); copyToClipboard('{safe_js_string(vuln.get('url', ''))}')" class="btn btn-secondary" style="font-size:11px;">Copy URL</button>
                                        <button onclick="event.stopPropagation(); copyToClipboard('{safe_js_string(vuln.get('payload', ''))}')" class="btn btn-secondary" style="font-size:11px;">Copy Payload</button>
                                    </div>
                                </div>
                            </td>
                        </tr>
"""

        html_content += f"""
                    </tbody>
                </table>
            </div>

            <div class="last-update">
                {'<span class="refresh-indicator"></span>' if is_live else ''}
                <span id="lastUpdate">{'Last updated: ' + datetime.datetime.now().strftime('%H:%M:%S') if is_live else 'Generated: ' + datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</span>
            </div>
        </div>
    </div>

    <script>
        // Pie chart colors
        const pieColors = ['#9b2335', '#d35400', '#c9a227', '#27ae60', '#2980b9'];

        // Draw pie chart
        function drawPieChart(data) {{
            const canvas = document.getElementById('pieChart');
            if (!canvas) return;

            canvas.width = 150;
            canvas.height = 150;

            const ctx = canvas.getContext('2d');
            const total = data.reduce((a, b) => a + b, 0);

            if (total === 0) {{
                ctx.beginPath();
                ctx.arc(75, 75, 70, 0, 2 * Math.PI);
                ctx.fillStyle = '#333';
                ctx.fill();
                return;
            }}

            let startAngle = -Math.PI / 2;
            data.forEach((value, i) => {{
                if (value === 0) return;
                const sliceAngle = (value / total) * 2 * Math.PI;
                ctx.beginPath();
                ctx.moveTo(75, 75);
                ctx.arc(75, 75, 70, startAngle, startAngle + sliceAngle);
                ctx.fillStyle = pieColors[i];
                ctx.fill();
                startAngle += sliceAngle;
            }});

            // Donut hole
            ctx.beginPath();
            ctx.arc(75, 75, 40, 0, 2 * Math.PI);
            ctx.fillStyle = '#16213e';
            ctx.fill();
        }}

        // View switching
        function showView(view) {{
            document.querySelectorAll('.view-content').forEach(el => el.classList.remove('active'));
            document.querySelectorAll('.tab').forEach(el => el.classList.remove('active'));
            document.getElementById(view + 'View').classList.add('active');
            document.getElementById('tab-' + view).classList.add('active');
        }}

        // Toggle host details
        function toggleHostDetails(hostId) {{
            const el = document.getElementById('host-' + hostId);
            if (el) el.classList.toggle('show');
        }}

        // Toggle vulnerability detail
        function toggleVulnDetail(id) {{
            const el = document.getElementById(id);
            if (el) el.classList.toggle('show');
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
        }}

        function expandAll() {{
            document.querySelectorAll('.vuln-details').forEach(el => el.classList.add('show'));
        }}

        // Copy to clipboard
        function copyToClipboard(text) {{
            navigator.clipboard.writeText(text).then(() => {{
                showToast('Copied to clipboard!');
            }}).catch(() => {{
                const ta = document.createElement('textarea');
                ta.value = text;
                document.body.appendChild(ta);
                ta.select();
                document.execCommand('copy');
                document.body.removeChild(ta);
                showToast('Copied to clipboard!');
            }});
        }}

        function showToast(msg) {{
            const toast = document.createElement('div');
            toast.textContent = msg;
            toast.style.cssText = 'position:fixed;bottom:20px;right:20px;background:#27ae60;color:white;padding:12px 24px;border-radius:4px;z-index:9999;';
            document.body.appendChild(toast);
            setTimeout(() => toast.remove(), 2000);
        }}

        // Initialize pie chart
        drawPieChart([{severity_counts['critical']}, {severity_counts['high']}, {severity_counts['medium']}, {severity_counts['low']}, {severity_counts['info']}]);

        {auto_refresh_script}
    </script>
</body>
</html>"""

        with open(self.html_file, 'w', encoding='utf-8') as f:
            f.write(html_content)

    def generate_from_results(self, results: List[Dict[str, Any]], scan_info: Dict[str, Any] = None):
        """
        Generate a report directly from a list of results (for final report generation).
        This method allows the LiveReportGenerator to be used as a drop-in replacement for ReportGenerator.
        """
        self.live_mode = False
        self.scan_data["scan_info"]["status"] = "completed"
        self.scan_data["results"] = results

        if scan_info:
            self.scan_data["scan_info"].update(scan_info)

        # Update stats from results
        for result in results:
            self._update_stats(result)

        self._write_json()
        self._generate_html()

        return str(self.html_file)
