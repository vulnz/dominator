"""
Live HTML Report Generator - Updates in real-time during scanning
"""

import json
import os
import datetime
import threading
import time
from typing import List, Dict, Any
from pathlib import Path


class LiveReportGenerator:
    """Generates live HTML reports that update during scanning"""

    def __init__(self, output_dir: str = "."):
        """Initialize live report generator

        Args:
            output_dir: Directory to save report files
        """
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)

        self.json_file = self.output_dir / "live_scan_data.json"
        self.html_file = self.output_dir / "live_report.html"

        self.scan_data = {
            "scan_info": {
                "start_time": datetime.datetime.now().isoformat(),
                "status": "running",
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
        """Initialize live report with scan info

        Args:
            targets: List of scan targets
            modules: List of modules to run
        """
        with self.lock:
            self.scan_data["scan_info"]["targets"] = targets
            self.scan_data["scan_info"]["modules_total"] = len(modules)
            self._write_json()
            self._generate_html()

    def add_result(self, result: Dict[str, Any]):
        """Add a new scan result

        Args:
            result: Scan result dictionary
        """
        with self.lock:
            self.scan_data["results"].append(result)
            self._update_stats(result)
            self._write_json()

    def module_completed(self, module_name: str, findings_count: int):
        """Mark a module as completed

        Args:
            module_name: Name of completed module
            findings_count: Number of findings from this module
        """
        with self.lock:
            self.scan_data["scan_info"]["modules_completed"] += 1
            self._write_json()

    def finalize(self, duration: float):
        """Finalize the scan report

        Args:
            duration: Total scan duration in seconds
        """
        with self.lock:
            self.scan_data["scan_info"]["status"] = "completed"
            self.scan_data["scan_info"]["end_time"] = datetime.datetime.now().isoformat()
            self.scan_data["scan_info"]["duration"] = duration
            self._write_json()

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

    def _generate_html(self):
        """Generate live HTML report"""
        html_content = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Live Scan Report - Dominator</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }

        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, Cantarell, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            padding: 20px;
        }

        .container {
            max-width: 1400px;
            margin: 0 auto;
        }

        .header {
            text-align: center;
            color: white;
            margin-bottom: 30px;
        }

        .header h1 {
            font-size: 2.5em;
            margin-bottom: 10px;
            text-shadow: 2px 2px 4px rgba(0,0,0,0.3);
        }

        .status-badge {
            display: inline-block;
            padding: 8px 20px;
            border-radius: 20px;
            font-weight: bold;
            font-size: 14px;
            margin-top: 10px;
        }

        .status-running {
            background: #ffc107;
            color: #333;
            animation: pulse 2s infinite;
        }

        .status-completed {
            background: #28a745;
            color: white;
        }

        @keyframes pulse {
            0%, 100% { opacity: 1; }
            50% { opacity: 0.7; }
        }

        .stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }

        .stat-card {
            background: white;
            border-radius: 15px;
            padding: 25px;
            text-align: center;
            box-shadow: 0 10px 30px rgba(0,0,0,0.2);
            transition: transform 0.3s, box-shadow 0.3s;
        }

        .stat-card:hover {
            transform: translateY(-5px);
            box-shadow: 0 15px 40px rgba(0,0,0,0.3);
        }

        .stat-card h3 {
            font-size: 3em;
            margin-bottom: 5px;
            font-weight: bold;
        }

        .stat-card p {
            color: #666;
            font-size: 1.1em;
            font-weight: 500;
        }

        .critical { color: #dc3545; }
        .high { color: #fd7e14; }
        .medium { color: #ffc107; }
        .low { color: #28a745; }
        .info { color: #17a2b8; }

        .progress-section {
            background: white;
            border-radius: 15px;
            padding: 25px;
            margin-bottom: 30px;
            box-shadow: 0 10px 30px rgba(0,0,0,0.2);
        }

        .progress-bar {
            height: 30px;
            background: #e9ecef;
            border-radius: 15px;
            overflow: hidden;
            margin-top: 10px;
        }

        .progress-fill {
            height: 100%;
            background: linear-gradient(90deg, #667eea, #764ba2);
            transition: width 0.5s ease;
            display: flex;
            align-items: center;
            justify-content: center;
            color: white;
            font-weight: bold;
        }

        .results-section {
            background: white;
            border-radius: 15px;
            padding: 25px;
            box-shadow: 0 10px 30px rgba(0,0,0,0.2);
        }

        .results-section h2 {
            margin-bottom: 20px;
            color: #333;
        }

        .vulnerability {
            margin: 15px 0;
            padding: 20px;
            border-left: 4px solid #ccc;
            background: #f8f9fa;
            border-radius: 8px;
            transition: all 0.3s;
        }

        .vulnerability:hover {
            background: #e9ecef;
            transform: translateX(5px);
        }

        .vulnerability.critical { border-left-color: #dc3545; }
        .vulnerability.high { border-left-color: #fd7e14; }
        .vulnerability.medium { border-left-color: #ffc107; }
        .vulnerability.low { border-left-color: #28a745; }
        .vulnerability.info { border-left-color: #17a2b8; }

        .vuln-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 10px;
        }

        .vuln-title {
            font-weight: bold;
            font-size: 1.1em;
            color: #333;
        }

        .severity-badge {
            padding: 4px 12px;
            border-radius: 12px;
            font-size: 0.85em;
            font-weight: bold;
            color: white;
        }

        .severity-badge.critical { background: #dc3545; }
        .severity-badge.high { background: #fd7e14; }
        .severity-badge.medium { background: #ffc107; color: #333; }
        .severity-badge.low { background: #28a745; }
        .severity-badge.info { background: #17a2b8; }

        .vuln-detail {
            margin: 5px 0;
            font-size: 0.95em;
            color: #555;
        }

        .vuln-url {
            color: #667eea;
            text-decoration: none;
            word-break: break-all;
        }

        .vuln-url:hover {
            text-decoration: underline;
        }

        .last-update {
            text-align: center;
            color: white;
            margin-top: 20px;
            font-size: 0.9em;
            opacity: 0.8;
        }

        .loading {
            text-align: center;
            padding: 40px;
            color: #666;
        }

        .spinner {
            border: 4px solid #f3f3f3;
            border-top: 4px solid #667eea;
            border-radius: 50%;
            width: 40px;
            height: 40px;
            animation: spin 1s linear infinite;
            margin: 20px auto;
        }

        @keyframes spin {
            0% { transform: rotate(0deg); }
            100% { transform: rotate(360deg); }
        }

        .no-results {
            text-align: center;
            padding: 40px;
            color: #666;
            font-style: italic;
        }

        .filter-controls {
            margin-bottom: 20px;
            display: flex;
            gap: 10px;
            flex-wrap: wrap;
        }

        .filter-btn {
            padding: 8px 16px;
            border: 2px solid #667eea;
            background: white;
            color: #667eea;
            border-radius: 20px;
            cursor: pointer;
            font-weight: bold;
            transition: all 0.3s;
        }

        .filter-btn:hover {
            background: #667eea;
            color: white;
        }

        .filter-btn.active {
            background: #667eea;
            color: white;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🛡️ Live Scan Report</h1>
            <div id="statusBadge" class="status-badge status-running">⏳ Scanning...</div>
        </div>

        <div class="stats-grid">
            <div class="stat-card">
                <h3 id="criticalCount" class="critical">0</h3>
                <p>Critical</p>
            </div>
            <div class="stat-card">
                <h3 id="highCount" class="high">0</h3>
                <p>High</p>
            </div>
            <div class="stat-card">
                <h3 id="mediumCount" class="medium">0</h3>
                <p>Medium</p>
            </div>
            <div class="stat-card">
                <h3 id="lowCount" class="low">0</h3>
                <p>Low</p>
            </div>
            <div class="stat-card">
                <h3 id="infoCount" class="info">0</h3>
                <p>Info</p>
            </div>
        </div>

        <div class="progress-section">
            <h3>Scan Progress</h3>
            <div class="progress-bar">
                <div id="progressFill" class="progress-fill" style="width: 0%;">0%</div>
            </div>
            <p style="margin-top: 10px; color: #666;" id="progressText">Initializing...</p>
        </div>

        <div class="results-section">
            <h2>Vulnerabilities Found (<span id="vulnCount">0</span>)</h2>

            <div class="filter-controls">
                <button class="filter-btn active" onclick="filterResults('all')">All</button>
                <button class="filter-btn" onclick="filterResults('critical')">Critical</button>
                <button class="filter-btn" onclick="filterResults('high')">High</button>
                <button class="filter-btn" onclick="filterResults('medium')">Medium</button>
                <button class="filter-btn" onclick="filterResults('low')">Low</button>
                <button class="filter-btn" onclick="filterResults('info')">Info</button>
            </div>

            <div id="results">
                <div class="loading">
                    <div class="spinner"></div>
                    <p>Waiting for scan results...</p>
                </div>
            </div>
        </div>

        <div class="last-update" id="lastUpdate">
            Last updated: Never
        </div>
    </div>

    <script>
        let currentFilter = 'all';
        let allResults = [];

        // Auto-refresh every 2 seconds
        setInterval(loadData, 2000);

        // Load data immediately
        loadData();

        function loadData() {
            fetch('live_scan_data.json?' + new Date().getTime())
                .then(response => response.json())
                .then(data => {
                    updateStats(data.stats);
                    updateProgress(data.scan_info);
                    updateResults(data.results);
                    updateStatus(data.scan_info.status);
                    updateLastUpdate();
                })
                .catch(error => {
                    console.error('Error loading data:', error);
                });
        }

        function updateStats(stats) {
            document.getElementById('criticalCount').textContent = stats.critical;
            document.getElementById('highCount').textContent = stats.high;
            document.getElementById('mediumCount').textContent = stats.medium;
            document.getElementById('lowCount').textContent = stats.low;
            document.getElementById('infoCount').textContent = stats.info;
        }

        function updateProgress(scanInfo) {
            const total = scanInfo.modules_total;
            const completed = scanInfo.modules_completed;
            const percentage = total > 0 ? Math.round((completed / total) * 100) : 0;

            document.getElementById('progressFill').style.width = percentage + '%';
            document.getElementById('progressFill').textContent = percentage + '%';
            document.getElementById('progressText').textContent =
                `Modules: ${completed}/${total} completed`;
        }

        function updateResults(results) {
            allResults = results.filter(r => r.vulnerability);
            document.getElementById('vulnCount').textContent = allResults.length;

            filterResults(currentFilter);
        }

        function filterResults(severity) {
            currentFilter = severity;

            // Update active button
            document.querySelectorAll('.filter-btn').forEach(btn => {
                btn.classList.remove('active');
            });
            event.target.classList.add('active');

            // Filter results
            const filtered = severity === 'all'
                ? allResults
                : allResults.filter(r => r.severity && r.severity.toLowerCase() === severity);

            renderResults(filtered);
        }

        function renderResults(results) {
            const container = document.getElementById('results');

            if (results.length === 0) {
                container.innerHTML = '<div class="no-results">No vulnerabilities found yet...</div>';
                return;
            }

            container.innerHTML = results.map((result, index) => {
                const severity = (result.severity || 'info').toLowerCase();
                const module = escapeHtml(result.module || result.type || 'Unknown');
                const url = escapeHtml(result.url || 'N/A');
                const parameter = result.parameter ? escapeHtml(result.parameter) : null;
                const payload = result.payload ? escapeHtml(result.payload) : null;

                return `
                    <div class="vulnerability ${severity}">
                        <div class="vuln-header">
                            <div class="vuln-title">${module}</div>
                            <div class="severity-badge ${severity}">${result.severity || 'Info'}</div>
                        </div>
                        <div class="vuln-detail">
                            <strong>URL:</strong> <a href="${url}" target="_blank" class="vuln-url">${url}</a>
                        </div>
                        ${parameter ? `<div class="vuln-detail"><strong>Parameter:</strong> ${parameter}</div>` : ''}
                        ${payload ? `<div class="vuln-detail"><strong>Payload:</strong> <code>${payload}</code></div>` : ''}
                    </div>
                `;
            }).join('');
        }

        function updateStatus(status) {
            const badge = document.getElementById('statusBadge');
            if (status === 'completed') {
                badge.className = 'status-badge status-completed';
                badge.textContent = '✓ Scan Completed';
            } else {
                badge.className = 'status-badge status-running';
                badge.textContent = '⏳ Scanning...';
            }
        }

        function updateLastUpdate() {
            const now = new Date();
            document.getElementById('lastUpdate').textContent =
                'Last updated: ' + now.toLocaleTimeString();
        }

        function escapeHtml(text) {
            const div = document.createElement('div');
            div.textContent = text;
            return div.innerHTML;
        }
    </script>
</body>
</html>"""

        with open(self.html_file, 'w', encoding='utf-8') as f:
            f.write(html_content)
