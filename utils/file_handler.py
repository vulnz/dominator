"""
File handling utilities
"""

import json
import xml.etree.ElementTree as ET
from typing import List, Dict, Any
import os

class FileHandler:
    """File handling class"""
    
    def save_json(self, data: List[Dict[str, Any]], filename: str):
        """Save in JSON format"""
        with open(filename, 'w', encoding='utf-8') as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
    
    def save_xml(self, data: List[Dict[str, Any]], filename: str):
        """Save in XML format"""
        root = ET.Element("scan_results")
        
        for item in data:
            vuln = ET.SubElement(root, "vulnerability")
            for key, value in item.items():
                elem = ET.SubElement(vuln, key)
                elem.text = str(value)
        
        tree = ET.ElementTree(root)
        tree.write(filename, encoding='utf-8', xml_declaration=True)
    
    def save_txt(self, data: List[Dict[str, Any]], filename: str):
        """Save in text format"""
        with open(filename, 'w', encoding='utf-8') as f:
            f.write("Web Vulnerability Scanner Report\n")
            f.write("=" * 50 + "\n\n")
            
            if not data:
                f.write("No vulnerabilities found\n")
                return
            
            for i, item in enumerate(data, 1):
                f.write(f"{i}. {item.get('vulnerability', 'Unknown')}\n")
                f.write(f"   Target: {item.get('target', '')}\n")
                f.write(f"   Module: {item.get('module', '')}\n")
                f.write(f"   Severity: {item.get('severity', '')}\n")
                f.write(f"   Parameter: {item.get('parameter', '')}\n")
                f.write(f"   Payload: {item.get('payload', '')}\n")
                f.write("-" * 40 + "\n")
    
    def save_html(self, data: List[Dict[str, Any]], filename: str):
        """Save data as advanced HTML report"""
        import json
        import time
        
        # Prepare data for the template
        vulnerabilities = []
        scan_stats = {}
        
        for item in data:
            if 'scan_stats' in item:
                scan_stats = item['scan_stats']
                continue
            
            # Process screenshot if present
            screenshot_base64 = None
            if item.get('screenshot'):
                try:
                    import os
                    import base64
                    screenshot_path = os.path.join('screenshots', item['screenshot'])
                    if os.path.exists(screenshot_path):
                        with open(screenshot_path, "rb") as img_file:
                            screenshot_base64 = base64.b64encode(img_file.read()).decode('utf-8')
                except Exception as e:
                    print(f"Error processing screenshot: {e}")
            
            vuln_data = {
                'vulnerability': item.get('vulnerability', 'Unknown'),
                'target': item.get('target', ''),
                'severity': item.get('severity', 'Unknown'),
                'parameter': item.get('parameter', ''),
                'module': item.get('module', 'unknown'),
                'evidence': self._escape_html(item.get('evidence', '')),
                'payload': self._escape_html(str(item.get('payload', ''))),
                'request_url': item.get('request_url', ''),
                'response_snippet': self._escape_html(item.get('response_snippet', '')),
                'remediation': self._escape_html(item.get('remediation', '')),
                'detector': item.get('detector', 'Unknown'),
                'screenshot': item.get('screenshot'),
                'screenshot_base64': screenshot_base64
            }
            vulnerabilities.append(vuln_data)
        
        # Prepare report data
        report_data = {
            'vulnerabilities': vulnerabilities,
            'scan_stats': scan_stats
        }
        
        # Get advanced HTML template
        template = self._get_advanced_html_template()
        html_content = template.replace('{report_data}', json.dumps(report_data, ensure_ascii=False))
        
        with open(filename, 'w', encoding='utf-8') as f:
            f.write(html_content)
    
    def _get_success_indicators(self) -> List[str]:
        """Get indicators of successful form submission"""
        return [
            # English indicators
            'success', 'successful', 'updated', 'created', 'deleted',
            'saved', 'submitted', 'processed', 'completed', 'done',
            'thank you', 'thanks', 'welcome', 'logged in', 'registered',
            
            # Common response patterns
            'operation completed', 'request processed', 'data saved',
            'changes saved', 'profile updated', 'password changed',
            
            # Error absence indicators
            'no error', 'valid', 'accepted', 'approved'
        ]
    
    def _escape_html(self, text: str) -> str:
        """Escape HTML characters"""
        return (text.replace('&', '&amp;')
                   .replace('<', '&lt;')
                   .replace('>', '&gt;')
                   .replace('"', '&quot;')
                   .replace("'", '&#x27;'))
    
    def _get_advanced_html_template(self) -> str:
        """Get advanced HTML report template"""
        return """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Dominator Security Scan Report</title>
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css" rel="stylesheet">
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: #f5f7fa;
            color: #333;
            line-height: 1.6;
        }
        
        .header {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 2rem 0;
            text-align: center;
            box-shadow: 0 4px 6px rgba(0,0,0,0.1);
        }
        
        .header h1 {
            font-size: 2.5rem;
            margin-bottom: 0.5rem;
            font-weight: 300;
        }
        
        .header p {
            font-size: 1.1rem;
            opacity: 0.9;
        }
        
        .container {
            max-width: 1400px;
            margin: 0 auto;
            padding: 0 20px;
        }
        
        .dashboard {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 20px;
            margin: 30px 0;
        }
        
        .stat-card {
            background: white;
            padding: 25px;
            border-radius: 10px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
            text-align: center;
            transition: transform 0.3s ease;
        }
        
        .stat-card:hover {
            transform: translateY(-5px);
        }
        
        .stat-card .icon {
            font-size: 2.5rem;
            margin-bottom: 15px;
        }
        
        .stat-card.high .icon { color: #e74c3c; }
        .stat-card.medium .icon { color: #f39c12; }
        .stat-card.low .icon { color: #3498db; }
        .stat-card.info .icon { color: #2ecc71; }
        
        .stat-card h3 {
            font-size: 2rem;
            margin-bottom: 10px;
            font-weight: 600;
        }
        
        .stat-card p {
            color: #666;
            font-size: 0.9rem;
        }
        
        .filters {
            background: white;
            padding: 20px;
            border-radius: 10px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
            margin: 20px 0;
            display: flex;
            flex-wrap: wrap;
            gap: 15px;
            align-items: center;
        }
        
        .filter-group {
            display: flex;
            align-items: center;
            gap: 10px;
        }
        
        .filter-group label {
            font-weight: 500;
            color: #555;
        }
        
        .filter-select, .filter-input {
            padding: 8px 12px;
            border: 2px solid #e1e8ed;
            border-radius: 6px;
            font-size: 14px;
            transition: border-color 0.3s ease;
        }
        
        .filter-select:focus, .filter-input:focus {
            outline: none;
            border-color: #667eea;
        }
        
        .vulnerabilities {
            background: white;
            border-radius: 10px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
            overflow: hidden;
        }
        
        .vuln-header {
            background: #f8f9fa;
            padding: 20px;
            border-bottom: 1px solid #e9ecef;
        }
        
        .vuln-header h2 {
            color: #333;
            font-size: 1.5rem;
            margin-bottom: 10px;
        }
        
        .vuln-item {
            border-bottom: 1px solid #e9ecef;
            transition: background-color 0.3s ease;
        }
        
        .vuln-item:hover {
            background-color: #f8f9fa;
        }
        
        .vuln-summary {
            padding: 20px;
            cursor: pointer;
            display: flex;
            align-items: center;
            justify-content: space-between;
        }
        
        .vuln-info {
            flex: 1;
        }
        
        .vuln-title {
            font-size: 1.1rem;
            font-weight: 600;
            margin-bottom: 5px;
            color: #333;
        }
        
        .vuln-meta {
            display: flex;
            gap: 15px;
            font-size: 0.9rem;
            color: #666;
        }
        
        .severity-badge {
            padding: 4px 12px;
            border-radius: 20px;
            font-size: 0.8rem;
            font-weight: 600;
            text-transform: uppercase;
        }
        
        .severity-high { background: #fee; color: #c53030; }
        .severity-medium { background: #fff3cd; color: #b45309; }
        .severity-low { background: #e3f2fd; color: #1565c0; }
        .severity-info { background: #e8f5e8; color: #2d7d32; }
        
        .vuln-details {
            display: none;
            padding: 0 20px 20px;
            background: #f8f9fa;
        }
        
        .vuln-details.active {
            display: block;
        }
        
        .detail-section {
            margin-bottom: 20px;
        }
        
        .detail-section h4 {
            color: #333;
            margin-bottom: 10px;
            font-size: 1rem;
            font-weight: 600;
        }
        
        .detail-content {
            background: white;
            padding: 15px;
            border-radius: 6px;
            border-left: 4px solid #667eea;
            font-family: 'Courier New', monospace;
            font-size: 0.9rem;
            line-height: 1.4;
            overflow-x: auto;
        }
        
        .screenshot {
            max-width: 100%;
            border-radius: 6px;
            box-shadow: 0 2px 8px rgba(0,0,0,0.1);
            margin: 10px 0;
        }
        
        .tech-grid {
            display: grid;
            grid-template-columns: repeat(auto-fill, minmax(200px, 1fr));
            gap: 15px;
            margin: 20px 0;
        }
        
        .tech-item {
            background: white;
            padding: 15px;
            border-radius: 8px;
            box-shadow: 0 2px 5px rgba(0,0,0,0.1);
            text-align: center;
        }
        
        .tech-item .tech-name {
            font-weight: 600;
            color: #333;
            margin-bottom: 5px;
        }
        
        .tech-item .tech-version {
            color: #666;
            font-size: 0.9rem;
        }
        
        .expand-icon {
            transition: transform 0.3s ease;
        }
        
        .expand-icon.rotated {
            transform: rotate(180deg);
        }
        
        .no-results {
            text-align: center;
            padding: 40px;
            color: #666;
        }
        
        .footer {
            background: #333;
            color: white;
            text-align: center;
            padding: 20px 0;
            margin-top: 40px;
        }
        
        @media (max-width: 768px) {
            .dashboard {
                grid-template-columns: 1fr;
            }
            
            .filters {
                flex-direction: column;
                align-items: stretch;
            }
            
            .vuln-meta {
                flex-direction: column;
                gap: 5px;
            }
        }
    </style>
</head>
<body>
    <div class="header">
        <div class="container">
            <h1><i class="fas fa-shield-alt"></i> Dominator Security Report</h1>
            <p>Comprehensive Web Application Security Assessment</p>
        </div>
    </div>
    
    <div class="container">
        <!-- Dashboard Stats -->
        <div class="dashboard">
            <div class="stat-card high">
                <div class="icon"><i class="fas fa-exclamation-triangle"></i></div>
                <h3 id="high-count">0</h3>
                <p>High Severity</p>
            </div>
            <div class="stat-card medium">
                <div class="icon"><i class="fas fa-exclamation-circle"></i></div>
                <h3 id="medium-count">0</h3>
                <p>Medium Severity</p>
            </div>
            <div class="stat-card low">
                <div class="icon"><i class="fas fa-info-circle"></i></div>
                <h3 id="low-count">0</h3>
                <p>Low Severity</p>
            </div>
            <div class="stat-card info">
                <div class="icon"><i class="fas fa-cog"></i></div>
                <h3 id="info-count">0</h3>
                <p>Informational</p>
            </div>
        </div>
        
        <!-- Scan Information -->
        <div class="stat-card" style="margin-bottom: 20px;">
            <h3>Scan Summary</h3>
            <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 20px; margin-top: 15px; text-align: left;">
                <div><strong>Duration:</strong> <span id="scan-duration">-</span></div>
                <div><strong>URLs Tested:</strong> <span id="urls-tested">-</span></div>
                <div><strong>Parameters:</strong> <span id="params-tested">-</span></div>
                <div><strong>Requests:</strong> <span id="requests-made">-</span></div>
            </div>
        </div>
        
        <!-- Technology Detection -->
        <div id="tech-section" class="vulnerabilities" style="margin-bottom: 20px; display: none;">
            <div class="vuln-header">
                <h2><i class="fas fa-microchip"></i> Detected Technologies</h2>
            </div>
            <div class="tech-grid" id="tech-grid">
                <!-- Technologies will be populated here -->
            </div>
        </div>
        
        <!-- Filters -->
        <div class="filters">
            <div class="filter-group">
                <label for="severity-filter">Severity:</label>
                <select id="severity-filter" class="filter-select">
                    <option value="">All Severities</option>
                    <option value="High">High</option>
                    <option value="Medium">Medium</option>
                    <option value="Low">Low</option>
                    <option value="Info">Info</option>
                </select>
            </div>
            <div class="filter-group">
                <label for="module-filter">Module:</label>
                <select id="module-filter" class="filter-select">
                    <option value="">All Modules</option>
                </select>
            </div>
            <div class="filter-group">
                <label for="search-filter">Search:</label>
                <input type="text" id="search-filter" class="filter-input" placeholder="Search vulnerabilities...">
            </div>
        </div>
        
        <!-- Vulnerabilities List -->
        <div class="vulnerabilities">
            <div class="vuln-header">
                <h2><i class="fas fa-bug"></i> Vulnerabilities Found</h2>
                <p>Click on any vulnerability to view detailed information</p>
            </div>
            <div id="vulnerabilities-list">
                <!-- Vulnerabilities will be populated here -->
            </div>
        </div>
    </div>
    
    <div class="footer">
        <div class="container">
            <p>&copy; 2024 Dominator Web Security Scanner. Generated on <span id="report-date"></span></p>
        </div>
    </div>
    
    <script>
        // Report data will be injected here
        const reportData = {report_data};
        
        // Initialize report
        document.addEventListener('DOMContentLoaded', function() {
            initializeReport();
        });
        
        function initializeReport() {
            populateStats();
            populateTechnologies();
            populateVulnerabilities();
            setupFilters();
            setupEventListeners();
            
            // Set report date
            document.getElementById('report-date').textContent = new Date().toLocaleString();
        }
        
        function populateStats() {
            const stats = reportData.scan_stats || {};
            const vulnerabilities = reportData.vulnerabilities || [];
            
            // Count by severity
            const counts = {
                high: vulnerabilities.filter(v => v.severity === 'High').length,
                medium: vulnerabilities.filter(v => v.severity === 'Medium').length,
                low: vulnerabilities.filter(v => v.severity === 'Low').length,
                info: vulnerabilities.filter(v => v.severity === 'Info').length
            };
            
            document.getElementById('high-count').textContent = counts.high;
            document.getElementById('medium-count').textContent = counts.medium;
            document.getElementById('low-count').textContent = counts.low;
            document.getElementById('info-count').textContent = counts.info;
            
            // Scan stats
            document.getElementById('scan-duration').textContent = stats.scan_duration || '-';
            document.getElementById('urls-tested').textContent = stats.total_urls || '-';
            document.getElementById('params-tested').textContent = stats.total_params || '-';
            document.getElementById('requests-made').textContent = stats.total_requests || '-';
        }
        
        function populateTechnologies() {
            const technologies = reportData.scan_stats?.technologies || {};
            const techGrid = document.getElementById('tech-grid');
            const techSection = document.getElementById('tech-section');
            
            let hasAnyTech = false;
            
            for (const [domain, techs] of Object.entries(technologies)) {
                if (techs && techs.length > 0) {
                    hasAnyTech = true;
                    techs.forEach(tech => {
                        const techItem = document.createElement('div');
                        techItem.className = 'tech-item';
                        techItem.innerHTML = `
                            <div class="tech-name">${tech.name}</div>
                            <div class="tech-version">${tech.version || 'Unknown Version'}</div>
                            <div style="font-size: 0.8rem; color: #888; margin-top: 5px;">
                                ${tech.category} (${tech.confidence}%)
                            </div>
                        `;
                        techGrid.appendChild(techItem);
                    });
                }
            }
            
            if (hasAnyTech) {
                techSection.style.display = 'block';
            }
        }
        
        function populateVulnerabilities() {
            const vulnerabilities = reportData.vulnerabilities || [];
            const container = document.getElementById('vulnerabilities-list');
            
            if (vulnerabilities.length === 0) {
                container.innerHTML = '<div class="no-results"><i class="fas fa-check-circle" style="font-size: 3rem; color: #2ecc71; margin-bottom: 15px;"></i><h3>No Vulnerabilities Found</h3><p>The scan completed successfully with no security issues detected.</p></div>';
                return;
            }
            
            // Populate module filter
            const modules = [...new Set(vulnerabilities.map(v => v.module))];
            const moduleFilter = document.getElementById('module-filter');
            modules.forEach(module => {
                const option = document.createElement('option');
                option.value = module;
                option.textContent = module.toUpperCase();
                moduleFilter.appendChild(option);
            });
            
            vulnerabilities.forEach((vuln, index) => {
                const vulnElement = createVulnerabilityElement(vuln, index);
                container.appendChild(vulnElement);
            });
        }
        
        function createVulnerabilityElement(vuln, index) {
            const vulnDiv = document.createElement('div');
            vulnDiv.className = 'vuln-item';
            vulnDiv.dataset.severity = vuln.severity;
            vulnDiv.dataset.module = vuln.module;
            vulnDiv.dataset.searchText = `${vuln.vulnerability} ${vuln.target} ${vuln.parameter} ${vuln.evidence}`.toLowerCase();
            
            vulnDiv.innerHTML = `
                <div class="vuln-summary" onclick="toggleDetails(${index})">
                    <div class="vuln-info">
                        <div class="vuln-title">${vuln.vulnerability}</div>
                        <div class="vuln-meta">
                            <span><i class="fas fa-globe"></i> ${vuln.target}</span>
                            <span><i class="fas fa-tag"></i> ${vuln.parameter}</span>
                            <span><i class="fas fa-cog"></i> ${vuln.module.toUpperCase()}</span>
                        </div>
                    </div>
                    <div style="display: flex; align-items: center; gap: 15px;">
                        <span class="severity-badge severity-${vuln.severity.toLowerCase()}">${vuln.severity}</span>
                        <i class="fas fa-chevron-down expand-icon" id="icon-${index}"></i>
                    </div>
                </div>
                <div class="vuln-details" id="details-${index}">
                    <div class="detail-section">
                        <h4><i class="fas fa-info-circle"></i> Evidence</h4>
                        <div class="detail-content">${vuln.evidence}</div>
                    </div>
                    <div class="detail-section">
                        <h4><i class="fas fa-code"></i> Payload</h4>
                        <div class="detail-content">${vuln.payload}</div>
                    </div>
                    <div class="detail-section">
                        <h4><i class="fas fa-link"></i> Request URL</h4>
                        <div class="detail-content">${vuln.request_url}</div>
                    </div>
                    ${vuln.response_snippet ? `
                    <div class="detail-section">
                        <h4><i class="fas fa-file-code"></i> Response Snippet</h4>
                        <div class="detail-content">${vuln.response_snippet}</div>
                    </div>
                    ` : ''}
                    ${vuln.screenshot_base64 ? `
                    <div class="detail-section">
                        <h4><i class="fas fa-camera"></i> Proof of Concept Screenshot</h4>
                        <img src="data:image/png;base64,${vuln.screenshot_base64}" class="screenshot" alt="Vulnerability Screenshot">
                    </div>
                    ` : ''}
                    ${vuln.remediation ? `
                    <div class="detail-section">
                        <h4><i class="fas fa-tools"></i> Remediation</h4>
                        <div class="detail-content">${vuln.remediation}</div>
                    </div>
                    ` : ''}
                    <div class="detail-section">
                        <h4><i class="fas fa-search"></i> Detection Method</h4>
                        <div class="detail-content">${vuln.detector}</div>
                    </div>
                </div>
            `;
            
            return vulnDiv;
        }
        
        function toggleDetails(index) {
            const details = document.getElementById(`details-${index}`);
            const icon = document.getElementById(`icon-${index}`);
            
            details.classList.toggle('active');
            icon.classList.toggle('rotated');
        }
        
        function setupFilters() {
            const severityFilter = document.getElementById('severity-filter');
            const moduleFilter = document.getElementById('module-filter');
            const searchFilter = document.getElementById('search-filter');
            
            [severityFilter, moduleFilter, searchFilter].forEach(filter => {
                filter.addEventListener('change', applyFilters);
                filter.addEventListener('input', applyFilters);
            });
        }
        
        function applyFilters() {
            const severityFilter = document.getElementById('severity-filter').value;
            const moduleFilter = document.getElementById('module-filter').value;
            const searchFilter = document.getElementById('search-filter').value.toLowerCase();
            
            const vulnItems = document.querySelectorAll('.vuln-item');
            
            vulnItems.forEach(item => {
                let show = true;
                
                if (severityFilter && item.dataset.severity !== severityFilter) {
                    show = false;
                }
                
                if (moduleFilter && item.dataset.module !== moduleFilter) {
                    show = false;
                }
                
                if (searchFilter && !item.dataset.searchText.includes(searchFilter)) {
                    show = false;
                }
                
                item.style.display = show ? 'block' : 'none';
            });
        }
        
        function setupEventListeners() {
            // Add any additional event listeners here
        }
    </script>
</body>
</html>
        """
    
    def read_file_lines(self, filename: str) -> List[str]:
        """Read lines from file"""
        if not os.path.exists(filename):
            return []
        
        with open(filename, 'r', encoding='utf-8') as f:
            return [line.strip() for line in f if line.strip()]
