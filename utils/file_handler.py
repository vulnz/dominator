"""
File handling utilities
"""

import json
import xml.etree.ElementTree as ET
from typing import List, Dict, Any
import os

class FileHandler:
    """File handling class"""
    
    
    def save_html(self, data: List[Dict[str, Any]], filename: str):
        """Save data as advanced HTML report with enhanced features"""
        import json
        import time
        
        # Prepare data for the template
        vulnerabilities = []
        scan_stats = {}
        
        print(f"[DEBUG] save_html: Processing {len(data)} items")
        for i, item in enumerate(data):
            print(f"[DEBUG] Item {i}: keys = {list(item.keys()) if isinstance(item, dict) else 'not dict'}")
            
            # Extract scan_stats but don't skip processing this item yet
            if 'scan_stats' in item:
                scan_stats = item['scan_stats']
                print(f"[DEBUG] Found scan_stats in item {i}")
                # Don't continue here - check if this item also has vulnerability data
            
            # Check if this item has vulnerability data
            if 'vulnerability' in item and item.get('vulnerability'):
                print(f"[DEBUG] Found vulnerability in item {i}: {item.get('vulnerability', 'UNKNOWN')}")
                # Process this vulnerability even if it also has scan_stats
            else:
                print(f"[DEBUG] Skipping item {i}: no vulnerability field or empty vulnerability")
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
                'screenshot_base64': screenshot_base64,
                'cve_links': item.get('cve_links', []),
                'exploit_links': item.get('exploit_links', []),
                'technologies': item.get('technologies', [])
            }
            vulnerabilities.append(vuln_data)
        
        # Deduplicate technologies across all vulnerabilities
        all_technologies = set()
        for vuln in vulnerabilities:
            if vuln.get('technologies'):
                all_technologies.update(vuln['technologies'])
        
        # Update scan_stats with deduplicated technologies
        if 'technologies' not in scan_stats:
            scan_stats['technologies'] = {}
        
        # Group technologies by domain and deduplicate
        tech_by_domain = {}
        for vuln in vulnerabilities:
            if vuln.get('target'):
                from urllib.parse import urlparse
                try:
                    parsed = urlparse(vuln['target'])
                    domain = parsed.netloc
                    if domain not in tech_by_domain:
                        tech_by_domain[domain] = set()
                    if vuln.get('technologies'):
                        tech_by_domain[domain].update(vuln['technologies'])
                except:
                    pass
        
        # Convert sets to lists for JSON serialization
        for domain in tech_by_domain:
            tech_by_domain[domain] = list(tech_by_domain[domain])
        
        scan_stats['technologies'] = tech_by_domain
        
        # Prepare report data
        report_data = {
            'vulnerabilities': vulnerabilities,
            'scan_stats': scan_stats,
            'filetree_enabled': getattr(self, 'config', None) and getattr(self.config, 'filetree', False)
        }
        
        print(f"[DEBUG] Final report_data: {len(vulnerabilities)} vulnerabilities")
        if vulnerabilities:
            for i, v in enumerate(vulnerabilities[:3]):
                print(f"[DEBUG] Vuln {i+1}: {v.get('vulnerability', 'NO_VULN')} - {v.get('severity', 'NO_SEV')}")
        else:
            print(f"[DEBUG] WARNING: No vulnerabilities found for HTML report!")
            print(f"[DEBUG] Original data items: {len(data)}")
            for i, item in enumerate(data):
                print(f"[DEBUG] Item {i} keys: {list(item.keys()) if isinstance(item, dict) else 'not dict'}")
                if isinstance(item, dict) and 'vulnerability' in item:
                    print(f"[DEBUG] Item {i} vulnerability: '{item.get('vulnerability', 'EMPTY')}'")
        
        # Get advanced HTML template
        template = self._get_advanced_html_template()
        
        # Debug: Show what we're putting into the template
        print(f"[DEBUG] About to insert into template: vulnerabilities={len(report_data['vulnerabilities'])}")
        
        html_content = template.replace('{report_data}', json.dumps(report_data, ensure_ascii=False, indent=2))
        
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
        """Get advanced HTML report template with enhanced features"""
        return """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Dominator Security Scan Report</title>
    <link rel="icon" type="image/x-icon" id="dynamic-favicon">
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
        
        .stat-card.critical .icon { color: #8b0000; }
        .stat-card.high .icon { color: #e74c3c; }
        .stat-card.medium .icon { color: #f39c12; }
        .stat-card.low .icon { color: #3498db; }
        .stat-card.info .icon { color: #2ecc71; }
        
        .executive-summary {
            background: white;
            border-radius: 15px;
            box-shadow: 0 4px 20px rgba(0,0,0,0.1);
            margin: 30px 0;
            overflow: hidden;
        }
        
        .summary-header {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 30px;
            text-align: center;
        }
        
        .summary-header h2 {
            font-size: 2rem;
            margin-bottom: 10px;
            font-weight: 300;
        }
        
        .summary-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
            gap: 0;
        }
        
        .summary-card {
            padding: 30px;
            border-right: 1px solid #e9ecef;
            min-height: 250px;
            display: flex;
            align-items: center;
            justify-content: center;
        }
        
        .summary-card:last-child {
            border-right: none;
        }
        
        .summary-content {
            text-align: center;
            width: 100%;
        }
        
        .summary-content h3 {
            color: #333;
            margin-bottom: 20px;
            font-size: 1.3rem;
        }
        
        .risk-meter {
            width: 120px;
            height: 120px;
            border-radius: 50%;
            margin: 0 auto 20px;
            display: flex;
            align-items: center;
            justify-content: center;
            position: relative;
            background: conic-gradient(from 0deg, #2ecc71 0deg 90deg, #f39c12 90deg 180deg, #e74c3c 180deg 270deg, #8b0000 270deg 360deg);
        }
        
        .risk-level {
            width: 80px;
            height: 80px;
            background: white;
            border-radius: 50%;
            display: flex;
            align-items: center;
            justify-content: center;
            font-weight: bold;
            font-size: 0.9rem;
        }
        
        .chart-container {
            width: 200px;
            height: 200px;
            margin: 0 auto;
            position: relative;
        }
        
        .severity-critical { background: #8b0000; color: white; }
        .severity-high { background: #fee; color: #c53030; }
        .severity-medium { background: #fff3cd; color: #b45309; }
        .severity-low { background: #e3f2fd; color: #1565c0; }
        .severity-info { background: #e8f5e8; color: #2d7d32; }
        
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
        
        /* Scope Section Styles */
        .scope-section {
            background: linear-gradient(135deg, #f8f9fa 0%, #e9ecef 100%);
            border-radius: 15px;
            padding: 25px;
            margin: 25px 0;
            box-shadow: 0 4px 15px rgba(0,0,0,0.1);
        }
        
        .scope-header {
            background: linear-gradient(135deg, #28a745 0%, #20c997 100%);
            color: white;
            padding: 20px;
            border-radius: 10px;
            text-align: center;
            margin-bottom: 20px;
        }
        
        .scope-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
            gap: 20px;
        }
        
        .scope-item {
            background: white;
            padding: 20px;
            border-radius: 10px;
            border-left: 4px solid #28a745;
            box-shadow: 0 2px 8px rgba(0,0,0,0.1);
        }
        
        .scope-label {
            font-weight: bold;
            color: #28a745;
            margin-bottom: 10px;
            font-size: 1.1em;
        }
        
        .target-badge, .module-badge, .tech-badge {
            display: inline-block;
            padding: 6px 12px;
            margin: 3px;
            border-radius: 20px;
            font-size: 0.85em;
            font-weight: 500;
            text-decoration: none;
            transition: all 0.3s ease;
        }
        
        .target-badge {
            background: linear-gradient(135deg, #007bff, #0056b3);
            color: white;
        }
        
        .module-badge {
            background: linear-gradient(135deg, #28a745, #1e7e34);
            color: white;
        }
        
        .tech-badge {
            background: linear-gradient(135deg, #17a2b8, #138496);
            color: white;
        }
        
        .target-badge:hover, .module-badge:hover, .tech-badge:hover {
            transform: translateY(-2px);
            box-shadow: 0 4px 8px rgba(0,0,0,0.2);
        }
        
        /* File Tree Styles */
        .filetree-section {
            background: #2d3748;
            color: #e2e8f0;
            border-radius: 15px;
            padding: 25px;
            margin: 25px 0;
            box-shadow: 0 4px 15px rgba(0,0,0,0.2);
        }
        
        .filetree-header {
            background: linear-gradient(135deg, #4a5568, #2d3748);
            color: white;
            padding: 20px;
            border-radius: 10px;
            text-align: center;
            margin-bottom: 20px;
        }
        
        .file-tree {
            font-family: 'Courier New', monospace;
            font-size: 0.9em;
            line-height: 1.6;
        }
        
        .tree-level {
            list-style: none;
            margin: 0;
            padding: 0;
        }
        
        .tree-item {
            margin: 3px 0;
            padding: 2px 0;
            transition: background-color 0.3s ease;
        }
        
        .tree-item:hover {
            background-color: rgba(255,255,255,0.1);
            border-radius: 4px;
            padding-left: 5px;
        }
        
        .folder-icon {
            color: #ffd700;
            margin-right: 8px;
        }
        
        .file-icon {
            color: #87ceeb;
            margin-right: 8px;
        }
        
        /* CVE and Exploit Link Styles */
        .cve-link, .exploit-link {
            display: inline-block;
            padding: 4px 8px;
            margin: 2px 4px;
            border-radius: 6px;
            text-decoration: none;
            font-weight: bold;
            font-size: 0.9em;
            transition: all 0.3s ease;
            border: 2px solid transparent;
        }
        
        .cve-link {
            background: linear-gradient(135deg, #007bff, #0056b3);
            color: white;
        }
        
        .cve-link:hover {
            background: linear-gradient(135deg, #0056b3, #004085);
            transform: translateY(-2px);
            box-shadow: 0 4px 8px rgba(0,123,255,0.3);
            border-color: #007bff;
        }
        
        .exploit-link {
            background: linear-gradient(135deg, #dc3545, #c82333);
            color: white;
        }
        
        .exploit-link:hover {
            background: linear-gradient(135deg, #c82333, #a71e2a);
            transform: translateY(-2px);
            box-shadow: 0 4px 8px rgba(220,53,69,0.3);
            border-color: #dc3545;
        }
        
        .cve-info, .exploit-info {
            color: #6c757d;
            font-size: 0.85em;
            margin-left: 5px;
        }
        
        /* Screenshot Thumbnail Styles */
        .screenshot-thumbnail {
            max-width: 200px;
            height: auto;
            border: 2px solid #dee2e6;
            border-radius: 8px;
            cursor: pointer;
            transition: all 0.3s ease;
            box-shadow: 0 2px 8px rgba(0,0,0,0.1);
        }
        
        .screenshot-thumbnail:hover {
            transform: scale(1.05);
            border-color: #007bff;
            box-shadow: 0 4px 15px rgba(0,123,255,0.3);
        }
        
        .screenshot-caption {
            font-size: 0.8em;
            color: #6c757d;
            margin-top: 8px;
            text-align: center;
            font-style: italic;
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
        <!-- Executive Summary -->
        <div class="executive-summary">
            <div class="summary-header">
                <h2><i class="fas fa-chart-pie"></i> Executive Summary</h2>
                <p>Comprehensive security assessment results and risk analysis</p>
            </div>
            
            <div class="summary-grid">
                <div class="summary-card">
                    <div class="summary-content">
                        <h3>Security Posture</h3>
                        <div class="risk-meter">
                            <div class="risk-level" id="risk-level">
                                <span class="risk-text" id="risk-text">Calculating...</span>
                            </div>
                        </div>
                        <p id="risk-description">Analyzing security findings...</p>
                    </div>
                </div>
                
                <div class="summary-card">
                    <div class="summary-content">
                        <h3>Vulnerability Distribution</h3>
                        <div class="chart-container">
                            <canvas id="severityChart" width="200" height="200"></canvas>
                        </div>
                    </div>
                </div>
                
                <div class="summary-card">
                    <div class="summary-content">
                        <h3>Testing Coverage</h3>
                        <div class="chart-container">
                            <canvas id="payloadChart" width="200" height="200"></canvas>
                        </div>
                    </div>
                </div>
            </div>
        </div>

        <!-- Dashboard Stats -->
        <div class="dashboard">
            <div class="stat-card critical">
                <div class="icon"><i class="fas fa-skull-crossbones"></i></div>
                <h3 id="critical-count">0</h3>
                <p>Critical Severity</p>
            </div>
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
                <div><strong>CVSS Score:</strong> <span id="max-cvss">-</span></div>
                <div><strong>OWASP Top 10:</strong> <span id="owasp-categories">-</span></div>
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
                    <option value="Critical">Critical</option>
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
            <p>&copy; 2025 Dominator Web Security Scanner. Generated on <span id="report-date"></span></p>
        </div>
    </div>
    
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <script>
        // Report data will be injected here
        const reportData = {report_data};
        
        // Initialize report
        document.addEventListener('DOMContentLoaded', function() {
            initializeReport();
        });
        
        function initializeReport() {
            console.log('Initializing report...');
            console.log('Report data:', reportData);
            console.log('Vulnerabilities count:', reportData.vulnerabilities ? reportData.vulnerabilities.length : 'undefined');
            
            // Set favicon from target
            setDynamicFavicon();
            
            // Generate scope section
            generateScopeSection();
            
            // Generate file tree if enabled
            if (reportData.filetree_enabled) {
                generateFileTreeSection();
            }
            
            populateStats();
            populateTechnologies();
            populateVulnerabilities();
            setupFilters();
            setupEventListeners();
            
            // Set report date
            document.getElementById('report-date').textContent = new Date().toLocaleString();
        }
        
        function setDynamicFavicon() {
            const vulnerabilities = reportData.vulnerabilities || [];
            if (vulnerabilities.length > 0) {
                const firstTarget = vulnerabilities[0].target;
                if (firstTarget) {
                    try {
                        const url = new URL(firstTarget);
                        const faviconUrl = `${url.protocol}//${url.host}/favicon.ico`;
                        document.getElementById('dynamic-favicon').href = faviconUrl;
                    } catch (e) {
                        console.log('Could not set dynamic favicon:', e);
                    }
                }
            }
        }
        
        function generateScopeSection() {
            const vulnerabilities = reportData.vulnerabilities || [];
            const scanStats = reportData.scan_stats || {};
            
            // Extract unique targets
            const targets = new Set();
            vulnerabilities.forEach(vuln => {
                if (vuln.target) {
                    try {
                        const url = new URL(vuln.target);
                        targets.add(`${url.protocol}//${url.host}`);
                    } catch (e) {
                        targets.add(vuln.target);
                    }
                }
            });
            
            // Get modules and technologies
            const modules = Object.keys(scanStats.module_stats || {});
            const technologies = scanStats.technologies || {};
            const allTechs = new Set();
            Object.values(technologies).forEach(domainTechs => {
                if (Array.isArray(domainTechs)) {
                    domainTechs.forEach(tech => allTechs.add(tech));
                }
            });
            
            let scopeHtml = `
                <div class="scope-section">
                    <div class="scope-header">
                        <h2><i class="fas fa-crosshairs"></i> Scan Scope</h2>
                        <p>Overview of targets, modules, and technologies analyzed</p>
                    </div>
                    <div class="scope-grid">
            `;
            
            // Targets
            if (targets.size > 0) {
                scopeHtml += `
                    <div class="scope-item">
                        <div class="scope-label"><i class="fas fa-globe"></i> Target Domains (${targets.size})</div>
                        <div class="scope-value">
                `;
                Array.from(targets).sort().forEach(target => {
                    scopeHtml += `<span class="target-badge">${target}</span>`;
                });
                scopeHtml += `</div></div>`;
            }
            
            // Modules
            if (modules.length > 0) {
                scopeHtml += `
                    <div class="scope-item">
                        <div class="scope-label"><i class="fas fa-cogs"></i> Security Modules (${modules.length})</div>
                        <div class="scope-value">
                `;
                modules.sort().forEach(module => {
                    scopeHtml += `<span class="module-badge">${module.toUpperCase()}</span>`;
                });
                scopeHtml += `</div></div>`;
            }
            
            // Technologies
            if (allTechs.size > 0) {
                scopeHtml += `
                    <div class="scope-item">
                        <div class="scope-label"><i class="fas fa-microchip"></i> Technologies Detected (${allTechs.size})</div>
                        <div class="scope-value">
                `;
                Array.from(allTechs).sort().forEach(tech => {
                    scopeHtml += `<span class="tech-badge">${tech}</span>`;
                });
                scopeHtml += `</div></div>`;
            }
            
            scopeHtml += `</div></div>`;
            
            // Insert before dashboard
            const dashboard = document.querySelector('.dashboard');
            if (dashboard) {
                dashboard.insertAdjacentHTML('beforebegin', scopeHtml);
            }
        }
        
        function generateFileTreeSection() {
            const scanStats = reportData.scan_stats || {};
            const filePaths = scanStats.file_tree_paths || [];
            
            if (filePaths.length === 0) return;
            
            // Build tree structure
            const tree = {};
            filePaths.forEach(path => {
                const parts = path.split('/').filter(part => part);
                let current = tree;
                parts.forEach(part => {
                    if (!current[part]) {
                        current[part] = {};
                    }
                    current = current[part];
                });
            });
            
            if (Object.keys(tree).length > 0) {
                let filetreeHtml = `
                    <div class="filetree-section">
                        <div class="filetree-header">
                            <h2><i class="fas fa-folder-tree"></i> File Tree Structure</h2>
                            <p>Discovered files and directories during scanning (${filePaths.length} paths)</p>
                        </div>
                        <div class="file-tree">
                            ${generateTreeHtml(tree, 0)}
                        </div>
                    </div>
                `;
                
                // Insert before vulnerabilities
                const vulnSection = document.querySelector('.vulnerabilities');
                if (vulnSection) {
                    vulnSection.insertAdjacentHTML('beforebegin', filetreeHtml);
                }
            }
        }
        
        function generateTreeHtml(tree, level) {
            let html = '<ul class="tree-level">';
            const entries = Object.entries(tree).sort();
            
            entries.forEach(([name, subtree]) => {
                const indent = level * 20;
                html += `<li class="tree-item" style="margin-left: ${indent}px;">`;
                
                if (Object.keys(subtree).length > 0) {
                    html += `<span class="folder-icon"><i class="fas fa-folder"></i></span><strong>${name}/</strong>`;
                    html += generateTreeHtml(subtree, level + 1);
                } else {
                    html += `<span class="file-icon"><i class="fas fa-file"></i></span>${name}`;
                }
                
                html += '</li>';
            });
            
            html += '</ul>';
            return html;
        }
        
        function populateStats() {
            const stats = reportData.scan_stats || {};
            const vulnerabilities = reportData.vulnerabilities || [];
            
            // Count by severity
            const counts = {
                critical: vulnerabilities.filter(v => v.severity === 'Critical').length,
                high: vulnerabilities.filter(v => v.severity === 'High').length,
                medium: vulnerabilities.filter(v => v.severity === 'Medium').length,
                low: vulnerabilities.filter(v => v.severity === 'Low').length,
                info: vulnerabilities.filter(v => v.severity === 'Info').length
            };
            
            document.getElementById('critical-count').textContent = counts.critical;
            document.getElementById('high-count').textContent = counts.high;
            document.getElementById('medium-count').textContent = counts.medium;
            document.getElementById('low-count').textContent = counts.low;
            document.getElementById('info-count').textContent = counts.info;
            
            // Update risk assessment
            updateRiskAssessment(counts);
            
            // Create charts
            createSeverityChart(counts);
            createPayloadChart(stats);
            
            // Scan stats
            document.getElementById('scan-duration').textContent = stats.scan_duration || '-';
            document.getElementById('urls-tested').textContent = stats.total_urls || '-';
            document.getElementById('params-tested').textContent = stats.total_params || '-';
            document.getElementById('requests-made').textContent = stats.total_requests || '-';
            
            // Calculate max CVSS and OWASP categories
            let maxCvss = 0;
            let owaspCategories = new Set();
            
            vulnerabilities.forEach(v => {
                if (v.cvss) {
                    maxCvss = Math.max(maxCvss, parseFloat(v.cvss) || 0);
                }
                if (v.owasp) {
                    owaspCategories.add(v.owasp);
                }
            });
            
            document.getElementById('max-cvss').textContent = maxCvss > 0 ? maxCvss.toFixed(1) : '-';
            document.getElementById('owasp-categories').textContent = owaspCategories.size > 0 ? 
                Array.from(owaspCategories).slice(0, 3).join(', ') + (owaspCategories.size > 3 ? '...' : '') : '-';
        }
        
        function updateRiskAssessment(counts) {
            const total = counts.critical + counts.high + counts.medium + counts.low + counts.info;
            const riskScore = (counts.critical * 10 + counts.high * 7 + counts.medium * 4 + counts.low * 2 + counts.info * 1);
            
            let riskLevel, riskText, riskDescription;
            
            if (counts.critical > 0) {
                riskLevel = 'critical';
                riskText = 'CRITICAL';
                riskDescription = `Immediate action required! ${counts.critical} critical vulnerabilities found that pose severe security risks.`;
            } else if (counts.high > 0) {
                riskLevel = 'high';
                riskText = 'HIGH';
                riskDescription = `High priority remediation needed. ${counts.high} high-severity vulnerabilities require prompt attention.`;
            } else if (counts.medium > 0) {
                riskLevel = 'medium';
                riskText = 'MEDIUM';
                riskDescription = `Moderate security concerns identified. ${counts.medium} medium-severity issues should be addressed.`;
            } else if (counts.low > 0) {
                riskLevel = 'low';
                riskText = 'LOW';
                riskDescription = `Minor security improvements recommended. ${counts.low} low-severity findings detected.`;
            } else if (total > 0) {
                riskLevel = 'info';
                riskText = 'INFO';
                riskDescription = `Security assessment complete. Only informational findings detected.`;
            } else {
                riskLevel = 'secure';
                riskText = 'SECURE';
                riskDescription = `Excellent! No security vulnerabilities detected during the assessment.`;
            }
            
            document.getElementById('risk-text').textContent = riskText;
            document.getElementById('risk-text').className = `risk-text ${riskLevel}`;
            document.getElementById('risk-description').textContent = riskDescription;
        }
        
        function createSeverityChart(counts) {
            const ctx = document.getElementById('severityChart').getContext('2d');
            const data = [
                counts.critical,
                counts.high,
                counts.medium,
                counts.low,
                counts.info
            ];
            const labels = ['Critical', 'High', 'Medium', 'Low', 'Info'];
            const colors = ['#8b0000', '#e74c3c', '#f39c12', '#3498db', '#2ecc71'];
            
            // Filter out zero values
            const filteredData = [];
            const filteredLabels = [];
            const filteredColors = [];
            
            data.forEach((value, index) => {
                if (value > 0) {
                    filteredData.push(value);
                    filteredLabels.push(labels[index]);
                    filteredColors.push(colors[index]);
                }
            });
            
            if (filteredData.length === 0) {
                // Show "No vulnerabilities" chart
                filteredData.push(1);
                filteredLabels.push('No Vulnerabilities');
                filteredColors.push('#2ecc71');
            }
            
            new Chart(ctx, {
                type: 'doughnut',
                data: {
                    labels: filteredLabels,
                    datasets: [{
                        data: filteredData,
                        backgroundColor: filteredColors,
                        borderWidth: 2,
                        borderColor: '#fff'
                    }]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    plugins: {
                        legend: {
                            position: 'bottom',
                            labels: {
                                padding: 15,
                                usePointStyle: true,
                                font: {
                                    size: 11
                                }
                            }
                        }
                    }
                }
            });
        }
        
        function createPayloadChart(stats) {
            const ctx = document.getElementById('payloadChart').getContext('2d');
            const payloadStats = stats.payload_stats || {};
            
            const modules = Object.keys(payloadStats);
            const payloadCounts = modules.map(module => payloadStats[module].payloads_used || 0);
            const successCounts = modules.map(module => payloadStats[module].successful_payloads || 0);
            
            if (modules.length === 0) {
                // Show "No data" chart
                new Chart(ctx, {
                    type: 'doughnut',
                    data: {
                        labels: ['No Testing Data'],
                        datasets: [{
                            data: [1],
                            backgroundColor: ['#95a5a6'],
                            borderWidth: 2,
                            borderColor: '#fff'
                        }]
                    },
                    options: {
                        responsive: true,
                        maintainAspectRatio: false,
                        plugins: {
                            legend: {
                                position: 'bottom'
                            }
                        }
                    }
                });
                return;
            }
            
            // Create color palette
            const colors = [
                '#e74c3c', '#3498db', '#2ecc71', '#f39c12', '#9b59b6',
                '#1abc9c', '#34495e', '#e67e22', '#95a5a6', '#f1c40f'
            ];
            
            new Chart(ctx, {
                type: 'doughnut',
                data: {
                    labels: modules.map(m => m.toUpperCase()),
                    datasets: [{
                        label: 'Payloads Used',
                        data: payloadCounts,
                        backgroundColor: colors.slice(0, modules.length),
                        borderWidth: 2,
                        borderColor: '#fff'
                    }]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    plugins: {
                        legend: {
                            position: 'bottom',
                            labels: {
                                padding: 10,
                                usePointStyle: true,
                                font: {
                                    size: 10
                                }
                            }
                        },
                        tooltip: {
                            callbacks: {
                                afterLabel: function(context) {
                                    const moduleIndex = context.dataIndex;
                                    const successful = successCounts[moduleIndex];
                                    const total = payloadCounts[moduleIndex];
                                    const rate = total > 0 ? ((successful / total) * 100).toFixed(1) : 0;
                                    return `Success: ${successful}/${total} (${rate}%)`;
                                }
                            }
                        }
                    }
                }
            });
        }
        
        function populateTechnologies() {
            const technologies = reportData.scan_stats?.technologies || {};
            const techGrid = document.getElementById('tech-grid');
            const techSection = document.getElementById('tech-section');
            
            // Deduplicate technologies across all domains
            const allTechs = new Set();
            let hasAnyTech = false;
            
            for (const [domain, techs] of Object.entries(technologies)) {
                if (techs && techs.length > 0) {
                    hasAnyTech = true;
                    techs.forEach(tech => {
                        const techName = typeof tech === 'string' ? tech : (tech.name || tech);
                        allTechs.add(techName);
                    });
                }
            }
            
            // Create deduplicated technology items
            if (hasAnyTech) {
                Array.from(allTechs).sort().forEach(techName => {
                    const techItem = document.createElement('div');
                    techItem.className = 'tech-item';
                    
                    techItem.innerHTML = `
                        <div class="tech-name">${techName}</div>
                        <div class="tech-version">Detected</div>
                        <div style="font-size: 0.8rem; color: #888; margin-top: 5px;">
                            Technology Stack
                        </div>
                    `;
                    techGrid.appendChild(techItem);
                });
                
                techSection.style.display = 'block';
            }
        }
        
        function populateVulnerabilities() {
            console.log('Populating vulnerabilities...');
            const vulnerabilities = reportData.vulnerabilities || [];
            console.log('Vulnerabilities array:', vulnerabilities);
            console.log('Vulnerabilities length:', vulnerabilities.length);
            
            const container = document.getElementById('vulnerabilities-list');
            
            if (vulnerabilities.length === 0) {
                console.log('No vulnerabilities found, showing empty state');
                container.innerHTML = '<div class="no-results"><i class="fas fa-check-circle" style="font-size: 3rem; color: #2ecc71; margin-bottom: 15px;"></i><h3>No Vulnerabilities Found</h3><p>The scan completed successfully with no security issues detected.</p></div>';
                return;
            }
            
            console.log('Processing', vulnerabilities.length, 'vulnerabilities');
            
            // Sort vulnerabilities by severity (Critical -> High -> Medium -> Low -> Info)
            const severityOrder = { 'Critical': 0, 'High': 1, 'Medium': 2, 'Low': 3, 'Info': 4 };
            vulnerabilities.sort((a, b) => {
                const severityA = severityOrder[a.severity] !== undefined ? severityOrder[a.severity] : 5;
                const severityB = severityOrder[b.severity] !== undefined ? severityOrder[b.severity] : 5;
                return severityA - severityB;
            });
            
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
                        <a href="data:image/png;base64,${vuln.screenshot_base64}" target="_blank">
                            <img src="data:image/png;base64,${vuln.screenshot_base64}" class="screenshot-thumbnail" alt="Vulnerability Screenshot">
                        </a>
                        <div class="screenshot-caption">Click to view full size</div>
                    </div>
                    ` : ''}
                    ${vuln.cve_links && vuln.cve_links.length > 0 ? `
                    <div class="detail-section">
                        <h4><i class="fas fa-shield-alt"></i> CVE References</h4>
                        <div class="detail-content">
                            ${vuln.cve_links.slice(0, 5).map(cve => 
                                `<a href="${cve.url}" target="_blank" class="cve-link">${cve.cve_id}</a>
                                 <span class="cve-info">(CVSS: ${cve.score || 'N/A'}, ${cve.severity || 'Unknown'})</span>`
                            ).join('<br>')}
                            ${vuln.cve_links.length > 5 ? `<br><em>... and ${vuln.cve_links.length - 5} more CVEs</em>` : ''}
                        </div>
                    </div>
                    ` : ''}
                    ${vuln.exploit_links && vuln.exploit_links.length > 0 ? `
                    <div class="detail-section">
                        <h4><i class="fas fa-bomb"></i> Exploit References</h4>
                        <div class="detail-content">
                            ${vuln.exploit_links.slice(0, 3).map(exploit => 
                                `<a href="${exploit.url}" target="_blank" class="exploit-link">${exploit.exploit_id}</a>
                                 <span class="exploit-info">(${exploit.type || 'Unknown'})</span>`
                            ).join('<br>')}
                            ${vuln.exploit_links.length > 3 ? `<br><em>... and ${vuln.exploit_links.length - 3} more exploits</em>` : ''}
                        </div>
                    </div>
                    ` : ''}
                    <div class="detail-section">
                        <h4><i class="fas fa-shield-alt"></i> Security Information</h4>
                        <div class="detail-content">
                            <strong>CVSS Score:</strong> ${vuln.cvss || 'N/A'}<br>
                            <strong>CWE:</strong> ${vuln.cwe || 'N/A'}<br>
                            <strong>OWASP:</strong> ${vuln.owasp || 'N/A'}
                        </div>
                    </div>
                    ${vuln.remediation || vuln.recommendation ? `
                    <div class="detail-section">
                        <h4><i class="fas fa-tools"></i> Remediation</h4>
                        <div class="detail-content">${vuln.remediation || vuln.recommendation}</div>
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
