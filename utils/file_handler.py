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
        benchmark_analysis = None
        
        print(f"[DEBUG] save_html: Processing {len(data)} items")
        for i, item in enumerate(data):
            print(f"[DEBUG] Item {i}: keys = {list(item.keys()) if isinstance(item, dict) else 'not dict'}")
            
            # Extract scan_stats but don't skip processing this item yet
            if 'scan_stats' in item:
                scan_stats = item['scan_stats']
                print(f"[DEBUG] Found scan_stats in item {i}")
                # Don't continue here - check if this item also has vulnerability data
            
            # Extract benchmark analysis
            if 'benchmark_analysis' in item:
                benchmark_analysis = item['benchmark_analysis']
                print(f"[DEBUG] Found benchmark_analysis in item {i}")
            
            # Check if this item has vulnerability data
            if 'vulnerability' in item and item.get('vulnerability'):
                print(f"[DEBUG] Found vulnerability in item {i}: {item.get('vulnerability', 'UNKNOWN')}")
                # Process this vulnerability even if it also has scan_stats
            else:
                print(f"[DEBUG] Skipping item {i}: no vulnerability field or empty vulnerability")
                continue
            
            # Enrich vulnerability with metadata if missing
            if not item.get('cwe') or not item.get('owasp') or not item.get('cvss'):
                from utils.payload_loader import PayloadLoader
                module_name = item.get('module', 'unknown')
                severity = item.get('severity', 'Medium')
                metadata = PayloadLoader.get_vulnerability_metadata(module_name, severity)
                
                # Add missing metadata
                if not item.get('cwe'):
                    item['cwe'] = metadata.get('cwe', 'CWE-200')
                if not item.get('owasp'):
                    item['owasp'] = metadata.get('owasp', 'A06:2021 – Vulnerable and Outdated Components')
                if not item.get('cvss'):
                    item['cvss'] = metadata.get('cvss', '6.5')
                if not item.get('recommendation') and not item.get('remediation'):
                    item['remediation'] = metadata.get('recommendation', 'Review and implement appropriate security controls.')
            
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
                'technologies': item.get('technologies', []),
                'form_details': item.get('form_details', []),
                'method': item.get('method', item.get('http_method', self._extract_method_from_url(item.get('request_url', '')))),
                'http_method': item.get('http_method', item.get('method', self._extract_method_from_url(item.get('request_url', '')))),
                'url_parameters': self._extract_url_parameters(item.get('request_url', '')),
                'form_details': item.get('form_details', []),
                'cwe': item.get('cwe', 'CWE-200'),
                'owasp': item.get('owasp', 'A06:2021 – Vulnerable and Outdated Components'),
                'cvss': item.get('cvss', '6.5'),
                'passive_analysis': item.get('passive_analysis', False)
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
        
        # Separate active and passive vulnerabilities for better reporting
        active_vulnerabilities = []
        passive_vulnerabilities = []
        
        for vuln in vulnerabilities:
            if vuln.get('passive_analysis', False):
                passive_vulnerabilities.append(vuln)
            else:
                active_vulnerabilities.append(vuln)
        
        # Prepare report data
        report_data = {
            'vulnerabilities': vulnerabilities,
            'active_vulnerabilities': active_vulnerabilities,
            'passive_vulnerabilities': passive_vulnerabilities,
            'scan_stats': scan_stats,
            'filetree_enabled': bool(scan_stats.get('file_tree_paths')),
            'benchmark_analysis': benchmark_analysis,
            'site_structure': self._build_site_structure(vulnerabilities, scan_stats),
            'found_resources': scan_stats.get('found_resources', {})
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
        
        # Safely serialize data to JSON
        try:
            json_data = json.dumps(report_data, ensure_ascii=False, indent=2, default=self._json_serializer)
        except Exception as e:
            print(f"[ERROR] JSON serialization failed: {e}")
            # Fallback: create minimal report data
            fallback_data = {
                'vulnerabilities': [],
                'scan_stats': report_data.get('scan_stats', {}),
                'filetree_enabled': False,
                'benchmark_analysis': None
            }
            json_data = json.dumps(fallback_data, ensure_ascii=False, indent=2, default=self._json_serializer)
        
        # Safely insert JSON data into JavaScript
        # Escape any potential JavaScript breaking characters
        json_data_escaped = json_data.replace('</script>', '<\\/script>').replace('<!--', '<\\!--')
        html_content = template.replace('{report_data}', json_data_escaped)
        
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
    
    def _build_site_structure(self, vulnerabilities: List[Dict[str, Any]], scan_stats: Dict[str, Any]) -> Dict[str, Any]:
        """Build site structure from discovered URLs and paths"""
        structure = {
            'domains': {},
            'total_urls': 0,
            'total_parameters': 0,
            'total_forms': 0,
            'file_types': {},
            'directories': set(),
            'files': set()
        }
        
        # Collect URLs from vulnerabilities
        urls = set()
        for vuln in vulnerabilities:
            if vuln.get('target'):
                urls.add(vuln['target'])
            if vuln.get('request_url'):
                urls.add(vuln['request_url'])
        
        # Add URLs from scan stats
        if scan_stats.get('file_tree_paths'):
            for path in scan_stats['file_tree_paths']:
                # Reconstruct full URLs from paths
                if vulnerabilities:
                    base_domain = vulnerabilities[0].get('target', '').split('/')[0:3]
                    if len(base_domain) == 3:
                        full_url = '/'.join(base_domain) + path
                        urls.add(full_url)
        
        # Process each URL
        for url in urls:
            try:
                from urllib.parse import urlparse
                parsed = urlparse(url)
                domain = parsed.netloc
                path = parsed.path
                query = parsed.query
                
                if domain not in structure['domains']:
                    structure['domains'][domain] = {
                        'paths': set(),
                        'files': set(),
                        'directories': set(),
                        'parameters': set(),
                        'forms': []
                    }
                
                # Add path
                if path and path != '/':
                    structure['domains'][domain]['paths'].add(path)
                    
                    # Determine if it's a file or directory
                    if '.' in path.split('/')[-1]:
                        structure['domains'][domain]['files'].add(path)
                        structure['files'].add(path)
                        
                        # Track file types
                        ext = path.split('.')[-1].lower()
                        structure['file_types'][ext] = structure['file_types'].get(ext, 0) + 1
                    else:
                        structure['domains'][domain]['directories'].add(path)
                        structure['directories'].add(path)
                
                # Add parameters
                if query:
                    from urllib.parse import parse_qs
                    params = parse_qs(query)
                    for param in params.keys():
                        structure['domains'][domain]['parameters'].add(param)
                        structure['total_parameters'] += 1
                
            except Exception as e:
                continue
        
        # Convert sets to lists for JSON serialization
        for domain_data in structure['domains'].values():
            domain_data['paths'] = list(domain_data['paths'])
            domain_data['files'] = list(domain_data['files'])
            domain_data['directories'] = list(domain_data['directories'])
            domain_data['parameters'] = list(domain_data['parameters'])
        
        structure['directories'] = list(structure['directories'])
        structure['files'] = list(structure['files'])
        structure['total_urls'] = len(urls)
        
        return structure
    
    def _json_serializer(self, obj):
        """Custom JSON serializer for non-serializable objects"""
        import datetime
        
        # Handle datetime objects
        if isinstance(obj, datetime.datetime):
            return obj.isoformat()
        elif isinstance(obj, datetime.date):
            return obj.isoformat()
        elif isinstance(obj, datetime.time):
            return obj.isoformat()
        
        # Handle sets
        elif isinstance(obj, set):
            return list(obj)
        
        # Handle bytes
        elif isinstance(obj, bytes):
            try:
                return obj.decode('utf-8')
            except UnicodeDecodeError:
                return obj.decode('utf-8', errors='replace')
        
        # Handle other objects by converting to string
        else:
            try:
                return str(obj)
            except Exception:
                return f"<non-serializable: {type(obj).__name__}>"
    
    def _extract_method_from_url(self, url: str) -> str:
        """Extract HTTP method from request URL or context"""
        # This is a simple heuristic - in practice, method info should be stored separately
        if 'form' in url.lower():
            return 'POST'
        return 'GET'
    
    def _extract_url_parameters(self, url: str) -> List[Dict[str, str]]:
        """Extract parameters from URL"""
        try:
            from urllib.parse import urlparse, parse_qs
            parsed = urlparse(url)
            if parsed.query:
                params = parse_qs(parsed.query)
                return [{'name': k, 'values': v} for k, v in params.items()]
        except:
            pass
        return []
    
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
        .cve-link, .exploit-link, .method-badge {
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
        
        .method-get {
            background: linear-gradient(135deg, #28a745, #20c997);
            color: white;
        }
        
        .method-post {
            background: linear-gradient(135deg, #007bff, #0056b3);
            color: white;
        }
        
        .method-put {
            background: linear-gradient(135deg, #ffc107, #e0a800);
            color: black;
        }
        
        .method-delete {
            background: linear-gradient(135deg, #dc3545, #c82333);
            color: white;
        }
        
        .method-patch {
            background: linear-gradient(135deg, #6f42c1, #5a32a3);
            color: white;
        }
        
        .method-unknown {
            background: linear-gradient(135deg, #6c757d, #545b62);
            color: white;
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
        
        /* Found Resources Styles */
        .found-resources {
            padding: 20px;
        }
        
        .resources-summary {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 20px;
            border-radius: 10px;
            margin-bottom: 20px;
            text-align: center;
        }
        
        .resources-summary h3 {
            margin-bottom: 15px;
            font-size: 1.3rem;
        }
        
        .summary-stats {
            display: flex;
            flex-wrap: wrap;
            justify-content: center;
            gap: 20px;
        }
        
        .summary-stats span {
            background: rgba(255, 255, 255, 0.2);
            padding: 8px 15px;
            border-radius: 20px;
            font-weight: 500;
        }
        
        .resources-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(400px, 1fr));
            gap: 20px;
        }
        
        .resource-category {
            background: white;
            border-radius: 10px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
            overflow: hidden;
        }
        
        .category-header {
            padding: 15px 20px;
            display: flex;
            justify-content: space-between;
            align-items: center;
            font-weight: 600;
        }
        
        .category-header.severity-critical {
            background: linear-gradient(135deg, #8b0000, #a00000);
            color: white;
        }
        
        .category-header.severity-high {
            background: linear-gradient(135deg, #e74c3c, #c0392b);
            color: white;
        }
        
        .category-header.severity-medium {
            background: linear-gradient(135deg, #f39c12, #e67e22);
            color: white;
        }
        
        .category-header.severity-low {
            background: linear-gradient(135deg, #3498db, #2980b9);
            color: white;
        }
        
        .category-header.severity-info {
            background: linear-gradient(135deg, #2ecc71, #27ae60);
            color: white;
        }
        
        .resource-count {
            background: rgba(255, 255, 255, 0.2);
            padding: 4px 12px;
            border-radius: 15px;
            font-size: 0.9rem;
        }
        
        .category-resources {
            padding: 15px;
            max-height: 400px;
            overflow-y: auto;
        }
        
        .resource-item {
            padding: 12px;
            margin-bottom: 10px;
            border-radius: 8px;
            border-left: 4px solid #ddd;
            background: #f8f9fa;
            transition: all 0.3s ease;
        }
        
        .resource-item:hover {
            transform: translateX(5px);
            box-shadow: 0 2px 8px rgba(0,0,0,0.1);
        }
        
        .resource-item.severity-critical {
            border-left-color: #8b0000;
            background: #fff5f5;
        }
        
        .resource-item.severity-high {
            border-left-color: #e74c3c;
            background: #fef5f5;
        }
        
        .resource-item.severity-medium {
            border-left-color: #f39c12;
            background: #fffbf0;
        }
        
        .resource-item.severity-low {
            border-left-color: #3498db;
            background: #f0f8ff;
        }
        
        .resource-item.severity-info {
            border-left-color: #2ecc71;
            background: #f0fff4;
        }
        
        .resource-item.show-more {
            border-left-color: #95a5a6;
            background: #ecf0f1;
            font-style: italic;
            text-align: center;
        }
        
        .resource-value {
            font-family: 'Courier New', monospace;
            font-weight: 600;
            margin-bottom: 8px;
            word-break: break-all;
        }
        
        .resource-details {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 5px;
        }
        
        .resource-type {
            font-weight: 500;
            color: #555;
        }
        
        .resource-severity {
            padding: 2px 8px;
            border-radius: 12px;
            font-size: 0.8rem;
            font-weight: 600;
            text-transform: uppercase;
        }
        
        .resource-context {
            font-size: 0.85rem;
            color: #666;
            font-style: italic;
            margin-top: 5px;
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
        
        .passive-indicator {
            background: linear-gradient(135deg, #17a2b8, #138496);
            color: white;
            padding: 2px 6px;
            border-radius: 4px;
            font-size: 0.7rem;
            font-weight: bold;
            margin-right: 8px;
        }
        
        /* Passive vulnerability styling */
        #passive-vulnerabilities .vuln-header {
            background: linear-gradient(135deg, #17a2b8, #138496);
        }
        
        #passive-vulnerabilities .vuln-item {
            border-left: 4px solid #17a2b8;
        }
        
        #passive-vulnerabilities .vuln-item:hover {
            background-color: #f0f9ff;
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
        
        <!-- Site Structure Section -->
        <div id="site-structure-section" class="vulnerabilities" style="margin-bottom: 20px;">
            <div class="vuln-header">
                <h2><i class="fas fa-sitemap"></i> Site Structure</h2>
                <p>Discovered files, directories, and parameters during scanning</p>
            </div>
            <div id="site-structure-content">
                <!-- Site structure will be populated here -->
            </div>
        </div>
        
        <!-- Found Resources Section -->
        <div id="found-resources-section" class="vulnerabilities" style="margin-bottom: 20px;">
            <div class="vuln-header">
                <h2><i class="fas fa-search"></i> Found Resources</h2>
                <p>Sensitive information and resources discovered during passive analysis</p>
            </div>
            <div id="found-resources-content">
                <!-- Found resources will be populated here -->
            </div>
        </div>
        
        <!-- Active Vulnerabilities List -->
        <div class="vulnerabilities" id="active-vulnerabilities">
            <div class="vuln-header">
                <h2><i class="fas fa-bug"></i> Active Vulnerabilities Found</h2>
                <p>Vulnerabilities found through active testing and payload injection</p>
            </div>
            <div id="active-vulnerabilities-list">
                <!-- Active vulnerabilities will be populated here -->
            </div>
        </div>
        
        <!-- Passive Vulnerabilities List -->
        <div class="vulnerabilities" id="passive-vulnerabilities" style="margin-top: 20px;">
            <div class="vuln-header" style="background: linear-gradient(135deg, #17a2b8, #138496);">
                <h2><i class="fas fa-eye"></i> Passive Vulnerabilities Found</h2>
                <p>Vulnerabilities found through passive analysis of responses and headers</p>
            </div>
            <div id="passive-vulnerabilities-list">
                <!-- Passive vulnerabilities will be populated here -->
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
        let reportData;
        try {
            reportData = {report_data};
        } catch (e) {
            console.error('Error parsing report data:', e);
            reportData = {
                vulnerabilities: [],
                scan_stats: {},
                filetree_enabled: false,
                benchmark_analysis: null
            };
        }
        
        // Initialize report
        document.addEventListener('DOMContentLoaded', function() {
            initializeReport();
        });
        
        function initializeReport() {
            console.log('Initializing report...');
            console.log('Report data:', reportData);
            console.log('Vulnerabilities count:', reportData.vulnerabilities ? reportData.vulnerabilities.length : 'undefined');
            
            try {
                // Set favicon from target
                setDynamicFavicon();
                
                // Generate scope section
                generateScopeSection();
                
                // Generate benchmark analysis if available
                if (reportData.benchmark_analysis) {
                    generateBenchmarkSection();
                }
                
                // Generate file tree if enabled
                if (reportData.filetree_enabled && reportData.scan_stats && reportData.scan_stats.file_tree_paths) {
                    generateFileTreeSection();
                }
                
                populateStats();
                populateTechnologies();
                populateVulnerabilities();
                populateSiteStructure();
                populateFoundResources();
                setupFilters();
                setupEventListeners();
            
                // Set report date
                document.getElementById('report-date').textContent = new Date().toLocaleString();
            
                console.log('Report initialization completed successfully');
            } catch (error) {
                console.error('Error during report initialization:', error);
                // Show error message to user
                document.body.innerHTML = `
                    <div style="padding: 50px; text-align: center; font-family: Arial, sans-serif;">
                        <h1 style="color: #e74c3c;">Report Loading Error</h1>
                        <p>There was an error loading the security report. Please check the console for details.</p>
                        <p style="color: #666; font-size: 0.9em;">Error: ${error.message}</p>
                    </div>
                `;
            }
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
        
        function generateBenchmarkSection() {
            const benchmarkData = reportData.benchmark_analysis;
            if (!benchmarkData || !benchmarkData.summary) {
                console.log('No benchmark data or summary available');
                return;
            }
            
            console.log('Generating benchmark section...');
            
            const summary = benchmarkData.summary || {};
            const byCategory = benchmarkData.by_category || {};
            
            let benchmarkHtml = `
                <div class="executive-summary" style="margin: 25px 0;">
                    <div class="summary-header" style="background: linear-gradient(135deg, #e74c3c 0%, #c0392b 100%);">
                        <h2><i class="fas fa-chart-line"></i> TestPHP.VulnWeb.com Benchmark Analysis</h2>
                        <p>Эффективность сканера по сравнению с известными уязвимостями</p>
                    </div>
                    <div class="summary-grid">
                        <div class="summary-card">
                            <div class="summary-content">
                                <h3>Общая эффективность</h3>
                                <div class="risk-meter">
                                    <div class="risk-level">
                                        <span style="font-size: 1.2rem; font-weight: bold;">${(summary.detection_rate || 0).toFixed(1)}%</span>
                                    </div>
                                </div>
                                <p>Коэффициент обнаружения</p>
                                <div style="margin-top: 15px; font-size: 0.9rem;">
                                    <div>Найдено: ${summary.total_found_vulnerabilities || 0}</div>
                                    <div>Известно: ${summary.total_known_vulnerabilities || 0}</div>
                                    <div>Ложных: ${(benchmarkData.false_positives || []).length}</div>
                                </div>
                            </div>
                        </div>
                        
                        <div class="summary-card">
                            <div class="summary-content">
                                <h3>Результаты по категориям</h3>
                                <div style="text-align: left;">
            `;
            
            // Добавляем результаты по категориям
            for (const [category, data] of Object.entries(byCategory)) {
                if (data.total_known > 0) {
                    const rate = data.detection_rate || 0;
                    const color = rate >= 80 ? '#2ecc71' : rate >= 60 ? '#f39c12' : rate >= 40 ? '#e67e22' : '#e74c3c';
                    
                    benchmarkHtml += `
                        <div style="margin: 8px 0; display: flex; justify-content: space-between; align-items: center;">
                            <span style="font-weight: 500;">${category.toUpperCase()}:</span>
                            <span style="color: ${color}; font-weight: bold;">${rate.toFixed(1)}%</span>
                        </div>
                        <div style="background: #f0f0f0; height: 4px; border-radius: 2px; margin: 4px 0;">
                            <div style="background: ${color}; height: 100%; width: ${rate}%; border-radius: 2px;"></div>
                        </div>
                    `;
                }
            }
            
            benchmarkHtml += `
                                </div>
                            </div>
                        </div>
                        
                        <div class="summary-card">
                            <div class="summary-content">
                                <h3>Качество результатов</h3>
                                <div class="chart-container">
                                    <canvas id="benchmarkChart" width="200" height="200"></canvas>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
            `;
            
            // Вставляем после scope section
            const scopeSection = document.querySelector('.scope-section');
            if (scopeSection) {
                scopeSection.insertAdjacentHTML('afterend', benchmarkHtml);
            } else {
                // Fallback: вставляем перед dashboard
                const dashboard = document.querySelector('.dashboard');
                if (dashboard) {
                    dashboard.insertAdjacentHTML('beforebegin', benchmarkHtml);
                }
            }
            
            // Создаем график бенчмарка
            setTimeout(() => createBenchmarkChart(benchmarkData), 100);
        }
        
        function createBenchmarkChart(benchmarkData) {
            const ctx = document.getElementById('benchmarkChart');
            if (!ctx) return;
            
            const summary = benchmarkData.summary || {};
            const correctlyIdentified = (benchmarkData.correctly_identified || []).length;
            const missed = (benchmarkData.missed_vulnerabilities || []).length;
            const falsePositives = (benchmarkData.false_positives || []).length;
            
            new Chart(ctx.getContext('2d'), {
                type: 'doughnut',
                data: {
                    labels: ['Правильно найдено', 'Пропущено', 'Ложные срабатывания'],
                    datasets: [{
                        data: [correctlyIdentified, missed, falsePositives],
                        backgroundColor: ['#2ecc71', '#e74c3c', '#f39c12'],
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
                                label: function(context) {
                                    const label = context.label;
                                    const value = context.parsed;
                                    const total = correctlyIdentified + missed + falsePositives;
                                    const percentage = total > 0 ? ((value / total) * 100).toFixed(1) : 0;
                                    return `${label}: ${value} (${percentage}%)`;
                                }
                            }
                        }
                    }
                }
            });
        }
        
        function generateFileTreeSection() {
            const scanStats = reportData.scan_stats || {};
            const filePaths = scanStats.file_tree_paths || [];
            
            console.log('Generating file tree section...');
            console.log('File paths:', filePaths);
            
            if (filePaths.length === 0) {
                console.log('No file paths found for tree generation');
                return;
            }
            
            // Build tree structure
            const tree = {};
            filePaths.forEach(path => {
                console.log('Processing path:', path);
                const parts = path.split('/').filter(part => part);
                let current = tree;
                parts.forEach((part, index) => {
                    if (!current[part]) {
                        current[part] = {};
                    }
                    current = current[part];
                });
            });
            
            console.log('Built tree structure:', tree);
            
            if (Object.keys(tree).length > 0) {
                let filetreeHtml = `
                    <div class="filetree-section">
                        <div class="filetree-header">
                            <h2><i class="fas fa-folder-tree"></i> Discovered File Structure</h2>
                            <p>Files and directories found during scanning (${filePaths.length} paths discovered)</p>
                        </div>
                        <div class="file-tree">
                            <div class="tree-root">
                                <div class="tree-item root-item">
                                    <span class="folder-icon"><i class="fas fa-globe"></i></span>
                                    <strong>Website Root</strong>
                                </div>
                                ${generateTreeHtml(tree, 1)}
                            </div>
                        </div>
                    </div>
                `;
                
                console.log('Generated file tree HTML');
                
                // Insert after dashboard but before vulnerabilities
                const dashboard = document.querySelector('.dashboard');
                if (dashboard) {
                    dashboard.insertAdjacentHTML('afterend', filetreeHtml);
                    console.log('Inserted file tree section after dashboard');
                } else {
                    // Fallback: insert before vulnerabilities
                    const vulnSection = document.querySelector('.vulnerabilities');
                    if (vulnSection) {
                        vulnSection.insertAdjacentHTML('beforebegin', filetreeHtml);
                        console.log('Inserted file tree section before vulnerabilities');
                    }
                }
            }
        }
        
        function generateTreeHtml(tree, level) {
            let html = '<ul class="tree-level">';
            const entries = Object.entries(tree).sort((a, b) => {
                // Sort folders first, then files
                const aIsFolder = Object.keys(a[1]).length > 0;
                const bIsFolder = Object.keys(b[1]).length > 0;
                if (aIsFolder && !bIsFolder) return -1;
                if (!aIsFolder && bIsFolder) return 1;
                return a[0].localeCompare(b[0]);
            });
            
            entries.forEach(([name, subtree]) => {
                const indent = level * 20;
                const isFolder = Object.keys(subtree).length > 0;
                
                html += `<li class="tree-item" style="margin-left: ${indent}px;">`;
                
                if (isFolder) {
                    html += `<span class="folder-icon"><i class="fas fa-folder"></i></span><strong>${name}/</strong>`;
                    html += generateTreeHtml(subtree, level + 1);
                } else {
                    // Determine file type icon
                    let fileIcon = 'fas fa-file';
                    const extension = name.split('.').pop().toLowerCase();
                    switch (extension) {
                        case 'php':
                            fileIcon = 'fab fa-php';
                            break;
                        case 'html':
                        case 'htm':
                            fileIcon = 'fab fa-html5';
                            break;
                        case 'js':
                            fileIcon = 'fab fa-js-square';
                            break;
                        case 'css':
                            fileIcon = 'fab fa-css3-alt';
                            break;
                        case 'jpg':
                        case 'jpeg':
                        case 'png':
                        case 'gif':
                            fileIcon = 'fas fa-image';
                            break;
                        case 'pdf':
                            fileIcon = 'fas fa-file-pdf';
                            break;
                        case 'txt':
                            fileIcon = 'fas fa-file-alt';
                            break;
                        case 'xml':
                            fileIcon = 'fas fa-file-code';
                            break;
                    }
                    html += `<span class="file-icon"><i class="${fileIcon}"></i></span>${name}`;
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
        
        function populateSiteStructure() {
            console.log('Populating site structure...');
            const siteStructure = reportData.site_structure || {};
            const container = document.getElementById('site-structure-content');
            
            if (!container) {
                console.error('Site structure container not found');
                return;
            }
            
            if (!siteStructure.domains || Object.keys(siteStructure.domains).length === 0) {
                container.innerHTML = '<div class="no-results"><p>No site structure data available</p></div>';
                return;
            }
            
            let structureHtml = '<div class="site-structure">';
            
            // Summary stats
            structureHtml += `
                <div class="structure-summary">
                    <h3>Site Discovery Summary</h3>
                    <div class="summary-stats">
                        <span><strong>URLs:</strong> ${siteStructure.total_urls || 0}</span>
                        <span><strong>Parameters:</strong> ${siteStructure.total_parameters || 0}</span>
                        <span><strong>Files:</strong> ${siteStructure.files ? siteStructure.files.length : 0}</span>
                        <span><strong>Directories:</strong> ${siteStructure.directories ? siteStructure.directories.length : 0}</span>
                    </div>
                </div>
            `;
            
            // Structure grid
            structureHtml += '<div class="structure-grid">';
            
            for (const [domain, domainData] of Object.entries(siteStructure.domains)) {
                structureHtml += `<div class="structure-section">`;
                structureHtml += `<h4><i class="fas fa-globe"></i> ${domain}</h4>`;
                
                // Files
                if (domainData.files && domainData.files.length > 0) {
                    structureHtml += '<div class="files-section"><h5>Files:</h5>';
                    domainData.files.forEach(file => {
                        const ext = file.split('.').pop().toLowerCase();
                        let icon = 'fas fa-file';
                        
                        switch (ext) {
                            case 'php': icon = 'fab fa-php'; break;
                            case 'html': case 'htm': icon = 'fab fa-html5'; break;
                            case 'js': icon = 'fab fa-js-square'; break;
                            case 'css': icon = 'fab fa-css3-alt'; break;
                            case 'jpg': case 'jpeg': case 'png': case 'gif': icon = 'fas fa-image'; break;
                            case 'pdf': icon = 'fas fa-file-pdf'; break;
                            case 'txt': icon = 'fas fa-file-alt'; break;
                            case 'xml': icon = 'fas fa-file-code'; break;
                        }
                        
                        structureHtml += `
                            <div class="file-item">
                                <i class="${icon} file-icon"></i>
                                <span>${file}</span>
                            </div>
                        `;
                    });
                    structureHtml += '</div>';
                }
                
                // Directories
                if (domainData.directories && domainData.directories.length > 0) {
                    structureHtml += '<div class="dirs-section"><h5>Directories:</h5>';
                    domainData.directories.forEach(dir => {
                        structureHtml += `
                            <div class="dir-item">
                                <i class="fas fa-folder dir-icon"></i>
                                <span>${dir}</span>
                            </div>
                        `;
                    });
                    structureHtml += '</div>';
                }
                
                // Parameters
                if (domainData.parameters && domainData.parameters.length > 0) {
                    structureHtml += '<div class="params-section"><h5>Parameters:</h5>';
                    domainData.parameters.forEach(param => {
                        structureHtml += `
                            <div class="param-item">
                                <i class="fas fa-cog param-icon"></i>
                                <span>${param}</span>
                            </div>
                        `;
                    });
                    structureHtml += '</div>';
                }
                
                structureHtml += '</div>';
            }
            
            structureHtml += '</div></div>';
            container.innerHTML = structureHtml;
        }
        
        function populateFoundResources() {
            console.log('Populating found resources...');
            const foundResources = reportData.found_resources || {};
            const container = document.getElementById('found-resources-content');
            
            if (!container) {
                console.error('Found resources container not found');
                return;
            }
            
            if (Object.keys(foundResources).length === 0) {
                container.innerHTML = '<div class="no-results"><p>No sensitive resources found during passive analysis</p></div>';
                return;
            }
            
            let resourcesHtml = '<div class="found-resources">';
            
            // Calculate totals
            let totalResources = 0;
            let criticalCount = 0;
            let highCount = 0;
            let mediumCount = 0;
            let lowCount = 0;
            let infoCount = 0;
            
            for (const resources of Object.values(foundResources)) {
                totalResources += resources.length;
                resources.forEach(resource => {
                    switch (resource.severity) {
                        case 'Critical': criticalCount++; break;
                        case 'High': highCount++; break;
                        case 'Medium': mediumCount++; break;
                        case 'Low': lowCount++; break;
                        default: infoCount++; break;
                    }
                });
            }
            
            // Summary stats
            resourcesHtml += `
                <div class="resources-summary">
                    <h3>Resources Discovery Summary</h3>
                    <div class="summary-stats">
                        <span><strong>Total Resources:</strong> ${totalResources}</span>
                        <span><strong>Categories:</strong> ${Object.keys(foundResources).length}</span>
                        <span class="severity-critical"><strong>Critical:</strong> ${criticalCount}</span>
                        <span class="severity-high"><strong>High:</strong> ${highCount}</span>
                        <span class="severity-medium"><strong>Medium:</strong> ${mediumCount}</span>
                        <span class="severity-low"><strong>Low:</strong> ${lowCount}</span>
                        <span class="severity-info"><strong>Info:</strong> ${infoCount}</span>
                    </div>
                </div>
            `;
            
            // Resources by category
            resourcesHtml += '<div class="resources-grid">';
            
            // Sort categories by severity (critical first)
            const sortedCategories = Object.entries(foundResources).sort((a, b) => {
                const getSeverityWeight = (resources) => {
                    let weight = 0;
                    resources.forEach(r => {
                        switch (r.severity) {
                            case 'Critical': weight += 10; break;
                            case 'High': weight += 7; break;
                            case 'Medium': weight += 4; break;
                            case 'Low': weight += 2; break;
                            default: weight += 1; break;
                        }
                    });
                    return weight;
                };
                return getSeverityWeight(b[1]) - getSeverityWeight(a[1]);
            });
            
            for (const [category, resources] of sortedCategories) {
                if (resources.length === 0) continue;
                
                // Get category icon
                const categoryIcon = getCategoryIcon(category);
                const categoryName = category.replace(/_/g, ' ').replace(/\b\w/g, l => l.toUpperCase());
                
                // Get highest severity in category
                const severities = resources.map(r => r.severity);
                let highestSeverity = 'Info';
                if (severities.includes('Critical')) highestSeverity = 'Critical';
                else if (severities.includes('High')) highestSeverity = 'High';
                else if (severities.includes('Medium')) highestSeverity = 'Medium';
                else if (severities.includes('Low')) highestSeverity = 'Low';
                
                resourcesHtml += `
                    <div class="resource-category">
                        <div class="category-header severity-${highestSeverity.toLowerCase()}">
                            <h4><i class="${categoryIcon}"></i> ${categoryName}</h4>
                            <span class="resource-count">${resources.length} found</span>
                        </div>
                        <div class="category-resources">
                `;
                
                // Show first 10 resources, with option to expand
                const displayResources = resources.slice(0, 10);
                const hasMore = resources.length > 10;
                
                displayResources.forEach(resource => {
                    const severityClass = resource.severity.toLowerCase();
                    let displayValue = resource.value;
                    
                    // Special handling for sensitive data
                    if (resource.masked_value) {
                        displayValue = resource.masked_value;
                    } else if (resource.formatted_value) {
                        displayValue = resource.formatted_value;
                    } else if (displayValue.length > 50) {
                        displayValue = displayValue.substring(0, 50) + '...';
                    }
                    
                    resourcesHtml += `
                        <div class="resource-item severity-${severityClass}">
                            <div class="resource-value">${displayValue}</div>
                            <div class="resource-details">
                                <span class="resource-type">${resource.name}</span>
                                <span class="resource-severity severity-${severityClass}">${resource.severity}</span>
                            </div>
                            <div class="resource-context">${resource.context}</div>
                        </div>
                    `;
                });
                
                if (hasMore) {
                    resourcesHtml += `
                        <div class="resource-item show-more">
                            <div class="resource-value">... and ${resources.length - 10} more ${categoryName.toLowerCase()}</div>
                        </div>
                    `;
                }
                
                resourcesHtml += `
                        </div>
                    </div>
                `;
            }
            
            resourcesHtml += '</div></div>';
            container.innerHTML = resourcesHtml;
        }
        
        function getCategoryIcon(category) {
            const icons = {
                'credit_cards': 'fas fa-credit-card',
                'phone_numbers': 'fas fa-phone',
                'email_addresses': 'fas fa-envelope',
                'social_networks': 'fab fa-facebook',
                'subdomains': 'fas fa-sitemap',
                'ip_addresses': 'fas fa-network-wired',
                'urls': 'fas fa-link',
                'api_keys': 'fas fa-key',
                'crypto_addresses': 'fab fa-bitcoin',
                'documents': 'fas fa-file-pdf',
                'images': 'fas fa-image',
                'databases': 'fas fa-database',
                'cloud_services': 'fas fa-cloud',
                'development': 'fas fa-code',
                'network_info': 'fas fa-network-wired',
                'geographic': 'fas fa-map-marker-alt',
                'financial': 'fas fa-dollar-sign',
                'personal_data': 'fas fa-user-shield',
                'technical': 'fas fa-cogs',
                'business': 'fas fa-building',
                'security': 'fas fa-shield-alt',
                'media': 'fas fa-play-circle',
                'infrastructure': 'fas fa-server',
                'compliance': 'fas fa-balance-scale',
                'analytics': 'fas fa-chart-line',
                'communication': 'fas fa-comments',
                'backup_storage': 'fas fa-archive',
                'monitoring': 'fas fa-eye',
                'certificates': 'fas fa-certificate',
                'version_control': 'fab fa-git-alt'
            };
            return icons[category] || 'fas fa-search';
        }
        
        function populateVulnerabilities() {
            console.log('Populating vulnerabilities...');
            const activeVulnerabilities = reportData.active_vulnerabilities || [];
            const passiveVulnerabilities = reportData.passive_vulnerabilities || [];
            const allVulnerabilities = reportData.vulnerabilities || [];
            
            console.log('Active vulnerabilities:', activeVulnerabilities.length);
            console.log('Passive vulnerabilities:', passiveVulnerabilities.length);
            console.log('Total vulnerabilities:', allVulnerabilities.length);
            
            const activeContainer = document.getElementById('active-vulnerabilities-list');
            const passiveContainer = document.getElementById('passive-vulnerabilities-list');
            
            if (!activeContainer || !passiveContainer) {
                console.error('Vulnerability containers not found');
                return;
            }
            
            // Sort vulnerabilities by severity
            const severityOrder = { 'Critical': 0, 'High': 1, 'Medium': 2, 'Low': 3, 'Info': 4 };
            const sortVulns = (vulns) => vulns.sort((a, b) => {
                const severityA = severityOrder[a.severity] !== undefined ? severityOrder[a.severity] : 5;
                const severityB = severityOrder[b.severity] !== undefined ? severityOrder[b.severity] : 5;
                return severityA - severityB;
            });
            
            sortVulns(activeVulnerabilities);
            sortVulns(passiveVulnerabilities);
            
            // Populate module filter with all modules
            const allModules = [...new Set(allVulnerabilities.map(v => v.module))];
            const moduleFilter = document.getElementById('module-filter');
            allModules.forEach(module => {
                const option = document.createElement('option');
                option.value = module;
                option.textContent = module.toUpperCase();
                moduleFilter.appendChild(option);
            });
            
            // Populate active vulnerabilities
            if (activeVulnerabilities.length === 0) {
                activeContainer.innerHTML = '<div class="no-results"><i class="fas fa-check-circle" style="font-size: 2rem; color: #2ecc71; margin-bottom: 10px;"></i><h4>No Active Vulnerabilities Found</h4><p>No vulnerabilities found through active testing.</p></div>';
            } else {
                activeVulnerabilities.forEach((vuln, index) => {
                    try {
                        const vulnElement = createVulnerabilityElement(vuln, index, 'active');
                        activeContainer.appendChild(vulnElement);
                    } catch (error) {
                        console.error(`Error creating active vulnerability element ${index}:`, error, vuln);
                    }
                });
            }
            
            // Populate passive vulnerabilities
            if (passiveVulnerabilities.length === 0) {
                passiveContainer.innerHTML = '<div class="no-results"><i class="fas fa-info-circle" style="font-size: 2rem; color: #17a2b8; margin-bottom: 10px;"></i><h4>No Passive Vulnerabilities Found</h4><p>No vulnerabilities found through passive analysis.</p></div>';
            } else {
                passiveVulnerabilities.forEach((vuln, index) => {
                    try {
                        const vulnElement = createVulnerabilityElement(vuln, index + activeVulnerabilities.length, 'passive');
                        passiveContainer.appendChild(vulnElement);
                    } catch (error) {
                        console.error(`Error creating passive vulnerability element ${index}:`, error, vuln);
                    }
                });
            }
            
            // Hide sections if no vulnerabilities
            if (activeVulnerabilities.length === 0) {
                document.getElementById('active-vulnerabilities').style.display = 'none';
            }
            if (passiveVulnerabilities.length === 0) {
                document.getElementById('passive-vulnerabilities').style.display = 'none';
            }
        }
        
        function createVulnerabilityElement(vuln, index, type = 'active') {
            const vulnDiv = document.createElement('div');
            vulnDiv.className = 'vuln-item';
            vulnDiv.dataset.severity = vuln.severity || 'Unknown';
            vulnDiv.dataset.module = vuln.module || 'unknown';
            vulnDiv.dataset.type = type;
            vulnDiv.dataset.searchText = `${vuln.vulnerability || ''} ${vuln.target || ''} ${vuln.parameter || ''} ${vuln.evidence || ''}`.toLowerCase();
            
            // Add visual indicator for passive vulnerabilities
            const typeIndicator = type === 'passive' ? '<span class="passive-indicator">[PASSIVE]</span> ' : '';
            
            vulnDiv.innerHTML = `
                <div class="vuln-summary" onclick="toggleDetails(${index})">
                    <div class="vuln-info">
                        <div class="vuln-title">${typeIndicator}${vuln.vulnerability || 'Unknown Vulnerability'}</div>
                        <div class="vuln-meta">
                            <span><i class="fas fa-globe"></i> ${vuln.target || 'Unknown Target'}</span>
                            <span><i class="fas fa-tag"></i> ${vuln.parameter || 'N/A'}</span>
                            <span><i class="fas fa-cog"></i> ${(vuln.module || 'unknown').toUpperCase()}</span>
                            ${vuln.http_method ? `<span class="method-badge method-${vuln.http_method.toLowerCase()}">${vuln.http_method}</span>` : (vuln.method ? `<span class="method-badge method-${vuln.method.toLowerCase()}">${vuln.method}</span>` : '<span class="method-badge method-unknown">Unknown</span>')}
                        </div>
                    </div>
                    <div style="display: flex; align-items: center; gap: 15px;">
                        <span class="severity-badge severity-${(vuln.severity || 'unknown').toLowerCase()}">${vuln.severity || 'Unknown'}</span>
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
                        <h4><i class="fas fa-link"></i> Request Details</h4>
                        <div class="detail-content">
                            <strong>URL:</strong> ${vuln.request_url}<br>
                            <strong>HTTP Method:</strong> ${vuln.http_method || vuln.method || 'Unknown'}<br>
                            ${vuln.url_parameters && vuln.url_parameters.length > 0 ? 
                                `<strong>Parameters:</strong> ${vuln.url_parameters.map(p => `${p.name}=${p.values.join(',')}`).join(', ')}<br>` : ''}
                            ${vuln.form_details && vuln.form_details.action ? 
                                `<strong>Form Action:</strong> ${vuln.form_details.action}<br>
                                 <strong>Form Method:</strong> ${vuln.form_details.method}<br>
                                 <strong>Form Inputs:</strong> ${vuln.form_details.input_count || 0}<br>` : ''}
                        </div>
                    </div>
                    ${vuln.form_details && vuln.form_details.length > 0 ? `
                    <div class="detail-section">
                        <h4><i class="fas fa-wpforms"></i> Form Details</h4>
                        <div class="detail-content">
                            ${vuln.form_details.map(form => `
                                <strong>Form:</strong> ${form.method} ${form.action}<br>
                                <strong>Inputs:</strong> ${form.inputs ? form.inputs.map(inp => `${inp.name}(${inp.type})`).join(', ') : 'None'}<br>
                                <strong>CSRF Protected:</strong> ${form.has_csrf_token ? 'Yes' : 'No'}<br>
                            `).join('<br>')}
                        </div>
                    </div>
                    ` : ''}
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
    
    def save_benchmark_report(self, benchmark_analysis: Dict[str, Any], filename: str):
        """Сохранение отчета о бенчмарке в текстовом формате"""
        try:
            import sys
            import os
            
            # Добавляем путь к модулю анализа
            current_dir = os.path.dirname(os.path.abspath(__file__))
            parent_dir = os.path.dirname(current_dir)
            analysis_path = os.path.join(parent_dir, 'analysis')
            if analysis_path not in sys.path:
                sys.path.insert(0, analysis_path)
            
            from testphp_benchmark import TestPHPBenchmark
            
            benchmark = TestPHPBenchmark()
            report_text = benchmark.generate_benchmark_report(benchmark_analysis)
            
            with open(filename, 'w', encoding='utf-8') as f:
                f.write(report_text)
                
            print(f"Отчет о бенчмарке сохранен: {filename}")
            
        except Exception as e:
            print(f"Ошибка при сохранении отчета о бенчмарке: {e}")
    
    def read_file_lines(self, filename: str) -> List[str]:
        """Read lines from file"""
        if not os.path.exists(filename):
            return []
        
        with open(filename, 'r', encoding='utf-8') as f:
            return [line.strip() for line in f if line.strip()]
