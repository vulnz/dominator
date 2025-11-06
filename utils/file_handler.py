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
        """Save in HTML format"""
        try:
            import os
            from datetime import datetime
            
            # Read HTML template
            template_path = os.path.join('report', 'templates', 'html_template.html')
            if not os.path.exists(template_path):
                raise Exception(f"HTML template not found at {template_path}")
            
            with open(template_path, 'r', encoding='utf-8') as f:
                template = f.read()
            
            # Calculate statistics
            total_vulns = len(data)
            high_count = len([v for v in data if v.get('severity', '').lower() == 'high'])
            medium_count = len([v for v in data if v.get('severity', '').lower() == 'medium'])
            low_count = len([v for v in data if v.get('severity', '').lower() == 'low'])
            
            # Generate vulnerabilities HTML
            if not data:
                vulnerabilities_content = '''
                <div class="no-vulns">
                    <div class="no-vulns-icon">✅</div>
                    <h2>No Vulnerabilities Found</h2>
                    <p>The scan completed successfully without finding any vulnerabilities.</p>
                </div>
                '''
            else:
                vulnerabilities_content = ""
                for i, item in enumerate(data, 1):
                    severity = item.get('severity', 'info').lower()
                    
                    # Escape HTML characters
                    target = self._escape_html(str(item.get('target', '')))
                    module = self._escape_html(str(item.get('module', '')))
                    vuln = self._escape_html(str(item.get('vulnerability', 'Unknown')))
                    param = self._escape_html(str(item.get('parameter', '')))
                    payload = self._escape_html(str(item.get('payload', '')))
                    evidence = self._escape_html(str(item.get('evidence', '')))
                    request_url = self._escape_html(str(item.get('request_url', '')))
                    detector = self._escape_html(str(item.get('detector', 'Unknown')))
                    response_snippet = self._escape_html(str(item.get('response_snippet', '')))
                    
                    vuln_html = f'''
                    <div class="vulnerability severity-{severity}">
                        <div class="vuln-header">
                            <div class="vuln-title">#{i} {vuln}</div>
                            <div class="vuln-meta">
                                <div class="meta-item">
                                    <span class="meta-label">Severity:</span>
                                    <span class="severity-badge">{item.get('severity', 'Unknown')}</span>
                                </div>
                                <div class="meta-item">
                                    <span class="meta-label">Module:</span>
                                    <span>{module}</span>
                                </div>
                                <div class="meta-item">
                                    <span class="meta-label">Parameter:</span>
                                    <span>{param}</span>
                                </div>
                            </div>
                        </div>
                        <div class="vuln-details">
                            <div class="detail-section">
                                <div class="detail-title">🎯 Target</div>
                                <div class="code-block">{target}</div>
                            </div>
                            
                            <div class="detail-section">
                                <div class="detail-title">📤 Request</div>
                                <div class="code-block request-block">{request_url}</div>
                            </div>
                            
                            <div class="detail-section">
                                <div class="detail-title">💉 Payload</div>
                                <div class="code-block">{payload}</div>
                            </div>
                            
                            <div class="detail-section">
                                <div class="detail-title">📥 Response Snippet</div>
                                <div class="code-block response-block">{response_snippet}</div>
                            </div>
                            
                            <div class="detail-section">
                                <div class="detail-title">🔍 Evidence</div>
                                <div class="code-block">{evidence}</div>
                                <div class="detector-info">
                                    <span class="detector-name">Detector:</span> {detector}
                                </div>
                            </div>
                        </div>
                    </div>
                    '''
                    vulnerabilities_content += vuln_html
            
            # Replace template variables
            html_content = template.format(
                timestamp=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                total_vulns=total_vulns,
                high_count=high_count,
                medium_count=medium_count,
                low_count=low_count,
                vulnerabilities_content=vulnerabilities_content
            )
            
            with open(filename, 'w', encoding='utf-8') as f:
                f.write(html_content)
                
        except Exception as e:
            raise Exception(f"Error creating HTML report: {e}")
    
    def _escape_html(self, text: str) -> str:
        """Escape HTML characters"""
        return (text.replace('&', '&amp;')
                   .replace('<', '&lt;')
                   .replace('>', '&gt;')
                   .replace('"', '&quot;')
                   .replace("'", '&#x27;'))
    
    def read_file_lines(self, filename: str) -> List[str]:
        """Read lines from file"""
        if not os.path.exists(filename):
            return []
        
        with open(filename, 'r', encoding='utf-8') as f:
            return [line.strip() for line in f if line.strip()]
