"""
Утилиты для работы с файлами
"""

import json
import xml.etree.ElementTree as ET
from typing import List, Dict, Any
import os

class FileHandler:
    """Класс для работы с файлами"""
    
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
        html_template = """
<!DOCTYPE html>
<html>
<head>
    <title>Web Vulnerability Scanner Report</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        .header { background-color: #f0f0f0; padding: 10px; border-radius: 5px; }
        .vulnerability { border: 1px solid #ddd; margin: 10px 0; padding: 10px; border-radius: 5px; }
        .high { border-left: 5px solid #ff0000; }
        .medium { border-left: 5px solid #ff9900; }
        .low { border-left: 5px solid #ffff00; }
        .info { border-left: 5px solid #0099ff; }
    </style>
</head>
<body>
    <div class="header">
        <h1>Web Vulnerability Scanner Report</h1>
        <p>Vulnerabilities found: {count}</p>
    </div>
    {vulnerabilities}
</body>
</html>
        """
        
        vulnerabilities_html = ""
        
        if not data:
            vulnerabilities_html = "<p>No vulnerabilities found</p>"
        else:
            for item in data:
                severity = item.get('severity', 'info').lower()
                vuln_html = f"""
                <div class="vulnerability {severity}">
                    <h3>{item.get('vulnerability', 'Unknown')}</h3>
                    <p><strong>Target:</strong> {item.get('target', '')}</p>
                    <p><strong>Module:</strong> {item.get('module', '')}</p>
                    <p><strong>Severity:</strong> {item.get('severity', '')}</p>
                    <p><strong>Parameter:</strong> {item.get('parameter', '')}</p>
                    <p><strong>Payload:</strong> <code>{item.get('payload', '')}</code></p>
                    <p><strong>Evidence:</strong> {item.get('evidence', '')}</p>
                </div>
                """
                vulnerabilities_html += vuln_html
        
        final_html = html_template.format(
            count=len(data),
            vulnerabilities=vulnerabilities_html
        )
        
        with open(filename, 'w', encoding='utf-8') as f:
            f.write(final_html)
    
    def read_file_lines(self, filename: str) -> List[str]:
        """Read lines from file"""
        if not os.path.exists(filename):
            return []
        
        with open(filename, 'r', encoding='utf-8') as f:
            return [line.strip() for line in f if line.strip()]
