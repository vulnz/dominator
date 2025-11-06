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
            critical_count = len([v for v in data if v.get('severity', '').lower() == 'critical'])
            high_count = len([v for v in data if v.get('severity', '').lower() == 'high'])
            medium_count = len([v for v in data if v.get('severity', '').lower() == 'medium'])
            low_count = len([v for v in data if v.get('severity', '').lower() == 'low'])
            
            # Generate vulnerabilities HTML
            if not data:
                vulnerabilities_content = '''
                <div class="no-vulns">
                    <div class="no-vulns-icon">🛡️</div>
                    <h2>Отличные новости!</h2>
                    <p>Сканирование завершено успешно - уязвимости не обнаружены!</p>
                </div>
                '''
            else:
                vulnerabilities_content = ""
                for i, item in enumerate(data, 1):
                    severity = item.get('severity', 'low').lower()
                    
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
                    
                    # Определяем иконки для разных типов уязвимостей
                    vuln_icons = {
                        'xss': '🚨',
                        'sqli': '💉', 
                        'lfi': '📁',
                        'default': '⚠️'
                    }
                    
                    vuln_icon = vuln_icons.get(module.lower(), vuln_icons['default'])
                    
                    # Форматируем название уязвимости в стиле Acunetix
                    vuln_display = vuln
                    if 'vulnerability' in vuln.lower():
                        vuln_display = vuln.replace('vulnerability', '').replace('Vulnerability', '').strip()
                    if not vuln_display:
                        vuln_display = f"{module.upper()} Vulnerability"
                    
                    # Определяем класс серьезности для стилизации
                    severity_class = severity
                    if severity == 'critical':
                        severity_class = 'critical'
                    elif severity == 'high':
                        severity_class = 'high'
                    elif severity == 'medium':
                        severity_class = 'medium'
                    else:
                        severity_class = 'low'
                    
                    vuln_html = f'''
                <div class="vulnerability" data-severity="{severity}" data-module="{module}">
                    <div class="vuln-header">
                        <div class="vuln-info">
                            <div class="vuln-id">{i}</div>
                            <div class="vuln-title">{vuln_icon} {vuln_display}</div>
                        </div>
                        <div class="vuln-badges">
                            <span class="severity-badge severity-{severity_class}">{severity.upper()}</span>
                            <span class="module-badge">{module.upper()}</span>
                            <span class="expand-icon">▼</span>
                        </div>
                    </div>
                    <div class="vuln-details">
                        <div class="details-content">
                            <div class="details-grid">
                                <div class="detail-item">
                                    <div class="detail-label">🌐 Целевой URL</div>
                                    <div class="detail-value">{target}</div>
                                </div>
                                <div class="detail-item">
                                    <div class="detail-label">🎯 Уязвимый параметр</div>
                                    <div class="detail-value">{param or 'N/A'}</div>
                                </div>
                                <div class="detail-item">
                                    <div class="detail-label">🔍 Метод обнаружения</div>
                                    <div class="detail-value">{detector}</div>
                                </div>
                                <div class="detail-item">
                                    <div class="detail-label">🛡️ Модуль безопасности</div>
                                    <div class="detail-value">{module.upper()}</div>
                                </div>
                            </div>
                            
                            {f'''
                            <div class="code-section">
                                <div class="code-header">📡 HTTP Запрос</div>
                                <div class="code-content">{request_url or 'Данные запроса недоступны'}</div>
                            </div>
                            ''' if request_url else ''}
                            
                            {f'''
                            <div class="code-section">
                                <div class="code-header">📥 Ответ сервера</div>
                                <div class="code-content">{response_snippet or 'Данные ответа недоступны'}</div>
                            </div>
                            ''' if response_snippet else ''}
                            
                            {f'''
                            <div class="code-section">
                                <div class="code-header">💣 Вредоносная нагрузка</div>
                                <div class="code-content">{payload or 'Данные нагрузки недоступны'}</div>
                            </div>
                            ''' if payload else ''}
                            
                            {f'''
                            <div class="code-section">
                                <div class="code-header">🔍 Доказательства и анализ</div>
                                <div class="code-content">{evidence or 'Данные анализа недоступны'}</div>
                            </div>
                            ''' if evidence else ''}
                        </div>
                    </div>
                </div>
                    '''
                    vulnerabilities_content += vuln_html
            
            # Replace template variables
            html_content = template.replace('{timestamp}', datetime.now().strftime("%d.%m.%Y %H:%M:%S"))
            html_content = html_content.replace('{total_vulns}', str(total_vulns))
            html_content = html_content.replace('{critical_count}', str(critical_count))
            html_content = html_content.replace('{high_count}', str(high_count))
            html_content = html_content.replace('{medium_count}', str(medium_count))
            html_content = html_content.replace('{low_count}', str(low_count))
            html_content = html_content.replace('{vulnerabilities_content}', vulnerabilities_content)
            
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
