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
        """Load advanced HTML report template from file"""
        import os
        template_path = os.path.join(os.path.dirname(__file__), '..', 'templates', 'advanced_report.html')
        try:
            with open(template_path, 'r', encoding='utf-8') as f:
                return f.read()
        except FileNotFoundError:
            return '<!DOCTYPE html><html><head><title>Scan Report</title></head><body><h1>Error: Template not found</h1></body></html>'

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
