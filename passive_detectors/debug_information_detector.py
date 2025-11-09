"""
Passive debug information detector
Analyzes HTTP responses to discover debug information and development artifacts
"""

import re
from typing import Dict, List, Tuple, Any

class DebugInformationDetector:
    """Passive debug information analysis"""
    
    @staticmethod
    def analyze(response_text: str, url: str, headers: Dict[str, str]) -> Tuple[bool, List[Dict[str, Any]]]:
        """
        Passive debug information analysis
        
        How it works:
        1. Scans response content for debug output
        2. Looks for stack traces and error messages
        3. Identifies development comments
        4. Finds database connection strings
        5. Detects internal paths and system information
        
        Args:
            response_text: HTTP response body
            url: Current URL being analyzed
            headers: HTTP response headers
            
        Returns:
            Tuple[bool, List[Dict]]: (has_findings, list_of_findings)
        """
        findings = []
        
        # Stack trace patterns
        stack_trace_patterns = [
            # PHP stack traces
            (r'Fatal error:.*in\s+([^\s]+)\s+on line\s+(\d+)', 'PHP Fatal Error'),
            (r'Warning:.*in\s+([^\s]+)\s+on line\s+(\d+)', 'PHP Warning'),
            (r'Notice:.*in\s+([^\s]+)\s+on line\s+(\d+)', 'PHP Notice'),
            (r'Parse error:.*in\s+([^\s]+)\s+on line\s+(\d+)', 'PHP Parse Error'),
            
            # Java stack traces
            (r'Exception in thread.*\n\s+at\s+([^\n]+)', 'Java Exception'),
            (r'java\.lang\.\w+Exception', 'Java Exception'),
            (r'org\.springframework\..*Exception', 'Spring Framework Exception'),
            
            # .NET stack traces
            (r'System\.\w+Exception', '.NET Exception'),
            (r'at\s+[\w\.]+\(.*\)\s+in\s+([^\n]+)', '.NET Stack Trace'),
            
            # Python stack traces
            (r'Traceback \(most recent call last\):', 'Python Traceback'),
            (r'File\s+"([^"]+)",\s+line\s+(\d+)', 'Python Error'),
            
            # Node.js stack traces
            (r'Error:\s+.*\n\s+at\s+([^\n]+)', 'Node.js Error'),
        ]
        
        for pattern, error_type in stack_trace_patterns:
            matches = re.findall(pattern, response_text, re.MULTILINE | re.IGNORECASE)
            if matches:
                # Extract file paths from matches
                file_paths = []
                if isinstance(matches[0], tuple):
                    file_paths = [match[0] for match in matches[:3]]  # First 3 matches
                else:
                    file_paths = matches[:3]
                
                findings.append({
                    'type': 'stack_trace',
                    'severity': 'High',
                    'url': url,
                    'error_type': error_type,
                    'file_paths': file_paths,
                    'description': f'{error_type} with file paths exposed',
                    'recommendation': 'Disable debug mode and implement proper error handling'
                })
        
        # Debug output patterns
        debug_patterns = [
            (r'var_dump\(', 'PHP var_dump'),
            (r'print_r\(', 'PHP print_r'),
            (r'console\.log\([^)]+\)', 'JavaScript console.log'),
            (r'console\.debug\([^)]+\)', 'JavaScript console.debug'),
            (r'System\.out\.println', 'Java System.out'),
            (r'Console\.WriteLine', '.NET Console.WriteLine'),
            (r'DEBUG:\s+', 'Debug Log Entry'),
            (r'TRACE:\s+', 'Trace Log Entry'),
        ]
        
        for pattern, debug_type in debug_patterns:
            matches = re.findall(pattern, response_text, re.IGNORECASE)
            if matches:
                findings.append({
                    'type': 'debug_output',
                    'severity': 'Medium',
                    'url': url,
                    'debug_type': debug_type,
                    'occurrences': len(matches),
                    'description': f'{debug_type} found in response ({len(matches)} occurrences)',
                    'recommendation': 'Remove debug output from production code'
                })
        
        # Development comments
        comment_patterns = [
            (r'<!--.*TODO.*-->', 'TODO Comment'),
            (r'<!--.*FIXME.*-->', 'FIXME Comment'),
            (r'<!--.*DEBUG.*-->', 'Debug Comment'),
            (r'<!--.*TEST.*-->', 'Test Comment'),
            (r'<!--.*HACK.*-->', 'Hack Comment'),
            (r'/\*.*TODO.*\*/', 'TODO Comment'),
            (r'/\*.*FIXME.*\*/', 'FIXME Comment'),
            (r'//.*TODO.*', 'TODO Comment'),
            (r'//.*FIXME.*', 'FIXME Comment'),
        ]
        
        for pattern, comment_type in comment_patterns:
            matches = re.findall(pattern, response_text, re.IGNORECASE | re.DOTALL)
            if matches:
                findings.append({
                    'type': 'development_comment',
                    'severity': 'Low',
                    'url': url,
                    'comment_type': comment_type,
                    'occurrences': len(matches),
                    'description': f'{comment_type} found in response',
                    'recommendation': 'Remove development comments from production code'
                })
        
        # Database connection strings
        db_patterns = [
            (r'mysql://[^"\s]+', 'MySQL Connection String'),
            (r'postgresql://[^"\s]+', 'PostgreSQL Connection String'),
            (r'mongodb://[^"\s]+', 'MongoDB Connection String'),
            (r'Server=([^;]+);Database=([^;]+)', 'SQL Server Connection'),
            (r'Data Source=([^;]+)', 'Database Connection'),
            (r'host=([^;,\s]+).*database=([^;,\s]+)', 'Database Connection'),
        ]
        
        for pattern, db_type in db_patterns:
            matches = re.findall(pattern, response_text, re.IGNORECASE)
            if matches:
                findings.append({
                    'type': 'database_connection',
                    'severity': 'Critical',
                    'url': url,
                    'db_type': db_type,
                    'description': f'{db_type} exposed in response',
                    'recommendation': 'Remove database connection strings from client-side code'
                })
        
        # Internal paths and system information
        path_patterns = [
            (r'[A-Z]:\\[^"\s<>|]+', 'Windows File Path'),
            (r'/home/[^"\s<>|]+', 'Linux Home Path'),
            (r'/var/www/[^"\s<>|]+', 'Web Root Path'),
            (r'/usr/[^"\s<>|]+', 'System Path'),
            (r'/etc/[^"\s<>|]+', 'Configuration Path'),
        ]
        
        for pattern, path_type in path_patterns:
            matches = re.findall(pattern, response_text)
            if matches:
                unique_paths = list(set(matches))[:5]  # First 5 unique paths
                findings.append({
                    'type': 'internal_path',
                    'severity': 'Medium',
                    'url': url,
                    'path_type': path_type,
                    'paths': unique_paths,
                    'description': f'{path_type} disclosed in response',
                    'recommendation': 'Remove internal file paths from error messages and responses'
                })
        
        # Check headers for debug information
        debug_headers = [
            'X-Debug-Token', 'X-Debug-Token-Link', 'X-Symfony-Profiler-Token',
            'X-Debug-Mode', 'X-Powered-By', 'X-AspNet-Version'
        ]
        
        for header_name in debug_headers:
            if header_name in headers:
                findings.append({
                    'type': 'debug_header',
                    'severity': 'Medium',
                    'url': url,
                    'header': header_name,
                    'value': headers[header_name],
                    'description': f'Debug header found: {header_name}',
                    'recommendation': 'Remove debug headers from production responses'
                })
        
        # Environment variables exposure
        env_patterns = [
            (r'PATH=([^\n\r]+)', 'PATH Environment Variable'),
            (r'HOME=([^\n\r]+)', 'HOME Environment Variable'),
            (r'USER=([^\n\r]+)', 'USER Environment Variable'),
            (r'[A-Z_]+_PASSWORD=([^\n\r\s]+)', 'Password Environment Variable'),
            (r'[A-Z_]+_KEY=([^\n\r\s]+)', 'Key Environment Variable'),
        ]
        
        for pattern, env_type in env_patterns:
            matches = re.findall(pattern, response_text, re.IGNORECASE)
            if matches:
                severity = 'Critical' if 'password' in env_type.lower() or 'key' in env_type.lower() else 'Medium'
                findings.append({
                    'type': 'environment_variable',
                    'severity': severity,
                    'url': url,
                    'env_type': env_type,
                    'description': f'{env_type} exposed in response',
                    'recommendation': 'Remove environment variables from client-side responses'
                })
        
        return len(findings) > 0, findings
