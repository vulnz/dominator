"""
PHP Configuration Issues detector
"""

import re
from typing import Tuple, List, Dict, Any

class PHPConfigDetector:
    """PHP Configuration Issues detection logic"""
    
    @staticmethod
    def get_dangerous_php_settings() -> Dict[str, Dict[str, Any]]:
        """Get dangerous PHP configuration settings"""
        return {
            'register_globals': {
                'dangerous_values': ['On', '1', 'true'],
                'severity': 'High',
                'description': 'register_globals is enabled, allowing global variable pollution'
            },
            'allow_url_include': {
                'dangerous_values': ['On', '1', 'true'],
                'severity': 'High', 
                'description': 'allow_url_include is enabled, allowing remote file inclusion'
            },
            'allow_url_fopen': {
                'dangerous_values': ['On', '1', 'true'],
                'severity': 'Medium',
                'description': 'allow_url_fopen is enabled, allowing remote file access'
            },
            'display_errors': {
                'dangerous_values': ['On', '1', 'true'],
                'severity': 'Medium',
                'description': 'display_errors is enabled, revealing sensitive information'
            },
            'expose_php': {
                'dangerous_values': ['On', '1', 'true'],
                'severity': 'Low',
                'description': 'expose_php is enabled, revealing PHP version in headers'
            },
            'magic_quotes_gpc': {
                'dangerous_values': ['Off', '0', 'false'],
                'severity': 'Medium',
                'description': 'magic_quotes_gpc is disabled, may lead to SQL injection'
            },
            'safe_mode': {
                'dangerous_values': ['Off', '0', 'false'],
                'severity': 'Low',
                'description': 'safe_mode is disabled (deprecated but still relevant)'
            }
        }
    
    @staticmethod
    def detect_php_config_issues(response_text: str, response_code: int, 
                                headers: Dict[str, str]) -> Tuple[bool, str, str, List[Dict[str, Any]]]:
        """Detect PHP configuration issues"""
        if response_code != 200:
            return False, "", "", []
        
        issues = []
        
        # Check headers for PHP version disclosure
        php_header_issues = PHPConfigDetector._check_php_headers(headers)
        issues.extend(php_header_issues)
        
        # Check response content for phpinfo() output
        phpinfo_issues = PHPConfigDetector._check_phpinfo_content(response_text)
        issues.extend(phpinfo_issues)
        
        # Check for PHP error messages revealing configuration
        error_issues = PHPConfigDetector._check_php_errors(response_text)
        issues.extend(error_issues)
        
        if issues:
            # Determine overall severity
            severities = [issue['severity'] for issue in issues]
            if 'High' in severities:
                overall_severity = 'High'
            elif 'Medium' in severities:
                overall_severity = 'Medium'
            else:
                overall_severity = 'Low'
            
            evidence = f"Found {len(issues)} PHP configuration issues"
            return True, evidence, overall_severity, issues
        
        return False, "", "", []
    
    @staticmethod
    def _check_php_headers(headers: Dict[str, str]) -> List[Dict[str, Any]]:
        """Check headers for PHP-related issues"""
        issues = []
        
        # Check X-Powered-By header
        powered_by = headers.get('X-Powered-By', '')
        if 'php' in powered_by.lower():
            issues.append({
                'type': 'version_disclosure',
                'setting': 'X-Powered-By',
                'value': powered_by,
                'severity': 'Low',
                'description': f'PHP version disclosed in X-Powered-By header: {powered_by}'
            })
        
        # Check Server header
        server = headers.get('Server', '')
        if 'php' in server.lower():
            issues.append({
                'type': 'version_disclosure',
                'setting': 'Server',
                'value': server,
                'severity': 'Low',
                'description': f'PHP information disclosed in Server header: {server}'
            })
        
        return issues
    
    @staticmethod
    def _check_phpinfo_content(response_text: str) -> List[Dict[str, Any]]:
        """Check response content for phpinfo() configuration issues"""
        issues = []
        
        # Check if this is phpinfo() output
        if not ('phpinfo()' in response_text or 'PHP Version' in response_text):
            return issues
        
        dangerous_settings = PHPConfigDetector.get_dangerous_php_settings()
        
        for setting_name, setting_info in dangerous_settings.items():
            # Look for the setting in phpinfo output
            pattern = rf'{re.escape(setting_name)}\s*</td>\s*<td[^>]*>\s*([^<]+)'
            matches = re.finditer(pattern, response_text, re.IGNORECASE)
            
            for match in matches:
                value = match.group(1).strip()
                
                if value in setting_info['dangerous_values']:
                    issues.append({
                        'type': 'dangerous_setting',
                        'setting': setting_name,
                        'value': value,
                        'severity': setting_info['severity'],
                        'description': setting_info['description']
                    })
        
        return issues
    
    @staticmethod
    def _check_php_errors(response_text: str) -> List[Dict[str, Any]]:
        """Check for PHP error messages revealing configuration"""
        issues = []
        
        # PHP error patterns that reveal configuration
        error_patterns = [
            {
                'pattern': r'Warning:.*in\s+([^\s]+)\s+on line\s+(\d+)',
                'type': 'path_disclosure',
                'severity': 'Medium',
                'description': 'PHP warning reveals file system paths'
            },
            {
                'pattern': r'Fatal error:.*in\s+([^\s]+)\s+on line\s+(\d+)',
                'type': 'path_disclosure', 
                'severity': 'Medium',
                'description': 'PHP fatal error reveals file system paths'
            },
            {
                'pattern': r'Notice:.*in\s+([^\s]+)\s+on line\s+(\d+)',
                'type': 'path_disclosure',
                'severity': 'Low',
                'description': 'PHP notice reveals file system paths'
            },
            {
                'pattern': r'Parse error:.*in\s+([^\s]+)\s+on line\s+(\d+)',
                'type': 'path_disclosure',
                'severity': 'Medium', 
                'description': 'PHP parse error reveals file system paths'
            }
        ]
        
        for error_info in error_patterns:
            matches = re.finditer(error_info['pattern'], response_text, re.IGNORECASE)
            for match in matches:
                file_path = match.group(1) if match.groups() else 'unknown'
                line_number = match.group(2) if len(match.groups()) > 1 else 'unknown'
                
                issues.append({
                    'type': error_info['type'],
                    'setting': 'display_errors',
                    'value': f'{file_path}:{line_number}',
                    'severity': error_info['severity'],
                    'description': f"{error_info['description']}: {file_path}"
                })
        
        return issues
    
    @staticmethod
    def get_evidence(issues: List[Dict[str, Any]]) -> str:
        """Get detailed evidence for PHP configuration issues"""
        evidence_parts = []
        
        for issue in issues[:5]:  # Show first 5 issues
            evidence_parts.append(f"{issue['setting']}: {issue['description']}")
        
        if len(issues) > 5:
            evidence_parts.append(f"... and {len(issues) - 5} more issues")
        
        return "; ".join(evidence_parts)
    
    @staticmethod
    def get_response_snippet(issues: List[Dict[str, Any]], response_text: str) -> str:
        """Get response snippet showing PHP configuration issues"""
        snippets = []
        
        for issue in issues[:3]:
            if issue['type'] == 'dangerous_setting':
                snippets.append(f"{issue['setting']}: {issue['value']}")
            elif issue['type'] == 'path_disclosure':
                snippets.append(f"Path disclosed: {issue['value']}")
            else:
                snippets.append(f"{issue['setting']}: {issue['value']}")
        
        return "\n".join(snippets)
    
    @staticmethod
    def get_remediation_advice() -> str:
        """Get remediation advice for PHP configuration issues"""
        return (
            "Secure PHP configuration: "
            "1) Disable register_globals, allow_url_include, display_errors, expose_php, "
            "2) Enable safe_mode if using old PHP, "
            "3) Configure error_reporting to log errors instead of displaying them, "
            "4) Remove X-Powered-By header, "
            "5) Restrict access to phpinfo() pages."
        )
