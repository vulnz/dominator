"""
Passive backup files detector
Analyzes HTTP responses to discover references to backup files and sensitive files
"""

import re
from typing import Dict, List, Tuple, Any

class BackupFilesDetector:
    """Passive backup files analysis"""
    
    @staticmethod
    def analyze(response_text: str, url: str, headers: Dict[str, str]) -> Tuple[bool, List[Dict[str, Any]]]:
        """
        Passive backup files analysis
        
        How it works:
        1. Scans response content for backup file patterns
        2. Looks for configuration files references
        3. Identifies database dump files
        4. Finds temporary and log files
        5. Detects version control files
        
        Args:
            response_text: HTTP response body
            url: Current URL being analyzed
            headers: HTTP response headers
            
        Returns:
            Tuple[bool, List[Dict]]: (has_findings, list_of_findings)
        """
        findings = []
        
        # Backup file patterns
        backup_patterns = [
            # Common backup extensions
            (r'[a-zA-Z0-9_.-]+\.bak\b', 'Backup File'),
            (r'[a-zA-Z0-9_.-]+\.backup\b', 'Backup File'),
            (r'[a-zA-Z0-9_.-]+\.old\b', 'Old File'),
            (r'[a-zA-Z0-9_.-]+\.orig\b', 'Original File'),
            (r'[a-zA-Z0-9_.-]+\.save\b', 'Save File'),
            (r'[a-zA-Z0-9_.-]+\.copy\b', 'Copy File'),
            
            # Compressed backups
            (r'[a-zA-Z0-9_.-]+\.tar\.gz\b', 'Compressed Backup'),
            (r'[a-zA-Z0-9_.-]+\.zip\b', 'ZIP Archive'),
            (r'[a-zA-Z0-9_.-]+\.rar\b', 'RAR Archive'),
            (r'[a-zA-Z0-9_.-]+\.7z\b', '7-Zip Archive'),
            
            # Database dumps
            (r'[a-zA-Z0-9_.-]+\.sql\b', 'SQL Dump'),
            (r'[a-zA-Z0-9_.-]+\.dump\b', 'Database Dump'),
            (r'database\.sql\b', 'Database SQL File'),
            (r'backup\.sql\b', 'SQL Backup'),
            
            # Temporary files
            (r'[a-zA-Z0-9_.-]+\.tmp\b', 'Temporary File'),
            (r'[a-zA-Z0-9_.-]+\.temp\b', 'Temporary File'),
            (r'[a-zA-Z0-9_.-]+~\b', 'Backup File'),
            
            # Log files
            (r'[a-zA-Z0-9_.-]+\.log\b', 'Log File'),
            (r'error\.log\b', 'Error Log'),
            (r'access\.log\b', 'Access Log'),
            (r'debug\.log\b', 'Debug Log'),
        ]
        
        # Find backup file references
        found_files = set()
        for pattern, file_type in backup_patterns:
            matches = re.findall(pattern, response_text, re.IGNORECASE)
            for match in matches:
                if match not in found_files and len(match) > 3:  # Avoid false positives
                    found_files.add(match)
                    
                    # Determine severity based on file type
                    severity = 'Medium'
                    if any(ext in match.lower() for ext in ['.sql', '.dump', '.bak', '.backup']):
                        severity = 'High'
                    elif any(ext in match.lower() for ext in ['.log', '.tmp']):
                        severity = 'Low'
                    
                    findings.append({
                        'type': 'backup_file_reference',
                        'severity': severity,
                        'url': url,
                        'filename': match,
                        'file_type': file_type,
                        'description': f'{file_type} reference found: {match}',
                        'recommendation': f'Verify if {match} is accessible and remove if sensitive'
                    })
        
        # Configuration files
        config_patterns = [
            (r'config\.php\b', 'PHP Configuration'),
            (r'settings\.php\b', 'Settings File'),
            (r'\.env\b', 'Environment File'),
            (r'web\.config\b', 'Web Configuration'),
            (r'app\.config\b', 'Application Configuration'),
            (r'database\.yml\b', 'Database Configuration'),
            (r'config\.json\b', 'JSON Configuration'),
            (r'\.htaccess\b', 'Apache Configuration'),
            (r'\.htpasswd\b', 'Apache Password File'),
        ]
        
        for pattern, config_type in config_patterns:
            matches = re.findall(pattern, response_text, re.IGNORECASE)
            for match in matches:
                findings.append({
                    'type': 'config_file_reference',
                    'severity': 'High',
                    'url': url,
                    'filename': match,
                    'config_type': config_type,
                    'description': f'{config_type} reference found: {match}',
                    'recommendation': f'Ensure {match} is not publicly accessible'
                })
        
        # Version control files
        vcs_patterns = [
            (r'\.git/\w+', 'Git Repository File'),
            (r'\.svn/\w+', 'SVN Repository File'),
            (r'\.hg/\w+', 'Mercurial Repository File'),
            (r'\.bzr/\w+', 'Bazaar Repository File'),
        ]
        
        for pattern, vcs_type in vcs_patterns:
            matches = re.findall(pattern, response_text, re.IGNORECASE)
            for match in matches:
                findings.append({
                    'type': 'vcs_file_reference',
                    'severity': 'High',
                    'url': url,
                    'filename': match,
                    'vcs_type': vcs_type,
                    'description': f'{vcs_type} reference found: {match}',
                    'recommendation': f'Remove version control files from web directory'
                })
        
        # Sensitive file patterns in directory listings
        if 'index of' in response_text.lower():
            sensitive_files = [
                'passwd', 'shadow', 'hosts', 'fstab', 'crontab',
                'id_rsa', 'id_dsa', 'authorized_keys', 'known_hosts',
                'private.key', 'server.key', 'certificate.crt'
            ]
            
            for sensitive_file in sensitive_files:
                if sensitive_file in response_text.lower():
                    findings.append({
                        'type': 'sensitive_file_listing',
                        'severity': 'Critical',
                        'url': url,
                        'filename': sensitive_file,
                        'description': f'Sensitive system file listed: {sensitive_file}',
                        'recommendation': 'Disable directory listing and secure sensitive files'
                    })
        
        # Check for common backup directories
        backup_dirs = [
            'backup/', 'backups/', 'old/', 'archive/', 'dumps/',
            'temp/', 'tmp/', 'logs/', 'log/'
        ]
        
        for backup_dir in backup_dirs:
            if backup_dir in response_text.lower():
                findings.append({
                    'type': 'backup_directory',
                    'severity': 'Medium',
                    'url': url,
                    'directory': backup_dir,
                    'description': f'Backup directory reference found: {backup_dir}',
                    'recommendation': f'Verify access controls for {backup_dir} directory'
                })
        
        return len(findings) > 0, findings
