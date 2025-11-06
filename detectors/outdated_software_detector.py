"""
Outdated software detection logic
"""

import re
from typing import Dict, Any, List, Tuple, Optional

class OutdatedSoftwareDetector:
    """Outdated software vulnerability detection logic"""
    
    @staticmethod
    def get_software_version_patterns() -> Dict[str, List[str]]:
        """Get patterns for detecting software versions"""
        return {
            'php': [
                r'X-Powered-By:\s*PHP/([0-9]+\.[0-9]+\.[0-9]+)',
                r'Server:\s*.*PHP/([0-9]+\.[0-9]+\.[0-9]+)',
                r'PHP Version\s+([0-9]+\.[0-9]+\.[0-9]+)'
            ],
            'apache': [
                r'Server:\s*Apache/([0-9]+\.[0-9]+\.[0-9]+)',
                r'Server:\s*Apache-Coyote/([0-9]+\.[0-9]+)'
            ],
            'nginx': [
                r'Server:\s*nginx/([0-9]+\.[0-9]+\.[0-9]+)',
                r'Server:\s*nginx/([0-9]+\.[0-9]+)'
            ],
            'iis': [
                r'Server:\s*Microsoft-IIS/([0-9]+\.[0-9]+)',
                r'X-Powered-By:\s*ASP\.NET'
            ],
            'tomcat': [
                r'Server:\s*Apache-Tomcat/([0-9]+\.[0-9]+\.[0-9]+)',
                r'X-Powered-By:\s*Servlet/([0-9]+\.[0-9]+)'
            ],
            'wordpress': [
                r'<meta name="generator" content="WordPress ([0-9]+\.[0-9]+(?:\.[0-9]+)?)"',
                r'/wp-content/.*?ver=([0-9]+\.[0-9]+(?:\.[0-9]+)?)'
            ],
            'drupal': [
                r'<meta name="generator" content="Drupal ([0-9]+)"',
                r'Drupal\.settings'
            ],
            'joomla': [
                r'<meta name="generator" content="Joomla! - Open Source Content Management"',
                r'/media/jui/js/.*?([0-9]+\.[0-9]+\.[0-9]+)'
            ]
        }
    
    @staticmethod
    def get_known_vulnerabilities() -> Dict[str, Dict[str, List[str]]]:
        """Get known vulnerabilities for software versions"""
        return {
            'php': {
                '5.6.40': ['CVE-2019-11036', 'CVE-2019-11034', 'CVE-2018-19395'],
                '7.0.0': ['CVE-2016-7480', 'CVE-2016-4345', 'CVE-2016-4346'],
                '7.1.0': ['CVE-2017-8923', 'CVE-2017-7272']
            },
            'apache': {
                '2.4.29': ['CVE-2018-1312', 'CVE-2018-1283'],
                '2.4.25': ['CVE-2017-3167', 'CVE-2017-3169']
            },
            'nginx': {
                '1.19.0': ['CVE-2021-23017'],
                '1.18.0': ['CVE-2020-11724']
            }
        }
    
    @staticmethod
    def detect_outdated_software(response_headers: Dict[str, str], response_text: str) -> List[Dict[str, Any]]:
        """
        Detect outdated software versions
        
        Args:
            response_headers: HTTP response headers
            response_text: HTTP response text
        
        Returns:
            List of detected outdated software
        """
        detections = []
        patterns = OutdatedSoftwareDetector.get_software_version_patterns()
        vulnerabilities = OutdatedSoftwareDetector.get_known_vulnerabilities()
        
        # Combine headers into searchable text
        headers_text = '\n'.join([f"{k}: {v}" for k, v in response_headers.items()])
        search_text = headers_text + '\n' + response_text
        
        for software, pattern_list in patterns.items():
            for pattern in pattern_list:
                matches = re.finditer(pattern, search_text, re.IGNORECASE)
                for match in matches:
                    version = match.group(1) if match.groups() else 'Unknown'
                    
                    # Check if this version has known vulnerabilities
                    known_vulns = vulnerabilities.get(software, {}).get(version, [])
                    
                    severity = OutdatedSoftwareDetector._get_severity(software, version, known_vulns)
                    
                    detection = {
                        'software': software,
                        'version': version,
                        'severity': severity,
                        'known_vulnerabilities': known_vulns,
                        'detection_method': 'header_analysis' if 'Server:' in match.group(0) or 'X-Powered-By:' in match.group(0) else 'content_analysis'
                    }
                    
                    detections.append(detection)
        
        return detections
    
    @staticmethod
    def _get_severity(software: str, version: str, known_vulns: List[str]) -> str:
        """Determine severity based on software and vulnerabilities"""
        if known_vulns:
            # Check for critical CVEs
            critical_patterns = ['RCE', 'Remote Code Execution', 'Authentication Bypass']
            for vuln in known_vulns:
                for pattern in critical_patterns:
                    if pattern.lower() in vuln.lower():
                        return 'Critical'
            return 'High'
        
        # General age-based severity
        if software == 'php':
            if version.startswith('5.'):
                return 'Critical'  # PHP 5.x is EOL
            elif version.startswith('7.0') or version.startswith('7.1'):
                return 'High'
        
        return 'Medium'
    
    @staticmethod
    def get_evidence(detections: List[Dict[str, Any]]) -> str:
        """Get evidence of outdated software"""
        if not detections:
            return "No outdated software detected"
        
        evidence_parts = []
        for detection in detections:
            software = detection['software']
            version = detection['version']
            vulns = detection.get('known_vulnerabilities', [])
            
            evidence = f"{software.upper()} {version}"
            if vulns:
                evidence += f" (Known vulnerabilities: {', '.join(vulns[:3])})"
            
            evidence_parts.append(evidence)
        
        return "; ".join(evidence_parts)
    
    @staticmethod
    def get_remediation_advice(software: str, version: str) -> str:
        """Get remediation advice for specific software"""
        advice = {
            'php': f"Upgrade PHP from version {version} to the latest stable version. PHP 5.x is end-of-life and should be upgraded immediately.",
            'apache': f"Upgrade Apache from version {version} to the latest stable version to patch known security vulnerabilities.",
            'nginx': f"Upgrade Nginx from version {version} to the latest stable version.",
            'wordpress': f"Upgrade WordPress from version {version} to the latest version and ensure all plugins are updated.",
            'drupal': f"Upgrade Drupal from version {version} to the latest version and apply all security patches."
        }
        
        return advice.get(software, f"Upgrade {software} from version {version} to the latest stable version.")
