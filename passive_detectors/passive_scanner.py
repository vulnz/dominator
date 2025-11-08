"""
Passive scanner integration module
Coordinates all passive detectors and provides unified interface
"""

from typing import Dict, List, Any, Tuple
from .security_headers_detector import SecurityHeadersDetector
from .sensitive_data_detector import SensitiveDataDetector
from .technology_detector import TechnologyDetector
from .version_disclosure_detector import VersionDisclosureDetector

class PassiveScanner:
    """
    Unified passive scanner that coordinates all passive detectors
    
    How it works:
    1. Receives HTTP responses during crawling
    2. Runs all passive detectors in parallel
    3. Aggregates and categorizes findings
    4. Provides unified reporting interface
    5. No additional HTTP requests sent
    """
    
    def __init__(self):
        """Initialize passive scanner"""
        self.findings = {
            'security_issues': [],
            'sensitive_data': [],
            'technologies': [],
            'version_disclosures': [],
            'all_findings': []
        }
        
        self.stats = {
            'pages_analyzed': 0,
            'total_findings': 0,
            'critical_findings': 0,
            'high_findings': 0,
            'medium_findings': 0,
            'low_findings': 0
        }
    
    def analyze_response(self, headers: Dict[str, str], response_text: str, url: str) -> Dict[str, Any]:
        """
        Analyze single HTTP response with all passive detectors
        
        Args:
            headers: HTTP response headers
            response_text: HTTP response content
            url: URL being analyzed
            
        Returns:
            Dict containing all findings from this response
        """
        response_findings = {
            'url': url,
            'security_issues': [],
            'sensitive_data': [],
            'technologies': [],
            'version_disclosures': [],
            'total_count': 0
        }
        
        try:
            # Security headers analysis
            has_security, security_issues = SecurityHeadersDetector.analyze(headers, url)
            if has_security:
                response_findings['security_issues'].extend(security_issues)
                self.findings['security_issues'].extend(security_issues)
            
            # Cookie security analysis
            has_cookies, cookie_issues = SecurityHeadersDetector.analyze_cookies(headers, url)
            if has_cookies:
                response_findings['security_issues'].extend(cookie_issues)
                self.findings['security_issues'].extend(cookie_issues)
            
            # Sensitive data detection
            has_sensitive, sensitive_data = SensitiveDataDetector.analyze(response_text, url, headers)
            if has_sensitive:
                response_findings['sensitive_data'].extend(sensitive_data)
                self.findings['sensitive_data'].extend(sensitive_data)
            
            # Technology detection
            has_tech, technologies = TechnologyDetector.analyze(headers, response_text, url)
            if has_tech:
                response_findings['technologies'].extend(technologies)
                self.findings['technologies'].extend(technologies)
            
            # Version disclosure detection
            has_versions, versions = VersionDisclosureDetector.analyze(headers, response_text, url)
            if has_versions:
                response_findings['version_disclosures'].extend(versions)
                self.findings['version_disclosures'].extend(versions)
            
            # Calculate totals
            all_response_findings = (
                response_findings['security_issues'] +
                response_findings['sensitive_data'] +
                response_findings['technologies'] +
                response_findings['version_disclosures']
            )
            
            response_findings['total_count'] = len(all_response_findings)
            self.findings['all_findings'].extend(all_response_findings)
            
            # Update statistics
            self._update_stats(all_response_findings)
            
        except Exception as e:
            print(f"    [PASSIVE] Error analyzing {url}: {e}")
        
        return response_findings
    
    def _update_stats(self, findings: List[Dict[str, Any]]):
        """Update scanner statistics"""
        self.stats['pages_analyzed'] += 1
        self.stats['total_findings'] += len(findings)
        
        for finding in findings:
            severity = finding.get('severity', 'Low').lower()
            if severity == 'critical':
                self.stats['critical_findings'] += 1
            elif severity == 'high':
                self.stats['high_findings'] += 1
            elif severity == 'medium':
                self.stats['medium_findings'] += 1
            else:
                self.stats['low_findings'] += 1
    
    def get_findings_by_severity(self, severity: str) -> List[Dict[str, Any]]:
        """Get findings filtered by severity level"""
        severity_lower = severity.lower()
        return [
            finding for finding in self.findings['all_findings']
            if finding.get('severity', '').lower() == severity_lower
        ]
    
    def get_findings_by_type(self, finding_type: str) -> List[Dict[str, Any]]:
        """Get findings filtered by type"""
        return [
            finding for finding in self.findings['all_findings']
            if finding.get('type', '') == finding_type
        ]
    
    def get_sensitive_data_summary(self) -> Dict[str, Any]:
        """Get summary of sensitive data findings"""
        sensitive_data = self.findings['sensitive_data']
        
        # Count by type
        type_counts = {}
        for item in sensitive_data:
            item_type = item.get('type', 'unknown')
            type_counts[item_type] = type_counts.get(item_type, 0) + 1
        
        # Get unique emails and phones
        emails = []
        phones = []
        for item in sensitive_data:
            if item.get('type') == 'email_disclosure' and 'emails' in item:
                emails.extend(item['emails'])
            elif item.get('type') == 'phone_disclosure' and 'phones' in item:
                phones.extend(item['phones'])
        
        return {
            'total_leaks': len(sensitive_data),
            'types': type_counts,
            'unique_emails': list(set(emails)),
            'unique_phones': list(set(phones)),
            'email_count': len(set(emails)),
            'phone_count': len(set(phones))
        }
    
    def get_technology_summary(self) -> Dict[str, Any]:
        """Get summary of detected technologies"""
        technologies = self.findings['technologies']
        
        # Group by category
        by_category = {}
        by_name = {}
        
        for tech in technologies:
            category = tech.get('category', 'Unknown')
            name = tech.get('name', 'Unknown')
            
            if category not in by_category:
                by_category[category] = []
            by_category[category].append(tech)
            
            by_name[name] = tech
        
        return {
            'total_technologies': len(technologies),
            'by_category': by_category,
            'by_name': by_name,
            'unique_technologies': len(by_name)
        }
    
    def generate_report(self) -> Dict[str, Any]:
        """Generate comprehensive passive scan report"""
        return {
            'statistics': self.stats,
            'findings': self.findings,
            'sensitive_data_summary': self.get_sensitive_data_summary(),
            'technology_summary': self.get_technology_summary(),
            'critical_findings': self.get_findings_by_severity('critical'),
            'high_findings': self.get_findings_by_severity('high')
        }
    
    def print_summary(self):
        """Print summary of passive scan results"""
        print(f"\n=== PASSIVE SCAN SUMMARY ===")
        print(f"Pages Analyzed: {self.stats['pages_analyzed']}")
        print(f"Total Findings: {self.stats['total_findings']}")
        print(f"  Critical: {self.stats['critical_findings']}")
        print(f"  High: {self.stats['high_findings']}")
        print(f"  Medium: {self.stats['medium_findings']}")
        print(f"  Low: {self.stats['low_findings']}")
        
        # Sensitive data summary
        sensitive_summary = self.get_sensitive_data_summary()
        if sensitive_summary['total_leaks'] > 0:
            print(f"\nSensitive Data Leaks: {sensitive_summary['total_leaks']}")
            print(f"  Unique Emails: {sensitive_summary['email_count']}")
            print(f"  Unique Phones: {sensitive_summary['phone_count']}")
            print(f"  Leak Types: {', '.join(sensitive_summary['types'].keys())}")
        
        # Technology summary
        tech_summary = self.get_technology_summary()
        if tech_summary['total_technologies'] > 0:
            print(f"\nDetected Technologies: {tech_summary['unique_technologies']} unique")
            for category, techs in tech_summary['by_category'].items():
                tech_names = [t.get('name', 'Unknown') for t in techs]
                unique_names = list(set(tech_names))
                print(f"  {category}: {', '.join(unique_names[:5])}")
        
        # Top findings by type
        if self.findings['all_findings']:
            type_counts = {}
            for finding in self.findings['all_findings']:
                finding_type = finding.get('type', 'unknown')
                type_counts[finding_type] = type_counts.get(finding_type, 0) + 1
            
            print(f"\nTop Finding Types:")
            for finding_type, count in sorted(type_counts.items(), key=lambda x: x[1], reverse=True)[:5]:
                print(f"  {finding_type}: {count}")
