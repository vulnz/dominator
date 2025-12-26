"""
Passive scanner integration module
Coordinates all passive detectors and provides unified interface

Integrates 25+ passive detectors for comprehensive security analysis
without sending additional HTTP requests.
"""

from typing import Dict, List, Any, Tuple
import sys
import os

# Core passive detectors
from .security_headers_detector import SecurityHeadersDetector
from .sensitive_data_detector import SensitiveDataDetector
from .technology_detector import TechnologyDetector
from .version_disclosure_detector import VersionDisclosureDetector
from .debug_information_detector import DebugInformationDetector
from .backup_files_detector import BackupFilesDetector
from .js_secrets_detector import JSSecretsDetector
from .api_endpoints_detector import APIEndpointsDetector

# New passive detectors (2024 additions)
from .error_message_detector import ErrorMessageDetector
from .wsdl_detector import WSDLDetector
from .websocket_detector import WebSocketDetector
from .viewstate_detector import ViewStateDetector
from .uuid_detector import UUIDDetector
from .subdomain_extractor import SubdomainExtractor
from .sri_checker import SRIChecker
from .session_replay_detector import SessionReplayDetector
from .rfd_detector import RFDDetector
from .nginx_alias_traversal import NginxAliasTraversalDetector
from .java_detector import JavaDetector
from .html5_auditor import HTML5Auditor
from .cryptojacking_detector import CryptojackingDetector
from .client_path_traversal import ClientPathTraversalDetector
from .java_stack_fingerprint import JavaStackFingerprint
from .anomaly_detector import AnomalyDetector
from .source_exposure_detector import SourceExposureDetector
from .waf_detector import WAFDetector
from .idor_detector import IDORDetector

# Import PasswordOverHTTPDetector from detectors folder
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
from detectors.password_over_http_detector import PasswordOverHTTPDetector

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
            'resources': [],        # Subdomains, UUIDs, etc.
            'html5_features': [],   # HTML5 security features
            'all_findings': []
        }

        self.stats = {
            'pages_analyzed': 0,
            'total_findings': 0,
            'critical_findings': 0,
            'high_findings': 0,
            'medium_findings': 0,
            'low_findings': 0,
            'info_findings': 0
        }

        # Collected resources across scan
        self.collected_resources = {
            'subdomains': set(),
            'uuids': [],
            'websocket_endpoints': [],
            'wsdl_services': [],
            'session_replay_services': []
        }
    
    def _is_binary_response(self, response_text: str, headers: Dict[str, str] = None) -> bool:
        """
        Check if response appears to be binary content that shouldn't be analyzed.

        Args:
            response_text: HTTP response content
            headers: HTTP response headers

        Returns:
            True if response appears to be binary
        """
        if not response_text:
            return False

        # Check content-type header for binary types
        if headers:
            content_type = headers.get('content-type', headers.get('Content-Type', '')).lower()
            binary_types = ['image/', 'audio/', 'video/', 'application/octet-stream',
                          'application/zip', 'application/gzip', 'application/pdf',
                          'application/x-gzip', 'font/', 'application/woff', 'application/font']
            if any(bt in content_type for bt in binary_types):
                return True

        # Check for high ratio of non-printable characters (binary detection)
        try:
            sample = response_text[:1000]
            non_printable = sum(1 for c in sample if ord(c) < 32 and c not in '\n\r\t')
            if len(sample) > 0 and non_printable / len(sample) > 0.3:
                return True
        except Exception:
            pass

        return False

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
            'resources': [],
            'html5_features': [],
            'total_count': 0
        }

        # Skip binary responses to avoid unicode garbage in output
        if self._is_binary_response(response_text, headers):
            return response_findings

        try:
            # ==================== CORE DETECTORS ====================

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

            # Debug information detection (stack traces, debug output)
            has_debug, debug_info = DebugInformationDetector.analyze(response_text, url, headers)
            if has_debug:
                response_findings['sensitive_data'].extend(debug_info)
                self.findings['sensitive_data'].extend(debug_info)

            # Backup files detection (.bak, .sql, .old files)
            has_backups, backup_files = BackupFilesDetector.analyze(response_text, url, headers)
            if has_backups:
                response_findings['sensitive_data'].extend(backup_files)
                self.findings['sensitive_data'].extend(backup_files)

            # API endpoints detection (REST, GraphQL, exposed secrets)
            has_api, api_findings = APIEndpointsDetector.analyze(response_text, url, headers)
            if has_api:
                response_findings['sensitive_data'].extend(api_findings)
                self.findings['sensitive_data'].extend(api_findings)

            # Password over HTTP detection
            response_code = headers.get('status_code', 200) if isinstance(headers.get('status_code'), int) else 200
            is_vuln, evidence, forms_found = PasswordOverHTTPDetector.detect_password_over_http(
                url, response_text, response_code
            )
            if is_vuln:
                password_finding = {
                    'type': 'Password Transmitted over HTTP',
                    'severity': 'High',
                    'url': url,
                    'description': 'Password field detected on HTTP (non-encrypted) page.',
                    'evidence': PasswordOverHTTPDetector.get_evidence(forms_found),
                    'remediation': PasswordOverHTTPDetector.get_remediation_advice(),
                    'cwe': 'CWE-319',
                    'owasp': 'A02:2021'
                }
                response_findings['security_issues'].append(password_finding)
                self.findings['security_issues'].append(password_finding)

            # ==================== NEW DETECTORS (2024) ====================

            # Error message detection (SQL errors, stack traces, debug info)
            has_errors, error_findings = ErrorMessageDetector.detect(response_text, url, headers)
            if has_errors:
                response_findings['sensitive_data'].extend(error_findings)
                self.findings['sensitive_data'].extend(error_findings)

            # WSDL/SOAP service detection
            has_wsdl, wsdl_findings = WSDLDetector.detect(response_text, url, headers)
            if has_wsdl:
                response_findings['technologies'].extend(wsdl_findings)
                self.findings['technologies'].extend(wsdl_findings)
                # Collect WSDL services
                for f in wsdl_findings:
                    if f.get('type') == 'WSDL Service Detected':
                        self.collected_resources['wsdl_services'].append({
                            'url': url, 'service': f.get('service_name', 'Unknown')
                        })

            # WebSocket endpoint detection
            has_ws, ws_findings = WebSocketDetector.detect(response_text, url, headers)
            if has_ws:
                response_findings['technologies'].extend(ws_findings)
                self.findings['technologies'].extend(ws_findings)
                # Collect WebSocket endpoints
                for f in ws_findings:
                    if 'endpoints' in f:
                        self.collected_resources['websocket_endpoints'].extend(f['endpoints'])

            # ASP.NET ViewState analysis
            has_viewstate, viewstate_findings = ViewStateDetector.detect(response_text, url, headers)
            if has_viewstate:
                response_findings['security_issues'].extend(viewstate_findings)
                self.findings['security_issues'].extend(viewstate_findings)

            # UUID/GUID detection for IDOR testing
            has_uuid, uuid_findings = UUIDDetector.detect(response_text, url, headers)
            if has_uuid:
                response_findings['resources'].extend(uuid_findings)
                self.findings['resources'].extend(uuid_findings)
                # Collect UUIDs
                for f in uuid_findings:
                    if 'uuids' in f:
                        self.collected_resources['uuids'].extend(f['uuids'])

            # Subdomain extraction
            has_subdomains, subdomain_findings = SubdomainExtractor.detect(response_text, url, headers)
            if has_subdomains:
                response_findings['resources'].extend(subdomain_findings)
                self.findings['resources'].extend(subdomain_findings)
                # Collect subdomains
                for f in subdomain_findings:
                    if 'subdomains' in f:
                        self.collected_resources['subdomains'].update(f['subdomains'])

            # Subresource Integrity (SRI) checking
            has_sri, sri_findings = SRIChecker.detect(response_text, url, headers)
            if has_sri:
                response_findings['security_issues'].extend(sri_findings)
                self.findings['security_issues'].extend(sri_findings)

            # Session replay service detection (Hotjar, FullStory, etc.)
            has_replay, replay_findings = SessionReplayDetector.detect(response_text, url, headers)
            if has_replay:
                response_findings['sensitive_data'].extend(replay_findings)
                self.findings['sensitive_data'].extend(replay_findings)
                # Collect session replay services
                for f in replay_findings:
                    if f.get('service'):
                        self.collected_resources['session_replay_services'].append(f['service'])

            # Reflected File Download (RFD) detection
            has_rfd, rfd_findings = RFDDetector.detect(response_text, url, headers)
            if has_rfd:
                response_findings['security_issues'].extend(rfd_findings)
                self.findings['security_issues'].extend(rfd_findings)

            # NGINX Alias Traversal detection
            has_nginx, nginx_findings = NginxAliasTraversalDetector.detect(response_text, url, headers)
            if has_nginx:
                response_findings['security_issues'].extend(nginx_findings)
                self.findings['security_issues'].extend(nginx_findings)

            # Java/J2EE technology detection
            has_java, java_findings = JavaDetector.detect(response_text, url, headers)
            if has_java:
                response_findings['technologies'].extend(java_findings)
                self.findings['technologies'].extend(java_findings)

            # Java stack trace fingerprinting
            has_stack, stack_findings = JavaStackFingerprint.detect(response_text, url, headers)
            if has_stack:
                response_findings['technologies'].extend(stack_findings)
                self.findings['technologies'].extend(stack_findings)

            # HTML5 security audit
            has_html5, html5_findings = HTML5Auditor.detect(response_text, url, headers)
            if has_html5:
                response_findings['html5_features'].extend(html5_findings)
                self.findings['html5_features'].extend(html5_findings)

            # Cryptojacking/miner detection
            has_crypto, crypto_findings = CryptojackingDetector.detect(response_text, url, headers)
            if has_crypto:
                response_findings['security_issues'].extend(crypto_findings)
                self.findings['security_issues'].extend(crypto_findings)

            # Client-Side Path Traversal detection
            has_cspt, cspt_findings = ClientPathTraversalDetector.detect(response_text, url, headers)
            if has_cspt:
                response_findings['security_issues'].extend(cspt_findings)
                self.findings['security_issues'].extend(cspt_findings)

            # Anomaly response detection (unusual file types, size anomalies)
            has_anomaly, anomaly_findings = AnomalyDetector.detect(response_text, url, headers)
            if has_anomaly:
                response_findings['security_issues'].extend(anomaly_findings)
                self.findings['security_issues'].extend(anomaly_findings)

            # Source code / archive exposure detection
            has_exposure, exposure_findings = SourceExposureDetector.detect(response_text, url, headers)
            if has_exposure:
                response_findings['security_issues'].extend(exposure_findings)
                self.findings['security_issues'].extend(exposure_findings)

            # WAF detection (passive)
            has_waf, waf_findings = WAFDetector.analyze(headers, response_text, url)
            if has_waf:
                response_findings['technologies'].extend(waf_findings)
                self.findings['technologies'].extend(waf_findings)

            # Passive IDOR detection (URL patterns, sequential IDs)
            has_idor, idor_findings = IDORDetector.analyze(response_text, url, headers)
            if has_idor:
                response_findings['security_issues'].extend(idor_findings)
                self.findings['security_issues'].extend(idor_findings)

            # ==================== FINALIZE ====================

            # Calculate totals
            all_response_findings = (
                response_findings['security_issues'] +
                response_findings['sensitive_data'] +
                response_findings['technologies'] +
                response_findings['version_disclosures'] +
                response_findings['resources'] +
                response_findings['html5_features']
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
            elif severity in ('info', 'informational'):
                self.stats['info_findings'] += 1
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
