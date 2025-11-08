"""
Outdated software detection logic with dynamic CVE checking from external APIs
"""

import re
import json
import requests
from typing import Dict, Any, List, Tuple, Optional
from datetime import datetime, timedelta
import time

class OutdatedSoftwareDetector:
    """Enhanced outdated software vulnerability detection with real-time CVE integration"""
    
    # Cache for API responses to avoid repeated calls
    _api_cache = {}
    _cache_expiry = {}
    _rate_limit_delay = 1  # Delay between API calls in seconds
    _last_api_call = 0
    
    @staticmethod
    def get_software_version_patterns() -> Dict[str, List[str]]:
        """Get patterns for detecting software versions from headers and content"""
        return {
            'php': [
                r'X-Powered-By:\s*PHP/([0-9]+\.[0-9]+(?:\.[0-9]+)?)',
                r'Server:\s*.*PHP/([0-9]+\.[0-9]+(?:\.[0-9]+)?)',
                r'PHP Version\s+([0-9]+\.[0-9]+(?:\.[0-9]+)?)',
                r'PHP/([0-9]+\.[0-9]+(?:\.[0-9]+)?)'
            ],
            'apache': [
                r'Server:\s*Apache/([0-9]+\.[0-9]+(?:\.[0-9]+)?)',
                r'Server:\s*Apache-Coyote/([0-9]+\.[0-9]+)',
                r'Apache/([0-9]+\.[0-9]+(?:\.[0-9]+)?)'
            ],
            'nginx': [
                r'Server:\s*nginx/([0-9]+\.[0-9]+(?:\.[0-9]+)?)',
                r'nginx/([0-9]+\.[0-9]+(?:\.[0-9]+)?)'
            ],
            'iis': [
                r'Server:\s*Microsoft-IIS/([0-9]+\.[0-9]+)',
                r'X-Powered-By:\s*ASP\.NET',
                r'Microsoft-IIS/([0-9]+\.[0-9]+)'
            ],
            'tomcat': [
                r'Server:\s*Apache-Tomcat/([0-9]+\.[0-9]+(?:\.[0-9]+)?)',
                r'X-Powered-By:\s*Servlet/([0-9]+\.[0-9]+)',
                r'Apache-Tomcat/([0-9]+\.[0-9]+(?:\.[0-9]+)?)'
            ],
            'wordpress': [
                r'<meta name="generator" content="WordPress ([0-9]+\.[0-9]+(?:\.[0-9]+)?)"',
                r'/wp-content/.*?ver=([0-9]+\.[0-9]+(?:\.[0-9]+)?)',
                r'wp-includes.*?ver=([0-9]+\.[0-9]+(?:\.[0-9]+)?)'
            ],
            'drupal': [
                r'<meta name="generator" content="Drupal ([0-9]+(?:\.[0-9]+)?)"',
                r'Drupal\.settings',
                r'/sites/all/.*?([0-9]+\.[0-9]+)'
            ],
            'joomla': [
                r'<meta name="generator" content="Joomla! - Open Source Content Management"',
                r'/media/jui/js/.*?([0-9]+\.[0-9]+\.[0-9]+)',
                r'Joomla! ([0-9]+\.[0-9]+(?:\.[0-9]+)?)'
            ],
            'jquery': [
                r'jquery[/-]([0-9]+\.[0-9]+(?:\.[0-9]+)?)',
                r'jQuery v([0-9]+\.[0-9]+(?:\.[0-9]+)?)'
            ],
            'bootstrap': [
                r'bootstrap[/-]([0-9]+\.[0-9]+(?:\.[0-9]+)?)',
                r'Bootstrap v([0-9]+\.[0-9]+(?:\.[0-9]+)?)'
            ],
            'express': [
                r'X-Powered-By:\s*Express',
                r'express[/-]([0-9]+\.[0-9]+(?:\.[0-9]+)?)'
            ],
            'react': [
                r'react[/-]([0-9]+\.[0-9]+(?:\.[0-9]+)?)',
                r'React v([0-9]+\.[0-9]+(?:\.[0-9]+)?)'
            ],
            'vue': [
                r'vue[/-]([0-9]+\.[0-9]+(?:\.[0-9]+)?)',
                r'Vue\.js v([0-9]+\.[0-9]+(?:\.[0-9]+)?)'
            ],
            'angular': [
                r'angular[/-]([0-9]+\.[0-9]+(?:\.[0-9]+)?)',
                r'Angular v([0-9]+\.[0-9]+(?:\.[0-9]+)?)'
            ]
        }
    
    @staticmethod
    def detect_outdated_software(response_headers: Dict[str, str], response_text: str, wappalyzer_technologies: List = None) -> List[Dict[str, Any]]:
        """
        Enhanced detection of outdated software versions with real-time CVE checking
        
        Args:
            response_headers: HTTP response headers
            response_text: HTTP response text
            wappalyzer_technologies: Technologies detected by Wappalyzer
        
        Returns:
            List of detected outdated software with real CVE information
        """
        detections = []
        patterns = OutdatedSoftwareDetector.get_software_version_patterns()
        
        # Combine headers into searchable text
        headers_text = '\n'.join([f"{k}: {v}" for k, v in response_headers.items()])
        search_text = headers_text + '\n' + response_text
        
        # First, process Wappalyzer technologies if available
        if wappalyzer_technologies:
            for tech in wappalyzer_technologies:
                tech_name = tech.lower() if isinstance(tech, str) else str(tech).lower()
                
                # Map Wappalyzer technology names to our software categories
                software_mapping = OutdatedSoftwareDetector._get_software_mapping()
                
                for wapp_name, software_key in software_mapping.items():
                    if wapp_name in tech_name:
                        # Try to extract version from Wappalyzer data or search for it
                        version = OutdatedSoftwareDetector._extract_version_from_wappalyzer(tech, search_text, software_key)
                        if version:
                            # Get real CVE data from external APIs
                            cves = OutdatedSoftwareDetector._fetch_cves_from_apis(software_key, version)
                            severity = OutdatedSoftwareDetector._calculate_severity_from_cves(cves)
                            
                            detection = {
                                'software': software_key,
                                'version': version,
                                'severity': severity,
                                'cves': cves,
                                'detection_method': 'wappalyzer_integration',
                                'exploit_available': any(cve.get('exploit_available', False) for cve in cves),
                                'max_cvss_score': max([cve.get('score', 0) for cve in cves], default=0),
                                'eol_status': OutdatedSoftwareDetector._check_eol_status(software_key, version)
                            }
                            detections.append(detection)
        
        # Then, use traditional pattern matching for additional detection
        for software, pattern_list in patterns.items():
            for pattern in pattern_list:
                matches = re.finditer(pattern, search_text, re.IGNORECASE)
                for match in matches:
                    version = match.group(1) if match.groups() else None
                    if not version:
                        continue
                    
                    # Skip if we already detected this software via Wappalyzer
                    if any(d['software'] == software and d['version'] == version for d in detections):
                        continue
                    
                    # Get real CVE data from external APIs
                    cves = OutdatedSoftwareDetector._fetch_cves_from_apis(software, version)
                    severity = OutdatedSoftwareDetector._calculate_severity_from_cves(cves)
                    
                    detection = {
                        'software': software,
                        'version': version,
                        'severity': severity,
                        'cves': cves,
                        'detection_method': 'header_analysis' if 'Server:' in match.group(0) or 'X-Powered-By:' in match.group(0) else 'content_analysis',
                        'exploit_available': any(cve.get('exploit_available', False) for cve in cves),
                        'max_cvss_score': max([cve.get('score', 0) for cve in cves], default=0),
                        'eol_status': OutdatedSoftwareDetector._check_eol_status(software, version)
                    }
                    detections.append(detection)
        
        return detections
    
    @staticmethod
    def _get_software_mapping() -> Dict[str, str]:
        """Get mapping of Wappalyzer technology names to software keys"""
        return {
            'php': 'php',
            'apache': 'apache', 
            'nginx': 'nginx',
            'microsoft iis': 'iis',
            'wordpress': 'wordpress',
            'drupal': 'drupal',
            'joomla': 'joomla',
            'jquery': 'jquery',
            'bootstrap': 'bootstrap',
            'tomcat': 'tomcat',
            'express': 'express',
            'react': 'react',
            'vue': 'vue',
            'angular': 'angular'
        }
    
    @staticmethod
    def _extract_version_from_wappalyzer(tech_data, search_text: str, software_key: str) -> Optional[str]:
        """Extract version from Wappalyzer technology data or search text"""
        # If tech_data is a dict with version info
        if isinstance(tech_data, dict) and 'version' in tech_data:
            return tech_data['version']
        
        # Try to find version in the search text using our patterns
        patterns = OutdatedSoftwareDetector.get_software_version_patterns()
        if software_key in patterns:
            for pattern in patterns[software_key]:
                match = re.search(pattern, search_text, re.IGNORECASE)
                if match and match.groups():
                    return match.group(1)
        
        return None
    
    @staticmethod
    def _fetch_cves_from_apis(software: str, version: str) -> List[Dict[str, Any]]:
        """Fetch CVE data from external APIs"""
        cves = []
        
        # Rate limiting
        current_time = time.time()
        if current_time - OutdatedSoftwareDetector._last_api_call < OutdatedSoftwareDetector._rate_limit_delay:
            time.sleep(OutdatedSoftwareDetector._rate_limit_delay)
        OutdatedSoftwareDetector._last_api_call = time.time()
        
        # Check cache first
        cache_key = f"{software}_{version}"
        if cache_key in OutdatedSoftwareDetector._api_cache:
            cache_time = OutdatedSoftwareDetector._cache_expiry.get(cache_key)
            if cache_time and datetime.now() < cache_time:
                return OutdatedSoftwareDetector._api_cache[cache_key]
        
        try:
            # Try multiple CVE data sources
            cves.extend(OutdatedSoftwareDetector._fetch_from_nist_nvd(software, version))
            cves.extend(OutdatedSoftwareDetector._fetch_from_cve_circl(software, version))
            
            # Cache the results for 24 hours
            OutdatedSoftwareDetector._api_cache[cache_key] = cves
            OutdatedSoftwareDetector._cache_expiry[cache_key] = datetime.now() + timedelta(hours=24)
            
        except Exception as e:
            print(f"Error fetching CVE data for {software} {version}: {e}")
        
        return cves
    
    @staticmethod
    def _fetch_from_nist_nvd(software: str, version: str) -> List[Dict[str, Any]]:
        """Fetch CVE data from NIST NVD API"""
        cves = []
        try:
            # NIST NVD API v2 - search by keyword
            url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
            params = {
                'keywordSearch': f"{software} {version}",
                'resultsPerPage': 10
            }
            headers = {'User-Agent': 'Dominator-Security-Scanner/1.0'}
            
            response = requests.get(url, params=params, headers=headers, timeout=10)
            if response.status_code == 200:
                data = response.json()
                for vuln in data.get('vulnerabilities', []):
                    cve_data = vuln.get('cve', {})
                    cve_id = cve_data.get('id', '')
                    
                    # Extract CVSS score
                    cvss_score = 0
                    severity = 'Unknown'
                    metrics = cve_data.get('metrics', {})
                    if 'cvssMetricV31' in metrics:
                        cvss = metrics['cvssMetricV31'][0]['cvssData']
                        cvss_score = cvss.get('baseScore', 0)
                        severity = cvss.get('baseSeverity', 'Unknown')
                    elif 'cvssMetricV30' in metrics:
                        cvss = metrics['cvssMetricV30'][0]['cvssData']
                        cvss_score = cvss.get('baseScore', 0)
                        severity = cvss.get('baseSeverity', 'Unknown')
                    
                    description = ''
                    descriptions = cve_data.get('descriptions', [])
                    if descriptions:
                        description = descriptions[0].get('value', '')
                    
                    cves.append({
                        'cve': cve_id,
                        'score': cvss_score,
                        'severity': severity,
                        'description': description,
                        'source': 'NIST NVD',
                        'exploit_available': OutdatedSoftwareDetector._check_exploit_availability(cve_id)
                    })
        except Exception as e:
            print(f"Error fetching from NIST NVD: {e}")
        
        return cves
    
    @staticmethod
    def _fetch_from_cve_circl(software: str, version: str) -> List[Dict[str, Any]]:
        """Fetch CVE data from CVE-CIRCL API"""
        cves = []
        try:
            # CVE-CIRCL API
            url = f"https://cve.circl.lu/api/search/{software}"
            headers = {'User-Agent': 'Dominator-Security-Scanner/1.0'}
            
            response = requests.get(url, headers=headers, timeout=10)
            if response.status_code == 200:
                data = response.json()
                count = 0
                for cve_id, cve_data in data.items():
                    if count >= 5:  # Limit results
                        break
                    if version in str(cve_data.get('vulnerable_product', [])):
                        cvss_score = float(cve_data.get('cvss', 0))
                        
                        cves.append({
                            'cve': cve_id,
                            'score': cvss_score,
                            'description': cve_data.get('summary', ''),
                            'source': 'CVE-CIRCL',
                            'exploit_available': OutdatedSoftwareDetector._check_exploit_availability(cve_id)
                        })
                        count += 1
        except Exception as e:
            print(f"Error fetching from CVE-CIRCL: {e}")
        
        return cves
    
    @staticmethod
    def _check_exploit_availability(cve_id: str) -> bool:
        """Check if exploits are available for a CVE"""
        try:
            # Check ExploitDB API
            url = f"https://www.exploit-db.com/search?cve={cve_id}"
            headers = {'User-Agent': 'Dominator-Security-Scanner/1.0'}
            
            response = requests.get(url, headers=headers, timeout=5)
            return 'No Results' not in response.text and response.status_code == 200
        except:
            return False
    
    @staticmethod
    def _check_eol_status(software: str, version: str) -> Dict[str, Any]:
        """Check End-of-Life status for software version"""
        try:
            # Use endoflife.date API
            url = f"https://endoflife.date/api/{software}.json"
            headers = {'User-Agent': 'Dominator-Security-Scanner/1.0'}
            
            response = requests.get(url, headers=headers, timeout=5)
            if response.status_code == 200:
                data = response.json()
                for release in data:
                    if str(release.get('cycle', '')).startswith(version.split('.')[0]):
                        return {
                            'is_eol': release.get('eol', False),
                            'eol_date': release.get('eol'),
                            'support_status': 'EOL' if release.get('eol', False) else 'Supported'
                        }
        except Exception as e:
            print(f"Error checking EOL status: {e}")
        
        return {'is_eol': False, 'eol_date': None, 'support_status': 'Unknown'}
    
    @staticmethod
    def _calculate_severity_from_cves(cves: List[Dict[str, Any]]) -> str:
        """Calculate severity based on CVE scores, exploit availability, and EOL status"""
        if not cves:
            return 'Info'
        
        max_score = max([cve.get('score', 0) for cve in cves], default=0)
        has_exploit = any(cve.get('exploit_available', False) for cve in cves)
        critical_cves = len([cve for cve in cves if cve.get('score', 0) >= 9.0])
        
        # Enhanced severity calculation
        if max_score >= 9.0 and has_exploit:
            return 'Critical'
        elif max_score >= 9.0 or (max_score >= 7.0 and has_exploit) or critical_cves >= 3:
            return 'Critical'
        elif max_score >= 7.0 or (max_score >= 5.0 and has_exploit):
            return 'High'
        elif max_score >= 4.0:
            return 'Medium'
        elif max_score > 0:
            return 'Low'
        else:
            return 'Info'
    
    @staticmethod
    def get_evidence(detections: List[Dict[str, Any]]) -> str:
        """Get evidence of outdated software with real CVE information"""
        if not detections:
            return "No outdated software detected"
        
        evidence_parts = []
        for detection in detections:
            software = detection['software']
            version = detection['version']
            cves = detection.get('cves', [])
            max_score = detection.get('max_cvss_score', 0)
            eol_status = detection.get('eol_status', {})
            
            evidence = f"{software.upper()} {version}"
            
            # Add EOL information
            if eol_status.get('is_eol', False):
                evidence += f" (EOL: {eol_status.get('eol_date', 'Yes')})"
            
            # Add CVE information
            if cves:
                cve_names = [cve['cve'] for cve in cves[:3]]
                evidence += f" (CVEs: {', '.join(cve_names)}"
                if max_score > 0:
                    evidence += f", Max CVSS: {max_score}"
                if detection.get('exploit_available'):
                    evidence += f", Exploits Available"
                
                # Add data sources
                sources = list(set([cve.get('source', 'Unknown') for cve in cves]))
                evidence += f", Sources: {', '.join(sources)}"
                evidence += ")"
            
            evidence_parts.append(evidence)
        
        return "; ".join(evidence_parts)
    
    @staticmethod
    def get_remediation_advice(software: str, version: str, cves: List[Dict[str, Any]] = None, eol_status: Dict[str, Any] = None) -> str:
        """Get detailed remediation advice with real CVE and EOL information"""
        # Get latest version information from external sources
        latest_version = OutdatedSoftwareDetector._get_latest_version(software)
        
        base_advice = f"Upgrade {software.title()} from version {version} to the latest stable version"
        if latest_version:
            base_advice += f" ({latest_version})"
        base_advice += "."
        
        # Add EOL-specific advice
        if eol_status and eol_status.get('is_eol', False):
            base_advice += f" URGENT: This version reached End-of-Life on {eol_status.get('eol_date', 'unknown date')} and no longer receives security updates."
        
        # Add CVE-specific advice
        if cves:
            critical_cves = [cve for cve in cves if cve.get('score', 0) >= 9.0]
            high_cves = [cve for cve in cves if 7.0 <= cve.get('score', 0) < 9.0]
            exploit_cves = [cve for cve in cves if cve.get('exploit_available', False)]
            
            if critical_cves:
                base_advice += f" CRITICAL: {len(critical_cves)} critical vulnerabilities (CVSS ≥9.0) found."
            if high_cves:
                base_advice += f" HIGH: {len(high_cves)} high-severity vulnerabilities (CVSS 7.0-8.9) found."
            if exploit_cves:
                base_advice += f" EXPLOITABLE: {len(exploit_cves)} vulnerabilities have publicly available exploits."
            
            # Add specific CVE references
            top_cves = sorted(cves, key=lambda x: x.get('score', 0), reverse=True)[:3]
            if top_cves:
                cve_refs = [f"{cve['cve']} (CVSS: {cve.get('score', 'N/A')})" for cve in top_cves]
                base_advice += f" Top CVEs: {', '.join(cve_refs)}."
        
        return base_advice
    
    @staticmethod
    def _get_latest_version(software: str) -> Optional[str]:
        """Get latest version information from external sources"""
        try:
            # Try different APIs for version information
            if software == 'php':
                return OutdatedSoftwareDetector._get_php_latest_version()
            elif software in ['apache', 'nginx', 'wordpress', 'drupal', 'joomla']:
                return OutdatedSoftwareDetector._get_github_latest_version(software)
            elif software in ['jquery', 'bootstrap', 'react', 'vue', 'angular']:
                return OutdatedSoftwareDetector._get_npm_latest_version(software)
        except Exception as e:
            print(f"Error getting latest version for {software}: {e}")
        
        return None
    
    @staticmethod
    def _get_php_latest_version() -> Optional[str]:
        """Get latest PHP version from official API"""
        try:
            url = "https://www.php.net/releases/index.php?json&version=8"
            response = requests.get(url, timeout=5)
            if response.status_code == 200:
                data = response.json()
                return data.get('version')
        except:
            pass
        return None
    
    @staticmethod
    def _get_github_latest_version(software: str) -> Optional[str]:
        """Get latest version from GitHub releases"""
        repo_mapping = {
            'apache': 'apache/httpd',
            'nginx': 'nginx/nginx',
            'wordpress': 'WordPress/WordPress',
            'drupal': 'drupal/drupal',
            'joomla': 'joomla/joomla-cms'
        }
        
        repo = repo_mapping.get(software)
        if not repo:
            return None
        
        try:
            url = f"https://api.github.com/repos/{repo}/releases/latest"
            headers = {'User-Agent': 'Dominator-Security-Scanner/1.0'}
            response = requests.get(url, headers=headers, timeout=5)
            if response.status_code == 200:
                data = response.json()
                tag = data.get('tag_name', '')
                # Clean version tag (remove 'v' prefix, etc.)
                return re.sub(r'^[vV]', '', tag)
        except:
            pass
        return None
    
    @staticmethod
    def _get_npm_latest_version(package: str) -> Optional[str]:
        """Get latest version from NPM registry"""
        try:
            url = f"https://registry.npmjs.org/{package}/latest"
            response = requests.get(url, timeout=5)
            if response.status_code == 200:
                data = response.json()
                return data.get('version')
        except:
            pass
        return None
