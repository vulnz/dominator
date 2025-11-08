"""
Outdated software detection logic with CVE API integration
"""

import re
import json
import requests
from typing import Dict, Any, List, Tuple, Optional
from datetime import datetime, timedelta
import time
import hashlib

class OutdatedSoftwareDetector:
    """Enhanced outdated software vulnerability detection with CVE API integration"""
    
    # Cache for API responses to avoid repeated calls
    _api_cache = {}
    _cache_expiry = {}
    _rate_limit_delay = 2  # Delay between API calls in seconds
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
        Enhanced detection of outdated software versions with CVE API integration
        
        Args:
            response_headers: HTTP response headers
            response_text: HTTP response text
            wappalyzer_technologies: Technologies detected by Wappalyzer
        
        Returns:
            List of detected outdated software with CVE information and links
        """
        detections = []
        patterns = OutdatedSoftwareDetector.get_software_version_patterns()
        
        # Combine headers into searchable text
        headers_text = '\n'.join([f"{k}: {v}" for k, v in response_headers.items()])
        search_text = headers_text + '\n' + response_text
        
        # Process pattern matching for software detection
        for software, pattern_list in patterns.items():
            for pattern in pattern_list:
                matches = re.finditer(pattern, search_text, re.IGNORECASE)
                for match in matches:
                    version = match.group(1) if match.groups() else None
                    if not version:
                        continue
                    
                    # Skip if we already detected this software version
                    if any(d['software'] == software and d['version'] == version for d in detections):
                        continue
                    
                    # Get CVE data from APIs
                    cve_data = OutdatedSoftwareDetector._fetch_cve_data(software, version)
                    
                    detection = {
                        'software': software,
                        'version': version,
                        'severity': cve_data['severity'],
                        'cve_count': cve_data['cve_count'],
                        'critical_cves': cve_data['critical_cves'],
                        'high_cves': cve_data['high_cves'],
                        'cve_links': cve_data['cve_links'],
                        'latest_version': cve_data['latest_version'],
                        'is_eol': cve_data['is_eol'],
                        'eol_date': cve_data['eol_date'],
                        'detection_method': 'header_analysis' if 'Server:' in match.group(0) or 'X-Powered-By:' in match.group(0) else 'content_analysis'
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
    def _fetch_cve_data(software: str, version: str) -> Dict[str, Any]:
        """Fetch comprehensive CVE data from multiple APIs"""
        # Rate limiting
        current_time = time.time()
        if current_time - OutdatedSoftwareDetector._last_api_call < OutdatedSoftwareDetector._rate_limit_delay:
            time.sleep(OutdatedSoftwareDetector._rate_limit_delay)
        OutdatedSoftwareDetector._last_api_call = time.time()
        
        # Check cache first
        cache_key = hashlib.md5(f"{software}_{version}".encode()).hexdigest()
        if cache_key in OutdatedSoftwareDetector._api_cache:
            cache_time = OutdatedSoftwareDetector._cache_expiry.get(cache_key)
            if cache_time and datetime.now() < cache_time:
                return OutdatedSoftwareDetector._api_cache[cache_key]
        
        # Initialize result structure
        result = {
            'severity': 'Info',
            'cve_count': 0,
            'critical_cves': [],
            'high_cves': [],
            'cve_links': [],
            'latest_version': None,
            'is_eol': False,
            'eol_date': None
        }
        
        try:
            # Fetch from NVD API
            nvd_data = OutdatedSoftwareDetector._fetch_from_nvd_api(software, version)
            if nvd_data:
                result.update(nvd_data)
            
            # Fetch EOL information
            eol_data = OutdatedSoftwareDetector._fetch_eol_data(software, version)
            if eol_data:
                result['is_eol'] = eol_data.get('is_eol', False)
                result['eol_date'] = eol_data.get('eol_date')
            
            # Fetch latest version info
            latest_version = OutdatedSoftwareDetector._fetch_latest_version(software)
            if latest_version:
                result['latest_version'] = latest_version
            
            # Cache the results for 6 hours
            OutdatedSoftwareDetector._api_cache[cache_key] = result
            OutdatedSoftwareDetector._cache_expiry[cache_key] = datetime.now() + timedelta(hours=6)
            
        except Exception as e:
            print(f"Error fetching CVE data for {software} {version}: {e}")
        
        return result
    
    @staticmethod
    def _fetch_from_nvd_api(software: str, version: str) -> Optional[Dict[str, Any]]:
        """Fetch CVE data from NIST NVD API v2"""
        try:
            # Map software names to CPE format
            cpe_name = OutdatedSoftwareDetector._get_cpe_name(software)
            if not cpe_name:
                return None
            
            # NIST NVD API v2 - search by CPE
            url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
            params = {
                'cpeName': f"cpe:2.3:a:*:{cpe_name}:{version}:*:*:*:*:*:*:*",
                'resultsPerPage': 20
            }
            headers = {'User-Agent': 'Dominator-Security-Scanner/1.0'}
            
            response = requests.get(url, params=params, headers=headers, timeout=15)
            if response.status_code != 200:
                # Fallback to keyword search
                params = {
                    'keywordSearch': f"{software} {version}",
                    'resultsPerPage': 10
                }
                response = requests.get(url, params=params, headers=headers, timeout=15)
            
            if response.status_code == 200:
                data = response.json()
                vulnerabilities = data.get('vulnerabilities', [])
                
                if not vulnerabilities:
                    return None
                
                critical_cves = []
                high_cves = []
                cve_links = []
                max_score = 0
                
                for vuln in vulnerabilities[:15]:  # Limit to first 15 CVEs
                    cve_data = vuln.get('cve', {})
                    cve_id = cve_data.get('id', '')
                    
                    if not cve_id:
                        continue
                    
                    # Extract CVSS score and severity
                    cvss_score = 0
                    severity = 'Unknown'
                    metrics = cve_data.get('metrics', {})
                    
                    if 'cvssMetricV31' in metrics and metrics['cvssMetricV31']:
                        cvss = metrics['cvssMetricV31'][0]['cvssData']
                        cvss_score = cvss.get('baseScore', 0)
                        severity = cvss.get('baseSeverity', 'Unknown')
                    elif 'cvssMetricV30' in metrics and metrics['cvssMetricV30']:
                        cvss = metrics['cvssMetricV30'][0]['cvssData']
                        cvss_score = cvss.get('baseScore', 0)
                        severity = cvss.get('baseSeverity', 'Unknown')
                    elif 'cvssMetricV2' in metrics and metrics['cvssMetricV2']:
                        cvss = metrics['cvssMetricV2'][0]['cvssData']
                        cvss_score = cvss.get('baseScore', 0)
                        # Convert CVSS v2 to severity
                        if cvss_score >= 9.0:
                            severity = 'CRITICAL'
                        elif cvss_score >= 7.0:
                            severity = 'HIGH'
                        elif cvss_score >= 4.0:
                            severity = 'MEDIUM'
                        else:
                            severity = 'LOW'
                    
                    max_score = max(max_score, cvss_score)
                    
                    # Create CVE link
                    cve_link = f"https://nvd.nist.gov/vuln/detail/{cve_id}"
                    cve_links.append({
                        'cve_id': cve_id,
                        'url': cve_link,
                        'score': cvss_score,
                        'severity': severity
                    })
                    
                    # Categorize by severity
                    if cvss_score >= 9.0:
                        critical_cves.append({
                            'cve_id': cve_id,
                            'score': cvss_score,
                            'url': cve_link
                        })
                    elif cvss_score >= 7.0:
                        high_cves.append({
                            'cve_id': cve_id,
                            'score': cvss_score,
                            'url': cve_link
                        })
                
                # Determine overall severity
                overall_severity = 'Info'
                if max_score >= 9.0:
                    overall_severity = 'Critical'
                elif max_score >= 7.0:
                    overall_severity = 'High'
                elif max_score >= 4.0:
                    overall_severity = 'Medium'
                elif max_score > 0:
                    overall_severity = 'Low'
                
                return {
                    'severity': overall_severity,
                    'cve_count': len(vulnerabilities),
                    'critical_cves': critical_cves,
                    'high_cves': high_cves,
                    'cve_links': cve_links
                }
                
        except Exception as e:
            print(f"Error fetching from NVD API: {e}")
        
        return None
    
    @staticmethod
    def _get_cpe_name(software: str) -> Optional[str]:
        """Map software names to CPE format names"""
        cpe_mapping = {
            'php': 'php',
            'apache': 'apache_http_server',
            'nginx': 'nginx',
            'iis': 'internet_information_server',
            'wordpress': 'wordpress',
            'drupal': 'drupal',
            'joomla': 'joomla',
            'mysql': 'mysql',
            'postgresql': 'postgresql',
            'tomcat': 'tomcat',
            'jenkins': 'jenkins',
            'node': 'node.js',
            'express': 'express',
            'react': 'react',
            'vue': 'vue.js',
            'angular': 'angular'
        }
        return cpe_mapping.get(software.lower())
    
    @staticmethod
    def _fetch_eol_data(software: str, version: str) -> Optional[Dict[str, Any]]:
        """Fetch End-of-Life data from endoflife.date API"""
        try:
            # Map software names to endoflife.date product names
            eol_mapping = {
                'php': 'php',
                'apache': 'apache',
                'nginx': 'nginx',
                'wordpress': 'wordpress',
                'drupal': 'drupal',
                'mysql': 'mysql',
                'postgresql': 'postgresql',
                'nodejs': 'nodejs',
                'node': 'nodejs'
            }
            
            product = eol_mapping.get(software.lower())
            if not product:
                return None
            
            url = f"https://endoflife.date/api/{product}.json"
            headers = {'User-Agent': 'Dominator-Security-Scanner/1.0'}
            
            response = requests.get(url, headers=headers, timeout=10)
            if response.status_code == 200:
                data = response.json()
                
                # Find matching version
                version_major = version.split('.')[0]
                for release in data:
                    cycle = str(release.get('cycle', ''))
                    if cycle.startswith(version_major) or version.startswith(cycle):
                        eol_date = release.get('eol')
                        is_eol = False
                        
                        if eol_date:
                            if isinstance(eol_date, bool):
                                is_eol = eol_date
                            else:
                                try:
                                    eol_datetime = datetime.strptime(str(eol_date), '%Y-%m-%d')
                                    is_eol = datetime.now() > eol_datetime
                                except:
                                    is_eol = False
                        
                        return {
                            'is_eol': is_eol,
                            'eol_date': str(eol_date) if eol_date else None
                        }
        except Exception as e:
            print(f"Error fetching EOL data: {e}")
        
        return None
    
    @staticmethod
    def _fetch_latest_version(software: str) -> Optional[str]:
        """Fetch latest version information from various APIs"""
        try:
            if software.lower() == 'php':
                return OutdatedSoftwareDetector._get_php_latest_version()
            elif software.lower() in ['wordpress', 'drupal', 'joomla']:
                return OutdatedSoftwareDetector._get_github_latest_version(software)
            elif software.lower() in ['jquery', 'bootstrap', 'react', 'vue', 'angular']:
                return OutdatedSoftwareDetector._get_npm_latest_version(software)
        except Exception as e:
            print(f"Error getting latest version for {software}: {e}")
        
        return None
    
    @staticmethod
    def get_evidence(detections: List[Dict[str, Any]]) -> str:
        """Get evidence of outdated software with CVE information and links"""
        if not detections:
            return "No outdated software detected"
        
        evidence_parts = []
        for detection in detections:
            software = detection['software']
            version = detection['version']
            cve_count = detection.get('cve_count', 0)
            critical_cves = detection.get('critical_cves', [])
            high_cves = detection.get('high_cves', [])
            latest_version = detection.get('latest_version')
            is_eol = detection.get('is_eol', False)
            eol_date = detection.get('eol_date')
            
            evidence = f"{software.upper()} {version}"
            
            # Add version comparison
            if latest_version:
                evidence += f" (Latest: {latest_version})"
            
            # Add EOL information
            if is_eol:
                evidence += f" [EOL: {eol_date}]" if eol_date else " [EOL]"
            
            # Add CVE information
            if cve_count > 0:
                evidence += f" - {cve_count} CVE(s)"
                if critical_cves:
                    evidence += f" ({len(critical_cves)} Critical"
                    if high_cves:
                        evidence += f", {len(high_cves)} High)"
                    else:
                        evidence += ")"
                elif high_cves:
                    evidence += f" ({len(high_cves)} High)"
            
            evidence_parts.append(evidence)
        
        return "; ".join(evidence_parts)
    
    @staticmethod
    def get_remediation_advice(software: str, version: str, detection_data: Dict[str, Any] = None) -> str:
        """Get detailed remediation advice with CVE and version information"""
        latest_version = detection_data.get('latest_version') if detection_data else None
        is_eol = detection_data.get('is_eol', False) if detection_data else False
        eol_date = detection_data.get('eol_date') if detection_data else None
        critical_cves = detection_data.get('critical_cves', []) if detection_data else []
        high_cves = detection_data.get('high_cves', []) if detection_data else []
        
        base_advice = f"Upgrade {software.title()} from version {version}"
        if latest_version:
            base_advice += f" to the latest stable version ({latest_version})"
        base_advice += "."
        
        # Add EOL-specific advice
        if is_eol:
            urgency = " URGENT:"
            if eol_date:
                base_advice += f"{urgency} This version reached End-of-Life on {eol_date} and no longer receives security updates."
            else:
                base_advice += f"{urgency} This version has reached End-of-Life and no longer receives security updates."
        
        # Add CVE-specific advice
        if critical_cves:
            base_advice += f" CRITICAL: {len(critical_cves)} critical vulnerabilities (CVSS ≥9.0) found."
        if high_cves:
            base_advice += f" HIGH: {len(high_cves)} high-severity vulnerabilities (CVSS 7.0-8.9) found."
        
        # Add specific CVE references with links
        if critical_cves or high_cves:
            top_cves = (critical_cves + high_cves)[:3]
            if top_cves:
                cve_refs = []
                for cve in top_cves:
                    cve_refs.append(f"{cve['cve_id']} (CVSS: {cve.get('score', 'N/A')}) - {cve.get('url', '')}")
                base_advice += f" Top CVEs: {'; '.join(cve_refs)}."
        
        return base_advice
    
    @staticmethod
    def get_cve_links_html(cve_links: List[Dict[str, Any]]) -> str:
        """Generate HTML links for CVEs"""
        if not cve_links:
            return "No CVEs found"
        
        html_links = []
        for cve in cve_links[:10]:  # Limit to first 10 CVEs
            cve_id = cve.get('cve_id', '')
            url = cve.get('url', '')
            score = cve.get('score', 0)
            severity = cve.get('severity', 'Unknown')
            
            if url:
                html_links.append(f'<a href="{url}" target="_blank">{cve_id}</a> (CVSS: {score}, {severity})')
            else:
                html_links.append(f'{cve_id} (CVSS: {score}, {severity})')
        
        return '<br>'.join(html_links)
    
    @staticmethod
    def _get_php_latest_version() -> Optional[str]:
        """Get latest PHP version from official API"""
        try:
            url = "https://www.php.net/releases/index.php?json&version=8"
            headers = {'User-Agent': 'Dominator-Security-Scanner/1.0'}
            response = requests.get(url, headers=headers, timeout=10)
            if response.status_code == 200:
                data = response.json()
                return data.get('version')
        except Exception as e:
            print(f"Error fetching PHP version: {e}")
        return None
    
    @staticmethod
    def _get_github_latest_version(software: str) -> Optional[str]:
        """Get latest version from GitHub releases"""
        repo_mapping = {
            'wordpress': 'WordPress/WordPress',
            'drupal': 'drupal/drupal',
            'joomla': 'joomla/joomla-cms'
        }
        
        repo = repo_mapping.get(software.lower())
        if not repo:
            return None
        
        try:
            url = f"https://api.github.com/repos/{repo}/releases/latest"
            headers = {'User-Agent': 'Dominator-Security-Scanner/1.0'}
            response = requests.get(url, headers=headers, timeout=10)
            if response.status_code == 200:
                data = response.json()
                tag = data.get('tag_name', '')
                # Clean version tag (remove 'v' prefix, etc.)
                return re.sub(r'^[vV]', '', tag)
        except Exception as e:
            print(f"Error fetching GitHub version for {software}: {e}")
        return None
    
    @staticmethod
    def _get_npm_latest_version(package: str) -> Optional[str]:
        """Get latest version from NPM registry"""
        try:
            url = f"https://registry.npmjs.org/{package}/latest"
            headers = {'User-Agent': 'Dominator-Security-Scanner/1.0'}
            response = requests.get(url, headers=headers, timeout=10)
            if response.status_code == 200:
                data = response.json()
                return data.get('version')
        except Exception as e:
            print(f"Error fetching NPM version for {package}: {e}")
        return None
