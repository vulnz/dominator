"""
Git repository scanner module
Specialized scanner for Git exposure detection
"""

import requests
from typing import List, Dict, Any, Tuple
from detectors.git_detector import GitDetector
from payloads.git_payloads import GitPayloads


class GitScanner:
    """Specialized Git repository scanner"""
    
    def __init__(self, config, request_counter=None, scan_stats=None):
        """Initialize Git scanner"""
        self.config = config
        self.request_counter = request_counter
        self.scan_stats = scan_stats or {}
        self.found_vulnerabilities = set()
        
    def scan_git_exposure(self, parsed_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Main Git exposure scanning method"""
        results = []
        base_url = parsed_data['url']
        
        # Update payload stats
        module_key = 'git'
        if module_key not in self.scan_stats.get('payload_stats', {}):
            if 'payload_stats' not in self.scan_stats:
                self.scan_stats['payload_stats'] = {}
            self.scan_stats['payload_stats'][module_key] = {
                'payloads_used': 0, 'requests_made': 0, 'successful_payloads': 0
            }
        
        # Remove query parameters from base URL
        if '?' in base_url:
            base_url = base_url.split('?')[0]
        
        # Get the base directory URL
        base_dir = self._get_base_directory(base_url)
        
        try:
            print(f"    [GITEXPOSED] Testing for exposed .git repository...")
            print(f"    [GITEXPOSED] Base directory: {base_dir}")
            
            # Get git paths to test
            git_paths = self._get_git_paths()
            
            # Update payload stats
            self.scan_stats['payload_stats'][module_key]['payloads_used'] += len(git_paths)
            
            print(f"    [GITEXPOSED] Testing {len(git_paths)} git paths...")
            
            # Collect all exposed git files
            exposed_files = []
            highest_severity = 'Low'
            
            # Test each git path individually
            for git_path in git_paths:
                if self._should_stop():
                    break
                    
                try:
                    test_url = f"{base_dir}{git_path}"
                    
                    # Make HTTP request
                    response = self._make_request(test_url)
                    if response is None:
                        continue
                    
                    # Update request count
                    self._update_request_count(module_key)
                    
                    print(f"    [GITEXPOSED] Testing: {git_path} -> {response.status_code} ({len(response.text)} bytes)")
                    
                    # Use Git detector
                    is_exposed, evidence, severity = GitDetector.detect_git_exposure(
                        response.text, response.status_code, test_url
                    )
                    
                    if is_exposed:
                        print(f"    [GITEXPOSED] GIT EXPOSURE FOUND: {git_path} - {evidence}")
                        
                        # Get detailed evidence
                        file_info = self._process_exposed_file(git_path, response, evidence, severity)
                        exposed_files.append(file_info)
                        
                        # Update successful payload count
                        self._update_success_count(module_key)
                        
                        # Track highest severity
                        if severity == 'High':
                            highest_severity = 'High'
                        elif severity == 'Medium' and highest_severity != 'High':
                            highest_severity = 'Medium'
                        
                    else:
                        print(f"    [GITEXPOSED] No exposure: {git_path} - {evidence}")
                        
                except Exception as e:
                    print(f"    [GITEXPOSED] Error testing {git_path}: {e}")
                    continue
            
            # Create grouped or individual vulnerabilities
            if exposed_files:
                results = self._create_vulnerability_results(exposed_files, base_dir, highest_severity)
                print(f"    [GITEXPOSED] Found {len(exposed_files)} git file exposures")
            else:
                print(f"    [GITEXPOSED] No git repository exposures found")
                
        except Exception as e:
            print(f"    [GITEXPOSED] Error during git exposure testing: {e}")
        
        return results
    
    def _get_base_directory(self, base_url: str) -> str:
        """Get base directory URL for testing"""
        if base_url.endswith('.php') or base_url.endswith('.html') or base_url.endswith('.asp'):
            # For file URLs, use the directory containing the file
            base_dir = '/'.join(base_url.split('/')[:-1]) + '/'
        else:
            # Ensure base URL ends with /
            if not base_url.endswith('/'):
                base_url += '/'
            base_dir = base_url
        
        return base_dir
    
    def _get_git_paths(self) -> List[str]:
        """Get git paths to test with fallback"""
        try:
            return GitPayloads.get_git_paths()
        except:
            # Fallback git paths if GitPayloads is not available
            return [
                '.git/',
                '.git/config',
                '.git/HEAD',
                '.git/index',
                '.git/logs/HEAD',
                '.git/logs/refs/heads/master',
                '.git/logs/refs/heads/main',
                '.git/refs/heads/master',
                '.git/refs/heads/main',
                '.git/objects/',
                '.git/info/refs',
                '.git/description',
                '.git/hooks/',
                '.git/packed-refs'
            ]
    
    def _make_request(self, test_url: str) -> requests.Response:
        """Make HTTP request with error handling"""
        try:
            response = requests.get(
                test_url,
                timeout=self.config.timeout,
                headers=self.config.headers,
                verify=False,
                allow_redirects=False
            )
            return response
        except Exception as e:
            print(f"    [GITEXPOSED] Request error for {test_url}: {e}")
            return None
    
    def _update_request_count(self, module_key: str):
        """Update request count statistics"""
        if self.request_counter:
            if hasattr(self.request_counter, 'increment'):
                self.request_counter.increment()
            else:
                # Assume it's a simple counter object
                self.request_counter += 1
        
        if 'payload_stats' in self.scan_stats and module_key in self.scan_stats['payload_stats']:
            self.scan_stats['payload_stats'][module_key]['requests_made'] += 1
    
    def _update_success_count(self, module_key: str):
        """Update successful payload count"""
        if 'payload_stats' in self.scan_stats and module_key in self.scan_stats['payload_stats']:
            self.scan_stats['payload_stats'][module_key]['successful_payloads'] += 1
        
        if 'total_payloads_used' in self.scan_stats:
            self.scan_stats['total_payloads_used'] += 1
    
    def _process_exposed_file(self, git_path: str, response: requests.Response, 
                            evidence: str, severity: str) -> Dict[str, Any]:
        """Process exposed git file and extract information"""
        try:
            detailed_evidence = GitDetector.get_evidence(git_path, response.text)
            response_snippet = GitDetector.get_response_snippet(response.text)
        except:
            detailed_evidence = evidence
            response_snippet = response.text[:200] + "..." if len(response.text) > 200 else response.text
        
        return {
            'path': git_path,
            'url': response.url,
            'evidence': detailed_evidence,
            'severity': severity,
            'response_snippet': response_snippet[:100] + "..." if len(response_snippet) > 100 else response_snippet
        }
    
    def _create_vulnerability_results(self, exposed_files: List[Dict[str, Any]], 
                                    base_dir: str, highest_severity: str) -> List[Dict[str, Any]]:
        """Create vulnerability results from exposed files"""
        results = []
        
        if len(exposed_files) <= 7:
            # Group into single vulnerability
            print(f"    [GITEXPOSED] Grouping {len(exposed_files)} git exposures into single finding")
            
            # Build comprehensive evidence
            file_list = []
            critical_files = []
            for file_info in exposed_files:
                file_list.append(f"• {file_info['path']} ({file_info['severity']})")
                if file_info['severity'] == 'High':
                    critical_files.append(file_info['path'])
            
            evidence = f"Git repository exposed with {len(exposed_files)} accessible files:\n" + "\n".join(file_list)
            if critical_files:
                evidence += f"\n\nCRITICAL FILES EXPOSED: {', '.join(critical_files)}"
            
            # Build response snippet from most critical files
            response_snippets = []
            for file_info in exposed_files[:3]:  # Show first 3 files
                response_snippets.append(f"{file_info['path']}: {file_info['response_snippet']}")
            
            response_snippet = "\n".join(response_snippets)
            if len(exposed_files) > 3:
                response_snippet += f"\n... and {len(exposed_files) - 3} more files"
            
            # Get remediation advice
            remediation = GitDetector.get_remediation_advice('.git')
            
            results.append({
                'module': 'gitexposed',
                'target': base_dir,
                'vulnerability': f'Git Repository Exposed ({len(exposed_files)} files)',
                'severity': highest_severity,
                'parameter': f'git_repository: {len(exposed_files)} files',
                'payload': ', '.join([f['path'] for f in exposed_files]),
                'evidence': evidence,
                'request_url': base_dir + '.git/',
                'detector': 'GitDetector.detect_git_exposure',
                'response_snippet': response_snippet,
                'remediation': remediation,
                'exposed_files': exposed_files  # Keep detailed info for reports
            })
        else:
            # Too many files, create individual vulnerabilities
            print(f"    [GITEXPOSED] Found {len(exposed_files)} git exposures - creating individual findings")
            for file_info in exposed_files:
                remediation = GitDetector.get_remediation_advice(file_info['path'])
                
                results.append({
                    'module': 'git',
                    'target': file_info['url'],
                    'vulnerability': f'Git File Exposed: {file_info["path"]}',
                    'severity': file_info['severity'],
                    'parameter': f'git_file: {file_info["path"]}',
                    'payload': file_info['path'],
                    'evidence': file_info['evidence'],
                    'request_url': file_info['url'],
                    'detector': 'GitDetector.detect_git_exposure',
                    'response_snippet': file_info['response_snippet'],
                    'remediation': remediation
                })
        
        return results
    
    def _should_stop(self) -> bool:
        """Check if scanning should stop"""
        # Check if request counter has stop condition
        if hasattr(self.request_counter, 'should_stop'):
            return self.request_counter.should_stop()
        
        # Check if config has request limit
        if hasattr(self.config, 'request_limit') and self.config.request_limit:
            if hasattr(self.request_counter, 'count'):
                return self.request_counter.count >= self.config.request_limit
            elif isinstance(self.request_counter, int):
                return self.request_counter >= self.config.request_limit
        
        return False
