"""
Git repository exposure detector
"""

import re
from typing import Tuple, List, Dict, Any

class GitDetector:
    """Git repository exposure detection logic"""
    
    @staticmethod
    def detect_git_exposure(response_text: str, response_code: int, url: str) -> Tuple[bool, str, str]:
        """
        Detect if .git directory or files are exposed
        Returns (is_exposed, evidence, severity)
        """
        if response_code == 404:
            return False, "HTTP 404 - .git not found", "Info"
        
        if response_code == 403:
            return True, "HTTP 403 - .git directory exists but access forbidden", "Medium"
        
        if response_code != 200:
            return False, f"HTTP {response_code} - unexpected response", "Info"
        
        # Check for git directory listing
        if GitDetector._is_git_directory_listing(response_text):
            return True, "Git directory listing exposed", "High"
        
        # Check for git files content
        git_file_type = GitDetector._detect_git_file_type(url, response_text)
        if git_file_type:
            severity = GitDetector._get_git_file_severity(git_file_type)
            return True, f"Git {git_file_type} file exposed", severity
        
        # Check for git-specific content patterns
        if GitDetector._has_git_content_patterns(response_text):
            return True, "Git repository content detected", "High"
        
        return False, "No git exposure detected", "Info"
    
    @staticmethod
    def _is_git_directory_listing(response_text: str) -> bool:
        """Check if response shows git directory listing"""
        response_lower = response_text.lower()
        
        git_listing_indicators = [
            'index of /.git',
            'directory listing for /.git',
            'parent directory',
            'config</a>',
            'head</a>',
            'refs/</a>',
            'objects/</a>',
            'hooks/</a>',
            'logs/</a>',
            'info/</a>'
        ]
        
        # Need multiple indicators for directory listing
        found_indicators = sum(1 for indicator in git_listing_indicators 
                              if indicator in response_lower)
        
        return found_indicators >= 3
    
    @staticmethod
    def _detect_git_file_type(url: str, response_text: str) -> str:
        """Detect what type of git file is exposed"""
        url_lower = url.lower()
        
        # Check URL path for git files
        if '/.git/config' in url_lower:
            if GitDetector._is_git_config_file(response_text):
                return "config"
        
        if '/.git/head' in url_lower:
            if GitDetector._is_git_head_file(response_text):
                return "HEAD"
        
        if '/.git/index' in url_lower:
            if GitDetector._is_git_index_file(response_text):
                return "index"
        
        if '/.git/logs/' in url_lower:
            if GitDetector._is_git_log_file(response_text):
                return "log"
        
        if '/.git/refs/' in url_lower:
            if GitDetector._is_git_ref_file(response_text):
                return "reference"
        
        if '/.git/objects/' in url_lower:
            if GitDetector._is_git_object_file(response_text):
                return "object"
        
        return ""
    
    @staticmethod
    def _is_git_config_file(response_text: str) -> bool:
        """Check if response contains git config file content"""
        config_patterns = [
            r'\[core\]',
            r'\[remote\s+["\']?origin["\']?\]',
            r'repositoryformatversion\s*=',
            r'filemode\s*=',
            r'bare\s*=',
            r'url\s*=.*\.git',
            r'\[branch\s+["\']?\w+["\']?\]'
        ]
        
        found_patterns = sum(1 for pattern in config_patterns 
                           if re.search(pattern, response_text, re.IGNORECASE))
        
        return found_patterns >= 2
    
    @staticmethod
    def _is_git_head_file(response_text: str) -> bool:
        """Check if response contains git HEAD file content"""
        head_patterns = [
            r'^ref:\s*refs/heads/\w+',
            r'^[a-f0-9]{40}$',
            r'^[a-f0-9]{64}$'  # SHA-256 for newer git
        ]
        
        response_stripped = response_text.strip()
        return any(re.match(pattern, response_stripped, re.MULTILINE) 
                  for pattern in head_patterns)
    
    @staticmethod
    def _is_git_index_file(response_text: str) -> bool:
        """Check if response contains git index file (binary)"""
        # Git index files start with "DIRC" signature
        return response_text.startswith('DIRC') or 'DIRC' in response_text[:20]
    
    @staticmethod
    def _is_git_log_file(response_text: str) -> bool:
        """Check if response contains git log file content"""
        log_patterns = [
            r'[a-f0-9]{40}\s+[a-f0-9]{40}',  # SHA hashes
            r'[a-f0-9]{64}\s+[a-f0-9]{64}',  # SHA-256 hashes
            r'\d{10}\s+[+-]\d{4}',           # Timestamp with timezone
            r'commit\s+[a-f0-9]{40}',
            r'tree\s+[a-f0-9]{40}',
            r'parent\s+[a-f0-9]{40}'
        ]
        
        found_patterns = sum(1 for pattern in log_patterns 
                           if re.search(pattern, response_text))
        
        return found_patterns >= 1
    
    @staticmethod
    def _is_git_ref_file(response_text: str) -> bool:
        """Check if response contains git reference file content"""
        ref_patterns = [
            r'^[a-f0-9]{40}$',
            r'^[a-f0-9]{64}$'
        ]
        
        response_stripped = response_text.strip()
        return any(re.match(pattern, response_stripped) 
                  for pattern in ref_patterns)
    
    @staticmethod
    def _is_git_object_file(response_text: str) -> bool:
        """Check if response contains git object file (usually binary)"""
        # Git objects are usually compressed, look for zlib header or git signatures
        if len(response_text) == 0:
            return False
        
        # Check for zlib compression header
        if response_text.startswith('\x78'):
            return True
        
        # Check for loose object patterns
        object_patterns = [
            r'^blob\s+\d+\x00',
            r'^tree\s+\d+\x00',
            r'^commit\s+\d+\x00',
            r'^tag\s+\d+\x00'
        ]
        
        return any(re.match(pattern, response_text, re.MULTILINE) 
                  for pattern in object_patterns)
    
    @staticmethod
    def _has_git_content_patterns(response_text: str) -> bool:
        """Check for general git content patterns"""
        git_patterns = [
            r'\.git[/\\]',
            r'refs[/\\]heads[/\\]',
            r'refs[/\\]tags[/\\]',
            r'objects[/\\][a-f0-9]{2}[/\\][a-f0-9]{38}',
            r'[a-f0-9]{40}.*commit',
            r'tree\s+[a-f0-9]{40}',
            r'parent\s+[a-f0-9]{40}'
        ]
        
        found_patterns = sum(1 for pattern in git_patterns 
                           if re.search(pattern, response_text, re.IGNORECASE))
        
        return found_patterns >= 2
    
    @staticmethod
    def _get_git_file_severity(file_type: str) -> str:
        """Get severity level for different git file types"""
        high_severity_files = ['config', 'index', 'log']
        medium_severity_files = ['HEAD', 'reference', 'object']
        
        if file_type in high_severity_files:
            return "High"
        elif file_type in medium_severity_files:
            return "Medium"
        else:
            return "Low"
    
    @staticmethod
    def get_git_test_paths() -> List[str]:
        """Get list of common git paths to test"""
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
            '.git/refs/heads/develop',
            '.git/objects/',
            '.git/info/refs',
            '.git/description',
            '.git/hooks/',
            '.git/packed-refs'
        ]
    
    @staticmethod
    def get_evidence(file_type: str, response_text: str) -> str:
        """Get detailed evidence for git exposure"""
        evidence_parts = []
        
        if 'config' in file_type.lower():
            evidence_parts.append("Git configuration file exposed")
            if '[core]' in response_text:
                evidence_parts.append("contains core git settings")
            if 'repositoryformatversion' in response_text:
                evidence_parts.append("contains repository metadata")
            if '[remote' in response_text:
                evidence_parts.append("contains remote repository URLs")
        elif 'head' in file_type.lower():
            evidence_parts.append("Git HEAD file exposed")
            if 'ref:' in response_text:
                branch = response_text.split('ref: refs/heads/')[-1].strip() if 'ref: refs/heads/' in response_text else 'unknown'
                evidence_parts.append(f"reveals current branch: {branch}")
        elif 'index' in file_type.lower():
            evidence_parts.append("Git index file exposed")
            evidence_parts.append(f"contains staging area data ({len(response_text)} bytes)")
        elif 'log' in file_type.lower():
            evidence_parts.append("Git log file exposed")
            commits = len([line for line in response_text.split('\n') if len(line.strip()) == 40])
            if commits > 0:
                evidence_parts.append(f"reveals {commits} commit hashes")
        elif 'ref' in file_type.lower():
            evidence_parts.append("Git reference file exposed")
            if len(response_text.strip()) == 40:
                evidence_parts.append("contains commit hash")
        elif 'object' in file_type.lower():
            evidence_parts.append("Git object file exposed")
        else:
            evidence_parts.append("Git repository file exposed")
        
        return "; ".join(evidence_parts)
    
    @staticmethod
    def get_response_snippet(response_text: str, max_length: int = 300) -> str:
        """Get response snippet for git exposure"""
        if len(response_text) > max_length:
            return response_text[:max_length] + "..."
        return response_text
    
    @staticmethod
    def get_remediation_advice(git_path: str) -> str:
        """Get remediation advice for git exposure"""
        base_advice = (
            "CRITICAL: Git repository is exposed! "
            "This can leak source code, credentials, and sensitive information. "
            "Immediate actions required:\n"
            "1. Remove .git directory from web-accessible locations\n"
            "2. Configure web server to deny access to .git directories\n"
            "3. For Apache: add 'RedirectMatch 404 /\\.git' to .htaccess\n"
            "4. For Nginx: add 'location ~ /\\.git { deny all; }' to server config\n"
            "5. Use proper deployment practices (deploy only necessary files)"
        )
        
        if 'config' in git_path:
            return base_advice + "\n6. URGENT: Git config may contain repository URLs and credentials"
        elif 'index' in git_path:
            return base_advice + "\n6. URGENT: Git index reveals complete file structure and metadata"
        
        return base_advice
