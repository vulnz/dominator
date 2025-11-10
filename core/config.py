"""
Scanner configuration
"""

import os
from typing import List, Dict, Optional

class Config:
    """Scanner configuration class"""
    
    def __init__(self, args):
        """Initialize configuration from arguments"""
        self.target = args.target
        self.target_file = args.file
        self.headers = self._parse_headers(args.headers, args.headers_file)
        self.cookies = args.cookies
        self.auth_type = args.auth
        self.modules = self._parse_modules(args.modules, args.all, getattr(args, 'filetree', False))
        self.exclude_paths = self._parse_exclude(args.exclude)
        self.timeout = args.timeout
        self.threads = args.threads
        self.request_limit = args.limit
        self.page_limit = args.page_limit
        self.output_file = args.output
        self.output_format = args.format
        self.single_url = getattr(args, 'single_url', False) or getattr(args, 'nocrawl', False)
        self.filetree = getattr(args, 'filetree', False)
        
        # Crawler settings
        self.crawler_depth = getattr(args, 'crawler_depth', 3)
        self.enable_js_crawling = getattr(args, 'enable_js_crawling', True)
        self.max_crawl_pages = getattr(args, 'max_crawl_pages', 100)
        
        # Directory paths
        self.modules_dir = "modules"
        self.payloads_dir = "payloads"
        self.detectors_dir = "detectors"
        self.templates_dir = "report/templates"
        
    def _parse_headers(self, headers: Optional[List[str]], headers_file: Optional[str]) -> Dict[str, str]:
        """Parse HTTP headers"""
        result = {}
        
        # From command line arguments
        if headers:
            for header in headers:
                if ':' in header:
                    key, value = header.split(':', 1)
                    result[key.strip()] = value.strip()
        
        # From file
        if headers_file and os.path.exists(headers_file):
            with open(headers_file, 'r', encoding='utf-8') as f:
                for line in f:
                    line = line.strip()
                    if line and ':' in line:
                        key, value = line.split(':', 1)
                        result[key.strip()] = value.strip()
        
        return result
    
    def _parse_modules(self, modules_str: Optional[str], use_all: bool, filetree_mode: bool = False) -> List[str]:
        """Parse scanning modules"""
        all_modules = [
            'xss', 'sqli', 'lfi', 'rfi', 'xxe', 'csrf', 'idor', 'ssrf',
            'dirbrute', 'git', 'dirtraversal', 'secheaders',
            'versiondisclosure', 'clickjacking', 'blindxss', 'passwordoverhttp',
            'outdatedsoftware', 'databaseerrors', 'phpinfo', 'ssltls',
            'httponlycookies', 'technology', 'commandinjection', 'pathtraversal',
            'ldapinjection', 'nosqlinjection', 'fileupload', 'cors', 'jwt',
            'deserialization', 'responsesplitting', 'ssti', 'crlf',
            'textinjection', 'htmlinjection'
        ]
        
        # If filetree mode is enabled, only use file/directory discovery modules
        if filetree_mode:
            filetree_modules = ['dirbrute', 'git', 'phpinfo']
            if modules_str:
                # Allow user to specify additional modules with filetree
                user_modules = [m.strip() for m in modules_str.split(',')]
                normalized_modules = [self._normalize_module_name(m) for m in user_modules]
                # Combine filetree modules with user modules
                return list(set(filetree_modules + normalized_modules))
            else:
                return filetree_modules
        
        if modules_str:
            # Handle special case where user specifies "all" as module name
            if modules_str.strip().lower() == 'all':
                return all_modules
            modules = [m.strip() for m in modules_str.split(',')]
            # Normalize module names
            return [self._normalize_module_name(m) for m in modules]
        elif use_all:
            return all_modules
        else:
            # If no modules specified and --all not used, use all modules by default
            return all_modules
    
    def _parse_exclude(self, exclude_str: Optional[str]) -> List[str]:
        """Parse excluded paths"""
        if exclude_str:
            return [path.strip() for path in exclude_str.split(',')]
        return []
    
    def get_targets(self) -> List[str]:
        """Get list of targets for scanning"""
        targets = []
        
        # From -t parameter
        if self.target:
            if isinstance(self.target, list):
                # Multiple targets passed as list
                targets.extend(self.target)
            else:
                # Single target passed as string
                targets.append(self.target)
        
        # From file
        if self.target_file and os.path.exists(self.target_file):
            with open(self.target_file, 'r', encoding='utf-8') as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#'):
                        targets.append(line)
        
        return targets
    
    def _normalize_module_name(self, module_name: str) -> str:
        """Normalize module names for consistency"""
        module_mapping = {
            'gitexposed': 'git',
            'git-exposed': 'git',
            'securityheaders': 'secheaders',
            'security-headers': 'secheaders',
            'httponlycookie': 'httponlycookies',
            'httponly-cookies': 'httponlycookies'
        }
        return module_mapping.get(module_name.lower(), module_name.lower())
