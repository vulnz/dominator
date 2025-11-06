"""
Path management library - handles dynamic path generation
"""

import re
from typing import List, Dict, Any, Optional
from urllib.parse import urlparse, urljoin

class PathManager:
    """Manage and generate paths dynamically"""
    
    def __init__(self):
        self.tested_paths = set()
        self.base_paths = {}
    
    def normalize_url(self, url: str) -> str:
        """Normalize URL for consistent processing"""
        if not url:
            return ""
        
        # Remove fragment
        if '#' in url:
            url = url.split('#')[0]
        
        # Ensure proper scheme
        if not url.startswith(('http://', 'https://')):
            if url.startswith('//'):
                url = 'http:' + url
            elif url.startswith('/'):
                return url  # Relative path
            else:
                url = 'http://' + url
        
        return url.rstrip('/')
    
    def get_base_url(self, url: str) -> str:
        """Extract base URL from full URL"""
        parsed = urlparse(self.normalize_url(url))
        return f"{parsed.scheme}://{parsed.netloc}"
    
    def get_base_path(self, url: str) -> str:
        """Extract base path from URL"""
        parsed = urlparse(self.normalize_url(url))
        path = parsed.path
        
        # If path ends with a file, get directory
        if '.' in path.split('/')[-1]:
            path = '/'.join(path.split('/')[:-1])
        
        return path.rstrip('/') + '/'
    
    def build_test_url(self, base_url: str, path: str) -> str:
        """Build test URL from base URL and path"""
        base_url = self.normalize_url(base_url)
        
        if path.startswith('http'):
            return path
        
        if path.startswith('/'):
            return self.get_base_url(base_url) + path
        
        return urljoin(base_url + '/', path)
    
    def generate_directory_paths(self, base_url: str, directories: List[str]) -> List[str]:
        """Generate directory test paths"""
        paths = []
        base_path = self.get_base_path(base_url)
        
        for directory in directories:
            # Test in base path
            test_path = f"{base_path}{directory}/"
            paths.append(test_path)
            
            # Test in root
            if base_path != '/':
                root_path = f"/{directory}/"
                paths.append(root_path)
        
        return list(set(paths))  # Remove duplicates
    
    def generate_file_paths(self, base_url: str, files: List[str]) -> List[str]:
        """Generate file test paths"""
        paths = []
        base_path = self.get_base_path(base_url)
        
        for file in files:
            # Test in base path
            test_path = f"{base_path}{file}"
            paths.append(test_path)
            
            # Test in root
            if base_path != '/':
                root_path = f"/{file}"
                paths.append(root_path)
        
        return list(set(paths))  # Remove duplicates
    
    def generate_backup_paths(self, original_url: str) -> List[str]:
        """Generate backup file paths based on original URL"""
        paths = []
        parsed = urlparse(self.normalize_url(original_url))
        
        if not parsed.path or parsed.path == '/':
            return paths
        
        # Get original filename
        path_parts = parsed.path.strip('/').split('/')
        if not path_parts or not path_parts[-1]:
            return paths
        
        filename = path_parts[-1]
        directory = '/'.join(path_parts[:-1])
        
        # Generate backup variations
        backup_extensions = ['.bak', '.backup', '.old', '.orig', '.copy', '.tmp']
        backup_prefixes = ['backup_', 'old_', 'copy_', 'orig_']
        
        for ext in backup_extensions:
            backup_path = f"/{directory}/{filename}{ext}" if directory else f"/{filename}{ext}"
            paths.append(backup_path)
        
        for prefix in backup_prefixes:
            backup_path = f"/{directory}/{prefix}{filename}" if directory else f"/{prefix}{filename}"
            paths.append(backup_path)
        
        return paths
    
    def is_path_tested(self, path: str) -> bool:
        """Check if path was already tested"""
        normalized_path = self.normalize_path(path)
        return normalized_path in self.tested_paths
    
    def mark_path_tested(self, path: str):
        """Mark path as tested"""
        normalized_path = self.normalize_path(path)
        self.tested_paths.add(normalized_path)
    
    def normalize_path(self, path: str) -> str:
        """Normalize path for deduplication"""
        if not path:
            return ""
        
        # Remove query parameters and fragments
        if '?' in path:
            path = path.split('?')[0]
        if '#' in path:
            path = path.split('#')[0]
        
        # Normalize slashes
        path = re.sub(r'/+', '/', path)
        
        return path.lower().strip('/')
    
    def extract_paths_from_response(self, response_text: str, base_url: str) -> List[str]:
        """Extract potential paths from response content"""
        paths = []
        
        # Extract href attributes
        href_pattern = r'href\s*=\s*["\']([^"\']+)["\']'
        href_matches = re.findall(href_pattern, response_text, re.IGNORECASE)
        
        for href in href_matches:
            if href.startswith(('http', '//', 'mailto:', 'tel:', 'javascript:')):
                continue
            
            if href.startswith('/'):
                paths.append(href)
            elif not href.startswith('#'):
                # Relative path
                full_path = urljoin(base_url, href)
                parsed = urlparse(full_path)
                paths.append(parsed.path)
        
        # Extract src attributes
        src_pattern = r'src\s*=\s*["\']([^"\']+)["\']'
        src_matches = re.findall(src_pattern, response_text, re.IGNORECASE)
        
        for src in src_matches:
            if src.startswith(('http', '//', 'data:')):
                continue
            
            if src.startswith('/'):
                paths.append(src)
            elif not src.startswith('#'):
                full_path = urljoin(base_url, src)
                parsed = urlparse(full_path)
                paths.append(parsed.path)
        
        # Extract action attributes from forms
        action_pattern = r'action\s*=\s*["\']([^"\']+)["\']'
        action_matches = re.findall(action_pattern, response_text, re.IGNORECASE)
        
        for action in action_matches:
            if action.startswith(('http', '//')):
                continue
            
            if action.startswith('/'):
                paths.append(action)
            elif action and not action.startswith('#'):
                full_path = urljoin(base_url, action)
                parsed = urlparse(full_path)
                paths.append(parsed.path)
        
        # Clean and deduplicate paths
        clean_paths = []
        for path in paths:
            normalized = self.normalize_path(path)
            if normalized and normalized not in clean_paths:
                clean_paths.append('/' + normalized)
        
        return clean_paths
    
    def get_directory_from_path(self, path: str) -> str:
        """Get directory part from path"""
        if not path or path == '/':
            return '/'
        
        path = path.strip('/')
        if '.' in path.split('/')[-1]:  # Has file extension
            return '/' + '/'.join(path.split('/')[:-1]) + '/'
        else:
            return '/' + path + '/'
    
    def get_filename_from_path(self, path: str) -> Optional[str]:
        """Get filename from path"""
        if not path or path == '/':
            return None
        
        filename = path.split('/')[-1]
        if '.' in filename:
            return filename
        
        return None
    
    def generate_common_paths(self, base_url: str) -> Dict[str, List[str]]:
        """Generate common paths for testing"""
        return {
            'admin_paths': self._get_admin_paths(),
            'config_paths': self._get_config_paths(),
            'backup_paths': self._get_backup_paths(),
            'info_paths': self._get_info_paths()
        }
    
    def _get_admin_paths(self) -> List[str]:
        """Get admin-related paths"""
        return [
            '/admin/', '/administrator/', '/admin.php', '/login.php',
            '/admin/login.php', '/admin/index.php', '/dashboard/',
            '/control/', '/panel/', '/manage/', '/backend/'
        ]
    
    def _get_config_paths(self) -> List[str]:
        """Get configuration file paths"""
        return [
            '/config.php', '/config.ini', '/configuration.php',
            '/settings.php', '/.env', '/web.config', '/.htaccess'
        ]
    
    def _get_backup_paths(self) -> List[str]:
        """Get backup file paths"""
        return [
            '/backup/', '/backups/', '/backup.zip', '/backup.sql',
            '/dump.sql', '/database.sql', '/db.sql'
        ]
    
    def _get_info_paths(self) -> List[str]:
        """Get information disclosure paths"""
        return [
            '/info.php', '/phpinfo.php', '/test.php', '/debug.php',
            '/robots.txt', '/sitemap.xml', '/.git/', '/.svn/'
        ]
