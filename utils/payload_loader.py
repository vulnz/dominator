"""
Payload loader utility for loading payloads from text files
"""

import os
from typing import List, Dict, Any
import json

class PayloadLoader:
    """Utility class for loading payloads from text files"""
    
    _cache = {}
    _base_path = None
    
    @classmethod
    def set_base_path(cls, base_path: str):
        """Set base path for payload files"""
        cls._base_path = base_path
    
    @classmethod
    def load_payloads(cls, payload_type: str) -> List[str]:
        """Load payloads from text file with caching"""
        if payload_type in cls._cache:
            return cls._cache[payload_type]
        
        if cls._base_path is None:
            # Default to data/payloads directory
            current_dir = os.path.dirname(os.path.abspath(__file__))
            cls._base_path = os.path.join(os.path.dirname(current_dir), 'data', 'payloads')
        
        payload_file = os.path.join(cls._base_path, f"{payload_type}_payloads.txt")
        
        if not os.path.exists(payload_file):
            print(f"Warning: Payload file not found: {payload_file}")
            return []
        
        try:
            with open(payload_file, 'r', encoding='utf-8') as f:
                lines = f.readlines()
            
            payloads = []
            for line in lines:
                line = line.strip()
                # Skip empty lines and comments
                if line and not line.startswith('#'):
                    payloads.append(line)
            
            cls._cache[payload_type] = payloads
            return payloads
            
        except Exception as e:
            print(f"Error loading payloads from {payload_file}: {e}")
            return []
    
    @classmethod
    def load_cwe_mapping(cls) -> Dict[str, Any]:
        """Load CWE/OWASP mapping from JSON file"""
        if 'cwe_mapping' in cls._cache:
            return cls._cache['cwe_mapping']
        
        if cls._base_path is None:
            current_dir = os.path.dirname(os.path.abspath(__file__))
            base_dir = os.path.dirname(current_dir)
        else:
            base_dir = os.path.dirname(cls._base_path)
        
        mapping_file = os.path.join(base_dir, 'data', 'cwe_owasp_mapping.json')
        
        if not os.path.exists(mapping_file):
            print(f"Warning: CWE mapping file not found: {mapping_file}")
            return {}
        
        try:
            with open(mapping_file, 'r', encoding='utf-8') as f:
                mapping = json.load(f)
            
            cls._cache['cwe_mapping'] = mapping
            return mapping
            
        except Exception as e:
            print(f"Error loading CWE mapping from {mapping_file}: {e}")
            return {}
    
    @classmethod
    def get_vulnerability_metadata(cls, module_name: str, severity: str = 'Medium') -> Dict[str, Any]:
        """Get vulnerability metadata from CWE mapping"""
        mapping = cls.load_cwe_mapping()
        
        if 'vulnerabilities' not in mapping:
            return cls._get_default_metadata(module_name, severity)
        
        vuln_data = mapping['vulnerabilities'].get(module_name)
        if not vuln_data:
            return cls._get_default_metadata(module_name, severity)
        
        # Get CVSS score based on severity
        cvss_score = vuln_data.get('severity_mapping', {}).get(severity, vuln_data.get('cvss_base', '6.5'))
        
        return {
            'cwe': vuln_data.get('cwe', 'CWE-200'),
            'owasp': vuln_data.get('owasp', 'A06:2021 – Vulnerable and Outdated Components'),
            'cvss': cvss_score,
            'recommendation': vuln_data.get('recommendation', 'Review and implement appropriate security controls.'),
            'description': vuln_data.get('description', 'Security vulnerability detected.')
        }
    
    @classmethod
    def _get_default_metadata(cls, module_name: str, severity: str) -> Dict[str, Any]:
        """Get default metadata for unknown modules"""
        cvss_defaults = {
            'Critical': '9.8',
            'High': '8.8',
            'Medium': '6.5',
            'Low': '3.1',
            'Info': '0.0'
        }
        
        return {
            'cwe': 'CWE-200',
            'owasp': 'A06:2021 – Vulnerable and Outdated Components',
            'cvss': cvss_defaults.get(severity, '6.5'),
            'recommendation': 'Review and implement appropriate security controls.',
            'description': 'Security vulnerability detected.'
        }
    
    @classmethod
    def load_wordlist(cls, wordlist_name: str) -> List[str]:
        """Load wordlist from text file with caching"""
        cache_key = f"wordlist_{wordlist_name}"
        
        if cache_key in cls._cache:
            return cls._cache[cache_key]
        
        if cls._base_path is None:
            current_dir = os.path.dirname(os.path.abspath(__file__))
            base_dir = os.path.dirname(current_dir)
        else:
            base_dir = os.path.dirname(cls._base_path)
        
        wordlist_file = os.path.join(base_dir, 'wordlists', f"{wordlist_name}.txt")
        
        if not os.path.exists(wordlist_file):
            print(f"Warning: Wordlist file not found: {wordlist_file}")
            return []
        
        try:
            with open(wordlist_file, 'r', encoding='utf-8') as f:
                lines = f.readlines()
            
            wordlist = []
            for line in lines:
                line = line.strip()
                # Skip empty lines and comments
                if line and not line.startswith('#'):
                    wordlist.append(line)
            
            cls._cache[cache_key] = wordlist
            return wordlist
            
        except Exception as e:
            print(f"Error loading wordlist from {wordlist_file}: {e}")
            return []
    
    @classmethod
    def clear_cache(cls):
        """Clear payload cache"""
        cls._cache.clear()
