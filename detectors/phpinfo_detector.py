"""
PHPInfo exposure detection logic
"""

import re
from typing import Tuple, List, Dict, Any

class PHPInfoDetector:
    """PHPInfo exposure detection logic"""
    
    @staticmethod
    def get_phpinfo_indicators() -> List[str]:
        """Get PHPInfo page indicators"""
        return [
            'phpinfo()',
            'PHP Version',
            'System',
            'Build Date',
            'Configure Command',
            'Server API',
            'Virtual Directory Support',
            'Configuration File (php.ini) Path',
            'Loaded Configuration File',
            'Scan this dir for additional .ini files',
            'Additional .ini files parsed',
            'PHP API',
            'PHP Extension',
            'Zend Extension',
            'PHP Credits',
            'PHP License',
            'This program makes use of the Zend Scripting Language Engine'
        ]
    
    @staticmethod
    def get_phpinfo_title_patterns() -> List[str]:
        """Get PHPInfo title patterns"""
        return [
            r'<title[^>]*>.*?phpinfo.*?</title>',
            r'<h1[^>]*>.*?phpinfo.*?</h1>',
            r'<h2[^>]*>.*?PHP Version.*?</h2>'
        ]
    
    @staticmethod
    def detect_phpinfo_exposure(response_text: str, response_code: int, url: str) -> Tuple[bool, str, str]:
        """
        Detect PHPInfo exposure
        Returns: (is_exposed, evidence, severity)
        """
        if response_code != 200:
            return False, "Non-200 response code", "None"
        
        response_lower = response_text.lower()
        
        # Check for multiple PHPInfo indicators
        indicators = PHPInfoDetector.get_phpinfo_indicators()
        found_indicators = []
        
        for indicator in indicators:
            if indicator.lower() in response_lower:
                found_indicators.append(indicator)
        
        # Need at least 3 indicators to confirm PHPInfo
        if len(found_indicators) >= 3:
            # Check for title patterns
            title_patterns = PHPInfoDetector.get_phpinfo_title_patterns()
            has_title_match = False
            
            for pattern in title_patterns:
                if re.search(pattern, response_text, re.IGNORECASE):
                    has_title_match = True
                    break
            
            # Check for PHPInfo table structure
            has_table_structure = (
                '<table' in response_lower and 
                'php version' in response_lower and
                ('system' in response_lower or 'build date' in response_lower)
            )
            
            if has_title_match or has_table_structure:
                severity = "High"
                evidence = f"PHPInfo page detected with {len(found_indicators)} indicators: {', '.join(found_indicators[:5])}"
                return True, evidence, severity
        
        # Check for partial PHPInfo exposure
        if len(found_indicators) >= 2:
            severity = "Medium"
            evidence = f"Possible PHPInfo exposure with {len(found_indicators)} indicators: {', '.join(found_indicators)}"
            return True, evidence, severity
        
        return False, "No PHPInfo indicators found", "None"
    
    @staticmethod
    def get_evidence(indicators: List[str], response_text: str) -> str:
        """Get detailed evidence of PHPInfo exposure"""
        evidence_parts = []
        
        if indicators:
            evidence_parts.append(f"Found {len(indicators)} PHPInfo indicators: {', '.join(indicators[:5])}")
        
        # Look for version information
        version_match = re.search(r'PHP Version\s+(\d+\.\d+\.\d+[^\s<]*)', response_text, re.IGNORECASE)
        if version_match:
            evidence_parts.append(f"PHP Version: {version_match.group(1)}")
        
        # Look for system information
        system_match = re.search(r'System\s+([^\n<]+)', response_text, re.IGNORECASE)
        if system_match:
            evidence_parts.append(f"System: {system_match.group(1).strip()}")
        
        return ". ".join(evidence_parts)
    
    @staticmethod
    def get_response_snippet(response_text: str) -> str:
        """Get relevant response snippet"""
        # Look for PHPInfo table or key information
        patterns = [
            r'<h1[^>]*>.*?phpinfo.*?</h1>',
            r'PHP Version\s+[^\n<]+',
            r'System\s+[^\n<]+',
            r'<title[^>]*>.*?phpinfo.*?</title>'
        ]
        
        for pattern in patterns:
            match = re.search(pattern, response_text, re.IGNORECASE | re.DOTALL)
            if match:
                return match.group(0)[:200]
        
        return response_text[:200]
    
    @staticmethod
    def get_evidence(indicators: list, response_text: str) -> str:
        """Get detailed evidence for phpinfo exposure"""
        found_indicators = []
        response_lower = response_text.lower()
        
        for indicator in indicators:
            if indicator.lower() in response_lower:
                found_indicators.append(indicator)
        
        evidence = f"PHPInfo page detected with {len(found_indicators)} indicators"
        if found_indicators:
            evidence += f": {', '.join(found_indicators[:5])}"
        
        return evidence
    
    @staticmethod
    def get_response_snippet(response_text: str) -> str:
        """Get response snippet for phpinfo exposure"""
        # Look for phpinfo table content
        import re
        table_match = re.search(r'<table[^>]*>.*?</table>', response_text, re.IGNORECASE | re.DOTALL)
        if table_match:
            table_content = table_match.group(0)
            if len(table_content) > 500:
                return table_content[:500] + "..."
            return table_content
        
        # Fallback to general snippet
        if len(response_text) > 300:
            return response_text[:300] + "..."
        return response_text
    
    @staticmethod
    def get_remediation_advice() -> str:
        """Get remediation advice for PHPInfo exposure"""
        return (
            "Remove or restrict access to PHPInfo pages. "
            "PHPInfo pages reveal sensitive server configuration information "
            "that can be used by attackers to identify vulnerabilities. "
            "If PHPInfo is needed for debugging, restrict access to authorized users only."
        )
