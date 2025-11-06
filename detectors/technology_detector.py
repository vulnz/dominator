"""
Technology detection using Wappalyzer-like patterns
"""

import re
import json
from typing import Dict, List, Any, Tuple

class TechnologyDetector:
    """Technology detection logic"""
    
    @staticmethod
    def get_technology_patterns() -> Dict[str, Dict[str, Any]]:
        """Get technology detection patterns"""
        return {
            "Apache": {
                "headers": {"Server": r"Apache(?:/([0-9.]+))?"},
                "category": "Web Server",
                "confidence": 100
            },
            "Nginx": {
                "headers": {"Server": r"nginx(?:/([0-9.]+))?"},
                "category": "Web Server", 
                "confidence": 100
            },
            "IIS": {
                "headers": {"Server": r"Microsoft-IIS(?:/([0-9.]+))?"},
                "category": "Web Server",
                "confidence": 100
            },
            "PHP": {
                "headers": {"X-Powered-By": r"PHP(?:/([0-9.]+))?"},
                "html": [r"<\?php", r"\.php(?:\?|$)"],
                "category": "Programming Language",
                "confidence": 90
            },
            "ASP.NET": {
                "headers": {"X-Powered-By": r"ASP\.NET"},
                "html": [r"__VIEWSTATE", r"\.aspx(?:\?|$)"],
                "category": "Web Framework",
                "confidence": 95
            },
            "WordPress": {
                "html": [r"/wp-content/", r"/wp-includes/", r"wp-json"],
                "headers": {"X-Pingback": r"xmlrpc\.php"},
                "category": "CMS",
                "confidence": 100
            },
            "Joomla": {
                "html": [r"/components/com_", r"Joomla!", r"/media/jui/"],
                "category": "CMS",
                "confidence": 95
            },
            "Drupal": {
                "html": [r"Drupal\.settings", r"/sites/default/files/", r"/misc/drupal\.js"],
                "category": "CMS",
                "confidence": 95
            },
            "jQuery": {
                "html": [r"jquery(?:-([0-9.]+))?(?:\.min)?\.js"],
                "category": "JavaScript Library",
                "confidence": 90
            },
            "Bootstrap": {
                "html": [r"bootstrap(?:-([0-9.]+))?(?:\.min)?\.css", r"bootstrap(?:-([0-9.]+))?(?:\.min)?\.js"],
                "category": "UI Framework",
                "confidence": 90
            },
            "MySQL": {
                "html": [r"mysql_connect", r"mysql_query"],
                "category": "Database",
                "confidence": 70
            },
            "PostgreSQL": {
                "html": [r"pg_connect", r"postgresql"],
                "category": "Database", 
                "confidence": 70
            },
            "Redis": {
                "headers": {"Server": r"Redis"},
                "category": "Cache",
                "confidence": 100
            },
            "Cloudflare": {
                "headers": {"CF-Ray": r".*", "Server": r"cloudflare"},
                "category": "CDN",
                "confidence": 100
            },
            "Google Analytics": {
                "html": [r"google-analytics\.com/analytics\.js", r"gtag\(", r"ga\("],
                "category": "Analytics",
                "confidence": 100
            }
        }
    
    @staticmethod
    def detect_technologies(response_text: str, response_headers: Dict[str, str], url: str) -> List[Dict[str, Any]]:
        """
        Detect technologies from response
        Returns list of detected technologies
        """
        detected = []
        patterns = TechnologyDetector.get_technology_patterns()
        
        for tech_name, tech_info in patterns.items():
            confidence = 0
            version = None
            evidence = []
            
            # Check headers
            if "headers" in tech_info:
                for header_name, pattern in tech_info["headers"].items():
                    header_value = response_headers.get(header_name, "")
                    if header_value:
                        match = re.search(pattern, header_value, re.IGNORECASE)
                        if match:
                            confidence = tech_info.get("confidence", 50)
                            if match.groups():
                                version = match.group(1)
                            evidence.append(f"Header {header_name}: {header_value}")
            
            # Check HTML content
            if "html" in tech_info and response_text:
                html_matches = 0
                for pattern in tech_info["html"]:
                    matches = re.findall(pattern, response_text, re.IGNORECASE)
                    if matches:
                        html_matches += 1
                        # Try to extract version from first match
                        if not version and matches and isinstance(matches[0], tuple):
                            version = matches[0][0] if matches[0][0] else None
                        elif not version and matches and isinstance(matches[0], str):
                            version_match = re.search(r'([0-9]+\.[0-9]+(?:\.[0-9]+)?)', matches[0])
                            if version_match:
                                version = version_match.group(1)
                        evidence.append(f"HTML pattern: {pattern}")
                
                if html_matches > 0:
                    # Increase confidence based on number of matches
                    confidence = max(confidence, min(tech_info.get("confidence", 50) * html_matches / len(tech_info["html"]), 100))
            
            # Check URL patterns
            if "url" in tech_info:
                for pattern in tech_info["url"]:
                    if re.search(pattern, url, re.IGNORECASE):
                        confidence = max(confidence, tech_info.get("confidence", 50))
                        evidence.append(f"URL pattern: {pattern}")
            
            if confidence > 0:
                detected.append({
                    "name": tech_name,
                    "version": version,
                    "category": tech_info.get("category", "Unknown"),
                    "confidence": int(confidence),
                    "evidence": evidence
                })
        
        # Sort by confidence
        detected.sort(key=lambda x: x["confidence"], reverse=True)
        return detected
    
    @staticmethod
    def get_technology_summary(technologies: List[Dict[str, Any]]) -> str:
        """Get summary of detected technologies"""
        if not technologies:
            return "No technologies detected"
        
        categories = {}
        for tech in technologies:
            category = tech["category"]
            if category not in categories:
                categories[category] = []
            
            tech_str = tech["name"]
            if tech["version"]:
                tech_str += f" {tech['version']}"
            categories[category].append(tech_str)
        
        summary_parts = []
        for category, techs in categories.items():
            summary_parts.append(f"{category}: {', '.join(techs)}")
        
        return "; ".join(summary_parts)
