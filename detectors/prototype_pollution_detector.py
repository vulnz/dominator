"""
Prototype Pollution vulnerability detector
"""

import requests
import json
from typing import Dict, List, Tuple, Any

class PrototypePollutionDetector:
    """Prototype Pollution vulnerability detection logic"""
    
    @staticmethod
    def get_prototype_payloads() -> List[Dict[str, Any]]:
        """Get prototype pollution payloads"""
        return [
            {
                'name': 'constructor.prototype.polluted',
                'payload': '{"constructor": {"prototype": {"polluted": "yes"}}}',
                'content_type': 'application/json'
            },
            {
                'name': '__proto__.polluted',
                'payload': '{"__proto__": {"polluted": "yes"}}',
                'content_type': 'application/json'
            },
            {
                'name': 'constructor[prototype][polluted]',
                'payload': 'constructor[prototype][polluted]=yes',
                'content_type': 'application/x-www-form-urlencoded'
            },
            {
                'name': '__proto__[polluted]',
                'payload': '__proto__[polluted]=yes',
                'content_type': 'application/x-www-form-urlencoded'
            }
        ]
    
    @staticmethod
    def detect_prototype_pollution(url: str, headers: Dict[str, str], timeout: int = 10) -> Tuple[bool, str, str, List[Dict[str, Any]]]:
        """Detect Prototype Pollution vulnerabilities"""
        vulnerabilities = []
        payloads = PrototypePollutionDetector.get_prototype_payloads()
        
        for payload_info in payloads:
            try:
                test_headers = headers.copy()
                test_headers['Content-Type'] = payload_info['content_type']
                
                if payload_info['content_type'] == 'application/json':
                    response = requests.post(url, data=payload_info['payload'], headers=test_headers, timeout=timeout, verify=False)
                else:
                    response = requests.post(url, data=payload_info['payload'], headers=test_headers, timeout=timeout, verify=False)
                
                # Check for prototype pollution indicators
                pollution_indicators = [
                    'polluted',
                    'prototype',
                    '__proto__',
                    'constructor'
                ]
                
                response_text = response.text.lower()
                if any(indicator in response_text for indicator in pollution_indicators):
                    # Additional checks for actual pollution
                    if 'polluted' in response_text and 'yes' in response_text:
                        vulnerabilities.append({
                            'type': 'prototype_pollution',
                            'payload': payload_info['name'],
                            'evidence': f"Prototype pollution detected with payload: {payload_info['name']}",
                            'severity': 'High'
                        })
                
            except Exception as e:
                continue
        
        if vulnerabilities:
            evidence = f"Found {len(vulnerabilities)} prototype pollution vulnerabilities"
            return True, evidence, "High", vulnerabilities
        
        return False, "No prototype pollution vulnerabilities found", "Info", []
    
    @staticmethod
    def get_evidence(vulnerabilities: List[Dict[str, Any]]) -> str:
        """Get detailed evidence of prototype pollution vulnerabilities"""
        evidence_parts = []
        for vuln in vulnerabilities:
            evidence_parts.append(f"• {vuln['evidence']}")
        return "\n".join(evidence_parts)
    
    @staticmethod
    def get_remediation_advice() -> str:
        """Get remediation advice for prototype pollution vulnerabilities"""
        return "Use Object.create(null) to create objects without prototype. Validate and sanitize all user inputs. Use Map instead of plain objects for user-controlled data."
