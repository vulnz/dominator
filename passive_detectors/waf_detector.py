import requests
from typing import List, Dict, Any, Tuple

class WAFDetector:
    """Detect presence of a Web Application Firewall (WAF) using passive and active methods"""

    WAF_SIGNATURES = {
        'Cloudflare': {'signatures': ['cloudflare', 'cf-ray'], 'icon': 'fab fa-cloudflare'},
        'Incapsula': {'signatures': ['incapsula', 'visid_incap'], 'icon': 'fas fa-shield-alt'},
        'Akamai': {'signatures': ['akamai', 'x-akamai'], 'icon': 'fas fa-shield-alt'},
        'AWS WAF': {'signatures': ['awselb', 'x-amz-cf-id', 'x-amz-waf-'], 'icon': 'fab fa-aws'},
        'Sucuri': {'signatures': ['sucuri', 'x-sucuri-id'], 'icon': 'fas fa-shield-alt'},
        'Wordfence': {'signatures': ['wordfence', 'wf-loginalerted'], 'icon': 'fab fa-wordpress'},
        'ModSecurity': {'signatures': ['mod_security', 'modsecurity', 'owasp_crs'], 'icon': 'fas fa-shield-alt'},
        'FortiWeb': {'signatures': ['fortiweb', 'fortigate'], 'icon': 'fas fa-shield-alt'},
        'Imperva': {'signatures': ['imperva', 'incap_ses'], 'icon': 'fas fa-shield-alt'},
        'F5 BIG-IP': {'signatures': ['big-ip', 'f5'], 'icon': 'fas fa-shield-alt'},
        'Barracuda': {'signatures': ['barracuda', 'x-barracuda-'], 'icon': 'fas fa-shield-alt'},
        'Citrix NetScaler': {'signatures': ['netscaler', 'citrix_ns_id'], 'icon': 'fas fa-shield-alt'},
        'Microsoft Azure': {'signatures': ['azure', 'x-azure-'], 'icon': 'fab fa-microsoft'},
        'Google Cloud Armor': {'signatures': ['google', 'gcp', 'cloud-armor'], 'icon': 'fab fa-google'},
    }

    @classmethod
    def analyze(cls, headers: Dict[str, str], response_text: str, url: str) -> Tuple[bool, List[Dict[str, Any]]]:
        """
        Analyze response headers and content for WAF signatures.
        Returns (has_findings, findings_list)
        """
        findings = []
        detected_wafs = set()

        # 1. Check response headers
        for waf_name, data in cls.WAF_SIGNATURES.items():
            for signature in data['signatures']:
                for key, value in headers.items():
                    if signature in key.lower() or signature in value.lower():
                        if waf_name not in detected_wafs:
                            findings.append(cls._create_waf_finding(waf_name, url, f'Header signature found: {key}: {value}'))
                            detected_wafs.add(waf_name)

        # 2. Check response body
        response_lower = response_text.lower()
        for waf_name, data in cls.WAF_SIGNATURES.items():
            for signature in data['signatures']:
                if signature in response_lower:
                    if waf_name not in detected_wafs:
                        findings.append(cls._create_waf_finding(waf_name, url, f'Body signature found: "{signature}"'))
                        detected_wafs.add(waf_name)

        return len(findings) > 0, findings

    @classmethod
    def _create_waf_finding(cls, waf_name: str, url: str, reason: str, is_active: bool = False) -> Dict[str, Any]:
        """Create a standardized WAF finding dictionary."""
        icon = cls.WAF_SIGNATURES.get(waf_name, {}).get('icon', 'shield')
        module_name = 'wafdetect'
        detector = 'WAFDetector.analyze' if not is_active else 'WAFDetector.active_detect'

        return {
            'module': module_name,
            'target': url,
            'vulnerability': f'WAF Detected: {waf_name}',
            'severity': 'Info',
            'parameter': 'N/A',
            'payload': 'N/A' if not is_active else "<script>alert('WAF-TEST')</script>",
            'evidence': reason,
            'request_url': url,
            'detector': detector,
            'response_snippet': reason,
            'method': 'GET',
            'passive_analysis': not is_active,
            'waf_name': waf_name,
            'icon': icon
        }

    @classmethod
    def active_detect(cls, url: str, headers: Dict[str, str], timeout: int) -> Tuple[bool, List[Dict[str, Any]]]:
        """
        Actively detect WAF by sending a malicious-looking payload.
        Returns (has_findings, findings_list)
        """
        findings = []
        try:
            # Send a simple attack payload
            attack_payload = "<script>alert('dominator_waf_test')</script>"
            attack_url = f"{url}?waf_test={attack_payload}"
            
            print(f"    [WAF-DETECT] Sending active probe to: {attack_url}")
            
            attack_response = requests.get(
                attack_url, 
                timeout=timeout, 
                headers=headers, 
                verify=False
            )

            # Check for blocking status codes
            if attack_response.status_code in [403, 406, 429, 501, 999]:
                reason = f'Blocked with status code {attack_response.status_code}'
                findings.append(cls._create_waf_finding("Generic WAF", url, reason, is_active=True))
                return True, findings

            # Check response body for blocking signatures
            response_lower = attack_response.text.lower()
            blocking_keywords = ['blocked', 'forbidden', 'access denied', 'unauthorized', 'waf', 'security incident']
            for keyword in blocking_keywords:
                if keyword in response_lower:
                    reason = f'Response body contains blocking keyword: "{keyword}"'
                    findings.append(cls._create_waf_finding("Generic WAF", url, reason, is_active=True))
                    return True, findings

            # Check for signatures in the response body of the attack request
            for waf_name, data in cls.WAF_SIGNATURES.items():
                for signature in data['signatures']:
                    if signature in response_lower:
                        reason = f'Active probe response body contains signature: "{signature}"'
                        findings.append(cls._create_waf_finding(waf_name, url, reason, is_active=True))
                        return True, findings

        except requests.exceptions.RequestException as e:
            print(f"    [WAF-DETECT] Error during active WAF detection: {e}")

        return False, findings
