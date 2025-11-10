from typing import List, Dict, Any, Tuple

class WAFDetector:
    """Passively detect presence of a Web Application Firewall (WAF)"""

    WAF_SIGNATURES = {
        'Cloudflare': ['cloudflare', 'cf-ray'],
        'Incapsula': ['incapsula', 'visid_incap'],
        'Akamai': ['akamai', 'x-akamai'],
        'AWS WAF': ['awselb', 'x-amz-cf-id', 'x-amz-waf-'],
        'Sucuri': ['sucuri', 'x-sucuri-id'],
        'Wordfence': ['wordfence', 'wf-loginalerted'],
        'ModSecurity': ['mod_security', 'modsecurity', 'owasp_crs'],
        'FortiWeb': ['fortiweb', 'fortigate'],
        'Imperva': ['imperva', 'incap_ses'],
        'F5 BIG-IP': ['big-ip', 'f5'],
        'Barracuda': ['barracuda', 'x-barracuda-'],
        'Citrix NetScaler': ['netscaler', 'citrix_ns_id'],
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
        for waf_name, signatures in cls.WAF_SIGNATURES.items():
            for signature in signatures:
                for key, value in headers.items():
                    if signature in key.lower() or signature in value.lower():
                        if waf_name not in detected_wafs:
                            findings.append(cls._create_waf_finding(waf_name, url, f'Header signature found: {key}: {value}'))
                            detected_wafs.add(waf_name)

        # 2. Check response body
        response_lower = response_text.lower()
        for waf_name, signatures in cls.WAF_SIGNATURES.items():
            for signature in signatures:
                if signature in response_lower:
                    if waf_name not in detected_wafs:
                        findings.append(cls._create_waf_finding(waf_name, url, f'Body signature found: "{signature}"'))
                        detected_wafs.add(waf_name)

        return len(findings) > 0, findings

    @staticmethod
    def _create_waf_finding(waf_name: str, url: str, reason: str) -> Dict[str, Any]:
        """Create a standardized WAF finding dictionary."""
        return {
            'module': 'waf_detection',
            'target': url,
            'vulnerability': f'WAF Detected: {waf_name}',
            'severity': 'Info',
            'parameter': 'N/A',
            'payload': 'N/A',
            'evidence': reason,
            'request_url': url,
            'detector': 'WAFDetector.analyze',
            'response_snippet': reason,
            'method': 'GET',
            'passive_analysis': True,
            'waf_name': waf_name,
            'icon': 'shield'  # For report generation
        }
