"""
IDOR (Insecure Direct Object Reference) Scanner Module

Detects IDOR vulnerabilities by testing parameter tampering
Based on XVWA vulnerable code: Direct database access without authorization
"""

from typing import List, Dict, Any, Optional
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from core.base_module import BaseModule
from core.logger import get_logger
import re

logger = get_logger(__name__)


class IDORModule(BaseModule):
    """IDOR Scanner Module"""

    def __init__(self, module_path: str):
        """Initialize IDOR module"""
        super().__init__(module_path)

        logger.info(f"IDOR module loaded: {len(self.payloads)} payloads")

    def scan(self, targets: List[Dict[str, Any]], http_client: Any) -> List[Dict[str, Any]]:
        """
        Scan for IDOR vulnerabilities

        Args:
            targets: List of URLs with parameters
            http_client: HTTP client

        Returns:
            List of results
        """
        results = []

        logger.info(f"Starting IDOR scan on {len(targets)} targets")

        # IDOR is common in ID-like parameters
        id_params = ['id', 'item', 'user', 'uid', 'userid', 'user_id',
                     'itemid', 'item_id', 'object', 'obj', 'doc', 'file',
                     'account', 'profile', 'order', 'invoice', 'aid', 'pid',
                     'cid', 'gid', 'tid', 'sid', 'rid', 'vid', 'eid']

        for target in targets:
            url = target.get('url')
            params = target.get('params', {})
            method = target.get('method', 'GET').upper()

            # ENHANCEMENT: Extract ID parameters from URL query string
            url_id_params = self._extract_id_from_url(url)
            if url_id_params:
                # Merge URL parameters with existing params
                params.update(url_id_params)
                logger.debug(f"Extracted ID parameters from URL: {url_id_params}")

            if not params:
                continue

            # Test each parameter (prioritize ID-like params)
            for param_name in params:
                param_lower = param_name.lower()
                is_id_param = any(keyword in param_lower for keyword in id_params)

                # Skip action/operation parameters (not IDs)
                skip_params = ['action', 'operation', 'method', 'mode', 'type', 'submit', 'csrf']
                if any(skip in param_lower for skip in skip_params):
                    logger.debug(f"Skipping non-ID parameter: {param_name}")
                    continue

                # Only test parameters that look like IDs
                if not is_id_param and not param_lower.endswith('id'):
                    continue

                logger.debug(f"Testing IDOR in parameter: {param_name} via {method}")

                # Get baseline response with original value
                original_value = params[param_name]

                if method == 'POST':
                    baseline_response = http_client.post(url, data=params)
                else:
                    baseline_response = http_client.get(url, params=params)

                if not baseline_response:
                    continue

                baseline_text = getattr(baseline_response, 'text', '')
                baseline_status = baseline_response.status_code
                baseline_length = len(baseline_text)

                # Test different IDs
                different_responses = []

                for payload in self.payloads[:10]:  # Limit to 10 IDs
                    # Skip if payload is same as original
                    if str(payload).strip() == str(original_value).strip():
                        continue

                    test_params = params.copy()
                    test_params[param_name] = payload

                    # Send request
                    if method == 'POST':
                        response = http_client.post(url, data=test_params)
                    else:
                        response = http_client.get(url, params=test_params)

                    if not response:
                        continue

                    # PASSIVE ANALYSIS: Check for path disclosure, DB errors in response
                    self.analyze_payload_response(response, url, str(payload))

                    response_text = getattr(response, 'text', '')
                    response_status = response.status_code

                    # Check if response is different and successful
                    if response_status == 200:
                        # Different content = different object accessed
                        length_diff = abs(len(response_text) - baseline_length)

                        # Significant content difference (not just reflected param)
                        if length_diff > 100:
                            different_responses.append({
                                'payload': payload,
                                'status': response_status,
                                'length': len(response_text),
                                'text': response_text
                            })

                # Detect IDOR
                if different_responses:
                    detected, confidence, evidence = self._detect_idor(
                        param_name, original_value, different_responses,
                        baseline_text, baseline_length
                    )

                    if detected:
                        # Add visual proof showing actual data differences
                        visual_proof = self._create_visual_proof(
                            original_value,
                            different_responses[0]['payload'],
                            baseline_text,
                            different_responses[0]['text']
                        )

                        result = self.create_result(
                            vulnerable=True,
                            url=url,
                            parameter=param_name,
                            payload=different_responses[0]['payload'],
                            evidence=evidence + visual_proof,
                            description="Insecure Direct Object Reference (IDOR) vulnerability detected. "
                                      "Application allows unauthorized access to objects by manipulating ID parameters.",
                            confidence=confidence
                        )

                        results.append(result)
                        logger.info(f"✓ IDOR found in {url} (parameter: {param_name}, "
                                  f"confidence: {confidence:.2f})")

                        # Move to next parameter
                        break

        logger.info(f"IDOR scan complete: {len(results)} vulnerabilities found")
        return results

    def _detect_idor(self, param_name: str, original_value: Any,
                     different_responses: List[Dict], baseline_text: str,
                     baseline_length: int) -> tuple:
        """
        Detect IDOR vulnerability

        Returns:
            (detected: bool, confidence: float, evidence: str)
        """
        if not different_responses:
            return False, 0.0, ""

        # STAGE 1: Check if multiple different IDs return different content
        unique_lengths = set(r['length'] for r in different_responses)

        # Need at least 2 different response lengths
        if len(unique_lengths) < 2:
            return False, 0.0, ""

        # STAGE 2: Look for data disclosure patterns
        # Database fields, user data, etc.
        data_patterns = [
            r'itemcode',  # XVWA specific
            r'itemname',
            r'price',
            r'username',
            r'email',
            r'name\s*[:\=]',
            r'id\s*[:\=]',
            r'<td>',  # Table data
            r'<tr>',
        ]

        data_disclosure_count = 0
        for response in different_responses:
            for pattern in data_patterns:
                if re.search(pattern, response['text'], re.IGNORECASE):
                    data_disclosure_count += 1
                    break

        # STAGE 3: Check that responses are meaningful (not just error pages)
        has_meaningful_content = any(
            r['length'] > 500 for r in different_responses
        )

        if not has_meaningful_content:
            return False, 0.0, ""

        # STAGE 4: Calculate confidence
        confidence = 0.4  # Base confidence

        # Multiple successful ID accesses
        if len(different_responses) >= 3:
            confidence += 0.2

        # Data disclosure detected
        if data_disclosure_count >= 2:
            confidence += 0.3

        # Parameter name is clearly an ID
        if param_name.lower() in ['id', 'item', 'itemid', 'user', 'userid']:
            confidence += 0.1

        # Significant content variation
        if len(unique_lengths) >= 3:
            confidence += 0.1

        confidence = min(1.0, confidence)

        if confidence < 0.50:
            logger.debug(f"IDOR confidence too low: {confidence:.2f}")
            return False, 0.0, ""

        # Generate evidence
        evidence = f"Parameter '{param_name}' allows access to {len(different_responses)} different objects. "
        evidence += f"Original ID '{original_value}' returned {baseline_length} bytes. "
        evidence += f"Modified IDs: "

        sample_ids = [str(r['payload']) for r in different_responses[:3]]
        evidence += ", ".join(sample_ids)
        evidence += f" returned significantly different content ({', '.join(str(r['length']) for r in different_responses[:3])} bytes)."

        return True, confidence, evidence

    def _extract_id_from_url(self, url: str) -> Optional[Dict[str, str]]:
        """
        Extract ID parameters from URL query string

        Args:
            url: Target URL

        Returns:
            Dictionary of ID parameters or None
        """
        try:
            parsed = urlparse(url)
            query_params = parse_qs(parsed.query)

            # ID-like parameter keywords
            id_keywords = ['id', 'item', 'user', 'uid', 'userid', 'user_id',
                          'itemid', 'item_id', 'object', 'obj', 'doc', 'file',
                          'account', 'profile', 'order', 'invoice', 'aid', 'pid',
                          'cid', 'gid', 'tid', 'sid', 'rid', 'vid', 'eid']

            extracted = {}
            for key, values in query_params.items():
                key_lower = key.lower()
                # Check if parameter name contains ID keywords
                if any(keyword in key_lower for keyword in id_keywords):
                    # Take first value if multiple
                    extracted[key] = values[0] if values else None
                    logger.debug(f"Extracted ID parameter from URL: {key}={extracted[key]}")

            return extracted if extracted else None

        except Exception as e:
            logger.debug(f"Error extracting ID from URL: {e}")
            return None

    def _create_visual_proof(self, original_id: Any, tampered_id: Any,
                            original_data: str, tampered_data: str) -> str:
        """
        Create visual proof showing data differences between IDs

        Args:
            original_id: Original ID value
            tampered_id: Tampered ID value
            original_data: Response data for original ID
            tampered_data: Response data for tampered ID

        Returns:
            Formatted proof string
        """
        proof = "\n\n" + "=" * 60 + "\n"
        proof += "VISUAL PROOF OF IDOR VULNERABILITY\n"
        proof += "=" * 60 + "\n\n"

        # Show original ID access
        proof += f"[1] Original ID: {original_id}\n"
        proof += "-" * 60 + "\n"
        original_sample = self._extract_data_sample(original_data)
        proof += f"Data Sample:\n{original_sample}\n\n"

        # Show tampered ID access
        proof += f"[2] Tampered ID: {tampered_id}\n"
        proof += "-" * 60 + "\n"
        tampered_sample = self._extract_data_sample(tampered_data)
        proof += f"Data Sample:\n{tampered_sample}\n\n"

        # Conclusion
        proof += "=" * 60 + "\n"
        proof += "RESULT: Different objects accessed without authorization!\n"
        proof += "The application does not verify user permissions before\n"
        proof += "returning object data. An attacker can access other users'\n"
        proof += "data by simply changing the ID parameter.\n"
        proof += "=" * 60 + "\n"

        return proof

    def _extract_data_sample(self, data: str, max_length: int = 300) -> str:
        """
        Extract meaningful data sample from response

        Args:
            data: Response data
            max_length: Maximum sample length

        Returns:
            Formatted data sample
        """
        # Look for table data, JSON, or structured content
        patterns = [
            (r'<tr>.*?</tr>', 'HTML Table Row'),
            (r'\{[^}]+\}', 'JSON Object'),
            (r'itemcode.*?price', 'Item Data'),
            (r'username.*?email', 'User Data'),
            (r'name.*?id.*?value', 'Structured Data'),
        ]

        for pattern, label in patterns:
            match = re.search(pattern, data, re.IGNORECASE | re.DOTALL)
            if match:
                sample = match.group(0)
                # Clean HTML tags
                sample = re.sub(r'<[^>]+>', ' ', sample)
                sample = re.sub(r'\s+', ' ', sample).strip()

                if len(sample) > max_length:
                    sample = sample[:max_length] + "..."

                return f"  {sample}"

        # Fallback: just take a meaningful chunk
        clean_data = re.sub(r'<[^>]+>', ' ', data)
        clean_data = re.sub(r'\s+', ' ', clean_data).strip()

        if len(clean_data) > max_length:
            clean_data = clean_data[:max_length] + "..."

        return f"  {clean_data}"


def get_module(module_path: str):
    """Create module instance"""
    return IDORModule(module_path)
