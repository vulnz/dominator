"""
UUID/GUID Passive Observer Module

Passively detects and reports UUID/GUIDs observed in HTTP traffic.

Detects:
- UUIDs in URL paths and query parameters
- UUIDs in request/response bodies
- UUIDs in headers and cookies
- Different UUID versions (v1-v5)

Security implications:
- UUID v1 exposes MAC address and timestamp (information disclosure)
- Sequential/predictable UUIDs may indicate IDOR vulnerabilities
- UUIDs used as tokens may be brute-forceable
"""

import re
from typing import Dict, List, Tuple, Any, Set
from collections import defaultdict


class UUIDDetector:
    """
    UUID/GUID Passive Observer

    Passively detects and analyzes UUIDs for security implications.
    """

    # UUID pattern (matches all UUID versions)
    # Format: 8-4-4-4-12 hexadecimal characters
    UUID_PATTERN = re.compile(
        r'\b([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})\b'
    )

    # Compact UUID pattern (without dashes)
    UUID_COMPACT_PATTERN = re.compile(
        r'\b([0-9a-fA-F]{32})\b'
    )

    # UUID in URL path pattern
    UUID_PATH_PATTERN = re.compile(
        r'/([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})(?:/|$|\?)'
    )

    # Known UUID parameter names (potential IDOR)
    IDOR_PARAM_NAMES = [
        'id', 'uid', 'uuid', 'guid', 'user_id', 'userid', 'user-id',
        'account_id', 'accountid', 'account', 'profile', 'profile_id',
        'doc_id', 'document_id', 'file_id', 'fileid', 'resource_id',
        'order_id', 'orderid', 'transaction_id', 'token', 'session',
    ]

    # Storage for observed UUIDs (for pattern analysis)
    _observed_uuids: Dict[str, List[str]] = defaultdict(list)

    @classmethod
    def detect(cls, response_text: str, url: str, headers: Dict[str, str] = None,
               request_body: str = None) -> Tuple[bool, List[Dict[str, Any]]]:
        """
        Detect UUIDs/GUIDs in HTTP traffic.

        Args:
            response_text: HTTP response body
            url: URL being analyzed
            headers: HTTP response headers
            request_body: HTTP request body (optional)

        Returns:
            Tuple of (found_uuids, list_of_findings)
        """
        findings = []
        found_uuids: Set[str] = set()

        # Detect UUIDs in URL
        url_findings = cls._detect_in_url(url)
        for finding in url_findings:
            found_uuids.add(finding.get('uuid', ''))
        findings.extend(url_findings)

        # Detect UUIDs in response body
        if response_text:
            body_findings = cls._detect_in_body(response_text, url, 'response')
            for finding in body_findings:
                uuid = finding.get('uuid', '')
                if uuid not in found_uuids:
                    found_uuids.add(uuid)
                    findings.append(finding)

        # Detect UUIDs in request body
        if request_body:
            request_findings = cls._detect_in_body(request_body, url, 'request')
            for finding in request_findings:
                uuid = finding.get('uuid', '')
                if uuid not in found_uuids:
                    found_uuids.add(uuid)
                    findings.append(finding)

        # Detect UUIDs in headers
        if headers:
            header_findings = cls._detect_in_headers(headers, url)
            for finding in header_findings:
                uuid = finding.get('uuid', '')
                if uuid not in found_uuids:
                    found_uuids.add(uuid)
                    findings.append(finding)

        # Analyze UUID patterns for potential vulnerabilities
        if found_uuids:
            pattern_findings = cls._analyze_uuid_patterns(found_uuids, url)
            findings.extend(pattern_findings)

        # Limit findings to prevent excessive output
        if len(findings) > 20:
            # Keep high-severity and unique findings
            high_severity = [f for f in findings if f.get('severity') in ['High', 'Medium']]
            info = [f for f in findings if f.get('severity') == 'Info'][:10]
            findings = high_severity + info

        return len(findings) > 0, findings

    @classmethod
    def _detect_in_url(cls, url: str) -> List[Dict[str, Any]]:
        """Detect UUIDs in URL path and query parameters"""
        findings = []
        from urllib.parse import urlparse, parse_qs

        parsed = urlparse(url)

        # Check URL path
        path_matches = cls.UUID_PATH_PATTERN.findall(parsed.path)
        for uuid in path_matches:
            uuid_info = cls._analyze_uuid(uuid)
            finding = {
                'type': 'UUID in URL Path',
                'severity': 'Info',
                'url': url,
                'uuid': uuid,
                'uuid_version': uuid_info['version'],
                'location': 'URL Path',
                'description': f'UUID found in URL path: {uuid}',
                'category': 'uuid_in_path',
                'recommendation': 'Verify authorization is checked server-side. '
                                 'UUIDs in paths may be vulnerable to IDOR.'
            }

            # Upgrade severity if UUID v1 (leaks MAC/timestamp)
            if uuid_info['version'] == 1:
                finding['severity'] = 'Low'
                finding['description'] += f" [UUID v1 - may leak MAC address: {uuid_info.get('mac', 'unknown')}]"

            findings.append(finding)

        # Check query parameters
        params = parse_qs(parsed.query)
        for param_name, values in params.items():
            for value in values:
                uuid_match = cls.UUID_PATTERN.search(value)
                if uuid_match:
                    uuid = uuid_match.group(1)
                    uuid_info = cls._analyze_uuid(uuid)

                    severity = 'Info'
                    description = f'UUID in parameter "{param_name}": {uuid}'

                    # Check if parameter name suggests IDOR
                    if param_name.lower() in cls.IDOR_PARAM_NAMES:
                        severity = 'Medium'
                        description += f' [Parameter name "{param_name}" suggests potential IDOR]'

                    # Check if UUID v1
                    if uuid_info['version'] == 1:
                        severity = 'Low' if severity == 'Info' else severity
                        description += f' [UUID v1 leaks timestamp]'

                    findings.append({
                        'type': 'UUID in Query Parameter',
                        'severity': severity,
                        'url': url,
                        'uuid': uuid,
                        'parameter': param_name,
                        'uuid_version': uuid_info['version'],
                        'location': 'Query Parameter',
                        'description': description,
                        'category': 'uuid_in_param',
                        'recommendation': 'Test for IDOR by manipulating UUID values. '
                                         'Ensure proper authorization checks.'
                    })

        return findings

    @classmethod
    def _detect_in_body(cls, body: str, url: str, source: str) -> List[Dict[str, Any]]:
        """Detect UUIDs in request/response body"""
        findings = []

        # Find all UUIDs
        matches = cls.UUID_PATTERN.findall(body)

        # Limit to first 20 unique UUIDs
        unique_uuids = list(set(matches))[:20]

        for uuid in unique_uuids:
            uuid_info = cls._analyze_uuid(uuid)

            # Get context around UUID
            context = cls._get_context(body, uuid, 50)

            severity = 'Info'
            description = f'UUID found in {source} body'

            # Check for sensitive context keywords
            sensitive_keywords = ['user', 'account', 'token', 'session', 'auth', 'id', 'password', 'key']
            context_lower = context.lower()
            for keyword in sensitive_keywords:
                if keyword in context_lower:
                    severity = 'Low'
                    description += f' (context includes "{keyword}")'
                    break

            findings.append({
                'type': f'UUID in {source.title()} Body',
                'severity': severity,
                'url': url,
                'uuid': uuid,
                'uuid_version': uuid_info['version'],
                'context': context,
                'location': f'{source.title()} Body',
                'description': description,
                'category': f'uuid_in_{source}',
                'recommendation': 'Review if UUID is used for authorization. Test for IDOR vulnerabilities.'
            })

            # Store for pattern analysis
            cls._observed_uuids[url].append(uuid)

        return findings

    @classmethod
    def _detect_in_headers(cls, headers: Dict[str, str], url: str) -> List[Dict[str, Any]]:
        """Detect UUIDs in HTTP headers"""
        findings = []

        for header_name, header_value in headers.items():
            matches = cls.UUID_PATTERN.findall(str(header_value))
            for uuid in matches:
                uuid_info = cls._analyze_uuid(uuid)

                severity = 'Info'
                description = f'UUID in header "{header_name}"'

                # Higher severity for auth-related headers
                auth_headers = ['authorization', 'x-auth', 'x-token', 'x-session', 'cookie']
                if header_name.lower() in auth_headers:
                    severity = 'Low'
                    description += ' (authentication-related header)'

                findings.append({
                    'type': 'UUID in HTTP Header',
                    'severity': severity,
                    'url': url,
                    'uuid': uuid,
                    'header': header_name,
                    'uuid_version': uuid_info['version'],
                    'location': f'Header: {header_name}',
                    'description': description,
                    'category': 'uuid_in_header',
                    'recommendation': 'Verify UUID-based tokens are properly validated. '
                                     'Consider if UUIDs should be exposed in headers.'
                })

        return findings

    @classmethod
    def _analyze_uuid(cls, uuid: str) -> Dict[str, Any]:
        """
        Analyze UUID to determine version and extract information

        UUID versions:
        - v1: Time-based with MAC address
        - v2: DCE Security (rare)
        - v3: MD5 hash-based
        - v4: Random
        - v5: SHA-1 hash-based
        """
        info = {
            'uuid': uuid,
            'version': 0,
            'variant': 'unknown',
        }

        try:
            # Remove dashes and get bytes
            hex_str = uuid.replace('-', '')

            # Version is in 7th nibble (13th character, 0-indexed position 12)
            version_char = hex_str[12]
            info['version'] = int(version_char, 16)

            # Variant is determined by 9th byte (17th and 18th characters)
            variant_nibble = int(hex_str[16], 16)
            if variant_nibble < 8:
                info['variant'] = 'NCS backward compatibility'
            elif variant_nibble < 12:
                info['variant'] = 'RFC 4122'
            elif variant_nibble < 14:
                info['variant'] = 'Microsoft backward compatibility'
            else:
                info['variant'] = 'Future definition'

            # For UUID v1, extract timestamp and MAC address
            if info['version'] == 1:
                # MAC address is in the last 12 characters
                mac_hex = hex_str[20:]
                mac = ':'.join(mac_hex[i:i+2] for i in range(0, 12, 2))
                info['mac'] = mac

                # Timestamp can be extracted from bytes 0-7 and 8-9
                # This is complex, so just flag it
                info['has_timestamp'] = True

        except Exception:
            info['version'] = 0

        return info

    @classmethod
    def _analyze_uuid_patterns(cls, uuids: Set[str], url: str) -> List[Dict[str, Any]]:
        """Analyze set of UUIDs for patterns that suggest vulnerabilities"""
        findings = []

        if len(uuids) < 2:
            return findings

        uuid_list = list(uuids)

        # Check for UUID v1 (information disclosure)
        v1_uuids = []
        for uuid in uuid_list:
            info = cls._analyze_uuid(uuid)
            if info['version'] == 1:
                v1_uuids.append((uuid, info))

        if v1_uuids:
            # Check if same MAC appears in multiple UUIDs
            mac_addresses = set()
            for uuid, info in v1_uuids:
                if 'mac' in info:
                    mac_addresses.add(info['mac'])

            if mac_addresses:
                findings.append({
                    'type': 'UUID v1 Information Disclosure',
                    'severity': 'Medium',
                    'url': url,
                    'mac_addresses': list(mac_addresses),
                    'description': f'UUID v1 detected revealing MAC address(es): {", ".join(mac_addresses)}. '
                                  f'This discloses hardware information and timestamps.',
                    'category': 'uuid_v1_disclosure',
                    'location': 'Multiple Locations',
                    'recommendation': 'Switch to UUID v4 (random) for identifiers. '
                                     'UUID v1 exposes server/device MAC addresses and creation timestamps.'
                })

        # Check for sequential patterns (potential predictability)
        try:
            # Convert UUIDs to comparable format
            sorted_uuids = sorted(uuid_list)
            if len(sorted_uuids) >= 3:
                # Check if UUIDs appear sequential in any nibble position
                sequential_positions = []
                for pos in range(32):
                    values = []
                    for uuid in sorted_uuids[:5]:  # Check first 5
                        hex_str = uuid.replace('-', '')
                        if pos < len(hex_str):
                            values.append(int(hex_str[pos], 16))

                    if len(values) >= 3:
                        # Check if values are sequential
                        differences = [values[i+1] - values[i] for i in range(len(values)-1)]
                        if all(d == differences[0] for d in differences) and differences[0] != 0:
                            sequential_positions.append(pos)

                if sequential_positions:
                    findings.append({
                        'type': 'Potentially Sequential UUIDs',
                        'severity': 'Low',
                        'url': url,
                        'description': 'UUIDs show potentially sequential patterns. '
                                      'May indicate predictable ID generation.',
                        'category': 'uuid_sequential',
                        'location': 'Multiple Locations',
                        'recommendation': 'Verify UUIDs are truly random. Test for IDOR by predicting next/previous values.'
                    })
        except Exception:
            pass

        return findings

    @classmethod
    def _get_context(cls, text: str, uuid: str, chars: int = 50) -> str:
        """Get text context around UUID"""
        try:
            pos = text.find(uuid)
            if pos == -1:
                return ''

            start = max(0, pos - chars)
            end = min(len(text), pos + len(uuid) + chars)
            context = text[start:end]

            # Clean up whitespace
            context = ' '.join(context.split())

            return context
        except Exception:
            return ''


def detect_uuids(response_text: str, url: str, headers: Dict[str, str] = None,
                 request_body: str = None) -> Tuple[bool, List[Dict[str, Any]]]:
    """Convenience function for UUID detection"""
    return UUIDDetector.detect(response_text, url, headers, request_body)
