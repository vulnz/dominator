"""
ASP.NET ViewState Detection and Security Analysis Module

Passively detects ASP.NET ViewState and analyzes it for security issues.

Detects:
- ViewState fields in HTML forms
- ViewState MAC validation status
- ViewState encryption status
- Potential deserialization vulnerabilities

Security checks:
- Missing MAC (Message Authentication Code)
- Unencrypted ViewState containing sensitive data
- Large ViewState (performance/DoS risk)
- ViewState version (vulnerable versions)
- EventValidation presence
"""

import re
import base64
import hashlib
from typing import Dict, List, Tuple, Any, Optional


class ViewStateDetector:
    """
    ASP.NET ViewState Detection and Security Analysis

    Passively detects and analyzes ViewState for security issues.
    """

    # ViewState field pattern
    VIEWSTATE_PATTERN = re.compile(
        r'<input[^>]*name=["\']__VIEWSTATE["\'][^>]*value=["\']([^"\']+)["\']',
        re.IGNORECASE | re.DOTALL
    )

    # ViewState generator pattern
    VIEWSTATE_GENERATOR_PATTERN = re.compile(
        r'<input[^>]*name=["\']__VIEWSTATEGENERATOR["\'][^>]*value=["\']([^"\']+)["\']',
        re.IGNORECASE
    )

    # Event validation pattern
    EVENT_VALIDATION_PATTERN = re.compile(
        r'<input[^>]*name=["\']__EVENTVALIDATION["\'][^>]*value=["\']([^"\']+)["\']',
        re.IGNORECASE
    )

    # ViewState encrypted indicator pattern (encrypted starts with different bytes)
    # Unencrypted ViewState typically starts with /wE (base64 of 0xFF 0x01)
    # Encrypted ViewState has different patterns

    # ASP.NET version patterns
    ASPNET_PATTERNS = [
        re.compile(r'X-AspNet-Version:\s*([^\r\n]+)', re.IGNORECASE),
        re.compile(r'X-Powered-By:\s*ASP\.NET', re.IGNORECASE),
        re.compile(r'\.aspx', re.IGNORECASE),
        re.compile(r'__doPostBack', re.IGNORECASE),
    ]

    # Sensitive data patterns (to check in decoded ViewState)
    SENSITIVE_PATTERNS = [
        re.compile(r'password', re.IGNORECASE),
        re.compile(r'credit.?card', re.IGNORECASE),
        re.compile(r'ssn|social.?security', re.IGNORECASE),
        re.compile(r'api.?key', re.IGNORECASE),
        re.compile(r'secret', re.IGNORECASE),
        re.compile(r'connectionstring', re.IGNORECASE),
        re.compile(r'server=.*?;', re.IGNORECASE),
        re.compile(r'\d{3}-\d{2}-\d{4}'),  # SSN pattern
        re.compile(r'\d{16}'),  # Credit card pattern
    ]

    @classmethod
    def detect(cls, response_text: str, url: str, headers: Dict[str, str] = None) -> Tuple[bool, List[Dict[str, Any]]]:
        """
        Detect ViewState and analyze for security issues.

        Args:
            response_text: HTTP response body
            url: URL being analyzed
            headers: HTTP response headers

        Returns:
            Tuple of (found_viewstate, list_of_findings)
        """
        findings = []

        if not response_text:
            return False, findings

        # Check if this is an ASP.NET application
        is_aspnet = cls._is_aspnet(response_text, headers)

        # Find ViewState
        viewstate_match = cls.VIEWSTATE_PATTERN.search(response_text)
        if not viewstate_match:
            return False, findings

        viewstate_value = viewstate_match.group(1)

        # Basic ViewState detection
        findings.append({
            'type': 'ViewState Detected',
            'severity': 'Info',
            'url': url,
            'viewstate_length': len(viewstate_value),
            'description': f'ASP.NET ViewState detected ({len(viewstate_value)} chars encoded)',
            'category': 'viewstate_detected',
            'location': 'Response Body',
            'recommendation': 'Ensure ViewState MAC validation is enabled. Consider encryption for sensitive data.'
        })

        # Analyze ViewState
        analysis = cls._analyze_viewstate(viewstate_value, url)
        findings.extend(analysis)

        # Check for ViewState generator
        generator_match = cls.VIEWSTATE_GENERATOR_PATTERN.search(response_text)
        if generator_match:
            generator = generator_match.group(1)
            findings.append({
                'type': 'ViewState Generator',
                'severity': 'Info',
                'url': url,
                'generator': generator,
                'description': f'ViewState Generator ID: {generator}. Can be used to identify the control tree.',
                'category': 'viewstate_generator',
                'location': 'Response Body',
                'recommendation': 'ViewState Generator aids in ViewState forgery attacks if MAC is disabled.'
            })

        # Check for Event Validation
        event_match = cls.EVENT_VALIDATION_PATTERN.search(response_text)
        if not event_match and is_aspnet:
            findings.append({
                'type': 'Missing Event Validation',
                'severity': 'Medium',
                'url': url,
                'description': 'EventValidation field not found. Page may be vulnerable to parameter tampering.',
                'category': 'missing_eventvalidation',
                'location': 'Response Body',
                'recommendation': 'Enable EventValidation in web.config: <pages enableEventValidation="true"/>'
            })

        # Check ViewState size (DoS risk if too large)
        if len(viewstate_value) > 100000:  # > 100KB
            findings.append({
                'type': 'Large ViewState',
                'severity': 'Low',
                'url': url,
                'size': len(viewstate_value),
                'description': f'ViewState is very large ({len(viewstate_value) // 1024}KB). '
                              f'May impact performance and enable DoS attacks.',
                'category': 'large_viewstate',
                'location': 'Response Body',
                'recommendation': 'Reduce ViewState size by disabling it on controls that don\'t need it. '
                                 'Use ViewStateMode="Disabled" on specific controls.'
            })

        return True, findings

    @classmethod
    def _is_aspnet(cls, response_text: str, headers: Dict[str, str] = None) -> bool:
        """Check if response is from ASP.NET application"""
        # Check headers
        if headers:
            for key, value in headers.items():
                if 'aspnet' in key.lower() or 'aspnet' in value.lower():
                    return True

        # Check response patterns
        for pattern in cls.ASPNET_PATTERNS:
            if pattern.search(response_text):
                return True

        return False

    @classmethod
    def _analyze_viewstate(cls, viewstate: str, url: str) -> List[Dict[str, Any]]:
        """Analyze ViewState for security issues"""
        findings = []

        try:
            # Decode base64 ViewState
            decoded = base64.b64decode(viewstate)
        except Exception:
            findings.append({
                'type': 'ViewState Decode Error',
                'severity': 'Info',
                'url': url,
                'description': 'Could not decode ViewState. May be encrypted or malformed.',
                'category': 'viewstate_decode_error',
                'location': 'Response Body',
                'recommendation': 'ViewState appears to be encrypted, which is good for security.'
            })
            return findings

        # Check for MAC (Message Authentication Code)
        mac_result = cls._check_mac(decoded, viewstate)
        if mac_result:
            findings.append(mac_result)

        # Check ViewState version
        version_result = cls._check_version(decoded, url)
        if version_result:
            findings.append(version_result)

        # Check for sensitive data in ViewState
        sensitive_findings = cls._check_sensitive_data(decoded, url)
        findings.extend(sensitive_findings)

        # Check if ViewState is encrypted
        encryption_result = cls._check_encryption(decoded, url)
        if encryption_result:
            findings.append(encryption_result)

        return findings

    @classmethod
    def _check_mac(cls, decoded: bytes, original: str) -> Optional[Dict[str, Any]]:
        """Check if ViewState has MAC validation"""
        # ViewState with MAC typically has 20-32 additional bytes at the end
        # The first byte indicates if MAC is present (0xFF = no MAC, other = has MAC)

        if len(decoded) < 20:
            return None

        # Check first few bytes for indicators
        # Unprotected ViewState often starts with 0xFF 0x01
        if decoded.startswith(b'\xff\x01'):
            return {
                'type': 'ViewState MAC Not Enabled',
                'severity': 'Critical',
                'url': '',  # Will be set by caller
                'description': 'ViewState does not appear to have MAC (Message Authentication Code) enabled. '
                              'This allows ViewState manipulation and potential deserialization attacks (CVE-2020-0688).',
                'category': 'viewstate_no_mac',
                'location': 'Response Body',
                'recommendation': 'Enable ViewState MAC in web.config: <pages enableViewStateMac="true"/>. '
                                 'This is critical for preventing deserialization attacks. '
                                 'Set machineKey explicitly in web.config for web farm scenarios.'
            }

        return None

    @classmethod
    def _check_version(cls, decoded: bytes, url: str) -> Optional[Dict[str, Any]]:
        """Check ViewState version for known vulnerabilities"""
        # .NET 2.0+ ViewState starts with 0xFF 0x01 or similar patterns
        # Different versions have different serialization formats

        try:
            # Look for version indicators in decoded data
            decoded_str = decoded.decode('latin-1', errors='ignore')

            # Check for .NET 1.x format (different serialization)
            if b'System.Web.UI.LosFormatter' in decoded:
                return {
                    'type': 'Legacy ViewState Format',
                    'severity': 'Medium',
                    'url': url,
                    'description': 'ViewState appears to use legacy .NET 1.x format. '
                                  'Consider upgrading to newer framework version.',
                    'category': 'viewstate_legacy',
                    'location': 'Response Body',
                    'recommendation': 'Upgrade to modern .NET framework. Enable ViewState encryption.'
                }
        except Exception:
            pass

        return None

    @classmethod
    def _check_sensitive_data(cls, decoded: bytes, url: str) -> List[Dict[str, Any]]:
        """Check for sensitive data in ViewState"""
        findings = []

        try:
            decoded_str = decoded.decode('latin-1', errors='ignore')

            for pattern in cls.SENSITIVE_PATTERNS:
                match = pattern.search(decoded_str)
                if match:
                    # Get context around match
                    start = max(0, match.start() - 30)
                    end = min(len(decoded_str), match.end() + 30)
                    context = decoded_str[start:end]
                    # Clean non-printable characters
                    context = ''.join(c if c.isprintable() else '.' for c in context)

                    findings.append({
                        'type': 'Sensitive Data in ViewState',
                        'severity': 'High',
                        'url': url,
                        'pattern_matched': pattern.pattern,
                        'context': context[:100],
                        'description': f'Potential sensitive data found in ViewState: pattern "{pattern.pattern}" matched.',
                        'category': 'viewstate_sensitive_data',
                        'location': 'ViewState',
                        'recommendation': 'Never store sensitive data in ViewState. Enable ViewState encryption. '
                                         'Move sensitive data to server-side session state.'
                    })
                    break  # Report only first match per response

        except Exception:
            pass

        return findings

    @classmethod
    def _check_encryption(cls, decoded: bytes, url: str) -> Optional[Dict[str, Any]]:
        """Check if ViewState is encrypted"""
        # Encrypted ViewState typically doesn't start with 0xFF 0x01
        # and appears more random

        if len(decoded) < 10:
            return None

        # Check entropy - encrypted data should have high entropy
        byte_counts = {}
        for byte in decoded[:1000]:  # Sample first 1KB
            byte_counts[byte] = byte_counts.get(byte, 0) + 1

        # Calculate simple entropy measure
        unique_bytes = len(byte_counts)

        # Unencrypted ViewState typically has lower entropy (lots of repeated bytes)
        # Encrypted ViewState should use most of the byte range
        if unique_bytes < 50 and len(decoded) > 100:
            return {
                'type': 'ViewState Not Encrypted',
                'severity': 'Medium',
                'url': url,
                'description': 'ViewState does not appear to be encrypted. '
                              'Data stored in ViewState may be visible to users.',
                'category': 'viewstate_not_encrypted',
                'location': 'Response Body',
                'recommendation': 'Enable ViewState encryption in web.config: '
                                 '<pages viewStateEncryptionMode="Always"/>. '
                                 'Configure machineKey with strong encryption.'
            }

        return None


def detect_viewstate(response_text: str, url: str, headers: Dict[str, str] = None) -> Tuple[bool, List[Dict[str, Any]]]:
    """Convenience function for ViewState detection"""
    return ViewStateDetector.detect(response_text, url, headers)
