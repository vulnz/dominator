"""
WSDL Detection and Audit Module

Passively detects WSDL (Web Services Description Language) endpoints and
performs security audits on discovered SOAP web services.

Detects:
- WSDL file endpoints (?wsdl, .wsdl)
- SOAP service patterns
- WS-Security issues
- Information disclosure via WSDL

Security checks:
- Exposed internal endpoints
- Missing WS-Security
- Verbose error messages
- Information leakage in service descriptions
"""

import re
from typing import Dict, List, Tuple, Any, Optional
from urllib.parse import urljoin, urlparse
import xml.etree.ElementTree as ET


class WSDLDetector:
    """
    WSDL Detection and Security Audit

    Passively detects and analyzes WSDL/SOAP web services for security issues.
    """

    # WSDL namespace prefixes
    WSDL_NS = {
        'wsdl': 'http://schemas.xmlsoap.org/wsdl/',
        'soap': 'http://schemas.xmlsoap.org/wsdl/soap/',
        'soap12': 'http://schemas.xmlsoap.org/wsdl/soap12/',
        'wsse': 'http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd',
        'wsp': 'http://schemas.xmlsoap.org/ws/2004/09/policy',
        'xsd': 'http://www.w3.org/2001/XMLSchema',
    }

    @classmethod
    def detect(cls, response_text: str, url: str, headers: Dict[str, str] = None) -> Tuple[bool, List[Dict[str, Any]]]:
        """
        Detect WSDL endpoints and SOAP services.

        Args:
            response_text: HTTP response body
            url: URL being analyzed
            headers: HTTP response headers

        Returns:
            Tuple of (found_wsdl, list_of_findings)
        """
        findings = []

        if not response_text:
            return False, findings

        # Check if response is WSDL
        is_wsdl = cls._is_wsdl_response(response_text, headers)

        if is_wsdl:
            # Parse and audit the WSDL
            wsdl_findings = cls._audit_wsdl(response_text, url)
            findings.extend(wsdl_findings)

        # Check for WSDL endpoint references in any response
        wsdl_refs = cls._find_wsdl_references(response_text, url)
        findings.extend(wsdl_refs)

        # Check for SOAP patterns
        soap_patterns = cls._detect_soap_patterns(response_text, url)
        findings.extend(soap_patterns)

        return len(findings) > 0, findings

    @classmethod
    def _is_wsdl_response(cls, response_text: str, headers: Dict[str, str] = None) -> bool:
        """Check if response is a WSDL document"""
        # Check content type
        if headers:
            content_type = headers.get('content-type', '').lower()
            if 'wsdl' in content_type or 'xml' in content_type:
                pass  # Continue checking

        # Check for WSDL indicators
        wsdl_indicators = [
            '<definitions',
            '<wsdl:definitions',
            'schemas.xmlsoap.org/wsdl',
            '<types>',
            '<wsdl:types>',
            '<portType',
            '<wsdl:portType',
        ]

        response_lower = response_text.lower()
        return any(ind.lower() in response_lower for ind in wsdl_indicators)

    @classmethod
    def _audit_wsdl(cls, wsdl_content: str, url: str) -> List[Dict[str, Any]]:
        """Perform security audit on WSDL content"""
        findings = []

        # Parse XML
        try:
            # Remove BOM if present
            if wsdl_content.startswith('\ufeff'):
                wsdl_content = wsdl_content[1:]

            root = ET.fromstring(wsdl_content)
        except ET.ParseError:
            findings.append({
                'type': 'WSDL Parse Error',
                'severity': 'Info',
                'url': url,
                'description': 'WSDL document could not be parsed (malformed XML)',
                'category': 'wsdl_parse_error',
                'location': 'Response Body',
                'recommendation': 'Verify WSDL is well-formed XML'
            })
            return findings

        # Check 1: WSDL Exposure
        findings.append({
            'type': 'WSDL Exposed',
            'severity': 'Low',
            'url': url,
            'description': 'WSDL document is publicly accessible. This exposes service structure, operations, and parameters.',
            'category': 'wsdl_exposure',
            'location': 'Response Body',
            'recommendation': 'Consider restricting WSDL access to authorized users only. '
                             'Implement IP whitelisting or authentication for WSDL endpoints.'
        })

        # Check 2: Extract service operations (information disclosure)
        operations = cls._extract_operations(root)
        if operations:
            findings.append({
                'type': 'SOAP Operations Disclosed',
                'severity': 'Low',
                'url': url,
                'description': f'WSDL exposes {len(operations)} SOAP operations: {", ".join(operations[:10])}{"..." if len(operations) > 10 else ""}',
                'operations': operations,
                'category': 'soap_operations',
                'location': 'WSDL Document',
                'recommendation': 'Review exposed operations for sensitive functionality. '
                                 'Consider if all operations should be publicly documented.'
            })

        # Check 3: Extract endpoints (potential internal URLs)
        endpoints = cls._extract_endpoints(root)
        internal_endpoints = [ep for ep in endpoints if cls._is_internal_endpoint(ep)]

        if internal_endpoints:
            findings.append({
                'type': 'Internal Endpoints Exposed',
                'severity': 'Medium',
                'url': url,
                'description': f'WSDL exposes internal endpoints: {", ".join(internal_endpoints[:5])}',
                'endpoints': internal_endpoints,
                'category': 'internal_endpoints',
                'location': 'WSDL Document',
                'recommendation': 'Remove or obscure internal endpoint addresses in public WSDL. '
                                 'Use external-facing URLs only.'
            })

        # Check 4: Missing WS-Security
        has_ws_security = cls._check_ws_security(root, wsdl_content)
        if not has_ws_security:
            findings.append({
                'type': 'Missing WS-Security',
                'severity': 'Medium',
                'url': url,
                'description': 'WSDL does not define WS-Security policies. SOAP messages may be transmitted insecurely.',
                'category': 'missing_ws_security',
                'location': 'WSDL Document',
                'recommendation': 'Implement WS-Security for SOAP message encryption and signing. '
                                 'Use WS-SecurityPolicy to define security requirements.'
            })

        # Check 5: Complex types (potential for XXE/injection)
        complex_types = cls._extract_complex_types(root)
        if complex_types:
            findings.append({
                'type': 'Complex Data Types',
                'severity': 'Info',
                'url': url,
                'description': f'WSDL defines {len(complex_types)} complex types. These should be tested for injection vulnerabilities.',
                'types': complex_types[:10],
                'category': 'complex_types',
                'location': 'WSDL Document',
                'recommendation': 'Test all input parameters for SQL injection, XXE, and other injection attacks. '
                                 'Implement strict input validation on the server.'
            })

        return findings

    @classmethod
    def _extract_operations(cls, root) -> List[str]:
        """Extract SOAP operation names from WSDL"""
        operations = []

        # Try different namespace combinations
        for ns_prefix in ['', 'wsdl:']:
            for op in root.iter(f'{{{cls.WSDL_NS["wsdl"]}}}{ns_prefix.replace(":", "")}operation'):
                name = op.get('name')
                if name:
                    operations.append(name)

        # Fallback: search by tag name
        for elem in root.iter():
            if 'operation' in elem.tag.lower():
                name = elem.get('name')
                if name and name not in operations:
                    operations.append(name)

        return list(set(operations))

    @classmethod
    def _extract_endpoints(cls, root) -> List[str]:
        """Extract service endpoint URLs from WSDL"""
        endpoints = []

        # Look for soap:address elements
        for ns in ['soap', 'soap12']:
            for addr in root.iter(f'{{{cls.WSDL_NS.get(ns, "")}}}address'):
                location = addr.get('location')
                if location:
                    endpoints.append(location)

        # Fallback search
        for elem in root.iter():
            location = elem.get('location')
            if location and location.startswith(('http://', 'https://')):
                endpoints.append(location)

        return list(set(endpoints))

    @classmethod
    def _is_internal_endpoint(cls, endpoint: str) -> bool:
        """Check if endpoint appears to be internal"""
        internal_indicators = [
            'localhost', '127.0.0.1', '10.', '172.16.', '172.17.',
            '172.18.', '172.19.', '172.2', '172.3', '192.168.',
            '.internal', '.local', '.intranet', '.corp', '.private'
        ]

        endpoint_lower = endpoint.lower()
        return any(ind in endpoint_lower for ind in internal_indicators)

    @classmethod
    def _check_ws_security(cls, root, wsdl_content: str) -> bool:
        """Check if WS-Security is defined"""
        ws_security_indicators = [
            'wsse:', 'wssecurity', 'ws-security', 'securitypolicy',
            'oasis-200401-wss', 'ws-policy', 'wsp:'
        ]

        content_lower = wsdl_content.lower()
        return any(ind in content_lower for ind in ws_security_indicators)

    @classmethod
    def _extract_complex_types(cls, root) -> List[str]:
        """Extract complex type names from WSDL"""
        types = []

        for elem in root.iter():
            if 'complexType' in elem.tag:
                name = elem.get('name')
                if name:
                    types.append(name)

        return list(set(types))

    @classmethod
    def _find_wsdl_references(cls, response_text: str, base_url: str) -> List[Dict[str, Any]]:
        """Find WSDL endpoint references in response"""
        findings = []

        # Pattern for WSDL URLs
        wsdl_patterns = [
            r'(https?://[^\s"\'<>]+\.wsdl)',
            r'(https?://[^\s"\'<>]+\?wsdl)',
            r'href=["\']([^"\']+\.wsdl)["\']',
            r'href=["\']([^"\']+\?wsdl)["\']',
            r'location=["\']([^"\']+\.wsdl)["\']',
            r'location=["\']([^"\']+\?wsdl)["\']',
        ]

        found_wsdls = set()

        for pattern in wsdl_patterns:
            matches = re.finditer(pattern, response_text, re.IGNORECASE)
            for match in matches:
                wsdl_url = match.group(1)
                if wsdl_url not in found_wsdls:
                    found_wsdls.add(wsdl_url)

                    full_url = urljoin(base_url, wsdl_url)

                    findings.append({
                        'type': 'WSDL Reference Found',
                        'severity': 'Info',
                        'url': base_url,
                        'wsdl_url': full_url,
                        'description': f'WSDL endpoint reference discovered: {full_url}',
                        'category': 'wsdl_reference',
                        'location': 'Response Body',
                        'recommendation': 'Fetch and audit the referenced WSDL for security issues.'
                    })

        return findings

    @classmethod
    def _detect_soap_patterns(cls, response_text: str, url: str) -> List[Dict[str, Any]]:
        """Detect SOAP-related patterns in responses"""
        findings = []

        # SOAP error patterns (information disclosure)
        soap_error_patterns = [
            (r'<soap:Fault>|<SOAP-ENV:Fault>', 'SOAP Fault'),
            (r'<faultcode>.*?</faultcode>', 'SOAP Fault Code'),
            (r'<faultstring>.*?</faultstring>', 'SOAP Fault String'),
            (r'System\.Web\.Services\.Protocols\.SoapException', 'ASP.NET SOAP Exception'),
            (r'AxisFault', 'Apache Axis Fault'),
        ]

        for pattern, fault_type in soap_error_patterns:
            if re.search(pattern, response_text, re.IGNORECASE | re.DOTALL):
                # Extract fault message
                fault_match = re.search(r'<faultstring>(.*?)</faultstring>', response_text, re.IGNORECASE | re.DOTALL)
                fault_msg = fault_match.group(1)[:200] if fault_match else 'N/A'

                findings.append({
                    'type': 'SOAP Error Disclosure',
                    'severity': 'Medium',
                    'url': url,
                    'description': f'{fault_type} detected. May reveal service internals.',
                    'fault_type': fault_type,
                    'fault_message': fault_msg,
                    'category': 'soap_error',
                    'location': 'Response Body',
                    'recommendation': 'Configure SOAP service to return generic error messages. '
                                     'Log detailed errors server-side only.'
                })
                break  # One finding per response

        return findings


def detect_wsdl(response_text: str, url: str, headers: Dict[str, str] = None) -> Tuple[bool, List[Dict[str, Any]]]:
    """Convenience function for WSDL detection"""
    return WSDLDetector.detect(response_text, url, headers)
