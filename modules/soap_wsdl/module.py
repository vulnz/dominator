"""
SOAP/WSDL/DTD Discovery Scanner Module
Discovers and analyzes WSDL endpoints, SOAP services, and DTD files
"""

import re
from typing import List, Dict, Any
from urllib.parse import urlparse, urljoin
from core.base_module import BaseModule
from core.logger import get_logger

logger = get_logger(__name__)


class SOAPWSDLModule(BaseModule):
    """SOAP/WSDL/DTD discovery and analysis scanner"""

    def __init__(self, module_path: str, payload_limit: int = None):
        """Initialize SOAP/WSDL module"""
        super().__init__(module_path, payload_limit=payload_limit)

        self.wsdl_paths = [
            '?wsdl', '?WSDL', '/wsdl', '/service?wsdl', '/services?wsdl',
            '/ws?wsdl', '/api?wsdl', '/soap?wsdl', '/webservice?wsdl',
            '/Service.asmx?wsdl', '/Service.svc?wsdl',
        ]

        self.soap_endpoints = [
            '/soap', '/services', '/webservices', '/ws', '/api/soap',
            '/Service.asmx', '/Service.svc', '/axis2/services/',
        ]

        logger.info("SOAP/WSDL/DTD Discovery module loaded")

    def scan(self, targets: List[Dict[str, Any]], http_client: Any) -> List[Dict[str, Any]]:
        """Scan for SOAP/WSDL/DTD endpoints"""
        results = []
        tested_hosts = set()

        for target in targets:
            url = target.get('url')
            parsed = urlparse(url)
            host_key = parsed.netloc

            if host_key in tested_hosts:
                continue
            tested_hosts.add(host_key)

            # Check URL for ?wsdl
            if '?wsdl' in url.lower():
                wsdl_result = self._check_wsdl(url, http_client)
                if wsdl_result:
                    results.append(wsdl_result)
                continue

            # Passive scan for SOAP indicators
            passive_results = self._passive_scan(url, http_client)
            results.extend(passive_results)

            # Active: Probe for WSDL
            wsdl_results = self._discover_wsdl(url, http_client)
            results.extend(wsdl_results)

            # Active: Probe for SOAP
            soap_results = self._discover_soap(url, http_client)
            results.extend(soap_results)

        return results

    def _check_wsdl(self, url: str, http_client) -> Dict:
        """Check WSDL endpoint"""
        try:
            response = http_client.get(url)
            if response and response.status_code == 200 and self._is_wsdl(response.text):
                analysis = self._analyze_wsdl(response.text)
                return self.create_result(
                    vulnerable=True,
                    url=url,
                    parameter='wsdl',
                    payload='?wsdl',
                    evidence=f"WSDL exposed. Services: {len(analysis['services'])}, Operations: {len(analysis['operations'])}",
                    severity='Medium',
                    method='GET',
                    additional_info={
                        'injection_type': 'Service Discovery',
                        'analysis': analysis,
                        'cwe': 'CWE-200',
                        'owasp': 'A05:2021',
                        'cvss': 5.3
                    }
                )
        except Exception:
            pass
        return None

    def _passive_scan(self, url: str, http_client) -> List[Dict]:
        """Passive scan for SOAP/WSDL indicators"""
        results = []

        try:
            response = http_client.get(url)
            if not response:
                return results

            content_type = response.headers.get('Content-Type', '').lower()

            # Check for SOAP response
            if any(x in content_type for x in ['xml', 'soap']):
                if '<soap:' in response.text.lower() or '<s:' in response.text.lower():
                    results.append(self.create_result(
                        vulnerable=True,
                        url=url,
                        parameter='Content-Type',
                        payload=content_type,
                        evidence=f"SOAP response detected. Content-Type: {content_type}",
                        severity='Info',
                        method='GET',
                        additional_info={
                            'injection_type': 'Service Detection',
                            'cwe': 'CWE-200',
                            'owasp': 'A05:2021',
                            'cvss': 3.7
                        }
                    ))

            # Find WSDL references
            wsdl_refs = re.findall(r'["\']([^"\']+\.wsdl)["\']', response.text, re.IGNORECASE)
            for ref in wsdl_refs[:3]:
                results.append(self.create_result(
                    vulnerable=True,
                    url=url,
                    parameter='reference',
                    payload=ref,
                    evidence=f"WSDL reference: {ref}",
                    severity='Low',
                    method='GET',
                    additional_info={
                        'injection_type': 'Discovery',
                        'wsdl_url': urljoin(url, ref),
                        'cwe': 'CWE-200',
                        'owasp': 'A05:2021',
                        'cvss': 3.7
                    }
                ))

            # Find DTD references
            dtd_refs = re.findall(r'<!DOCTYPE[^>]+SYSTEM\s+["\']([^"\']+)["\']', response.text)
            for ref in dtd_refs[:3]:
                results.append(self.create_result(
                    vulnerable=True,
                    url=url,
                    parameter='DOCTYPE',
                    payload=ref,
                    evidence=f"External DTD reference: {ref}",
                    severity='Medium',
                    method='GET',
                    additional_info={
                        'injection_type': 'XXE Vector',
                        'cwe': 'CWE-611',
                        'owasp': 'A05:2021',
                        'cvss': 5.3
                    }
                ))

        except Exception:
            pass

        return results

    def _discover_wsdl(self, url: str, http_client) -> List[Dict]:
        """Discover WSDL endpoints"""
        results = []
        parsed = urlparse(url)
        base = f"{parsed.scheme}://{parsed.netloc}"

        for path in self.wsdl_paths[:5]:  # Limit tests
            test_url = base + path if path.startswith('/') else url.rstrip('/') + path

            try:
                response = http_client.get(test_url)
                if response and response.status_code == 200 and self._is_wsdl(response.text):
                    analysis = self._analyze_wsdl(response.text)
                    results.append(self.create_result(
                        vulnerable=True,
                        url=test_url,
                        parameter='path',
                        payload=path,
                        evidence=f"WSDL found. Operations: {analysis['operations'][:5]}",
                        severity='Medium',
                        method='GET',
                        additional_info={
                            'injection_type': 'Service Discovery',
                            'analysis': analysis,
                            'cwe': 'CWE-200',
                            'owasp': 'A05:2021',
                            'cvss': 5.3
                        }
                    ))
                    break
            except Exception:
                continue

        return results

    def _discover_soap(self, url: str, http_client) -> List[Dict]:
        """Discover SOAP endpoints"""
        results = []
        parsed = urlparse(url)
        base = f"{parsed.scheme}://{parsed.netloc}"

        for endpoint in self.soap_endpoints[:3]:  # Limit tests
            test_url = base + endpoint

            try:
                response = http_client.get(test_url)
                if response and self._is_soap_endpoint(response):
                    results.append(self.create_result(
                        vulnerable=True,
                        url=test_url,
                        parameter='endpoint',
                        payload=endpoint,
                        evidence=f"SOAP endpoint found: {endpoint}",
                        severity='Low',
                        method='GET',
                        additional_info={
                            'injection_type': 'Service Discovery',
                            'cwe': 'CWE-200',
                            'owasp': 'A05:2021',
                            'cvss': 3.7
                        }
                    ))
                    break
            except Exception:
                continue

        return results

    def _is_wsdl(self, text: str) -> bool:
        """Check if response is WSDL"""
        indicators = ['<wsdl:definitions', '<definitions', 'xmlns:wsdl', '<wsdl:service']
        return any(ind.lower() in text.lower() for ind in indicators)

    def _is_soap_endpoint(self, response) -> bool:
        """Check if response indicates SOAP endpoint"""
        if not response:
            return False
        ct = response.headers.get('Content-Type', '').lower()
        if 'xml' in ct or 'soap' in ct:
            return True
        indicators = ['soap:', 'wsdl', 'xmlns:soap', '<fault', 'envelope']
        return any(ind in response.text.lower() for ind in indicators)

    def _analyze_wsdl(self, wsdl: str) -> Dict:
        """Extract information from WSDL"""
        return {
            'services': re.findall(r'<(?:wsdl:)?service\s+name=["\']([^"\']+)["\']', wsdl, re.I),
            'operations': list(set(re.findall(r'<(?:wsdl:)?operation\s+name=["\']([^"\']+)["\']', wsdl, re.I))),
            'ports': re.findall(r'<(?:wsdl:)?portType\s+name=["\']([^"\']+)["\']', wsdl, re.I),
            'bindings': re.findall(r'<(?:wsdl:)?binding\s+name=["\']([^"\']+)["\']', wsdl, re.I),
        }


def get_module(module_path: str, payload_limit: int = None):
    """Factory function to create module instance"""
    return SOAPWSDLModule(module_path, payload_limit)
