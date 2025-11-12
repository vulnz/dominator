"""
Passive API endpoints detector
Analyzes HTTP responses to discover API endpoints and potential security issues
"""

import re
from typing import Dict, List, Tuple, Any
from urllib.parse import urlparse, urljoin

class APIEndpointsDetector:
    """Passive API endpoints analysis"""
    
    @staticmethod
    def analyze(response_text: str, url: str, headers: Dict[str, str]) -> Tuple[bool, List[Dict[str, Any]]]:
        """
        Passive API endpoints analysis

        How it works:
        1. Scans response content for API endpoint patterns
        2. Looks for REST API paths, GraphQL endpoints, SOAP services
        3. Identifies API documentation links
        4. Detects API keys and tokens in responses
        5. Finds version information in API responses

        Args:
            response_text: HTTP response body
            url: Current URL being analyzed
            headers: HTTP response headers

        Returns:
            Tuple[bool, List[Dict]]: (has_findings, list_of_findings)
        """
        # ANTI-FALSE-POSITIVE: Skip common JS libraries and minified files
        url_lower = url.lower()
        skip_patterns = [
            'jquery.js', 'jquery.min.js', 'jquery-',
            'bootstrap.js', 'bootstrap.min.js',
            'angular.js', 'angular.min.js',
            'react.js', 'react.min.js', 'react-dom',
            'vue.js', 'vue.min.js',
            'lodash.js', 'lodash.min.js', 'underscore',
            'moment.js', 'moment.min.js',
            'axios.js', 'axios.min.js',
            'd3.js', 'd3.min.js',
            '.min.js', '-min.js',
            'vendor.js', 'bundle.js', 'chunk.js'
        ]

        if any(pattern in url_lower for pattern in skip_patterns):
            return False, []

        findings = []
        
        # API endpoint patterns
        api_patterns = [
            # REST API patterns
            (r'/api/v\d+/[a-zA-Z0-9_/]+', 'REST API Endpoint'),
            (r'/rest/[a-zA-Z0-9_/]+', 'REST API Endpoint'),
            (r'/webapi/[a-zA-Z0-9_/]+', 'Web API Endpoint'),
            
            # GraphQL patterns
            (r'/graphql/?', 'GraphQL Endpoint'),
            (r'/graphiql/?', 'GraphQL IDE'),
            
            # SOAP patterns
            (r'/soap/[a-zA-Z0-9_/]+', 'SOAP Endpoint'),
            (r'\.asmx', 'ASMX Web Service'),
            
            # Common API paths
            (r'/api/[a-zA-Z0-9_/]+', 'API Endpoint'),
            (r'/v\d+/[a-zA-Z0-9_/]+', 'Versioned API'),
            
            # Mobile API patterns
            (r'/mobile/api/[a-zA-Z0-9_/]+', 'Mobile API'),
            (r'/app/api/[a-zA-Z0-9_/]+', 'App API'),
        ]
        
        # Find API endpoints
        found_endpoints = set()
        for pattern, endpoint_type in api_patterns:
            matches = re.findall(pattern, response_text, re.IGNORECASE)
            for match in matches:
                if match not in found_endpoints:
                    found_endpoints.add(match)
                    findings.append({
                        'type': 'api_endpoint',
                        'severity': 'Info',
                        'url': url,
                        'endpoint': match,
                        'endpoint_type': endpoint_type,
                        'description': f'{endpoint_type} discovered: {match}',
                        'recommendation': 'Review API endpoint for proper authentication and authorization'
                    })
        
        # API documentation patterns
        doc_patterns = [
            (r'/swagger/?', 'Swagger Documentation'),
            (r'/swagger-ui/?', 'Swagger UI'),
            (r'/api-docs/?', 'API Documentation'),
            (r'/docs/?', 'Documentation'),
            (r'/redoc/?', 'ReDoc Documentation'),
            (r'/openapi\.json', 'OpenAPI Specification'),
            (r'/swagger\.json', 'Swagger Specification'),
        ]
        
        for pattern, doc_type in doc_patterns:
            if re.search(pattern, response_text, re.IGNORECASE):
                findings.append({
                    'type': 'api_documentation',
                    'severity': 'Medium',
                    'url': url,
                    'doc_type': doc_type,
                    'description': f'{doc_type} exposed publicly',
                    'recommendation': 'Restrict access to API documentation in production'
                })
        
        # API keys and tokens in response
        secret_patterns = [
            (r'api[_-]?key["\']?\s*[:=]\s*["\']([a-zA-Z0-9_-]{20,})["\']', 'API Key'),
            (r'access[_-]?token["\']?\s*[:=]\s*["\']([a-zA-Z0-9_.-]{20,})["\']', 'Access Token'),
            (r'bearer\s+([a-zA-Z0-9_.-]{20,})', 'Bearer Token'),
            (r'jwt["\']?\s*[:=]\s*["\']([a-zA-Z0-9_.-]{20,})["\']', 'JWT Token'),
        ]
        
        for pattern, secret_type in secret_patterns:
            matches = re.findall(pattern, response_text, re.IGNORECASE)
            for match in matches:
                findings.append({
                    'type': 'exposed_secret',
                    'severity': 'High',
                    'url': url,
                    'secret_type': secret_type,
                    'secret_preview': match[:10] + '...' if len(match) > 10 else match,
                    'description': f'{secret_type} exposed in response',
                    'recommendation': 'Remove sensitive tokens from client-side responses'
                })
        
        # API version information
        version_patterns = [
            (r'"version"\s*:\s*"([^"]+)"', 'API Version'),
            (r'"api_version"\s*:\s*"([^"]+)"', 'API Version'),
            (r'<version>([^<]+)</version>', 'Service Version'),
        ]
        
        for pattern, version_type in version_patterns:
            matches = re.findall(pattern, response_text, re.IGNORECASE)
            for match in matches:
                findings.append({
                    'type': 'version_disclosure',
                    'severity': 'Low',
                    'url': url,
                    'version_type': version_type,
                    'version': match,
                    'description': f'{version_type} disclosed: {match}',
                    'recommendation': 'Consider hiding version information from responses'
                })
        
        # Check headers for API-related information
        api_headers = ['X-API-Version', 'X-RateLimit-Limit', 'X-RateLimit-Remaining']
        for header_name in api_headers:
            if header_name in headers:
                findings.append({
                    'type': 'api_header',
                    'severity': 'Info',
                    'url': url,
                    'header': header_name,
                    'value': headers[header_name],
                    'description': f'API-related header found: {header_name}',
                    'recommendation': 'Review if API headers expose sensitive information'
                })
        
        return len(findings) > 0, findings
