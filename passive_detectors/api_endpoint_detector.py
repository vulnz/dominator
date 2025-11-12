"""
API Endpoint Detector - Passive Detection Module

Detects exposed API endpoints, API documentation, and GraphQL endpoints.
"""

from typing import List, Dict, Any
import re


class APIEndpointDetector:
    """Detects API endpoints and documentation"""

    def detect(self, url: str, response: Any, soup: Any) -> List[Dict[str, Any]]:
        """
        Detect API endpoints and documentation

        Args:
            url: URL being analyzed
            response: Response object
            soup: BeautifulSoup object

        Returns:
            List of findings
        """
        findings = []

        response_text = getattr(response, 'text', '')
        headers = getattr(response, 'headers', {})

        # Detection 1: Swagger/OpenAPI documentation
        swagger_indicators = [
            'swagger-ui', 'swagger.json', 'swagger.yaml',
            'openapi', 'api/v1/docs', 'api/v2/docs', 'api/v3/docs',
            'api-docs', 'swagger', '/docs', '/api/docs',
            'redoc', 'rapidoc'
        ]

        for indicator in swagger_indicators:
            if indicator in response_text.lower() or indicator in url.lower():
                findings.append({
                    'type': 'api_documentation_exposed',
                    'severity': 'Medium',
                    'url': url,
                    'description': f'API documentation exposed: {indicator}',
                    'indicator': indicator,
                    'recommendation': 'Ensure API documentation is protected and not exposed to unauthorized users'
                })
                break  # Only report once per URL

        # Detection 2: GraphQL endpoint
        graphql_indicators = [
            '"data":', '"errors":', '"query":', '__schema',
            'GraphQL', 'graphiql', '/graphql', 'graphql'
        ]

        graphql_score = sum(1 for ind in graphql_indicators if ind in response_text)
        if graphql_score >= 2 or '/graphql' in url.lower():
            findings.append({
                'type': 'graphql_endpoint',
                'severity': 'Info',
                'url': url,
                'description': 'GraphQL endpoint detected. Ensure introspection is disabled in production.',
                'recommendation': 'Disable GraphQL introspection in production and implement proper authentication'
            })

        # Detection 3: REST API patterns
        rest_patterns = [
            r'/api/v\d+/',
            r'/api/',
            r'\.json',
            r'/rest/',
            r'/v\d+/users',
            r'/v\d+/items'
        ]

        for pattern in rest_patterns:
            if re.search(pattern, url, re.IGNORECASE):
                # Check if response is JSON
                content_type = headers.get('content-type', '').lower()
                if 'application/json' in content_type:
                    findings.append({
                        'type': 'api_endpoint',
                        'severity': 'Info',
                        'url': url,
                        'description': f'REST API endpoint detected: {pattern}',
                        'recommendation': 'Ensure proper authentication and rate limiting are implemented'
                    })
                    break

        # Detection 4: Exposed API keys in response
        api_key_patterns = [
            r'api[_-]?key["\']?\s*[:=]\s*["\']([a-zA-Z0-9_\-]{20,})["\']',
            r'apikey["\']?\s*[:=]\s*["\']([a-zA-Z0-9_\-]{20,})["\']',
            r'access[_-]?token["\']?\s*[:=]\s*["\']([a-zA-Z0-9_\-]{20,})["\']',
            r'client[_-]?secret["\']?\s*[:=]\s*["\']([a-zA-Z0-9_\-]{20,})["\']',
        ]

        for pattern in api_key_patterns:
            matches = re.findall(pattern, response_text, re.IGNORECASE)
            if matches:
                findings.append({
                    'type': 'api_key_exposed',
                    'severity': 'High',
                    'url': url,
                    'description': f'API key or token exposed in response: {matches[0][:20]}...',
                    'value': matches[0][:50],  # Only first 50 chars for security
                    'recommendation': 'CRITICAL: Remove exposed API keys from responses immediately'
                })
                break

        # Detection 5: CORS misconfiguration
        cors_header = headers.get('access-control-allow-origin', '')
        if cors_header == '*':
            findings.append({
                'type': 'cors_misconfiguration',
                'severity': 'Medium',
                'url': url,
                'header': 'Access-Control-Allow-Origin',
                'value': '*',
                'description': 'CORS policy allows requests from any origin (*)',
                'recommendation': 'Restrict CORS to specific trusted origins'
            })

        # Detection 6: API versioning issues
        if '/v1/' in url.lower():
            findings.append({
                'type': 'old_api_version',
                'severity': 'Low',
                'url': url,
                'description': 'Old API version (v1) detected. Ensure deprecated versions are properly secured.',
                'recommendation': 'Monitor and deprecate old API versions, ensure they have same security as current versions'
            })

        return findings


def get_detector():
    """Factory function to create detector instance"""
    return APIEndpointDetector()
