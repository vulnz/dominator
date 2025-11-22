"""
GraphQL Security Scanner
Tests GraphQL endpoints for various security vulnerabilities
"""

from core.base_module import BaseModule
from core.http_client import HTTPClient
from core.logger import get_logger
from typing import List, Dict, Any
import json
import re
from urllib.parse import urljoin, urlparse

logger = get_logger(__name__)


class GraphQLSecurityScanner(BaseModule):
    """Scans for GraphQL security vulnerabilities"""

    def __init__(self, module_path: str, payload_limit: int = None):
        super().__init__(module_path, payload_limit=payload_limit)
        self.module_name = "GraphQL Security"
        self.logger = logger
        self.graphql_paths = [
            '/graphql',
            '/graphiql',
            '/api/graphql',
            '/api/graphiql',
            '/v1/graphql',
            '/v2/graphql',
            '/query',
            '/gql',
            '/api',
            '/api/query'
        ]

    def scan(self, targets: List[Dict[str, Any]], http_client: Any = None) -> List[Dict[str, Any]]:
        """
        Scan targets for GraphQL vulnerabilities

        Args:
            targets: List of targets to scan
            http_client: HTTP client for making requests

        Returns:
            List of vulnerability findings
        """
        self.logger.info(f"Starting {self.module_name} scan on {len(targets)} targets")

        results = []
        client = http_client or HTTPClient(timeout=10)

        for target in targets:
            url = target.get('url')
            if not url:
                continue

            # First, discover GraphQL endpoints
            graphql_endpoints = self._discover_graphql_endpoints(client, url)

            # Test each discovered endpoint
            for endpoint in graphql_endpoints:
                for payload in self.payloads[:self.payload_limit]:
                    payload = payload.strip()
                    if not payload or payload.startswith('#'):
                        continue

                    finding = self._test_graphql_payload(client, endpoint, payload)
                    if finding:
                        results.append(finding)

                        # Early exit if configured
                        if self.config.get('early_exit', False):
                            break

        client.close()
        self.logger.info(f"{self.module_name} scan complete: {len(results)} vulnerabilities found")
        return results

    def _discover_graphql_endpoints(self, client: HTTPClient, base_url: str) -> List[str]:
        """Discover GraphQL endpoints"""
        endpoints = []
        parsed = urlparse(base_url)
        base = f"{parsed.scheme}://{parsed.netloc}"

        for path in self.graphql_paths:
            test_url = urljoin(base, path)

            # Try a simple introspection query to detect GraphQL
            test_query = '{"query": "{__typename}"}'
            response = client.post(test_url, data=test_query, headers={'Content-Type': 'application/json'})

            if response and response.status_code in [200, 400, 500]:
                try:
                    data = response.json()
                    if 'data' in data or 'errors' in data:
                        endpoints.append(test_url)
                        self.logger.info(f"Found GraphQL endpoint: {test_url}")
                except:
                    pass

        # If no endpoints found, use original URL
        if not endpoints:
            endpoints.append(base_url)

        return endpoints

    def _test_graphql_payload(self, client: HTTPClient, url: str, payload: str) -> Dict[str, Any]:
        """Test a single GraphQL payload"""

        try:
            # Parse payload type and content
            vuln_type = 'GraphQL Misconfiguration'
            severity = 'High'
            payload_type = 'UNKNOWN'
            query = payload

            if ':' in payload:
                parts = payload.split(':', 1)
                payload_type = parts[0]
                if len(parts) > 1:
                    query = parts[1]
                    if ':' in query:
                        subparts = query.split(':', 1)
                        if len(subparts) > 1:
                            query = subparts[1]

            # Handle special payload types
            if payload_type == 'INTROSPECTION':
                vuln_type = 'GraphQL Introspection Enabled'
                severity = 'Medium'
                query = self._build_introspection_query(query)

            elif payload_type == 'DOS':
                vuln_type = 'GraphQL DoS Vulnerability'
                severity = 'High'
                query = self._build_dos_query(query)

            elif payload_type == 'BATCH':
                vuln_type = 'GraphQL Batch Query Abuse'
                severity = 'Medium'
                query = self._build_batch_query(query)

            elif payload_type == 'ALIAS':
                vuln_type = 'GraphQL Alias-based DoS'
                severity = 'Medium'
                query = self._build_alias_query(query)

            elif payload_type == 'SQLI':
                vuln_type = 'GraphQL SQL Injection'
                severity = 'Critical'

            elif payload_type == 'NOSQLI':
                vuln_type = 'GraphQL NoSQL Injection'
                severity = 'Critical'

            elif payload_type == 'XSS':
                vuln_type = 'GraphQL XSS Vulnerability'
                severity = 'High'

            elif payload_type == 'IDOR':
                vuln_type = 'GraphQL IDOR Vulnerability'
                severity = 'High'

            elif payload_type == 'AUTHZ':
                vuln_type = 'GraphQL Authorization Bypass'
                severity = 'Critical'

            elif payload_type == 'MUTATION':
                vuln_type = 'GraphQL Mutation Vulnerability'
                severity = 'High'

            # Send GraphQL request
            graphql_payload = {'query': query}
            response = client.post(
                url,
                data=json.dumps(graphql_payload),
                headers={'Content-Type': 'application/json'}
            )

            if not response:
                return None

            # Analyze response
            vulnerable, evidence = self._analyze_graphql_response(
                response, payload_type, query
            )

            if vulnerable:
                return {
                    'vulnerability': True,
                    'module': self.module_name,
                    'type': vuln_type,
                    'severity': severity,
                    'url': url,
                    'parameter': 'GraphQL Query',
                    'payload': query[:200] + '...' if len(query) > 200 else query,
                    'method': 'POST',
                    'confidence': 0.80,
                    'description': f'{vuln_type} detected in GraphQL endpoint.',
                    'evidence': evidence,
                    'recommendation': 'Disable introspection in production. Implement query depth limiting. Use query cost analysis. Validate and sanitize all inputs.',
                    'cwe': self.config.get('cwe', 'CWE-89'),
                    'cvss': self.config.get('cvss', 7.5),
                    'owasp': self.config.get('owasp', 'A03:2021'),
                    'references': [
                        'https://owasp.org/www-project-graphql-security/',
                        'https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html',
                        'https://graphql.org/learn/best-practices/#security'
                    ]
                }

        except Exception as e:
            self.logger.debug(f"Error testing GraphQL payload: {str(e)}")

        return None

    def _build_introspection_query(self, query: str) -> str:
        """Build introspection query"""
        return query.replace('{', ' {').replace('}', '} ')

    def _build_dos_query(self, query: str) -> str:
        """Build depth-based DoS query"""
        return query.replace('{', ' {').replace('}', '} ')

    def _build_batch_query(self, query: str) -> str:
        """Build batch query"""
        if '[REPEAT:' in query:
            match = re.search(r'\[REPEAT:(\d+)\]', query)
            if match:
                count = int(match.group(1))
                base_query = query.split(']', 1)[1]
                queries = []
                for i in range(count):
                    queries.append(f"q{i}: {base_query}")
                return 'query {' + ' '.join(queries) + '}'
        return query

    def _build_alias_query(self, query: str) -> str:
        """Build alias-based query"""
        if '[ALIAS:' in query:
            match = re.search(r'\[ALIAS:(\d+)\]', query)
            if match:
                count = int(match.group(1))
                base_query = query.split(']', 1)[1]
                aliases = []
                for i in range(count):
                    aliases.append(f"alias{i}:{base_query}")
                return ' '.join(aliases)
        return query

    def _analyze_graphql_response(self, response, payload_type: str, query: str) -> tuple:
        """Analyze GraphQL response for vulnerabilities"""

        try:
            data = response.json()

            # Check for introspection data
            if payload_type == 'INTROSPECTION':
                if 'data' in data and '__schema' in data.get('data', {}):
                    schema_info = data['data']['__schema']
                    if schema_info:
                        return True, f'Introspection enabled. Schema contains {len(schema_info.get("types", []))} types'

            # Check for successful queries that might indicate vulnerabilities
            if 'data' in data and data['data']:
                # SQLi/NoSQLi detection
                if payload_type in ['SQLI', 'NOSQLI']:
                    if 'user' in str(data['data']) or 'password' in str(data['data']):
                        return True, 'Injection payload returned sensitive data'

                # IDOR detection
                if payload_type == 'IDOR':
                    if 'password' in str(data['data']) or 'ssn' in str(data['data']) or 'apiKey' in str(data['data']):
                        return True, 'IDOR vulnerability: accessed unauthorized data'

                # Authorization bypass
                if payload_type == 'AUTHZ':
                    if 'admin' in str(data['data']) or 'delete' in str(data['data']):
                        return True, 'Authorization bypass: accessed restricted functionality'

            # Check for error-based enumeration
            if 'errors' in data:
                errors = data['errors']
                if isinstance(errors, list) and errors:
                    error_msg = str(errors[0])

                    # Field suggestions indicate exposed schema
                    if 'Did you mean' in error_msg or 'suggest' in error_msg.lower():
                        return True, f'Field suggestion exposed: {error_msg[:100]}'

                    # Detailed error messages
                    if any(keyword in error_msg.lower() for keyword in ['sql', 'database', 'query failed', 'syntax error']):
                        return True, f'Detailed error message: {error_msg[:100]}'

            # Check for batch/alias abuse
            if payload_type in ['BATCH', 'ALIAS']:
                if response.status_code == 200 and len(response.text) > 10000:
                    return True, f'Batch/Alias abuse successful: response size {len(response.text)} bytes'

        except:
            pass

        return False, ''


def get_module(module_path: str, payload_limit: int = None):
    """Factory function to create module instance"""
    return GraphQLSecurityScanner(module_path, payload_limit=payload_limit)
