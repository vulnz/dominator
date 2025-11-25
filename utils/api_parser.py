#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
API Specification Parser

Supports parsing multiple API specification formats:
- OpenAPI/Swagger 2.0 (JSON/YAML)
- OpenAPI 3.0/3.1 (JSON/YAML)
- Postman Collection v2.1
- HAR (HTTP Archive)
- WADL (Web Application Description Language)
- RAML (RESTful API Modeling Language)
- GraphQL Introspection Schema
- API Blueprint
"""

import json
import re
from typing import List, Dict, Any, Optional, Tuple
from urllib.parse import urljoin, urlparse
from pathlib import Path
import requests


class APIEndpoint:
    """Represents a single API endpoint"""

    def __init__(self, url: str, method: str = 'GET', params: Dict = None,
                 headers: Dict = None, body: Any = None, content_type: str = None,
                 description: str = None, auth: Dict = None):
        self.url = url
        self.method = method.upper()
        self.params = params or {}
        self.headers = headers or {}
        self.body = body
        self.content_type = content_type or 'application/json'
        self.description = description
        self.auth = auth

    def to_target(self) -> Dict[str, Any]:
        """Convert to scanner target format"""
        return {
            'url': self.url,
            'method': self.method,
            'params': self.params,
            'headers': self.headers,
            'body': self.body,
            'content_type': self.content_type,
            'description': self.description
        }

    def __repr__(self):
        return f"APIEndpoint({self.method} {self.url})"


class APIParser:
    """Universal API Specification Parser"""

    SUPPORTED_FORMATS = [
        'openapi', 'swagger', 'postman', 'har', 'wadl',
        'raml', 'graphql', 'blueprint', 'auto'
    ]

    def __init__(self, timeout: int = 30):
        self.timeout = timeout
        self.base_url = None
        self.auth_info = {}
        self.endpoints: List[APIEndpoint] = []
        self.spec_info = {}

    def parse(self, source: str, format_type: str = 'auto',
              base_url: str = None) -> List[APIEndpoint]:
        """
        Parse API specification from file path or URL

        Args:
            source: File path or URL to API specification
            format_type: Format type ('auto' for auto-detection)
            base_url: Override base URL for endpoints

        Returns:
            List of APIEndpoint objects
        """
        self.base_url = base_url
        self.endpoints = []

        # Load content
        content = self._load_content(source)
        if not content:
            return []

        # Auto-detect format if needed
        if format_type == 'auto':
            format_type = self._detect_format(content, source)

        # Parse based on format
        parsers = {
            'openapi': self._parse_openapi,
            'swagger': self._parse_openapi,  # Same parser
            'postman': self._parse_postman,
            'har': self._parse_har,
            'wadl': self._parse_wadl,
            'raml': self._parse_raml,
            'graphql': self._parse_graphql,
            'blueprint': self._parse_blueprint
        }

        parser = parsers.get(format_type)
        if parser:
            try:
                parser(content)
            except Exception as e:
                print(f"[!] Error parsing {format_type} spec: {e}")

        return self.endpoints

    def _load_content(self, source: str) -> Optional[str]:
        """Load content from file or URL"""
        try:
            # Check if URL
            if source.startswith(('http://', 'https://')):
                response = requests.get(source, timeout=self.timeout, verify=False)
                response.raise_for_status()
                return response.text
            else:
                # File path
                path = Path(source)
                if path.exists():
                    return path.read_text(encoding='utf-8')
                else:
                    print(f"[!] File not found: {source}")
                    return None
        except Exception as e:
            print(f"[!] Error loading API spec: {e}")
            return None

    def _detect_format(self, content: str, source: str) -> str:
        """Auto-detect API specification format"""
        source_lower = source.lower()

        # Check by file extension first
        if source_lower.endswith('.har'):
            return 'har'
        elif source_lower.endswith('.wadl'):
            return 'wadl'
        elif source_lower.endswith('.raml'):
            return 'raml'
        elif 'postman' in source_lower or source_lower.endswith('.postman_collection.json'):
            return 'postman'
        elif source_lower.endswith('.apib') or source_lower.endswith('.blueprint'):
            return 'blueprint'
        elif source_lower.endswith('.graphql') or source_lower.endswith('.gql'):
            return 'graphql'

        # Try to parse as JSON
        try:
            data = json.loads(content)

            # OpenAPI 3.x
            if 'openapi' in data:
                return 'openapi'

            # Swagger 2.0
            if 'swagger' in data:
                return 'swagger'

            # Postman Collection
            if 'info' in data and '_postman_id' in data.get('info', {}):
                return 'postman'
            if 'item' in data and 'info' in data:
                return 'postman'

            # HAR
            if 'log' in data and 'entries' in data.get('log', {}):
                return 'har'

            # GraphQL introspection
            if '__schema' in data or 'data' in data and '__schema' in data.get('data', {}):
                return 'graphql'

        except json.JSONDecodeError:
            pass

        # Try YAML
        try:
            import yaml
            data = yaml.safe_load(content)

            if isinstance(data, dict):
                if 'openapi' in data:
                    return 'openapi'
                if 'swagger' in data:
                    return 'swagger'
                if 'raml' in str(content[:100]).lower():
                    return 'raml'
        except:
            pass

        # Check for WADL (XML)
        if '<application' in content and 'wadl' in content.lower():
            return 'wadl'

        # Check for RAML header
        if content.strip().startswith('#%RAML'):
            return 'raml'

        # Check for API Blueprint
        if 'FORMAT: 1A' in content or '# Group' in content:
            return 'blueprint'

        # Default to OpenAPI
        return 'openapi'

    def _parse_openapi(self, content: str):
        """Parse OpenAPI/Swagger specification"""
        try:
            data = json.loads(content)
        except json.JSONDecodeError:
            try:
                import yaml
                data = yaml.safe_load(content)
            except:
                print("[!] Failed to parse OpenAPI spec as JSON or YAML")
                return

        # Store spec info
        self.spec_info = {
            'title': data.get('info', {}).get('title', 'Unknown API'),
            'version': data.get('info', {}).get('version', '1.0'),
            'description': data.get('info', {}).get('description', '')
        }

        # Determine base URL
        if not self.base_url:
            # OpenAPI 3.x
            if 'servers' in data and data['servers']:
                self.base_url = data['servers'][0].get('url', '')
            # Swagger 2.0
            elif 'host' in data:
                scheme = data.get('schemes', ['https'])[0]
                base_path = data.get('basePath', '')
                self.base_url = f"{scheme}://{data['host']}{base_path}"

        # Extract security definitions
        self._extract_security(data)

        # Parse paths
        paths = data.get('paths', {})
        for path, path_item in paths.items():
            for method in ['get', 'post', 'put', 'patch', 'delete', 'head', 'options']:
                if method in path_item:
                    operation = path_item[method]
                    endpoint = self._create_openapi_endpoint(path, method, operation, data)
                    if endpoint:
                        self.endpoints.append(endpoint)

    def _create_openapi_endpoint(self, path: str, method: str,
                                  operation: Dict, spec: Dict) -> Optional[APIEndpoint]:
        """Create endpoint from OpenAPI operation"""
        # Build full URL
        url = urljoin(self.base_url or '', path)

        # Extract parameters
        params = {}
        headers = {}
        body = None
        content_type = 'application/json'

        # Process parameters
        for param in operation.get('parameters', []):
            param_name = param.get('name', '')
            param_in = param.get('in', 'query')
            param_schema = param.get('schema', {})
            param_example = param.get('example') or param_schema.get('example')

            # Generate example value if not provided
            if not param_example:
                param_example = self._generate_example_value(param_schema, param_name)

            if param_in == 'query':
                params[param_name] = param_example
            elif param_in == 'header':
                headers[param_name] = param_example
            elif param_in == 'path':
                # Replace path parameter
                url = url.replace('{' + param_name + '}', str(param_example))

        # Process request body (OpenAPI 3.x)
        if 'requestBody' in operation:
            request_body = operation['requestBody']
            content = request_body.get('content', {})

            # Prefer JSON
            for ct in ['application/json', 'application/x-www-form-urlencoded', 'multipart/form-data']:
                if ct in content:
                    content_type = ct
                    schema = content[ct].get('schema', {})
                    body = self._schema_to_example(schema, spec)
                    break

        # Process body for Swagger 2.0
        for param in operation.get('parameters', []):
            if param.get('in') == 'body':
                schema = param.get('schema', {})
                body = self._schema_to_example(schema, spec)
                break

        return APIEndpoint(
            url=url,
            method=method.upper(),
            params=params,
            headers=headers,
            body=body,
            content_type=content_type,
            description=operation.get('summary') or operation.get('description'),
            auth=self.auth_info
        )

    def _extract_security(self, spec: Dict):
        """Extract security/authentication info from spec"""
        # OpenAPI 3.x
        if 'components' in spec and 'securitySchemes' in spec.get('components', {}):
            schemes = spec['components']['securitySchemes']
            for name, scheme in schemes.items():
                self.auth_info[name] = {
                    'type': scheme.get('type'),
                    'scheme': scheme.get('scheme'),
                    'in': scheme.get('in'),
                    'name': scheme.get('name')
                }

        # Swagger 2.0
        if 'securityDefinitions' in spec:
            for name, scheme in spec['securityDefinitions'].items():
                self.auth_info[name] = {
                    'type': scheme.get('type'),
                    'in': scheme.get('in'),
                    'name': scheme.get('name')
                }

    def _generate_example_value(self, schema: Dict, param_name: str = '') -> Any:
        """Generate example value from schema"""
        param_type = schema.get('type', 'string')
        param_format = schema.get('format', '')

        # Check for enum
        if 'enum' in schema:
            return schema['enum'][0]

        # Generate based on type
        type_examples = {
            'integer': 1,
            'number': 1.0,
            'boolean': True,
            'array': [],
            'object': {}
        }

        # Special handling for common parameter names
        name_examples = {
            'id': 1,
            'user_id': 1,
            'userId': 1,
            'email': 'test@example.com',
            'username': 'testuser',
            'password': 'password123',
            'name': 'Test',
            'page': 1,
            'limit': 10,
            'offset': 0,
            'query': 'test',
            'search': 'test',
            'token': 'test_token',
            'api_key': 'test_api_key'
        }

        # Check parameter name first
        param_lower = param_name.lower()
        for key, value in name_examples.items():
            if key in param_lower:
                return value

        # Format-based examples
        format_examples = {
            'email': 'test@example.com',
            'uri': 'https://example.com',
            'url': 'https://example.com',
            'uuid': '550e8400-e29b-41d4-a716-446655440000',
            'date': '2024-01-01',
            'date-time': '2024-01-01T00:00:00Z',
            'password': 'password123',
            'byte': 'dGVzdA==',
            'binary': 'file_content'
        }

        if param_format in format_examples:
            return format_examples[param_format]

        return type_examples.get(param_type, 'test')

    def _schema_to_example(self, schema: Dict, spec: Dict) -> Any:
        """Convert JSON schema to example value"""
        # Resolve $ref if present
        if '$ref' in schema:
            ref = schema['$ref']
            schema = self._resolve_ref(ref, spec)

        # Check for example
        if 'example' in schema:
            return schema['example']

        schema_type = schema.get('type', 'object')

        if schema_type == 'object':
            result = {}
            properties = schema.get('properties', {})
            for prop_name, prop_schema in properties.items():
                result[prop_name] = self._schema_to_example(prop_schema, spec)
            return result

        elif schema_type == 'array':
            items = schema.get('items', {})
            return [self._schema_to_example(items, spec)]

        else:
            return self._generate_example_value(schema)

    def _resolve_ref(self, ref: str, spec: Dict) -> Dict:
        """Resolve JSON reference"""
        if not ref.startswith('#/'):
            return {}

        parts = ref[2:].split('/')
        current = spec

        for part in parts:
            if isinstance(current, dict) and part in current:
                current = current[part]
            else:
                return {}

        return current if isinstance(current, dict) else {}

    def _parse_postman(self, content: str):
        """Parse Postman Collection"""
        try:
            data = json.loads(content)
        except json.JSONDecodeError:
            print("[!] Failed to parse Postman collection as JSON")
            return

        # Store spec info
        info = data.get('info', {})
        self.spec_info = {
            'title': info.get('name', 'Postman Collection'),
            'version': info.get('schema', ''),
            'description': info.get('description', '')
        }

        # Get variables for URL resolution
        variables = {}
        for var in data.get('variable', []):
            variables[var.get('key', '')] = var.get('value', '')

        # Parse items recursively
        self._parse_postman_items(data.get('item', []), variables)

    def _parse_postman_items(self, items: List, variables: Dict, parent_auth: Dict = None):
        """Recursively parse Postman items"""
        for item in items:
            # Check if folder
            if 'item' in item:
                # Folder - recurse
                folder_auth = item.get('auth', parent_auth)
                self._parse_postman_items(item['item'], variables, folder_auth)
            else:
                # Request
                request = item.get('request', {})
                if isinstance(request, str):
                    # Simple URL string
                    url = self._resolve_postman_variables(request, variables)
                    self.endpoints.append(APIEndpoint(url=url, method='GET'))
                else:
                    endpoint = self._create_postman_endpoint(request, variables, parent_auth)
                    if endpoint:
                        self.endpoints.append(endpoint)

    def _create_postman_endpoint(self, request: Dict, variables: Dict,
                                  auth: Dict = None) -> Optional[APIEndpoint]:
        """Create endpoint from Postman request"""
        # Get URL
        url_obj = request.get('url', {})
        if isinstance(url_obj, str):
            url = url_obj
        else:
            raw = url_obj.get('raw', '')
            url = self._resolve_postman_variables(raw, variables)

        if not url:
            return None

        # Set base URL if not set
        if not self.base_url:
            parsed = urlparse(url)
            self.base_url = f"{parsed.scheme}://{parsed.netloc}"

        method = request.get('method', 'GET')

        # Parse headers
        headers = {}
        for header in request.get('header', []):
            if not header.get('disabled', False):
                key = header.get('key', '')
                value = self._resolve_postman_variables(header.get('value', ''), variables)
                headers[key] = value

        # Parse query params
        params = {}
        if isinstance(url_obj, dict):
            for param in url_obj.get('query', []):
                if not param.get('disabled', False):
                    key = param.get('key', '')
                    value = self._resolve_postman_variables(param.get('value', ''), variables)
                    params[key] = value

        # Parse body
        body = None
        content_type = 'application/json'
        body_obj = request.get('body', {})

        if body_obj:
            mode = body_obj.get('mode', '')

            if mode == 'raw':
                body = body_obj.get('raw', '')
                # Try to parse as JSON
                try:
                    body = json.loads(body)
                except:
                    pass

                # Get content type from options
                options = body_obj.get('options', {}).get('raw', {})
                lang = options.get('language', 'json')
                if lang == 'json':
                    content_type = 'application/json'
                elif lang == 'xml':
                    content_type = 'application/xml'

            elif mode == 'urlencoded':
                content_type = 'application/x-www-form-urlencoded'
                body = {}
                for item in body_obj.get('urlencoded', []):
                    if not item.get('disabled', False):
                        body[item.get('key', '')] = item.get('value', '')

            elif mode == 'formdata':
                content_type = 'multipart/form-data'
                body = {}
                for item in body_obj.get('formdata', []):
                    if not item.get('disabled', False):
                        body[item.get('key', '')] = item.get('value', '')

        return APIEndpoint(
            url=url,
            method=method,
            params=params,
            headers=headers,
            body=body,
            content_type=content_type,
            description=request.get('description', '')
        )

    def _resolve_postman_variables(self, text: str, variables: Dict) -> str:
        """Resolve Postman {{variable}} syntax"""
        if not text:
            return text

        pattern = r'\{\{([^}]+)\}\}'

        def replace_var(match):
            var_name = match.group(1)
            return str(variables.get(var_name, f'{{{{{var_name}}}}}'))

        return re.sub(pattern, replace_var, text)

    def _parse_har(self, content: str):
        """Parse HAR (HTTP Archive) format"""
        try:
            data = json.loads(content)
        except json.JSONDecodeError:
            print("[!] Failed to parse HAR as JSON")
            return

        log = data.get('log', {})

        # Store spec info
        creator = log.get('creator', {})
        self.spec_info = {
            'title': f"HAR from {creator.get('name', 'Unknown')}",
            'version': creator.get('version', ''),
            'description': f"Captured {len(log.get('entries', []))} requests"
        }

        # Parse entries
        for entry in log.get('entries', []):
            request = entry.get('request', {})

            url = request.get('url', '')
            method = request.get('method', 'GET')

            # Set base URL
            if not self.base_url and url:
                parsed = urlparse(url)
                self.base_url = f"{parsed.scheme}://{parsed.netloc}"

            # Parse headers
            headers = {}
            for header in request.get('headers', []):
                name = header.get('name', '')
                # Skip some headers
                if name.lower() not in ['host', 'content-length', 'connection']:
                    headers[name] = header.get('value', '')

            # Parse query params
            params = {}
            for param in request.get('queryString', []):
                params[param.get('name', '')] = param.get('value', '')

            # Parse body
            body = None
            content_type = 'application/json'
            post_data = request.get('postData', {})

            if post_data:
                content_type = post_data.get('mimeType', 'application/json')
                text = post_data.get('text', '')

                if post_data.get('params'):
                    # Form data
                    body = {}
                    for param in post_data['params']:
                        body[param.get('name', '')] = param.get('value', '')
                elif text:
                    # Raw body
                    try:
                        body = json.loads(text)
                    except:
                        body = text

            self.endpoints.append(APIEndpoint(
                url=url,
                method=method,
                params=params,
                headers=headers,
                body=body,
                content_type=content_type
            ))

    def _parse_wadl(self, content: str):
        """Parse WADL (Web Application Description Language)"""
        try:
            import xml.etree.ElementTree as ET
            root = ET.fromstring(content)
        except Exception as e:
            print(f"[!] Failed to parse WADL XML: {e}")
            return

        # WADL namespace
        ns = {'wadl': 'http://wadl.dev.java.net/2009/02'}

        # Get base URL from resources
        resources = root.find('.//wadl:resources', ns) or root.find('.//resources')
        if resources is not None:
            self.base_url = self.base_url or resources.get('base', '')

        # Store spec info
        doc = root.find('.//wadl:doc', ns) or root.find('.//doc')
        self.spec_info = {
            'title': doc.get('title', 'WADL API') if doc is not None else 'WADL API',
            'version': '1.0',
            'description': doc.text if doc is not None else ''
        }

        # Parse resources recursively
        self._parse_wadl_resource(resources or root, '')

    def _parse_wadl_resource(self, element, parent_path: str):
        """Recursively parse WADL resource elements"""
        ns = {'wadl': 'http://wadl.dev.java.net/2009/02'}

        # Find resource elements
        resources = element.findall('wadl:resource', ns) or element.findall('resource')

        for resource in resources:
            path = resource.get('path', '')
            full_path = f"{parent_path}/{path}".replace('//', '/')

            # Find methods
            methods = resource.findall('wadl:method', ns) or resource.findall('method')

            for method in methods:
                method_name = method.get('name', 'GET').upper()
                method_id = method.get('id', '')

                # Parse request params
                params = {}
                request = method.find('wadl:request', ns) or method.find('request')

                if request is not None:
                    for param in request.findall('wadl:param', ns) or request.findall('param'):
                        param_name = param.get('name', '')
                        param_style = param.get('style', 'query')
                        param_default = param.get('default', 'test')

                        if param_style == 'query':
                            params[param_name] = param_default
                        elif param_style == 'template':
                            full_path = full_path.replace('{' + param_name + '}', param_default)

                url = urljoin(self.base_url or '', full_path)

                self.endpoints.append(APIEndpoint(
                    url=url,
                    method=method_name,
                    params=params,
                    description=method_id
                ))

            # Recurse into nested resources
            self._parse_wadl_resource(resource, full_path)

    def _parse_raml(self, content: str):
        """Parse RAML (RESTful API Modeling Language)"""
        try:
            import yaml
            data = yaml.safe_load(content)
        except Exception as e:
            print(f"[!] Failed to parse RAML: {e}")
            return

        if not isinstance(data, dict):
            return

        # Store spec info
        self.spec_info = {
            'title': data.get('title', 'RAML API'),
            'version': data.get('version', '1.0'),
            'description': data.get('description', '')
        }

        # Get base URI
        self.base_url = self.base_url or data.get('baseUri', '')

        # Parse resources (keys starting with /)
        for key, value in data.items():
            if key.startswith('/'):
                self._parse_raml_resource(key, value)

    def _parse_raml_resource(self, path: str, resource: Dict, parent_path: str = ''):
        """Recursively parse RAML resources"""
        if not isinstance(resource, dict):
            return

        full_path = f"{parent_path}{path}"

        # HTTP methods
        methods = ['get', 'post', 'put', 'patch', 'delete', 'head', 'options']

        for method in methods:
            if method in resource:
                method_data = resource[method] or {}

                # Parse query parameters
                params = {}
                query_params = method_data.get('queryParameters', {})
                for param_name, param_info in query_params.items():
                    if isinstance(param_info, dict):
                        params[param_name] = param_info.get('example', 'test')
                    else:
                        params[param_name] = 'test'

                # Parse body
                body = None
                content_type = 'application/json'
                body_def = method_data.get('body', {})

                if 'application/json' in body_def:
                    json_body = body_def['application/json']
                    if isinstance(json_body, dict):
                        body = json_body.get('example')
                        if isinstance(body, str):
                            try:
                                body = json.loads(body)
                            except:
                                pass

                url = urljoin(self.base_url or '', full_path)

                self.endpoints.append(APIEndpoint(
                    url=url,
                    method=method.upper(),
                    params=params,
                    body=body,
                    content_type=content_type,
                    description=method_data.get('description', '')
                ))

        # Recurse into nested resources
        for key, value in resource.items():
            if key.startswith('/'):
                self._parse_raml_resource(key, value, full_path)

    def _parse_graphql(self, content: str):
        """Parse GraphQL schema/introspection"""
        try:
            data = json.loads(content)
        except json.JSONDecodeError:
            # Try to parse as SDL (Schema Definition Language)
            self._parse_graphql_sdl(content)
            return

        # Get schema from introspection response
        schema = data.get('__schema') or data.get('data', {}).get('__schema', {})

        if not schema:
            return

        self.spec_info = {
            'title': 'GraphQL API',
            'version': '1.0',
            'description': 'GraphQL introspection schema'
        }

        # Get query and mutation types
        query_type = schema.get('queryType', {}).get('name', 'Query')
        mutation_type = schema.get('mutationType', {}).get('name', 'Mutation')

        # Parse types
        for type_def in schema.get('types', []):
            type_name = type_def.get('name', '')

            if type_name in [query_type, mutation_type]:
                for field in type_def.get('fields', []):
                    field_name = field.get('name', '')

                    # Build GraphQL query
                    args = field.get('args', [])
                    args_str = ''
                    variables = {}

                    if args:
                        arg_parts = []
                        for arg in args:
                            arg_name = arg.get('name', '')
                            arg_type = self._get_graphql_type_name(arg.get('type', {}))
                            arg_parts.append(f'${arg_name}: {arg_type}')
                            variables[arg_name] = self._generate_graphql_example(arg.get('type', {}))
                        args_str = f"({', '.join(arg_parts)})"

                    # Create query body
                    if type_name == query_type:
                        query = f"query {field_name}Query{args_str} {{ {field_name}"
                    else:
                        query = f"mutation {field_name}Mutation{args_str} {{ {field_name}"

                    if args:
                        field_args = ', '.join([f'{a["name"]}: ${a["name"]}' for a in args])
                        query += f"({field_args})"

                    query += " { __typename } }"

                    body = {
                        'query': query,
                        'variables': variables
                    }

                    url = self.base_url or '/graphql'

                    self.endpoints.append(APIEndpoint(
                        url=url,
                        method='POST',
                        body=body,
                        content_type='application/json',
                        description=f"GraphQL {'Query' if type_name == query_type else 'Mutation'}: {field_name}"
                    ))

    def _parse_graphql_sdl(self, content: str):
        """Parse GraphQL SDL (Schema Definition Language)"""
        # Basic SDL parsing - extract type definitions
        self.spec_info = {
            'title': 'GraphQL API',
            'version': '1.0',
            'description': 'GraphQL SDL Schema'
        }

        # Find Query and Mutation types
        type_pattern = r'type\s+(Query|Mutation)\s*\{([^}]+)\}'

        for match in re.finditer(type_pattern, content):
            type_name = match.group(1)
            type_body = match.group(2)

            # Extract fields
            field_pattern = r'(\w+)\s*(?:\([^)]*\))?\s*:'

            for field_match in re.finditer(field_pattern, type_body):
                field_name = field_match.group(1)

                if type_name == 'Query':
                    query = f"query {{ {field_name} {{ __typename }} }}"
                else:
                    query = f"mutation {{ {field_name} {{ __typename }} }}"

                body = {'query': query, 'variables': {}}

                url = self.base_url or '/graphql'

                self.endpoints.append(APIEndpoint(
                    url=url,
                    method='POST',
                    body=body,
                    content_type='application/json',
                    description=f"GraphQL {type_name}: {field_name}"
                ))

    def _get_graphql_type_name(self, type_def: Dict) -> str:
        """Get GraphQL type name from type definition"""
        kind = type_def.get('kind', '')

        if kind == 'NON_NULL':
            return self._get_graphql_type_name(type_def.get('ofType', {})) + '!'
        elif kind == 'LIST':
            return f"[{self._get_graphql_type_name(type_def.get('ofType', {}))}]"
        else:
            return type_def.get('name', 'String')

    def _generate_graphql_example(self, type_def: Dict) -> Any:
        """Generate example value for GraphQL type"""
        kind = type_def.get('kind', '')

        if kind in ['NON_NULL', 'LIST']:
            inner = self._generate_graphql_example(type_def.get('ofType', {}))
            return [inner] if kind == 'LIST' else inner

        type_name = type_def.get('name', 'String')

        examples = {
            'String': 'test',
            'Int': 1,
            'Float': 1.0,
            'Boolean': True,
            'ID': '1'
        }

        return examples.get(type_name, 'test')

    def _parse_blueprint(self, content: str):
        """Parse API Blueprint format"""
        self.spec_info = {
            'title': 'API Blueprint',
            'version': '1.0',
            'description': ''
        }

        # Extract title
        title_match = re.search(r'^#\s+(.+)$', content, re.MULTILINE)
        if title_match:
            self.spec_info['title'] = title_match.group(1)

        # Extract HOST
        host_match = re.search(r'HOST:\s*(.+)$', content, re.MULTILINE)
        if host_match:
            self.base_url = self.base_url or host_match.group(1).strip()

        # Extract endpoints
        # Pattern: ## Method [/path]
        endpoint_pattern = r'##\s+(\w+)\s+\[([^\]]+)\]'

        for match in re.finditer(endpoint_pattern, content):
            method = match.group(1).upper()
            path = match.group(2)

            # Parse path parameters
            params = {}
            param_pattern = r'\{([^}]+)\}'
            for param_match in re.finditer(param_pattern, path):
                param_name = param_match.group(1)
                path = path.replace('{' + param_name + '}', 'test')

            url = urljoin(self.base_url or '', path)

            self.endpoints.append(APIEndpoint(
                url=url,
                method=method,
                params=params
            ))

    def get_targets(self) -> List[Dict[str, Any]]:
        """Convert endpoints to scanner targets format"""
        return [ep.to_target() for ep in self.endpoints]

    def get_summary(self) -> Dict[str, Any]:
        """Get parsing summary"""
        methods = {}
        for ep in self.endpoints:
            methods[ep.method] = methods.get(ep.method, 0) + 1

        return {
            'spec_info': self.spec_info,
            'base_url': self.base_url,
            'total_endpoints': len(self.endpoints),
            'methods': methods,
            'auth_schemes': list(self.auth_info.keys()),
            'auth_info': self.auth_info  # Full auth details for auto-config
        }

    def get_auth_header_hint(self) -> Dict[str, str]:
        """Get authentication header hints from spec for user convenience"""
        hints = {}
        for name, info in self.auth_info.items():
            # Use 'or' to handle None values (dict.get returns None if key exists but value is None)
            auth_type = (info.get('type') or '').lower()
            auth_scheme = (info.get('scheme') or '').lower()
            auth_in = info.get('in') or ''
            header_name = info.get('name') or ''

            if auth_type == 'http' and auth_scheme == 'bearer':
                hints['type'] = 'Bearer Token'
                hints['header'] = 'Authorization'
                hints['format'] = 'Bearer <your-token>'
            elif auth_type == 'apikey':
                hints['type'] = 'API Key'
                hints['header'] = header_name or 'X-API-Key'
                hints['in'] = auth_in  # header, query, or cookie
                hints['format'] = '<your-api-key>'
            elif auth_type == 'oauth2':
                hints['type'] = 'OAuth 2.0'
                hints['header'] = 'Authorization'
                hints['format'] = 'Bearer <oauth-token>'
            elif auth_type == 'http' and auth_scheme == 'basic':
                hints['type'] = 'Basic Auth'
                hints['header'] = 'Authorization'
                hints['format'] = 'Basic <base64-credentials>'
        return hints


def fetch_swagger_url(url: str, timeout: int = 30) -> Optional[str]:
    """
    Fetch Swagger/OpenAPI spec from common endpoints

    Args:
        url: Base URL of the API
        timeout: Request timeout

    Returns:
        URL of the found spec, or None
    """
    common_paths = [
        '/swagger.json',
        '/openapi.json',
        '/api-docs',
        '/v2/api-docs',
        '/v3/api-docs',
        '/swagger/v1/swagger.json',
        '/swagger/docs/v1',
        '/api/swagger.json',
        '/api/openapi.json',
        '/docs/swagger.json',
        '/.well-known/openapi.json',
        '/api-docs.json',
        '/swagger.yaml',
        '/openapi.yaml'
    ]

    # Normalize base URL
    parsed = urlparse(url)
    base = f"{parsed.scheme}://{parsed.netloc}"

    for path in common_paths:
        spec_url = urljoin(base, path)
        try:
            response = requests.get(spec_url, timeout=timeout, verify=False)
            if response.status_code == 200:
                # Verify it's actually a spec
                try:
                    data = response.json()
                    if 'swagger' in data or 'openapi' in data or 'paths' in data:
                        return spec_url
                except:
                    # Try YAML
                    try:
                        import yaml
                        data = yaml.safe_load(response.text)
                        if isinstance(data, dict) and ('swagger' in data or 'openapi' in data):
                            return spec_url
                    except:
                        pass
        except:
            continue

    return None


# CLI usage
if __name__ == '__main__':
    import sys

    if len(sys.argv) < 2:
        print("Usage: python api_parser.py <spec_file_or_url> [format]")
        print("\nSupported formats: openapi, swagger, postman, har, wadl, raml, graphql, blueprint, auto")
        sys.exit(1)

    source = sys.argv[1]
    format_type = sys.argv[2] if len(sys.argv) > 2 else 'auto'

    parser = APIParser()
    endpoints = parser.parse(source, format_type)

    print(f"\n{'='*60}")
    print(f"API Specification: {parser.spec_info.get('title', 'Unknown')}")
    print(f"Base URL: {parser.base_url}")
    print(f"Total Endpoints: {len(endpoints)}")
    print(f"{'='*60}\n")

    for ep in endpoints:
        print(f"{ep.method:8} {ep.url}")
        if ep.params:
            print(f"         Params: {ep.params}")
        if ep.body:
            print(f"         Body: {json.dumps(ep.body)[:100]}...")
