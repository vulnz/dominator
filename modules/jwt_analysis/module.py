"""
JWT Analysis Scanner Module
Analyzes JWT tokens for security vulnerabilities
Uses JWT from user-provided Authorization header or scans responses for tokens
"""

import re
import json
import base64
import hashlib
import hmac
from typing import Dict, List, Any, Optional
from urllib.parse import urlparse
from core.base_module import BaseModule


class Module(BaseModule):
    """JWT token vulnerability analyzer"""

    def __init__(self, http_client=None, config: Optional[Dict] = None):
        super().__init__(http_client, config)
        self.name = "JWT Analysis Scanner"
        self.description = "Analyzes JWT tokens for security issues"
        self.common_secrets = [
            'secret', 'password', '123456', 'admin', 'key', 'private',
            'jwt_secret', 'supersecret', 'changeme', 'qwerty', 'letmein',
            'secret123', 'password123', 'jwt', 'token', 'auth', 'test',
            'development', 'dev', 'prod', 'production', 'your-256-bit-secret',
            'your-secret-key', 'mysecret', 'HS256-secret', ''
        ]

    def run(self, target: str, params: Optional[Dict] = None) -> List[Dict[str, Any]]:
        """Run JWT analysis"""
        results = []

        # Get JWT from user-provided headers
        jwt_token = None
        if params:
            # Check for JWT in custom headers
            headers = params.get('headers', {})
            auth_header = headers.get('Authorization', '') or headers.get('authorization', '')
            if auth_header.startswith('Bearer '):
                jwt_token = auth_header[7:]
            elif 'jwt' in headers:
                jwt_token = headers.get('jwt')

        # If no JWT in params, try to find one in the response
        if not jwt_token:
            jwt_token = self._find_jwt_in_response(target)

        if jwt_token:
            # Analyze the JWT
            analysis = self._analyze_jwt(jwt_token, target)
            if analysis:
                results.append(analysis)

            # Test for vulnerabilities
            vuln_results = self._test_jwt_vulnerabilities(jwt_token, target)
            results.extend(vuln_results)

        return results

    def _find_jwt_in_response(self, url: str) -> Optional[str]:
        """Find JWT in response headers or body"""
        try:
            response = self.http_client.get(url)
            if not response:
                return None

            # Check headers
            for header, value in response.headers.items():
                if self._is_jwt(value):
                    return value
                if header.lower() == 'authorization' and value.startswith('Bearer '):
                    token = value[7:]
                    if self._is_jwt(token):
                        return token

            # Check cookies
            cookies = response.headers.get('Set-Cookie', '')
            jwt_match = re.search(r'(?:token|jwt|auth)[^=]*=([A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*)', cookies)
            if jwt_match:
                return jwt_match.group(1)

            # Check response body for JWT patterns
            jwt_pattern = r'eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*'
            matches = re.findall(jwt_pattern, response.text)
            if matches:
                return matches[0]

        except Exception:
            pass

        return None

    def _is_jwt(self, token: str) -> bool:
        """Check if string looks like a JWT"""
        if not token:
            return False
        parts = token.split('.')
        if len(parts) != 3:
            return False
        # Check if parts are base64url encoded
        try:
            for part in parts[:2]:
                self._base64url_decode(part)
            return True
        except Exception:
            return False

    def _base64url_decode(self, data: str) -> bytes:
        """Decode base64url data"""
        # Add padding if needed
        padding = 4 - len(data) % 4
        if padding != 4:
            data += '=' * padding
        return base64.urlsafe_b64decode(data)

    def _decode_jwt(self, token: str) -> Optional[Dict]:
        """Decode JWT without verification"""
        try:
            parts = token.split('.')
            if len(parts) != 3:
                return None

            header = json.loads(self._base64url_decode(parts[0]))
            payload = json.loads(self._base64url_decode(parts[1]))
            signature = parts[2]

            return {
                'header': header,
                'payload': payload,
                'signature': signature,
                'raw': token
            }
        except Exception:
            return None

    def _analyze_jwt(self, token: str, url: str) -> Optional[Dict]:
        """Analyze JWT for security issues"""
        decoded = self._decode_jwt(token)
        if not decoded:
            return None

        header = decoded['header']
        payload = decoded['payload']
        issues = []

        # Check algorithm
        alg = header.get('alg', 'unknown')

        if alg.upper() == 'NONE':
            issues.append({
                'issue': 'Algorithm None',
                'severity': 'Critical',
                'description': 'JWT uses "none" algorithm - signature can be removed entirely'
            })

        if alg.upper() in ['HS256', 'HS384', 'HS512']:
            issues.append({
                'issue': 'Symmetric Algorithm',
                'severity': 'Medium',
                'description': f'JWT uses symmetric algorithm ({alg}). If secret is weak, token can be forged.'
            })

        # Check for missing signature
        if not decoded['signature'] or decoded['signature'] == '':
            issues.append({
                'issue': 'Missing Signature',
                'severity': 'Critical',
                'description': 'JWT has no signature - token integrity is not verified'
            })

        # Check payload for sensitive data
        sensitive_keys = ['password', 'secret', 'private_key', 'api_key', 'ssn', 'credit_card']
        for key in payload:
            if any(s in key.lower() for s in sensitive_keys):
                issues.append({
                    'issue': 'Sensitive Data in Token',
                    'severity': 'Medium',
                    'description': f'JWT contains potentially sensitive field: {key}'
                })

        # Check expiration
        if 'exp' not in payload:
            issues.append({
                'issue': 'No Expiration',
                'severity': 'Low',
                'description': 'JWT has no expiration claim (exp) - token never expires'
            })

        # Check for admin/role claims that could be modified
        privilege_keys = ['role', 'admin', 'is_admin', 'privilege', 'permissions', 'groups']
        for key in payload:
            if any(p in key.lower() for p in privilege_keys):
                issues.append({
                    'issue': 'Privilege Claims Present',
                    'severity': 'Info',
                    'description': f'JWT contains privilege-related claim: {key}={payload[key]}'
                })

        if issues:
            return {
                'vulnerability': True,
                'type': 'JWT Security Analysis',
                'severity': max([i['severity'] for i in issues], key=lambda x: {'Critical': 4, 'High': 3, 'Medium': 2, 'Low': 1, 'Info': 0}.get(x, 0)),
                'url': url,
                'parameter': 'JWT Token',
                'payload': token[:50] + '...' if len(token) > 50 else token,
                'method': 'Analysis',
                'injection_type': 'Token Analysis',
                'evidence': f"Algorithm: {alg}, Issues found: {len(issues)}",
                'issues': issues,
                'decoded_header': header,
                'decoded_payload': {k: str(v)[:100] for k, v in payload.items()},
                'description': f"JWT token analysis found {len(issues)} potential security issues.",
                'recommendation': 'Use RS256 or ES256 algorithms, implement token expiration, avoid sensitive data in payload, validate all claims server-side.',
                'cwe': 'CWE-347',
                'owasp': 'A02:2021',
                'cvss': 7.5,
                'response': json.dumps({'header': header, 'payload_keys': list(payload.keys())})
            }

        return None

    def _test_jwt_vulnerabilities(self, token: str, url: str) -> List[Dict]:
        """Test JWT for exploitable vulnerabilities"""
        results = []
        decoded = self._decode_jwt(token)
        if not decoded:
            return results

        # Test 1: Algorithm confusion (none)
        none_result = self._test_none_algorithm(decoded, url)
        if none_result:
            results.append(none_result)

        # Test 2: Weak secret brute force (for HS256)
        if decoded['header'].get('alg', '').startswith('HS'):
            weak_secret = self._test_weak_secret(token, decoded)
            if weak_secret:
                results.append({
                    'vulnerability': True,
                    'type': 'JWT Weak Secret',
                    'severity': 'Critical',
                    'url': url,
                    'parameter': 'JWT Token',
                    'payload': f'Secret found: {weak_secret}',
                    'method': 'Brute Force',
                    'injection_type': 'Weak Secret',
                    'evidence': f"JWT signed with weak/common secret: '{weak_secret}'",
                    'description': 'JWT is signed with a weak or common secret. Attacker can forge tokens.',
                    'recommendation': 'Use a strong, random secret of at least 256 bits. Consider using asymmetric algorithms (RS256).',
                    'cwe': 'CWE-521',
                    'owasp': 'A02:2021',
                    'cvss': 9.8,
                    'response': f'Cracked secret: {weak_secret}'
                })

        return results

    def _test_none_algorithm(self, decoded: Dict, url: str) -> Optional[Dict]:
        """Test if server accepts 'none' algorithm"""
        try:
            # Create token with 'none' algorithm
            header = {'alg': 'none', 'typ': 'JWT'}
            payload = decoded['payload']

            header_b64 = base64.urlsafe_b64encode(json.dumps(header).encode()).decode().rstrip('=')
            payload_b64 = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip('=')

            none_token = f"{header_b64}.{payload_b64}."

            # Test with the none token
            response = self.http_client.get(
                url,
                headers={'Authorization': f'Bearer {none_token}'}
            )

            # If we get a successful response, it might be vulnerable
            if response and response.status_code == 200:
                # This is a potential issue but needs manual verification
                return {
                    'vulnerability': True,
                    'type': 'JWT Algorithm Confusion',
                    'severity': 'High',
                    'url': url,
                    'parameter': 'JWT Token',
                    'payload': none_token[:50] + '...',
                    'method': 'GET',
                    'injection_type': 'None Algorithm Attack',
                    'evidence': f"Server returned 200 with 'none' algorithm token. Needs manual verification.",
                    'description': 'Server may accept JWT tokens with "none" algorithm, allowing signature bypass.',
                    'recommendation': 'Explicitly reject tokens with "none" algorithm. Use a whitelist of allowed algorithms.',
                    'cwe': 'CWE-347',
                    'owasp': 'A02:2021',
                    'cvss': 9.1,
                    'response': response.text[:500] if response.text else ''
                }
        except Exception:
            pass

        return None

    def _test_weak_secret(self, token: str, decoded: Dict) -> Optional[str]:
        """Test if JWT was signed with a common/weak secret"""
        try:
            alg = decoded['header'].get('alg', 'HS256')
            parts = token.split('.')
            message = f"{parts[0]}.{parts[1]}"
            signature = parts[2]

            # Determine hash algorithm
            if alg == 'HS256':
                hash_alg = hashlib.sha256
            elif alg == 'HS384':
                hash_alg = hashlib.sha384
            elif alg == 'HS512':
                hash_alg = hashlib.sha512
            else:
                return None

            # Decode the actual signature
            try:
                actual_sig = self._base64url_decode(signature)
            except Exception:
                return None

            # Test common secrets
            for secret in self.common_secrets:
                expected_sig = hmac.new(
                    secret.encode('utf-8'),
                    message.encode('utf-8'),
                    hash_alg
                ).digest()

                if hmac.compare_digest(expected_sig, actual_sig):
                    return secret

        except Exception:
            pass

        return None
