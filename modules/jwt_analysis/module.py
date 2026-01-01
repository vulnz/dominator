"""
JWT Analysis Scanner Module
Analyzes JWT tokens for security vulnerabilities
"""

import re
import json
import base64
import hmac
import hashlib
from typing import List, Dict, Any
from core.base_module import BaseModule
from core.logger import get_logger

logger = get_logger(__name__)


class JWTModule(BaseModule):
    """JWT token vulnerability analyzer"""

    def __init__(self, module_path: str, payload_limit: int = None):
        """Initialize JWT module"""
        super().__init__(module_path, payload_limit=payload_limit)

        # Comprehensive list of common weak JWT secrets from real-world leaks and defaults
        self.common_secrets = [
            # Empty and trivial
            '', ' ', 'secret', 'password', 'pass', 'pwd',
            # Common defaults
            '123456', '12345678', '123456789', '1234567890',
            'admin', 'administrator', 'root', 'user', 'guest',
            'key', 'private', 'privatekey', 'private_key', 'private-key',
            # JWT-specific defaults (from tutorials, libraries)
            'jwt_secret', 'jwt-secret', 'jwt_secret_key', 'jwtsecret',
            'your-256-bit-secret', 'your-secret-key', 'your_secret_key',
            'my-secret-key', 'my_secret_key', 'mysecret', 'mysecretkey',
            'super-secret', 'supersecret', 'super_secret', 'topsecret',
            'secret123', 'secret1234', 'secretkey', 'secret_key', 'secret-key',
            'password123', 'password1234', 'passw0rd', 'P@ssw0rd',
            # Common insecure passwords
            'changeme', 'changeit', 'qwerty', 'qwerty123', 'letmein',
            'welcome', 'welcome1', 'login', 'access', 'master',
            'monkey', 'dragon', 'baseball', 'football', 'shadow',
            'sunshine', 'princess', 'trustno1', 'abc123', 'iloveyou',
            # Development/test values
            'jwt', 'token', 'auth', 'test', 'testing', 'development',
            'dev', 'debug', 'demo', 'sample', 'example', 'default',
            'temp', 'temporary', 'dummy', 'placeholder',
            # Framework/library defaults
            'AllYourBase', 'HS256-secret', 'hmac-secret', 'signing-key',
            'keyboard cat', 'keyboard-cat', 'shhhhh', 'ssh', 'shhhhhhhared-secret',
            # Keyboard patterns
            'asdfgh', 'asdfghjkl', 'zxcvbn', 'qazwsx', '1qaz2wsx',
            # Company/product names often used
            'company', 'api', 'apikey', 'api_key', 'api-key', 'app',
            'application', 'server', 'service', 'backend', 'frontend',
            # UUID-like but weak
            '00000000-0000-0000-0000-000000000000', 'aaaaaaaa',
            # Base64-encoded weak secrets
            'c2VjcmV0', 'cGFzc3dvcmQ=', 'YWRtaW4=',  # secret, password, admin
            # Node.js/Express common
            'express-session-secret', 'session-secret', 'cookie-secret',
            # Spring Boot defaults
            'spring-boot-secret', 'spring-security-jwt-secret',
            # Laravel defaults
            'base64:somebase64string', 'SomeRandomString',
        ]

        logger.info("JWT Analysis module loaded")

    def scan(self, targets: List[Dict[str, Any]], http_client: Any) -> List[Dict[str, Any]]:
        """Scan for JWT vulnerabilities"""
        results = []
        tested_tokens = set()

        for target in targets:
            # Handle both dict and string targets
            if isinstance(target, str):
                url = target
                headers = {}
            elif isinstance(target, dict):
                url = target.get('url', '')
                headers = target.get('headers', {})
                # Ensure headers is a dict
                if not isinstance(headers, dict):
                    headers = {}
            else:
                continue

            # Check Authorization header for JWT
            auth_header = headers.get('Authorization', '') or headers.get('authorization', '')
            if auth_header.startswith('Bearer '):
                jwt_token = auth_header[7:]
                if jwt_token not in tested_tokens:
                    tested_tokens.add(jwt_token)
                    jwt_results = self._analyze_jwt(url, jwt_token, 'Authorization header')
                    results.extend(jwt_results)

            # Also scan response for JWTs
            try:
                response = http_client.get(url)
                if response:
                    found_jwts = self._find_jwts(response.text)
                    for jwt_token in found_jwts:
                        if jwt_token not in tested_tokens:
                            tested_tokens.add(jwt_token)
                            jwt_results = self._analyze_jwt(url, jwt_token, 'Response body')
                            results.extend(jwt_results)
            except Exception:
                pass

        return results

    def _find_jwts(self, text: str) -> List[str]:
        """Find JWT tokens in text"""
        # JWT pattern: base64.base64.base64
        pattern = r'eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+'
        return list(set(re.findall(pattern, text)))[:5]  # Limit to 5

    def _analyze_jwt(self, url: str, token: str, source: str) -> List[Dict]:
        """Analyze JWT token for vulnerabilities"""
        results = []

        try:
            parts = token.split('.')
            if len(parts) != 3:
                return results

            # Decode header and payload
            header = self._base64_decode(parts[0])
            payload = self._base64_decode(parts[1])

            if not header or not payload:
                return results

            header_json = json.loads(header)
            payload_json = json.loads(payload)

            algorithm = header_json.get('alg', '')

            # 1. Check for 'none' algorithm
            if algorithm.lower() == 'none':
                results.append(self.create_result(
                    vulnerable=True,
                    url=url,
                    parameter='JWT',
                    payload=token[:50] + '...',
                    evidence=f"JWT uses 'none' algorithm - signature not verified!",
                    severity='Critical',
                    method='GET',
                    additional_info={
                        'injection_type': 'JWT None Algorithm',
                        'source': source,
                        'cwe': 'CWE-327',
                        'owasp': 'A02:2021',
                        'cvss': 9.8
                    }
                ))

            # 2. Check for weak secret (HS256/HS384/HS512)
            if algorithm.upper().startswith('HS'):
                weak_secret = self._check_weak_secret(token, algorithm)
                if weak_secret:
                    results.append(self.create_result(
                        vulnerable=True,
                        url=url,
                        parameter='JWT',
                        payload=token[:50] + '...',
                        evidence=f"JWT signed with weak secret: '{weak_secret}'",
                        severity='Critical',
                        method='GET',
                        additional_info={
                            'injection_type': 'JWT Weak Secret',
                            'weak_secret': weak_secret,
                            'source': source,
                            'cwe': 'CWE-326',
                            'owasp': 'A02:2021',
                            'cvss': 9.1
                        }
                    ))

            # 3. Check for sensitive data in payload
            sensitive_keys = {'password', 'secret', 'key', 'credit', 'ssn', 'token'}
            sensitive_found = [k for k in payload_json if any(s in k.lower() for s in sensitive_keys)]

            if sensitive_found:
                # Build detailed evidence showing actual JWT content
                evidence_parts = [
                    "**JWT Contains Sensitive Data**\n",
                    f"**Source:** {source}",
                    f"**Sensitive Fields Found:** {', '.join(sensitive_found)}",
                    f"\n**JWT Header:**\n```json\n{json.dumps(header_json, indent=2)}\n```",
                    f"\n**JWT Payload (showing sensitive fields):**"
                ]

                # Show actual values (masked for security)
                for key in sensitive_found:
                    value = payload_json.get(key, '')
                    if isinstance(value, str) and len(value) > 4:
                        masked = value[:2] + '*' * (len(value) - 4) + value[-2:]
                    else:
                        masked = '****'
                    evidence_parts.append(f"  - `{key}`: {masked}")

                evidence_parts.append(f"\n**Full JWT (truncated):**\n`{token[:100]}...`")

                results.append(self.create_result(
                    vulnerable=True,
                    url=url,
                    parameter='JWT',
                    payload=token[:50] + '...',
                    evidence='\n'.join(evidence_parts),
                    severity='Medium',
                    method='GET',
                    additional_info={
                        'injection_type': 'JWT Sensitive Data',
                        'sensitive_fields': sensitive_found,
                        'source': source,
                        'header': header_json,
                        'payload_keys': list(payload_json.keys()),
                        'cwe': 'CWE-200',
                        'owasp': 'A02:2021',
                        'cvss': 5.3
                    }
                ))

            # 4. Check for missing expiration
            if 'exp' not in payload_json:
                results.append(self.create_result(
                    vulnerable=True,
                    url=url,
                    parameter='JWT',
                    payload=token[:50] + '...',
                    evidence="JWT has no expiration (exp) claim",
                    severity='Low',
                    method='GET',
                    additional_info={
                        'injection_type': 'JWT No Expiration',
                        'source': source,
                        'cwe': 'CWE-613',
                        'owasp': 'A02:2021',
                        'cvss': 3.7
                    }
                ))

        except Exception:
            pass

        return results

    def _base64_decode(self, data: str) -> str:
        """Decode base64url"""
        try:
            padding = 4 - len(data) % 4
            if padding != 4:
                data += '=' * padding
            data = data.replace('-', '+').replace('_', '/')
            return base64.b64decode(data).decode('utf-8')
        except Exception:
            return ''

    def _check_weak_secret(self, token: str, algorithm: str) -> str:
        """Check if JWT uses a weak secret"""
        parts = token.split('.')
        if len(parts) != 3:
            return ''

        message = f"{parts[0]}.{parts[1]}"
        signature = parts[2]

        # Fix base64url padding
        sig_padding = 4 - len(signature) % 4
        if sig_padding != 4:
            signature += '=' * sig_padding
        signature = signature.replace('-', '+').replace('_', '/')

        try:
            original_sig = base64.b64decode(signature)
        except Exception:
            return ''

        hash_func = {
            'HS256': hashlib.sha256,
            'HS384': hashlib.sha384,
            'HS512': hashlib.sha512
        }.get(algorithm.upper(), hashlib.sha256)

        for secret in self.common_secrets[:80]:  # Test up to 80 common secrets
            try:
                computed = hmac.new(
                    secret.encode('utf-8'),
                    message.encode('utf-8'),
                    hash_func
                ).digest()

                if computed == original_sig:
                    return secret
            except Exception:
                continue

        return ''


def get_module(module_path: str, payload_limit: int = None):
    """Factory function to create module instance"""
    return JWTModule(module_path, payload_limit)
