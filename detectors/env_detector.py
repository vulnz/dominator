"""
Environment files (.env) exposure detector
"""

import re
from typing import Tuple, List, Dict, Any

class EnvDetector:
    """Environment files exposure detection logic"""
    
    @staticmethod
    def detect_env_exposure(response_text: str, response_code: int, url: str) -> Tuple[bool, str, str]:
        """
        Detect if .env files are exposed
        Returns (is_exposed, evidence, severity)
        """
        if response_code == 404:
            return False, "HTTP 404 - .env file not found", "Info"
        
        if response_code == 403:
            return True, "HTTP 403 - .env file exists but access forbidden", "Medium"
        
        if response_code != 200:
            return False, f"HTTP {response_code} - unexpected response", "Info"
        
        # Check for environment file content patterns
        if EnvDetector._is_env_file_content(response_text):
            severity = EnvDetector._get_env_severity(response_text)
            return True, f"Environment file exposed with {EnvDetector._count_env_variables(response_text)} variables", severity
        
        return False, "No environment file content detected", "Info"
    
    @staticmethod
    def _is_env_file_content(response_text: str) -> bool:
        """Check if response contains environment file content"""
        # Common .env file patterns
        env_patterns = [
            r'^[A-Z_][A-Z0-9_]*\s*=\s*.+$',  # KEY=value format
            r'APP_NAME\s*=',
            r'APP_ENV\s*=',
            r'APP_KEY\s*=',
            r'APP_DEBUG\s*=',
            r'APP_URL\s*=',
            r'DB_CONNECTION\s*=',
            r'DB_HOST\s*=',
            r'DB_PORT\s*=',
            r'DB_DATABASE\s*=',
            r'DB_USERNAME\s*=',
            r'DB_PASSWORD\s*=',
            r'REDIS_HOST\s*=',
            r'MAIL_MAILER\s*=',
            r'AWS_ACCESS_KEY_ID\s*=',
            r'AWS_SECRET_ACCESS_KEY\s*=',
            r'STRIPE_KEY\s*=',
            r'STRIPE_SECRET\s*=',
            r'PUSHER_APP_ID\s*=',
            r'JWT_SECRET\s*=',
            r'SESSION_DRIVER\s*=',
            r'CACHE_DRIVER\s*=',
            r'QUEUE_CONNECTION\s*='
        ]
        
        # Count matches
        matches = 0
        for pattern in env_patterns:
            if re.search(pattern, response_text, re.MULTILINE | re.IGNORECASE):
                matches += 1
        
        # Need at least 2 patterns to confirm it's an env file
        return matches >= 2
    
    @staticmethod
    def _count_env_variables(response_text: str) -> int:
        """Count environment variables in the file"""
        # Count lines that look like KEY=value
        env_var_pattern = r'^[A-Z_][A-Z0-9_]*\s*=\s*.+$'
        matches = re.findall(env_var_pattern, response_text, re.MULTILINE)
        return len(matches)
    
    @staticmethod
    def _get_env_severity(response_text: str) -> str:
        """Determine severity based on sensitive content"""
        response_lower = response_text.lower()
        
        # Critical patterns that indicate high severity
        critical_patterns = [
            'password', 'secret', 'key', 'token', 'api_key',
            'private_key', 'aws_access_key', 'aws_secret',
            'stripe_secret', 'jwt_secret', 'app_key',
            'database', 'db_password', 'redis_password',
            'mail_password', 'smtp_password'
        ]
        
        # Medium severity patterns
        medium_patterns = [
            'db_host', 'db_username', 'db_database',
            'redis_host', 'mail_host', 'app_url',
            'app_env', 'app_debug'
        ]
        
        critical_count = sum(1 for pattern in critical_patterns if pattern in response_lower)
        medium_count = sum(1 for pattern in medium_patterns if pattern in response_lower)
        
        if critical_count >= 3:
            return "High"
        elif critical_count >= 1 or medium_count >= 5:
            return "Medium"
        else:
            return "Low"
    
    @staticmethod
    def get_sensitive_variables(response_text: str) -> List[str]:
        """Extract sensitive variable names from env file"""
        sensitive_vars = []
        
        # Patterns for sensitive variables
        sensitive_patterns = [
            r'([A-Z_]*PASSWORD[A-Z_]*)\s*=',
            r'([A-Z_]*SECRET[A-Z_]*)\s*=',
            r'([A-Z_]*KEY[A-Z_]*)\s*=',
            r'([A-Z_]*TOKEN[A-Z_]*)\s*=',
            r'(AWS_[A-Z_]+)\s*=',
            r'(STRIPE_[A-Z_]+)\s*=',
            r'(JWT_[A-Z_]+)\s*=',
            r'(API_[A-Z_]*KEY[A-Z_]*)\s*=',
            r'(DB_PASSWORD)\s*=',
            r'(APP_KEY)\s*='
        ]
        
        for pattern in sensitive_patterns:
            matches = re.findall(pattern, response_text, re.IGNORECASE)
            sensitive_vars.extend(matches)
        
        return list(set(sensitive_vars))  # Remove duplicates
    
    @staticmethod
    def get_evidence(response_text: str) -> str:
        """Get detailed evidence for env file exposure"""
        var_count = EnvDetector._count_env_variables(response_text)
        sensitive_vars = EnvDetector.get_sensitive_variables(response_text)
        
        evidence = f"Environment file contains {var_count} configuration variables"
        
        if sensitive_vars:
            evidence += f". SENSITIVE VARIABLES EXPOSED: {', '.join(sensitive_vars[:10])}"
            if len(sensitive_vars) > 10:
                evidence += f" and {len(sensitive_vars) - 10} more"
        
        # Check for specific frameworks
        if 'APP_NAME' in response_text.upper():
            evidence += ". Laravel application detected"
        if 'REACT_APP_' in response_text.upper():
            evidence += ". React application detected"
        if 'VUE_APP_' in response_text.upper():
            evidence += ". Vue.js application detected"
        if 'NEXT_PUBLIC_' in response_text.upper():
            evidence += ". Next.js application detected"
        
        return evidence
    
    @staticmethod
    def get_response_snippet(response_text: str, max_length: int = 500) -> str:
        """Get response snippet showing env variables"""
        lines = response_text.split('\n')
        
        # Show first few non-empty lines
        snippet_lines = []
        for line in lines[:20]:  # Check first 20 lines
            line = line.strip()
            if line and not line.startswith('#'):  # Skip comments
                # Mask sensitive values
                if '=' in line:
                    key, value = line.split('=', 1)
                    if any(sensitive in key.upper() for sensitive in ['PASSWORD', 'SECRET', 'KEY', 'TOKEN']):
                        line = f"{key}=***MASKED***"
                snippet_lines.append(line)
                if len(snippet_lines) >= 10:  # Show max 10 variables
                    break
        
        snippet = '\n'.join(snippet_lines)
        if len(snippet) > max_length:
            snippet = snippet[:max_length] + "..."
        
        return snippet
    
    @staticmethod
    def get_remediation_advice() -> str:
        """Get remediation advice for env file exposure"""
        return (
            "CRITICAL: Environment file exposed! This can leak sensitive configuration data. "
            "Immediate actions required:\n"
            "1. Remove .env files from web-accessible directories\n"
            "2. Configure web server to deny access to .env files\n"
            "3. For Apache: add 'RedirectMatch 404 /\\.env' to .htaccess\n"
            "4. For Nginx: add 'location ~ /\\.env { deny all; }' to server config\n"
            "5. Rotate all exposed secrets, API keys, and passwords\n"
            "6. Use proper deployment practices (exclude .env from deployments)\n"
            "7. Consider using environment variables or secure secret management"
        )
