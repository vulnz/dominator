"""
JavaScript Secrets Detector - Passive Detection Module

Detects exposed secrets, API keys, tokens, and credentials in JavaScript files.
"""

from typing import List, Dict, Any
import re


class JSSecretsDetector:
    """Detects secrets exposed in JavaScript code"""

    def detect(self, url: str, response: Any, soup: Any) -> List[Dict[str, Any]]:
        """
        Detect secrets in JavaScript code

        Args:
            url: URL being analyzed
            response: Response object
            soup: BeautifulSoup object

        Returns:
            List of findings
        """
        findings = []

        # Only analyze JavaScript files and inline scripts
        content_type = getattr(response, 'headers', {}).get('content-type', '').lower()
        is_js_file = '.js' in url.lower() or 'javascript' in content_type or 'application/json' in content_type

        response_text = getattr(response, 'text', '')

        # Check inline scripts in HTML
        if soup and not is_js_file:
            scripts = soup.find_all('script')
            for script in scripts:
                script_content = script.string if script.string else ''
                if script_content:
                    findings.extend(self._analyze_js_content(url, script_content, inline=True))

        # Check JS files
        if is_js_file and response_text:
            findings.extend(self._analyze_js_content(url, response_text, inline=False))

        return findings

    def _analyze_js_content(self, url: str, content: str, inline: bool = False) -> List[Dict[str, Any]]:
        """
        Analyze JavaScript content for secrets

        Args:
            url: URL of the resource
            content: JavaScript content
            inline: Whether this is inline script or JS file

        Returns:
            List of findings
        """
        findings = []
        location = 'inline script' if inline else 'JavaScript file'

        # Detection 1: AWS Access Keys
        aws_access_key = re.search(r'(?:A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}', content)
        if aws_access_key:
            findings.append({
                'type': 'aws_access_key_exposed',
                'severity': 'Critical',
                'url': url,
                'description': f'AWS Access Key exposed in {location}: {aws_access_key.group(0)[:20]}...',
                'value': aws_access_key.group(0),
                'recommendation': 'CRITICAL: Revoke this AWS access key immediately and rotate credentials'
            })

        # Detection 2: AWS Secret Keys
        aws_secret = re.search(r'(?:aws_secret_access_key|aws_secret)["\']?\s*[:=]\s*["\']([A-Za-z0-9/+=]{40})["\']', content, re.IGNORECASE)
        if aws_secret:
            findings.append({
                'type': 'aws_secret_key_exposed',
                'severity': 'Critical',
                'url': url,
                'description': f'AWS Secret Key exposed in {location}',
                'value': aws_secret.group(1)[:20] + '...',
                'recommendation': 'CRITICAL: Revoke AWS credentials immediately'
            })

        # Detection 3: Generic API Keys
        api_key_patterns = [
            r'(?:api[_-]?key|apikey)["\']?\s*[:=]\s*["\']([a-zA-Z0-9_\-]{20,})["\']',
            r'(?:client[_-]?secret)["\']?\s*[:=]\s*["\']([a-zA-Z0-9_\-]{20,})["\']',
            r'(?:secret[_-]?key)["\']?\s*[:=]\s*["\']([a-zA-Z0-9_\-]{20,})["\']',
        ]

        for pattern in api_key_patterns:
            matches = re.findall(pattern, content, re.IGNORECASE)
            if matches:
                for match in matches[:3]:  # Limit to first 3
                    findings.append({
                        'type': 'api_key_exposed_in_js',
                        'severity': 'High',
                        'url': url,
                        'description': f'API key/secret exposed in {location}: {match[:15]}...',
                        'value': match[:30],
                        'recommendation': 'Remove API keys from client-side code, use server-side proxy instead'
                    })
                break

        # Detection 4: Google API Keys
        google_api = re.search(r'AIza[0-9A-Za-z_\-]{35}', content)
        if google_api:
            findings.append({
                'type': 'google_api_key_exposed',
                'severity': 'High',
                'url': url,
                'description': f'Google API key exposed in {location}: {google_api.group(0)[:20]}...',
                'value': google_api.group(0),
                'recommendation': 'Restrict API key usage by IP/domain and monitor for abuse'
            })

        # Detection 5: Stripe Keys
        stripe_key = re.search(r'(?:sk|pk)_(?:test|live)_[0-9a-zA-Z]{24,}', content)
        if stripe_key:
            severity = 'Critical' if 'sk_live' in stripe_key.group(0) else 'High'
            findings.append({
                'type': 'stripe_key_exposed',
                'severity': severity,
                'url': url,
                'description': f'Stripe {"SECRET" if "sk_" in stripe_key.group(0) else "publishable"} key exposed in {location}',
                'value': stripe_key.group(0)[:20] + '...',
                'recommendation': 'Revoke exposed Stripe key and rotate credentials' if 'sk_' in stripe_key.group(0) else 'Review Stripe key usage'
            })

        # Detection 6: JWT Tokens
        jwt_pattern = r'eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+'
        jwt_matches = re.findall(jwt_pattern, content)
        if jwt_matches:
            findings.append({
                'type': 'jwt_token_exposed',
                'severity': 'High',
                'url': url,
                'description': f'JWT token(s) exposed in {location} ({len(jwt_matches)} found)',
                'value': jwt_matches[0][:50] + '...' if jwt_matches else '',
                'recommendation': 'Remove hardcoded JWT tokens, use secure session management'
            })

        # Detection 7: Database Connection Strings
        db_patterns = [
            r'mongodb(?:\+srv)?://[^\s\'"]+',
            r'mysql://[^\s\'"]+',
            r'postgres(?:ql)?://[^\s\'"]+',
            r'redis://[^\s\'"]+',
        ]

        for pattern in db_patterns:
            matches = re.findall(pattern, content, re.IGNORECASE)
            if matches:
                findings.append({
                    'type': 'database_connection_string_exposed',
                    'severity': 'Critical',
                    'url': url,
                    'description': f'Database connection string exposed in {location}: {matches[0][:30]}...',
                    'value': matches[0][:50],
                    'recommendation': 'CRITICAL: Remove database credentials from client-side code immediately'
                })
                break

        # Detection 8: Private Keys
        private_key_indicators = [
            '-----BEGIN RSA PRIVATE KEY-----',
            '-----BEGIN DSA PRIVATE KEY-----',
            '-----BEGIN EC PRIVATE KEY-----',
            '-----BEGIN PRIVATE KEY-----',
            '-----BEGIN OPENSSH PRIVATE KEY-----',
        ]

        for indicator in private_key_indicators:
            if indicator in content:
                findings.append({
                    'type': 'private_key_exposed',
                    'severity': 'Critical',
                    'url': url,
                    'description': f'Private key exposed in {location}',
                    'recommendation': 'CRITICAL: Revoke this private key immediately and rotate all credentials'
                })
                break

        # Detection 9: OAuth Client Secrets
        oauth_pattern = r'(?:client_secret|oauth[_-]?secret)["\']?\s*[:=]\s*["\']([a-zA-Z0-9_\-]{16,})["\']'
        oauth_matches = re.findall(oauth_pattern, content, re.IGNORECASE)
        if oauth_matches:
            findings.append({
                'type': 'oauth_secret_exposed',
                'severity': 'High',
                'url': url,
                'description': f'OAuth client secret exposed in {location}',
                'value': oauth_matches[0][:20] + '...',
                'recommendation': 'Revoke OAuth credentials and use server-side flow instead'
            })

        # Detection 10: Generic Passwords
        password_patterns = [
            r'(?:password|passwd|pwd)["\']?\s*[:=]\s*["\']([^"\']{6,})["\']',
            r'(?:admin|root)_(?:password|passwd|pwd)["\']?\s*[:=]\s*["\']([^"\']{6,})["\']',
        ]

        for pattern in password_patterns:
            matches = re.findall(pattern, content, re.IGNORECASE)
            # Filter out common placeholders
            placeholders = ['password', '123456', 'admin', 'test', 'example', 'changeme', 'your_password', 'your-password']
            real_passwords = [m for m in matches if m.lower() not in placeholders and not any(p in m.lower() for p in placeholders)]

            if real_passwords:
                findings.append({
                    'type': 'password_exposed_in_js',
                    'severity': 'High',
                    'url': url,
                    'description': f'Password exposed in {location}',
                    'value': real_passwords[0][:20] + '...' if len(real_passwords[0]) > 20 else real_passwords[0],
                    'recommendation': 'Remove hardcoded passwords from client-side code'
                })
                break

        # Detection 11: GitHub Tokens
        github_pattern = r'(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36,}'
        github_matches = re.findall(github_pattern, content)
        if github_matches:
            findings.append({
                'type': 'github_token_exposed',
                'severity': 'Critical',
                'url': url,
                'description': f'GitHub token exposed in {location}',
                'value': github_matches[0][:20] + '...',
                'recommendation': 'CRITICAL: Revoke this GitHub token immediately'
            })

        # Detection 12: Slack Tokens
        slack_pattern = r'xox[baprs]-[0-9a-zA-Z]{10,}'
        slack_matches = re.findall(slack_pattern, content)
        if slack_matches:
            findings.append({
                'type': 'slack_token_exposed',
                'severity': 'High',
                'url': url,
                'description': f'Slack token exposed in {location}',
                'value': slack_matches[0][:20] + '...',
                'recommendation': 'Revoke this Slack token and rotate credentials'
            })

        # Detection 13: Firebase Keys
        firebase_pattern = r'(?:firebase|FIREBASE)["\']?\s*[:=]\s*["\']?([a-zA-Z0-9_\-]{20,})'
        firebase_matches = re.findall(firebase_pattern, content, re.IGNORECASE)
        if firebase_matches:
            findings.append({
                'type': 'firebase_key_exposed',
                'severity': 'Medium',
                'url': url,
                'description': f'Firebase configuration exposed in {location}',
                'value': firebase_matches[0][:20] + '...',
                'recommendation': 'Ensure Firebase security rules are properly configured'
            })

        # Detection 14: Telegram Bot Tokens
        telegram_pattern = r'[0-9]{8,10}:[A-Za-z0-9_-]{35}'
        telegram_matches = re.findall(telegram_pattern, content)
        if telegram_matches:
            findings.append({
                'type': 'telegram_bot_token_exposed',
                'severity': 'High',
                'url': url,
                'description': f'Telegram bot token exposed in {location}',
                'value': telegram_matches[0][:20] + '...',
                'recommendation': 'Revoke this bot token via @BotFather'
            })

        return findings


def get_detector():
    """Factory function to create detector instance"""
    return JSSecretsDetector()
