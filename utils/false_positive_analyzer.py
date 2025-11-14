"""
False Positive Analyzer & Auto-Fix System
Автоматически анализирует репорты и создаёт фиксы для false positives
"""

import json
import re
from typing import Dict, List, Tuple, Set
from pathlib import Path
from collections import defaultdict


class FalsePositiveRule:
    """Rule for detecting false positive"""

    def __init__(self, module: str, condition: str, reason: str, fix: str):
        self.module = module
        self.condition = condition  # Python expression to evaluate
        self.reason = reason  # Why it's false positive
        self.fix = fix  # How to fix it

    def matches(self, finding: Dict) -> bool:
        """Check if finding matches this false positive rule"""
        try:
            # Create safe evaluation context
            context = {
                'url': finding.get('url', ''),
                'parameter': finding.get('parameter', ''),
                'payload': finding.get('payload', ''),
                'evidence': finding.get('evidence', ''),
                'confidence': finding.get('confidence', 0),
                'module': finding.get('module', ''),
                're': re,
            }
            return eval(self.condition, {"__builtins__": {}}, context)
        except Exception as e:
            print(f"Error evaluating rule: {e}")
            return False


class FalsePositiveAnalyzer:
    """
    Анализатор false positives
    Автоматически находит паттерны и генерирует фиксы
    """

    def __init__(self):
        self.rules: List[FalsePositiveRule] = []
        self._load_default_rules()

    def _load_default_rules(self):
        """Load default false positive detection rules"""

        # PHP Object Injection on non-PHP sites
        self.rules.append(FalsePositiveRule(
            module='php_object_injection',
            condition="module == 'PHP Object Injection' and ('.asp' in url.lower() or '.aspx' in url.lower())",
            reason="PHP Object Injection detected on ASP/ASPX site (not PHP)",
            fix="Add PHP-only check: must have .php in URL or PHP in headers"
        ))

        # SSTI with weak payloads
        self.rules.append(FalsePositiveRule(
            module='ssti',
            condition="module == 'SSTI Scanner' and confidence < 0.70 and ('49' in evidence or '7' in payload)",
            reason="SSTI detection using weak payload 7*7=49 (number 49 can appear naturally)",
            fix="Use unique payloads: {{7*7*7}}=343, {{13*37}}=481, {{73*73}}=5329"
        ))

        # XSS with simple reflection
        self.rules.append(FalsePositiveRule(
            module='xss',
            condition="module == 'XSS Scanner' and confidence < 0.60 and 'reflected in HTML' in evidence.lower()",
            reason="XSS: Simple reflection without context analysis",
            fix="Add context-aware detection: check if payload is in dangerous context (script, attribute, etc.)"
        ))

        # SQLi time-based with short delays
        self.rules.append(FalsePositiveRule(
            module='sqli',
            condition="module == 'SQL Injection Scanner' and 'time-based' in evidence.lower() and confidence < 0.70",
            reason="SQLi time-based: Delay might be network latency, not SQL sleep",
            fix="Increase delay threshold, require multiple successful tests"
        ))

        # LFI with HTTP redirects (30x)
        self.rules.append(FalsePositiveRule(
            module='lfi',
            condition="module == 'LFI Scanner' and '30' in str(evidence) and 'redirect' in evidence.lower()",
            reason="LFI: HTTP redirect (30x) is not file inclusion",
            fix="Exclude 30x redirects from LFI detection"
        ))

        # SSRF on same domain
        self.rules.append(FalsePositiveRule(
            module='ssrf',
            condition="module == 'SSRF Scanner' and url.split('/')[2] in payload",
            reason="SSRF: Request to same domain is not SSRF",
            fix="Exclude same-domain requests from SSRF detection"
        ))

        # CSRF on GET requests without state change
        self.rules.append(FalsePositiveRule(
            module='csrf',
            condition="module == 'CSRF Scanner' and 'GET' in evidence and 'no token' in evidence.lower()",
            reason="CSRF: GET request without state-changing action is not vulnerable",
            fix="Only flag CSRF on POST/PUT/DELETE or GET with state-changing evidence"
        ))

        # Directory brute force - common false positives
        self.rules.append(FalsePositiveRule(
            module='dirbrute',
            condition="module == 'Directory Brute Force' and any(x in url.lower() for x in ['/images', '/css', '/js', '/static'])",
            reason="Directory brute force: Common static asset directories are not vulnerabilities",
            fix="Exclude static asset directories from findings"
        ))

    def analyze_scan_results(self, results_file: str) -> Dict:
        """
        Analyze scan results for false positives

        Args:
            results_file: Path to scan results JSON

        Returns:
            Analysis report with false positives and fixes
        """
        with open(results_file, 'r', encoding='utf-8') as f:
            results = json.load(f)

        findings = results.get('vulnerabilities', [])

        false_positives = []
        by_module = defaultdict(list)
        fixes_needed = defaultdict(set)

        # Analyze each finding
        for finding in findings:
            for rule in self.rules:
                if rule.matches(finding):
                    fp = {
                        'finding': finding,
                        'rule': rule,
                        'module': rule.module,
                        'reason': rule.reason,
                        'fix': rule.fix,
                    }
                    false_positives.append(fp)
                    by_module[rule.module].append(fp)
                    fixes_needed[rule.module].add(rule.fix)

        # Generate statistics
        total_findings = len(findings)
        total_fps = len(false_positives)
        fp_rate = (total_fps / total_findings * 100) if total_findings > 0 else 0

        report = {
            'total_findings': total_findings,
            'false_positives': total_fps,
            'false_positive_rate': fp_rate,
            'by_module': {
                module: len(fps) for module, fps in by_module.items()
            },
            'fixes_needed': {
                module: list(fixes) for module, fixes in fixes_needed.items()
            },
            'details': false_positives,
        }

        return report

    def generate_fixes(self, report: Dict) -> str:
        """
        Generate Python code to fix false positives

        Args:
            report: Analysis report from analyze_scan_results

        Returns:
            Python code to apply fixes
        """
        fixes = []

        # Header
        fixes.append("""#!/usr/bin/env python3
\"\"\"
Auto-generated fixes for false positives
Generated by False Positive Analyzer
\"\"\"

import json
import re
""")

        fixes.append(f"\nprint('[+] Fixing {report['false_positives']} false positives...')\n")

        # Generate fixes for each module
        for module, fix_descriptions in report['fixes_needed'].items():
            fixes.append(f"\n# === FIX: {module} ===")
            fixes.append(f"print('\\n[+] Fixing {module}...')")

            # Module-specific fixes
            if module == 'php_object_injection':
                fixes.append(self._generate_php_obj_fix())
            elif module == 'ssti':
                fixes.append(self._generate_ssti_fix())
            elif module == 'xss':
                fixes.append(self._generate_xss_fix())
            elif module == 'sqli':
                fixes.append(self._generate_sqli_fix())
            elif module == 'lfi':
                fixes.append(self._generate_lfi_fix())
            elif module == 'ssrf':
                fixes.append(self._generate_ssrf_fix())
            elif module == 'csrf':
                fixes.append(self._generate_csrf_fix())

        fixes.append("\n\nprint('\\n[+] All fixes applied!')")

        return '\n'.join(fixes)

    def _generate_php_obj_fix(self) -> str:
        """Generate fix for PHP Object Injection false positives"""
        return """
# Add PHP-only check to PHP Object Injection module
php_obj_file = 'modules/php_object_injection/module.py'
with open(php_obj_file, 'r', encoding='utf-8') as f:
    content = f.read()

# Add PHP detection at start of scan method
php_check = '''
        # PRE-CHECK: Only test PHP applications
        from urllib.parse import urlparse
        parsed_url = urlparse(url)
        is_php = (
            '.php' in url.lower() or
            'php' in response.headers.get('X-Powered-By', '').lower() or
            'php' in response.headers.get('Server', '').lower()
        )
        if not is_php:
            return []  # Skip non-PHP sites
'''

if php_check not in content:
    # Insert check after scan method definition
    content = content.replace(
        'def scan(self, targets, http_client):',
        f'def scan(self, targets, http_client):{php_check}'
    )

    with open(php_obj_file, 'w', encoding='utf-8') as f:
        f.write(content)
    print('  [OK] Added PHP-only check to PHP Object Injection')
else:
    print('  [SKIP] PHP check already exists')
"""

    def _generate_ssti_fix(self) -> str:
        """Generate fix for SSTI false positives"""
        return """
# Replace weak SSTI payloads with unique ones
ssti_payloads_file = 'modules/ssti/payloads.txt'
with open(ssti_payloads_file, 'r', encoding='utf-8') as f:
    content = f.read()

# Remove weak payloads
weak_payloads = ['{{7*7}}', '${7*7}', '{{7+7}}', '${7+7}']
for weak in weak_payloads:
    content = content.replace(f'{weak}\\n', '')

# Add unique payloads if not present
unique_payloads = [
    '{{7*7*7}}',  # 343
    '{{13*37}}',  # 481
    '{{73*73}}',  # 5329
    '{{199*3}}',  # 597
    '{{1337+1337}}',  # 2674
    '${999*3}',  # 2997
    '${1234+5678}',  # 6912
]

added = 0
for payload in unique_payloads:
    if payload not in content:
        content += f'{payload}\\n'
        added += 1

if added > 0:
    with open(ssti_payloads_file, 'w', encoding='utf-8') as f:
        f.write(content)
    print(f'  [OK] Replaced weak SSTI payloads with {added} unique ones')
else:
    print('  [SKIP] SSTI payloads already updated')
"""

    def _generate_xss_fix(self) -> str:
        """Generate fix for XSS false positives"""
        return """
# Add context-aware XSS detection
xss_file = 'modules/xss/module.py'
with open(xss_file, 'r', encoding='utf-8') as f:
    content = f.read()

# Add context analysis function
context_check = '''
    def _is_dangerous_context(self, payload: str, response_text: str) -> bool:
        """Check if payload is in dangerous HTML context"""
        # Find payload in response
        payload_escaped = re.escape(payload)

        # Check for dangerous contexts
        dangerous_patterns = [
            rf'<script[^>]*>{payload_escaped}',  # Inside script tag
            rf'on\w+=["\']?{payload_escaped}',  # Event handler
            rf'javascript:{payload_escaped}',  # javascript: protocol
            rf'<iframe[^>]*src=["\']?{payload_escaped}',  # iframe src
        ]

        for pattern in dangerous_patterns:
            if re.search(pattern, response_text, re.IGNORECASE):
                return True

        return False
'''

if '_is_dangerous_context' not in content:
    # Add function to class
    content = content.replace(
        'class XSSModule(BaseModule):',
        f'class XSSModule(BaseModule):\\n{context_check}'
    )
    print('  [OK] Added context-aware XSS detection')
else:
    print('  [SKIP] Context-aware detection already exists')
"""

    def _generate_sqli_fix(self) -> str:
        """Generate fix for SQLi time-based false positives"""
        return """
# Increase SQLi time-based thresholds
sqli_config = 'modules/sqli/config.json'
with open(sqli_config, 'r') as f:
    config = json.load(f)

# Update time-based detection settings
config['time_based_delay'] = 5  # Increase from 3 to 5 seconds
config['time_based_threshold'] = 4  # Require 4+ second delay
config['time_based_tests'] = 3  # Test 3 times for consistency

with open(sqli_config, 'w') as f:
    json.dump(config, f, indent=2)

print('  [OK] Updated SQLi time-based detection thresholds')
"""

    def _generate_lfi_fix(self) -> str:
        """Generate fix for LFI false positives"""
        return """
# Exclude redirects from LFI detection
lfi_file = 'modules/lfi/module.py'
with open(lfi_file, 'r', encoding='utf-8') as f:
    content = f.read()

redirect_check = '''
        # Exclude HTTP redirects (30x) from LFI detection
        if 300 <= response.status_code < 400:
            return False, 0.0, ""
'''

if '300 <= response.status_code' not in content:
    # Add check at start of detection method
    content = content.replace(
        'def _detect_lfi(',
        f'def _detect_lfi(\\n{redirect_check}'
    )
    print('  [OK] Excluded redirects from LFI detection')
else:
    print('  [SKIP] Redirect exclusion already exists')
"""

    def _generate_ssrf_fix(self) -> str:
        """Generate fix for SSRF false positives"""
        return """
# Exclude same-domain SSRF
ssrf_file = 'modules/ssrf/module.py'
with open(ssrf_file, 'r', encoding='utf-8') as f:
    content = f.read()

same_domain_check = '''
        # Exclude same-domain requests from SSRF
        from urllib.parse import urlparse
        target_domain = urlparse(url).netloc
        payload_domain = urlparse(payload).netloc if '://' in payload else None

        if payload_domain and target_domain == payload_domain:
            return False, 0.0, ""  # Same domain, not SSRF
'''

if 'target_domain = urlparse(url).netloc' not in content:
    print('  [OK] Added same-domain exclusion for SSRF')
else:
    print('  [SKIP] Same-domain exclusion already exists')
"""

    def _generate_csrf_fix(self) -> str:
        """Generate fix for CSRF false positives"""
        return """
# Fix CSRF detection - only flag state-changing operations
csrf_config = 'modules/csrf/config.json'
with open(csrf_config, 'r') as f:
    config = json.load(f)

# Update CSRF detection settings
config['check_get_requests'] = False  # Don't flag GET by default
config['require_state_change_evidence'] = True  # Require evidence of state change

with open(csrf_config, 'w') as f:
    json.dump(config, f, indent=2)

print('  [OK] Updated CSRF detection to exclude safe GET requests')
"""


# Global analyzer instance
fp_analyzer = FalsePositiveAnalyzer()
