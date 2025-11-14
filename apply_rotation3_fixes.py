#!/usr/bin/env python3
"""
Apply ROTATION 3 critical fixes automatically
"""

print("[+] Applying ROTATION 3 fixes...")
print("="*80)

# FIX 1: PHP Object Injection - Disable METHOD 3
print("\n[1] Fixing PHP Object Injection...")

php_obj_file = 'modules/php_object_injection/module.py'

with open(php_obj_file, 'r', encoding='utf-8') as f:
    content = f.read()

# Check if already fixed
if 'url: str =' in content and 'METHOD 3: DISABLED' in content:
    print("  [SKIP] PHP Object Injection already fixed")
else:
    # Add url parameter to function signature
    content = content.replace(
        'def _detect_php_object_injection(self, payload: str, response: Any,\n'
        '                                baseline_text: str, baseline_length: int) -> tuple:',
        'def _detect_php_object_injection(self, payload: str, response: Any,\n'
        '                                baseline_text: str, baseline_length: int,\n'
        '                                url: str = \'\') -> tuple:'
    )

    # Disable METHOD 3 by commenting it out
    old_method3 = '''        # METHOD 3: Behavior-based detection
        # Check for significant response changes with valid vs invalid serialization

        # If payload is valid serialization format
        if self._is_valid_serialization(payload):
            # Check for behavior change
            length_diff = abs(response_length - baseline_length)

            # FIXED: Raised threshold from 100 to 2000 to reduce false positives
            # Only detect if significant change AND URL suggests object handling
            url_indicators = ['object', 'unserialize', 'deserialize', 'serialize', 'php_object']
            url_lower = str(url if 'url' in locals() else '').lower()
            url_has_indicator = any(ind in url_lower for ind in url_indicators)

            # Higher threshold + URL check to reduce false positives
            if length_diff > 2000 and url_has_indicator:
                # Check if it's not just reflection
                if payload not in response_text:
                    confidence = 0.60

                    # Check for PHP object patterns
                    if re.search(r'object\\([^\\)]+\\)', response_text, re.IGNORECASE):
                        confidence = 0.75

                    evidence = f"Application behavior changed significantly with serialized input. "
                    evidence += f"Response length diff: {length_diff} bytes. "
                    evidence += "May indicate deserialization processing."

                    return True, confidence, evidence'''

    new_method3 = '''        # METHOD 3: DISABLED - Too many false positives
        # Behavior-based detection is unreliable for PHP Object Injection
        # Relying only on error-based (METHOD 1) and indicator-based (METHOD 2) detection'''

    content = content.replace(old_method3, new_method3)

    # Update function call to pass url
    content = content.replace(
        'detected, confidence, evidence = self._detect_php_object_injection(\n'
        '                        payload, response, baseline_text, baseline_length\n'
        '                    )',
        'detected, confidence, evidence = self._detect_php_object_injection(\n'
        '                        payload, response, baseline_text, baseline_length,\n'
        '                        url=url\n'
        '                    )'
    )

    # Increase confidence thresholds
    content = content.replace('confidence = 0.80', 'confidence = 0.90')
    content = content.replace('confidence = 0.70', 'confidence = 0.85')

    with open(php_obj_file, 'w', encoding='utf-8') as f:
        f.write(content)

    print("  [OK] PHP Object Injection fixed:")
    print("    - Added url parameter")
    print("    - Disabled METHOD 3 (behavior-based)")
    print("    - Increased confidence thresholds (0.80->0.90, 0.70->0.85)")

# FIX 2: SSTI - Add stronger payloads
print("\n[2] Upgrading SSTI payloads...")

ssti_payloads_file = 'modules/ssti/payloads.txt'

with open(ssti_payloads_file, 'r', encoding='utf-8') as f:
    existing_payloads = f.read()

# Add unique payloads if not present
new_payloads = [
    '{{7*7*7}}',
    '{{199*3}}',
    '{{1337+1337}}',
    '{{13*37}}',
    '{{73*73}}',
    '${999*3}',
    '${1234+5678}',
    '{{999+1}}',
]

added = 0
for payload in new_payloads:
    if payload not in existing_payloads:
        existing_payloads += f"\n{payload}"
        added += 1

if added > 0:
    with open(ssti_payloads_file, 'w', encoding='utf-8') as f:
        f.write(existing_payloads)
    print(f"  [OK] Added {added} unique SSTI payloads")
else:
    print("  [SKIP] SSTI payloads already upgraded")

# FIX 3: Update confidence threshold in config
print("\n[3] Updating PHP Object Injection config...")

import json

php_obj_config_file = 'modules/php_object_injection/config.json'

with open(php_obj_config_file, 'r') as f:
    config = json.load(f)

if config.get('confidence_threshold', 0) < 0.85:
    config['confidence_threshold'] = 0.85
    with open(php_obj_config_file, 'w') as f:
        json.dump(config, f, indent=2)
    print("  [OK] Updated confidence_threshold to 0.85")
else:
    print("  [SKIP] Confidence threshold already >= 0.85")

print("\n" + "="*80)
print("[+] ROTATION 3 fixes applied successfully!")
print("\nChanges:")
print("  1. PHP Object Injection: METHOD 3 disabled, confidence increased")
print("  2. SSTI: Added unique mathematical payloads")
print("  3. Config: Updated confidence thresholds")
print("\nReady for ROTATION 3 testing!")
