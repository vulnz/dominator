#!/usr/bin/env python3
"""
Fix false positives in PHP Object Injection and add curl/request/response to reports
"""

import re

print("[+] Fixing PHP Object Injection false positives...")

# FIX 1: PHP Object Injection - raise threshold and add URL check
php_obj_file = 'modules/php_object_injection/module.py'

with open(php_obj_file, 'r', encoding='utf-8') as f:
    content = f.read()

# Find METHOD 3 and update it
old_code = """        # METHOD 3: Behavior-based detection
        # Check for significant response changes with valid vs invalid serialization

        # If payload is valid serialization format
        if self._is_valid_serialization(payload):
            # Check for behavior change
            length_diff = abs(response_length - baseline_length)

            # If response is very different, might indicate deserialization
            if length_diff > 100:"""

new_code = """        # METHOD 3: Behavior-based detection
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
            if length_diff > 2000 and url_has_indicator:"""

if old_code in content:
    content = content.replace(old_code, new_code)
    print("[+] PHP Object Injection: Raised threshold 100 -> 2000, added URL check")
else:
    print("[!] Could not find METHOD 3 code to replace (might be already fixed)")

# Also update confidence threshold
content = re.sub(
    r'confidence = 0\.55',
    'confidence = 0.65  # Raised from 0.55 to reduce false positives',
    content
)

with open(php_obj_file, 'w', encoding='utf-8') as f:
    f.write(content)

print("[+] PHP Object Injection false positives fixed")

# FIX 2: Raise confidence threshold in config
import json

php_config_file = 'modules/php_object_injection/config.json'
with open(php_config_file, 'r') as f:
    config = json.load(f)

old_threshold = config.get('confidence_threshold', 0.55)
config['confidence_threshold'] = 0.70  # Raise to reduce false positives

with open(php_config_file, 'w') as f:
    json.dump(config, f, indent=2)

print(f"[+] PHP Object Injection config: confidence_threshold {old_threshold} -> 0.70")

print("\n[+] All false positive fixes applied!")
print("\n[!] Note: Curl/Request/Response in reports requires report_generator.py changes")
print("    This will be implemented in next update")
