#!/usr/bin/env python3
"""
Quick fixes for critical issues found in Rotation 1
"""

import json
import os

print("[+] Applying critical fixes...")

# FIX 1: Remove payload limits from config files
configs_to_fix = [
    'modules/sqli/config.json',
    'modules/lfi/config.json',
    'modules/cmdi/config.json',
]

for config_file in configs_to_fix:
    if os.path.exists(config_file):
        with open(config_file, 'r') as f:
            config = json.load(f)

        # Remove max_payloads limit
        if 'max_payloads' in config:
            old_val = config['max_payloads']
            config['max_payloads'] = 200  # Increase limit significantly

            with open(config_file, 'w') as f:
                json.dump(config, f, indent=2)

            print(f"[+] {config_file}: max_payloads {old_val} -> 200")

# FIX 2: Update weak_credentials config for more attempts
weak_creds_config = 'modules/weak_credentials/config.json'
if os.path.exists(weak_creds_config):
    with open(weak_creds_config, 'r') as f:
        config = json.load(f)

    config['max_attempts'] = 200  # Double the attempts
    config['test_direct_urls'] = True  # Add flag for direct URL testing

    with open(weak_creds_config, 'w') as f:
        json.dump(config, f, indent=2)

    print(f"[+] weak_credentials: max_attempts -> 200, added direct URL testing")

# FIX 3: Update file_upload config
file_upload_config = 'modules/file_upload/config.json'
if os.path.exists(file_upload_config):
    with open(file_upload_config, 'r') as f:
        config = json.load(f)

    config['max_uploads'] = 50  # More upload attempts
    config['test_all_forms'] = True  # Test all file forms

    with open(file_upload_config, 'w') as f:
        json.dump(config, f, indent=2)

    print(f"[+] file_upload: max_uploads -> 50, test all forms enabled")

# FIX 4: Lower confidence thresholds to catch more
threshold_configs = [
    ('modules/sqli/config.json', 0.4),
    ('modules/lfi/config.json', 0.4),
    ('modules/cmdi/config.json', 0.4),
    ('modules/xss/config.json', 0.4),
]

for config_file, new_threshold in threshold_configs:
    if os.path.exists(config_file):
        with open(config_file, 'r') as f:
            config = json.load(f)

        if 'confidence_threshold' in config:
            old_val = config['confidence_threshold']
            config['confidence_threshold'] = new_threshold

            with open(config_file, 'w') as f:
                json.dump(config, f, indent=2)

            print(f"[+] {config_file}: confidence_threshold {old_val} -> {new_threshold}")

print("\n[+] All fixes applied!")
print("\n[+] Applied:")
print("  - Increased payload limits (SQLi, LFI, CMDi)")
print("  - Weak_credentials: more attempts + direct URL testing")
print("  - File_upload: more attempts + test all forms")
print("  - Lowered confidence thresholds for better detection")
print("\n[+] Ready for ROTATION 2")
