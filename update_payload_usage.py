#!/usr/bin/env python3
"""
Script to update all modules to use get_limited_payloads() instead of self.payloads[:N]
"""

import os
import re

MODULES = [
    'redirect', 'xpath', 'file_upload', 'git', 'weak_credentials',
    'dirbrute', 'formula_injection', 'rfi', 'env_secrets', 'dom_xss',
    'idor', 'csrf', 'xxe', 'xss', 'ssti', 'php_object_injection',
    'cmdi', 'lfi', 'ssrf', 'sqli'
]

def update_payload_usage(file_path):
    """Replace self.payloads[:N] with self.get_limited_payloads()"""
    with open(file_path, 'r', encoding='utf-8') as f:
        content = f.read()

    original_content = content

    # Pattern 1: Replace self.payloads[:N] with self.get_limited_payloads()
    # This matches patterns like self.payloads[:50], self.payloads[:payload_limit], etc.
    pattern1 = r'self\.payloads\[:\d+\]'
    content = re.sub(pattern1, 'self.get_limited_payloads()', content)

    # Pattern 2: Also handle self.payloads[:payload_limit]
    pattern2 = r'self\.payloads\[:payload_limit\]'
    content = re.sub(pattern2, 'self.get_limited_payloads()', content)

    # Only write if changed
    if content != original_content:
        with open(file_path, 'w', encoding='utf-8') as f:
            f.write(content)
        return True
    return False

def main():
    """Update all modules"""
    modules_dir = 'modules'
    updated_count = 0

    for module_name in MODULES:
        module_file = os.path.join(modules_dir, module_name, 'module.py')

        if os.path.exists(module_file):
            print(f"Checking {module_name}...")
            if update_payload_usage(module_file):
                print(f"[OK] Updated {module_name}")
                updated_count += 1
            else:
                print(f"[SKIP] No changes needed for {module_name}")
        else:
            print(f"[SKIP] Module file not found: {module_file}")

    print(f"\n[DONE] Updated {updated_count} modules!")

if __name__ == '__main__':
    main()
