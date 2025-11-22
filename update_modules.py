#!/usr/bin/env python3
"""
Script to update all modules to support payload_limit parameter
Updates both get_module() functions and __init__ methods
"""

import os
import re

# List of all module directories
MODULES = [
    'redirect', 'xpath', 'file_upload', 'git', 'weak_credentials',
    'dirbrute', 'formula_injection', 'rfi', 'env_secrets', 'dom_xss',
    'idor', 'csrf', 'xxe', 'xss', 'ssti', 'php_object_injection',
    'cmdi', 'lfi', 'ssrf', 'sqli'
]

def update_get_module(file_path):
    """Update get_module function signature and call"""
    with open(file_path, 'r', encoding='utf-8') as f:
        content = f.read()

    # Pattern 1: Update get_module signature
    old_signature = r'def get_module\(module_path: str\):'
    new_signature = r'def get_module(module_path: str, payload_limit: int = None):'
    content = re.sub(old_signature, new_signature, content)

    # Pattern 2: Update module instantiation in get_module
    # Find the class name from the file
    class_match = re.search(r'class (\w+)\(BaseModule\):', content)
    if class_match:
        class_name = class_match.group(1)

        # Update instantiation to pass payload_limit
        old_instantiation = f'return {class_name}(module_path)'
        new_instantiation = f'return {class_name}(module_path, payload_limit=payload_limit)'
        content = content.replace(old_instantiation, new_instantiation)

    with open(file_path, 'w', encoding='utf-8') as f:
        f.write(content)

def update_init_method(file_path):
    """Update __init__ method to accept and pass payload_limit"""
    with open(file_path, 'r', encoding='utf-8') as f:
        content = f.read()

    # Pattern: Update __init__ signature
    old_init = r'def __init__\(self, module_path: str\):'
    new_init = r'def __init__(self, module_path: str, payload_limit: int = None):'
    content = re.sub(old_init, new_init, content)

    # Pattern: Update super().__init__ call
    old_super = r'super\(\).__init__\(module_path\)'
    new_super = r'super().__init__(module_path, payload_limit=payload_limit)'
    content = re.sub(old_super, new_super, content)

    with open(file_path, 'w', encoding='utf-8') as f:
        f.write(content)

def main():
    """Update all modules"""
    modules_dir = 'modules'

    for module_name in MODULES:
        module_file = os.path.join(modules_dir, module_name, 'module.py')

        if os.path.exists(module_file):
            print(f"Updating {module_name}...")
            update_get_module(module_file)
            update_init_method(module_file)
            print(f"[OK] Updated {module_name}")
        else:
            print(f"[SKIP] Module file not found: {module_file}")

    print("\n[DONE] All modules updated!")

if __name__ == '__main__':
    main()
