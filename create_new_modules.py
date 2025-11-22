#!/usr/bin/env python3
"""
Script to create all new security modules from Gsec analysis
This creates 7 new modules with proper structure
"""

import os
import json
from pathlib import Path

# Module definitions
MODULES = {
    "host_header": {
        "name": "Host Header Injection",
        "description": "Detects Host header injection vulnerabilities including password reset poisoning, cache poisoning, and SSRF",
        "severity": "High",
        "cwe": "CWE-444",
        "cvss": 7.5
    },
    "http_smuggling": {
        "name": "HTTP Request Smuggling",
        "description": "Detects HTTP request smuggling vulnerabilities (CL.TE, TE.CL, TE.TE desync attacks)",
        "severity": "Critical",
        "cwe": "CWE-444",
        "cvss": 9.1
    },
    "graphql": {
        "name": "GraphQL Security",
        "description": "Tests GraphQL endpoints for introspection, DoS, batch query abuse, and injection vulnerabilities",
        "severity": "High",
        "cwe": "CWE-89",
        "cvss": 7.5
    },
    "api_security": {
        "name": "API Security",
        "description": "Advanced API security testing including BOLA/IDOR, HTTP verb tampering, mass assignment, and authentication bypass",
        "severity": "High",
        "cwe": "CWE-639",
        "cvss": 8.2
    },
    "cloud_storage": {
        "name": "Cloud Storage Enumeration",
        "description": "Discovers exposed cloud storage buckets (AWS S3, Azure, GCP, Firebase) and checks public/private access",
        "severity": "High",
        "cwe": "CWE-200",
        "cvss": 7.5
    },
    "session": {
        "name": "Session Management",
        "description": "Tests for session fixation, hijacking, timeout issues, and concurrent session vulnerabilities",
        "severity": "High",
        "cwe": "CWE-384",
        "cvss": 7.5
    },
    "ssl_tls": {
        "name": "SSL/TLS Security",
        "description": "Analyzes SSL/TLS configuration including weak ciphers, protocols, and certificate validation",
        "severity": "Medium",
        "cwe": "CWE-327",
        "cvss": 5.9
    }
}

def create_module_structure(module_dir, module_info):
    """Create module directory structure with all necessary files"""

    # Create directory
    Path(module_dir).mkdir(parents=True, exist_ok=True)

    # Create config.json
    config = {
        "name": module_info["name"],
        "description": module_info["description"],
        "enabled": True,
        "severity": module_info["severity"],
        "cwe": module_info["cwe"],
        "cvss": module_info["cvss"]
    }

    with open(f"{module_dir}/config.json", "w") as f:
        json.dump(config, f, indent=2)

    # Create __init__.py
    init_content = f'''"""
{module_info["name"]} Scanner Module
"""

from .scanner import {module_info["name"].replace(" ", "")}Scanner

__all__ = ['{module_info["name"].replace(" ", "")}Scanner']
'''

    with open(f"{module_dir}/__init__.py", "w") as f:
        f.write(init_content)

    print(f"✅ Created module structure for: {module_info['name']}")

# Create all modules
modules_dir = Path("modules")

for module_key, module_info in MODULES.items():
    module_path = modules_dir / module_key
    create_module_structure(module_path, module_info)

print("\n✅ All module structures created successfully!")
print("\nNext steps:")
print("1. Implement scanner.py for each module")
print("2. Add payloads.txt where needed")
print("3. Update GUI to include new modules")
