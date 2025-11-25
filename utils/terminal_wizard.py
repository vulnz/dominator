#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Terminal Wizard for Dominator Scanner

Interactive CLI wizard for guided scan configuration.
Similar to the GUI wizard but for terminal users.
"""

import sys
import os
from pathlib import Path


class TerminalWizard:
    """Interactive terminal wizard for scan configuration"""

    def __init__(self):
        self.config = {
            'targets': [],
            'modules': [],
            'threads': 10,
            'timeout': 20,
            'waf_mode': False,
            'crawl': True,
            'max_crawl_pages': 50,
            'auth_type': None,
            'cookies': None,
            'headers': [],
            'proxy': None,
            'output_format': 'html',
            'auto_report': True,
            'verbose': False,
            'fast_mode': False,
            'payload_limit': 0,
            # API Testing
            'api_mode': False,
            'api_spec': None,
            'api_auth_token': None,
        }

        # Available modules by category
        self.module_categories = {
            'Injection': ['sqli', 'xss', 'cmdi', 'ssti', 'xxe', 'xpath', 'lfi', 'rfi'],
            'Security': ['csrf', 'idor', 'redirect', 'security_headers', 'ssl_tls'],
            'Discovery': ['dirbrute', 'git', 'env_secrets', 'backup_files', 'http_methods'],
            'Advanced': ['ssrf', 'dom_xss', 'header_injection', 'graphql', 'host_header'],
            'Reconnaissance': ['subdomain', 'port_scan', 'js_analysis']
        }

    def clear_screen(self):
        """Clear terminal screen"""
        os.system('cls' if os.name == 'nt' else 'clear')

    def print_banner(self):
        """Print wizard banner"""
        print("\n" + "=" * 60)
        print("       DOMINATOR SCANNER - TERMINAL WIZARD")
        print("=" * 60)
        print("  Interactive scan configuration guide")
        print("  Press Ctrl+C at any time to cancel")
        print("=" * 60 + "\n")

    def print_step(self, step_num: int, total: int, title: str):
        """Print step header"""
        print(f"\n[Step {step_num}/{total}] {title}")
        print("-" * 50)

    def get_input(self, prompt: str, default: str = None, required: bool = True) -> str:
        """Get user input with default value support"""
        if default:
            prompt = f"{prompt} [{default}]: "
        else:
            prompt = f"{prompt}: "

        try:
            value = input(prompt).strip()
            if not value and default:
                return default
            if not value and required:
                print("  This field is required.")
                return self.get_input(prompt.replace(f" [{default}]", "").replace(": ", ""),
                                      default, required)
            return value
        except KeyboardInterrupt:
            print("\n\nWizard cancelled.")
            sys.exit(0)

    def get_yes_no(self, prompt: str, default: bool = True) -> bool:
        """Get yes/no response"""
        default_str = "Y/n" if default else "y/N"
        try:
            response = input(f"{prompt} [{default_str}]: ").strip().lower()
            if not response:
                return default
            return response in ['y', 'yes', '1', 'true']
        except KeyboardInterrupt:
            print("\n\nWizard cancelled.")
            sys.exit(0)

    def get_choice(self, prompt: str, choices: list, allow_multiple: bool = False) -> list:
        """Get choice from list"""
        print(f"\n{prompt}")
        for i, choice in enumerate(choices, 1):
            print(f"  {i}. {choice}")

        if allow_multiple:
            print("\n  Enter numbers separated by commas (e.g., 1,3,5)")
            print("  Enter 'all' for all options")

        try:
            response = input("\nYour choice: ").strip().lower()

            if allow_multiple and response == 'all':
                return choices

            if ',' in response or allow_multiple:
                indices = [int(x.strip()) - 1 for x in response.split(',') if x.strip().isdigit()]
                return [choices[i] for i in indices if 0 <= i < len(choices)]
            else:
                idx = int(response) - 1
                if 0 <= idx < len(choices):
                    return [choices[idx]]
                print("  Invalid choice.")
                return self.get_choice(prompt, choices, allow_multiple)

        except (ValueError, IndexError):
            print("  Invalid input. Please enter a number.")
            return self.get_choice(prompt, choices, allow_multiple)
        except KeyboardInterrupt:
            print("\n\nWizard cancelled.")
            sys.exit(0)

    def run(self) -> dict:
        """Run the wizard and return configuration"""
        self.clear_screen()
        self.print_banner()

        total_steps = 7

        # Step 1: Target
        self.print_step(1, total_steps, "TARGET CONFIGURATION")
        print("Enter target URL(s) or domain(s) to scan.")
        print("Examples: https://example.com, 192.168.1.1, example.com:8080")
        print("For multiple targets, separate with commas or spaces.\n")

        targets_input = self.get_input("Target(s)")
        self.config['targets'] = [t.strip() for t in targets_input.replace(',', ' ').split() if t.strip()]

        print(f"\n  Added {len(self.config['targets'])} target(s)")

        # Step 2: Scan Type
        self.print_step(2, total_steps, "SCAN TYPE")
        scan_types = [
            "Quick Scan - Fast common vulnerabilities check",
            "Standard Scan - Balanced coverage and speed",
            "Full Scan - Comprehensive all-modules scan",
            "API Testing - Scan REST API from OpenAPI/Swagger/Postman spec",
            "Recon Only - Passive reconnaissance (no attacks)",
            "Custom - Choose specific modules"
        ]
        choice = self.get_choice("Select scan type:", scan_types)[0]

        if "Quick" in choice:
            self.config['modules'] = ['xss', 'sqli', 'security_headers']
            self.config['fast_mode'] = True
            self.config['payload_limit'] = 5
        elif "Standard" in choice:
            self.config['modules'] = ['xss', 'sqli', 'csrf', 'lfi', 'ssrf', 'security_headers', 'dirbrute']
        elif "Full" in choice:
            self.config['modules'] = ['all']
        elif "API Testing" in choice:
            self._configure_api_testing()
        elif "Recon" in choice:
            self.config['modules'] = ['subdomain', 'port_scan', 'js_analysis', 'security_headers']
            self.config['crawl'] = False
        else:
            # Custom selection
            self._select_modules()

        print(f"\n  Selected modules: {', '.join(self.config['modules'])}")

        # Step 3: Performance Settings
        self.print_step(3, total_steps, "PERFORMANCE SETTINGS")

        if not self.config['fast_mode']:
            self.config['fast_mode'] = self.get_yes_no("Enable fast mode (quicker but less thorough)?", False)

        self.config['threads'] = int(self.get_input("Number of threads", "10"))
        self.config['timeout'] = int(self.get_input("Request timeout (seconds)", "20"))

        if self.get_yes_no("Limit payload count per module?", False):
            self.config['payload_limit'] = int(self.get_input("Max payloads per module", "10"))

        # Step 4: Crawling Options (skip for API mode - uses explicit endpoints)
        if not self.config.get('api_mode'):
            self.print_step(4, total_steps, "CRAWLING OPTIONS")
            self.config['crawl'] = self.get_yes_no("Enable crawling (discover more pages)?", True)

            if self.config['crawl']:
                self.config['max_crawl_pages'] = int(self.get_input("Max pages to crawl", "50"))

        # Step 5: Authentication & Headers (skip if already configured in API mode)
        if not self.config.get('api_mode'):
            self.print_step(5, total_steps, "AUTHENTICATION (optional)")

            if self.get_yes_no("Configure authentication?", False):
                auth_types = ["None", "Cookies", "JWT Token", "Basic Auth"]
                auth_choice = self.get_choice("Authentication type:", auth_types)[0]

                if "Cookies" in auth_choice:
                    self.config['cookies'] = self.get_input("Cookie string (name=value; name2=value2)")
                elif "JWT" in auth_choice:
                    self.config['auth_type'] = 'jwt'
                    jwt_token = self.get_input("JWT Token")
                    self.config['headers'].append(f"Authorization: Bearer {jwt_token}")
                elif "Basic" in auth_choice:
                    self.config['auth_type'] = 'basic'

            if self.get_yes_no("Add custom headers?", False):
                print("  Enter headers one per line. Empty line to finish.")
                while True:
                    header = input("  Header: ").strip()
                    if not header:
                        break
                    self.config['headers'].append(header)

        # Step 6: WAF Detection (skip for API mode)
        if not self.config.get('api_mode'):
            self.print_step(6, total_steps, "WAF DETECTION")
            print("WAF (Web Application Firewall) detection can help identify")
            print("security mechanisms and recommend appropriate bypass techniques.\n")

            waf_options = [
                "No WAF detection",
                "Detect WAF only (no bypass)",
                "Detect WAF and use bypass payloads if found"
            ]
            waf_choice = self.get_choice("WAF handling:", waf_options)[0]

            if "use bypass" in waf_choice.lower():
                self.config['waf_mode'] = True
                self.config['wafiffound'] = True
            elif "Detect WAF only" in waf_choice:
                self.config['waf_detect'] = True

        # Step 7: Output Settings
        self.print_step(7, total_steps, "OUTPUT SETTINGS")

        formats = ["HTML", "TXT", "JSON", "HTML + TXT", "All formats"]
        format_choice = self.get_choice("Report format:", formats)[0]

        if "HTML + TXT" in format_choice:
            self.config['output_format'] = 'html,txt'
        elif "All" in format_choice:
            self.config['output_format'] = 'html,txt,json'
        else:
            self.config['output_format'] = format_choice.lower()

        self.config['verbose'] = self.get_yes_no("Enable verbose output?", False)

        # Summary
        self._show_summary()

        if self.get_yes_no("\nProceed with scan?", True):
            return self.config
        else:
            print("\nScan cancelled.")
            sys.exit(0)

    def _select_modules(self):
        """Interactive module selection"""
        print("\nSelect modules by category:\n")
        selected = []

        for category, modules in self.module_categories.items():
            print(f"\n[{category}]")
            if self.get_yes_no(f"  Include {category} modules?", True):
                selected.extend(modules)

        if not selected:
            selected = ['xss', 'sqli']  # Default minimum

        self.config['modules'] = selected

    def _configure_api_testing(self):
        """Configure API testing mode"""
        self.config['api_mode'] = True
        self.config['crawl'] = False  # No crawling for API testing

        print("\n[API TESTING MODE]")
        print("Scan REST APIs from OpenAPI/Swagger, Postman, HAR, or other specs.\n")

        # API Spec source
        source_types = [
            "File - Load from local file (swagger.json, openapi.yaml, etc.)",
            "URL - Fetch from remote URL",
            "Auto-Discover - Find API spec from target URL"
        ]
        source_choice = self.get_choice("How to load API specification?", source_types)[0]

        if "File" in source_choice:
            while True:
                spec_path = self.get_input("Path to API spec file")
                if spec_path.strip():
                    self.config['api_spec'] = spec_path.strip()
                    break
                print("  [!] Path cannot be empty. Please enter a valid file path.")
        elif "URL" in source_choice:
            while True:
                spec_url = self.get_input("API specification URL")
                if spec_url.strip():
                    self.config['api_spec'] = spec_url.strip()
                    break
                print("  [!] URL cannot be empty. Please enter a valid URL.")
        else:
            # Auto-discover mode - will try common endpoints
            target = self.config['targets'][0] if self.config['targets'] else ""
            if not target:
                while True:
                    target = self.get_input("Target URL for API discovery")
                    if target.strip():
                        target = target.strip()
                        break
                    print("  [!] URL cannot be empty. Please enter a valid target URL.")
                self.config['targets'] = [target]
            self.config['api_discover'] = True

        # Module selection for API
        print("\nSelect API testing modules:")
        api_module_options = [
            "API Security - Full OWASP API Top 10 testing",
            "Injection Only - SQLi, XSS, Command Injection on API",
            "Auth Testing - JWT, BOLA/IDOR, access control",
            "All Modules - Web + API security tests"
        ]
        module_choice = self.get_choice("Module selection:", api_module_options)[0]

        if "API Security" in module_choice:
            self.config['modules'] = ['api_bola', 'api_mass_assignment', 'api_rate_limit',
                                      'api_excessive_data', 'jwt_analysis', 'graphql', 'cors', 'idor']
            self.config['api_modules_only'] = True
        elif "Injection" in module_choice:
            self.config['modules'] = ['sqli', 'xss', 'cmdi', 'ssti']
        elif "Auth" in module_choice:
            self.config['modules'] = ['jwt_analysis', 'idor', 'api_bola', 'cors']
        else:
            # All Modules - use --api-full for API mode
            self.config['modules'] = ['all']
            self.config['api_full'] = True

        # Authentication (using existing headers config)
        if self.get_yes_no("\nDoes the API require authentication?", False):
            auth_types = ["Bearer Token", "API Key", "Basic Auth", "Custom Header"]
            auth_choice = self.get_choice("Authentication type:", auth_types)[0]

            if "Bearer" in auth_choice:
                token = self.get_input("Bearer token (without 'Bearer ' prefix)")
                self.config['api_auth_token'] = token
            elif "API Key" in auth_choice:
                header_name = self.get_input("Header name", "X-API-Key")
                key_value = self.get_input("API key value")
                self.config['headers'].append(f"{header_name}: {key_value}")
            elif "Basic" in auth_choice:
                self.config['auth_type'] = 'basic'
            else:
                header = self.get_input("Custom header (format: Name: Value)")
                self.config['headers'].append(header)

        print(f"\n  API mode configured with {len(self.config['modules'])} modules")

    def _show_summary(self):
        """Show configuration summary"""
        print("\n" + "=" * 60)
        print("                   SCAN CONFIGURATION SUMMARY")
        print("=" * 60)

        # API Mode
        if self.config.get('api_mode'):
            print(f"\n  Mode:         API TESTING")
            if self.config.get('api_spec'):
                spec = self.config['api_spec']
                if len(spec) > 40:
                    spec = f"...{spec[-37:]}"
                print(f"  API Spec:     {spec}")
            if self.config.get('api_discover'):
                print(f"  Discovery:    Auto-discover from target")
            if self.config.get('api_auth_token'):
                print(f"  Auth:         Bearer Token (set)")
        else:
            print(f"\n  Targets:      {', '.join(self.config['targets'][:3])}")
            if len(self.config['targets']) > 3:
                print(f"                ... and {len(self.config['targets']) - 3} more")

        modules_str = ', '.join(self.config['modules'][:5])
        if len(self.config['modules']) > 5:
            modules_str += f" ... +{len(self.config['modules']) - 5} more"
        print(f"  Modules:      {modules_str}")

        print(f"  Threads:      {self.config['threads']}")
        print(f"  Timeout:      {self.config['timeout']}s")
        print(f"  Fast Mode:    {'Yes' if self.config['fast_mode'] else 'No'}")

        if not self.config.get('api_mode'):
            print(f"  Crawling:     {'Yes (max {})'.format(self.config['max_crawl_pages']) if self.config['crawl'] else 'No'}")
            print(f"  WAF Mode:     {'Yes' if self.config['waf_mode'] else 'No'}")

        print(f"  Output:       {self.config['output_format'].upper()}")

        if self.config['cookies']:
            print(f"  Cookies:      Set")
        if self.config['headers']:
            print(f"  Headers:      {len(self.config['headers'])} custom")

        print("\n" + "=" * 60)

    def build_command_args(self) -> list:
        """Build command line arguments from config"""
        args = []

        # API Testing mode
        if self.config.get('api_mode'):
            if self.config.get('api_spec'):
                args.extend(['--api', self.config['api_spec']])
            if self.config.get('api_discover'):
                args.append('--api-discover')
                # Auto-discover needs targets to find API spec from
                for target in self.config['targets']:
                    args.extend(['-t', target])
            if self.config.get('api_auth_token'):
                args.extend(['--api-auth-token', self.config['api_auth_token']])
            if self.config.get('api_modules_only'):
                args.append('-apim')
            if self.config.get('api_full'):
                args.append('--api-full')
        else:
            # Targets (only for non-API mode)
            for target in self.config['targets']:
                args.extend(['-t', target])

        # Modules (if not using -apim or --api-full)
        if not self.config.get('api_modules_only') and not self.config.get('api_full'):
            if self.config['modules'] and self.config['modules'] != ['all']:
                args.extend(['-m', ','.join(self.config['modules'])])
            elif self.config['modules'] == ['all']:
                args.append('--all')

        # Performance
        args.extend(['--threads', str(self.config['threads'])])
        args.extend(['--timeout', str(self.config['timeout'])])

        if self.config['fast_mode']:
            args.append('--fast')

        if self.config['payload_limit'] > 0:
            args.extend(['--payload-limit', str(self.config['payload_limit'])])

        # Crawling (skip for API mode)
        if not self.config.get('api_mode'):
            if not self.config['crawl']:
                args.append('--single-page')
            else:
                args.extend(['--max-crawl-pages', str(self.config['max_crawl_pages'])])

        # Authentication (shared between web and API)
        if self.config['cookies']:
            args.extend(['-c', self.config['cookies']])

        for header in self.config['headers']:
            args.extend(['-H', header])

        if self.config['auth_type']:
            args.extend(['-a', self.config['auth_type']])

        # WAF
        if self.config.get('waf_mode'):
            args.append('--waf')
        if self.config.get('wafiffound'):
            args.append('--wafiffound')
        if self.config.get('waf_detect'):
            args.append('--waf-detect')

        # Output
        args.extend(['--format', self.config['output_format']])
        args.append('--auto-report')

        if self.config['verbose']:
            args.append('--verbose')

        return args


def run_wizard():
    """Entry point for terminal wizard"""
    wizard = TerminalWizard()
    config = wizard.run()
    args = wizard.build_command_args()

    # Show generated command for debugging
    print("\n" + "=" * 60)
    print("Generated command:")
    print(f"  python main.py {' '.join(args)}")
    print("=" * 60 + "\n")

    return args


if __name__ == "__main__":
    run_wizard()
