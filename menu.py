#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Menu and argument parsing for Web Vulnerability Scanner
"""

import argparse

def create_parser():
    """Create command line argument parser"""
    parser = argparse.ArgumentParser(
        description='Web Vulnerability Scanner',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Usage examples:
  python main.py -t example.com
  python main.py -t 192.168.1.1:8080
  python main.py -t https://example.com/path
  python main.py -f targets.txt -m xss,sqli
  python main.py -t example.com -c "session=abc123" -H "User-Agent: Custom"
  python main.py -t example.com -a jwt -o report.html --timeout 30

API Testing examples:
  python main.py --api swagger.json -m sqli,xss
  python main.py --api https://api.example.com/v1/openapi.json --all
  python main.py --api collection.postman.json --api-auth-token "Bearer xxx"
  python main.py -t https://api.example.com --api-discover -m api_security
  python main.py --api requests.har --api-base-url https://api.example.com
        """
    )
    
    # GUI mode
    parser.add_argument('--gui', action='store_true',
                       help='Launch GUI interface with optional pre-configured parameters')
    parser.add_argument('--auto-start', action='store_true',
                       help='Auto-start scan when using --gui (requires target/file)')
    parser.add_argument('--wizard', action='store_true',
                       help='Launch interactive terminal wizard for guided scan configuration')

    # Target options
    target_group = parser.add_mutually_exclusive_group(required=False)
    target_group.add_argument('-t', '--target', nargs='+',
                       help='One or more scan targets (IP, domain, URL, IP:port, URL:port, subnet)')
    target_group.add_argument('-f', '--file',
                       help='File with targets for scanning')
    target_group.add_argument('--api-targets-file',
                       help='JSON file with API targets (includes method, headers, body, params)')
    
    # HTTP parameters
    parser.add_argument('-H', '--headers', action='append',
                       help='HTTP headers (can be used multiple times, format: "Header: Value")')
    parser.add_argument('-hf', '--headers-file',
                       help='File with HTTP headers (one per line)')
    parser.add_argument('-c', '--cookies',
                       help='HTTP cookies (format: "name=value; name2=value2")')
    parser.add_argument('-a', '--auth',
                       choices=['jwt', 'basic'],
                       help='Authorization type')
    parser.add_argument('--proxy',
                       help='HTTP/SOCKS proxy (format: http://127.0.0.1:8080 or socks5://127.0.0.1:1080)')
    parser.add_argument('--follow-redirects', action='store_true', default=True,
                       help='Follow HTTP redirects (default: True)')
    parser.add_argument('--no-redirects', action='store_true',
                       help='Do not follow HTTP redirects')
    parser.add_argument('--verify-ssl', action='store_true',
                       help='Verify SSL/TLS certificates (default: False for pentesting)')
    parser.add_argument('--dns',
                       help='Custom DNS server (format: 8.8.8.8 or 1.1.1.1)')
    
    # WAF and bypass options
    parser.add_argument('--waf', action='store_true',
                       help='Enable WAF detection and use WAF bypass payloads')
    parser.add_argument('--waf-mode', action='store_true',
                       help='Enable WAF bypass mode (uses cloudscraper or headless browser)')
    parser.add_argument('--browser', action='store_true',
                       help='Use headless browser for WAF bypass (requires playwright or cloudscraper)')
    parser.add_argument('--wafiffound', action='store_true',
                       help='Prompt to enable WAF bypass mode if a WAF is detected')
    parser.add_argument('--waf-detect', action='store_true',
                       help='Run only WAF detection and exit')

    # Subdomain options
    parser.add_argument('--enum-subdomains', action='store_true',
                       help='Enumerate subdomains before scanning (uses passive + active techniques)')
    parser.add_argument('--subdomain-takeover', action='store_true',
                       help='Check for subdomain takeover vulnerabilities')
    parser.add_argument('--scan-subdomains', action='store_true',
                       help='Scan main domain AND discovered subdomains (implies --enum-subdomains)')
    parser.add_argument('--subdomain-limit', type=int, default=10,
                       help='Maximum number of subdomains to scan when using --scan-subdomains (default: 10)')
    parser.add_argument('--subdomain-wordlist',
                       help='Custom wordlist for subdomain brute-forcing')
    parser.add_argument('--subdomain-passive-only', action='store_true',
                       help='Use only passive subdomain enumeration (no DNS brute-force)')

    # Scanning parameters
    parser.add_argument('-m', '--modules', 
                       help='Scanning modules (comma separated)')
    parser.add_argument('--all', action='store_true',
                       help='Use all available modules')
    parser.add_argument('--all-enhanced', action='store_true',
                       help='Use all available modules including enhanced ones for specific targets')
    parser.add_argument('--exclude',
                       help='Exclude paths from scanning (comma separated)')
    parser.add_argument('--exclude-ips',
                       help='Exclude IP addresses from scanning (comma separated)')
    parser.add_argument('--exclude-subdomains',
                       help='Exclude subdomains from scanning (comma separated)')
    parser.add_argument('--timeout', type=int, default=20,
                       help='Request timeout in seconds')
    parser.add_argument('--scan-timeout', type=int,
                       help='Maximum scan time in seconds')
    parser.add_argument('--max-time', type=int,
                       help='Maximum scan time in minutes (will stop scan and show report)')
    parser.add_argument('--threads', type=int, default=15,
                       help='Number of threads')
    parser.add_argument('--page-limit', type=int,
                       help='Page limit for scanning')
    parser.add_argument('--delay', type=float, default=0,
                       help='Delay between requests in seconds (default: 0)')
    parser.add_argument('--request-limit', type=int, default=10000, dest='limit',
                       help='Maximum number of requests to make (default: 10000)')
    parser.add_argument('--payload-limit', type=int, default=0,
                       help='Limit number of payloads per module (0 = no limit, default: 0)')
    parser.add_argument('--fast', action='store_true',
                       help='Fast scan mode (auto-sets: --payload-limit 5, --threads 8, enables concurrent requests and early exit)')
    parser.add_argument('--user-agent', default='Dominator/1.0',
                       help='User-Agent string to use')
    parser.add_argument('--rotate-agent', action='store_true',
                       help='Rotate User-Agent headers randomly for each request')
    parser.add_argument('--single-url', action='store_true',
                       help='Scan only the specified URL without crawling or testing other pages')
    parser.add_argument('--single-page', '--no-crawl', action='store_true', dest='nocrawl',
                       help='Scan only the target page without crawling (single-page mode)')
    parser.add_argument('-np', '--no-ping', action='store_true', dest='no_ping',
                       help='Skip target alive check - attempt scan regardless of connectivity status')
    parser.add_argument('--max-crawl-pages', type=int, default=50,
                       help='Maximum pages to crawl (default: 50)')
    parser.add_argument('--add-known-paths',
                       help='File with known paths/URLs to inject into scan (one per line)')
    parser.add_argument('--scope-file',
                       help='File with scope URLs to scan (one per line, alternative to -f/--file)')
    parser.add_argument('--custom-payloads',
                       help='Custom payloads file or inline payloads for specific module (format: module:file or module:payload1,payload2)')
    parser.add_argument('--max-requests', type=int,
                       help='Maximum total requests before stopping and generating report')
    parser.add_argument('--verbose', '-v', action='store_true',
                       help='Verbose output')
    parser.add_argument('--debug', action='store_true',
                       help='Enable debug output')
    parser.add_argument('--nopassive', action='store_true',
                       help='Disable passive detection modules')
    parser.add_argument('--recon-only', action='store_true',
                       help='Passive reconnaissance only - no active attacks (crawl + passive detectors only)')
    parser.add_argument('--live', action='store_true',
                       help='Enable live reporting mode - generate real-time HTML/TXT report as vulnerabilities are found')

    # Pre-scan Profiling options
    parser.add_argument('--profile', action='store_true', default=True,
                       help='Enable target profiling before scan (default: True)')
    parser.add_argument('--no-profile', action='store_true',
                       help='Disable pre-scan target profiling')
    parser.add_argument('--screenshot', action='store_true',
                       help='Capture screenshot of target (requires playwright or selenium)')
    parser.add_argument('--profile-only', action='store_true',
                       help='Run only target profiling without vulnerability scanning')
    parser.add_argument('--profile-output',
                       help='Save profile results to JSON file')

    # API Testing options
    parser.add_argument('--api-spec', '--api',
                       help='API specification file or URL (OpenAPI/Swagger, Postman, HAR, WADL, RAML, GraphQL)')
    parser.add_argument('--api-format',
                       choices=['auto', 'openapi', 'swagger', 'postman', 'har', 'wadl', 'raml', 'graphql', 'blueprint'],
                       default='auto',
                       help='API specification format (default: auto-detect)')
    parser.add_argument('--api-base-url',
                       help='Override base URL for API endpoints')
    parser.add_argument('--api-discover', action='store_true',
                       help='Try to auto-discover API spec from target (checks /swagger.json, /openapi.json, etc.)')
    parser.add_argument('--api-auth-token',
                       help='Bearer token for API authentication (shortcut for -H "Authorization: Bearer <token>")')
    parser.add_argument('-apim', '--api-modules', action='store_true',
                       help='Use API-specific security modules only (BOLA, Mass Assignment, Rate Limit, etc.)')
    parser.add_argument('--api-full', action='store_true',
                       help='Use all modules including API-specific ones for API testing')

    # Deduplication options
    parser.add_argument('--max-duplicates', type=int, default=3,
                       help='Maximum number of duplicate findings to show (default: 3)')
    parser.add_argument('--no-grouping', action='store_true',
                       help='Disable grouping of similar findings')
    parser.add_argument('--no-domain-dedupe', action='store_true',
                       help='Disable domain-level deduplication')
    
    # Auto Reports
    parser.add_argument('--auto-report', action='store_true',
                       help='Automatically generate HTML report with timestamp')
    parser.add_argument('--format',
                       default='html',
                       help='Report format or comma-separated list of formats (e.g., html,txt)')
    parser.add_argument('--report-mode',
                       choices=['full', 'simple'],
                       default='full',
                       help='Report detail level: full (all details, default) or simple (summary only)')

    # Retest options
    parser.add_argument('--retest', '--baseline',
                       help='Path to baseline scan results (JSON) for retest comparison. Scanner will mark vulnerabilities as FIXED/NEW/STILL_VULNERABLE')
    parser.add_argument('--save-baseline',
                       help='Save current scan results as baseline for future retests (JSON file path)')
    
    # Information commands
    parser.add_argument('--modules-list', action='store_true',
                       help='Show all available modules')
    parser.add_argument('--help-examples', action='store_true',
                       help='Show usage examples')
    parser.add_argument('--filetree', action='store_true',
                       help='Show file tree structure during scan')
    
    return parser

def show_modules():
    """Show all available modules with fancy CLI formatting"""
    import json
    from pathlib import Path

    # Find modules directory
    script_dir = Path(__file__).parent
    modules_dir = script_dir / "modules"

    if not modules_dir.exists():
        print("Modules directory not found!")
        return

    # Category mappings for auto-detection
    CATEGORY_MAP = {
        "sqli": "Injection", "xss": "Injection", "cmdi": "Injection", "ssti": "Injection",
        "xxe": "Injection", "xpath": "Injection", "nosql": "Injection", "ldap": "Injection",
        "ssi": "Injection", "formula": "Injection", "crlf": "Injection", "header_injection": "Injection",
        "lfi": "File & Path", "rfi": "File & Path", "path": "File & Path", "file_upload": "File & Path",
        "csrf": "Auth & Session", "session": "Auth & Session", "jwt": "Auth & Session",
        "weak_credentials": "Auth & Session", "idor": "Auth & Session", "auth": "Auth & Session",
        "api": "API Security", "graphql": "API Security", "soap": "API Security", "websocket": "API Security",
        "dirbrute": "Recon", "subdomain": "Recon", "port": "Recon", "param": "Recon",
        "favicon": "Recon", "robots": "Recon", "sensitive": "Recon",
        "git": "Info Disclosure", "env": "Info Disclosure", "backup": "Info Disclosure",
        "config": "Info Disclosure", "debug": "Info Disclosure", "package": "Info Disclosure",
        "phpinfo": "Info Disclosure", "db_exposure": "Info Disclosure", "base64": "Info Disclosure",
        "ssrf": "Server & Network", "redirect": "Server & Network", "smuggling": "Server & Network",
        "host_header": "Server & Network", "cors": "Server & Network", "http_methods": "Server & Network",
        "forbidden": "Server & Network", "cgi": "Server & Network", "iis": "Server & Network", "hpp": "Server & Network",
        "ssl": "Security Config", "security_headers": "Security Config", "csp": "Security Config",
        "tabnabbing": "Security Config", "cspt": "Security Config",
        "dom_xss": "Advanced", "prototype": "Advanced", "php_object": "Advanced",
        "type_juggling": "Advanced", "request_smuggling": "Advanced",
        "cloud": "Cloud", "storage": "Cloud",
    }

    # Category icons
    CATEGORY_ICONS = {
        "Injection": "💉", "File & Path": "📁", "Auth & Session": "🔑",
        "API Security": "🔌", "Recon": "🔍", "Info Disclosure": "📦",
        "Server & Network": "🌐", "Security Config": "🛡️", "Advanced": "⚡",
        "Cloud": "☁️", "Other": "🔧"
    }

    # Severity colors (ANSI)
    SEVERITY_COLORS = {
        "critical": "\033[91m", "high": "\033[91m", "medium": "\033[93m",
        "low": "\033[92m", "info": "\033[96m"
    }
    RESET = "\033[0m"
    BOLD = "\033[1m"
    DIM = "\033[2m"

    # Collect all modules with their config
    modules_by_category = {}

    for module_path in sorted(modules_dir.iterdir()):
        if module_path.is_dir() and not module_path.name.startswith('_'):
            if module_path.name == 'oob_detection':
                continue

            config_file = module_path / "config.json"
            toml_file = module_path / "config.toml"

            # Default values
            folder = module_path.name
            name = folder.replace('_', ' ').title()
            description = f"Module: {folder}"
            category = "Other"
            severity = "medium"
            enabled = True
            passive = False

            # Try TOML first, then JSON
            config = {}
            if toml_file.exists():
                try:
                    import tomllib
                    with open(toml_file, 'rb') as f:
                        config = tomllib.load(f)
                except:
                    pass

            if not config and config_file.exists():
                try:
                    with open(config_file, 'r', encoding='utf-8') as f:
                        config = json.load(f)
                except:
                    pass

            if config:
                name = config.get('name', name)
                description = config.get('description', description)
                category = config.get('category', 'Other')
                severity = config.get('severity', 'medium')
                enabled = config.get('enabled', True)
                passive = config.get('passive', False)

            # Auto-detect category from folder name
            if category == "Other":
                folder_lower = folder.lower()
                for key, cat in CATEGORY_MAP.items():
                    if key in folder_lower:
                        category = cat
                        break

            if category not in modules_by_category:
                modules_by_category[category] = []

            modules_by_category[category].append({
                'folder': folder,
                'name': name,
                'description': description,
                'severity': severity.lower() if severity else 'medium',
                'enabled': enabled,
                'passive': passive
            })

    # Print fancy header
    print()
    print(f"{BOLD}╔{'═' * 78}╗{RESET}")
    print(f"{BOLD}║{'DOMINATOR - VULNERABILITY SCANNING MODULES':^78}║{RESET}")
    print(f"{BOLD}╚{'═' * 78}╝{RESET}")

    total_modules = 0
    enabled_count = 0
    active_count = 0
    passive_count = 0

    # Category order
    category_order = ["Injection", "File & Path", "Auth & Session", "API Security",
                     "Recon", "Info Disclosure", "Server & Network", "Security Config",
                     "Advanced", "Cloud", "Other"]

    for category in category_order:
        if category not in modules_by_category:
            continue

        modules = modules_by_category[category]
        icon = CATEGORY_ICONS.get(category, "🔧")

        # Category header
        print()
        print(f"{BOLD}┌{'─' * 78}┐{RESET}")
        print(f"{BOLD}│ {icon} {category.upper():<73} │{RESET}")
        print(f"{BOLD}│ {len(modules)} modules{' ' * 68}│{RESET}")
        print(f"{BOLD}├{'─' * 78}┤{RESET}")

        for mod in sorted(modules, key=lambda x: x['folder']):
            status = f"\033[92m✓{RESET}" if mod['enabled'] else f"\033[91m✗{RESET}"
            sev = mod['severity']
            sev_color = SEVERITY_COLORS.get(sev, "")
            sev_tag = f"{sev_color}[{sev.upper():^8}]{RESET}"

            type_tag = f"{DIM}[PASSIVE]{RESET}" if mod['passive'] else f"[ACTIVE] "

            # Truncate description
            desc = mod['description'][:35] + "..." if len(mod['description']) > 35 else mod['description']

            print(f"│ {status} {mod['folder']:<18} {type_tag} {sev_tag} {desc:<35} │")

            total_modules += 1
            if mod['enabled']:
                enabled_count += 1
            if mod['passive']:
                passive_count += 1
            else:
                active_count += 1

        print(f"└{'─' * 78}┘")

    # Summary footer
    print()
    print(f"{BOLD}╔{'═' * 78}╗{RESET}")
    print(f"{BOLD}║{'SUMMARY':^78}║{RESET}")
    print(f"{BOLD}╠{'═' * 78}╣{RESET}")
    print(f"{BOLD}║{RESET} Total Modules: {total_modules:<10} Active: {active_count:<10} Passive: {passive_count:<10}      {BOLD}║{RESET}")
    print(f"{BOLD}║{RESET} Enabled: \033[92m{enabled_count:<10}{RESET} Disabled: \033[91m{total_modules - enabled_count:<10}{RESET}                          {BOLD}║{RESET}")
    print(f"{BOLD}╠{'═' * 78}╣{RESET}")
    print(f"{BOLD}║{RESET} {'USAGE EXAMPLES:':<76} {BOLD}║{RESET}")
    print(f"{BOLD}║{RESET}   python main.py -t <target> -m xss,sqli,cmdi                               {BOLD}║{RESET}")
    print(f"{BOLD}║{RESET}   python main.py -t <target> --all  (use all enabled modules)              {BOLD}║{RESET}")
    print(f"{BOLD}║{RESET}   python main.py -t <target> -m injection  (all injection modules)         {BOLD}║{RESET}")
    print(f"{BOLD}╚{'═' * 78}╝{RESET}")
    print()

def process_args(args):
    """Process and validate command line arguments"""
    # Handle API targets file (from GUI API Testing tab)
    if hasattr(args, 'api_targets_file') and args.api_targets_file:
        import json
        try:
            with open(args.api_targets_file, 'r', encoding='utf-8') as f:
                args.api_targets = json.load(f)
            # Set target from first API endpoint for Config compatibility
            if args.api_targets and len(args.api_targets) > 0:
                args.target = args.api_targets[0].get('url', '')
            print(f"[*] Loaded {len(args.api_targets)} API targets from file")
        except Exception as e:
            print(f"[!] Error loading API targets file: {e}")
            args.api_targets = []
    else:
        args.api_targets = []

    # Fix args for Config compatibility
    if hasattr(args, 'file') and args.file:
        args.target = args.file

    # Keep multiple targets as list, convert single target to string
    if hasattr(args, 'target') and isinstance(args.target, list) and len(args.target) == 1:
        args.target = args.target[0]
    elif hasattr(args, 'target') and isinstance(args.target, list) and len(args.target) > 1:
        # Keep as list for multiple targets
        pass

    # Add missing attributes that Config expects
    if not hasattr(args, 'cookies'):
        args.cookies = None
    if not hasattr(args, 'proxy'):
        args.proxy = None
    if not hasattr(args, 'limit'):
        args.limit = 10000
    if not hasattr(args, 'use_all'):
        args.use_all = False
    if not hasattr(args, 'auth'):
        args.auth = None
    if not hasattr(args, 'all'):
        args.all = (args.modules == 'all' if args.modules else False)
    if not hasattr(args, 'page_limit'):
        args.page_limit = None
    if not hasattr(args, 'output'):
        args.output = None
    if not hasattr(args, 'proxy'):
        args.proxy = None
    if not hasattr(args, 'format'):
        args.format = 'html'
    if not hasattr(args, 'group_findings'):
        args.group_findings = not args.no_grouping
    if not hasattr(args, 'dedupe_domain'):
        args.dedupe_domain = not args.no_domain_dedupe
    if not hasattr(args, 'nocrawl'):
        args.nocrawl = False
    if not hasattr(args, 'no_ping'):
        args.no_ping = False
    if not hasattr(args, 'debug'):
        args.debug = False
    if not hasattr(args, 'filetree'):
        args.filetree = False
    if not hasattr(args, 'payload_limit'):
        args.payload_limit = 0
    if not hasattr(args, 'nopassive'):
        args.nopassive = False
    if not hasattr(args, 'waf'):
        args.waf = False
    if not hasattr(args, 'wafiffound'):
        args.wafiffound = False
    if not hasattr(args, 'waf_detect'):
        args.waf_detect = False

    # Subdomain defaults
    if not hasattr(args, 'enum_subdomains'):
        args.enum_subdomains = False
    if not hasattr(args, 'subdomain_takeover'):
        args.subdomain_takeover = False
    if not hasattr(args, 'scan_subdomains'):
        args.scan_subdomains = False
    if not hasattr(args, 'subdomain_limit'):
        args.subdomain_limit = 10
    if not hasattr(args, 'subdomain_wordlist'):
        args.subdomain_wordlist = None
    if not hasattr(args, 'subdomain_passive_only'):
        args.subdomain_passive_only = False

    # If --scan-subdomains is set, it implies --enum-subdomains
    if args.scan_subdomains:
        args.enum_subdomains = True

    # Profiling defaults
    if not hasattr(args, 'profile'):
        args.profile = True
    if not hasattr(args, 'no_profile'):
        args.no_profile = False
    if not hasattr(args, 'screenshot'):
        args.screenshot = False
    if not hasattr(args, 'profile_only'):
        args.profile_only = False
    if not hasattr(args, 'profile_output'):
        args.profile_output = None

    # If --no-profile is set, disable profiling
    if args.no_profile:
        args.profile = False

    # API Testing defaults
    if not hasattr(args, 'api_spec'):
        args.api_spec = None
    if not hasattr(args, 'api_format'):
        args.api_format = 'auto'
    if not hasattr(args, 'api_base_url'):
        args.api_base_url = None
    if not hasattr(args, 'api_discover'):
        args.api_discover = False
    if not hasattr(args, 'api_auth_token'):
        args.api_auth_token = None

    # Handle API spec - parse and get endpoints as targets
    if args.api_spec:
        args = _process_api_spec(args)

    # Handle API auto-discovery
    if args.api_discover and args.target:
        args = _discover_api_spec(args)

    # Handle -apim flag (API-specific modules only)
    if getattr(args, 'api_modules', False):
        api_only_modules = [
            'api_security', 'api_bola', 'api_mass_assignment',
            'api_rate_limit', 'api_excessive_data', 'jwt_analysis',
            'graphql', 'cors', 'idor'
        ]
        args.modules = ','.join(api_only_modules)
        args.all = False
        print(f"\n[API MODULES] Using API-specific security modules:")
        for mod in api_only_modules:
            print(f"  - {mod}")
        print()

    # Handle --api-full flag
    if getattr(args, 'api_full', False):
        args.all = True
        print("[API FULL] Using all modules including API-specific ones")

    # Apply nocrawl logic
    if args.nocrawl:
        args.single_url = True
    
    # FIXED: WAF detection is a passive detector, not a module
    # If only WAF detection is requested, run minimal scan to trigger passive detection
    if args.waf_detect:
        # Use security_headers module as lightweight test to trigger WAF detection
        args.modules = 'security_headers'
        args.all = False
        args.nocrawl = True  # WAF detection doesn't need crawling
        args.nopassive = False  # Ensure passive detection is enabled
        print("WAF detection mode enabled. Running lightweight scan to detect WAF...")

    # Handle --all-enhanced flag
    if hasattr(args, 'all_enhanced') and args.all_enhanced:
        args.all = True
        enhanced_modules = ['fileinclusionenhanced', 'ssrfenhanced', 'infoleakenhanced']
        
        if args.modules:
            existing_modules = [m.strip() for m in args.modules.split(',')]
        else:
            existing_modules = []
            
        for module in enhanced_modules:
            if module not in existing_modules:
                existing_modules.append(module)
        
        args.modules = ','.join(existing_modules)
        print("Enhanced scan mode enabled, including all standard and enhanced modules.")

    # Handle --fast flag (ZAP-speed optimization)
    if hasattr(args, 'fast') and args.fast:
        print("\n[FAST MODE] ZAP-speed optimizations enabled:")

        # Set payload limit if not already set
        if not args.payload_limit or args.payload_limit == 0:
            args.payload_limit = 5
            print(f"  - Payload limit: {args.payload_limit}")
        else:
            print(f"  - Payload limit: {args.payload_limit} (user-specified)")

        # Set threads if not already set higher
        if args.threads < 8:
            args.threads = 8
            print(f"  - Threads: {args.threads}")
        else:
            print(f"  - Threads: {args.threads} (user-specified)")

        print("  - Concurrent requests: enabled (10 per module)")
        print("  - Early exit: enabled (stop on first vuln per parameter)")
        print()

    return args


def _process_api_spec(args):
    """Process API specification and extract endpoints as targets"""
    try:
        from utils.api_parser import APIParser

        print(f"\n[API TESTING] Loading API specification: {args.api_spec}")

        parser = APIParser()
        endpoints = parser.parse(
            args.api_spec,
            format_type=args.api_format,
            base_url=args.api_base_url
        )

        if not endpoints:
            print("[!] No endpoints found in API specification")
            return args

        # Get summary
        summary = parser.get_summary()
        print(f"[+] API: {summary['spec_info'].get('title', 'Unknown')}")
        print(f"[+] Base URL: {summary.get('base_url', 'N/A')}")
        print(f"[+] Endpoints found: {summary['total_endpoints']}")
        print(f"[+] Methods: {summary['methods']}")

        if summary.get('auth_schemes'):
            print(f"[+] Auth schemes: {', '.join(summary['auth_schemes'])}")

        # Display parsed endpoints with parameters
        print(f"\n{'─' * 60}")
        print(f"  PARSED API ENDPOINTS")
        print(f"{'─' * 60}")
        for i, ep in enumerate(endpoints, 1):
            method = ep.method.upper()
            # Extract path from full URL
            from urllib.parse import urlparse
            parsed_url = urlparse(ep.url)
            path = parsed_url.path or '/'

            # Color-code methods
            method_colors = {'GET': '32', 'POST': '33', 'PUT': '34', 'DELETE': '31', 'PATCH': '35'}
            color = method_colors.get(method, '37')
            print(f"  [{i:2d}] \033[{color}m{method:7s}\033[0m {path}")

            # Show parameters
            params = []
            if ep.params:
                params.extend([f"?{p}" for p in list(ep.params.keys())[:5]])
            if ep.body and isinstance(ep.body, dict):
                params.extend([f"@{p}" for p in list(ep.body.keys())[:5]])
            if ep.headers:
                params.extend([f"H:{h}" for h in list(ep.headers.keys())[:3]])

            if params:
                print(f"       └─ params: {', '.join(params[:8])}" + (" ..." if len(params) > 8 else ""))
        print(f"{'─' * 60}\n")

        # Convert endpoints to targets
        targets = []
        for ep in endpoints:
            target_dict = ep.to_target()

            # Add Bearer token if provided via --api-auth-token (convenience shortcut)
            if args.api_auth_token:
                target_dict['headers']['Authorization'] = f"Bearer {args.api_auth_token}"

            # Add any custom headers from -H flag
            if hasattr(args, 'headers') and args.headers:
                for header in args.headers:
                    if ':' in header:
                        key, value = header.split(':', 1)
                        target_dict['headers'][key.strip()] = value.strip()

            targets.append(target_dict)

        # Show auth hint from spec if user didn't provide auth
        if not args.api_auth_token and summary.get('auth_schemes'):
            auth_info = parser.get_auth_header_hint()
            if auth_info:
                print(f"\n[!] API requires authentication: {', '.join(summary['auth_schemes'])}")
                if auth_info.get('type'):
                    print(f"    Type: {auth_info['type']}")
                    print(f"    Header: {auth_info['header']}")
                    print(f"    Format: {auth_info['format']}")
                print(f"    Use: --api-auth-token <token> or -H \"{auth_info.get('header', 'Authorization')}: Bearer <token>\"")
                print()

        # Store API targets in args
        args.api_targets = targets

        # Set target from base_url if not already set
        if not args.target and summary.get('base_url'):
            args.target = summary['base_url']

        # Disable crawling for API testing (we have explicit endpoints)
        args.nocrawl = True
        args.single_url = True

        print(f"[+] API mode enabled - crawling disabled, testing {len(targets)} endpoints")
        print()

    except ImportError as e:
        print(f"[!] Error loading API parser: {e}")
        print("[!] Make sure pyyaml is installed: pip install pyyaml")
    except Exception as e:
        print(f"[!] Error processing API specification: {e}")
        import traceback
        traceback.print_exc()

    return args


def _discover_api_spec(args):
    """Try to auto-discover API specification from target"""
    try:
        from utils.api_parser import fetch_swagger_url

        target = args.target[0] if isinstance(args.target, list) else args.target

        print(f"\n[API DISCOVERY] Searching for API specification at {target}...")

        spec_url = fetch_swagger_url(target)

        if spec_url:
            print(f"[+] Found API specification: {spec_url}")
            args.api_spec = spec_url
            args = _process_api_spec(args)
        else:
            print("[!] No API specification found at common endpoints")
            print("    Checked: /swagger.json, /openapi.json, /api-docs, etc.")

    except Exception as e:
        print(f"[!] Error during API discovery: {e}")

    return args
