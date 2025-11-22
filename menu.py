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
        """
    )
    
    # GUI mode
    parser.add_argument('--gui', action='store_true',
                       help='Launch GUI interface with optional pre-configured parameters')
    parser.add_argument('--auto-start', action='store_true',
                       help='Auto-start scan when using --gui (requires target/file)')

    # Target options
    target_group = parser.add_mutually_exclusive_group(required=False)
    target_group.add_argument('-t', '--target', nargs='+',
                       help='One or more scan targets (IP, domain, URL, IP:port, URL:port, subnet)')
    target_group.add_argument('-f', '--file',
                       help='File with targets for scanning')
    
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
    
    # Scanning parameters
    parser.add_argument('--waf', action='store_true',
                       help='Enable WAF detection and use WAF bypass payloads')
    parser.add_argument('--wafiffound', action='store_true',
                       help='Prompt to enable WAF bypass mode if a WAF is detected')
    parser.add_argument('--waf-detect', action='store_true',
                       help='Run only WAF detection and exit')
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
    """Show all available modules - DYNAMICALLY loaded from config.json files"""
    import json
    from pathlib import Path

    # Find modules directory
    script_dir = Path(__file__).parent
    modules_dir = script_dir / "modules"

    if not modules_dir.exists():
        print("Modules directory not found!")
        return

    # Collect all modules with their config
    modules_by_category = {}

    for module_path in sorted(modules_dir.iterdir()):
        if module_path.is_dir() and not module_path.name.startswith('_'):
            config_file = module_path / "config.json"

            # Default values
            name = module_path.name
            description = f"Module: {module_path.name}"
            category = "Other"
            severity = "medium"
            enabled = True
            passive = False

            if config_file.exists():
                try:
                    with open(config_file, 'r', encoding='utf-8') as f:
                        config = json.load(f)
                        name = config.get('name', module_path.name)
                        description = config.get('description', description)
                        category = config.get('category', 'Other')
                        severity = config.get('severity', 'medium')
                        enabled = config.get('enabled', True)
                        passive = config.get('passive', False)
                except:
                    pass

            if category not in modules_by_category:
                modules_by_category[category] = []

            modules_by_category[category].append({
                'folder': module_path.name,
                'name': name,
                'description': description,
                'severity': severity,
                'enabled': enabled,
                'passive': passive
            })

    # Print header
    print("\n" + "=" * 80)
    print("                        AVAILABLE SCANNING MODULES")
    print("=" * 80)

    total_modules = 0
    enabled_count = 0

    # Print modules by category
    category_order = ['Injection', 'Information Disclosure', 'Recon', 'Security', 'Other']

    for category in category_order:
        if category in modules_by_category:
            modules = modules_by_category[category]
            print(f"\n[{category.upper()}] ({len(modules)} modules)")
            print("-" * 60)

            for mod in sorted(modules, key=lambda x: x['folder']):
                status = "✓" if mod['enabled'] else "✗"
                passive_tag = " [PASSIVE]" if mod['passive'] else ""
                severity_tag = f" [{mod['severity'].upper()}]" if mod['severity'] else ""

                # Truncate description if too long
                desc = mod['description'][:50] + "..." if len(mod['description']) > 50 else mod['description']

                print(f"  {status} {mod['folder']:<20} {desc}{severity_tag}{passive_tag}")

                total_modules += 1
                if mod['enabled']:
                    enabled_count += 1

    # Print remaining categories
    for category, modules in modules_by_category.items():
        if category not in category_order:
            print(f"\n[{category.upper()}] ({len(modules)} modules)")
            print("-" * 60)

            for mod in sorted(modules, key=lambda x: x['folder']):
                status = "✓" if mod['enabled'] else "✗"
                passive_tag = " [PASSIVE]" if mod['passive'] else ""
                severity_tag = f" [{mod['severity'].upper()}]" if mod['severity'] else ""
                desc = mod['description'][:50] + "..." if len(mod['description']) > 50 else mod['description']

                print(f"  {status} {mod['folder']:<20} {desc}{severity_tag}{passive_tag}")

                total_modules += 1
                if mod['enabled']:
                    enabled_count += 1

    # Print summary
    print("\n" + "=" * 80)
    print(f"Total: {total_modules} modules | Enabled: {enabled_count} | Disabled: {total_modules - enabled_count}")
    print("=" * 80)
    print("\nUsage: python main.py -t <target> -m xss,sqli,cmdi")
    print("       python main.py -t <target> --all  (use all enabled modules)")
    print("")

def process_args(args):
    """Process and validate command line arguments"""
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
    
    # Apply nocrawl logic
    if args.nocrawl:
        args.single_url = True
    
    # If only WAF detection is requested, override modules
    if args.waf_detect:
        args.modules = 'wafdetect'
        args.all = False
        args.nocrawl = True  # WAF detection doesn't need crawling
        print("WAF detection mode enabled. Running only the WAF detection module.")

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
