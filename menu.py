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
    
    # Target options
    target_group = parser.add_mutually_exclusive_group(required=True)
    target_group.add_argument('-t', '--target', nargs='+',
                       help='One or more scan targets (IP, domain, URL, IP:port, URL:port, subnet)')
    target_group.add_argument('-f', '--file', 
                       help='File with targets for scanning')
    
    # HTTP parameters
    parser.add_argument('-H', '--headers', action='append',
                       help='HTTP headers (can be used multiple times)')
    parser.add_argument('-hf', '--headers-file',
                       help='File with HTTP headers')
    parser.add_argument('-c', '--cookies',
                       help='HTTP cookies')
    parser.add_argument('-a', '--auth',
                       choices=['jwt', 'basic'],
                       help='Authorization type')
    
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
    parser.add_argument('--user-agent', default='Dominator/1.0',
                       help='User-Agent string to use')
    parser.add_argument('--single-url', action='store_true',
                       help='Scan only the specified URL without crawling or testing other pages')
    parser.add_argument('--nocrawl', action='store_true',
                       help='Disable web crawling completely')
    parser.add_argument('--max-crawl-pages', type=int, default=50,
                       help='Maximum pages to crawl (default: 50)')
    parser.add_argument('--verbose', '-v', action='store_true',
                       help='Verbose output')
    parser.add_argument('--debug', action='store_true',
                       help='Enable debug output')
    parser.add_argument('--nopassive', action='store_true',
                       help='Disable passive detection modules')
    
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
    
    # Information commands
    parser.add_argument('--modules-list', action='store_true',
                       help='Show all available modules')
    parser.add_argument('--help-examples', action='store_true',
                       help='Show usage examples')
    parser.add_argument('--filetree', action='store_true',
                       help='Show file tree structure during scan')
    
    return parser

def show_modules():
    """Show all available modules"""
    print("Available scanning modules:")
    print("- xss: Cross-Site Scripting (Enhanced for testphp.vulnweb.com)")
    print("- sqli: SQL Injection (Enhanced for testphp.vulnweb.com)")
    print("- lfi: Local File Inclusion")
    print("- rfi: Remote File Inclusion")
    print("- xxe: XML External Entity")
    print("- csrf: Cross-Site Request Forgery")
    print("- idor: Insecure Direct Object Reference")
    print("- ssrf: Server-Side Request Forgery")
    print("- dirbrute: Directory and File Bruteforce")
    print("- git: Git Repository Exposure")
    print("- dirtraversal: Directory Traversal")
    print("- secheaders: Security Headers and Cookie Flags")
    print("- clickjacking: Clickjacking Protection")
    print("- blindxss: Blind Cross-Site Scripting")
    print("- passwordoverhttp: Password Over HTTP")
    print("- outdatedsoftware: Outdated Software Detection with CVE Integration")
    print("- databaseerrors: Database Error Messages")
    print("- phpinfo: PHPInfo Exposure")
    print("- ssltls: SSL/TLS Configuration")
    print("- httponlycookies: HttpOnly Cookie Security")
    print("- technology: Technology Detection")
    print("- commandinjection: Command Injection")
    print("- pathtraversal: Path Traversal")
    print("- ldapinjection: LDAP Injection")
    print("- nosqlinjection: NoSQL Injection")
    print("- fileupload: File Upload Vulnerabilities")
    print("- cors: CORS Misconfiguration")
    print("- jwt: JWT Vulnerabilities")
    print("- deserialization: Insecure Deserialization")
    print("- responsesplitting: HTTP Response Splitting")
    print("- ssti: Server-Side Template Injection")
    print("- crlf: CRLF Injection")
    print("- textinjection: Text Injection")
    print("- htmlinjection: HTML Injection")
    print("- hostheader: Host Header Injection")
    print("- prototypepollution: Prototype Pollution")
    print("- vhost: Virtual Host Discovery")
    print("- infoleak: Information Leakage Detection")
    print("- openredirect: Open Redirect Vulnerabilities")
    print("\nEnhanced modules for testphp.vulnweb.com:")
    print("- fileinclusionenhanced: Enhanced File Inclusion Detection (LFI/RFI/SSRF)")
    print("- ssrfenhanced: Enhanced SSRF Detection")
    print("- infoleakenhanced: Enhanced Information Disclosure Detection")

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

    return args
