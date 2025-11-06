#!/usr/bin/env python3
"""
Dominator Web Vulnerability Scanner
Main entry point for the scanner
"""

import sys
import argparse
from core.config import Config
from core.scanner import VulnScanner

def main():
    """Main function"""
    parser = argparse.ArgumentParser(
        description='Dominator Web Vulnerability Scanner',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python scanner.py -u http://example.com --modules xss,sqli
  python scanner.py -u http://example.com --modules all
  python scanner.py -f targets.txt --modules phpinfo,ssltls
  python scanner.py -u http://example.com --modules secheaders --output report.json
  python scanner.py --single-url -u http://example.com/page.php?id=1 --modules textinjection,htmlinjection
        """
    )
    
    # Target options
    target_group = parser.add_mutually_exclusive_group(required=True)
    target_group.add_argument('-u', '--url', help='Target URL to scan')
    target_group.add_argument('-f', '--file', help='File containing target URLs')
    
    # Scanning options
    parser.add_argument('--modules', default='all',
                       help='Comma-separated list of modules to run (default: all)')
    parser.add_argument('--all-modules', action='store_true',
                       help='Use all available modules')
    parser.add_argument('--threads', type=int, default=5,
                       help='Number of threads to use (default: 5)')
    parser.add_argument('--timeout', type=int, default=10,
                       help='Request timeout in seconds (default: 10)')
    parser.add_argument('--scan-timeout', type=int,
                       help='Maximum scan time in seconds')
    parser.add_argument('--max-time', type=int,
                       help='Maximum scan time in minutes')
    parser.add_argument('--delay', type=float, default=0,
                       help='Delay between requests in seconds (default: 0)')
    parser.add_argument('--request-limit', type=int, default=None,
                       help='Maximum number of requests to make (default: unlimited)')
    parser.add_argument('--user-agent', default='Dominator/1.0',
                       help='User-Agent string to use')
    parser.add_argument('--headers', action='append',
                       help='Additional headers (format: "Header: Value")')
    parser.add_argument('--headers-file',
                       help='File containing headers (one per line)')
    parser.add_argument('--single-url', action='store_true',
                       help='Scan only the specified URL without crawling or testing other pages')
    
    # Output options
    parser.add_argument('--output', '-o',
                       help='Output file name')
    parser.add_argument('--format', choices=['json', 'xml', 'html', 'txt'],
                       default='json', help='Output format (default: json)')
    parser.add_argument('--verbose', '-v', action='store_true',
                       help='Verbose output')
    
    # Advanced options
    parser.add_argument('--crawl', action='store_true',
                       help='Enable web crawling to find more pages')
    parser.add_argument('--max-crawl-pages', type=int, default=20,
                       help='Maximum pages to crawl (default: 20)')
    parser.add_argument('--exclude',
                       help='Comma-separated list of modules to exclude')
    
    args = parser.parse_args()
    
    try:
        # Fix args for Config compatibility
        if hasattr(args, 'url') and args.url:
            args.target = args.url
        elif hasattr(args, 'file') and args.file:
            args.target = args.file
        
        # Add missing attributes that Config expects
        if not hasattr(args, 'cookies'):
            args.cookies = None
        if not hasattr(args, 'proxy'):
            args.proxy = None
        if not hasattr(args, 'request_limit'):
            args.request_limit = args.request_limit
        if not hasattr(args, 'use_all'):
            args.use_all = False
        if not hasattr(args, 'auth'):
            args.auth = None
        if not hasattr(args, 'all'):
            args.all = (args.modules == 'all' or args.all_modules)
        if not hasattr(args, 'limit'):
            args.limit = args.request_limit
        if not hasattr(args, 'page_limit'):
            args.page_limit = None
        if not hasattr(args, 'format'):
            args.format = 'json'
        
        # Create configuration
        config = Config(args)
        
        # Print banner
        print_banner()
        
        # Create and run scanner
        scanner = VulnScanner(config)
        results = scanner.scan()
        
        # Print results to console
        scanner.print_results(results)
        
        # Save report if output specified
        if args.output:
            scanner.save_report(results, args.output, args.format)
            print(f"\nReport saved to: {args.output}")
        
        # Exit with appropriate code
        vulnerabilities_found = any(r.get('vulnerability') for r in results)
        sys.exit(1 if vulnerabilities_found else 0)
        
    except KeyboardInterrupt:
        print("\n[!] Scan interrupted by user")
        sys.exit(130)
    except Exception as e:
        print(f"[!] Error: {e}")
        if args.verbose:
            import traceback
            traceback.print_exc()
        sys.exit(1)

def print_banner():
    """Print scanner banner"""
    banner = """
================================================================================
                          DOMINATOR WEB SCANNER                              
                         Advanced Vulnerability Scanner                       
================================================================================
    """
    print(banner)

if __name__ == '__main__':
    main()
