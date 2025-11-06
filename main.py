#!/usr/bin/env python3
"""
Web Vulnerability Scanner
Main file for running the scanner
"""

import argparse
import sys
import os
from core.scanner import VulnScanner
from core.config import Config
from utils.file_handler import FileHandler

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
    
    # Main parameters
    parser.add_argument('-t', '--target', 
                       help='Scan target (IP, domain, URL, IP:port, URL:port, subnet)')
    parser.add_argument('-f', '--file', 
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
    parser.add_argument('-m', '--modules', 
                       help='Scanning modules (comma separated)')
    parser.add_argument('--all', action='store_true', default=True,
                       help='Use all modules (default)')
    parser.add_argument('--exclude',
                       help='Exclude paths from scanning')
    parser.add_argument('--timeout', type=int, default=10,
                       help='Request timeout in seconds')
    parser.add_argument('--threads', type=int, default=10,
                       help='Number of threads')
    parser.add_argument('--limit', type=int,
                       help='Request limit before scan finish')
    parser.add_argument('--page-limit', type=int,
                       help='Page limit for scanning')
    
    # Reports
    parser.add_argument('-o', '--output',
                       help='File to save report')
    parser.add_argument('--format', 
                       choices=['xml', 'json', 'txt', 'html'],
                       default='txt',
                       help='Report format')
    
    # Information commands
    parser.add_argument('--modules-list', action='store_true',
                       help='Show all available modules')
    parser.add_argument('--help-examples', action='store_true',
                       help='Show usage examples')
    
    return parser

def show_modules():
    """Show all available modules"""
    print("Available scanning modules:")
    print("- xss: Cross-Site Scripting")
    print("- sqli: SQL Injection")
    print("- lfi: Local File Inclusion")
    print("- rfi: Remote File Inclusion")
    print("- xxe: XML External Entity")
    print("- csrf: Cross-Site Request Forgery")
    print("- idor: Insecure Direct Object Reference")
    print("- ssrf: Server-Side Request Forgery")

def main():
    """Main function"""
    parser = create_parser()
    args = parser.parse_args()
    
    # Show modules and exit
    if args.modules_list:
        show_modules()
        return
    
    # Check required parameters
    if not args.target and not args.file:
        print("Error: Must specify target (-t) or targets file (-f)")
        parser.print_help()
        sys.exit(1)
    
    try:
        # Create configuration
        config = Config(args)
        
        # Create scanner
        scanner = VulnScanner(config)
        
        # Start scanning
        print(f"Starting scan...")
        results = scanner.scan()
        
        # Save results
        if args.output:
            try:
                scanner.save_report(results, args.output, args.format)
                print(f"Report saved to {args.output}")
            except Exception as e:
                print(f"Error saving report: {e}")
                # Still print results to console
                scanner.print_results(results)
        else:
            scanner.print_results(results)
            
    except KeyboardInterrupt:
        print("\nScan interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"Error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)

if __name__ == "__main__":
    main()
