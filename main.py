#!/usr/bin/env python3
"""
Web Vulnerability Scanner
Main file for running the scanner
"""

import argparse
import sys
import os
import time
import threading
import signal
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
    
    # Target options
    target_group = parser.add_mutually_exclusive_group(required=True)
    target_group.add_argument('-t', '--target', 
                       help='Scan target (IP, domain, URL, IP:port, URL:port, subnet)')
    target_group.add_argument('-u', '--url', help='Target URL to scan')
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
    parser.add_argument('-m', '--modules', 
                       help='Scanning modules (comma separated)')
    parser.add_argument('--all', action='store_true',
                       help='Use all modules')
    parser.add_argument('--all-modules', action='store_true',
                       help='Use all available modules')
    parser.add_argument('--exclude',
                       help='Exclude paths from scanning')
    parser.add_argument('--timeout', type=int, default=10,
                       help='Request timeout in seconds')
    parser.add_argument('--scan-timeout', type=int,
                       help='Maximum scan time in seconds')
    parser.add_argument('--max-time', type=int,
                       help='Maximum scan time in minutes (will stop scan and show report)')
    parser.add_argument('--threads', type=int, default=10,
                       help='Number of threads')
    parser.add_argument('--limit', type=int,
                       help='Request limit before scan finish')
    parser.add_argument('--page-limit', type=int,
                       help='Page limit for scanning')
    parser.add_argument('--delay', type=float, default=0,
                       help='Delay between requests in seconds (default: 0)')
    parser.add_argument('--request-limit', type=int, default=None,
                       help='Maximum number of requests to make (default: unlimited)')
    parser.add_argument('--user-agent', default='Dominator/1.0',
                       help='User-Agent string to use')
    parser.add_argument('--single-url', action='store_true',
                       help='Scan only the specified URL without crawling or testing other pages')
    parser.add_argument('--crawl', action='store_true',
                       help='Enable web crawling to find more pages')
    parser.add_argument('--nocrawl', action='store_true',
                       help='Disable web crawling completely (same as --single-url)')
    parser.add_argument('--max-crawl-pages', type=int, default=20,
                       help='Maximum pages to crawl (default: 20)')
    parser.add_argument('--verbose', '-v', action='store_true',
                       help='Verbose output')
    
    # Deduplication options
    parser.add_argument('--max-duplicates', type=int, default=3,
                       help='Maximum number of duplicate findings to show (default: 3)')
    parser.add_argument('--no-grouping', action='store_true',
                       help='Disable grouping of similar findings')
    parser.add_argument('--no-domain-dedupe', action='store_true',
                       help='Disable domain-level deduplication')
    
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
    print("- dirbrute: Directory and File Bruteforce")
    print("- gitexposed: Exposed Git Repository")
    print("- dirtraversal: Directory Traversal")
    print("- secheaders: Security Headers and Cookie Flags")
    print("- clickjacking: Clickjacking Protection")
    print("- blindxss: Blind Cross-Site Scripting")
    print("- passwordoverhttp: Password Over HTTP")
    print("- outdatedsoftware: Outdated Software Detection")
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
    print("- contentreflection: Content Reflection")
    print("- htmlinjection: HTML Injection")

class ScanTimeout:
    """Handle scan timeout using threading"""
    def __init__(self, timeout_seconds):
        self.timeout_seconds = timeout_seconds
        self.timer = None
        self.timed_out = False
    
    def timeout_handler(self):
        """Handle scan timeout"""
        self.timed_out = True
        print("\n[!] Scan timeout reached, stopping...")
    
    def start(self):
        """Start timeout timer"""
        if self.timeout_seconds:
            self.timer = threading.Timer(self.timeout_seconds, self.timeout_handler)
            self.timer.start()
    
    def cancel(self):
        """Cancel timeout timer"""
        if self.timer:
            self.timer.cancel()
    
    def is_timed_out(self):
        """Check if timeout occurred"""
        return self.timed_out

class MaxTimeHandler:
    """Handle maximum scan time limit"""
    def __init__(self, max_minutes, scanner):
        self.max_minutes = max_minutes
        self.scanner = scanner
        self.timer = None
        self.stopped = False
    
    def timeout_handler(self):
        """Handle max time timeout"""
        self.stopped = True
        print(f"\n[!] Maximum scan time ({self.max_minutes} minutes) reached!")
        print("[!] Stopping scan and generating report with current results...")
        # Set a flag in scanner to stop gracefully
        if hasattr(self.scanner, 'stop_requested'):
            self.scanner.stop_requested = True
    
    def start(self):
        """Start max time timer"""
        if self.max_minutes:
            timeout_seconds = self.max_minutes * 60
            self.timer = threading.Timer(timeout_seconds, self.timeout_handler)
            self.timer.start()
            print(f"[INFO] Maximum scan time set to {self.max_minutes} minutes")
    
    def cancel(self):
        """Cancel max time timer"""
        if self.timer:
            self.timer.cancel()
    
    def is_stopped(self):
        """Check if max time was reached"""
        return self.stopped

def signal_handler(sig, frame):
    """Handle Ctrl+C signal for immediate exit"""
    print("\n[!] Получен сигнал прерывания (Ctrl+C)")
    print("[!] Немедленное завершение программы...")
    os._exit(1)

def print_banner():
    """Print scanner banner"""
    banner = """
================================================================================
                          DOMINATOR WEB SCANNER                              
                         Advanced Vulnerability Scanner                       
================================================================================
    """
    print(banner)

def main():
    """Main function"""
    # Set up signal handler for immediate Ctrl+C exit
    signal.signal(signal.SIGINT, signal_handler)
    
    parser = create_parser()
    args = parser.parse_args()
    
    # Print banner
    print_banner()
    
    # Show modules and exit
    if args.modules_list:
        show_modules()
        return
    
    # Check required parameters
    if not args.target and not args.file and not args.url:
        print("Error: Must specify target (-t), URL (-u) or targets file (-f)")
        parser.print_help()
        sys.exit(1)
    
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
        args.all = (args.modules == 'all' or args.all_modules if hasattr(args, 'all_modules') else False)
    if not hasattr(args, 'limit'):
        args.limit = args.request_limit
    if not hasattr(args, 'page_limit'):
        args.page_limit = None
    if not hasattr(args, 'format'):
        args.format = 'txt'
    if not hasattr(args, 'group_findings'):
        args.group_findings = not args.no_grouping
    if not hasattr(args, 'dedupe_domain'):
        args.dedupe_domain = not args.no_domain_dedupe
    if not hasattr(args, 'nocrawl'):
        args.nocrawl = False
    
    # Apply nocrawl logic
    if args.nocrawl:
        args.single_url = True
    
    # Check if modules are specified
    if not args.modules and not args.all:
        print("Warning: No modules specified, using all modules by default")
    
    try:
        # Set up scan timeout if specified
        timeout_handler = None
        if hasattr(args, 'scan_timeout') and args.scan_timeout:
            timeout_handler = ScanTimeout(args.scan_timeout)
            timeout_handler.start()
            print(f"Scan timeout set to {args.scan_timeout} seconds")
        
        # Create configuration
        config = Config(args)
        
        # Create scanner
        scanner = VulnScanner(config)
        
        # Set up max time handler if specified
        max_time_handler = None
        if args.max_time:
            max_time_handler = MaxTimeHandler(args.max_time, scanner)
            max_time_handler.start()
        
        # Start scanning
        start_time = time.time()
        print(f"Starting scan...")
        
        # Check for timeout during scan
        results = []
        if timeout_handler and timeout_handler.is_timed_out():
            print("\nScan stopped due to timeout before starting")
        else:
            results = scanner.scan()
        
        # Cancel timeouts if scan completed normally
        if timeout_handler:
            timeout_handler.cancel()
        if max_time_handler:
            max_time_handler.cancel()
        
        # Check if scan was stopped due to max time
        if max_time_handler and max_time_handler.is_stopped():
            print(f"\n[INFO] Scan was stopped after {args.max_time} minutes")
            print("[INFO] Showing results collected so far...")
        
        scan_duration = time.time() - start_time
        print(f"\nScan completed in {scan_duration:.2f} seconds")
        
        # Always print results to console first
        scanner.print_results(results)
        
        # Save results if output specified
        if args.output:
            try:
                scanner.save_report(results, args.output, args.format)
                print(f"\nReport saved to {args.output}")
            except Exception as e:
                print(f"Error saving report: {e}")
                import traceback
                traceback.print_exc()
        
        # Exit with appropriate code
        vulnerabilities_found = any(r.get('vulnerability') for r in results)
        if vulnerabilities_found:
            sys.exit(1)
        
        # Cleanup resources
        try:
            scanner.cleanup()
        except Exception as e:
            print(f"Warning: Error during cleanup: {e}")
            
    except KeyboardInterrupt:
        print("\n[!] Сканирование прервано пользователем")
        if 'timeout_handler' in locals() and timeout_handler:
            timeout_handler.cancel()
        if 'max_time_handler' in locals() and max_time_handler:
            max_time_handler.cancel()
        os._exit(1)
    except Exception as e:
        print(f"Error: {e}")
        import traceback
        traceback.print_exc()
        if 'timeout_handler' in locals() and timeout_handler:
            timeout_handler.cancel()
        sys.exit(1)

if __name__ == "__main__":
    main()
