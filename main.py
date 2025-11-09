#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Web Vulnerability Scanner
Main file for running the scanner
"""

import sys
import os
import time
import threading
import signal

# Global flag for shutdown
shutdown_requested = False

# Set console encoding for Windows
if sys.platform.startswith('win'):
    try:
        import codecs
        sys.stdout = codecs.getwriter('utf-8')(sys.stdout.buffer, 'strict')
        sys.stderr = codecs.getwriter('utf-8')(sys.stderr.buffer, 'strict')
    except:
        pass

from core.scanner import VulnScanner
from core.config import Config
from utils.file_handler import FileHandler
from menu import create_parser, show_modules, process_args

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
        print(f"\nMaximum scan time ({self.max_minutes} minutes) reached!")
        print("Stopping scan and generating report with current results...")
        # Set a flag in scanner to stop gracefully
        if hasattr(self.scanner, 'stop_requested'):
            self.scanner.stop_requested = True
    
    def start(self):
        """Start max time timer"""
        if self.max_minutes:
            timeout_seconds = self.max_minutes * 60
            self.timer = threading.Timer(timeout_seconds, self.timeout_handler)
            self.timer.start()
            print(f"Maximum scan time set to {self.max_minutes} minutes")
    
    def cancel(self):
        """Cancel max time timer"""
        if self.timer:
            self.timer.cancel()
    
    def is_stopped(self):
        """Check if max time was reached"""
        return self.stopped

def signal_handler(sig, frame):
    """Handle Ctrl+C signal for immediate exit"""
    print("\nInterrupt signal received (Ctrl+C)")
    print("Terminating program immediately...")
    # Принудительный выход без cleanup
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
    global shutdown_requested
    shutdown_requested = False
    
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
        print("Tip: Use --quick-testphp for instant testphp.vulnweb.com guestbook scan")
        parser.print_help()
        sys.exit(1)
    
    # Process arguments using menu module
    args = process_args(args)
    
    # Check if modules are specified
    if not args.modules and not args.all and not args.filetree:
        print("Warning: No modules specified, using all modules by default")
        args.all = True
    elif args.filetree and not args.modules:
        print("File tree mode enabled - using file discovery modules (dirbrute, git, phpinfo)")
    
    try:
        # Set up scan timeout if specified
        timeout_handler = None
        if hasattr(args, 'scan_timeout') and args.scan_timeout:
            timeout_handler = ScanTimeout(args.scan_timeout)
            timeout_handler.start()
        
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
        
        # Check for timeout during scan
        results = []
        if timeout_handler and timeout_handler.is_timed_out():
            print("\nScan stopped due to timeout before starting")
        elif shutdown_requested:
            print("\nScan stopped due to shutdown request")
        else:
            results = scanner.scan()
        
        # Cancel timeouts if scan completed normally
        if timeout_handler:
            timeout_handler.cancel()
        if max_time_handler:
            max_time_handler.cancel()
        
        # Check if scan was stopped due to max time
        if max_time_handler and max_time_handler.is_stopped():
            print(f"\nScan was stopped after {args.max_time} minutes")
            print("Showing results collected so far...")
        
        scan_duration = time.time() - start_time
        print(f"\nScan completed in {scan_duration:.2f} seconds")
        
        # Always print results to console first
        scanner.print_results(results)
        
        # Auto-generate HTML report if flag is set
        if args.auto_report:
            import datetime
            timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
            target_name = args.target.replace(':', '_').replace('/', '_').replace('\\', '_')
            auto_filename = f"scan_report_{target_name}_{timestamp}.html"
            try:
                scanner.save_report(results, auto_filename, 'html')
                print(f"\nHTML report saved to {auto_filename}")
            except Exception as e:
                print(f"Error saving auto-report: {e}")
        
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
        print("\nScan interrupted by user")
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
