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
        sys.stdout = codecs.getwriter('utf-8')(sys.stdout.buffer, 'replace')
        sys.stderr = codecs.getwriter('utf-8')(sys.stderr.buffer, 'replace')
        # Set console code page to UTF-8 if possible
        os.system('chcp 65001 >nul 2>&1')
    except Exception:
        pass

from core.clean_scanner import ModularScanner
from core.config import Config
from core.logger import setup_logging
from core.retest_manager import RetestManager
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

    # Setup logging
    setup_logging(level='INFO', verbose=getattr(args, 'verbose', False))
    
    # Show modules and exit
    if args.modules_list:
        show_modules()
        return
    
    
    # Check required parameters
    if not args.target and not args.file:
        print("Error: Must specify target (-t) or targets file (-f)")
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
        
        # Apply nopassive flag if set
        if hasattr(args, 'nopassive') and args.nopassive:
            config.nopassive = True
        
        # Create scanner
        scanner = ModularScanner(config)

        # Set WAF flags from arguments (if supported by new scanner)
        # scanner.waf = getattr(args, 'waf', False)
        # scanner.waf_if_found = getattr(args, 'wafiffound', False)

        # If only WAF detection is requested, adjust config
        if getattr(args, 'waf_detect', False):
            config.modules = ['wafdetect']
            config.nopassive = True # Disable other passive scans
        
        # Enable module coordination for conflict prevention
        if hasattr(config, 'enable_module_coordination') and config.enable_module_coordination:
            print("Module coordination enabled - optimizing execution order to prevent conflicts")
            
            # If WAF detection is not explicitly requested but other modules are, add it automatically
            if 'wafdetect' not in config.modules and len(config.modules) > 1:
                config.modules.insert(0, 'wafdetect')
                print("WAF detection automatically added for better module coordination")
        
        # Set up max time handler if specified
        max_time_handler = None
        if args.max_time:
            max_time_handler = MaxTimeHandler(args.max_time, scanner)
            max_time_handler.start()
        
        # Start scanning with coordination
        start_time = time.time()
        
        # Print module execution plan
        if hasattr(scanner, 'module_execution_order') and len(config.modules) > 1:
            ordered_modules = [m for m in scanner.module_execution_order if m in config.modules]
            remaining_modules = [m for m in config.modules if m not in ordered_modules]
            all_ordered = ordered_modules + remaining_modules
            
            print(f"Module execution plan ({len(all_ordered)} modules):")
            phase_names = {
                'wafdetect': 'Information Gathering',
                'technology': 'Information Gathering', 
                'dirbrute': 'Infrastructure Discovery',
                'secheaders': 'Security Configuration',
                'sqli': 'Injection Testing',
                'xss': 'Injection Testing',
                'idor': 'Logic Testing',
                'csrf': 'Logic Testing'
            }
            
            current_phase = ""
            for i, module in enumerate(all_ordered[:10]):  # Show first 10
                phase = phase_names.get(module, 'Advanced Testing')
                if phase != current_phase:
                    if current_phase:
                        print()
                    print(f"  Phase: {phase}")
                    current_phase = phase
                print(f"    {i+1}. {module}")
            
            if len(all_ordered) > 10:
                print(f"    ... and {len(all_ordered) - 10} more modules")
            print()
        
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

        # Retest logic: Compare with baseline if --retest flag is set
        retest_manager = None
        if hasattr(args, 'retest') and args.retest:
            print(f"\nRetest mode enabled - comparing with baseline: {args.retest}")
            retest_manager = RetestManager(args.retest)

            # Compare current results with baseline
            comparison = retest_manager.compare_scans(results)

            # Print retest summary
            retest_manager.print_retest_summary()

            # Annotate results with retest status (FIXED/NEW/STILL_VULNERABLE)
            results = retest_manager.get_annotated_results(results)

        # Save current scan as baseline if --save-baseline flag is set
        if hasattr(args, 'save_baseline') and args.save_baseline:
            if not retest_manager:
                retest_manager = RetestManager()

            print(f"\nSaving current scan as baseline: {args.save_baseline}")
            retest_manager.save_current_as_baseline(results, args.save_baseline)

        # Print coordination statistics if available
        if hasattr(scanner, 'shared_module_data') and scanner.shared_module_data:
            print("\nModule Coordination Summary:")
            if 'waf_detected' in scanner.shared_module_data:
                waf_info = scanner.shared_module_data['waf_detected']
                if waf_info['detected']:
                    print(f"  WAF Detection: {', '.join(waf_info['waf_names'])} - bypass mode enabled for subsequent modules")
                else:
                    print("  WAF Detection: No WAF detected - normal payloads used")
            
            if 'technology_detected' in scanner.shared_module_data:
                tech_info = scanner.shared_module_data['technology_detected']
                if tech_info['technologies']:
                    print(f"  Technology Detection: {len(tech_info['technologies'])} technologies found - context-aware testing enabled")
            
            if 'directories_found' in scanner.shared_module_data:
                dir_info = scanner.shared_module_data['directories_found']
                if dir_info['directories']:
                    print(f"  Directory Discovery: {len(dir_info['directories'])} directories found - enhanced path testing enabled")
        
        # Always print results to console first
        scanner.print_results(results)
        
        # Auto-generate report(s) if flag is set
        if args.auto_report:
            import datetime
            timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")

            # Handle multiple targets for filename
            targets = config.get_targets()
            if targets:
                if len(targets) > 1:
                    target_name = "_".join([t.replace(':', '_').replace('/', '_').replace('\\', '_').replace('?', '_').replace('=', '_').replace('&', '_') for t in targets[:3]])
                    if len(targets) > 3:
                        target_name += f"_and_{len(targets)-3}_more"
                else:
                    target_name = targets[0].replace(':', '_').replace('/', '_').replace('\\', '_').replace('?', '_').replace('=', '_').replace('&', '_')
            else:
                target_name = "unknown_target"

            # Limit filename length to avoid errors
            if len(target_name) > 150:
                target_name = target_name[:150]
            
            base_filename = f"scan_report_{target_name}_{timestamp}"
            
            report_formats = [f.strip() for f in args.format.split(',')]
            
            for report_format in report_formats:
                auto_filename = f"{base_filename}.{report_format}"
                try:
                    report_mode = getattr(args, 'report_mode', 'full')
                    scanner.save_report(results, auto_filename, report_format, report_mode)
                    print(f"\n{report_format.upper()} report saved to {auto_filename} (mode: {report_mode})")
                except Exception as e:
                    print(f"Error saving {report_format.upper()} auto-report: {e}")
        
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
