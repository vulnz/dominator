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
        # Use subprocess with CREATE_NO_WINDOW and NO shell=True to avoid window flash
        import subprocess
        # Use cmd.exe directly instead of shell=True to prevent window
        startupinfo = subprocess.STARTUPINFO()
        startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
        startupinfo.wShowWindow = 0  # SW_HIDE
        subprocess.run(
            ['cmd.exe', '/c', 'chcp', '65001'],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            creationflags=0x08000000,  # CREATE_NO_WINDOW
            startupinfo=startupinfo
        )
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
        self.start_time = time.time()

    def timeout_handler(self):
        """Handle max time timeout"""
        self.stopped = True
        elapsed = (time.time() - self.start_time) / 60
        print(f"\n{'='*80}")
        print(f"MAXIMUM SCAN TIME REACHED: {self.max_minutes} minutes")
        print(f"Actual elapsed time: {elapsed:.1f} minutes")
        print(f"Stopping scan and generating report with current results...")
        print(f"{'='*80}\n")

        # Set flags to stop scanner and all modules
        if hasattr(self.scanner, 'stop_requested'):
            self.scanner.stop_requested = True

        # Set global module stop flag
        try:
            from core.base_module import BaseModule
            BaseModule.set_global_stop(True)
        except Exception as e:
            print(f"Warning: Could not set module stop flag: {e}")
    
    def start(self):
        """Start max time timer"""
        if self.max_minutes:
            self.start_time = time.time()
            timeout_seconds = self.max_minutes * 60
            self.timer = threading.Timer(timeout_seconds, self.timeout_handler)
            self.timer.daemon = True  # Ensure timer thread doesn't prevent exit
            self.timer.start()
            print(f"{'='*80}")
            print(f"TIMEOUT ENFORCEMENT ENABLED")
            print(f"Maximum scan time: {self.max_minutes} minutes ({timeout_seconds} seconds)")
            print(f"Scan will be forcibly stopped after this time")
            print(f"{'='*80}\n")
    
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

def launch_gui(args):
    """Launch GUI with optional pre-configured parameters"""
    try:
        from PyQt5.QtWidgets import QApplication
        from pathlib import Path

        # Add GUI directory to path
        gui_path = Path(__file__).parent / 'GUI'
        if str(gui_path) not in sys.path:
            sys.path.insert(0, str(gui_path))

        # Import GUI
        from dominator_gui import DominatorGUI

        # Create QApplication
        app = QApplication(sys.argv)
        gui = DominatorGUI()

        # Pre-configure GUI from CLI arguments
        if args.target:
            gui.target_input.setPlainText('\n'.join(args.target))

        if args.file:
            gui.target_file_input.setText(args.file)

        # Configure modules
        if args.all:
            gui.all_modules_cb.setChecked(True)
        elif args.modules:
            # Parse module list
            module_names = [m.strip() for m in args.modules.split(',')]
            # Select specific modules in GUI
            for i in range(gui.module_list.count()):
                item = gui.module_list.item(i)
                module_folder = item.data(256)  # Qt.UserRole (stores folder name as string)
                if module_folder and module_folder in module_names:
                    item.setCheckState(2)  # Qt.Checked

        # Configure HTTP options
        if args.headers:
            gui.headers_input.setPlainText('\n'.join(args.headers))

        if args.cookies:
            gui.cookies_input.setText(args.cookies)

        if args.proxy:
            gui.proxy_input.setText(args.proxy)

        # Configure advanced options
        if args.threads:
            gui.threads_spin.setValue(args.threads)

        if args.timeout:
            gui.timeout_spin.setValue(args.timeout)

        if args.delay:
            gui.delay_spin.setValue(args.delay)

        if hasattr(args, 'max_crawl_pages'):
            gui.max_crawl_spin.setValue(args.max_crawl_pages)

        # Set flags
        if hasattr(args, 'nocrawl') and args.nocrawl:
            gui.single_page_checkbox.setChecked(True)

        if hasattr(args, 'rotate_agent') and args.rotate_agent:
            gui.rotate_agent_cb.setChecked(True)

        if hasattr(args, 'recon_only') and args.recon_only:
            gui.recon_only_cb.setChecked(True)

        # Auto-start scan if requested and target is specified
        if args.auto_start and (args.target or args.file):
            print("Auto-starting scan...")
            # Use QTimer to start scan after GUI is shown
            from PyQt5.QtCore import QTimer
            QTimer.singleShot(500, gui.start_scan)

        # Show GUI
        gui.show()

        # Run application
        sys.exit(app.exec_())

    except ImportError as e:
        print(f"Error: PyQt5 not installed. Install with: pip install PyQt5")
        print(f"Details: {e}")
        sys.exit(1)
    except Exception as e:
        print(f"Error launching GUI: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)

def main():
    """Main function"""
    global shutdown_requested
    shutdown_requested = False

    # Set up signal handler for immediate Ctrl+C exit
    signal.signal(signal.SIGINT, signal_handler)

    parser = create_parser()
    args = parser.parse_args()

    # Launch GUI if --gui flag is present
    if args.gui:
        launch_gui(args)
        return

    # Launch Terminal Wizard if --wizard flag is present
    wizard_used = False
    if getattr(args, 'wizard', False):
        from utils.terminal_wizard import run_wizard
        wizard_args = run_wizard()
        # Re-parse with wizard-generated arguments
        args = parser.parse_args(wizard_args)
        args = process_args(args)
        wizard_used = True

    # Print banner
    print_banner()

    # Setup logging
    setup_logging(level='INFO', verbose=getattr(args, 'verbose', False))

    # Show modules and exit
    if args.modules_list:
        show_modules()
        return


    # Check required parameters
    # API spec can be used instead of target
    api_spec = getattr(args, 'api_spec', None)
    if not args.target and not args.file and not api_spec:
        print("Error: Must specify target (-t), targets file (-f), or API spec (--api)")
        parser.print_help()
        sys.exit(1)

    # Process arguments using menu module (skip if wizard already processed)
    if not wizard_used:
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

        # FIXED: WAF detection is a passive detector, not a module
        # If only WAF detection is requested, adjust config
        if getattr(args, 'waf_detect', False):
            config.modules = ['security_headers']  # Lightweight module to trigger WAF detection
            config.nopassive = False  # Enable passive detection for WAF detector

        # Enable module coordination for conflict prevention
        if hasattr(config, 'enable_module_coordination') and config.enable_module_coordination:
            print("Module coordination enabled - optimizing execution order to prevent conflicts")
        
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

            # Use reports/ directory for output
            import os
            reports_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'reports')
            os.makedirs(reports_dir, exist_ok=True)
            base_filename = os.path.join(reports_dir, f"scan_report_{target_name}_{timestamp}")
            
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

        # FIXED: Generate reports even when scan is stopped/interrupted
        if 'results' in locals() and results and args.auto_report:
            print("\n[*] Generating partial scan reports...")
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

            # Use reports/ directory for output
            reports_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'reports')
            os.makedirs(reports_dir, exist_ok=True)
            base_filename = os.path.join(reports_dir, f"scan_report_PARTIAL_{target_name}_{timestamp}")

            report_formats = [f.strip() for f in args.format.split(',')]

            for report_format in report_formats:
                auto_filename = f"{base_filename}.{report_format}"
                try:
                    report_mode = getattr(args, 'report_mode', 'full')
                    scanner.save_report(results, auto_filename, report_format, report_mode)
                    print(f"[+] Partial {report_format.upper()} report saved to {auto_filename}")
                except Exception as e:
                    print(f"[!] Error saving partial {report_format.upper()} report: {e}")

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
