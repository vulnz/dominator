#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Multi-Target Scanner
Scans multiple targets and creates a consolidated report
"""

import sys
import os
import time
import argparse
from datetime import datetime
from typing import List, Dict, Any

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from core.clean_scanner import ModularScanner
from core.config import Config
from core.logger import setup_logging, get_logger

logger = get_logger(__name__)


class MultiTargetScanner:
    """Scanner for multiple targets with consolidated reporting"""

    def __init__(self, targets: List[str], args):
        """
        Initialize multi-target scanner

        Args:
            targets: List of target URLs
            args: Command line arguments
        """
        self.targets = targets
        self.args = args
        self.all_results = []
        self.scan_summary = {
            'total_targets': len(targets),
            'successful_scans': 0,
            'failed_scans': 0,
            'total_vulnerabilities': 0,
            'start_time': datetime.now(),
            'end_time': None,
            'target_results': {}
        }

    def scan_all_targets(self) -> Dict[str, Any]:
        """
        Scan all targets and collect results

        Returns:
            Dictionary with consolidated results
        """
        logger.info(f"Starting multi-target scan of {len(self.targets)} targets")
        logger.info(f"Targets: {', '.join(self.targets)}")

        for idx, target in enumerate(self.targets, 1):
            logger.info(f"\n{'='*80}")
            logger.info(f"Scanning Target {idx}/{len(self.targets)}: {target}")
            logger.info(f"{'='*80}")

            try:
                # Update args with current target
                self.args.target = target

                # Create config and scanner
                config = Config(self.args)
                scanner = ModularScanner(config)

                # Run scan
                target_results = scanner.scan()

                # Store results
                self.all_results.extend(target_results)

                # Update summary
                vuln_count = sum(1 for r in target_results if r.get('vulnerable', False))
                self.scan_summary['target_results'][target] = {
                    'status': 'success',
                    'vulnerabilities': vuln_count,
                    'total_findings': len(target_results)
                }
                self.scan_summary['successful_scans'] += 1
                self.scan_summary['total_vulnerabilities'] += vuln_count

                logger.info(f"✓ Target scan complete: {vuln_count} vulnerabilities found")

            except Exception as e:
                logger.error(f"✗ Failed to scan {target}: {e}")
                self.scan_summary['target_results'][target] = {
                    'status': 'failed',
                    'error': str(e)
                }
                self.scan_summary['failed_scans'] += 1

        self.scan_summary['end_time'] = datetime.now()

        return self.scan_summary

    def generate_consolidated_report(self, output_file: str = None, format: str = 'txt'):
        """
        Generate consolidated report for all targets

        Args:
            output_file: Output file path (optional)
            format: Report format (txt, html, json)
        """
        from core.report_generator import ReportGenerator

        if not output_file:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            output_file = f"multi_target_scan_{timestamp}"

        # Generate report with all results
        report_gen = ReportGenerator()

        # Add multi-target summary to metadata
        report_gen.metadata['multi_target_summary'] = self.scan_summary

        if format in ['txt', 'text']:
            report_path = report_gen.generate_text_report(output_file)
            logger.info(f"Text report generated: {report_path}")

        if format in ['html', 'both']:
            report_path = report_gen.generate_html_report(output_file)
            logger.info(f"HTML report generated: {report_path}")

        if format == 'json':
            report_path = report_gen.generate_json_report(output_file)
            logger.info(f"JSON report generated: {report_path}")

        # Print summary
        self._print_summary()

    def _print_summary(self):
        """Print scan summary to console"""
        logger.info(f"\n{'='*80}")
        logger.info("MULTI-TARGET SCAN SUMMARY")
        logger.info(f"{'='*80}")
        logger.info(f"Total Targets: {self.scan_summary['total_targets']}")
        logger.info(f"Successful Scans: {self.scan_summary['successful_scans']}")
        logger.info(f"Failed Scans: {self.scan_summary['failed_scans']}")
        logger.info(f"Total Vulnerabilities: {self.scan_summary['total_vulnerabilities']}")

        duration = self.scan_summary['end_time'] - self.scan_summary['start_time']
        logger.info(f"Total Duration: {duration}")

        logger.info(f"\nPer-Target Results:")
        for target, result in self.scan_summary['target_results'].items():
            if result['status'] == 'success':
                logger.info(f"  ✓ {target}: {result['vulnerabilities']} vulnerabilities")
            else:
                logger.info(f"  ✗ {target}: FAILED - {result.get('error', 'Unknown error')}")

        logger.info(f"{'='*80}\n")


def main():
    """Main function for multi-target scanning"""
    parser = argparse.ArgumentParser(
        description='Multi-Target Web Vulnerability Scanner',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Scan multiple targets from command line
  python multi_target_scan.py -t http://target1.com http://target2.com http://target3.com

  # Scan targets from file
  python multi_target_scan.py -f targets.txt

  # Scan with specific modules and generate HTML report
  python multi_target_scan.py -f targets.txt -m xss,sqli --format html

  # Scan with custom output file
  python multi_target_scan.py -t http://example1.com http://example2.com -o my_scan_report
        """
    )

    # Target specification
    target_group = parser.add_mutually_exclusive_group(required=True)
    target_group.add_argument('-t', '--targets', nargs='+', help='Target URLs (space-separated)')
    target_group.add_argument('-f', '--file', help='File containing target URLs (one per line)')

    # HTTP parameters (Config expects these)
    parser.add_argument('-H', '--headers', action='append', help='HTTP headers (can be used multiple times)')
    parser.add_argument('-hf', '--headers-file', help='File with HTTP headers')
    parser.add_argument('-c', '--cookies', help='HTTP cookies')
    parser.add_argument('-a', '--auth', choices=['jwt', 'basic'], help='Authorization type')

    # Scanning options
    parser.add_argument('-m', '--modules', help='Comma-separated list of modules to run')
    parser.add_argument('--all', action='store_true', help='Use all available modules')
    parser.add_argument('--max-crawl-pages', type=int, default=30, help='Maximum pages to crawl per target')
    parser.add_argument('--threads', type=int, default=5, help='Number of threads')
    parser.add_argument('--timeout', type=int, default=10, help='Request timeout in seconds')
    parser.add_argument('--exclude', help='Exclude paths from scanning (comma separated)')
    parser.add_argument('--single-url', action='store_true', help='Scan only the specified URL without crawling')
    parser.add_argument('--nocrawl', action='store_true', help='Disable web crawling completely')
    parser.add_argument('--limit', type=int, default=10000, help='Maximum number of requests')
    parser.add_argument('--page-limit', type=int, help='Page limit for scanning')
    parser.add_argument('--filetree', action='store_true', help='File/directory discovery mode')

    # Report options
    parser.add_argument('-o', '--output', help='Output file name (without extension)')
    parser.add_argument('--format', default='txt', choices=['txt', 'html', 'json', 'both'],
                        help='Report format')

    # Other options
    parser.add_argument('--verbose', action='store_true', help='Verbose output')
    parser.add_argument('--no-crawl', action='store_true', help='Disable crawling, test only provided URLs')

    args = parser.parse_args()

    # Setup logging
    setup_logging(verbose=args.verbose)

    # Get list of targets
    if args.targets:
        targets = args.targets
    else:
        # Read from file
        if not os.path.exists(args.file):
            logger.error(f"Target file not found: {args.file}")
            sys.exit(1)

        with open(args.file, 'r') as f:
            targets = [line.strip() for line in f if line.strip() and not line.startswith('#')]

    if not targets:
        logger.error("No targets specified")
        sys.exit(1)

    # Validate targets
    valid_targets = []
    for target in targets:
        if not target.startswith(('http://', 'https://')):
            logger.warning(f"Invalid target (missing protocol): {target}")
        else:
            valid_targets.append(target)

    if not valid_targets:
        logger.error("No valid targets found")
        sys.exit(1)

    logger.info(f"Multi-Target Scanner initialized with {len(valid_targets)} targets")

    # Create scanner
    scanner = MultiTargetScanner(valid_targets, args)

    # Run scans
    summary = scanner.scan_all_targets()

    # Generate report
    scanner.generate_consolidated_report(
        output_file=args.output,
        format=args.format
    )

    logger.info("Multi-target scan complete!")


if __name__ == '__main__':
    main()
