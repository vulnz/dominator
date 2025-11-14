"""
Retest Manager - Tracks fixed vulnerabilities between scans
Автоматически сравнивает результаты и помечает FIXED/NEW/STILL_VULNERABLE
"""

import json
import os
from typing import List, Dict, Any, Tuple
from pathlib import Path
from datetime import datetime
from core.logger import get_logger

logger = get_logger(__name__)


class RetestManager:
    """Manages vulnerability retest tracking"""

    def __init__(self, baseline_file: str = None):
        """
        Initialize retest manager

        Args:
            baseline_file: Path to baseline scan results (JSON)
        """
        self.baseline_file = baseline_file
        self.baseline_vulns = []
        self.comparison_result = None

        if baseline_file:
            self._load_baseline()

    def _load_baseline(self):
        """Load baseline scan results"""
        if not os.path.exists(self.baseline_file):
            logger.error(f"Baseline file not found: {self.baseline_file}")
            return

        try:
            with open(self.baseline_file, 'r', encoding='utf-8') as f:
                baseline_data = json.load(f)

            # Extract vulnerabilities from baseline
            self.baseline_vulns = baseline_data.get('results', [])
            if not self.baseline_vulns:
                self.baseline_vulns = baseline_data.get('vulnerabilities', [])

            logger.info(f"Loaded {len(self.baseline_vulns)} vulnerabilities from baseline")

        except Exception as e:
            logger.error(f"Error loading baseline: {e}")

    def compare_scans(self, current_results: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Compare current scan results with baseline

        Args:
            current_results: Current scan results

        Returns:
            Comparison summary with FIXED/NEW/STILL_VULNERABLE counts
        """
        if not self.baseline_vulns:
            logger.warning("No baseline loaded, cannot perform retest comparison")
            return {
                'fixed': [],
                'new': current_results,
                'still_vulnerable': [],
                'summary': {
                    'fixed_count': 0,
                    'new_count': len(current_results),
                    'still_vulnerable_count': 0,
                    'total_baseline': 0,
                    'total_current': len(current_results)
                }
            }

        # Create signature maps for comparison
        baseline_map = {}
        for vuln in self.baseline_vulns:
            if vuln.get('vulnerability', False):  # Only compare actual vulnerabilities
                sig = self._create_signature(vuln)
                baseline_map[sig] = vuln

        current_map = {}
        for vuln in current_results:
            if vuln.get('vulnerability', False):
                sig = self._create_signature(vuln)
                current_map[sig] = vuln

        # Find FIXED vulnerabilities (in baseline but not in current)
        fixed = []
        for sig, baseline_vuln in baseline_map.items():
            if sig not in current_map:
                fixed_vuln = baseline_vuln.copy()
                fixed_vuln['retest_status'] = 'FIXED'
                fixed_vuln['fixed_date'] = datetime.now().isoformat()
                fixed.append(fixed_vuln)

        # Find NEW vulnerabilities (in current but not in baseline)
        new = []
        for sig, current_vuln in current_map.items():
            if sig not in baseline_map:
                new_vuln = current_vuln.copy()
                new_vuln['retest_status'] = 'NEW'
                new_vuln['discovered_date'] = datetime.now().isoformat()
                new.append(new_vuln)

        # Find STILL_VULNERABLE (in both baseline and current)
        still_vulnerable = []
        for sig in baseline_map.keys():
            if sig in current_map:
                vuln = current_map[sig].copy()
                vuln['retest_status'] = 'STILL_VULNERABLE'
                vuln['first_seen'] = baseline_map[sig].get('timestamp', 'Unknown')
                vuln['last_seen'] = datetime.now().isoformat()
                still_vulnerable.append(vuln)

        self.comparison_result = {
            'fixed': fixed,
            'new': new,
            'still_vulnerable': still_vulnerable,
            'summary': {
                'fixed_count': len(fixed),
                'new_count': len(new),
                'still_vulnerable_count': len(still_vulnerable),
                'total_baseline': len(baseline_map),
                'total_current': len(current_map),
                'fix_rate': (len(fixed) / len(baseline_map) * 100) if len(baseline_map) > 0 else 0
            }
        }

        logger.info(f"Retest comparison complete:")
        logger.info(f"  FIXED: {len(fixed)}")
        logger.info(f"  NEW: {len(new)}")
        logger.info(f"  STILL VULNERABLE: {len(still_vulnerable)}")

        return self.comparison_result

    def _create_signature(self, vuln: Dict[str, Any]) -> str:
        """
        Create unique signature for vulnerability comparison

        Args:
            vuln: Vulnerability dictionary

        Returns:
            Unique signature string
        """
        # Use URL + type + parameter for signature
        # This allows us to track the same vuln across scans
        url = vuln.get('url', '')
        vuln_type = vuln.get('type', '')
        parameter = vuln.get('parameter', '')
        module = vuln.get('module', '')

        # Normalize URL (remove query params for comparison)
        if '?' in url:
            url = url.split('?')[0]

        return f"{url}|{module}|{vuln_type}|{parameter}"

    def generate_retest_report(self, output_file: str):
        """
        Generate retest comparison report

        Args:
            output_file: Output file path
        """
        if not self.comparison_result:
            logger.error("No comparison result available")
            return

        report_data = {
            'retest_date': datetime.now().isoformat(),
            'baseline_file': self.baseline_file,
            'summary': self.comparison_result['summary'],
            'fixed': self.comparison_result['fixed'],
            'new': self.comparison_result['new'],
            'still_vulnerable': self.comparison_result['still_vulnerable']
        }

        # Save JSON report
        json_file = output_file.replace('.html', '_retest.json')
        with open(json_file, 'w', encoding='utf-8') as f:
            json.dump(report_data, f, indent=2, ensure_ascii=False)

        logger.info(f"Retest report saved: {json_file}")

    def get_annotated_results(self, current_results: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Annotate current results with retest status

        Args:
            current_results: Current scan results

        Returns:
            Results with retest_status added
        """
        if not self.comparison_result:
            # If no comparison, return results as-is with NEW status
            for result in current_results:
                if result.get('vulnerability', False):
                    result['retest_status'] = 'NEW'
            return current_results

        # Create map of current results by signature
        annotated = []
        for result in current_results:
            if not result.get('vulnerability', False):
                # Non-vulnerabilities get no status
                annotated.append(result)
                continue

            sig = self._create_signature(result)

            # Check if STILL_VULNERABLE
            if any(self._create_signature(v) == sig for v in self.comparison_result['still_vulnerable']):
                result['retest_status'] = 'STILL_VULNERABLE'
                # Find original first_seen
                for sv in self.comparison_result['still_vulnerable']:
                    if self._create_signature(sv) == sig:
                        result['first_seen'] = sv.get('first_seen', 'Unknown')
                        break

            # Check if NEW
            elif any(self._create_signature(v) == sig for v in self.comparison_result['new']):
                result['retest_status'] = 'NEW'

            else:
                result['retest_status'] = 'UNKNOWN'

            annotated.append(result)

        # Add FIXED vulnerabilities to results (they won't be in current scan)
        for fixed_vuln in self.comparison_result['fixed']:
            annotated.append(fixed_vuln)

        return annotated

    def print_retest_summary(self):
        """Print retest summary to console"""
        if not self.comparison_result:
            return

        summary = self.comparison_result['summary']

        print("\n" + "="*80)
        print("RETEST COMPARISON SUMMARY")
        print("="*80)
        print(f"Baseline: {self.baseline_file}")
        print(f"Baseline vulnerabilities: {summary['total_baseline']}")
        print(f"Current vulnerabilities: {summary['total_current']}")
        print()
        print(f"✅ FIXED: {summary['fixed_count']}")
        print(f"🆕 NEW: {summary['new_count']}")
        print(f"⚠️  STILL VULNERABLE: {summary['still_vulnerable_count']}")
        print()
        print(f"Fix Rate: {summary['fix_rate']:.1f}%")
        print("="*80 + "\n")

        if summary['fixed_count'] > 0:
            print("Fixed Vulnerabilities:")
            for i, fixed in enumerate(self.comparison_result['fixed'][:10], 1):
                print(f"  {i}. [{fixed.get('type')}] {fixed.get('url')} - {fixed.get('parameter', 'N/A')}")
            if len(self.comparison_result['fixed']) > 10:
                print(f"  ... and {len(self.comparison_result['fixed']) - 10} more")
            print()

    def save_current_as_baseline(self, current_results: List[Dict[str, Any]], output_file: str):
        """
        Save current scan as baseline for future retests

        Args:
            current_results: Current scan results
            output_file: Output file path
        """
        baseline_data = {
            'scan_date': datetime.now().isoformat(),
            'total_results': len(current_results),
            'vulnerabilities': [r for r in current_results if r.get('vulnerability')],
            'results': current_results
        }

        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(baseline_data, f, indent=2, ensure_ascii=False)

        logger.info(f"Baseline saved: {output_file}")
