"""
Centralized result management and aggregation
"""

from typing import List, Dict, Any
from collections import defaultdict
import logging

logger = logging.getLogger(__name__)


class ResultManager:
    """Manages and aggregates scan results"""

    def __init__(self):
        """Initialize result manager"""
        self.results = []
        self.vulnerabilities_by_type = defaultdict(int)
        self.vulnerabilities_by_severity = defaultdict(int)
        self.urls_tested = set()
        self.duplicates_filtered = 0

    def add_result(self, result: Dict[str, Any]) -> bool:
        """
        Add a scan result

        Args:
            result: Result dictionary

        Returns:
            True if result was added, False if duplicate
        """
        # Skip non-vulnerable results unless they contain important info
        if not result.get('vulnerability') and not result.get('info'):
            return False

        # Check for duplicates
        if self._is_duplicate(result):
            self.duplicates_filtered += 1
            logger.debug(f"Filtered duplicate result for {result.get('url')} - {result.get('type')}")
            return False

        self.results.append(result)

        # Update statistics
        if result.get('vulnerability'):
            vuln_type = result.get('type', 'Unknown')
            severity = result.get('severity', 'Medium')
            self.vulnerabilities_by_type[vuln_type] += 1
            self.vulnerabilities_by_severity[severity] += 1

        # Track tested URL
        if result.get('url'):
            self.urls_tested.add(result['url'])

        return True

    def add_results(self, results: List[Dict[str, Any]]) -> int:
        """
        Add multiple results

        Args:
            results: List of result dictionaries

        Returns:
            Number of results added
        """
        added = 0
        for result in results:
            if self.add_result(result):
                added += 1
        return added

    def _is_duplicate(self, new_result: Dict[str, Any]) -> bool:
        """
        Check if result is a duplicate

        Args:
            new_result: Result to check

        Returns:
            True if duplicate exists
        """
        # Create signature for comparison
        new_sig = self._create_signature(new_result)

        for existing in self.results:
            existing_sig = self._create_signature(existing)
            if new_sig == existing_sig:
                return True

        return False

    def _create_signature(self, result: Dict[str, Any]) -> tuple:
        """
        Create a unique signature for a result

        Args:
            result: Result dictionary

        Returns:
            Tuple signature
        """
        # Passive findings (missing headers, cookies, etc.) should deduplicate by type only
        # e.g., "Missing X-Frame-Options" should appear once, not for every URL
        passive_types = {
            'missing_security_header',
            'insecure_cookie',
            'accessible_cookie',
            'information_disclosure',
            'version_disclosure',
            'technology_detected'
        }

        result_type = result.get('type', '')

        # For passive findings: signature by type + specific detail (header/cookie name)
        if result_type in passive_types:
            return (
                result_type,
                result.get('header', ''),
                result.get('cookie', ''),
                result.get('value', '')  # For information disclosure values
            )

        # For active findings: signature includes URL, parameter, payload
        return (
            result.get('url', ''),
            result.get('type', ''),
            result.get('parameter', ''),
            result.get('payload', ''),
            result.get('vulnerability', False)
        )

    def get_all_results(self) -> List[Dict[str, Any]]:
        """Get all results"""
        return self.results.copy()

    def get_vulnerabilities(self) -> List[Dict[str, Any]]:
        """Get only vulnerable findings"""
        return [r for r in self.results if r.get('vulnerability')]

    def get_by_severity(self, severity: str) -> List[Dict[str, Any]]:
        """
        Get results by severity

        Args:
            severity: Severity level (Critical, High, Medium, Low, Info)

        Returns:
            List of results with matching severity
        """
        return [r for r in self.results if r.get('severity') == severity]

    def get_by_type(self, vuln_type: str) -> List[Dict[str, Any]]:
        """
        Get results by vulnerability type

        Args:
            vuln_type: Vulnerability type (XSS, SQLi, etc.)

        Returns:
            List of results with matching type
        """
        return [r for r in self.results if r.get('type', '').lower() == vuln_type.lower()]

    def get_statistics(self) -> Dict[str, Any]:
        """
        Get scan statistics

        Returns:
            Dictionary with statistics
        """
        total_vulns = sum(1 for r in self.results if r.get('vulnerability'))

        return {
            'total_results': len(self.results),
            'total_vulnerabilities': total_vulns,
            'urls_tested': len(self.urls_tested),
            'duplicates_filtered': self.duplicates_filtered,
            'by_type': dict(self.vulnerabilities_by_type),
            'by_severity': dict(self.vulnerabilities_by_severity),
            'severity_breakdown': {
                'Critical': self.vulnerabilities_by_severity.get('Critical', 0),
                'High': self.vulnerabilities_by_severity.get('High', 0),
                'Medium': self.vulnerabilities_by_severity.get('Medium', 0),
                'Low': self.vulnerabilities_by_severity.get('Low', 0),
                'Info': self.vulnerabilities_by_severity.get('Info', 0),
            }
        }

    def clear(self):
        """Clear all results"""
        self.results.clear()
        self.vulnerabilities_by_type.clear()
        self.vulnerabilities_by_severity.clear()
        self.urls_tested.clear()
        self.duplicates_filtered = 0

    def print_summary(self):
        """Print a summary of results"""
        stats = self.get_statistics()

        print("\n" + "="*80)
        print("SCAN SUMMARY")
        print("="*80)
        print(f"Total Findings: {stats['total_results']}")
        print(f"Vulnerabilities: {stats['total_vulnerabilities']}")
        print(f"URLs Tested: {stats['urls_tested']}")
        print(f"Duplicates Filtered: {stats['duplicates_filtered']}")

        if stats['by_severity']:
            print("\nBy Severity:")
            for severity in ['Critical', 'High', 'Medium', 'Low', 'Info']:
                count = stats['severity_breakdown'].get(severity, 0)
                if count > 0:
                    print(f"  {severity}: {count}")

        if stats['by_type']:
            print("\nBy Type:")
            for vuln_type, count in sorted(stats['by_type'].items(), key=lambda x: x[1], reverse=True):
                print(f"  {vuln_type}: {count}")
        print("="*80 + "\n")
