"""
Formula Injection Scanner Module

Detects CSV/Excel Formula Injection vulnerabilities by:
1. Testing if formula characters (=, +, -, @) are accepted in input
2. Checking if formulas are reflected without sanitization
3. Looking for export/download functionality that might generate spreadsheets
4. Detecting lack of formula sanitization in data display
"""

from typing import List, Dict, Any
from core.base_module import BaseModule
from detectors.base_detector import BaseDetector
from core.logger import get_logger
import re

logger = get_logger(__name__)


class FormulaInjectionModule(BaseModule):
    """Formula Injection vulnerability scanner module"""

    def __init__(self, module_path: str):
        """Initialize Formula Injection module"""
        super().__init__(module_path)

        # Formula starters that spreadsheet apps execute
        self.formula_starters = ['=', '+', '-', '@', '|', '%']

        # Export/download indicators in URLs/forms
        self.export_keywords = [
            'export', 'download', 'csv', 'excel', 'xls', 'xlsx',
            'spreadsheet', 'report', 'data', 'extract'
        ]

        logger.info(f"Formula Injection module loaded: {len(self.payloads)} payloads")

    def scan(self, targets: List[Dict[str, Any]], http_client: Any) -> List[Dict[str, Any]]:
        """
        Scan for Formula Injection vulnerabilities

        Args:
            targets: List of URLs with parameters
            http_client: HTTP client

        Returns:
            List of results
        """
        results = []

        logger.info(f"Starting Formula Injection scan on {len(targets)} targets")

        # Prioritize targets with export/download functionality
        export_targets = []
        other_targets = []

        for target in targets:
            url = target.get('url', '').lower()
            params = target.get('params', {})

            # Check if URL or params suggest export functionality
            has_export = any(keyword in url for keyword in self.export_keywords)
            if not has_export and params:
                param_str = ' '.join(params.keys()).lower()
                has_export = any(keyword in param_str for keyword in self.export_keywords)

            if has_export:
                export_targets.append(target)
            else:
                other_targets.append(target)

        prioritized = export_targets + other_targets
        logger.info(f"Prioritized {len(export_targets)} export targets, {len(other_targets)} other targets")

        for target in prioritized[:50]:  # Test first 50 targets
            url = target.get('url')
            params = target.get('params', {})
            method = target.get('method', 'GET').upper()

            if not params:
                continue

            # Get baseline response
            if method == 'POST':
                baseline_response = http_client.post(url, data=params)
            else:
                baseline_response = http_client.get(url, params=params)

            if not baseline_response:
                continue

            baseline_text = getattr(baseline_response, 'text', '')

            # Test each parameter
            for param_name in params:
                logger.debug(f"Testing Formula Injection in parameter: {param_name} via {method}")

                # Try formula payloads
                for payload in self.payloads[:10]:  # Test first 10 payloads
                    test_params = params.copy()
                    test_params[param_name] = payload

                    # Send request
                    if method == 'POST':
                        response = http_client.post(url, data=test_params)
                    else:
                        response = http_client.get(url, params=test_params)

                    if not response:
                        continue

                    # Detect Formula Injection
                    detected, confidence, evidence = self._detect_formula_injection(
                        payload, response, baseline_text, url
                    )

                    if detected:
                        result = self.create_result(
                            vulnerable=True,
                            url=url,
                            parameter=param_name,
                            payload=payload,
                            evidence=evidence,
                            description="Formula Injection vulnerability detected. "
                                      "Application accepts formula input without sanitization. "
                                      "When exported to CSV/Excel, formulas may execute.",
                            confidence=confidence
                        )

                        # Add metadata
                        result['cwe'] = self.config.get('cwe', 'CWE-1236')
                        result['owasp'] = self.config.get('owasp', 'A03:2021')
                        result['cvss'] = self.config.get('cvss', '7.8')

                        results.append(result)
                        logger.info(f"✓ Formula Injection found in {url} "
                                  f"(parameter: {param_name}, confidence: {confidence:.2f})")

                        # Move to next parameter
                        break

        logger.info(f"Formula Injection scan complete: {len(results)} vulnerabilities found")
        return results

    def _detect_formula_injection(self, payload: str, response: Any,
                                  baseline_text: str, url: str) -> tuple:
        """
        Detect Formula Injection vulnerability

        Returns:
            (detected: bool, confidence: float, evidence: str)
        """
        response_text = getattr(response, 'text', '')

        # Check if payload is a formula
        if not any(payload.startswith(starter) for starter in self.formula_starters):
            return False, 0.0, ""

        # METHOD 1: Direct reflection without escaping
        # Check if formula is reflected exactly as-is
        if payload in response_text:
            confidence = 0.65

            # Check if it's in a dangerous context (table, data display, etc.)
            if self._is_in_data_context(payload, response_text):
                confidence = 0.75

            # Higher confidence if page has export functionality
            if any(keyword in url.lower() for keyword in self.export_keywords):
                confidence = 0.85

            # Check if formula is in HTML without escaping
            if self._is_unescaped_in_html(payload, response_text):
                confidence = 0.80

            evidence = f"Formula payload '{payload}' reflected without sanitization. "
            if any(keyword in url.lower() for keyword in self.export_keywords):
                evidence += "Page has export/download functionality. "
            evidence += "If data is exported to CSV/Excel, formula will execute. "
            evidence += BaseDetector.get_evidence(payload, response_text, context_size=150)

            return True, confidence, evidence

        # METHOD 2: Escaped but potentially vulnerable
        # Check if formula is HTML-escaped but still present
        escaped_forms = [
            payload.replace('=', '&#61;'),
            payload.replace('=', '&equals;'),
            payload.replace('<', '&lt;').replace('>', '&gt;'),
        ]

        for escaped in escaped_forms:
            if escaped in response_text:
                confidence = 0.60

                # Still vulnerable if exported to CSV
                if any(keyword in url.lower() for keyword in self.export_keywords):
                    confidence = 0.70

                evidence = f"Formula payload HTML-escaped but present in response. "
                evidence += "While safe in browser, may execute if exported to spreadsheet. "
                evidence += f"Found: '{escaped[:50]}...'"

                return True, confidence, evidence

        # METHOD 3: Stored formula detection
        # Check if there's any formula-like content in response
        formula_patterns = [
            r'=\w+\(',           # =FUNCTION(
            r'=\d+[+\-*/]\d+',   # =1+1
            r'@\w+\(',           # @FUNCTION(
            r'\|=',              # |=
        ]

        for pattern in formula_patterns:
            matches = re.findall(pattern, response_text)
            if matches and pattern not in baseline_text:
                # New formula content appeared
                confidence = 0.55

                if len(matches) >= 2:
                    confidence = 0.65

                evidence = f"Formula-like content detected in response: {matches[:3]}. "
                evidence += "Application may store and display formulas without sanitization."

                return True, confidence, evidence

        return False, 0.0, ""

    def _is_in_data_context(self, payload: str, response_text: str) -> bool:
        """
        Check if payload is in data display context (table, list, etc.)

        Args:
            payload: The payload
            response_text: Response HTML

        Returns:
            True if in data context
        """
        # Find payload position
        pos = response_text.find(payload)
        if pos == -1:
            return False

        # Get surrounding context (500 chars before and after)
        start = max(0, pos - 500)
        end = min(len(response_text), pos + len(payload) + 500)
        context = response_text[start:end].lower()

        # Check for table context
        table_indicators = ['<table', '<tr>', '<td>', '</td>', '<th>']
        if any(indicator in context for indicator in table_indicators):
            return True

        # Check for list context
        list_indicators = ['<ul>', '<li>', '<ol>', '</li>']
        if any(indicator in context for indicator in list_indicators):
            return True

        # Check for data display elements
        data_indicators = ['<div class="data', '<div class="row', '<span class="value']
        if any(indicator in context for indicator in data_indicators):
            return True

        return False

    def _is_unescaped_in_html(self, payload: str, response_text: str) -> bool:
        """
        Check if payload appears unescaped in HTML

        Args:
            payload: The payload
            response_text: Response HTML

        Returns:
            True if unescaped
        """
        # If payload contains = or other special chars, check if they're escaped
        if '=' in payload:
            # Check if = is escaped
            if payload in response_text:
                # = is not escaped if exact payload found
                return True
            elif '&#61;' in response_text or '&equals;' in response_text:
                # = is escaped
                return False

        return payload in response_text


def get_module(module_path: str):
    """Create module instance"""
    return FormulaInjectionModule(module_path)
