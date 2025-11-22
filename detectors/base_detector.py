"""
Base Detector Class - Universal methods for all detectors
Eliminates code duplication and standardizes detection logic
"""

import re
from typing import List, Tuple, Optional
from utils.payload_loader import PayloadLoader


class BaseDetector:
    """
    Base class for all vulnerability detectors

    Provides universal methods:
    - Evidence extraction
    - Response snippets
    - Pattern compilation
    - Multi-pattern matching
    - Confidence calculation
    """

    @staticmethod
    def get_evidence(pattern: str, response_text: str, context_size: int = 150) -> str:
        """
        Extract evidence from response with context

        Args:
            pattern: Pattern that was found
            response_text: HTTP response text
            context_size: Characters before/after pattern

        Returns:
            Evidence string with context
        """
        if pattern not in response_text:
            return f"Pattern found: {pattern}"

        pos = response_text.find(pattern)
        start = max(0, pos - context_size)
        end = min(len(response_text), pos + len(pattern) + context_size)

        snippet = response_text[start:end]

        # Highlight pattern
        evidence = snippet.replace(pattern, f"**{pattern}**")

        # Clean up
        evidence = evidence.replace('\n', ' ').replace('\r', ' ')
        evidence = ' '.join(evidence.split())  # Remove extra spaces

        return f"Found at position {pos}: ...{evidence}..."

    @staticmethod
    def get_response_snippet(response_text: str, max_length: int = 500) -> str:
        """
        Get truncated response snippet

        Args:
            response_text: Full response text
            max_length: Maximum snippet length

        Returns:
            Truncated response
        """
        if len(response_text) <= max_length:
            return response_text

        return response_text[:max_length] + "... (truncated)"

    @staticmethod
    def compile_patterns(patterns: List[str]) -> List[re.Pattern]:
        """
        Compile regex patterns for efficient matching

        Args:
            patterns: List of regex pattern strings

        Returns:
            List of compiled regex patterns
        """
        compiled = []
        for pattern in patterns:
            try:
                compiled.append(re.compile(pattern, re.IGNORECASE))
            except re.error as e:
                print(f"Warning: Invalid regex pattern '{pattern}': {e}")
        return compiled

    @staticmethod
    def check_multiple_patterns(text: str, patterns: List[str],
                                min_matches: int = 3,
                                case_sensitive: bool = False) -> Tuple[bool, List[str]]:
        """
        Check if multiple patterns exist in text

        Args:
            text: Text to search in
            patterns: List of patterns to find
            min_matches: Minimum number of patterns required
            case_sensitive: Whether matching is case sensitive

        Returns:
            (detected, list of matched patterns)
        """
        matches = []
        search_text = text if case_sensitive else text.lower()

        for pattern in patterns:
            search_pattern = pattern if case_sensitive else pattern.lower()
            if search_pattern in search_text:
                matches.append(pattern)

        return len(matches) >= min_matches, matches

    @staticmethod
    def check_patterns_with_regex(text: str, patterns: List[str],
                                  min_matches: int = 2) -> Tuple[bool, List[str]]:
        """
        Check patterns using regex matching

        Args:
            text: Text to search
            patterns: Regex patterns
            min_matches: Minimum matches required

        Returns:
            (detected, list of matched patterns)
        """
        matches = []
        compiled = BaseDetector.compile_patterns(patterns)

        for i, pattern in enumerate(compiled):
            if pattern.search(text):
                matches.append(patterns[i])

        return len(matches) >= min_matches, matches

    @staticmethod
    def calculate_confidence(indicators_found: int,
                           response_length: int,
                           has_suspicious_words: bool = False,
                           payload_reflected: bool = False) -> float:
        """
        Calculate detection confidence score

        Args:
            indicators_found: Number of vulnerability indicators found
            response_length: Length of response
            has_suspicious_words: Whether response contains suspicious words
            payload_reflected: Whether payload is reflected in response

        Returns:
            Confidence score (0.0 - 1.0)
        """
        confidence = 0.0

        # Each indicator adds confidence
        confidence += min(0.9, indicators_found * 0.25)

        # Response length check (real files vs snippets)
        if 500 < response_length < 100000:
            confidence += 0.1
        elif response_length < 50:
            confidence -= 0.3  # Too short, likely false positive

        # Payload reflection
        if payload_reflected:
            confidence += 0.15

        # Penalty for suspicious words (documentation, examples, etc)
        if has_suspicious_words:
            confidence -= 0.3

        return max(0.0, min(1.0, confidence))

    @staticmethod
    def has_suspicious_words(text: str) -> bool:
        """
        Check if text contains words that indicate false positive

        Args:
            text: Text to check

        Returns:
            True if suspicious words found
        """
        suspicious = [
            'example', 'sample', 'tutorial', 'documentation',
            'demo', 'test case', 'illustration', '<code>',
            'syntax:', 'usage:', 'example code'
        ]

        text_lower = text.lower()
        return any(word in text_lower for word in suspicious)

    @staticmethod
    def validate_response_length(response_text: str,
                                min_length: int = 50,
                                max_length: int = 10000000) -> bool:
        """
        Validate response length is within reasonable bounds

        Args:
            response_text: Response to validate
            min_length: Minimum acceptable length
            max_length: Maximum acceptable length

        Returns:
            True if length is valid
        """
        length = len(response_text)
        return min_length <= length <= max_length

    @staticmethod
    def load_patterns_from_file(pattern_file: str) -> List[str]:
        """
        Load patterns from TXT file using PayloadLoader

        Args:
            pattern_file: Path to pattern file (relative to data/)

        Returns:
            List of patterns
        """
        return PayloadLoader.load_patterns(pattern_file) or []

    @staticmethod
    def is_payload_reflected(payload: str, response_text: str,
                           min_length: int = 5) -> bool:
        """
        Check if payload is reflected in response

        Args:
            payload: Injected payload
            response_text: HTTP response
            min_length: Minimum payload length to check

        Returns:
            True if payload is reflected
        """
        if len(payload) < min_length:
            return False

        # Check for exact match
        if payload in response_text:
            return True

        # Check for URL-encoded version
        import urllib.parse
        encoded = urllib.parse.quote(payload)
        if encoded in response_text:
            return True

        # Check for HTML-encoded version
        import html
        html_encoded = html.escape(payload)
        if html_encoded in response_text:
            return True

        return False

    @staticmethod
    def is_payload_reflected_unencoded(payload: str, response_text: str) -> bool:
        """
        Check if payload is reflected WITHOUT HTML encoding (critical for XSS)

        If < becomes &lt; or > becomes &gt;, the XSS is BLOCKED

        Args:
            payload: Injected payload
            response_text: HTTP response

        Returns:
            True ONLY if payload is reflected without encoding
        """
        import html

        if len(payload) < 5:
            return False

        # Check for exact unencoded match
        if payload in response_text:
            # Verify it's not just the encoded version appearing
            # Check if the dangerous chars are actually unencoded
            dangerous_chars = ['<', '>', '"', "'"]
            for char in dangerous_chars:
                if char in payload:
                    # The char exists in payload - check if it appears unencoded in response
                    if char in response_text:
                        return True
            # No dangerous chars, but payload reflected
            return True

        # Check if HTML-encoded version appears (meaning it's BLOCKED)
        html_encoded = html.escape(payload)
        if html_encoded in response_text and payload not in response_text:
            # Payload is HTML-encoded - XSS is BLOCKED
            return False

        return False

    @staticmethod
    def is_html_encoded(payload: str, response_text: str) -> bool:
        """
        Check if payload's dangerous characters are HTML-encoded in response

        Args:
            payload: Original payload with special chars
            response_text: HTTP response text

        Returns:
            True if dangerous chars are encoded (XSS is blocked)
        """
        import html

        # Map of dangerous chars to their encoded versions
        encoding_map = {
            '<': '&lt;',
            '>': '&gt;',
            '"': '&quot;',
            "'": '&#x27;',
            '&': '&amp;'
        }

        # Check each dangerous char in payload
        for char, encoded in encoding_map.items():
            if char in payload:
                # If encoded version appears but unencoded doesn't, it's blocked
                # Need to check if the encoded version is in context of our payload
                payload_encoded = html.escape(payload)
                if payload_encoded in response_text and payload not in response_text:
                    return True

        return False

    @staticmethod
    def content_appears_new(indicator: str, baseline_text: str, response_text: str) -> bool:
        """
        Check if an indicator appears NEW in response (wasn't in baseline)

        Critical for false positive reduction - content must be INTRODUCED by payload

        Args:
            indicator: Pattern/content to check
            baseline_text: Response before payload injection
            response_text: Response after payload injection

        Returns:
            True if indicator is new (wasn't in baseline)
        """
        indicator_lower = indicator.lower()
        baseline_lower = baseline_text.lower() if baseline_text else ""
        response_lower = response_text.lower()

        # Content must exist in response but NOT in baseline
        in_response = indicator_lower in response_lower
        in_baseline = indicator_lower in baseline_lower

        return in_response and not in_baseline

    @staticmethod
    def get_new_content(baseline_text: str, response_text: str, min_diff_length: int = 20) -> str:
        """
        Extract content that appears new in response (wasn't in baseline)

        Args:
            baseline_text: Response before payload injection
            response_text: Response after payload injection
            min_diff_length: Minimum length difference to consider

        Returns:
            New content string or empty string
        """
        if not baseline_text:
            return ""

        # Simple diff - find content in response not in baseline
        baseline_set = set(baseline_text.split())
        response_set = set(response_text.split())

        new_words = response_set - baseline_set

        if len(new_words) < 3:
            return ""

        # Return first significant new content
        return " ".join(list(new_words)[:20])

    @staticmethod
    def get_remediation_advice(vulnerability_type: str) -> str:
        """
        Get generic remediation advice for vulnerability type

        Args:
            vulnerability_type: Type of vulnerability

        Returns:
            Remediation advice string
        """
        remediations = {
            'xss': 'Sanitize and encode all user input. Use Content-Security-Policy headers.',
            'sqli': 'Use parameterized queries or prepared statements. Never concatenate user input into SQL.',
            'lfi': 'Validate and whitelist file paths. Do not use user input in file operations.',
            'rfi': 'Disable remote file inclusion. Validate all file paths.',
            'command_injection': 'Avoid executing system commands with user input. Use safe APIs.',
            'ssrf': 'Validate and whitelist URLs. Do not allow user-controlled URLs in server requests.',
            'xxe': 'Disable external entity processing in XML parsers.',
            'csrf': 'Implement CSRF tokens. Use SameSite cookie attribute.',
            'idor': 'Implement proper access control checks. Use indirect object references.',
        }

        return remediations.get(vulnerability_type.lower(),
                               'Validate and sanitize all user input. Follow secure coding practices.')
