"""
Session Replay Service Detector

Passively detects session replay/recording services that capture user interactions.

These services can exfiltrate sensitive data including:
- Form inputs (passwords, credit cards, personal info)
- User clicks and scrolling behavior
- DOM snapshots
- Network requests

Based on research: https://freedom-to-tinker.com/2017/11/15/no-boundaries-exfiltration-of-personal-data-by-session-replay-scripts/
"""

import re
from typing import Dict, List, Tuple, Any


class SessionReplayDetector:
    """
    Session Replay Service Detector

    Identifies session recording scripts that may capture sensitive user data.
    """

    # Session replay service patterns
    # Format: (service_name, patterns_list, privacy_risk_level)
    REPLAY_SERVICES = [
        ('Yandex Metrika', [
            re.compile(r'mc\.yandex\.ru', re.IGNORECASE),
            re.compile(r'metrika\.yandex', re.IGNORECASE),
            re.compile(r'webvisor', re.IGNORECASE),
        ], 'High'),

        ('FullStory', [
            re.compile(r'fullstory\.com', re.IGNORECASE),
            re.compile(r'fs\.js', re.IGNORECASE),
            re.compile(r'FullStory\.init', re.IGNORECASE),
            re.compile(r'window\[\'_fs_', re.IGNORECASE),
        ], 'High'),

        ('SessionCam', [
            re.compile(r'sessioncam\.com', re.IGNORECASE),
            re.compile(r'sessioncamRecorder', re.IGNORECASE),
        ], 'High'),

        ('Hotjar', [
            re.compile(r'hotjar\.com', re.IGNORECASE),
            re.compile(r'static\.hotjar\.com', re.IGNORECASE),
            re.compile(r'hj\s*\(\s*[\'"]init[\'"]', re.IGNORECASE),
            re.compile(r'hjid', re.IGNORECASE),
        ], 'High'),

        ('ClickTale', [
            re.compile(r'clicktale\.net', re.IGNORECASE),
            re.compile(r'clicktale\.com', re.IGNORECASE),
            re.compile(r'ClickTale', re.IGNORECASE),
        ], 'High'),

        ('Smartlook', [
            re.compile(r'smartlook\.com', re.IGNORECASE),
            re.compile(r'rec\.smartlook', re.IGNORECASE),
            re.compile(r'smartlook\s*\(', re.IGNORECASE),
        ], 'High'),

        ('Mouseflow', [
            re.compile(r'mouseflow\.com', re.IGNORECASE),
            re.compile(r'cdn\.mouseflow\.com', re.IGNORECASE),
            re.compile(r'_mfq', re.IGNORECASE),
        ], 'High'),

        ('LogRocket', [
            re.compile(r'logrocket\.com', re.IGNORECASE),
            re.compile(r'cdn\.logrocket', re.IGNORECASE),
            re.compile(r'LogRocket\.init', re.IGNORECASE),
        ], 'High'),

        ('Lucky Orange', [
            re.compile(r'luckyorange\.com', re.IGNORECASE),
            re.compile(r'luckyorange\.net', re.IGNORECASE),
            re.compile(r'__lo_site_id', re.IGNORECASE),
        ], 'High'),

        ('Inspectlet', [
            re.compile(r'inspectlet\.com', re.IGNORECASE),
            re.compile(r'cdn\.inspectlet\.com', re.IGNORECASE),
            re.compile(r'__insp', re.IGNORECASE),
        ], 'High'),

        ('Heap Analytics', [
            re.compile(r'heap\.io', re.IGNORECASE),
            re.compile(r'heapanalytics\.com', re.IGNORECASE),
            re.compile(r'heap\s*\.\s*load', re.IGNORECASE),
        ], 'Medium'),

        ('Crazy Egg', [
            re.compile(r'crazyegg\.com', re.IGNORECASE),
            re.compile(r'script\.crazyegg\.com', re.IGNORECASE),
        ], 'Medium'),

        ('Clarity (Microsoft)', [
            re.compile(r'clarity\.ms', re.IGNORECASE),
            re.compile(r'microsoft\.com/clarity', re.IGNORECASE),
            re.compile(r'clarity\s*\(\s*[\'"]init', re.IGNORECASE),
        ], 'High'),

        ('Quantum Metric', [
            re.compile(r'quantummetric\.com', re.IGNORECASE),
            re.compile(r'cdn\.quantummetric', re.IGNORECASE),
        ], 'High'),

        ('Decibel Insight', [
            re.compile(r'decibelinsight\.com', re.IGNORECASE),
            re.compile(r'decibelinsight\.net', re.IGNORECASE),
        ], 'High'),

        ('UXCam', [
            re.compile(r'uxcam\.com', re.IGNORECASE),
        ], 'High'),

        ('Contentsquare', [
            re.compile(r'contentsquare\.com', re.IGNORECASE),
            re.compile(r'contentsquare\.net', re.IGNORECASE),
            re.compile(r'c\.contentsquare', re.IGNORECASE),
        ], 'High'),

        ('Glassbox', [
            re.compile(r'glassboxdigital\.com', re.IGNORECASE),
            re.compile(r'glassbox\.com', re.IGNORECASE),
        ], 'High'),

        ('Pendo', [
            re.compile(r'pendo\.io', re.IGNORECASE),
            re.compile(r'cdn\.pendo\.io', re.IGNORECASE),
            re.compile(r'pendo\.initialize', re.IGNORECASE),
        ], 'Medium'),

        ('Mixpanel', [
            re.compile(r'mixpanel\.com', re.IGNORECASE),
            re.compile(r'cdn\.mxpnl\.com', re.IGNORECASE),
            re.compile(r'mixpanel\.init', re.IGNORECASE),
        ], 'Medium'),
    ]

    # Patterns indicating session recording configuration
    RECORDING_CONFIG_PATTERNS = [
        (re.compile(r'record\s*:\s*true', re.IGNORECASE), 'Recording enabled'),
        (re.compile(r'recordSession\s*:\s*true', re.IGNORECASE), 'Session recording enabled'),
        (re.compile(r'recordInputs\s*:\s*true', re.IGNORECASE), 'Input recording enabled'),
        (re.compile(r'captureKeys\s*:\s*true', re.IGNORECASE), 'Keystroke capture enabled'),
        (re.compile(r'maskInputs\s*:\s*false', re.IGNORECASE), 'Input masking disabled'),
        (re.compile(r'maskAllInputs\s*:\s*false', re.IGNORECASE), 'All input masking disabled'),
        (re.compile(r'maskTextContent\s*:\s*false', re.IGNORECASE), 'Text masking disabled'),
        (re.compile(r'collectWhitespace\s*:\s*true', re.IGNORECASE), 'Whitespace collection enabled'),
    ]

    @classmethod
    def detect(cls, response_text: str, url: str, headers: Dict[str, str] = None) -> Tuple[bool, List[Dict[str, Any]]]:
        """
        Detect session replay services in HTTP response.

        Args:
            response_text: HTTP response body
            url: URL being analyzed
            headers: HTTP response headers

        Returns:
            Tuple of (found_services, list_of_findings)
        """
        findings = []

        if not response_text:
            return False, findings

        detected_services = []

        # Check for each replay service
        for service_name, patterns, risk_level in cls.REPLAY_SERVICES:
            for pattern in patterns:
                if pattern.search(response_text):
                    detected_services.append((service_name, risk_level))
                    break

        # Report detected services
        for service_name, risk_level in detected_services:
            severity = 'Medium' if risk_level == 'High' else 'Low'

            findings.append({
                'type': 'Session Replay Service Detected',
                'severity': severity,
                'url': url,
                'service': service_name,
                'privacy_risk': risk_level,
                'description': f'{service_name} session replay service detected. '
                              f'May capture user interactions including sensitive data.',
                'category': 'session_replay',
                'location': 'Response Body',
                'recommendation': f'Review {service_name} configuration to ensure sensitive data is masked. '
                                 f'Implement data masking for password fields, credit cards, and PII. '
                                 f'Consider privacy implications and GDPR/CCPA compliance.'
            })

        # Check for recording configuration issues
        config_findings = cls._check_recording_config(response_text, url)
        findings.extend(config_findings)

        # Add summary if multiple services detected
        if len(detected_services) > 1:
            findings.insert(0, {
                'type': 'Multiple Session Replay Services',
                'severity': 'Medium',
                'url': url,
                'services': [s[0] for s in detected_services],
                'count': len(detected_services),
                'description': f'{len(detected_services)} session replay services detected. '
                              f'May cause performance issues and increased data exposure.',
                'category': 'multiple_replay_services',
                'location': 'Response Body',
                'recommendation': 'Consider consolidating to a single session replay service. '
                                 'Review privacy policies and data retention for each service.'
            })

        return len(findings) > 0, findings

    @classmethod
    def _check_recording_config(cls, response_text: str, url: str) -> List[Dict[str, Any]]:
        """Check for risky recording configurations"""
        findings = []
        issues = []

        for pattern, issue_desc in cls.RECORDING_CONFIG_PATTERNS:
            if pattern.search(response_text):
                issues.append(issue_desc)

        if issues:
            findings.append({
                'type': 'Risky Session Recording Configuration',
                'severity': 'Medium',
                'url': url,
                'issues': issues,
                'description': f'Session recording configured with potential privacy risks: '
                              f'{", ".join(issues)}',
                'category': 'replay_config',
                'location': 'Response Body',
                'recommendation': 'Enable input masking (maskInputs: true). '
                                 'Disable keystroke capture on sensitive forms. '
                                 'Use CSS classes to exclude sensitive elements from recording.'
            })

        return findings


def detect_session_replay(response_text: str, url: str, headers: Dict[str, str] = None) -> Tuple[bool, List[Dict[str, Any]]]:
    """Convenience function for session replay detection"""
    return SessionReplayDetector.detect(response_text, url, headers)
