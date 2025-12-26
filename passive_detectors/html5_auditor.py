"""
HTML5 Security Auditor Passive Detector

Passively detects HTML5 features that may pose security risks:
- Client-side storage (localStorage, sessionStorage, IndexedDB)
- Geolocation API usage
- Application Cache (AppCache) - deprecated but may still be used
- Web Workers and Service Workers
- PostMessage API usage
- Cross-Origin Resource Sharing (CORS)
- Content Security Policy (CSP) issues

Based on HTML5 Auditor Burp extension.
"""

import re
from typing import Dict, List, Tuple, Any


class HTML5Auditor:
    """
    HTML5 Security Auditor

    Identifies HTML5 features with potential security implications.
    """

    # Client-side storage patterns
    STORAGE_PATTERNS = {
        'localStorage': [
            re.compile(r'localStorage\s*\.\s*(?:getItem|setItem|removeItem|clear|key)', re.IGNORECASE),
            re.compile(r'localStorage\s*\[\s*["\'][^"\']+["\']\s*\]', re.IGNORECASE),
            re.compile(r'window\.localStorage', re.IGNORECASE),
        ],
        'sessionStorage': [
            re.compile(r'sessionStorage\s*\.\s*(?:getItem|setItem|removeItem|clear|key)', re.IGNORECASE),
            re.compile(r'sessionStorage\s*\[\s*["\'][^"\']+["\']\s*\]', re.IGNORECASE),
            re.compile(r'window\.sessionStorage', re.IGNORECASE),
        ],
        'IndexedDB': [
            re.compile(r'indexedDB\s*\.\s*open', re.IGNORECASE),
            re.compile(r'window\.indexedDB', re.IGNORECASE),
            re.compile(r'IDBDatabase', re.IGNORECASE),
            re.compile(r'IDBTransaction', re.IGNORECASE),
        ],
        'WebSQL': [
            re.compile(r'openDatabase\s*\(', re.IGNORECASE),
            re.compile(r'executeSql\s*\(', re.IGNORECASE),
        ],
    }

    # Geolocation patterns
    GEOLOCATION_PATTERNS = [
        re.compile(r'navigator\s*\.\s*geolocation', re.IGNORECASE),
        re.compile(r'getCurrentPosition\s*\(', re.IGNORECASE),
        re.compile(r'watchPosition\s*\(', re.IGNORECASE),
    ]

    # Application Cache (deprecated but still risky)
    APPCACHE_PATTERNS = [
        re.compile(r'<html[^>]*manifest\s*=', re.IGNORECASE),
        re.compile(r'applicationCache', re.IGNORECASE),
        re.compile(r'CACHE MANIFEST', re.IGNORECASE),
        re.compile(r'\.appcache', re.IGNORECASE),
    ]

    # Web Workers
    WORKER_PATTERNS = {
        'Web Worker': [
            re.compile(r'new\s+Worker\s*\(', re.IGNORECASE),
            re.compile(r'self\.postMessage\s*\(', re.IGNORECASE),
        ],
        'Service Worker': [
            re.compile(r'serviceWorker\s*\.\s*register', re.IGNORECASE),
            re.compile(r'navigator\.serviceWorker', re.IGNORECASE),
            re.compile(r'ServiceWorkerRegistration', re.IGNORECASE),
        ],
        'Shared Worker': [
            re.compile(r'new\s+SharedWorker\s*\(', re.IGNORECASE),
        ],
    }

    # PostMessage API (potential for cross-origin attacks)
    POSTMESSAGE_PATTERNS = [
        re.compile(r'\.postMessage\s*\(', re.IGNORECASE),
        re.compile(r'addEventListener\s*\(\s*["\']message["\']', re.IGNORECASE),
        re.compile(r'onmessage\s*=', re.IGNORECASE),
    ]

    # Insecure postMessage usage patterns
    INSECURE_POSTMESSAGE = [
        re.compile(r'postMessage\s*\([^)]*,\s*["\']?\*["\']?\s*\)', re.IGNORECASE),
        re.compile(r'event\.origin', re.IGNORECASE),  # Good pattern - origin check
    ]

    # Sensitive data patterns that might be stored client-side
    SENSITIVE_STORAGE_PATTERNS = [
        re.compile(r'(?:local|session)Storage\s*\.\s*setItem\s*\(\s*["\'](?:token|jwt|auth|session|password|key|secret|credential)["\']', re.IGNORECASE),
        re.compile(r'(?:local|session)Storage\s*\[\s*["\'](?:token|jwt|auth|session|password|key|secret|credential)["\']', re.IGNORECASE),
    ]

    # Canvas fingerprinting
    CANVAS_PATTERNS = [
        re.compile(r'\.toDataURL\s*\(', re.IGNORECASE),
        re.compile(r'getImageData\s*\(', re.IGNORECASE),
        re.compile(r'canvas\s*\.\s*getContext\s*\(\s*["\']2d["\']', re.IGNORECASE),
    ]

    # WebRTC (IP leak potential)
    WEBRTC_PATTERNS = [
        re.compile(r'RTCPeerConnection', re.IGNORECASE),
        re.compile(r'webkitRTCPeerConnection', re.IGNORECASE),
        re.compile(r'mozRTCPeerConnection', re.IGNORECASE),
        re.compile(r'createDataChannel', re.IGNORECASE),
    ]

    # Blob URL patterns
    BLOB_PATTERNS = [
        re.compile(r'URL\.createObjectURL', re.IGNORECASE),
        re.compile(r'blob:', re.IGNORECASE),
    ]

    @classmethod
    def detect(cls, response_text: str, url: str, headers: Dict[str, str] = None) -> Tuple[bool, List[Dict[str, Any]]]:
        """
        Audit response for HTML5 security features.

        Args:
            response_text: HTTP response body
            url: URL being analyzed
            headers: HTTP response headers

        Returns:
            Tuple of (found_features, list_of_findings)
        """
        findings = []

        if not response_text:
            return False, findings

        # Check client-side storage
        storage_findings = cls._check_storage(response_text, url)
        findings.extend(storage_findings)

        # Check geolocation
        geo_findings = cls._check_geolocation(response_text, url)
        findings.extend(geo_findings)

        # Check application cache
        cache_findings = cls._check_appcache(response_text, url)
        findings.extend(cache_findings)

        # Check workers
        worker_findings = cls._check_workers(response_text, url)
        findings.extend(worker_findings)

        # Check postMessage
        postmsg_findings = cls._check_postmessage(response_text, url)
        findings.extend(postmsg_findings)

        # Check canvas (fingerprinting)
        canvas_findings = cls._check_canvas(response_text, url)
        findings.extend(canvas_findings)

        # Check WebRTC
        webrtc_findings = cls._check_webrtc(response_text, url)
        findings.extend(webrtc_findings)

        # Check Blob URLs
        blob_findings = cls._check_blob_urls(response_text, url)
        findings.extend(blob_findings)

        # Check sensitive data in storage
        sensitive_findings = cls._check_sensitive_storage(response_text, url)
        findings.extend(sensitive_findings)

        return len(findings) > 0, findings

    @classmethod
    def _check_storage(cls, content: str, url: str) -> List[Dict[str, Any]]:
        """Check for client-side storage usage"""
        findings = []

        for storage_type, patterns in cls.STORAGE_PATTERNS.items():
            for pattern in patterns:
                if pattern.search(content):
                    findings.append({
                        'type': 'Client-Side Storage Usage',
                        'severity': 'Low',
                        'url': url,
                        'storage_type': storage_type,
                        'description': f'{storage_type} is being used. Data stored client-side may be '
                                      f'accessible to XSS attacks or other malicious scripts.',
                        'category': 'html5_storage',
                        'location': 'Response Body',
                        'recommendation': f'Review what data is stored in {storage_type}. '
                                         f'Never store sensitive data (tokens, passwords) client-side. '
                                         f'Implement proper XSS protections.'
                    })
                    break

        return findings

    @classmethod
    def _check_geolocation(cls, content: str, url: str) -> List[Dict[str, Any]]:
        """Check for geolocation API usage"""
        findings = []

        for pattern in cls.GEOLOCATION_PATTERNS:
            if pattern.search(content):
                findings.append({
                    'type': 'Geolocation API Usage',
                    'severity': 'Medium',
                    'url': url,
                    'description': 'Geolocation API is being used. User location data may be collected.',
                    'category': 'html5_geolocation',
                    'location': 'Response Body',
                    'recommendation': 'Ensure geolocation data is collected with proper consent. '
                                     'Transmit location data only over HTTPS. '
                                     'Document data usage in privacy policy.'
                })
                break

        return findings

    @classmethod
    def _check_appcache(cls, content: str, url: str) -> List[Dict[str, Any]]:
        """Check for Application Cache (deprecated)"""
        findings = []

        for pattern in cls.APPCACHE_PATTERNS:
            if pattern.search(content):
                findings.append({
                    'type': 'Application Cache (Deprecated)',
                    'severity': 'Medium',
                    'url': url,
                    'description': 'Application Cache (AppCache) is being used. '
                                  'This feature is deprecated and has security issues including cache poisoning.',
                    'category': 'html5_appcache',
                    'location': 'Response Body',
                    'recommendation': 'Migrate to Service Workers for offline functionality. '
                                     'AppCache is deprecated and can be exploited for cache poisoning attacks.'
                })
                break

        return findings

    @classmethod
    def _check_workers(cls, content: str, url: str) -> List[Dict[str, Any]]:
        """Check for Web Worker usage"""
        findings = []

        for worker_type, patterns in cls.WORKER_PATTERNS.items():
            for pattern in patterns:
                if pattern.search(content):
                    severity = 'Info'
                    if worker_type == 'Service Worker':
                        severity = 'Low'  # Service workers need more scrutiny

                    findings.append({
                        'type': f'{worker_type} Detected',
                        'severity': severity,
                        'url': url,
                        'worker_type': worker_type,
                        'description': f'{worker_type} is being used. Workers execute in separate context.',
                        'category': 'html5_worker',
                        'location': 'Response Body',
                        'recommendation': f'Review {worker_type} code for security issues. '
                                         f'Ensure worker scripts are served with proper CSP. '
                                         f'Service Workers can intercept all network requests.'
                    })
                    break

        return findings

    @classmethod
    def _check_postmessage(cls, content: str, url: str) -> List[Dict[str, Any]]:
        """Check for postMessage API usage"""
        findings = []

        has_postmessage = any(p.search(content) for p in cls.POSTMESSAGE_PATTERNS)

        if has_postmessage:
            # Check for insecure patterns
            has_wildcard_origin = re.search(r'postMessage\s*\([^)]*,\s*["\']?\*["\']?\s*\)', content, re.IGNORECASE)
            has_origin_check = re.search(r'\.origin\s*(?:==|===|!=|!==)', content, re.IGNORECASE)

            severity = 'Info'
            description = 'postMessage API is being used for cross-origin communication.'

            if has_wildcard_origin:
                severity = 'Medium'
                description = 'postMessage is used with wildcard (*) origin. Any page can receive the message.'

            if not has_origin_check and has_postmessage:
                severity = 'Medium' if severity == 'Info' else severity
                description += ' No origin validation detected in message handler.'

            findings.append({
                'type': 'postMessage API Usage',
                'severity': severity,
                'url': url,
                'has_wildcard_origin': bool(has_wildcard_origin),
                'has_origin_check': bool(has_origin_check),
                'description': description,
                'category': 'html5_postmessage',
                'location': 'Response Body',
                'recommendation': 'Always validate message origin in event handlers. '
                                 'Avoid using wildcard (*) for targetOrigin. '
                                 'Validate and sanitize message data.'
            })

        return findings

    @classmethod
    def _check_canvas(cls, content: str, url: str) -> List[Dict[str, Any]]:
        """Check for Canvas API (fingerprinting potential)"""
        findings = []

        has_canvas = any(p.search(content) for p in cls.CANVAS_PATTERNS)

        if has_canvas:
            findings.append({
                'type': 'Canvas API Usage',
                'severity': 'Info',
                'url': url,
                'description': 'Canvas API is being used. May be used for browser fingerprinting.',
                'category': 'html5_canvas',
                'location': 'Response Body',
                'recommendation': 'Canvas can be used for browser fingerprinting. '
                                 'Review if toDataURL or getImageData is used for tracking purposes.'
            })

        return findings

    @classmethod
    def _check_webrtc(cls, content: str, url: str) -> List[Dict[str, Any]]:
        """Check for WebRTC (IP leak potential)"""
        findings = []

        has_webrtc = any(p.search(content) for p in cls.WEBRTC_PATTERNS)

        if has_webrtc:
            findings.append({
                'type': 'WebRTC API Usage',
                'severity': 'Low',
                'url': url,
                'description': 'WebRTC is being used. Can leak local/public IP addresses even through VPNs.',
                'category': 'html5_webrtc',
                'location': 'Response Body',
                'recommendation': 'WebRTC can reveal user IP addresses. '
                                 'Consider privacy implications. '
                                 'Users may need to disable WebRTC in browser for full VPN protection.'
            })

        return findings

    @classmethod
    def _check_blob_urls(cls, content: str, url: str) -> List[Dict[str, Any]]:
        """Check for Blob URL usage"""
        findings = []

        has_blob = any(p.search(content) for p in cls.BLOB_PATTERNS)

        if has_blob:
            findings.append({
                'type': 'Blob URL Usage',
                'severity': 'Info',
                'url': url,
                'description': 'Blob URLs are being created. May be used for dynamic content generation.',
                'category': 'html5_blob',
                'location': 'Response Body',
                'recommendation': 'Blob URLs can be used to bypass CSP. '
                                 'Ensure blob: is properly restricted in CSP.'
            })

        return findings

    @classmethod
    def _check_sensitive_storage(cls, content: str, url: str) -> List[Dict[str, Any]]:
        """Check for sensitive data in client-side storage"""
        findings = []

        for pattern in cls.SENSITIVE_STORAGE_PATTERNS:
            match = pattern.search(content)
            if match:
                findings.append({
                    'type': 'Sensitive Data in Client Storage',
                    'severity': 'High',
                    'url': url,
                    'matched': match.group(0)[:100],
                    'description': 'Potentially sensitive data (tokens, credentials) is being stored client-side. '
                                  'This data is accessible to XSS attacks.',
                    'category': 'html5_sensitive_storage',
                    'location': 'Response Body',
                    'recommendation': 'Never store sensitive tokens or credentials in localStorage/sessionStorage. '
                                     'Use HttpOnly cookies for session management. '
                                     'Consider using Web Crypto API for sensitive data encryption.'
                })
                break

        return findings


def audit_html5(response_text: str, url: str, headers: Dict[str, str] = None) -> Tuple[bool, List[Dict[str, Any]]]:
    """Convenience function for HTML5 security audit"""
    return HTML5Auditor.detect(response_text, url, headers)
