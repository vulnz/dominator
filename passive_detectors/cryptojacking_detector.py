"""
Cryptojacking / Cryptocurrency Miner Detection Module

Passively detects cryptocurrency mining scripts on web pages.

Detects:
- Known cryptojacking domains (CoinHive, Coinimp, etc.)
- WebAssembly-based miners
- Mining-related JavaScript patterns
- Browser-based mining libraries
- Hidden mining iframes

Based on CoinBlockerLists and other threat intelligence sources.
Reference: https://github.com/nicehash/NiceHashMiner
"""

import re
from typing import Dict, List, Tuple, Any, Set


class CryptojackingDetector:
    """
    Cryptojacking / Cryptocurrency Miner Detector

    Identifies malicious browser-based cryptocurrency miners.
    """

    # Known cryptojacking domains and scripts
    # Based on CoinBlockerLists and other sources
    MINING_DOMAINS = {
        # Major mining services (now defunct but may still be used)
        'coinhive.com',
        'coin-hive.com',
        'coinhive.min.js',
        'authedmine.com',

        # Active mining services
        'coinimp.com',
        'crypto-loot.com',
        'cryptoloot.pro',
        'minero.cc',
        'webmine.cz',
        'webminepool.com',
        'miner.pr0gramm.com',
        'minemytraffic.com',
        'ppoi.org',
        'coinblind.com',
        'mataharirama.xyz',
        'monerominer.rocks',
        'coinerra.com',
        'deepminer.com',
        'browsermine.com',
        'webminerpool.com',
        'jsecoin.com',

        # Monero mining pools
        'xmr.omine.org',
        'pool.supportxmr.com',
        'monerohash.com',
        'minexmr.com',
        'nanopool.org',
        'dwarfpool.com',

        # Additional known domains
        'cryptonight.wasm',
        'miner.js',
        'crypto-miner.js',
        'web-miner.js',
        'coinhiveaudio.js',
        'coin-hive-loader.js',

        # Obfuscated miners
        'rocks.io',
        'coin-have.com',
        'coinimp.static.com',
        'jscdnpackages.com',
        'static-cnt.bid',
        'cnt.statistic.date',
    }

    # JavaScript patterns that indicate mining
    MINING_JS_PATTERNS = [
        # CoinHive patterns
        re.compile(r'CoinHive\.(?:Anonymous|User|Token|JobThread)', re.IGNORECASE),
        re.compile(r'new\s+CoinHive', re.IGNORECASE),
        re.compile(r'coinhive\.min\.js', re.IGNORECASE),

        # Crypto-Loot patterns
        re.compile(r'CryptoLoot\.Anonymous', re.IGNORECASE),
        re.compile(r'new\s+CryptoLoot', re.IGNORECASE),

        # Coinimp patterns
        re.compile(r'Client\.Anonymous', re.IGNORECASE),
        re.compile(r'new\s+Client\s*\(\s*["\'][a-zA-Z0-9]+["\']', re.IGNORECASE),

        # Generic mining patterns
        re.compile(r'(?:start|stop)Mining', re.IGNORECASE),
        re.compile(r'miner\.start', re.IGNORECASE),
        re.compile(r'(?:hashes|hashrate)PerSecond', re.IGNORECASE),
        re.compile(r'setNumThreads', re.IGNORECASE),
        re.compile(r'getAcceptedHashes', re.IGNORECASE),
        re.compile(r'getTotalHashes', re.IGNORECASE),
        re.compile(r'setThrottle', re.IGNORECASE),
        re.compile(r'isRunning', re.IGNORECASE),
        re.compile(r'on\s*\(\s*["\'](?:found|accepted|error)["\']', re.IGNORECASE),

        # WebAssembly crypto patterns
        re.compile(r'cryptonight\.wasm', re.IGNORECASE),
        re.compile(r'wasmMiner', re.IGNORECASE),
        re.compile(r'asmjs-miner', re.IGNORECASE),

        # Stratum protocol (mining pool communication)
        re.compile(r'stratum\+tcp://', re.IGNORECASE),
        re.compile(r'pool\.(?:address|host)', re.IGNORECASE),

        # Mining pool keywords
        re.compile(r'["\']?(?:wallet|address)["\']?\s*:\s*["\'][0-9a-zA-Z]{95}', re.IGNORECASE),  # Monero address
        re.compile(r'["\']?(?:wallet|address)["\']?\s*:\s*["\']4[0-9a-zA-Z]{94}', re.IGNORECASE),  # Monero 4...
    ]

    # Hidden iframe patterns (often used to hide miners)
    HIDDEN_IFRAME_PATTERNS = [
        re.compile(r'<iframe[^>]*(?:width|height)\s*=\s*["\']?0', re.IGNORECASE),
        re.compile(r'<iframe[^>]*style\s*=\s*["\'][^"\']*(?:display\s*:\s*none|visibility\s*:\s*hidden)', re.IGNORECASE),
        re.compile(r'<iframe[^>]*(?:hidden|style="display:none")[^>]*src\s*=', re.IGNORECASE),
    ]

    # WebSocket patterns for mining pools
    WEBSOCKET_MINING_PATTERNS = [
        re.compile(r'wss?://[^"\']+(?:pool|mine|xmr|crypto)', re.IGNORECASE),
        re.compile(r'WebSocket\s*\(\s*["\']wss?://[^"\']+(?:3333|4444|5555|7777|8080|8888)', re.IGNORECASE),
    ]

    # CPU/GPU usage indicators
    RESOURCE_ABUSE_PATTERNS = [
        re.compile(r'navigator\.hardwareConcurrency', re.IGNORECASE),
        re.compile(r'new\s+Worker\s*\(\s*["\'][^"\']+(?:miner|hash|crypto)', re.IGNORECASE),
        re.compile(r'SharedArrayBuffer', re.IGNORECASE),
        re.compile(r'WebGL2RenderingContext', re.IGNORECASE),  # GPU mining
    ]

    @classmethod
    def detect(cls, response_text: str, url: str, headers: Dict[str, str] = None) -> Tuple[bool, List[Dict[str, Any]]]:
        """
        Detect cryptocurrency mining scripts.

        Args:
            response_text: HTTP response body
            url: URL being analyzed
            headers: HTTP response headers

        Returns:
            Tuple of (found_miner, list_of_findings)
        """
        findings = []

        if not response_text:
            return False, findings

        # Check for known mining domains
        domain_findings = cls._check_mining_domains(response_text, url)
        findings.extend(domain_findings)

        # Check for mining JavaScript patterns
        js_findings = cls._check_js_patterns(response_text, url)
        findings.extend(js_findings)

        # Check for hidden iframes
        iframe_findings = cls._check_hidden_iframes(response_text, url)
        findings.extend(iframe_findings)

        # Check WebSocket mining
        ws_findings = cls._check_websocket_mining(response_text, url)
        findings.extend(ws_findings)

        # Check resource abuse patterns
        resource_findings = cls._check_resource_abuse(response_text, url)
        findings.extend(resource_findings)

        # Add summary if mining detected
        if findings:
            high_severity = [f for f in findings if f.get('severity') in ['High', 'Critical']]
            if high_severity:
                findings.insert(0, {
                    'type': 'Cryptojacking Detected',
                    'severity': 'Critical',
                    'url': url,
                    'finding_count': len(findings),
                    'description': f'Page contains cryptocurrency mining code! '
                                  f'{len(findings)} indicators found.',
                    'category': 'cryptojacking_summary',
                    'location': 'Response Body',
                    'recommendation': 'IMMEDIATELY remove mining scripts. '
                                     'Report to website owner if not intentional. '
                                     'Mining without consent is illegal in many jurisdictions.'
                })

        return len(findings) > 0, findings

    @classmethod
    def _check_mining_domains(cls, content: str, url: str) -> List[Dict[str, Any]]:
        """Check for known mining domains in script sources"""
        findings = []
        found_domains: Set[str] = set()

        content_lower = content.lower()

        for domain in cls.MINING_DOMAINS:
            if domain.lower() in content_lower:
                if domain not in found_domains:
                    found_domains.add(domain)

                    findings.append({
                        'type': 'Known Cryptojacking Domain',
                        'severity': 'Critical',
                        'url': url,
                        'mining_domain': domain,
                        'description': f'Script from known cryptojacking domain detected: {domain}',
                        'category': 'cryptojacking_domain',
                        'location': 'Response Body',
                        'recommendation': 'Remove the mining script immediately. '
                                         'This domain is associated with browser-based cryptocurrency mining.'
                    })

        return findings

    @classmethod
    def _check_js_patterns(cls, content: str, url: str) -> List[Dict[str, Any]]:
        """Check for mining JavaScript patterns"""
        findings = []
        found_patterns: Set[str] = set()

        for pattern in cls.MINING_JS_PATTERNS:
            match = pattern.search(content)
            if match:
                matched_text = match.group(0)[:100]
                pattern_key = pattern.pattern[:50]

                if pattern_key not in found_patterns:
                    found_patterns.add(pattern_key)

                    findings.append({
                        'type': 'Cryptomining JavaScript Pattern',
                        'severity': 'High',
                        'url': url,
                        'pattern': matched_text,
                        'description': f'Cryptocurrency mining JavaScript code detected: {matched_text}',
                        'category': 'cryptojacking_js',
                        'location': 'Response Body',
                        'recommendation': 'Review and remove mining code. '
                                         'If intentional, ensure proper user consent and disclosure.'
                    })

        return findings

    @classmethod
    def _check_hidden_iframes(cls, content: str, url: str) -> List[Dict[str, Any]]:
        """Check for hidden iframes that may contain miners"""
        findings = []

        for pattern in cls.HIDDEN_IFRAME_PATTERNS:
            match = pattern.search(content)
            if match:
                iframe_html = match.group(0)[:200]

                # Check if iframe src is suspicious
                src_match = re.search(r'src\s*=\s*["\']([^"\']+)["\']', iframe_html, re.IGNORECASE)
                if src_match:
                    src_url = src_match.group(1)

                    # Check if src contains mining-related keywords
                    if any(kw in src_url.lower() for kw in ['mine', 'coin', 'hash', 'xmr', 'crypto']):
                        findings.append({
                            'type': 'Hidden Mining Iframe',
                            'severity': 'High',
                            'url': url,
                            'iframe_src': src_url,
                            'description': f'Hidden iframe with suspicious mining-related URL: {src_url}',
                            'category': 'cryptojacking_iframe',
                            'location': 'Response Body',
                            'recommendation': 'Remove hidden iframe. Hidden iframes are commonly used to hide miners.'
                        })
                        break

        return findings

    @classmethod
    def _check_websocket_mining(cls, content: str, url: str) -> List[Dict[str, Any]]:
        """Check for WebSocket connections to mining pools"""
        findings = []

        for pattern in cls.WEBSOCKET_MINING_PATTERNS:
            match = pattern.search(content)
            if match:
                ws_url = match.group(0)[:150]

                findings.append({
                    'type': 'Mining Pool WebSocket',
                    'severity': 'High',
                    'url': url,
                    'websocket': ws_url,
                    'description': f'WebSocket connection to suspected mining pool: {ws_url}',
                    'category': 'cryptojacking_websocket',
                    'location': 'Response Body',
                    'recommendation': 'Review WebSocket connection. Mining pools use WebSockets '
                                     'for real-time hash submission.'
                })
                break

        return findings

    @classmethod
    def _check_resource_abuse(cls, content: str, url: str) -> List[Dict[str, Any]]:
        """Check for patterns indicating CPU/GPU resource abuse"""
        findings = []
        abuse_indicators = []

        for pattern in cls.RESOURCE_ABUSE_PATTERNS:
            if pattern.search(content):
                abuse_indicators.append(pattern.pattern[:50])

        # Only report if multiple indicators (to reduce false positives)
        if len(abuse_indicators) >= 2:
            findings.append({
                'type': 'Resource Abuse Indicators',
                'severity': 'Medium',
                'url': url,
                'indicators': abuse_indicators,
                'description': f'Multiple resource abuse patterns detected that may indicate mining: '
                              f'{", ".join(abuse_indicators[:3])}',
                'category': 'cryptojacking_resource',
                'location': 'Response Body',
                'recommendation': 'Review code for unauthorized resource usage. '
                                 'These patterns are common in browser-based miners.'
            })

        return findings


def detect_cryptojacking(response_text: str, url: str, headers: Dict[str, str] = None) -> Tuple[bool, List[Dict[str, Any]]]:
    """Convenience function for cryptojacking detection"""
    return CryptojackingDetector.detect(response_text, url, headers)
