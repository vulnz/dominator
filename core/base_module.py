"""
Base module class for all vulnerability scanner modules
Each module is completely independent and self-contained
"""

from abc import ABC, abstractmethod
from typing import List, Dict, Any, Callable, Optional
import os
import json
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from core.logger import get_logger

logger = get_logger(__name__)


class BaseModule(ABC):
    """
    Base class for all scanner modules

    Each module must:
    1. Load payloads from TXT files
    2. Load detection patterns from TXT files
    3. Implement scan() method
    4. Return standardized results
    """

    # Class-level flag for timeout enforcement (shared across all modules)
    # Thread-safe implementation with lock protection
    _global_stop_requested = False
    _stop_lock = threading.Lock()

    def __init__(self, module_path: str, payload_limit: int = None):
        """
        Initialize module

        Args:
            module_path: Path to module directory (e.g., "modules/xss")
            payload_limit: Global payload limit from CLI args (overrides config)
        """
        self.module_path = module_path
        self.name = os.path.basename(module_path)
        self.payload_limit = payload_limit  # Store global limit

        # Load configuration
        self.config = self._load_config()

        # Load payloads and patterns from TXT files
        self.payloads = self._load_payloads()
        self.patterns = self._load_patterns()
        self.indicators = self._load_indicators()

        # Initialize passive scanner for payload response analysis
        # This allows detecting path disclosure, DB errors, etc. in payload responses
        self.passive_scanner = None
        self.payload_passive_findings = []

        # Performance optimization flags
        self.early_exit = True  # Stop testing parameter after first vulnerability found
        self.concurrent_requests = 10  # Number of concurrent requests

        logger.info(f"Module '{self.name}' initialized: {len(self.payloads)} payloads (limit: {payload_limit or 'none'}), {len(self.patterns)} patterns")

    def _load_config(self) -> Dict[str, Any]:
        """Load module configuration from config.json"""
        config_path = os.path.join(self.module_path, "config.json")

        if os.path.exists(config_path):
            try:
                with open(config_path, 'r', encoding='utf-8') as f:
                    config = json.load(f)
                    logger.debug(f"Loaded config for module '{self.name}'")
                    return config
            except Exception as e:
                logger.warning(f"Error loading config for '{self.name}': {e}")

        # Default config
        return {
            "name": self.name.upper(),
            "description": f"{self.name} vulnerability scanner",
            "severity": "Medium",
            "enabled": True,
            "max_payloads": 100,
            "timeout": 20
        }

    def _load_txt_file(self, filename: str) -> List[str]:
        """
        Load lines from TXT file

        Args:
            filename: Name of file in module directory

        Returns:
            List of non-empty lines
        """
        file_path = os.path.join(self.module_path, filename)

        if not os.path.exists(file_path):
            logger.warning(f"File not found: {file_path}")
            return []

        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                lines = [line.strip() for line in f if line.strip() and not line.startswith('#')]
                logger.debug(f"Loaded {len(lines)} lines from {filename}")
                return lines
        except Exception as e:
            logger.error(f"Error reading {file_path}: {e}")
            return []

    def _load_payloads(self) -> List[str]:
        """Load payloads from payloads.txt"""
        return self._load_txt_file("payloads.txt")

    def get_limited_payloads(self, custom_limit: int = None) -> List[str]:
        """
        Get payloads with limit applied (for performance optimization)

        Priority order:
        1. custom_limit parameter (if provided)
        2. Global payload_limit from CLI --payload-limit
        3. Module config max_payloads
        4. No limit (all payloads)

        Args:
            custom_limit: Override limit for specific test cases

        Returns:
            Limited list of payloads
        """
        payloads = self.payloads

        # Determine effective limit
        if custom_limit is not None:
            limit = custom_limit
        elif self.payload_limit is not None and self.payload_limit > 0:
            limit = self.payload_limit
        elif self.config.get("max_payloads", 0) > 0:
            limit = self.config.get("max_payloads")
        else:
            return payloads  # No limit

        if len(payloads) > limit:
            logger.debug(f"[{self.name}] Limiting payloads from {len(payloads)} to {limit}")
            return payloads[:limit]

        return payloads

    def _load_patterns(self) -> List[str]:
        """Load detection patterns from patterns.txt"""
        return self._load_txt_file("patterns.txt")

    def _load_indicators(self) -> List[str]:
        """Load success indicators from indicators.txt (optional)"""
        return self._load_txt_file("indicators.txt")

    @abstractmethod
    def scan(self, targets: List[Dict[str, Any]], http_client: Any) -> List[Dict[str, Any]]:
        """
        Scan targets for vulnerabilities

        Args:
            targets: List of target URLs with parameters
                [
                    {
                        'url': 'http://example.com/page.php',
                        'params': {'id': '1', 'name': 'test'}
                    }
                ]
            http_client: HTTP client instance for making requests

        Returns:
            List of results
                [
                    {
                        'vulnerability': True,
                        'type': 'XSS',
                        'severity': 'High',
                        'url': 'http://...',
                        'parameter': 'id',
                        'payload': '<script>...',
                        'evidence': '...',
                        'description': '...'
                    }
                ]
        """
        pass

    def analyze_payload_response(self, response: Any, url: str, payload: str) -> List[Dict[str, Any]]:
        """
        Analyze HTTP response from payload injection using passive scanner

        This method runs passive detection on responses received during payload testing.
        It can detect path disclosures, database errors, and other leaks that occur
        when sending malicious payloads.

        Args:
            response: HTTP response object
            url: Target URL
            payload: Payload that was sent

        Returns:
            List of passive findings from this response
        """
        findings = []

        if not response:
            return findings

        try:
            # Lazy load passive scanner (only when needed)
            if self.passive_scanner is None:
                from passive_detectors.passive_scanner import PassiveScanner
                self.passive_scanner = PassiveScanner()

            # Get response data
            response_text = getattr(response, 'text', '')
            headers = dict(getattr(response, 'headers', {}))

            # Run passive analysis
            passive_results = self.passive_scanner.analyze_response(headers, response_text, url)

            # Check if we found anything interesting
            if passive_results['total_count'] > 0:
                # Filter for HIGH severity findings (path disclosure, DB errors)
                high_severity_findings = []

                for finding in passive_results['sensitive_data']:
                    if finding.get('severity', '').lower() in ['high', 'critical']:
                        # Add metadata about payload that triggered this
                        finding['triggered_by_payload'] = payload[:100]
                        finding['source'] = f'{self.name} module payload testing'
                        high_severity_findings.append(finding)

                if high_severity_findings:
                    logger.info(f"[{self.name}] Payload '{payload[:30]}...' triggered {len(high_severity_findings)} passive findings!")
                    findings.extend(high_severity_findings)
                    self.payload_passive_findings.extend(high_severity_findings)

        except Exception as e:
            logger.debug(f"Error in passive analysis of payload response: {e}")

        return findings

    def get_payload_passive_findings(self) -> List[Dict[str, Any]]:
        """
        Get all passive findings collected during payload testing

        Returns:
            List of passive findings
        """
        return self.payload_passive_findings

    def should_stop(self) -> bool:
        """
        Check if module should stop execution (timeout/user interrupt)

        Modules should call this periodically during long-running scans
        to respect --max-time limits and user interrupts.

        Thread-safe: Uses lock to ensure consistent reads across threads.

        Returns:
            True if module should stop immediately
        """
        with BaseModule._stop_lock:
            return BaseModule._global_stop_requested

    @classmethod
    def set_global_stop(cls, stop: bool = True) -> None:
        """
        Set global stop flag for all modules

        Thread-safe: Uses lock to ensure consistent writes across threads.

        Args:
            stop: True to stop all modules
        """
        with cls._stop_lock:
            cls._global_stop_requested = stop
            if stop:
                logger.info("Global stop signal sent to all modules")

    def is_enabled(self) -> bool:
        """Check if module is enabled"""
        return self.config.get("enabled", True)

    def get_name(self) -> str:
        """Get module name"""
        return self.config.get("name", self.name.upper())

    def get_description(self) -> str:
        """Get module description"""
        return self.config.get("description", "")

    def get_severity(self) -> str:
        """Get default severity level"""
        return self.config.get("severity", "Medium")

    def get_oob_payloads(self) -> Dict[str, Any]:
        """
        Get Out-of-Band callback payloads for blind vulnerability testing.

        This method retrieves OOB payloads from the global OOB manager,
        allowing scan modules to inject callback URLs for detecting
        blind vulnerabilities (SSRF, XXE, blind SQLi, etc.)

        Returns:
            Dictionary with OOB payload information:
            {
                'dns': 'identifier.oob-domain.com',
                'http': 'http://identifier.oob-domain.com',
                'https': 'https://identifier.oob-domain.com',
                'domain': 'oob-domain.com',
                'identifier': 'unique-identifier'
            }
            or None if OOB is not configured
        """
        try:
            from GUI.components.oob_panel import get_oob_manager
            oob_manager = get_oob_manager()

            if not oob_manager.is_configured():
                return None

            return {
                'dns': oob_manager.get_dns_payload(f"-{self.name}"),
                'http': oob_manager.get_http_payload(f"-{self.name}"),
                'https': oob_manager.get_https_payload(f"-{self.name}"),
                'domain': oob_manager.oob_domain,
                'identifier': oob_manager.oob_identifier
            }
        except ImportError:
            logger.debug("OOB panel not available (GUI components not loaded)")
            return None
        except Exception as e:
            logger.debug(f"Error getting OOB payloads: {e}")
            return None

    def inject_oob_payload(self, payload_template: str, oob_type: str = 'http') -> str:
        """
        Inject OOB callback URL into a payload template.

        Use this to replace {{OOB}} placeholder in payloads with actual callback URLs.

        Args:
            payload_template: Payload string with {{OOB}} placeholder
            oob_type: Type of OOB URL to inject ('dns', 'http', or 'https')

        Returns:
            Payload with OOB URL injected, or original payload if OOB not configured
        """
        if '{{OOB}}' not in payload_template:
            return payload_template

        oob_payloads = self.get_oob_payloads()
        if not oob_payloads:
            # Return payload with placeholder removed
            return payload_template.replace('{{OOB}}', 'example.com')

        oob_url = oob_payloads.get(oob_type, oob_payloads.get('http', ''))
        return payload_template.replace('{{OOB}}', oob_url)

    def extract_response_context(self, response_text: str, trigger: str,
                                 chars_before: int = 100, chars_after: int = 50) -> str:
        """
        Extract response context around trigger with highlighting

        Args:
            response_text: Full response text
            trigger: The trigger/payload to find
            chars_before: Characters to show before trigger (default 100)
            chars_after: Characters to show after trigger (default 50)

        Returns:
            Context string with **trigger** highlighted
        """
        try:
            if not trigger or not response_text:
                return ""

            # Find trigger position (case insensitive)
            trigger_lower = trigger.lower()
            response_lower = response_text.lower()

            pos = response_lower.find(trigger_lower)
            if pos == -1:
                return ""

            # Extract context
            start = max(0, pos - chars_before)
            end = min(len(response_text), pos + len(trigger) + chars_after)

            context = response_text[start:end]

            # Highlight the trigger by wrapping it with **
            # Find trigger in context (case insensitive)
            context_lower = context.lower()
            trigger_pos = context_lower.find(trigger_lower)

            if trigger_pos != -1:
                # Preserve original case of trigger in context
                actual_trigger = context[trigger_pos:trigger_pos + len(trigger)]
                context = (context[:trigger_pos] +
                          f"**{actual_trigger}**" +
                          context[trigger_pos + len(trigger):])

            return context

        except Exception as e:
            logger.debug(f"Error extracting response context: {e}")
            return ""

    def create_result(self, vulnerable: bool = False, url: str = "", parameter: str = "",
                     payload: str = "", evidence: str = "", description: str = "",
                     confidence: float = 0.0, severity: str = None,
                     request: str = "", response: str = "", **kwargs) -> Dict[str, Any]:
        """
        Create standardized result dictionary with full security metadata

        REQUIRED FIELDS for professional reports:
        - CWE: Common Weakness Enumeration ID
        - Title: Vulnerability name/type
        - Severity: Critical/High/Medium/Low/Info
        - Description: What the vulnerability is
        - Solution/Remediation: How to fix it
        - Evidence: Proof of vulnerability (matched pattern, reflection, etc.)
        - Request: Full HTTP request that triggered the vulnerability
        - Response: Relevant part of HTTP response showing the vulnerability

        Args:
            vulnerable: Whether vulnerability was found
            url: Target URL
            parameter: Vulnerable parameter
            payload: Payload used
            evidence: Evidence of vulnerability (REQUIRED - matched pattern/reflection)
            description: Description of vulnerability
            confidence: Detection confidence (0.0-1.0)
            severity: Override severity from config
            request: Full HTTP request (method, headers, body)
            response: Relevant response content showing vulnerability
            **kwargs: Additional fields

        Returns:
            Standardized result dictionary with all required fields
        """
        from datetime import datetime
        from urllib.parse import urlparse

        # Get proper vulnerability name (remove "Scanner" suffix)
        vuln_name = self.config.get('name', 'Unknown Vulnerability')
        if vuln_name.endswith(' Scanner'):
            vuln_name = vuln_name[:-8]  # Remove " Scanner"

        # Get security metadata from config
        cwe = self.config.get('cwe', 'CWE-Unknown')
        cwe_name = self.config.get('cwe_name', '')
        owasp = self.config.get('owasp', 'A00:2021')
        owasp_name = self.config.get('owasp_name', '')
        cvss = self.config.get('cvss', '0.0')
        cvss_vector = self.config.get('cvss_vector', '')

        # Get remediation/solution (from config or generic based on CWE)
        remediation = self.config.get('remediation', self._get_generic_remediation(cwe))

        # Build HTTP request if not provided
        if not request and url:
            method = kwargs.get('method', 'GET')
            parsed = urlparse(url)
            request = self._build_http_request(method, parsed, parameter, payload)

        # Ensure evidence is meaningful
        if not evidence or evidence in ['', 'N/A', 'None']:
            if response:
                # Try to extract evidence from response
                evidence = self._extract_evidence_from_response(response, payload)
            else:
                evidence = f"Vulnerability detected with payload: {payload}" if payload else "Vulnerability detected"

        # Ensure description is meaningful
        if not description:
            description = self.config.get('description', f"{vuln_name} vulnerability detected")

        result = {
            # === REQUIRED FIELDS ===
            'vulnerability': vulnerable,
            'type': vuln_name,                          # Title
            'module': self.config.get('name', self.name),
            'severity': severity or self.get_severity(),
            'cwe': cwe,                                 # CWE ID
            'cwe_name': cwe_name,                       # CWE Name
            'description': description,                 # What is the vulnerability
            'remediation': remediation,                 # Solution - how to fix
            'evidence': evidence,                       # Proof of vulnerability
            'request': request,                         # Full HTTP request
            'response': response[:5000] if response else '',  # Response (truncated)

            # === ADDITIONAL METADATA ===
            'url': url,
            'parameter': parameter,
            'payload': payload,
            'method': kwargs.get('method', 'GET'),
            'confidence': confidence,
            'owasp': owasp,
            'owasp_name': owasp_name,
            'cvss': cvss,
            'cvss_vector': cvss_vector,
            'exploitation_steps': kwargs.get('exploitation_steps', []),
            'timestamp': datetime.now().isoformat()
        }

        # Add any additional fields
        result.update(kwargs)

        return result

    def _build_http_request(self, method: str, parsed_url, parameter: str, payload: str) -> str:
        """Build HTTP request string for evidence"""
        path = parsed_url.path or '/'
        if parsed_url.query:
            path += f"?{parsed_url.query}"

        request_lines = [
            f"{method} {path} HTTP/1.1",
            f"Host: {parsed_url.netloc}",
            "User-Agent: Dominator-Scanner/1.0",
            "Accept: */*",
            "Connection: close"
        ]

        if method == 'POST' and parameter and payload:
            body = f"{parameter}={payload}"
            request_lines.append("Content-Type: application/x-www-form-urlencoded")
            request_lines.append(f"Content-Length: {len(body)}")
            request_lines.append("")
            request_lines.append(body)

        return "\n".join(request_lines)

    def _extract_evidence_from_response(self, response: str, payload: str) -> str:
        """Extract evidence showing vulnerability from response"""
        if not response:
            return "No response captured"

        # If payload is reflected, show context around it
        if payload and payload in response:
            context = self.extract_response_context(response, payload, 150, 100)
            if context:
                return f"Payload reflected in response:\n{context}"

        # Show first 500 chars of response as evidence
        preview = response[:500]
        if len(response) > 500:
            preview += "\n... (truncated)"
        return f"Response preview:\n{preview}"

    def test_payloads_concurrent(self,
                                 payloads: List[str],
                                 test_function: Callable,
                                 max_workers: int = None) -> Any:
        """
        Test multiple payloads concurrently for performance (ZAP-speed optimization)

        This method sends multiple HTTP requests in parallel, dramatically improving
        scan speed. Uses early-exit strategy - stops testing as soon as a vulnerability
        is found.

        Args:
            payloads: List of payloads to test
            test_function: Function to test each payload.
                          Should accept (payload) and return (found: bool, result: dict or None)
            max_workers: Number of concurrent threads (default: self.concurrent_requests)

        Returns:
            First vulnerability result found, or None if no vulnerabilities

        Example:
            def test_single_payload(payload):
                response = http_client.get(url, params={'id': payload})
                if is_vulnerable(response):
                    return True, create_result(...)
                return False, None

            result = self.test_payloads_concurrent(payloads, test_single_payload)
        """
        if max_workers is None:
            max_workers = self.concurrent_requests

        # Early exit flag - shared state to signal other threads to stop
        found_vulnerability = False
        vulnerability_result = None

        def wrapper(payload):
            """Wrapper to handle early exit"""
            nonlocal found_vulnerability, vulnerability_result

            # Skip if another thread already found a vulnerability
            if found_vulnerability and self.early_exit:
                return False, None

            # Test the payload
            try:
                found, result = test_function(payload)

                # If vulnerability found, set flag and save result
                if found:
                    found_vulnerability = True
                    vulnerability_result = result
                    return True, result

                return False, None
            except Exception as e:
                logger.debug(f"Error testing payload {payload[:50]}: {e}")
                return False, None

        # Execute payloads concurrently
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            # Submit all payload tests
            futures = {executor.submit(wrapper, payload): payload for payload in payloads}

            # Process results as they complete
            for future in as_completed(futures):
                try:
                    found, result = future.result()

                    # Early exit: stop as soon as we find a vulnerability
                    if found and self.early_exit:
                        # Cancel remaining futures
                        for f in futures:
                            f.cancel()
                        return result

                except Exception as e:
                    payload = futures[future]
                    logger.debug(f"Exception testing payload {payload[:50]}: {e}")

        return vulnerability_result

    def _get_generic_remediation(self, cwe: str) -> str:
        """
        Get generic remediation advice based on CWE

        Args:
            cwe: CWE identifier (e.g., 'CWE-79')

        Returns:
            Remediation advice string
        """
        remediations = {
            'CWE-79': 'Sanitize all user input before rendering in HTML. Use context-appropriate encoding (HTML entity encoding, JavaScript encoding, URL encoding). Implement Content Security Policy (CSP) headers to prevent inline script execution.',

            'CWE-89': 'Use parameterized queries (prepared statements) instead of string concatenation. Apply strict input validation with allowlists. Use ORM frameworks. Implement least privilege database access with read-only accounts where possible.',

            'CWE-639': 'Implement proper authorization checks before allowing access to objects. Validate that the authenticated user has permission to access the requested object. Use indirect object references (mapping internal IDs to user-facing tokens). Log all object access attempts.',

            'CWE-352': 'Implement anti-CSRF tokens in all state-changing forms. Use SameSite cookie attribute. Validate Origin/Referer headers. Require re-authentication for sensitive operations.',

            'CWE-98': 'Avoid including files based on user input. Use allowlists of permitted files. Disable remote file inclusion (allow_url_include=Off in PHP). Use absolute paths and validate file extensions.',

            'CWE-611': 'Disable external entity processing in XML parsers. Use safe parser configurations (e.g., libxml_disable_entity_loader(true) in PHP). Validate and sanitize XML input. Use simple data formats like JSON when possible.',

            'CWE-918': 'Validate and sanitize all URLs. Use allowlists for permitted domains/protocols. Implement network segmentation to restrict server-side requests. Disable unused URL schemes. Use DNS resolution validation.',

            'CWE-94': 'Avoid using user input in template expressions. Use sandboxed template engines with auto-escaping. Validate input against strict allowlists. Use logic-less template engines when possible.',

            'CWE-77': 'Avoid executing system commands with user input. Use parameterized APIs instead of shell commands. Validate input against strict allowlists. Use language-specific functions instead of shell execution.',

            'CWE-601': 'Validate redirect URLs against allowlist of permitted domains. Use relative URLs for internal redirects. Implement warning pages for external redirects. Avoid user-controlled redirect parameters.',

            'CWE-91': 'Use parameterized XPath queries. Validate and sanitize all user input. Use allowlists for permitted characters. Avoid constructing XPath queries with string concatenation.',

            'CWE-502': 'Avoid deserializing untrusted data. Use safe serialization formats like JSON. Implement integrity checks (HMAC) on serialized data. Use allowlists for permitted classes during deserialization.',

            'CWE-943': 'Never trust user input in NoSQL queries. Use parameterized query methods provided by the database driver. Validate input types and formats. Implement proper authentication and authorization.',

            'CWE-1236': 'Avoid CSV formula injection by prefixing user input with single quote. Validate exported data. Use CSV export libraries that sanitize formulas. Warn users before opening exported files.',

            'CWE-521': 'Enforce strong password policies (minimum length, complexity). Implement account lockout after failed attempts. Use multi-factor authentication. Check passwords against breach databases. Never use default credentials.',

            'CWE-209': 'Implement custom error pages that don\'t reveal sensitive information. Log detailed errors server-side only. Use generic error messages for users. Disable debug mode in production.',

            'CWE-538': 'Remove .git directories and sensitive files from production servers. Use .gitignore properly. Configure web server to deny access to dotfiles. Never commit credentials to repositories.',

            'CWE-548': 'Disable directory listing in web server configuration. Configure proper index files. Implement proper access controls. Use security headers to prevent information disclosure.',

            'CWE-312': 'Never store credentials in code or configuration files. Use environment variables or secure vaults. Encrypt sensitive data at rest. Rotate credentials regularly. Use secret scanning tools.',

            'CWE-22': 'Validate file paths against allowlists. Use canonicalization to resolve paths. Reject paths with ../ or absolute paths. Use chroot jails or restricted directories.',
        }

        return remediations.get(cwe, 'Review and remediate this vulnerability according to security best practices. Implement input validation, output encoding, and principle of least privilege.')

