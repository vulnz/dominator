"""
Error Message Checks Passive Detector

Inspired by PortSwigger's Error Message Checks BApp extension.
Identifies and reports detailed server error messages that reveal:
- Stack traces with file paths and line numbers
- Database error messages with query details
- Framework-specific debugging information
- Technology disclosure through error patterns

This is a PASSIVE detector - no additional requests are sent.
It analyzes responses captured during normal crawling/scanning.
"""

import re
from typing import Dict, List, Tuple, Any, Set


class ErrorMessageDetector:
    """
    Passive error message detection for multiple technologies.

    Detects verbose error messages from:
    - Java/JVM (stack traces, JSP errors)
    - ASP.NET (framework errors, stack traces)
    - PHP (function errors, warnings, notices)
    - Python (tracebacks, Django/Flask errors)
    - Ruby (Rails errors, Rack traces)
    - Perl (die/warn messages)
    - Node.js (Express errors, stack traces)
    - Generic server errors
    """

    # Compiled regex patterns for performance
    _patterns = None
    _initialized = False

    @classmethod
    def _init_patterns(cls):
        """Initialize regex patterns (lazy loading for performance)"""
        if cls._initialized:
            return

        cls._patterns = {
            # ===== JAVA / JVM =====
            'java_stack_trace': {
                'patterns': [
                    # Java exception with package path
                    re.compile(r'(?:Exception|Error|Throwable)\s+(?:in|at)\s+([a-zA-Z_$][a-zA-Z\d_$]*(?:\.[a-zA-Z_$][a-zA-Z\d_$]*)+)', re.IGNORECASE),
                    # Java stack trace line
                    re.compile(r'at\s+([a-zA-Z_$][a-zA-Z\d_$]*(?:\.[a-zA-Z_$][a-zA-Z\d_$]*)+)\(([^)]+\.java):(\d+)\)'),
                    # Caused by chain
                    re.compile(r'Caused by:\s*([a-zA-Z_$][a-zA-Z\d_$]*(?:\.[a-zA-Z_$][a-zA-Z\d_$]*)*(?:Exception|Error))'),
                    # Tomcat/Servlet errors
                    re.compile(r'(?:javax|jakarta)\.servlet\.[a-zA-Z]+Exception'),
                    # Spring framework errors
                    re.compile(r'org\.springframework\.[a-zA-Z.]+Exception'),
                ],
                'severity': 'High',
                'type': 'Java Stack Trace',
                'description': 'Java/JVM stack trace exposed revealing code structure and file paths'
            },

            'jsp_error': {
                'patterns': [
                    re.compile(r'org\.apache\.jasper\.JasperException'),
                    re.compile(r'An error occurred at line:?\s*(\d+)\s*in the jsp file'),
                    re.compile(r'Stacktrace:'),
                    re.compile(r'javax\.el\.ELException'),
                ],
                'severity': 'High',
                'type': 'JSP Error',
                'description': 'JSP compilation or runtime error exposed'
            },

            # ===== ASP.NET =====
            'aspnet_error': {
                'patterns': [
                    # ASP.NET runtime error
                    re.compile(r'Server Error in \'[^\']+\' Application'),
                    re.compile(r'Runtime Error'),
                    re.compile(r'ASP\.NET\s+(?:is configured|error)'),
                    # Stack trace with line numbers
                    re.compile(r'at\s+[A-Za-z_][A-Za-z0-9_]*\.[A-Za-z_][A-Za-z0-9_<>]*\([^)]*\)\s+in\s+[^\s:]+:line\s+\d+'),
                    # .NET exception
                    re.compile(r'System\.[A-Za-z]+Exception'),
                    re.compile(r'Microsoft\.CSharp\.RuntimeBinder\.[A-Za-z]+Exception'),
                    # YSOD (Yellow Screen of Death)
                    re.compile(r'<title>.*(?:Runtime Error|Server Error).*</title>', re.IGNORECASE),
                ],
                'severity': 'High',
                'type': 'ASP.NET Error',
                'description': 'ASP.NET framework error exposed with potential source code paths'
            },

            # ===== PHP =====
            'php_error': {
                'patterns': [
                    # PHP warnings/errors with file path
                    re.compile(r'(?:Warning|Fatal error|Parse error|Notice):\s*[^<\n]+ in\s+(/[^\s]+\.php|[A-Z]:\\[^\s]+\.php)\s+on line\s+\d+', re.IGNORECASE),
                    # PHP function errors
                    re.compile(r'(?:Warning|Error):\s*([a-z_]+)\(\):', re.IGNORECASE),
                    # PHP stack trace
                    re.compile(r'#\d+\s+(/[^\s]+\.php|[A-Z]:\\[^\s]+\.php)\(\d+\):'),
                    # Xdebug output
                    re.compile(r'<b>(?:Warning|Fatal error|Notice)</b>:\s*[^<]+ in <b>([^<]+)</b> on line <b>(\d+)</b>'),
                    # PHP uncaught exception
                    re.compile(r'Uncaught (?:Exception|Error|TypeError) .+ thrown in .+ on line \d+'),
                ],
                'severity': 'High',
                'type': 'PHP Error',
                'description': 'PHP error message exposing file paths and code structure'
            },

            # ===== PYTHON =====
            'python_error': {
                'patterns': [
                    # Python traceback
                    re.compile(r'Traceback \(most recent call last\):'),
                    re.compile(r'File "([^"]+)", line (\d+)'),
                    # Django debug
                    re.compile(r'(?:Django|OperationalError|ProgrammingError|IntegrityError)'),
                    re.compile(r'You\'re seeing this error because you have DEBUG = True'),
                    # Flask/Werkzeug
                    re.compile(r'werkzeug\.exceptions\.[A-Za-z]+'),
                    re.compile(r'The debugger caught an exception'),
                    # Python exception types
                    re.compile(r'(?:ValueError|TypeError|AttributeError|KeyError|IndexError|ImportError|NameError|RuntimeError|ZeroDivisionError):'),
                ],
                'severity': 'High',
                'type': 'Python Traceback',
                'description': 'Python traceback exposed revealing application structure'
            },

            # ===== RUBY =====
            'ruby_error': {
                'patterns': [
                    # Ruby/Rails errors
                    re.compile(r'ActionController::RoutingError'),
                    re.compile(r'ActionView::Template::Error'),
                    re.compile(r'ActiveRecord::[A-Za-z]+Error'),
                    re.compile(r'Rack::QueryParser::InvalidParameterError'),
                    # Ruby stack trace
                    re.compile(r'([^\s]+\.rb):(\d+):in `([^\']+)\''),
                    # Rails error page indicators
                    re.compile(r'Rails\.root:'),
                    re.compile(r'<h1>.*(?:error|exception).*occurred</h1>', re.IGNORECASE),
                ],
                'severity': 'High',
                'type': 'Ruby/Rails Error',
                'description': 'Ruby on Rails error message exposing application details'
            },

            # ===== PERL =====
            'perl_error': {
                'patterns': [
                    # Perl errors
                    re.compile(r'(?:at|in)\s+(/[^\s]+\.(?:pl|pm|cgi))\s+line\s+(\d+)'),
                    re.compile(r'Use of uninitialized value'),
                    re.compile(r'Can\'t locate [^\s]+ in @INC'),
                    re.compile(r'Execution of [^\s]+ aborted'),
                ],
                'severity': 'High',
                'type': 'Perl Error',
                'description': 'Perl error message exposing script locations'
            },

            # ===== NODE.JS =====
            'nodejs_error': {
                'patterns': [
                    # Node.js errors
                    re.compile(r'at\s+[^\s]+\s+\((/[^\s]+\.js):(\d+):(\d+)\)'),
                    re.compile(r'at\s+[^\s]+\s+\(([A-Z]:\\[^\s]+\.js):(\d+):(\d+)\)'),
                    # Express errors
                    re.compile(r'Error: .+\n\s+at [^\s]+ \([^\)]+\)'),
                    re.compile(r'TypeError: .+\n\s+at'),
                    re.compile(r'ReferenceError: .+\n\s+at'),
                    # Express stack
                    re.compile(r'at Layer\.handle \[as handle_request\]'),
                ],
                'severity': 'High',
                'type': 'Node.js Error',
                'description': 'Node.js stack trace exposing server-side JavaScript paths'
            },

            # ===== GENERIC DATABASE ERRORS =====
            'database_error': {
                'patterns': [
                    # MySQL
                    re.compile(r'You have an error in your SQL syntax'),
                    re.compile(r'mysql_[a-z_]+\(\).*(?:Warning|Error)', re.IGNORECASE),
                    re.compile(r'mysqli?::?[a-z_]+\(\):', re.IGNORECASE),
                    # PostgreSQL
                    re.compile(r'ERROR:\s+syntax error at or near'),
                    re.compile(r'PG::(?:Syntax)?Error'),
                    re.compile(r'org\.postgresql\.util\.PSQLException'),
                    # SQLite
                    re.compile(r'SQLite(?:3)?::(?:Exception|Error)', re.IGNORECASE),
                    re.compile(r'SQLITE_ERROR'),
                    # Oracle
                    re.compile(r'ORA-\d{5}:'),
                    # MSSQL
                    re.compile(r'Microsoft OLE DB Provider for SQL Server'),
                    re.compile(r'Unclosed quotation mark after the character string'),
                    re.compile(r'\[Microsoft\]\[ODBC SQL Server Driver\]'),
                    # MongoDB
                    re.compile(r'MongoError:'),
                    re.compile(r'MongoDB[^:]*Exception'),
                ],
                'severity': 'High',
                'type': 'Database Error',
                'description': 'Database error message potentially revealing query structure'
            },

            # ===== GENERIC SERVER ERRORS =====
            # NOTE: Removed overly generic patterns that cause false positives
            # Only detect actual verbose error pages, not normal server headers
            'server_error': {
                'patterns': [
                    # Apache error page (actual error, not just header)
                    re.compile(r'<address>Apache/[\d.]+ \([^)]+\) Server at [^\s]+ Port \d+</address>'),
                    # IIS detailed error page
                    re.compile(r'<title>IIS\s+\d+\.\d+\s+Detailed Error</title>', re.IGNORECASE),
                    # Actual 500 error PAGE (not just status code)
                    re.compile(r'<html[^>]*>.*<title>500 Internal Server Error</title>', re.IGNORECASE | re.DOTALL),
                ],
                'severity': 'Medium',
                'type': 'Server Error',
                'description': 'Server error page with technology disclosure'
            },

            # ===== CONFIGURATION EXPOSURE =====
            'config_exposure': {
                'patterns': [
                    # Debug mode enabled
                    re.compile(r'Debug mode is enabled'),
                    re.compile(r'DEGUB\s*=\s*True', re.IGNORECASE),
                    re.compile(r'display_errors\s*=\s*On', re.IGNORECASE),
                    # Environment variables
                    re.compile(r'(?:DB_|DATABASE_|MYSQL_|POSTGRES_)(?:HOST|USER|PASSWORD|NAME)'),
                    # Connection strings
                    re.compile(r'(?:Server|Data Source)=[^;]+;(?:Database|Initial Catalog)=[^;]+;'),
                ],
                'severity': 'High',
                'type': 'Configuration Exposure',
                'description': 'Application configuration or debug settings exposed'
            },
        }

        cls._initialized = True

    @classmethod
    def analyze(cls, response_text: str, url: str, headers: Dict[str, str] = None) -> Tuple[bool, List[Dict[str, Any]]]:
        """
        Analyze response for error messages.

        This is a passive detector - it only analyzes existing response content.
        No additional HTTP requests are made.

        Args:
            response_text: HTTP response body
            url: URL being analyzed
            headers: HTTP response headers (optional)

        Returns:
            Tuple of (found_errors, list_of_findings)
        """
        # Initialize patterns if needed
        cls._init_patterns()

        if not response_text:
            return False, []

        findings = []
        detected_signatures: Set[str] = set()  # Prevent duplicates

        # Check each pattern category
        for category, config in cls._patterns.items():
            for pattern in config['patterns']:
                matches = pattern.finditer(response_text)

                for match in matches:
                    # Create signature to prevent duplicates
                    match_text = match.group(0)[:100]
                    signature = f"{category}:{match_text}"

                    if signature in detected_signatures:
                        continue
                    detected_signatures.add(signature)

                    # Extract context around the match
                    start = max(0, match.start() - 100)
                    end = min(len(response_text), match.end() + 200)
                    context = response_text[start:end].strip()

                    # Clean up context (remove excessive whitespace)
                    context = re.sub(r'\s+', ' ', context)[:400]

                    # Extract specific details if available
                    details = cls._extract_details(match, category)

                    finding = {
                        'type': config['type'],
                        'severity': config['severity'],
                        'url': url,
                        'description': config['description'],
                        'matched_pattern': match_text[:200],
                        'context': context,
                        'category': category,
                        'location': 'Response Body',
                        'details': details,
                        'recommendation': cls._get_recommendation(category)
                    }

                    findings.append(finding)

        # Deduplicate by URL + type combination
        seen = set()
        unique_findings = []
        for finding in findings:
            key = f"{finding['url']}:{finding['type']}:{finding['matched_pattern'][:50]}"
            if key not in seen:
                seen.add(key)
                unique_findings.append(finding)

        return len(unique_findings) > 0, unique_findings

    @classmethod
    def _extract_details(cls, match, category: str) -> Dict[str, Any]:
        """Extract specific details from match groups"""
        details = {}

        try:
            groups = match.groups()
            if not groups:
                return details

            if category in ['java_stack_trace', 'php_error', 'python_error', 'perl_error', 'nodejs_error']:
                if len(groups) >= 1:
                    details['file_path'] = groups[0]
                if len(groups) >= 2:
                    details['line_number'] = groups[1]
                if len(groups) >= 3:
                    details['method'] = groups[2]

        except Exception:
            pass

        return details

    @classmethod
    def _get_recommendation(cls, category: str) -> str:
        """Get remediation recommendation for error category"""
        recommendations = {
            'java_stack_trace': 'Configure custom error pages and disable stack trace display in production. '
                               'Use logging frameworks to capture errors server-side only.',

            'jsp_error': 'Disable JSP debugging in production. Configure custom error pages in web.xml. '
                        'Never expose raw JSP errors to end users.',

            'aspnet_error': 'Set <customErrors mode="On"/> in web.config. Disable detailed errors in production. '
                           'Use Application_Error in Global.asax for logging.',

            'php_error': 'Set display_errors=Off and log_errors=On in php.ini for production. '
                        'Use custom error handlers and never expose PHP errors publicly.',

            'python_error': 'Set DEBUG=False in production settings. Configure proper exception handling. '
                           'Use logging to capture errors server-side.',

            'ruby_error': 'Set config.consider_all_requests_local=false in production. '
                         'Configure custom error pages. Use exception notification services.',

            'perl_error': 'Use CGI::Carp fatalsToBrowser only in development. '
                         'Configure proper error handling and logging.',

            'nodejs_error': 'Disable stack traces in production. Use process.env.NODE_ENV="production". '
                           'Implement custom error handling middleware.',

            'database_error': 'Never expose raw database errors. Use try-catch blocks and log errors server-side. '
                             'Return generic error messages to users.',

            'server_error': 'Configure custom error pages. Remove server version headers. '
                           'Use security headers like Server: to hide technology.',

            'config_exposure': 'Disable debug mode in production. Remove sensitive configuration from responses. '
                              'Use environment variables stored securely.',
        }

        return recommendations.get(category,
            'Configure proper error handling. Disable verbose errors in production. '
            'Log detailed errors server-side only and show generic messages to users.')

    @classmethod
    def detect(cls, response_text: str, url: str, headers: Dict[str, str] = None) -> Tuple[bool, List[Dict[str, Any]]]:
        """
        Alias for analyze() method for compatibility with passive scanner.

        Args:
            response_text: HTTP response body
            url: URL being analyzed
            headers: HTTP response headers (optional)

        Returns:
            Tuple of (found_errors, list_of_findings)
        """
        return cls.analyze(response_text, url, headers)


# Convenience function for direct use
def detect_error_messages(response_text: str, url: str, headers: Dict[str, str] = None) -> Tuple[bool, List[Dict[str, Any]]]:
    """
    Convenience function to detect error messages.

    Args:
        response_text: HTTP response body
        url: URL being analyzed
        headers: HTTP response headers (optional)

    Returns:
        Tuple of (found_errors, list_of_findings)
    """
    return ErrorMessageDetector.analyze(response_text, url, headers)
