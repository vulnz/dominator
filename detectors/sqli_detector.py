"""
SQL injection vulnerability detector
"""

class SQLiDetector:
    """SQL injection vulnerability detection logic"""
    
    @staticmethod
    def get_error_patterns():
        """Get SQL error patterns"""
        return [
            "mysql_fetch_array",
            "ORA-01756",
            "Microsoft OLE DB Provider for ODBC Drivers",
            "PostgreSQL query failed",
            "Warning: mysql_",
            "valid MySQL result",
            "MySqlClient.",
            "SQLException",
            "ORA-00933",
            "quoted string not properly terminated",
            "mysql_num_rows",
            "mysql_fetch_assoc",
            "ORA-00936",
            "Microsoft JET Database Engine",
            "ODBC Microsoft Access Driver",
            "SQLServer JDBC Driver",
            "Oracle error",
            "PostgreSQL error",
            "Warning: pg_",
            "valid PostgreSQL result",
            "Npgsql.",
            "Driver.*SQL.*Server",
            "OLE DB.*SQL Server",
            "\\bSQL syntax.*MySQL",
            "Warning.*\\Wmysql_.*",
            "MySQLSyntaxErrorException",
            "valid MySQL result resource",
            "check the manual that corresponds to your MySQL server version",
            "Unknown column.*in.*field list",
            "MySqlException.*Number.*",
            "Warning.*mysql_fetch_.*expects.*parameter.*",
            "Table.*doesn.*t exist",
            "Unknown database",
            "mysql_fetch_array\\(\\).*supplied argument is not a valid MySQL result resource",
            "on MySQL result index",
            "Error Executing Database Query",
            "Some Database Error",
            "MySQL Query Error",
            "Warning: mysql_query",
            "MySQL Error",
            "ERROR: parser: parse error at or near",
            "PostgreSQL query failed: ERROR: parser: parse error at or near",
            "Warning: pg_query",
            "Warning: pg_exec",
            "PostgreSQL Error",
            "Warning: pg_connect(): Unable to connect to PostgreSQL server: FATAL",
            "Warning: pg_pconnect(): Unable to connect to PostgreSQL server: FATAL",
            "Supplied argument is not a valid PostgreSQL result",
            "Unable to connect to PostgreSQL server: FATAL: password authentication failed",
            "Warning: pg_query(): Query failed: FATAL: database .* does not exist",
            "PostgreSQL.*ERROR: parser: parse error at or near",
            "Warning: mssql_query",
            "Microsoft OLE DB Provider for ODBC Drivers.*ODBC.*SQL Server",
            "Warning: mssql_connect(): Unable to connect to server",
            "Microsoft OLE DB Provider for SQL Server.*80040e14",
            "mssql_query\\(\\).*supplied argument is not a valid MS SQL-Link resource",
            "Unable to connect to SQL Server",
            "Warning: mssql_.*\\(\\): Query failed",
            "Microsoft SQL Native Client error.*80040e14",
            "\\[SQL Server\\]",
            "ODBC SQL Server Driver",
            "ODBC Driver.*for SQL Server",
            "SQLServer JDBC Driver",
            "com\\.jnetdirect\\.jsql",
            "macromedia\\.jdbc\\.sqlserver",
            "Zend_Db_(Adapter|Statement)_Sqlsrv_Exception",
            "com\\.microsoft\\.sqlserver\\.jdbc",
            "Warning: odbc_exec",
            "Warning: odbc_fetch_array",
            "Warning: odbc_num_rows",
            "Microsoft Access Driver",
            "JET Database Engine",
            "Access Database Engine",
            "ODBC Microsoft Access",
            "Syntax error.*query expression",
            "Data type mismatch in criteria expression",
            "Microsoft JET Database Engine.*80040e14",
            "\\[Microsoft\\]\\[ODBC Microsoft Access Driver\\]"
        ]
    
    @staticmethod
    def detect_error_based_sqli(response_text: str, response_code: int) -> tuple:
        """Universal SQL injection detection for any website"""
        if response_code >= 500:
            return False, None
            
        error_patterns = SQLiDetector.get_error_patterns()
        response_lower = response_text.lower()
        
        # Enhanced pattern matching with regex for better detection
        import re
        
        # Check for MySQL patterns
        if 'mysql' in error_patterns:
            for pattern in error_patterns['mysql']:
                if re.search(pattern, response_text, re.IGNORECASE):
                    return True, f"MySQL SQL error pattern: {pattern}"
        
        # Check for generic patterns
        if 'generic' in error_patterns:
            for pattern in error_patterns['generic']:
                if re.search(pattern, response_text, re.IGNORECASE):
                    return True, f"SQL error pattern: {pattern}"
        
        # Strong SQL error patterns with regex
        strong_regex_patterns = [
            r'you have an error in your sql syntax',
            r'mysql_fetch_\w+\(\)',
            r'ora-\d{5}',
            r'postgresql.*error',
            r'sqlexception',
            r'mysql.*error',
            r'unknown column.*in.*field list',
            r'table.*doesn.*t exist',
            r'syntax error.*near',
            r'microsoft.*ole db.*provider',
            r'odbc.*driver',
            r'warning.*mysql_',
            r'fatal error.*mysql',
            r'pg_query\(\).*failed',
            r'sqlite.*error',
            r'database.*error',
            r'sql.*syntax.*error'
        ]
        
        # Check for strong regex patterns
        for pattern in strong_regex_patterns:
            if re.search(pattern, response_lower, re.IGNORECASE):
                return True, f"SQL error pattern: {pattern}"
        
        # Check for multiple weaker indicators
        weak_indicators = [
            'error', 'warning', 'mysql', 'sql', 'database', 'query',
            'syntax', 'column', 'table', 'select', 'insert', 'update'
        ]
        
        indicator_count = sum(1 for indicator in weak_indicators if indicator in response_lower)
        
        # If we have many SQL-related terms, it might be SQLi
        if indicator_count >= 4:
            return True, f"Multiple SQL indicators found ({indicator_count})"
        
        # Check for specific error message patterns
        specific_patterns = [
            'supplied argument is not a valid',
            'expects parameter',
            'invalid query',
            'query failed',
            'database connection',
            'access denied for user'
        ]
        
        for pattern in specific_patterns:
            if pattern in response_lower and any(sql_term in response_lower for sql_term in ['mysql', 'sql', 'database']):
                return True, f"SQL error: {pattern}"
        
        return False, None
    
    @staticmethod
    def detect_boolean_based_sqli(true_response: str, false_response: str) -> bool:
        """Detect boolean-based SQL injection"""
        # Compare response lengths and content
        if len(true_response) != len(false_response):
            return True
        
        # Check for significant differences in content
        return true_response != false_response
    
    @staticmethod
    def get_evidence(pattern: str) -> str:
        """Get evidence of SQL injection vulnerability"""
        return f"SQL error pattern found: {pattern}"
    
    @staticmethod
    def get_response_snippet(pattern: str, response_text: str) -> str:
        """Get response snippet showing error context"""
        if pattern.lower() in response_text.lower():
            start_pos = response_text.lower().find(pattern.lower())
            context_start = max(0, start_pos - 40)
            context_end = min(len(response_text), start_pos + len(pattern) + 40)
            return response_text[context_start:context_end]
        return "Error pattern not found in response"
import re
from typing import List, Dict, Any, Tuple

class SQLiDetector:
    """SQL injection vulnerability detection logic optimized for XVWA"""
    
    @staticmethod
    def get_error_patterns():
        """Get SQL error patterns commonly found in XVWA"""
        return {
            'mysql': [
                r"You have an error in your SQL syntax",
                r"mysql_fetch_array\(\)",
                r"mysql_fetch_assoc\(\)",
                r"mysql_num_rows\(\)",
                r"mysql_query\(\)",
                r"Warning.*mysql_.*",
                r"MySQL server version for the right syntax",
                r"MySQLSyntaxErrorException",
                r"valid MySQL result",
                r"check the manual that corresponds to your MySQL server version",
                r"Unknown column '[^']+' in 'field list'",
                r"Table '[^']+' doesn't exist",
                r"Column count doesn't match value count",
                r"Duplicate entry '[^']+' for key",
                r"Data truncated for column",
                r"Incorrect integer value",
                r"Division by zero",
                r"Operand should contain [0-9]+ column\(s\)",
                r"The used SELECT statements have a different number of columns",
                r"Subquery returns more than 1 row",
                r"SQLSTATE\[HY000\]",
                r"SQLSTATE\[23000\]",
                r"SQLSTATE\[42000\]",
                r"SQLSTATE\[42S02\]",
                r"SQLSTATE\[42S22\]"
            ],
            'generic': [
                r"SQL syntax.*MySQL",
                r"Warning.*mysql_.*",
                r"MySQLSyntaxErrorException",
                r"valid MySQL result",
                r"SQLSTATE\[\d+\]",
                r"Database error",
                r"SQL error",
                r"Invalid query",
                r"Unclosed quotation mark",
                r"Syntax error in query",
                r"Column count doesn't match",
                r"Table doesn't exist",
                r"Column.*doesn't exist",
                r"Unknown column",
                r"Unknown table",
                r"Duplicate entry",
                r"Division by zero",
                r"Invalid object name"
            ]
        }

    @staticmethod
    def detect_sqli(payload: str, response_text: str, response_code: int) -> Tuple[bool, str, str, Dict[str, Any]]:
        """Enhanced SQL injection detection for XVWA"""
        if response_code not in [200, 201, 202, 500, 400, 403]:
            return False, "", "", {}

        error_patterns = SQLiDetector.get_error_patterns()
        
        # Check for SQL error messages
        for db_type, patterns in error_patterns.items():
            for pattern in patterns:
                if re.search(pattern, response_text, re.IGNORECASE):
                    severity = "Critical"
                    cvss = "9.8"
                    return True, f"SQL injection detected via {db_type.upper()} error: {pattern}", severity, {
                        'cwe': 'CWE-89',
                        'cvss': cvss,
                        'owasp': 'A03:2021 – Injection',
                        'recommendation': 'Use parameterized queries/prepared statements. Implement proper input validation and sanitization.'
                    }

        # Check for union-based SQL injection patterns
        union_patterns = [
            r"union\s+select",
            r"union\s+all\s+select"
        ]
        
        for pattern in union_patterns:
            if re.search(pattern, payload, re.IGNORECASE):
                if SQLiDetector._check_union_response(response_text):
                    return True, f"Potential UNION-based SQL injection detected: {pattern}", "Critical", {
                        'cwe': 'CWE-89',
                        'cvss': '9.8',
                        'owasp': 'A03:2021 – Injection',
                        'recommendation': 'Use parameterized queries/prepared statements. Implement proper input validation and sanitization.'
                    }

        # Check for boolean-based blind SQL injection
        if SQLiDetector._check_boolean_sqli_indicators(payload, response_text):
            return True, "Potential boolean-based blind SQL injection detected", "Critical", {
                'cwe': 'CWE-89',
                'cvss': '9.8',
                'owasp': 'A03:2021 – Injection',
                'recommendation': 'Use parameterized queries/prepared statements. Implement proper input validation and sanitization.'
            }

        return False, "", "", {}

    @staticmethod
    def _check_union_response(response_text: str) -> bool:
        """Check if response indicates successful UNION injection"""
        union_indicators = [
            r"\d+\|\d+\|\d+",
            r"\d+,\d+,\d+",
            r"\d+\s+\d+\s+\d+",
            r"user\(\)",
            r"version\(\)",
            r"database\(\)",
            r"@@version",
            r"information_schema"
        ]
        
        for indicator in union_indicators:
            if re.search(indicator, response_text, re.IGNORECASE):
                return True
        
        return False

    @staticmethod
    def _check_boolean_sqli_indicators(payload: str, response_text: str) -> bool:
        """Check for boolean-based SQL injection indicators"""
        boolean_patterns = [
            r"and\s+\d+\s*=\s*\d+",
            r"or\s+\d+\s*=\s*\d+",
            r"'\s+and\s+'\d+'\s*=\s*'\d+'",
            r"'\s+or\s+'\d+'\s*=\s*'\d+'"
        ]
        
        for pattern in boolean_patterns:
            if re.search(pattern, payload, re.IGNORECASE):
                return True
        
        return False
