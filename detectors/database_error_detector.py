"""
Database error message detection logic
"""

import re
from typing import Dict, Any, List, Tuple

class DatabaseErrorDetector:
    """Database error message detection logic"""
    
    @staticmethod
    def get_database_error_patterns() -> Dict[str, List[str]]:
        """Get patterns for different database error messages"""
        return {
            'mysql': [
                r"You have an error in your SQL syntax",
                r"mysql_fetch_array\(\)",
                r"mysql_fetch_assoc\(\)",
                r"mysql_fetch_row\(\)",
                r"mysql_num_rows\(\)",
                r"MySQL server version for the right syntax",
                r"supplied argument is not a valid MySQL",
                r"Column count doesn't match value count",
                r"Duplicate entry .* for key",
                r"Table .* doesn't exist",
                r"Unknown column .* in 'field list'",
                r"Unknown column .* in 'where clause'"
            ],
            'postgresql': [
                r"PostgreSQL query failed",
                r"pg_query\(\)",
                r"pg_exec\(\)",
                r"pg_fetch_array\(\)",
                r"Warning.*PostgreSQL",
                r"invalid input syntax for",
                r"relation .* does not exist",
                r"column .* does not exist"
            ],
            'mssql': [
                r"Microsoft OLE DB Provider for SQL Server",
                r"Unclosed quotation mark after the character string",
                r"Microsoft SQL Native Client error",
                r"ODBC SQL Server Driver",
                r"SQLServer JDBC Driver",
                r"Incorrect syntax near",
                r"Invalid column name",
                r"Cannot insert the value NULL into column"
            ],
            'oracle': [
                r"ORA-[0-9]{5}",
                r"Oracle ODBC",
                r"Oracle Driver",
                r"Oracle Error",
                r"quoted string not properly terminated",
                r"invalid identifier"
            ],
            'sqlite': [
                r"SQLite error",
                r"sqlite3.OperationalError",
                r"no such table",
                r"no such column",
                r"SQL logic error"
            ],
            'access': [
                r"Microsoft JET Database Engine",
                r"ODBC Microsoft Access Driver",
                r"Syntax error in query expression"
            ]
        }
    
    @staticmethod
    def get_generic_sql_patterns() -> List[str]:
        """Get generic SQL error patterns"""
        return [
            r"SQL syntax.*MySQL",
            r"Warning.*mysql_.*",
            r"valid MySQL result",
            r"MySqlClient\.",
            r"com\.mysql\.jdbc",
            r"Zend_Db_(Adapter|Statement)",
            r"Pdo[./_\\]Mysql",
            r"MySqlException",
            r"SQLSTATE\[",
            r"SQLException",
            r"database error",
            r"sql error",
            r"query failed",
            r"ORA-\d+",
            r"Microsoft.*ODBC.*SQL",
            r"PostgreSQL.*ERROR",
            r"Warning.*\Wpg_",
            r"valid PostgreSQL result",
            r"Npgsql\."
        ]
    
    @staticmethod
    def detect_database_errors(response_text: str, response_code: int) -> Tuple[bool, str, str, List[str]]:
        """
        Detect database error messages in response
        
        Args:
            response_text: HTTP response text
            response_code: HTTP response code
        
        Returns:
            Tuple of (is_vulnerable, database_type, evidence, error_messages)
        """
        if response_code >= 500:
            # Server errors might contain database errors
            pass
        elif response_code >= 400:
            # Client errors less likely to contain DB errors
            return False, '', 'Client error response', []
        
        error_patterns = DatabaseErrorDetector.get_database_error_patterns()
        generic_patterns = DatabaseErrorDetector.get_generic_sql_patterns()
        
        detected_errors = []
        database_type = 'unknown'
        
        # Check specific database patterns
        for db_type, patterns in error_patterns.items():
            for pattern in patterns:
                matches = re.finditer(pattern, response_text, re.IGNORECASE)
                for match in matches:
                    detected_errors.append(match.group(0))
                    database_type = db_type
        
        # Check generic SQL patterns if no specific DB detected
        if not detected_errors:
            for pattern in generic_patterns:
                matches = re.finditer(pattern, response_text, re.IGNORECASE)
                for match in matches:
                    detected_errors.append(match.group(0))
                    database_type = 'generic_sql'
        
        if detected_errors:
            evidence = f"Database error messages detected ({database_type}): {detected_errors[0][:100]}..."
            return True, database_type, evidence, detected_errors
        
        return False, '', 'No database errors detected', []
    
    @staticmethod
    def get_evidence(database_type: str, error_messages: List[str]) -> str:
        """Get evidence of database error disclosure"""
        if not error_messages:
            return "Database error messages detected"
        
        first_error = error_messages[0]
        if len(first_error) > 150:
            first_error = first_error[:150] + "..."
        
        return f"Database error disclosed ({database_type}): {first_error}"
    
    @staticmethod
    def get_response_snippet(error_messages: List[str], response_text: str, max_length: int = 300) -> str:
        """Get response snippet containing the error"""
        if not error_messages:
            return response_text[:max_length] + ("..." if len(response_text) > max_length else "")
        
        first_error = error_messages[0]
        error_index = response_text.find(first_error)
        
        if error_index != -1:
            start = max(0, error_index - 50)
            end = min(len(response_text), error_index + len(first_error) + 50)
            snippet = response_text[start:end]
            
            if len(snippet) > max_length:
                snippet = snippet[:max_length] + "..."
            
            return snippet
        
        return response_text[:max_length] + ("..." if len(response_text) > max_length else "")
    
    @staticmethod
    def get_remediation_advice() -> str:
        """Get remediation advice for database error disclosure"""
        return (
            "Configure error handling to prevent database error messages from being displayed to users. "
            "Implement custom error pages that show generic error messages. "
            "Log detailed error information server-side for debugging purposes. "
            "Use try-catch blocks around database operations and handle errors gracefully."
        )
