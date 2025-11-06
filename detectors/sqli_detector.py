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
        """Detect error-based SQL injection"""
        error_patterns = SQLiDetector.get_error_patterns()
        
        for pattern in error_patterns:
            if pattern.lower() in response_text.lower():
                return True, pattern
        
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
