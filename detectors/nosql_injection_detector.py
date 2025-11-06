"""
NoSQL Injection vulnerability detection logic
"""

import re
from typing import Tuple, List, Dict, Any

class NoSQLInjectionDetector:
    """NoSQL Injection vulnerability detection logic"""
    
    @staticmethod
    def get_nosql_error_patterns() -> List[str]:
        """Get NoSQL error patterns"""
        return [
            'MongoError', 'CouchDBError', 'CassandraError',
            'mongodb://', 'couchdb', 'cassandra',
            'SyntaxError: Unexpected token',
            'ReferenceError:', 'TypeError:',
            'JSON.parse', 'JSON.stringify',
            'db.collection', 'db.find', 'db.insert',
            '$where', '$ne', '$gt', '$lt', '$regex',
            'ObjectId', 'ISODate', 'NumberLong',
            'E11000 duplicate key', 'ValidationError'
        ]
    
    @staticmethod
    def detect_nosql_injection(response_text: str, response_code: int, payload: str) -> bool:
        """
        Detect NoSQL injection vulnerability
        Returns True if NoSQL injection is detected
        """
        if response_code >= 500:
            return False
        
        response_lower = response_text.lower()
        patterns = NoSQLInjectionDetector.get_nosql_error_patterns()
        
        # Check for NoSQL-specific errors or responses
        found_patterns = 0
        for pattern in patterns:
            if pattern.lower() in response_lower:
                found_patterns += 1
        
        # Need multiple indicators for confidence
        if found_patterns >= 2:
            return True
        
        # Check for specific NoSQL injection patterns
        nosql_patterns = [
            r'mongoerror.*',
            r'syntaxerror: unexpected token',
            r'referenceerror:.*',
            r'db\.collection.*',
            r'\$where.*\$ne.*',
            r'objectid\(["\'].*["\'\)]',
            r'e11000 duplicate key'
        ]
        
        for pattern in nosql_patterns:
            if re.search(pattern, response_text, re.IGNORECASE):
                return True
        
        return False
    
    @staticmethod
    def get_evidence(payload: str, response_text: str) -> str:
        """Get evidence of NoSQL injection vulnerability"""
        patterns = NoSQLInjectionDetector.get_nosql_error_patterns()
        found_patterns = []
        
        response_lower = response_text.lower()
        for pattern in patterns:
            if pattern.lower() in response_lower:
                found_patterns.append(pattern)
        
        if found_patterns:
            return f"NoSQL injection detected. Found NoSQL indicators: {', '.join(found_patterns[:3])}"
        
        return "NoSQL injection vulnerability detected based on response patterns"
    
    @staticmethod
    def get_response_snippet(payload: str, response_text: str) -> str:
        """Get relevant response snippet"""
        patterns = NoSQLInjectionDetector.get_nosql_error_patterns()
        
        for pattern in patterns:
            if pattern.lower() in response_text.lower():
                start = max(0, response_text.lower().find(pattern.lower()) - 50)
                end = min(len(response_text), start + 200)
                return response_text[start:end]
        
        return response_text[:200]
    
    @staticmethod
    def get_remediation_advice() -> str:
        """Get remediation advice for NoSQL injection vulnerabilities"""
        return (
            "Use parameterized queries and proper input validation for NoSQL databases. "
            "Avoid dynamic query construction with user input. "
            "Implement proper access controls and use database-specific security features. "
            "Sanitize and validate all user inputs before using in database operations."
        )
