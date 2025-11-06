"""
Insecure Deserialization vulnerability detection logic with enhanced validation
"""

import re
import base64

class InsecureDeserializationDetector:
    """Insecure Deserialization vulnerability detection logic"""
    
    @staticmethod
    def detect_insecure_deserialization(response_text, response_code, payload):
        """Detect insecure deserialization vulnerability with enhanced validation"""
        if response_code >= 500:
            # Check if it's a deserialization-related error
            deser_error_patterns = [
                r'deserialization.*?error',
                r'unserialize.*?error',
                r'pickle.*?error',
                r'ObjectInputStream',
                r'readObject.*?exception',
                r'ClassNotFoundException',
                r'InvalidClassException'
            ]
            
            for pattern in deser_error_patterns:
                if re.search(pattern, response_text, re.IGNORECASE):
                    return True, "Deserialization error detected", "Medium"
            
            return False, "Server error unrelated to deserialization", "None"
        
        # Check for deserialization markers in payload
        if 'deser_marker' not in payload.lower():
            return False, "No deserialization marker in payload", "None"
        
        # Look for successful deserialization indicators
        success_indicators = [
            # Direct marker reflection
            r'deser_marker',
            r'deserialization_test',
            
            # Java deserialization success indicators
            r'java\.util\.HashMap',
            r'java\.util\.ArrayList',
            r'java\.lang\.String',
            r'serialVersionUID',
            
            # PHP deserialization success indicators
            r'stdClass.*?Object',
            r'__wakeup.*?called',
            r'__destruct.*?called',
            r'unserialize.*?success',
            
            # Python pickle success indicators
            r'pickle\.loads',
            r'__reduce__.*?called',
            r'copyreg\._reconstruct',
            
            # .NET deserialization success indicators
            r'BinaryFormatter',
            r'DataContractSerializer',
            r'System\.Collections',
            
            # Generic object instantiation indicators
            r'Object.*?instantiated',
            r'Constructor.*?called',
            r'Instance.*?created'
        ]
        
        matches = 0
        matched_indicators = []
        
        for pattern in success_indicators:
            if re.search(pattern, response_text, re.IGNORECASE | re.MULTILINE):
                matches += 1
                matched_indicators.append(pattern)
        
        # Strong indicators that confirm deserialization
        strong_indicators = [
            r'deser_marker.*?deserialization_test',
            r'java\.util\.HashMap.*?deser_marker',
            r'stdClass.*?deser_marker',
            r'__wakeup.*?deser_marker'
        ]
        
        for pattern in strong_indicators:
            if re.search(pattern, response_text, re.IGNORECASE):
                return True, "Deserialization marker successfully processed", "High"
        
        # Check for file system access (potential RCE via deserialization)
        file_access_patterns = [
            r'root:.*?:0:0:',
            r'daemon:.*?:/usr/sbin/nologin',
            r'\[fonts\]',
            r'\[extensions\]'
        ]
        
        for pattern in file_access_patterns:
            if re.search(pattern, response_text, re.IGNORECASE):
                if 'deser_marker' in payload:
                    return True, "File system access via deserialization", "High"
        
        # Check for command execution indicators
        command_indicators = [
            r'uid=\d+.*?gid=\d+',
            r'Microsoft Windows.*?Version',
            r'Directory of.*?C:\\',
            r'total \d+.*?drwx'
        ]
        
        for pattern in command_indicators:
            if re.search(pattern, response_text, re.IGNORECASE):
                if 'deser_marker' in payload:
                    return True, "Command execution via deserialization", "High"
        
        # Require multiple weak indicators
        if matches >= 2:
            return True, f"Multiple deserialization indicators found: {', '.join(matched_indicators[:3])}", "Medium"
        
        return False, "No clear deserialization vulnerability detected", "None"
    
    @staticmethod
    def get_response_snippet(payload, response_text):
        """Get response snippet showing deserialization"""
        # Find the most relevant part of the response
        deser_patterns = [
            r'deser_marker.*',
            r'deserialization_test.*',
            r'java\.util\..*',
            r'stdClass.*',
            r'root:.*?:0:0:.*',
            r'uid=\d+.*?gid=\d+.*'
        ]
        
        for pattern in deser_patterns:
            match = re.search(pattern, response_text, re.IGNORECASE | re.MULTILINE)
            if match:
                start = max(0, match.start() - 50)
                end = min(len(response_text), match.end() + 50)
                return response_text[start:end]
        
        return response_text[:200] + "..." if len(response_text) > 200 else response_text
    
    @staticmethod
    def get_remediation_advice():
        """Get remediation advice for insecure deserialization"""
        return "Avoid deserializing untrusted data, use safe serialization formats like JSON, implement integrity checks, and use allowlists for permitted classes."
