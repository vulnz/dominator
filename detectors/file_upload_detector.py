"""
File Upload vulnerability detection logic
"""

import re
from typing import Tuple, List, Dict, Any

class FileUploadDetector:
    """File Upload vulnerability detection logic"""
    
    @staticmethod
    def get_upload_indicators() -> List[str]:
        """Get file upload form indicators"""
        return [
            'type="file"', 'enctype="multipart/form-data"',
            'input type="file"', 'file upload', 'choose file',
            'browse file', 'select file', 'upload file',
            'drag and drop', 'drop files here',
            'accept=', 'multiple files'
        ]
    
    @staticmethod
    def get_dangerous_extensions() -> List[str]:
        """Get dangerous file extensions"""
        return [
            '.php', '.asp', '.aspx', '.jsp', '.jspx',
            '.exe', '.bat', '.cmd', '.sh', '.py',
            '.pl', '.rb', '.cgi', '.htaccess',
            '.config', '.ini', '.conf'
        ]
    
    @staticmethod
    def detect_file_upload_vulnerability(response_text: str, response_code: int, url: str) -> Tuple[bool, str, str]:
        """
        Detect file upload vulnerabilities
        Returns: (is_vulnerable, evidence, severity)
        """
        if response_code >= 400:
            return False, "Error response", "None"
        
        response_lower = response_text.lower()
        
        # Check for file upload forms
        upload_indicators = FileUploadDetector.get_upload_indicators()
        found_indicators = []
        
        for indicator in upload_indicators:
            if indicator.lower() in response_lower:
                found_indicators.append(indicator)
        
        if not found_indicators:
            return False, "No file upload forms found", "None"
        
        # Analyze upload form security
        security_issues = []
        
        # Check for missing file type restrictions
        if 'accept=' not in response_lower:
            security_issues.append("No file type restrictions")
        
        # Check for client-side only validation
        if 'javascript' in response_lower and 'validate' in response_lower:
            security_issues.append("Client-side validation only")
        
        # Check for dangerous file extensions allowed
        dangerous_exts = FileUploadDetector.get_dangerous_extensions()
        for ext in dangerous_exts:
            if ext in response_lower:
                security_issues.append(f"Dangerous extension {ext} potentially allowed")
        
        # Check for upload directory disclosure
        upload_patterns = [
            r'uploads?/[^"\s<>]+',
            r'files?/[^"\s<>]+',
            r'attachments?/[^"\s<>]+',
            r'documents?/[^"\s<>]+'
        ]
        
        for pattern in upload_patterns:
            if re.search(pattern, response_text, re.IGNORECASE):
                security_issues.append("Upload directory path disclosed")
                break
        
        if security_issues:
            severity = "High" if len(security_issues) >= 2 else "Medium"
            evidence = f"File upload form found with security issues: {', '.join(security_issues)}"
            return True, evidence, severity
        
        # Basic file upload form found but no obvious issues
        return True, "File upload form found - manual testing recommended", "Low"
    
    @staticmethod
    def get_evidence(indicators: List[str], security_issues: List[str]) -> str:
        """Get detailed evidence of file upload vulnerability"""
        evidence_parts = []
        
        if indicators:
            evidence_parts.append(f"Found file upload indicators: {', '.join(indicators[:3])}")
        
        if security_issues:
            evidence_parts.append(f"Security issues: {', '.join(security_issues)}")
        
        return ". ".join(evidence_parts)
    
    @staticmethod
    def get_response_snippet(response_text: str) -> str:
        """Get relevant response snippet"""
        # Look for file upload forms
        patterns = [
            r'<form[^>]*enctype="multipart/form-data"[^>]*>.*?</form>',
            r'<input[^>]*type="file"[^>]*>',
            r'file upload[^<]*',
            r'choose file[^<]*'
        ]
        
        for pattern in patterns:
            match = re.search(pattern, response_text, re.IGNORECASE | re.DOTALL)
            if match:
                return match.group(0)[:300]
        
        return response_text[:200]
    
    @staticmethod
    def get_response_snippet(response_text: str) -> str:
        """Get response snippet for file upload"""
        # Look for form content
        import re
        form_match = re.search(r'<form[^>]*>.*?</form>', response_text, re.IGNORECASE | re.DOTALL)
        if form_match:
            form_content = form_match.group(0)
            if len(form_content) > 400:
                return form_content[:400] + "..."
            return form_content
        
        if len(response_text) > 300:
            return response_text[:300] + "..."
        return response_text
    
    @staticmethod
    def get_remediation_advice() -> str:
        """Get remediation advice for file upload"""
        return (
            "Implement file type validation and size limits. "
            "Use whitelist of allowed file extensions. "
            "Store uploaded files outside web root and scan for malware."
        )
    
    @staticmethod
    def get_remediation_advice() -> str:
        """Get remediation advice for file upload vulnerabilities"""
        return (
            "Implement server-side file type validation using MIME type checking and file content analysis. "
            "Restrict file extensions to only necessary types. "
            "Store uploaded files outside the web root and use indirect access. "
            "Implement file size limits and scan for malware. "
            "Use proper file naming conventions to prevent path traversal."
        )
