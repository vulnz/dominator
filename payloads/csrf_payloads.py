"""
CSRF (Cross-Site Request Forgery) payloads
"""

from utils.payload_loader import PayloadLoader

class CSRFPayloads:
    """CSRF payload collection"""
    
    @staticmethod
    def get_basic_payloads():
        """Get basic CSRF test payloads from text file"""
        all_payloads = PayloadLoader.load_payloads('csrf')
        return [p for p in all_payloads if any(keyword in p for keyword in ['POST /', 'PUT /', 'DELETE /', 'PATCH /'])]
    
    @staticmethod
    def get_advanced_payloads():
        """Get advanced CSRF test payloads from text file"""
        all_payloads = PayloadLoader.load_payloads('csrf')
        return [p for p in all_payloads if any(keyword in p for keyword in ['Content-Type=', 'X-Requested-With=', 'Origin=', 'Referer='])]
    
    @staticmethod
    def get_bypass_payloads():
        """Get CSRF protection bypass payloads from text file"""
        all_payloads = PayloadLoader.load_payloads('csrf')
        return [p for p in all_payloads if any(keyword in p for keyword in ['csrf_token=', '_token=', 'authenticity_token=', '__RequestVerificationToken='])]
    
    @staticmethod
    def get_parameter_payloads():
        """Get CSRF parameter payloads from text file"""
        all_payloads = PayloadLoader.load_payloads('csrf')
        return [p for p in all_payloads if 'action=' in p]
    
    @staticmethod
    def get_all_payloads():
        """Get all CSRF payloads from text file"""
        return PayloadLoader.load_payloads('csrf')
    
    @staticmethod
    def get_html_poc_template():
        """Get HTML proof of concept template for CSRF"""
        return '''
<!DOCTYPE html>
<html>
<head>
    <title>CSRF Proof of Concept</title>
</head>
<body>
    <h1>CSRF Proof of Concept</h1>
    <p>This page demonstrates a potential CSRF vulnerability.</p>
    
    <form action="{target_url}" method="POST" id="csrf-form">
        {form_fields}
        <input type="submit" value="Submit Request">
    </form>
    
    <script>
        // Auto-submit form (optional)
        // document.getElementById('csrf-form').submit();
    </script>
</body>
</html>
        '''
