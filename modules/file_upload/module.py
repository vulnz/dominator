"""
File Upload Vulnerability Scanner Module

Detects Unrestricted File Upload vulnerabilities by:
1. Finding file upload forms (input type="file")
2. Testing upload restrictions (extension, content-type, magic bytes)
3. Attempting to upload dangerous file types (PHP, ASP, JSP shells)
4. Detecting if uploaded files are accessible and executable
"""

from typing import List, Dict, Any
from core.base_module import BaseModule
from core.logger import get_logger
import re
import io

logger = get_logger(__name__)


class FileUploadModule(BaseModule):
    """File Upload vulnerability scanner module"""

    def __init__(self, module_path: str):
        """Initialize File Upload module"""
        super().__init__(module_path)

        # Dangerous extensions that should be blocked
        self.dangerous_extensions = [
            '.php', '.php5', '.php4', '.php3', '.phtml', '.pht',
            '.asp', '.aspx', '.jsp', '.jspx',
            '.exe', '.bat', '.sh', '.pl', '.cgi',
        ]

        # Upload success indicators
        self.success_indicators = [
            'uploaded successfully',
            'upload successful',
            'file uploaded',
            'upload complete',
            'successfully uploaded',
            'file saved',
        ]

        logger.info(f"File Upload module loaded: {len(self.payloads)} test filenames")

    def scan(self, targets: List[Dict[str, Any]], http_client: Any) -> List[Dict[str, Any]]:
        """
        Scan for File Upload vulnerabilities

        Args:
            targets: List of URLs with parameters
            http_client: HTTP client

        Returns:
            List of results
        """
        results = []

        logger.info(f"Starting File Upload scan on {len(targets)} targets")

        # Find file upload forms
        upload_forms = []

        for target in targets:
            url = target.get('url')
            params = target.get('params', {})
            method = target.get('method', 'GET').upper()

            # Check if URL suggests file upload
            upload_keywords = ['upload', 'file', 'attach', 'document', 'image', 'photo']
            has_upload_keyword = any(keyword in url.lower() for keyword in upload_keywords)

            # Check if form has file parameter indicators
            if params:
                param_names_lower = ' '.join(params.keys()).lower()
                has_file_param = any(keyword in param_names_lower for keyword in upload_keywords)

                if has_upload_keyword or has_file_param or method == 'POST':
                    upload_forms.append(target)

        logger.info(f"Found {len(upload_forms)} potential upload forms")

        # Test each upload form
        for target in upload_forms[:20]:  # Limit to 20 forms
            url = target.get('url')
            params = target.get('params', {})
            method = target.get('method', 'POST').upper()

            if not params:
                continue

            # Find file input parameters
            file_params = []
            for param_name in params:
                param_lower = param_name.lower()
                if any(keyword in param_lower for keyword in ['file', 'upload', 'attach', 'image', 'photo', 'document']):
                    file_params.append(param_name)

            # If no obvious file params, try all params
            if not file_params:
                file_params = list(params.keys())[:3]  # Test first 3 params

            # Test each potential file parameter
            for file_param in file_params:
                logger.debug(f"Testing File Upload in parameter: {file_param}")

                # Test with PHP shell
                detected, confidence, evidence, uploaded_path = self._test_file_upload(
                    url, params, file_param, method, http_client
                )

                if detected:
                    result = self.create_result(
                        vulnerable=True,
                        url=url,
                        parameter=file_param,
                        payload="test_shell.php",
                        evidence=evidence,
                        description="Unrestricted File Upload vulnerability detected. "
                                  "Application allows uploading dangerous file types without proper validation.",
                        confidence=confidence
                    )

                    # Add metadata
                    result['cwe'] = self.config.get('cwe', 'CWE-434')
                    result['owasp'] = self.config.get('owasp', 'A03:2021')
                    result['cvss'] = self.config.get('cvss', '9.8')
                    if uploaded_path:
                        result['uploaded_file'] = uploaded_path

                    results.append(result)
                    logger.info(f"✓ File Upload vulnerability found in {url} "
                              f"(parameter: {file_param}, confidence: {confidence:.2f})")

                    # Move to next parameter
                    break

        logger.info(f"File Upload scan complete: {len(results)} vulnerabilities found")
        return results

    def _test_file_upload(self, url: str, params: Dict[str, Any], file_param: str,
                         method: str, http_client: Any) -> tuple:
        """
        Test file upload vulnerability

        Returns:
            (detected: bool, confidence: float, evidence: str, uploaded_path: str)
        """
        # Test 1: Upload PHP file
        php_content = b"<?php echo 'DOMINATOR_FILE_UPLOAD_TEST'; ?>"
        filename = "test_dominator_shell.php"

        try:
            # Prepare multipart form data
            files = {file_param: (filename, io.BytesIO(php_content), 'application/x-php')}

            # Add other form parameters with DEFAULT values if empty
            form_data = {}
            for param_name, param_value in params.items():
                if param_name != file_param:
                    # Provide default values for common parameters
                    if not param_value or param_value == 'test':
                        if 'price' in param_name.lower():
                            form_data[param_name] = '100'
                        elif 'desc' in param_name.lower() or 'description' in param_name.lower():
                            form_data[param_name] = 'Test Description'
                        elif 'name' in param_name.lower() or 'item' in param_name.lower():
                            form_data[param_name] = 'Test Item'
                        elif 'categ' in param_name.lower():
                            form_data[param_name] = 'test'
                        else:
                            form_data[param_name] = param_value if param_value else 'test'
                    else:
                        form_data[param_name] = param_value

            # Upload file
            if method == 'POST':
                response = http_client.post(url, data=form_data, files=files)
            else:
                # GET upload is unusual but possible
                response = http_client.get(url, params=form_data, files=files)

            if not response:
                return False, 0.0, "", ""

            response_text = getattr(response, 'text', '')

        except Exception as e:
            logger.debug(f"File upload test failed: {e}")
            return False, 0.0, "", ""

        # DETECTION 1: Check for upload success message
        success_found = None
        for indicator in self.success_indicators:
            if indicator in response_text.lower():
                success_found = indicator
                break

        if success_found:
            confidence = 0.70

            # Try to extract uploaded file path from response
            uploaded_path = self._extract_uploaded_path(response_text, filename)

            if uploaded_path:
                confidence = 0.80

                # Verification: Try to access the uploaded file
                try:
                    # Construct full URL to uploaded file
                    if uploaded_path.startswith('http'):
                        verify_url = uploaded_path
                    elif uploaded_path.startswith('/'):
                        # Extract base URL
                        base_match = re.match(r'(https?://[^/]+)', url)
                        if base_match:
                            verify_url = base_match.group(1) + uploaded_path
                        else:
                            verify_url = None
                    else:
                        # Relative path
                        base_url = url.rsplit('/', 1)[0]
                        verify_url = base_url + '/' + uploaded_path

                    if verify_url:
                        logger.debug(f"Verifying uploaded file at: {verify_url}")
                        verify_response = http_client.get(verify_url)

                        if verify_response:
                            verify_text = getattr(verify_response, 'text', '')

                            # Check if our PHP test code executed
                            if 'DOMINATOR_FILE_UPLOAD_TEST' in verify_text:
                                confidence = 0.95

                                evidence = f"File upload successful with dangerous extension '.php'. "
                                evidence += f"Uploaded file accessible at: {verify_url}. "
                                evidence += f"PHP code executed successfully. CRITICAL VULNERABILITY!"

                                return True, confidence, evidence, verify_url

                            # File accessible but not executed
                            elif response.status_code == 200:
                                confidence = 0.85

                                evidence = f"File upload successful with dangerous extension '.php'. "
                                evidence += f"Uploaded file accessible at: {verify_url}. "
                                evidence += "File validation insufficient."

                                return True, confidence, evidence, verify_url

                except Exception as e:
                    logger.debug(f"File verification failed: {e}")

            evidence = f"File upload successful: '{success_found}'. "
            evidence += f"Dangerous file '{filename}' accepted. "
            if uploaded_path:
                evidence += f"Uploaded to: {uploaded_path}. "
            evidence += "No content filtering or extension validation detected."

            return True, confidence, evidence, uploaded_path or ""

        # DETECTION 2: Check if response changed significantly
        # (might indicate file was uploaded but no success message)
        if len(response_text) > 100:
            # Look for file paths in response
            path_patterns = [
                r'/uploads?/[^\s<>"\']+\.php',
                r'/files?/[^\s<>"\']+\.php',
                r'/media/[^\s<>"\']+\.php',
                r'uploads?/[^\s<>"\']+\.php',
            ]

            for pattern in path_patterns:
                match = re.search(pattern, response_text, re.IGNORECASE)
                if match:
                    uploaded_path = match.group(0)
                    confidence = 0.75

                    evidence = f"PHP file upload appears successful. "
                    evidence += f"Found uploaded file path: {uploaded_path}. "
                    evidence += "No proper file type validation detected."

                    return True, confidence, evidence, uploaded_path

        # DETECTION 3: Test with double extension bypass
        if not success_found:
            # Try double extension
            filename_double = "test_dominator.php.jpg"
            files = {file_param: (filename_double, io.BytesIO(php_content), 'image/jpeg')}

            try:
                response2 = http_client.post(url, data=form_data, files=files)
                if response2:
                    response2_text = getattr(response2, 'text', '')

                    # Check for success
                    for indicator in self.success_indicators:
                        if indicator in response2_text.lower():
                            confidence = 0.80

                            evidence = f"File upload bypass successful using double extension. "
                            evidence += f"File '{filename_double}' accepted. "
                            evidence += "Extension validation can be bypassed."

                            return True, confidence, evidence, ""

            except Exception as e:
                logger.debug(f"Double extension test failed: {e}")

        return False, 0.0, "", ""

    def _extract_uploaded_path(self, response_text: str, filename: str) -> str:
        """
        Extract uploaded file path from response

        Args:
            response_text: Response HTML
            filename: Uploaded filename

        Returns:
            File path or empty string
        """
        # Look for file path patterns
        patterns = [
            rf'(?:href|src)=["\']([^"\']*{re.escape(filename)}[^"\']*)["\']',
            rf'/uploads?/[^\s<>"\']*{re.escape(filename)}',
            rf'/files?/[^\s<>"\']*{re.escape(filename)}',
            rf'uploads?/[^\s<>"\']*{re.escape(filename)}',
            rf'Path:\s*([^\s<>]*{re.escape(filename)})',
        ]

        for pattern in patterns:
            match = re.search(pattern, response_text, re.IGNORECASE)
            if match:
                if match.groups():
                    return match.group(1)
                else:
                    return match.group(0)

        return ""


def get_module(module_path: str):
    """Create module instance"""
    return FileUploadModule(module_path)
