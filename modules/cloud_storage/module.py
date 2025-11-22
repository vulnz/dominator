"""
Cloud Storage Enumeration Scanner
Discovers exposed cloud storage buckets including AWS S3, Azure, GCP, and Firebase
"""

from core.base_module import BaseModule
from core.http_client import HTTPClient
from core.logger import get_logger
from typing import List, Dict, Any
import re
from urllib.parse import urlparse

logger = get_logger(__name__)


class CloudStorageEnumerationScanner(BaseModule):
    """Scans for exposed cloud storage buckets"""

    def __init__(self, module_path: str, payload_limit: int = None):
        super().__init__(module_path, payload_limit=payload_limit)
        self.module_name = "Cloud Storage Enumeration"
        self.logger = logger

    def scan(self, targets: List[Dict[str, Any]], http_client: Any = None) -> List[Dict[str, Any]]:
        """
        Scan targets for exposed cloud storage

        Args:
            targets: List of targets to scan
            http_client: HTTP client for making requests

        Returns:
            List of vulnerability findings
        """
        self.logger.info(f"Starting {self.module_name} scan on {len(targets)} targets")

        results = []
        client = http_client or HTTPClient(timeout=10)

        for target in targets:
            url = target.get('url')
            if not url:
                continue

            # Extract domain from URL
            domain = self._extract_domain(url)
            company_name = self._extract_company_name(domain)

            # Test each payload
            for payload in self.payloads[:self.payload_limit]:
                payload = payload.strip()
                if not payload or payload.startswith('#'):
                    continue

                finding = self._test_cloud_storage(client, url, domain, company_name, payload)
                if finding:
                    results.append(finding)

                    # Don't early exit for cloud storage - we want to find all exposed buckets
                    if self.config.get('early_exit', False):
                        break

        client.close()
        self.logger.info(f"{self.module_name} scan complete: {len(results)} vulnerabilities found")
        return results

    def _test_cloud_storage(self, client: HTTPClient, url: str, domain: str,
                           company_name: str, payload: str) -> Dict[str, Any]:
        """Test for exposed cloud storage"""

        try:
            # Parse payload type
            storage_type = 'UNKNOWN'
            storage_url = payload

            if ':' in payload:
                parts = payload.split(':', 1)
                storage_type = parts[0]
                if len(parts) > 1:
                    storage_url = parts[1]

            # Replace DOMAIN placeholder with actual domain/company name
            storage_url = storage_url.replace('DOMAIN', company_name)

            # Test based on storage type
            if storage_type == 'FIREBASE':
                return self._test_firebase_realtime_db(client, storage_url, domain)

            elif storage_type == 'FIREBASE_STORAGE':
                return self._test_firebase_storage(client, storage_url, domain)

            elif storage_type == 'FIRESTORE':
                return self._test_firestore(client, storage_url, domain)

            elif storage_type == 'S3':
                return self._test_aws_s3(client, storage_url, domain)

            elif storage_type == 'AZURE':
                return self._test_azure_blob(client, storage_url, domain)

            elif storage_type == 'GCS':
                return self._test_gcs(client, storage_url, domain)

            elif storage_type == 'DO':
                return self._test_digitalocean_spaces(client, storage_url, domain)

            elif storage_type == 'B2':
                return self._test_backblaze_b2(client, storage_url, domain)

            elif storage_type == 'WASABI':
                return self._test_wasabi(client, storage_url, domain)

            elif storage_type == 'PATTERN':
                # Test common bucket name patterns across all platforms
                return self._test_bucket_pattern(client, domain, company_name, storage_url)

        except Exception as e:
            self.logger.debug(f"Error testing cloud storage: {str(e)}")

        return None

    def _test_firebase_realtime_db(self, client: HTTPClient, firebase_url: str, domain: str) -> Dict[str, Any]:
        """Test Firebase Realtime Database for public access"""

        test_url = f"https://{firebase_url}/.json"

        response = client.get(test_url)

        if response and response.status_code == 200:
            try:
                data = response.json()
                if data is not None:  # Firebase returns null for empty but accessible databases
                    access_level = 'public-read' if data else 'public-empty'

                    return {
                        'vulnerability': True,
                        'module': self.module_name,
                        'type': 'Exposed Firebase Realtime Database',
                        'severity': 'Critical' if data else 'High',
                        'url': test_url,
                        'parameter': 'Firebase Database',
                        'payload': firebase_url,
                        'method': 'GET',
                        'confidence': 0.95,
                        'description': f'Firebase Realtime Database is publicly accessible at {firebase_url}.',
                        'evidence': f'Database access level: {access_level}. Response: {str(data)[:100]}',
                        'recommendation': 'Configure Firebase security rules to restrict access. Use authentication and proper authorization.',
                        'cwe': self.config.get('cwe', 'CWE-200'),
                        'cvss': 9.1 if data else 7.5,
                        'owasp': self.config.get('owasp', 'A01:2021'),
                        'references': [
                            'https://firebase.google.com/docs/database/security',
                            'https://firebase.google.com/docs/rules'
                        ]
                    }
            except:
                pass

        elif response and response.status_code == 401:
            # Database exists but requires authentication - still worth noting
            return {
                'vulnerability': False,
                'module': self.module_name,
                'type': 'Firebase Database Found (Protected)',
                'severity': 'Info',
                'url': test_url,
                'parameter': 'Firebase Database',
                'payload': firebase_url,
                'method': 'GET',
                'confidence': 0.90,
                'description': f'Firebase Realtime Database found at {firebase_url} but requires authentication.',
                'evidence': 'Database requires authentication (401)',
                'recommendation': 'Verify security rules are properly configured.',
                'cwe': 'CWE-200',
                'cvss': 0.0,
                'owasp': 'A01:2021',
                'references': []
            }

        return None

    def _test_firebase_storage(self, client: HTTPClient, storage_url: str, domain: str) -> Dict[str, Any]:
        """Test Firebase Storage for public access"""

        test_url = f"https://{storage_url}"

        response = client.get(test_url)

        if response and response.status_code == 200:
            if 'appspot.com' in response.text or 'firebase' in response.text.lower():
                return {
                    'vulnerability': True,
                    'module': self.module_name,
                    'type': 'Exposed Firebase Storage',
                    'severity': 'High',
                    'url': test_url,
                    'parameter': 'Firebase Storage',
                    'payload': storage_url,
                    'method': 'GET',
                    'confidence': 0.85,
                    'description': f'Firebase Storage bucket found at {storage_url}.',
                    'evidence': 'Firebase Storage bucket is accessible',
                    'recommendation': 'Configure Firebase Storage security rules to restrict public access.',
                    'cwe': 'CWE-200',
                    'cvss': 7.5,
                    'owasp': 'A01:2021',
                    'references': ['https://firebase.google.com/docs/storage/security']
                }

        return None

    def _test_firestore(self, client: HTTPClient, firestore_url: str, domain: str) -> Dict[str, Any]:
        """Test Firestore for public access"""

        response = client.get(firestore_url)

        if response and response.status_code == 200:
            try:
                data = response.json()
                if 'documents' in data or 'fields' in data:
                    return {
                        'vulnerability': True,
                        'module': self.module_name,
                        'type': 'Exposed Cloud Firestore',
                        'severity': 'Critical',
                        'url': firestore_url,
                        'parameter': 'Firestore Database',
                        'payload': firestore_url,
                        'method': 'GET',
                        'confidence': 0.90,
                        'description': 'Cloud Firestore database is publicly accessible.',
                        'evidence': 'Firestore documents accessible without authentication',
                        'recommendation': 'Configure Firestore security rules. Require authentication.',
                        'cwe': 'CWE-200',
                        'cvss': 9.1,
                        'owasp': 'A01:2021',
                        'references': ['https://firebase.google.com/docs/firestore/security/get-started']
                    }
            except:
                pass

        return None

    def _test_aws_s3(self, client: HTTPClient, bucket_url: str, domain: str) -> Dict[str, Any]:
        """Test AWS S3 bucket for public access"""

        test_url = f"https://{bucket_url}"

        response = client.get(test_url)

        if response and response.status_code == 200:
            # Check if bucket listing is enabled
            if '<ListBucketResult' in response.text or '<Contents>' in response.text:
                # Count files in listing
                file_count = response.text.count('<Key>')

                return {
                    'vulnerability': True,
                    'module': self.module_name,
                    'type': 'Exposed AWS S3 Bucket',
                    'severity': 'Critical',
                    'url': test_url,
                    'parameter': 'S3 Bucket',
                    'payload': bucket_url,
                    'method': 'GET',
                    'confidence': 0.95,
                    'description': f'AWS S3 bucket is publicly accessible with {file_count} files listed.',
                    'evidence': f'Bucket listing enabled. Files: {file_count}',
                    'recommendation': 'Configure S3 bucket policy to restrict public access. Enable bucket encryption.',
                    'cwe': 'CWE-200',
                    'cvss': 9.1,
                    'owasp': 'A01:2021',
                    'references': [
                        'https://docs.aws.amazon.com/AmazonS3/latest/userguide/access-control-block-public-access.html'
                    ]
                }

        elif response and response.status_code == 403:
            # Bucket exists but listing is disabled (still a finding)
            return {
                'vulnerability': False,
                'module': self.module_name,
                'type': 'AWS S3 Bucket Found (Protected)',
                'severity': 'Info',
                'url': test_url,
                'parameter': 'S3 Bucket',
                'payload': bucket_url,
                'method': 'GET',
                'confidence': 0.90,
                'description': f'AWS S3 bucket exists at {bucket_url} but listing is disabled.',
                'evidence': 'Bucket exists (403 response)',
                'recommendation': 'Verify bucket permissions are properly configured.',
                'cwe': 'CWE-200',
                'cvss': 0.0,
                'owasp': 'A01:2021',
                'references': []
            }

        return None

    def _test_azure_blob(self, client: HTTPClient, blob_url: str, domain: str) -> Dict[str, Any]:
        """Test Azure Blob Storage for public access"""

        test_url = f"https://{blob_url}?restype=container&comp=list"

        response = client.get(test_url)

        if response and response.status_code == 200:
            if '<Blobs>' in response.text or '<Blob>' in response.text:
                blob_count = response.text.count('<Name>')

                return {
                    'vulnerability': True,
                    'module': self.module_name,
                    'type': 'Exposed Azure Blob Storage',
                    'severity': 'Critical',
                    'url': test_url,
                    'parameter': 'Azure Blob',
                    'payload': blob_url,
                    'method': 'GET',
                    'confidence': 0.95,
                    'description': f'Azure Blob Storage is publicly accessible with {blob_count} blobs.',
                    'evidence': f'Container listing enabled. Blobs: {blob_count}',
                    'recommendation': 'Configure Azure Storage account to restrict public access.',
                    'cwe': 'CWE-200',
                    'cvss': 9.1,
                    'owasp': 'A01:2021',
                    'references': [
                        'https://docs.microsoft.com/en-us/azure/storage/blobs/anonymous-read-access-prevent'
                    ]
                }

        return None

    def _test_gcs(self, client: HTTPClient, gcs_url: str, domain: str) -> Dict[str, Any]:
        """Test Google Cloud Storage for public access"""

        test_url = f"https://{gcs_url}"

        response = client.get(test_url)

        if response and response.status_code == 200:
            if '<ListBucketResult' in response.text or 'storage.googleapis.com' in response.text:
                return {
                    'vulnerability': True,
                    'module': self.module_name,
                    'type': 'Exposed Google Cloud Storage',
                    'severity': 'Critical',
                    'url': test_url,
                    'parameter': 'GCS Bucket',
                    'payload': gcs_url,
                    'method': 'GET',
                    'confidence': 0.95,
                    'description': 'Google Cloud Storage bucket is publicly accessible.',
                    'evidence': 'Bucket listing enabled',
                    'recommendation': 'Configure GCS bucket IAM to restrict public access.',
                    'cwe': 'CWE-200',
                    'cvss': 9.1,
                    'owasp': 'A01:2021',
                    'references': [
                        'https://cloud.google.com/storage/docs/access-control/making-data-public'
                    ]
                }

        return None

    def _test_digitalocean_spaces(self, client: HTTPClient, space_url: str, domain: str) -> Dict[str, Any]:
        """Test DigitalOcean Spaces for public access"""

        test_url = f"https://{space_url}"
        response = client.get(test_url)

        if response and response.status_code == 200:
            return self._create_finding('DigitalOcean Spaces', test_url, space_url)

        return None

    def _test_backblaze_b2(self, client: HTTPClient, b2_url: str, domain: str) -> Dict[str, Any]:
        """Test Backblaze B2 for public access"""

        test_url = f"https://{b2_url}"
        response = client.get(test_url)

        if response and response.status_code == 200:
            return self._create_finding('Backblaze B2', test_url, b2_url)

        return None

    def _test_wasabi(self, client: HTTPClient, wasabi_url: str, domain: str) -> Dict[str, Any]:
        """Test Wasabi storage for public access"""

        test_url = f"https://{wasabi_url}"
        response = client.get(test_url)

        if response and response.status_code == 200:
            return self._create_finding('Wasabi Storage', test_url, wasabi_url)

        return None

    def _test_bucket_pattern(self, client: HTTPClient, domain: str, company_name: str, pattern: str) -> Dict[str, Any]:
        """Test common bucket name patterns across platforms"""

        # Try pattern with company name
        bucket_name = f"{company_name}-{pattern}"

        # Test S3
        s3_url = f"https://{bucket_name}.s3.amazonaws.com"
        response = client.get(s3_url)
        if response and response.status_code in [200, 403]:
            return self._test_aws_s3(client, f"{bucket_name}.s3.amazonaws.com", domain)

        return None

    def _create_finding(self, storage_type: str, url: str, payload: str) -> Dict[str, Any]:
        """Create a generic cloud storage finding"""

        return {
            'vulnerability': True,
            'module': self.module_name,
            'type': f'Exposed {storage_type}',
            'severity': 'High',
            'url': url,
            'parameter': 'Cloud Storage',
            'payload': payload,
            'method': 'GET',
            'confidence': 0.80,
            'description': f'{storage_type} bucket is publicly accessible.',
            'evidence': 'Bucket accessible without authentication',
            'recommendation': 'Configure bucket access controls to restrict public access.',
            'cwe': 'CWE-200',
            'cvss': 7.5,
            'owasp': 'A01:2021',
            'references': []
        }

    def _extract_domain(self, url: str) -> str:
        """Extract domain from URL"""

        parsed = urlparse(url)
        return parsed.netloc or parsed.path

    def _extract_company_name(self, domain: str) -> str:
        """Extract company/app name from domain"""

        # Remove common TLDs and subdomains
        domain = domain.lower()
        domain = re.sub(r'^(www|app|api|dev|staging|test)\.', '', domain)
        domain = re.sub(r'\.(com|net|org|io|co|app|dev)$', '', domain)

        # Take first part before any remaining dots
        if '.' in domain:
            domain = domain.split('.')[0]

        return domain


def get_module(module_path: str, payload_limit: int = None):
    """Factory function to create module instance"""
    return CloudStorageEnumerationScanner(module_path, payload_limit=payload_limit)
