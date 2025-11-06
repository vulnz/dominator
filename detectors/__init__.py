"""
Vulnerability detectors
"""

from .xss_detector import XSSDetector
from .sqli_detector import SQLiDetector
from .lfi_detector import LFIDetector
from .csrf_detector import CSRFDetector
from .dirbrute_detector import DirBruteDetector
from .real404_detector import Real404Detector
from .git_detector import GitDetector
from .directory_traversal_detector import DirectoryTraversalDetector
from .security_headers_detector import SecurityHeadersDetector
from .ssrf_detector import SSRFDetector
from .rfi_detector import RFIDetector
from .version_disclosure_detector import VersionDisclosureDetector
from .clickjacking_detector import ClickjackingDetector
from .blind_xss_detector import BlindXSSDetector
from .password_over_http_detector import PasswordOverHTTPDetector
from .outdated_software_detector import OutdatedSoftwareDetector
from .database_error_detector import DatabaseErrorDetector

__all__ = ['XSSDetector', 'SQLiDetector', 'LFIDetector', 'CSRFDetector', 'DirBruteDetector', 'Real404Detector', 'GitDetector', 'DirectoryTraversalDetector', 'SecurityHeadersDetector', 'SSRFDetector', 'RFIDetector', 'VersionDisclosureDetector', 'ClickjackingDetector', 'BlindXSSDetector', 'PasswordOverHTTPDetector', 'OutdatedSoftwareDetector', 'DatabaseErrorDetector']
