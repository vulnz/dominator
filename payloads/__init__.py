"""
Vulnerability testing payloads
"""

from .xss_payloads import XSSPayloads
from .sqli_payloads import SQLiPayloads
from .lfi_payloads import LFIPayloads
from .csrf_payloads import CSRFPayloads
from .dirbrute_payloads import DirBrutePayloads
from .git_payloads import GitPayloads
from .directory_traversal_payloads import DirectoryTraversalPayloads
from .ssrf_payloads import SSRFPayloads
from .rfi_payloads import RFIPayloads
from .blind_xss_payloads import BlindXSSPayloads
from .phpinfo_payloads import PHPInfoPayloads
from .xxe_payloads import XXEPayloads
from .command_injection_payloads import CommandInjectionPayloads
from .idor_payloads import IDORPayloads
from .nosql_injection_payloads import NoSQLInjectionPayloads

__all__ = ['XSSPayloads', 'SQLiPayloads', 'LFIPayloads', 'CSRFPayloads', 'DirBrutePayloads', 'GitPayloads', 'DirectoryTraversalPayloads', 'SSRFPayloads', 'RFIPayloads', 'BlindXSSPayloads', 'PHPInfoPayloads', 'XXEPayloads', 'CommandInjectionPayloads', 'IDORPayloads', 'NoSQLInjectionPayloads']
