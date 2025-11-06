"""
Vulnerability testing payloads
"""

from .xss_payloads import XSSPayloads
from .sqli_payloads import SQLiPayloads
from .lfi_payloads import LFIPayloads
from .csrf_payloads import CSRFPayloads
from .dirbrute_payloads import DirBrutePayloads

__all__ = ['XSSPayloads', 'SQLiPayloads', 'LFIPayloads', 'CSRFPayloads', 'DirBrutePayloads']
