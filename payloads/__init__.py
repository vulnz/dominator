"""
Vulnerability testing payloads
"""

from .xss_payloads import XSSPayloads
from .sqli_payloads import SQLiPayloads
from .lfi_payloads import LFIPayloads
from .csrf_payloads import CSRFPayloads

__all__ = ['XSSPayloads', 'SQLiPayloads', 'LFIPayloads', 'CSRFPayloads']
