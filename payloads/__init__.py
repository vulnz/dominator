"""
Vulnerability testing payloads
"""

from .xss_payloads import XSSPayloads
from .sqli_payloads import SQLiPayloads
from .lfi_payloads import LFIPayloads

__all__ = ['XSSPayloads', 'SQLiPayloads', 'LFIPayloads']
