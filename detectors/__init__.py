"""
Vulnerability detectors
"""

from .xss_detector import XSSDetector
from .sqli_detector import SQLiDetector
from .lfi_detector import LFIDetector

__all__ = ['XSSDetector', 'SQLiDetector', 'LFIDetector']
