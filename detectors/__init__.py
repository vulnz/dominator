"""
Vulnerability detectors
"""

from .xss_detector import XSSDetector
from .sqli_detector import SQLiDetector
from .lfi_detector import LFIDetector
from .csrf_detector import CSRFDetector

__all__ = ['XSSDetector', 'SQLiDetector', 'LFIDetector', 'CSRFDetector']
