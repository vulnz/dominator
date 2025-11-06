"""
Vulnerability detectors
"""

from .xss_detector import XSSDetector
from .sqli_detector import SQLiDetector
from .lfi_detector import LFIDetector
from .csrf_detector import CSRFDetector
from .dirbrute_detector import DirBruteDetector
from .real404_detector import Real404Detector

__all__ = ['XSSDetector', 'SQLiDetector', 'LFIDetector', 'CSRFDetector', 'DirBruteDetector', 'Real404Detector']
