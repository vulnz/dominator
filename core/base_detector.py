"""
Base detector interface for all vulnerability detectors
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Optional, Dict, Any, List
from enum import Enum


class Severity(Enum):
    """Vulnerability severity levels"""
    CRITICAL = "Critical"
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"
    INFO = "Info"


@dataclass
class DetectorResult:
    """Standardized result from vulnerability detection"""
    vulnerable: bool
    severity: Severity = Severity.INFO
    evidence: str = ""
    description: str = ""
    url: str = ""
    parameter: str = ""
    payload: str = ""
    confidence: float = 1.0
    cwe: str = ""
    owasp: str = ""
    cvss: str = ""
    recommendation: str = ""
    additional_info: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Convert result to dictionary"""
        return {
            'vulnerability': self.vulnerable,
            'severity': self.severity.value if isinstance(self.severity, Severity) else self.severity,
            'evidence': self.evidence,
            'description': self.description,
            'url': self.url,
            'parameter': self.parameter,
            'payload': self.payload,
            'confidence': self.confidence,
            'cwe': self.cwe,
            'owasp': self.owasp,
            'cvss': self.cvss,
            'recommendation': self.recommendation,
            **self.additional_info
        }


class BaseDetector(ABC):
    """Abstract base class for all vulnerability detectors"""

    def __init__(self, config=None):
        """Initialize detector with configuration"""
        self.config = config
        self.name = self.__class__.__name__.replace('Detector', '').lower()

    @abstractmethod
    def detect(self, url: str, response_text: str, response_code: int,
               headers: Dict[str, str], **kwargs) -> List[DetectorResult]:
        """
        Detect vulnerabilities

        Args:
            url: Target URL
            response_text: HTTP response body
            response_code: HTTP status code
            headers: Response headers
            **kwargs: Additional context (payload, parameter, etc.)

        Returns:
            List of DetectorResult objects
        """
        pass

    def get_name(self) -> str:
        """Get detector name"""
        return self.name

    def supports_passive_scan(self) -> bool:
        """Whether detector can run passively during crawling"""
        return False
