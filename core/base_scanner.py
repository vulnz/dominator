"""
Base scanner class for all vulnerability scanner modules
"""

from abc import ABC, abstractmethod
from typing import List, Dict, Any
from core.http_client import HTTPClient
from core.result_manager import ResultManager
from core.base_detector import DetectorResult
from core.logger import get_logger

logger = get_logger(__name__)


class BaseScanner(ABC):
    """Abstract base class for vulnerability scanners"""

    def __init__(self, http_client: HTTPClient, config: Any = None):
        """
        Initialize scanner

        Args:
            http_client: HTTP client instance
            config: Scanner configuration
        """
        self.http_client = http_client
        self.config = config
        self.result_manager = ResultManager()
        self.name = self.__class__.__name__.replace('Scanner', '')
        self.stop_requested = False

    @abstractmethod
    def scan(self, targets: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Perform vulnerability scan

        Args:
            targets: List of target URLs with parameters

        Returns:
            List of scan results
        """
        pass

    def get_name(self) -> str:
        """Get scanner name"""
        return self.name

    def should_stop(self) -> bool:
        """Check if scan should stop"""
        return self.stop_requested

    def request_stop(self):
        """Request scanner to stop"""
        self.stop_requested = True
        logger.info(f"{self.name} scanner received stop request")

    def get_results(self) -> List[Dict[str, Any]]:
        """Get scan results"""
        return self.result_manager.get_all_results()

    def clear_results(self):
        """Clear scan results"""
        self.result_manager.clear()

    def _result_to_dict(self, result: DetectorResult, vuln_type: str) -> Dict[str, Any]:
        """
        Convert DetectorResult to dictionary format

        Args:
            result: DetectorResult object
            vuln_type: Vulnerability type name

        Returns:
            Dictionary representation
        """
        result_dict = result.to_dict()
        result_dict['type'] = vuln_type
        result_dict['scanner'] = self.name
        return result_dict
